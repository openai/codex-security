from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from workbench_test_support import (
    SCRIPT,
    create_cli_scan,
    load_script,
    run_workbench,
    write_completed_contract,
)


def complete_pending(state: Path, repository: Path, scan: dict, *, failed: bool = False):
    scan_dir = Path(scan["scanDir"])
    write_completed_contract(scan_dir, scan["scanId"], repository)
    subprocess.run(
        [
            sys.executable,
            str(SCRIPT.with_name("finalize_scan_contract.py")),
            "--scan-dir",
            str(scan_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return run_workbench(
        state,
        "fail-scan" if failed else "complete-scan",
        "--scan-id",
        scan["scanId"],
        *(["--message", "Synthetic interruption"] if failed else []),
    )


@pytest.mark.parametrize(
    ("ordering", "reason"),
    [
        ("running", "already_fixed"),
        ("running", "false_positive"),
        ("complete", "already_fixed"),
        ("complete", "false_positive"),
        ("registered-after", "already_fixed"),
        ("registered-after", "false_positive"),
        ("running", "wont_fix"),
        ("unrelated-completed", "false_positive"),
        ("same-target-completed", "already_fixed"),
        ("same-target-completed", "false_positive"),
        ("failed-sealed", "already_fixed"),
        ("failed-sealed", "false_positive"),
        ("clock-rollback", "false_positive"),
    ],
)
def test_triage_observes_first_result_admission(tmp_path: Path, ordering: str, reason: str):
    state, scans, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repository.mkdir()
    first = create_cli_scan(state, scans, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    pending = (
        None
        if ordering == "registered-after"
        else create_cli_scan(state, scans, repository, complete=ordering == "complete")
    )
    if ordering in {"same-target-completed", "unrelated-completed"}:
        target = repository
        if ordering == "unrelated-completed":
            target = tmp_path / "other-repository"
            target.mkdir()
        create_cli_scan(state, scans, target)
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        reason,
        "--note",
        "Synthetic reviewed decision.",
    )
    if pending is None:
        pending = create_cli_scan(state, scans, repository)
    elif ordering != "complete":
        complete_pending(state, repository, pending, failed=ordering == "failed-sealed")
    if ordering == "clock-rollback":
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET started_at = '2000-01-01T00:00:00Z', "
                "completed_at = '2000-01-01T00:00:01Z' WHERE id = ?",
                (pending["scanId"],),
            )
    expected = "closed" if ordering == "complete" or reason == "wont_fix" else "open"
    findings = run_workbench(
        state, "list-global-findings", "--repository", str(repository), "--include-resolved"
    )["findings"]
    assert len(findings) == 1
    assert findings[0]["status"] == expected
    detail = run_workbench(state, "get-scan", "--scan-id", pending["scanId"])["scan"]["findings"]
    assert detail[0]["status"] == expected
    assert len(
        run_workbench(
            state, "list-global-findings", "--repository", str(repository), "--status", "open"
        )["findings"]
    ) == int(expected == "open")
    if reason == "false_positive":
        next_scan = create_cli_scan(state, scans, repository, complete=False)
        feedback = run_workbench(state, "get-scan-feedback", "--scan-id", next_scan["scanId"])
        assert bool(feedback["falsePositives"]) is (expected == "closed")


@pytest.mark.parametrize("failed", [False, True])
def test_replayed_completion_does_not_advance_admission(tmp_path: Path, failed: bool):
    state, scans, repository = tmp_path / "state", tmp_path / "scans", tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state, scans, repository, complete=False)
    complete_pending(state, repository, scan, failed=failed)
    occurrence = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic retained decision.",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        before = connection.execute("SELECT sequence, scan_id FROM scan_admissions").fetchall()
    run_workbench(
        state, "preserve-scan-results" if failed else "complete-scan", "--scan-id", scan["scanId"]
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute("SELECT sequence, scan_id FROM scan_admissions").fetchall() == before
        )
    detail = run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"]["findings"][
        0
    ]
    assert detail["status"] == "closed"


def test_admission_migration_preserves_legacy_boundaries_and_first_admissions():
    schema = load_script("workbench_schema")
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        schema.apply_migrations(
            connection,
            tuple(item for item in schema.MIGRATIONS if item[0] <= 55),
            lambda: "2026-01-01T00:00:00Z",
            lambda _connection: None,
        )
        connection.execute(
            "INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', 'created', 'updated')"
        )

        def add_scan(scan_id, status, seal=None):
            connection.execute(
                "INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, "
                "scan_dir, status, phase, started_at, created_at, updated_at, seal_manifest_digest) "
                "VALUES (?, 'workspace', '/synthetic/repository', 'synthetic', '.', 'standard', "
                "?, ?, 'reporting', 'started', 'created', 'updated', ?)",
                (scan_id, f"/synthetic/output/{scan_id}", status, seal),
            )

        add_scan("completed", "complete", "sealed")
        add_scan("pending", "running")
        add_scan("retained", "failed", "sealed")
        add_scan("unsealed", "failed")
        connection.executescript("""
            INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at)
            VALUES ('finding', 'synthetic', 'rule', 'anchor', 'created', 'updated');
            INSERT INTO finding_occurrences (id, finding_id, scan_id, title, summary, severity,
                confidence, remediation, created_at)
            VALUES ('occurrence', 'finding', 'completed', 'Synthetic finding', 'Synthetic summary',
                'high', 'high', 'Synthetic remediation', 'created');
            INSERT INTO finding_decisions (id, occurrence_id, status, close_reason, note, created_at,
                decision_sequence, scan_sequence)
            VALUES ('decision', 'occurrence', 'closed', 'false_positive', 'Synthetic decision', 'created', 17, 4);
        """)
        schema.apply_migrations(
            connection, schema.MIGRATIONS, lambda: "updated", lambda _connection: None
        )
        admissions = dict(connection.execute("SELECT scan_id, sequence FROM scan_admissions"))
        assert list(admissions) == ["completed", "retained"]
        decision = connection.execute("SELECT * FROM finding_decisions").fetchone()
        assert (
            decision["decision_sequence"],
            decision["scan_sequence"],
            decision["admission_sequence"],
        ) == (17, 4, None)
        connection.execute("UPDATE scans SET status = 'complete' WHERE id = 'pending'")
        admitted = connection.execute(
            "SELECT sequence FROM scan_admissions WHERE scan_id = 'pending'"
        ).fetchone()[0]
        assert admitted > max(admissions.values())
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = 'sealed-again' WHERE id = 'pending'"
        )
        assert (
            connection.execute(
                "SELECT sequence FROM scan_admissions WHERE scan_id = 'pending'"
            ).fetchone()[0]
            == admitted
        )
        connection.execute("DELETE FROM scans WHERE id = 'pending'")
        add_scan("new-completion", "complete", "new-seal")
        assert (
            connection.execute(
                "SELECT sequence FROM scan_admissions WHERE scan_id = 'new-completion'"
            ).fetchone()[0]
            > admitted
        )
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = 'retained' WHERE id = 'unsealed'"
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM scan_admissions WHERE scan_id = 'unsealed'"
            ).fetchone()[0]
            == 1
        )
