from __future__ import annotations

import json
import os
import shutil
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

import pytest
from workbench_test_support import load_script, run_workbench, write_completed_contract

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = load_script("validate_scan_contract")
SCHEMA = load_script("workbench_schema")
RECEIPT_MIGRATION = next(
    version
    for version, name, _ in SCHEMA.MIGRATIONS
    if name == "share finding issue receipts across trackers"
)
LINEAR = {"type": "linear", "teamId": "team-example"}
JIRA = {"type": "jira", "cloudId": "site-example", "projectId": "10001"}


def source(tmp_path: Path) -> tuple[Path, dict]:
    scan_dir = tmp_path / "scan"
    shutil.copytree(PLUGIN_ROOT / "examples" / "completed-scan", scan_dir)
    return scan_dir, VALIDATOR.validate_contract(scan_dir)


def receipt_for(validated: dict, **fields) -> dict:
    finding = validated["findings"]["findings"][0]
    return {
        "findingId": finding["findingId"],
        "occurrenceId": finding["occurrenceId"],
        "issueIdentifier": "SEC-101",
        "operation": "create",
        **fields,
    }


def issues(state: Path, scan_dir: Path, action: str, *, destination=None, **fields) -> dict:
    return run_workbench(
        state,
        "finding-issues",
        input_text=json.dumps(
            {
                "action": action,
                "scanDirectory": str(scan_dir),
                "destination": destination or LINEAR,
                **fields,
            }
        ),
    )


def legacy_database(path: Path, validated: dict, destination: dict) -> None:
    path.parent.mkdir()
    with closing(sqlite3.connect(path)) as connection:
        connection.row_factory = sqlite3.Row
        SCHEMA.apply_migrations(
            connection,
            tuple(migration for migration in SCHEMA.MIGRATIONS if migration[0] < RECEIPT_MIGRATION),
            lambda: "2026-01-01T00:00:00Z",
            lambda _: None,
        )
        receipt = receipt_for(validated)
        connection.execute(
            "INSERT INTO finding_publications (scan_id, finding_id, occurrence_id, destination_type, "
            "team_id, project_id, external_id, external_url, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                validated["manifest"]["scan"]["id"],
                receipt["findingId"],
                receipt["occurrenceId"],
                "linear",
                destination["teamId"],
                destination.get("projectId"),
                "SEC-101",
                "https://linear.app/example/issue/SEC-101",
                "2026-01-01T00:00:00Z",
            ),
        )
        connection.commit()


def test_inspection_of_portable_source_does_not_create_state(tmp_path: Path) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    result = issues(state, scan_dir, "inspect")
    assert result["scanId"] == validated["manifest"]["scan"]["id"]
    assert result["receipts"] == []
    assert result["storeExists"] is False
    assert not state.exists()


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="requires Unix file permissions",
)
@pytest.mark.parametrize("action", ["inspect", "record"])
def test_inaccessible_state_preserves_sqlite_open_error(tmp_path: Path, action: str) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o000)
    try:
        with pytest.raises(PermissionError):
            (state / "workbench.sqlite3").stat()
        result = run_workbench(
            state,
            "finding-issues",
            input_text=json.dumps(
                {
                    "action": action,
                    "scanDirectory": str(scan_dir),
                    "destination": LINEAR,
                    **({"receipts": [receipt_for(validated)]} if action == "record" else {}),
                }
            ),
            check=False,
        )
        assert result["returncode"] != 0
        assert "sqlite3.OperationalError: unable to open database file" in result["stderr"]
    finally:
        state.chmod(0o700)


@pytest.mark.parametrize("project", [None, "project-example"])
def test_legacy_receipts_are_read_without_migration_and_preserved_on_upgrade(
    tmp_path: Path, project: str | None
) -> None:
    scan_dir, validated = source(tmp_path)
    destination = {"type": "linear", "teamId": "équipe-example"}
    if project is not None:
        destination["projectId"] = project
    state = tmp_path / "state"
    path = state / "workbench.sqlite3"
    legacy_database(path, validated, destination)
    original = path.read_bytes()
    inspected = issues(state, scan_dir, "inspect", destination=destination)
    assert inspected["storeExists"] is True
    assert inspected["receipts"] == [
        {
            **receipt_for(validated),
            "scanId": validated["manifest"]["scan"]["id"],
            "url": "https://linear.app/example/issue/SEC-101",
        }
    ]
    assert path.read_bytes() == original
    prepared = issues(state, scan_dir, "prepare", destination=destination)
    assert prepared["receipts"] == []
    assert prepared["storeExists"] is True
    assert issues(state, scan_dir, "inspect", destination=destination) == inspected
    with closing(sqlite3.connect(path)) as connection:
        assert (
            connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0]
            == SCHEMA.MIGRATIONS[-1][0]
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'finding_publications'"
            ).fetchone()
            is None
        )
        key = connection.execute("SELECT destination_key FROM finding_issue_receipts").fetchone()[0]
        assert key == json.dumps(
            ["linear", "équipe-example", project], ensure_ascii=False, separators=(",", ":")
        )


def test_records_id_only_acceptance_and_failed_readback_without_losing_create(
    tmp_path: Path,
) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    accepted = receipt_for(validated)
    recorded = issues(state, scan_dir, "record", destination=JIRA, receipts=[accepted])
    assert recorded["storeExists"] is True
    assert recorded["receipts"] == [{**accepted, "scanId": validated["manifest"]["scan"]["id"]}]
    failed_read = {"status": "failed", "error": "Read denied; diagnostic sk-synthetic-value"}
    issues(
        state,
        scan_dir,
        "record",
        destination=JIRA,
        receipts=[
            {
                **accepted,
                "url": "https://issues.example.test/browse/SEC-101",
                "readback": failed_read,
            }
        ],
    )
    issues(state, scan_dir, "record", destination=JIRA, receipts=[accepted])
    issues(
        state,
        scan_dir,
        "record",
        destination=JIRA,
        receipts=[
            {
                **accepted,
                "operation": "reuse",
                "readback": {"status": "verified"},
            }
        ],
    )
    history = issues(state, scan_dir, "inspect", destination=JIRA)["receipts"]
    assert len(history) == 2
    assert history[0]["operation"] == "create"
    assert history[0]["url"] == "https://issues.example.test/browse/SEC-101"
    assert history[0]["readback"] == failed_read
    assert history[1]["operation"] == "reuse"
    assert history[1]["readback"] == {"status": "verified"}
    with closing(sqlite3.connect(state / "workbench.sqlite3")) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


@pytest.mark.parametrize("operation", ["create", "update", "reuse"])
def test_readback_replay_preserves_the_accepted_receipt_url(tmp_path: Path, operation: str) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    accepted = receipt_for(
        validated, operation=operation, url="https://issues.example.test/browse/SEC-101"
    )
    issues(state, scan_dir, "record", receipts=[accepted])
    readback = {"status": "verified"}
    replayed = issues(
        state,
        scan_dir,
        "record",
        receipts=[
            {**accepted, "url": "https://issues.example.test/browse/SEC-999", "readback": readback}
        ],
    )
    expected = {
        **accepted,
        "scanId": validated["manifest"]["scan"]["id"],
        "readback": readback,
    }
    assert replayed["receipts"] == [expected]
    assert issues(state, scan_dir, "inspect")["receipts"] == [expected]


@pytest.mark.parametrize(
    "destination",
    [
        {"type": "linear", "teamId": "different-team"},
        {"type": "linear", "teamId": "team-example", "projectId": "project-example"},
        JIRA,
        {"type": "github-issue", "hostname": "github.com", "repository": "example/repo"},
        {"type": "github-advisory", "hostname": "github.com", "repository": "example/repo"},
    ],
)
def test_destination_scope_is_part_of_receipt_identity(tmp_path: Path, destination: dict) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    accepted = receipt_for(validated)
    issues(state, scan_dir, "record", receipts=[accepted])
    assert issues(state, scan_dir, "inspect", destination=destination)["receipts"] == []
    issues(state, scan_dir, "record", destination=destination, receipts=[accepted])
    assert len(issues(state, scan_dir, "inspect", destination=destination)["receipts"]) == 1
    assert len(issues(state, scan_dir, "inspect")["receipts"]) == 1


def test_same_issue_can_track_a_later_occurrence(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    sources = []
    for index in range(2):
        scan_dir = tmp_path / f"scan-{index}"
        scan_dir.mkdir()
        write_completed_contract(scan_dir, str(uuid.uuid4()), target)
        VALIDATOR.FINALIZER.finalize_scan(scan_dir)
        sources.append((scan_dir, VALIDATOR.validate_contract(scan_dir)))
    first_dir, first = sources[0]
    second_dir, second = sources[1]
    created = receipt_for(first)
    reused = receipt_for(second, operation="reuse", readback={"status": "verified"})
    assert created["findingId"] == reused["findingId"]
    assert created["occurrenceId"] != reused["occurrenceId"]
    issues(state, first_dir, "record", receipts=[created])
    assert (
        issues(state, second_dir, "inspect")["receipts"][0]["occurrenceId"]
        == created["occurrenceId"]
    )
    issues(state, second_dir, "record", receipts=[reused])
    history = issues(state, second_dir, "inspect")["receipts"]
    assert [entry["operation"] for entry in history] == ["create", "reuse"]
    assert len({entry["scanId"] for entry in history}) == 2


@pytest.mark.parametrize("operation", ["create", "update", "reuse"])
def test_issue_cannot_move_to_a_different_finding(tmp_path: Path, operation: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    sources = []
    for index in range(2):
        scan_dir = tmp_path / f"scan-{index}"
        scan_dir.mkdir()
        write_completed_contract(
            scan_dir, str(uuid.uuid4()), target, identity_anchor=f"synthetic-finding-{index}"
        )
        VALIDATOR.FINALIZER.finalize_scan(scan_dir)
        sources.append((scan_dir, VALIDATOR.validate_contract(scan_dir)))
    first_dir, first = sources[0]
    second_dir, second = sources[1]
    existing = receipt_for(first)
    conflicting = receipt_for(second, operation=operation)
    assert existing["findingId"] != conflicting["findingId"]
    issues(state, first_dir, "record", receipts=[existing])

    result = run_workbench(
        state,
        "finding-issues",
        input_text=json.dumps(
            {
                "action": "record",
                "scanDirectory": str(second_dir),
                "destination": LINEAR,
                "receipts": [receipt_for(second, issueIdentifier="SEC-102"), conflicting],
            }
        ),
        check=False,
    )
    assert result["returncode"] != 0
    assert "already associated with another finding" in result["stderr"]
    assert issues(state, second_dir, "inspect")["receipts"] == []
    assert issues(state, first_dir, "inspect")["receipts"] == [
        {**existing, "scanId": first["manifest"]["scan"]["id"]}
    ]
    # Issue identifiers are scoped to their destination.
    recorded = issues(state, second_dir, "record", destination=JIRA, receipts=[conflicting])
    assert recorded["receipts"] == [{**conflicting, "scanId": second["manifest"]["scan"]["id"]}]


@pytest.mark.parametrize("mutation", ["finding", "occurrence", "scan", "seal"])
def test_invalid_source_is_rejected_before_creating_state(tmp_path: Path, mutation: str) -> None:
    scan_dir, validated = source(tmp_path)
    state = tmp_path / "state"
    receipt = receipt_for(validated)
    payload = {
        "action": "record",
        "scanDirectory": str(scan_dir),
        "destination": LINEAR,
        "receipts": [receipt],
    }
    if mutation == "finding":
        payload["findingIds"] = ["not-a-finding"]
    elif mutation == "occurrence":
        receipt["occurrenceId"] = "not-an-occurrence"
    elif mutation == "scan":
        payload["expectedScanId"] = "not-this-scan"
    else:
        (scan_dir / "findings.json").write_text("{}")
    result = run_workbench(state, "finding-issues", input_text=json.dumps(payload), check=False)
    assert result["returncode"] != 0
    assert not state.exists()
