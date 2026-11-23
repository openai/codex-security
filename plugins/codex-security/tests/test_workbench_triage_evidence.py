"""Keep fix evidence tied to its current decision across older triage writers."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_scan_history import (
    compare_scan_pair,
    confirmed_match,
    create_cli_scan,
    save_scan_matches,
)
from workbench_test_support import get_scan, initialize_git_repository, run_workbench, set_triage


def write_legacy_triage(
    state: Path, occurrence: str, status: str, note: str | None, timestamp: str
) -> None:
    """Use the pre-revision writer's audit and current-state column lists."""
    reason = "already_fixed" if status == "closed" else None
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        previous = connection.execute(
            "SELECT status, close_reason, note FROM finding_triage WHERE occurrence_id = ?",
            (occurrence,),
        ).fetchone()
        if previous != (status, reason, note):
            connection.execute(
                "INSERT INTO finding_decisions "
                "(id, occurrence_id, status, close_reason, note, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), occurrence, status, reason, note, timestamp),
            )
        connection.execute(
            "INSERT INTO finding_triage "
            "(occurrence_id, status, close_reason, note, updated_at) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(occurrence_id) DO UPDATE SET status = excluded.status, "
            "close_reason = excluded.close_reason, note = excluded.note, "
            "updated_at = excluded.updated_at",
            (occurrence, status, reason, note, timestamp),
        )


@pytest.mark.parametrize("before_upgrade", [False, True])
@pytest.mark.parametrize("change", ["reopen", "rationale", "replay"])
def test_legacy_decisions_do_not_reuse_superseded_fix_evidence(
    tmp_path: Path, before_upgrade: bool, change: str
) -> None:
    state, root, repo = tmp_path / "state", tmp_path / "results", tmp_path / "repository"
    revision = initialize_git_repository(repo)
    before = create_cli_scan(
        state,
        root,
        repo,
        target_revision=revision,
        locations=[{"role": "concrete_implementation", "path": "README.md", "startLine": 1}],
    )
    after = create_cli_scan(state, root, repo, target_revision=revision, finding=False)
    occurrence = compare_scan_pair(state, before, after)["findings"][0]["beforeOccurrenceId"]
    note = "Verified the synthetic fixture."
    set_triage(
        state,
        occurrence,
        "closed",
        "--close-reason",
        "already_fixed",
        "--fixed-revision",
        revision,
        "--note",
        note,
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        timestamp = connection.execute(
            "SELECT updated_at FROM finding_triage WHERE occurrence_id = ?", (occurrence,)
        ).fetchone()[0]
        # Equal timestamps and reverse ID order must still follow actual append order.
        connection.execute("UPDATE finding_decisions SET id = 'z-original'")
        if before_upgrade:
            connection.execute("DROP TRIGGER IF EXISTS retain_finding_decision_revision")
            connection.execute("DELETE FROM schema_migrations WHERE version = 81")
    if change == "reopen":
        write_legacy_triage(state, occurrence, "open", None, timestamp)
    elif change == "rationale":
        note = "Changed the closure rationale without revision evidence."
    else:
        # An old no-op writer advances updated_at without appending a decision.
        timestamp = "2099-01-01T00:00:00Z"
    write_legacy_triage(state, occurrence, "closed", note, timestamp)
    result = compare_scan_pair(state, before, after)["findings"][0]
    triage = get_scan(state, before["scanId"])["scan"]["findings"][0]["triage"]
    if change == "replay":
        assert result["status"] == "resolved"
        assert triage["fixedRevision"] == revision
        assert triage["updatedAt"] == timestamp
    else:
        assert result["status"] == "not_observed"
        assert "fixedRevision" not in triage
        assert "fixedRevision" not in result["beforeTriage"][0]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        revisions = [
            row[0]
            for row in connection.execute(
                "SELECT fixed_revision FROM finding_decisions ORDER BY rowid"
            )
        ]
        assert revisions == [revision] + [None] * {"reopen": 2, "rationale": 1, "replay": 0}[change]
    # Reasserting the same revision and current note must record fresh evidence.
    rebound = set_triage(
        state,
        occurrence,
        "closed",
        "--close-reason",
        "already_fixed",
        "--fixed-revision",
        revision,
        "--note",
        note,
    )["scan"]["findings"][0]["triage"]
    assert rebound["fixedRevision"] == revision
    assert compare_scan_pair(state, before, after)["findings"][0]["status"] == "resolved"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        actual = [
            row[0]
            for row in connection.execute(
                "SELECT fixed_revision FROM finding_decisions ORDER BY rowid"
            )
        ]
        assert actual == revisions + ([] if change == "replay" else [revision])


@pytest.mark.parametrize("decision", ["false_positive", "verified_fix", "open"])
def test_reasserted_triage_controls_matched_findings_and_feedback(
    tmp_path: Path, decision: str
) -> None:
    state, root, repo = tmp_path / "state", tmp_path / "results", tmp_path / "repository"
    revision = initialize_git_repository(repo)
    scans = [
        create_cli_scan(
            state, root, repo, target_revision=revision, identity_anchor=f"synthetic-{index}"
        )
        for index in range(2)
    ]
    findings = [get_scan(state, scan["scanId"])["scan"]["findings"][0] for scan in scans]
    first, second = [finding["occurrenceId"] for finding in findings]
    save_scan_matches(state, *scans, confirmed_match(first, second))
    current = create_cli_scan(state, root, repo, target_revision=revision, finding=False)

    def repository_finding():
        rows = run_workbench(state, "list-global-findings", "--repository", str(repo))["findings"]
        assert len(rows) == 1
        assert rows[0]["occurrenceCount"] == 2
        assert set(rows[0]["matchedFindingIds"]) == {finding["findingId"] for finding in findings}
        return rows[0]

    repository_finding()
    assert [
        match["occurrenceId"]
        for match in get_scan(state, scans[0]["scanId"])["scan"]["findings"][0]["matches"]
    ] == [second]
    note = "The synthetic finding has been reviewed."
    status = "open" if decision == "open" else "closed"
    reason = "already_fixed" if decision == "verified_fix" else "false_positive"
    args = [] if status == "open" else ["--close-reason", reason, "--note", note]
    evidence = ["--fixed-revision", revision] if decision == "verified_fix" else []
    original = set_triage(state, first, status, *args, *evidence)["scan"]["findings"][0]["triage"]
    other_status = "closed" if status == "open" else "open"
    other_args = (
        ["--close-reason", "false_positive", "--note", "The other fixture was reviewed."]
        if other_status == "closed"
        else []
    )
    other = set_triage(state, second, other_status, *other_args)["scan"]["findings"][0]["triage"]
    assert repository_finding()["status"] == other_status
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])
    assert len(feedback["falsePositives"]) == int(other_status == "closed")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        audit = connection.execute("SELECT * FROM finding_decisions ORDER BY rowid").fetchall()
        assert len(audit) == 2

    # An older caller can repeat a verified closure without supplying its evidence again.
    replay_args = ["--close-reason", reason] if decision == "verified_fix" else args
    repeated = set_triage(state, first, status, *replay_args)["scan"]["findings"][0]["triage"]
    assert repository_finding()["status"] == status
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])
    if decision == "false_positive":
        assert len(feedback["falsePositives"]) == 1
        assert feedback["falsePositives"][0]["reason"] == note
        assert feedback["falsePositives"][0]["sourceScanId"] == scans[0]["scanId"]
    else:
        assert feedback["falsePositives"] == []
    assert repeated == {**original, "updatedAt": repeated["updatedAt"]}
    assert repeated["updatedAt"] > other["updatedAt"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute("SELECT * FROM finding_decisions ORDER BY rowid").fetchall() == audit
        )
