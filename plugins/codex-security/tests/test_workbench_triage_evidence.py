"""Keep fix evidence tied to its current decision across older triage writers."""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest
from test_workbench_scan_history import compare_scan_pair, create_cli_scan
from workbench_test_support import get_scan, initialize_git_repository, set_triage


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
