"""Exercise durable dependency task ownership across independent clients."""

from __future__ import annotations

import argparse
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from test_dependency_import_workbench import record, result, setup_report, start
from workbench_test_support import run_workbench


def claim(
    state: Path,
    report_id: str,
    assessment_id: str,
    *,
    account_id: str | None = "account-a",
    host_id: str = "local",
    finding_id: str | None = None,
    retry_attempt_id: str | None = None,
    check: bool = True,
) -> dict[str, Any]:
    """Claim through the same command boundary used by separate MCP clients."""
    return run_workbench(
        state,
        "claim-dependency-task-launch",
        "--report-id",
        report_id,
        "--assessment-id",
        assessment_id,
        "--host-id",
        host_id,
        "--kind",
        "fix" if finding_id else "assessment",
        *(["--account-id", account_id] if account_id is not None else []),
        *(["--finding-id", finding_id] if finding_id else []),
        *(["--retry-attempt-id", retry_attempt_id] if retry_attempt_id else []),
        check=check,
    )


def settle(
    state: Path,
    launch: dict[str, Any],
    status: str,
    *,
    thread_id: str | None = None,
    check: bool = True,
) -> dict[str, Any]:
    """Settle a captured attempt without reading a newer token first."""
    return run_workbench(
        state,
        "settle-dependency-task-launch",
        "--launch-id",
        launch["id"],
        "--attempt-id",
        launch["attemptId"],
        "--host-id",
        launch["hostId"],
        "--status",
        status,
        *(["--account-id", launch["accountId"]] if launch["accountId"] is not None else []),
        *(["--thread-id", thread_id] if thread_id else []),
        check=check,
    )


def history(state: Path, report_id: str, *, account_id: str = "account-a") -> dict[str, Any]:
    """Reopen persisted report history from another process."""
    return run_workbench(
        state,
        "get-dependency-task-launches",
        "--report-id",
        report_id,
        "--account-id",
        account_id,
        "--host-id",
        "local",
    )


def test_claim_serializes_clients_and_isolates_scope(tmp_path: Path) -> None:
    """Exactly one client may launch each account/host/assessment identity."""
    _, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    for account_id in (None, "account-a"):
        with ThreadPoolExecutor(max_workers=4) as executor:
            requests = [
                executor.submit(claim, state, report_id, assessment_id, account_id=account_id)
                for _ in range(4)
            ]
            claims = [request.result() for request in requests]
        assert sum(item["claimed"] for item in claims) == 1
        assert len({item["launch"]["attemptId"] for item in claims}) == 1
        assert all(item["launch"]["accountId"] == account_id for item in claims)
    remote = claim(state, report_id, assessment_id, host_id="remote")
    assert remote["claimed"] is True
    assert len(history(state, report_id)["launches"]) == 1
    assert history(state, report_id, account_id="different")["launches"] == []
    wrong_scope = {**remote["launch"], "accountId": "different"}
    assert "not found" in settle(state, wrong_scope, "failed", check=False)["stderr"]


def test_recovery_checks_attempt_and_keeps_known_link(tmp_path: Path) -> None:
    """Unknown attempts need explicit recovery and old callbacks cannot erase links."""
    _, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    first = claim(state, report_id, assessment_id)["launch"]
    assert claim(state, report_id, assessment_id)["claimed"] is False
    recovered = claim(state, report_id, assessment_id, retry_attempt_id=first["attemptId"])
    assert recovered["claimed"] is True
    second = recovered["launch"]
    assert second["attemptId"] != first["attemptId"]
    assert "stale" in settle(state, first, "settled", thread_id="late", check=False)["stderr"]
    assert (
        "changed"
        in claim(
            state,
            report_id,
            assessment_id,
            retry_attempt_id=first["attemptId"],
            check=False,
        )["stderr"]
    )
    settle(state, second, "outcome_unknown")
    assert history(state, report_id)["launches"][0]["status"] == "outcome_unknown"
    assert claim(state, report_id, assessment_id)["claimed"] is False
    third = claim(
        state,
        report_id,
        assessment_id,
        retry_attempt_id=second["attemptId"],
    )["launch"]
    settle(state, third, "failed")
    assert settle(state, third, "outcome_unknown")["launch"]["status"] == "failed"
    fourth = claim(state, report_id, assessment_id)["launch"]
    assert fourth["attemptId"] != third["attemptId"]
    assert "stale" in settle(state, third, "failed", check=False)["stderr"]
    settle(state, fourth, "failed")
    known = settle(state, fourth, "settled", thread_id="saved-task")["launch"]
    assert settle(state, fourth, "outcome_unknown")["launch"] == known
    assert settle(state, fourth, "failed")["launch"] == known
    assert (
        "cannot be replaced"
        in settle(
            state,
            fourth,
            "settled",
            thread_id="another-task",
            check=False,
        )["stderr"]
    )
    assert (
        "already has a task"
        in claim(
            state,
            report_id,
            assessment_id,
            retry_attempt_id=fourth["attemptId"],
            check=False,
        )["stderr"]
    )
    assert history(state, report_id)["launches"] == [known]


def test_history_migrates_and_retains_all_assessments(tmp_path: Path) -> None:
    """An existing report survives migration and reopening keeps its full history."""
    _, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("DROP TABLE dependency_task_launches")
        connection.execute("DELETE FROM schema_migrations WHERE version = 43")
        for _ in range(105):
            connection.execute(
                "INSERT INTO dependency_assessments SELECT ?, report_id, finding_ids_json, "
                "target_revision, target_snapshot_digest, claims_json, state, created_at, results_json "
                "FROM dependency_assessments WHERE id = ?",
                (str(uuid.uuid4()), assessment_id),
            )
    launch = claim(state, report_id, assessment_id)["launch"]
    settle(state, launch, "settled", thread_id="saved-task")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for (saved_id,) in connection.execute(
            "SELECT id FROM dependency_assessments WHERE id != ?", (assessment_id,)
        ).fetchall():
            connection.execute(
                "INSERT INTO dependency_task_launches SELECT ?, account_id, host_id, report_id, "
                "kind, ?, finding_id, ?, status, ?, error, created_at, updated_at "
                "FROM dependency_task_launches WHERE id = ?",
                (str(uuid.uuid4()), saved_id, str(uuid.uuid4()), f"task-{saved_id}", launch["id"]),
            )
    reopened = history(state, report_id)
    assert len(reopened["assessments"]) == 106
    assert len(reopened["launches"]) == 106
    assert assessment_id in {item["id"] for item in reopened["assessments"]}
    assert all(
        item["createdAt"] and item["reportId"] == report_id for item in reopened["assessments"]
    )
    assert (
        next(item for item in reopened["launches"] if item["id"] == launch["id"])["threadId"]
        == "saved-task"
    )


def test_claim_validates_report_and_saved_assessment_ownership(tmp_path: Path) -> None:
    """A fix must use this report's finding and its latest saved assessment."""
    target, state, report_id, findings = setup_report(tmp_path)
    finding_id, other_id = [item["id"] for item in findings]
    first_id = start(state, report_id, [finding_id])["assessment"]["id"]
    other_report = run_workbench(
        state,
        "import-dependency-findings",
        "--target-path",
        str(target),
        "--report-path",
        str(tmp_path / "scanner.json"),
        "--vendor",
        "snyk",
    )["report"]["id"]
    assert (
        "does not belong"
        in claim(
            state,
            other_report,
            first_id,
            check=False,
        )["stderr"]
    )
    record(tmp_path, state, first_id, [result(finding_id, target)])
    assert (
        "Confirm this finding"
        in claim(
            state,
            report_id,
            first_id,
            finding_id=other_id,
            check=False,
        )["stderr"]
    )
    second_id = start(state, report_id, [finding_id])["assessment"]["id"]
    record(tmp_path, state, second_id, [result(finding_id, target)])
    assert (
        "different saved assessment"
        in claim(
            state,
            report_id,
            first_id,
            finding_id=finding_id,
            check=False,
        )["stderr"]
    )
    assert claim(state, report_id, second_id, finding_id=finding_id)["claimed"] is True
    assert "already complete" in claim(state, report_id, second_id, check=False)["stderr"]


def test_launch_and_recovery_require_current_evidence(tmp_path: Path) -> None:
    """Launching or recovering a task rechecks snapshots and resolver evidence."""
    target, state, report_id, findings = setup_report(tmp_path)
    finding_id = findings[0]["id"]
    ignored = target / "installed.json"
    (target / ".git" / "info" / "exclude").write_text("installed.json\n")
    ignored.write_text("installed-version-one\n")
    assessment_id = start(state, report_id, [finding_id])["assessment"]["id"]
    launch = claim(state, report_id, assessment_id)["launch"]
    source = (target / "app.js").read_text()
    (target / "app.js").write_text(source + "// changed\n")
    assert (
        "repository changed"
        in claim(
            state,
            report_id,
            assessment_id,
            retry_attempt_id=launch["attemptId"],
            check=False,
        )["stderr"]
    )
    assert (
        "repository changed"
        in claim(
            state,
            report_id,
            assessment_id,
            host_id="remote",
            check=False,
        )["stderr"]
    )
    (target / "app.js").write_text(source)
    record(
        tmp_path, state, assessment_id, [result(finding_id, target, input_path="installed.json")]
    )
    fix = claim(state, report_id, assessment_id, finding_id=finding_id)["launch"]
    ignored.write_text("installed-version-two\n")
    assert (
        "resolver input changed"
        in claim(
            state,
            report_id,
            assessment_id,
            finding_id=finding_id,
            retry_attempt_id=fix["attemptId"],
            check=False,
        )["stderr"]
    )
    assert (
        "resolver input changed"
        in claim(
            state,
            report_id,
            assessment_id,
            finding_id=finding_id,
            host_id="remote",
            check=False,
        )["stderr"]
    )
    assert claim(state, report_id, assessment_id, finding_id=finding_id)["launch"] == fix


@pytest.mark.parametrize("kind", ["assessment", "fix"])
def test_launch_snapshot_allows_competing_writer(
    tmp_path: Path, workbench_api: dict[str, Any], monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """Repository checks leave SQLite writable and existing tasks skip those checks."""
    target, state, report_id, findings = setup_report(tmp_path)
    finding_id = findings[0]["id"]
    assessment_id = start(state, report_id, [finding_id])["assessment"]["id"]
    if kind == "fix":
        record(tmp_path, state, assessment_id, [result(finding_id, target)])
    api = workbench_api["dependency_imports"]
    snapshot = api._snapshot
    database = state / "workbench.sqlite3"

    def snapshot_with_writer(path: Path) -> tuple[str, str]:
        with sqlite3.connect(database, timeout=0) as writer:
            writer.execute(
                "UPDATE dependency_reports SET report_name = 'renamed-by-another-client'"
            )
        return snapshot(path)

    monkeypatch.setattr(api, "_snapshot", snapshot_with_writer)
    args = argparse.Namespace(
        account_id="account-a",
        host_id="local",
        report_id=report_id,
        kind=kind,
        assessment_id=assessment_id,
        finding_id=finding_id if kind == "fix" else None,
        retry_attempt_id=None,
    )
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        first = api.claim_task_launch(connection, args)
        assert first["claimed"] is True
        assert connection.execute("SELECT report_name FROM dependency_reports").fetchone()[0] == (
            "renamed-by-another-client"
        )

        def stale_repository(path: Path) -> tuple[str, str]:
            raise AssertionError(
                "Existing pending and known task links must skip repository reads."
            )

        monkeypatch.setattr(api, "_snapshot", stale_repository)
        assert api.claim_task_launch(connection, args) == {**first, "claimed": False}
        known = api.settle_task_launch(
            connection,
            argparse.Namespace(
                account_id=args.account_id,
                host_id=args.host_id,
                launch_id=first["launch"]["id"],
                attempt_id=first["launch"]["attemptId"],
                status="settled",
                thread_id="saved-task",
                error=None,
            ),
        )
        assert api.claim_task_launch(connection, args) == {**known, "claimed": False}


@pytest.mark.parametrize("changed", ["assessment", "finding", "attempt"])
def test_launch_rechecks_database_after_snapshot(
    tmp_path: Path, workbench_api: dict[str, Any], monkeypatch: pytest.MonkeyPatch, changed: str
) -> None:
    """A concurrent completion, replacement assessment, or retry invalidates the claim."""
    target, state, report_id, findings = setup_report(tmp_path)
    finding_id = findings[0]["id"]
    assessment_id = start(state, report_id, [finding_id])["assessment"]["id"]
    replacement_id = assessment_id
    retry_attempt_id = None
    if changed == "finding":
        record(tmp_path, state, assessment_id, [result(finding_id, target)])
        replacement_id = start(state, report_id, [finding_id])["assessment"]["id"]
    elif changed == "attempt":
        retry_attempt_id = claim(state, report_id, assessment_id)["launch"]["attemptId"]
    api = workbench_api["dependency_imports"]
    snapshot = api._snapshot

    def snapshot_with_changed_owner(path: Path) -> tuple[str, str]:
        captured = snapshot(path)
        if changed == "attempt":
            claim(state, report_id, assessment_id, retry_attempt_id=retry_attempt_id)
        else:
            record(tmp_path, state, replacement_id, [result(finding_id, target)])
        return captured

    monkeypatch.setattr(api, "_snapshot", snapshot_with_changed_owner)
    args = argparse.Namespace(
        account_id="account-a",
        host_id="local",
        report_id=report_id,
        kind="fix" if changed == "finding" else "assessment",
        assessment_id=assessment_id,
        finding_id=finding_id if changed == "finding" else None,
        retry_attempt_id=retry_attempt_id,
    )
    message = {
        "assessment": "assessment changed during launch checks",
        "finding": "saved assessment changed",
        "attempt": "attempt changed",
    }[changed]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        with pytest.raises(ValueError, match=message):
            api.claim_task_launch(connection, args)
        rows = connection.execute("SELECT attempt_id FROM dependency_task_launches").fetchall()
        if changed == "attempt":
            assert len(rows) == 1 and rows[0]["attempt_id"] != retry_attempt_id
        else:
            assert rows == []
