from __future__ import annotations

import json
import signal
import sqlite3
from pathlib import Path

import pytest


def checkpoint_payload():
    example = Path(__file__).resolve().parents[1] / "examples/completed-scan/findings.json"
    finding = json.loads(example.read_text(encoding="utf-8"))["findings"][0]
    return {
        "action": "save",
        "finding": finding,
        "assessment": {
            "findingId": finding["findingId"],
            "occurrenceId": finding.get("occurrenceId"),
            "inputSha256": "a" * 64,
            "rubricSha256": None,
            "knowledgeBaseSha256": None,
            "source": "existing-severity",
            "decision": "assessed",
            "level": "high",
            "rubricLabel": None,
            "rationale": "Inherited the finding's existing severity.",
            "confidence": None,
            "reviewTrigger": None,
        },
        "runId": "synthetic-run",
        "scanId": "synthetic-scan",
    }


def test_full_optional_progress_does_not_discard_the_assessment(
    workbench_api, workbench_db, monkeypatch
):
    timestamp = "2026-09-09T00:00:00Z"
    payload = checkpoint_payload()
    finding = payload["finding"]
    severity = workbench_api["severity"]
    severity.upsert_finding(workbench_db, finding, timestamp)
    workbench_db.commit()
    pages = workbench_db.execute("PRAGMA page_count").fetchone()[0]
    page_size = workbench_db.execute("PRAGMA page_size").fetchone()[0]
    workbench_db.execute(f"PRAGMA max_page_count={pages}")
    write_progress = severity.write_progress
    failures = []

    def capture_full(connection, payload, saved_at):
        assert (
            connection.execute("SELECT COUNT(*) FROM finding_severity_assessments").fetchone()[0]
            == 1
        )
        try:
            write_progress(connection, payload, saved_at)
        except sqlite3.DatabaseError as error:
            failures.append(error.sqlite_errorcode)
            assert not connection.in_transaction
            raise

    monkeypatch.setattr(severity, "write_progress", capture_full)
    result = severity.checkpoint(
        workbench_db,
        {
            **payload,
            "progress": {"status": "running", "details": "x" * (page_size * 2)},
        },
        timestamp,
    )
    assert result == {}
    assert failures == [sqlite3.SQLITE_FULL]
    assert severity.assessments(workbench_db, [finding["findingId"]]) == [
        {**payload["assessment"], "assessedAt": timestamp}
    ]
    assert (
        workbench_db.execute("SELECT COUNT(*) FROM severity_classification_runs").fetchone()[0] == 0
    )
    assert not workbench_db.in_transaction


def test_optional_progress_commit_failure_preserves_the_assessment(tmp_path, workbench_api):
    resource = pytest.importorskip("resource")
    payload = checkpoint_payload()
    timestamp = "2026-09-09T00:00:00Z"
    severity = workbench_api["severity"]
    commit_failures = []

    class Connection(sqlite3.Connection):
        def __exit__(self, *args):
            try:
                return super().__exit__(*args)
            except sqlite3.DatabaseError as error:
                commit_failures.append(error.sqlite_errorname)
                raise

    connection = sqlite3.connect(tmp_path / "workbench.sqlite3", factory=Connection)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA page_size=4096")
        workbench_api["apply_migrations"](connection)
        connection.execute("PRAGMA journal_mode=WAL")
        severity.upsert_finding(connection, payload["finding"], timestamp)
        connection.commit()
        progress = {
            "status": "running",
            "phase": "classification",
            "total": 2,
            "completed": 0,
            "reused": 0,
            "remaining": 2,
            "findingId": payload["finding"]["findingId"],
        }
        severity.checkpoint(
            connection, {**payload, "action": "progress", "progress": progress}, timestamp
        )
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        previous_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        previous_signal = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        try:
            # Two WAL pages fit the assessment; adding the progress page fails
            # during commit, after SQLite has accepted both INSERT statements.
            resource.setrlimit(resource.RLIMIT_FSIZE, (10_000, previous_limit[1]))
            result = severity.checkpoint(
                connection,
                {**payload, "progress": {**progress, "completed": 1, "remaining": 1}},
                timestamp,
            )
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, previous_limit)
            signal.signal(signal.SIGXFSZ, previous_signal)
        assert result == {}
        assert commit_failures == ["SQLITE_IOERR_WRITE"]
        assert severity.assessments(connection, [payload["finding"]["findingId"]]) == [
            {**payload["assessment"], "assessedAt": timestamp}
        ]
        saved = json.loads(
            connection.execute("SELECT progress_json FROM severity_classification_runs").fetchone()[
                0
            ]
        )
        assert saved == progress
    finally:
        connection.close()
