from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import (
    add_worker,
    assert_published_aggregate,
    complete,
)
from test_deep_scan_successful_publication import (
    publication_scan as publication_scan,
)


@pytest.fixture
def saturated_scan(publication_scan, workbench_db):
    scan = publication_scan()
    completed_result = add_worker(workbench_db, scan)
    completed_result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "coverage": scan.coverage,
            }
        )
    )
    reducer_result = add_worker(workbench_db, scan)
    reducer_result.write_bytes(completed_result.read_bytes())
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET completion_sequence = 1 WHERE id = ?",
            (completed_result.parent.name,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
            (reducer_result.parent.name,),
        )
        workbench_db.execute(
            "INSERT INTO deep_scan_dedup_inputs "
            "(scan_id, dedup_worker_id, discovery_worker_id, input_order) VALUES (?, ?, ?, 0)",
            (scan.scan_id, reducer_result.parent.name, completed_result.parent.name),
        )
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "consecutive_no_new = stop_after_no_new, completion_sequence = 1, "
            "max_discovery_runs = 3, discovery_runs_dispatched = 1, "
            "manifest_path = NULL, terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    scan.completed_worker_id = completed_result.parent.name
    scan.reducer_id = reducer_result.parent.name
    return scan


def finish(workbench_api, connection, scan, *, terminal_reason="saturated"):
    return workbench_api["deep_scan"].finish_deep_scan(
        connection,
        Namespace(
            scan_id=scan.scan_id,
            terminal_reason=terminal_reason,
            manifest_path=str(scan.scan_dir / "scan-manifest.json"),
            staged_manifest_path=None,
            omitted_worker_id=[],
        ),
    )["deepScan"]


def test_saturated_finish_cancels_unfinished_discovery_without_using_its_drafts(
    workbench_api, workbench_db, saturated_scan
):
    scan = saturated_scan
    unfinished = []
    for status in ("queued", "running"):
        result = add_worker(workbench_db, scan, status=status)
        result.write_text("{unfinished worker draft")
        unfinished.append(result)

    finished = finish(workbench_api, workbench_db, scan)

    assert finished["status"] == "succeeded"
    assert finished["terminalReason"] == "saturated"
    workers = {worker["id"]: worker for worker in finished["workers"]}
    assert workers[scan.completed_worker_id]["status"] == "succeeded"
    assert workers[scan.reducer_id]["status"] == "succeeded"
    for result in unfinished:
        worker = workers[result.parent.name]
        assert worker["status"] == "canceled"
        assert worker["completedAt"] is not None
        assert worker["completionSequence"] is None
        assert worker["mergeState"] == "none"
        assert result.read_text() == "{unfinished worker draft"

    complete(workbench_api, workbench_db, scan)
    assert_published_aggregate(scan)


def test_saturated_finish_retains_failed_discovery_diagnostic(
    workbench_api, workbench_db, saturated_scan
):
    scan = saturated_scan
    result = add_worker(workbench_db, scan, status="failed")
    error = "Worker stopped while persisting its result."
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET error_message = ? WHERE id = ?",
            (error, result.parent.name),
        )

    finished = finish(workbench_api, workbench_db, scan)

    assert finished["status"] == "succeeded"
    failed_worker = next(
        worker for worker in finished["workers"] if worker["id"] == result.parent.name
    )
    assert failed_worker["status"] == "failed"
    assert failed_worker["error"] == error
    complete(workbench_api, workbench_db, scan)
    assert_published_aggregate(scan)


@pytest.mark.parametrize(
    ("terminal_reason", "kind"),
    [("saturated", "setup"), ("saturated", "dedup"), ("capped", "discovery")],
    ids=["saturated-setup", "saturated-reducer", "capped-discovery"],
)
def test_finish_preserves_other_worker_failure_checks(
    workbench_api, workbench_db, saturated_scan, terminal_reason, kind
):
    scan = saturated_scan
    result = add_worker(workbench_db, scan, status="failed")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = ? WHERE id = ?", (kind, result.parent.name)
        )
        if terminal_reason == "capped":
            workbench_db.execute(
                "UPDATE deep_scan_runs SET discovery_runs_dispatched = max_discovery_runs "
                "WHERE scan_id = ?",
                (scan.scan_id,),
            )

    with pytest.raises(SystemExit, match="after a worker has failed"):
        finish(workbench_api, workbench_db, scan, terminal_reason=terminal_reason)

    run = workbench_db.execute(
        "SELECT status, terminal_reason FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
    ).fetchone()
    assert tuple(run) == ("running", None)
