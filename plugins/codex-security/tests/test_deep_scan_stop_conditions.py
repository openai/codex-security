from __future__ import annotations

import json
import os
import sqlite3
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
from workbench_test_support import saved_draft, write_checkpoint


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


@pytest.mark.parametrize("existing_head", [False, True])
def test_rejected_deadline_publication_does_not_leave_parent_observations(
    workbench_api, workbench_db, publication_scan, existing_head
):
    scan = publication_scan()
    canonical_names = ("scan-manifest.json", "findings.json", "coverage.json")
    for name in canonical_names:
        os.utime(scan.scan_dir / name, ns=(1_000_000_000, 1_000_000_000))
    pending = {"id": "authorization-review", "reason": "Review the remaining authorization path."}
    if existing_head:
        checkpoint = write_checkpoint(
            scan.scan_dir / "checkpoints",
            saved_draft(scan.scan_id, findings=scan.findings, deferred=[pending]),
        )
        head = scan.scan_dir / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        for path in (checkpoint, head):
            os.utime(path, ns=(2_000_000_000, 2_000_000_000))
    from workbench.saved_sources import _saved_result_paths

    def observations():
        return {
            relative: (
                (scan.scan_dir / relative).read_bytes(),
                (scan.scan_dir / relative).stat().st_mtime_ns,
            )
            for relative, _ in _saved_result_paths(scan.scan_dir, [])
            if (scan.scan_dir / relative).is_file()
        }

    before = observations()
    artifacts = {
        name: ((scan.scan_dir / name).read_bytes(), (scan.scan_dir / name).stat().st_mtime_ns)
        for name in canonical_names
    }
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "created_at = '2000-01-01T00:00:00+00:00', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "CREATE TRIGGER reject_deadline_commit BEFORE UPDATE OF status ON deep_scan_runs "
            "WHEN NEW.status = 'succeeded' BEGIN SELECT RAISE(ABORT, 'deadline commit failed'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="deadline commit failed"):
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert observations() == before
    assert {
        name: ((scan.scan_dir / name).read_bytes(), (scan.scan_dir / name).stat().st_mtime_ns)
        for name in artifacts
    } == artifacts
    assert (
        workbench_db.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == "running"
    )
    with workbench_db:
        workbench_db.execute("DROP TRIGGER reject_deadline_commit")
    assert (
        finish(workbench_api, workbench_db, scan, terminal_reason="capped")["status"] == "succeeded"
    )
    if existing_head:
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert any(item["reason"] == pending["reason"] for item in coverage["deferred"])


def test_zero_accepted_deadline_preserves_worker_checkpoint_links_and_receipts(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    workers = {}
    originals = {}
    for name in ("first", "second"):
        result = add_worker(workbench_db, scan, status="canceled")
        worker_id = result.parent.name
        output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
        output.parent.mkdir(parents=True)
        result.parent.rename(output)
        result = output / result.name
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? "
                "WHERE id = ?",
                (str(output), str(result), worker_id),
            )
        receipt = result.parent / "artifacts" / "review.md"
        receipt.parent.mkdir()
        receipt.write_text(f"Synthetic {name} source review.\n")
        checkpoint = write_checkpoint(
            result.parent / "checkpoints",
            saved_draft(
                scan.scan_id,
                complete=False,
                surfaces=[
                    {
                        "id": "api",
                        "label": name,
                        "disposition": "no_issue_found",
                        "receiptRefs": ["artifacts/review.md"],
                    }
                ],
                deferred=[{"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}],
            ),
        )
        head = result.parent / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        workers[worker_id] = receipt
        originals.update({path: path.read_bytes() for path in (receipt, checkpoint, head)})
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workers = 2, max_discovery_runs = 3, discovery_runs_dispatched = 2, "
            "created_at = '2000-01-01T00:00:00+00:00', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )

    finished = finish(workbench_api, workbench_db, scan, terminal_reason="capped")

    assert finished["status"] == "succeeded"
    assert finished["completionSequence"] == 0
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert {row["id"] for row in coverage["surfaces"]} == {
        f"{worker_id}/api" for worker_id in workers
    }
    for worker_id, receipt in workers.items():
        surface = next(row for row in coverage["surfaces"] if row["workerId"] == worker_id)
        task = next(row for row in coverage["deferred"] if row.get("workerId") == worker_id)
        assert surface["disposition"] == "no_issue_found"
        assert surface["receiptRefs"] == [receipt.relative_to(scan.scan_dir).as_posix()]
        assert task["id"] == f"{worker_id}/review"
        assert task["surfaceIds"] == [surface["id"]]
    assert all(path.read_bytes() == contents for path, contents in originals.items())
