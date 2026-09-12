from __future__ import annotations

import hashlib
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_publication_stop_interleavings import published_bytes
from test_workbench_db import BUDGET_COST


@pytest.mark.parametrize("explicit_ids", [True, False], ids=["named-surfaces", "omitted-ids"])
def test_cost_completion_retains_independent_unmerged_surfaces_and_receipts(
    workbench_api, workbench_db, publication_scan, explicit_ids
):
    scan = publication_scan()
    worker_id = add_worker(workbench_db, scan).parent.name
    output = scan.scan_dir / "artifacts/deep_discovery/workers/discovery-0001/output"
    output.mkdir(parents=True)
    surfaces = [
        {
            "label": "Filesystem boundary",
            "disposition": "needs_follow_up",
            "notes": "Filesystem race remains untested.",
        },
        {
            "label": "Template boundary",
            "disposition": "needs_follow_up",
            "notes": "Template caller policy remains untested.",
        },
    ]
    receipts = {}
    for index, surface in enumerate(surfaces, start=1):
        if explicit_ids:
            surface["id"] = f"source-surface-{index}"
        relative = f"artifacts/review-{index}.md"
        surface["receiptRefs"] = [relative]
        receipt = output / relative
        receipt.parent.mkdir(exist_ok=True)
        receipts[receipt] = f"Independent review receipt {index}.\n".encode()
        receipt.write_bytes(receipts[receipt])
    deferred = {"reason": "Both independent validation tasks remain unfinished."}
    if explicit_ids:
        deferred["surfaceIds"] = [surface["id"] for surface in surfaces]
    contents = json.dumps(
        {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": scan.findings,
            "coverage": {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": surfaces,
                "deferred": [deferred],
            },
        }
    ).encode()
    digest = hashlib.sha256(contents).hexdigest()
    accepted = output / "checkpoints" / f"{digest}.json"
    accepted.parent.mkdir()
    accepted.write_bytes(contents)
    # The mutable result may advance after acceptance. Publication must read the
    # accepted checkpoint, while receipt paths remain relative to its owner.
    result = output / "result.json"
    result.write_text("A later, unaccepted result.")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ?, "
            "prompt_path = ?, merge_state = 'buffered' WHERE id = ?",
            (str(output), str(result), str(output.parent / "prompt.md"), worker_id),
        )
        workbench_db.execute(
            "INSERT INTO deep_scan_attempts (scan_id, worker_id, attempt, status, started_at, "
            "completed_at, accepted_result_path, accepted_result_sha256) "
            "VALUES (?, ?, 1, 'succeeded', ?, ?, ?, ?)",
            (scan.scan_id, worker_id, scan.timestamp, scan.timestamp, str(accepted), digest),
        )
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "workflow_version = 'deep-security-scan/v2', manifest_path = NULL, "
            "terminal_reason = NULL, completed_at = NULL, max_discovery_runs = 100"
        )
    counter_query = (
        "SELECT discovery_runs_dispatched, completion_sequence, consecutive_no_new "
        "FROM deep_scan_runs"
    )
    counters = tuple(workbench_db.execute(counter_query).fetchone())
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()

    workbench_api["complete_budget_exhausted_scan"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            cost_json=json.dumps(BUDGET_COST),
            message="Scan reached its original cost limit.",
        ),
    )

    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "complete"
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    actual = coverage["surfaces"]
    assert [(item["label"], item["notes"]) for item in actual] == [
        (item["label"], item["notes"]) for item in surfaces
    ]
    assert len({item["id"] for item in actual}) == len(surfaces)
    for original, retained in zip(surfaces, actual, strict=True):
        assert retained["provenance"] == {
            "workerId": worker_id,
            "attempt": 1,
            **({"sourceId": original["id"]} if explicit_ids else {}),
        }
        assert retained["receiptRefs"] == [
            (output / ref).relative_to(scan.scan_dir).as_posix() for ref in original["receiptRefs"]
        ]
    for path, receipt_contents in receipts.items():
        assert path.read_bytes() == receipt_contents
    obligation = next(item for item in coverage["deferred"] if item["reason"] == deferred["reason"])
    if explicit_ids:
        assert obligation["surfaceIds"] == [item["id"] for item in actual]
    assert {"workerId": worker_id, "attempt": 1, "completeness": "partial"} in coverage["reviews"]
    report = (scan.scan_dir / "report.md").read_text()
    assert all(surface["notes"] in report for surface in surfaces)
    assert deferred["reason"] in report
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == []
    assert tuple(workbench_db.execute(counter_query).fetchone()) == counters
    attempt = workbench_db.execute(
        "SELECT accepted_result_path, accepted_result_sha256 FROM deep_scan_attempts "
        "WHERE worker_id = ?",
        (worker_id,),
    ).fetchone()
    assert tuple(attempt) == (str(accepted), digest)
    assert accepted.read_bytes() == contents
    before = published_bytes(scan)
    workbench_api["complete_scan"](
        workbench_db, Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None)
    )
    assert published_bytes(scan) == before
    assert accepted.read_bytes() == contents
