from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("host_coverage", [True, False], ids=["accepted-projection", "legacy"])
@pytest.mark.parametrize("parent_draft", [True, False], ids=["parent-draft", "no-parent"])
def test_stopped_recovery_preserves_accepted_coverage_without_worker_id_collisions(
    workbench_api, workbench_db, publication_scan, host_coverage, parent_draft
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    source_coverage = {
        "completeness": "partial",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "reviews": [],
    }
    source_files = []
    for disposition in ("needs_follow_up", "rejected"):
        result = add_worker(workbench_db, scan)
        worker_id = result.parent.name
        surface = {
            "id": "surface-1",
            "candidateId": "candidate-1",
            "label": "Independent review",
            "disposition": disposition,
            "receiptRefs": [],
        }
        deferred = {"candidateId": "candidate-1", "reason": "Validation remains unresolved."}
        coverage = {
            "completeness": "partial" if disposition == "needs_follow_up" else "complete",
            "surfaces": [surface],
            "explicitExclusions": [],
            "deferred": [deferred] if disposition == "needs_follow_up" else [],
        }
        result.write_text(
            json.dumps(
                {"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": coverage}
            )
        )
        source_files.append(result)
        prefix = f"{worker_id}-attempt-1"
        provenance = {"workerId": worker_id, "attempt": 1, "candidateId": "candidate-1"}
        source_coverage["reviews"].append(
            {"workerId": worker_id, "attempt": 1, "completeness": coverage["completeness"]}
        )
        source_coverage["surfaces"].append(
            {
                **surface,
                "id": f"{prefix}-surface-1",
                "provenance": {**provenance, "sourceId": "surface-1"},
            }
        )
        if coverage["deferred"]:
            source_coverage["deferred"].append(
                {
                    **deferred,
                    "id": f"{prefix}-deferred-1",
                    "candidateId": f"{prefix}-candidate-1",
                    "provenance": provenance,
                }
            )
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
            "WHERE result_manifest_path = ?",
            (str(reducer),),
        )
    aggregate = {"scanId": scan.scan_id, "complete": True, "findings": []}
    if host_coverage:
        aggregate["sourceCoverage"] = copy.deepcopy(source_coverage)
    reducer.write_text(json.dumps(aggregate))
    source_files.append(reducer)
    saved_bytes = {path: path.read_bytes() for path in source_files}
    if not parent_draft:
        for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / filename).unlink()

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    assert stopped["progress"]["status"] == "failed"
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert len(coverage["deferred"]) == 2
    assert coverage["deferred"][-1]["id"] == "scan-stopped"
    assert len(coverage["surfaces"]) == 2
    if host_coverage:
        for field in ("reviews", "surfaces", "deferred"):
            assert (
                coverage[field][:-1] if field == "deferred" else coverage[field]
            ) == source_coverage[field]
    else:
        assert coverage["deferred"][0]["candidateId"] == "candidate-1"
    manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    workbench_api["preserve_scan_results"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())


def test_stopped_recovery_keeps_unmerged_coverage_after_accepted_review(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    accepted = add_worker(workbench_db, scan)
    accepted.write_text(
        json.dumps(
            {"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": scan.coverage}
        )
    )
    reducer = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
            "WHERE result_manifest_path = ?",
            (str(reducer),),
        )
    reviews = [{"workerId": accepted.parent.name, "attempt": 1, "completeness": "complete"}]
    reducer.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "sourceCoverage": {**scan.coverage, "reviews": reviews},
            }
        )
    )
    pending = add_worker(workbench_db, scan, status="canceled")
    deferred = {"id": "pending-review", "reason": "The independent review remains unresolved."}
    pending.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": False,
                "findings": [],
                "coverage": {**scan.coverage, "completeness": "partial", "deferred": [deferred]},
            }
        )
    )

    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["reviews"] == reviews
    assert deferred in coverage["deferred"]
