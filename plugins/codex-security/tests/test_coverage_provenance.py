from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("retained", [False, True], ids=["missing", "retained"])
@pytest.mark.parametrize("optional_ids", [False, True], ids=["absent-ids", "present-ids"])
@pytest.mark.parametrize("field", ["surfaces", "deferred", "explicitExclusions", "openQuestions"])
def test_recovery_preserves_descriptive_provenance(
    workbench_api, workbench_db, publication_scan, retained, optional_ids, field
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    prefix = f"{worker_id}-attempt-1"
    descriptions = {
        "description": "Synthetic source note.",
        "details": {"basis": ["source review"], "resolved": False},
        "optional": None,
    }
    imported = {
        **descriptions,
        "workerId": "imported-worker",
        "attempt": 999,
        "sourceId": "imported-source",
        "candidateId": "imported-candidate",
    }
    records = {
        "surfaces": {
            "id": "source-surface",
            "label": "Synthetic surface",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        },
        "deferred": {
            "id": "source-deferred",
            "reason": "Synthetic follow-up remains unresolved.",
            "surfaceIds": ["source-surface"],
        },
        "explicitExclusions": {"pattern": "vendor/**", "reason": "Review separately."},
        "openQuestions": {"question": "Which deployment controls apply?"},
    }
    item = records[field]
    if optional_ids:
        item.setdefault("id", "source-record")
        item["candidateId"] = "source-candidate"
    item["provenance"] = copy.deepcopy(imported)
    expected = copy.deepcopy(item)
    expected["provenance"] = {**descriptions, "workerId": worker_id, "attempt": 1}
    if "id" in item:
        expected["provenance"]["sourceId"] = item["id"]
    if optional_ids:
        expected["provenance"]["candidateId"] = "source-candidate"
    if field == "surfaces":
        expected["id"] = f"{prefix}-surface-1"
    elif field == "deferred":
        expected["id"] = f"{prefix}-deferred-1"
        expected["surfaceIds"] = [f"{prefix}-surface-1"]
        if optional_ids:
            expected["candidateId"] = f"{prefix}-candidate-1"
    source_coverage = {**scan.coverage, field: [item]}
    if field == "deferred":
        source_coverage["surfaces"] = [records["surfaces"]]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": source_coverage,
            }
        )
    )
    original = result.read_bytes()
    parent = {
        **scan.coverage,
        field: [expected] if retained else [],
        "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
    }
    if field == "deferred" and retained:
        parent["surfaces"] = [
            {
                **records["surfaces"],
                "id": f"{prefix}-surface-1",
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": "source-surface",
                },
            }
        ]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(parent))
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    published = (scan.scan_dir / "coverage.json").read_bytes()
    coverage = json.loads(published)
    actual = coverage[field]
    if field == "deferred":
        actual = [record for record in actual if record.get("id") != "scan-stopped"]
        assert actual[0]["surfaceIds"] == [coverage["surfaces"][0]["id"]]
    assert coverage["completeness"] == "partial"
    assert result.read_bytes() == original
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
    assert result.read_bytes() == original
    if field == "explicitExclusions" and not retained and not optional_ids:
        assert actual[0].pop("id").startswith("saved-")
    assert actual == [expected]
