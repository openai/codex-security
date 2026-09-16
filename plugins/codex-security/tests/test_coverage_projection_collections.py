from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize(
    "case",
    [
        "raw_null",
        "raw_null_row",
        "raw_idless",
        "raw_bad_id",
        "parent_null",
        "parent_null_row",
        "parent_idless",
        "parent_bad_id",
        "raw_receipts_null",
        "raw_receipts_null_row",
        "raw_receipts_object",
        "raw_links_null",
        "raw_links_null_row",
        "raw_links_object",
        "raw_links_nested",
        "retained_links_null",
        "retained_links_null_row",
        "retained_links_object",
        "retained_links_nested",
        "retained_parent_null",
        "retained_parent_null_row",
        "retained_parent_idless",
        "retained_parent_bad_id",
    ],
)
def test_reviewed_missing_deferred_recovers_malformed_worker_surfaces(
    workbench_api, workbench_db, publication_scan, case
):
    scan = publication_scan()
    worker_count = 1
    surface = {
        "id": "source-surface",
        "label": "Source review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    deferred = {
        "id": "pending-check",
        "reason": "Validation remains unresolved.",
        "candidateId": "pending-candidate",
        "surfaceIds": [surface["id"]],
    }
    reviews, surfaces, originals = [], [], {}
    for _ in range(worker_count):
        result = add_worker(workbench_db, scan)
        worker_id = result.parent.name
        reviews.append({"workerId": worker_id, "attempt": 1, "completeness": "partial"})
        surfaces.append(
            {
                **surface,
                "id": f"{worker_id}-attempt-1-surface-1",
                "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
            }
        )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": True,
                    "findings": [],
                    "coverage": {
                        **scan.coverage,
                        "completeness": "partial",
                        "surfaces": [surface],
                        "deferred": [deferred],
                    },
                }
            )
        )
        originals[result] = result.read_bytes()
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": surfaces,
                "deferred": [],
                "reviews": reviews,
            }
        )
    )
    raw = json.loads(result.read_text())
    parent_path = scan.scan_dir / "coverage.json"
    parent = json.loads(parent_path.read_text())
    retained = {
        **deferred,
        "id": f"{worker_id}-attempt-1-deferred-1",
        "candidateId": f"{worker_id}-attempt-1-candidate-1",
        "surfaceIds": [surfaces[0]["id"]],
        "provenance": {
            "workerId": worker_id,
            "attempt": 1,
            "sourceId": deferred["id"],
            "candidateId": deferred["candidateId"],
        },
    }
    if case.startswith("retained_"):
        parent["deferred"] = [retained]
    target = parent if "parent" in case or case.startswith("retained_links") else raw["coverage"]
    if "links" in case or "receipts" in case:
        values = {
            "null": None,
            "null_row": [None],
            "object": {"legacy": "value"},
            "nested": [["legacy"]],
        }
        suffix = case.split("_", 2)[2]
        field = "surfaceIds" if "links" in case else "receiptRefs"
        collection = "deferred" if "links" in case else "surfaces"
        target[collection][0][field] = values[suffix]
        if case.startswith("retained_links"):
            raw["coverage"][collection][0][field] = values[suffix]
    elif case.endswith("null_row"):
        target["surfaces"] = [None]
    elif case.endswith("null"):
        target["surfaces"] = None
    elif case.endswith("idless"):
        target["surfaces"][0].pop("id")
    elif case.endswith("bad_id"):
        target["surfaces"][0]["id"] = ["legacy"]
    result.write_text(json.dumps(raw))
    originals[result] = result.read_bytes()
    parent_path.write_text(json.dumps(parent))
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            cost_json=None,
            message="Stopped.",
        ),
    )
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))[
        "scan"
    ]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert isinstance(coverage["surfaces"], list)
    assert coverage["completeness"] == "partial"
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    if "links" in case:
        # The existing finalizer drops invalid deferred links and reports them.
        assert pending == []
        assert recovered["warnings"]
    else:
        assert len(pending) == 1
        assert pending[0]["provenance"]["workerId"] == worker_id
        assert pending[0]["provenance"]["attempt"] == 1
    assert all(path.read_bytes() == data for path, data in originals.items())
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
