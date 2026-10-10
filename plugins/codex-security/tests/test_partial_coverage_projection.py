from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("worker_count", [1, 2])
@pytest.mark.parametrize("missing_parent_surfaces", [False, True])
@pytest.mark.parametrize("retained_deferred", [False, True])
@pytest.mark.parametrize("idless_surface", [False, True])
def test_missing_projection_keeps_surface_links_and_independent_reviews(
    workbench_api,
    workbench_db,
    publication_scan,
    worker_count,
    missing_parent_surfaces,
    retained_deferred,
    idless_surface,
):
    scan = publication_scan()
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
    worker_surfaces = (
        [{"label": "Background review", "disposition": "reviewed", "receiptRefs": []}]
        if idless_surface
        else []
    ) + [surface]
    reviews, surfaces, deferred_records, originals = [], [], [], {}
    for _ in range(worker_count):
        result = add_worker(workbench_db, scan)
        worker_id = result.parent.name
        reviews.append({"workerId": worker_id, "attempt": 1, "completeness": "partial"})
        if idless_surface:
            surfaces.append(
                {
                    **worker_surfaces[0],
                    "id": f"{worker_id}-attempt-1-surface-1",
                    "provenance": {"workerId": worker_id, "attempt": 1},
                }
            )
        surfaces.append(
            {
                **surface,
                "id": f"{worker_id}-attempt-1-surface-{len(worker_surfaces)}",
                "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
            }
        )
        deferred_records.append(
            {
                **deferred,
                "id": f"{worker_id}-attempt-1-deferred-1",
                "candidateId": f"{worker_id}-attempt-1-candidate-1",
                "surfaceIds": [surfaces[-1]["id"]],
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": deferred["id"],
                    "candidateId": deferred["candidateId"],
                },
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
                        "surfaces": worker_surfaces,
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
                "surfaces": None if missing_parent_surfaces else surfaces,
                "deferred": deferred_records if retained_deferred else [],
                "reviews": reviews,
            }
        )
    )
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
    pending = [item for item in coverage["deferred"] if item.get("reason") == deferred["reason"]]
    assert len(pending) == worker_count
    by_surface_id = {item["id"]: item for item in coverage["surfaces"]}
    for item in pending:
        if not missing_parent_surfaces:
            linked = by_surface_id[item["surfaceIds"][0]]
            assert linked["provenance"]["workerId"] == item["provenance"]["workerId"]
        assert item["provenance"]["attempt"] == 1
        assert item["provenance"]["sourceId"] == deferred["id"]
        assert item["provenance"]["candidateId"] == deferred["candidateId"]
    assert {item["provenance"]["workerId"] for item in pending} == {
        item["workerId"] for item in reviews
    }
    if missing_parent_surfaces:
        # The existing finalizer repairs malformed collections and reports a warning.
        assert coverage["surfaces"] == []
        assert recovered["warnings"]
    else:
        assert len(by_surface_id) == worker_count * len(worker_surfaces)
    assert coverage["completeness"] == "partial"
    assert all(path.read_bytes() == data for path, data in originals.items())
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
