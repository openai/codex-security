from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("retained", [False, True])
@pytest.mark.parametrize("source_id", ["legacy", ["legacy"]])
def test_recovery_preserves_exclusion_id_extensions(
    workbench_api, workbench_db, publication_scan, retained, source_id
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    exclusion = {
        "pattern": "vendor/**",
        "reason": "Review dependency separately.",
        "id": source_id,
    }
    projected = {
        **exclusion,
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": source_id},
    }
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "explicitExclusions": [exclusion]},
            }
        )
    )
    original = result.read_bytes()
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "explicitExclusions": [projected] if retained else [],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
            }
        )
    )
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))[
        "scan"
    ]
    assert recovered["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["explicitExclusions"] == [projected]
    assert coverage["completeness"] == "partial"
    assert result.read_bytes() == original
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
