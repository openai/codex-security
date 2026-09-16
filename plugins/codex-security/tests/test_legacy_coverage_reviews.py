from __future__ import annotations

import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import complete
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("reviews", [1, 3])
@pytest.mark.parametrize("stopped", [False, True], ids=["completion", "recovery"])
def test_standard_publication_preserves_legacy_review_extension(
    workbench_api, workbench_db, publication_scan, reviews, stopped
):
    scan = publication_scan(mode="standard")
    scan.coverage["reviews"] = reviews
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    if stopped:
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
        published = workbench_api["recover_scan_results"](
            workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
    else:
        published = complete(workbench_api, workbench_db, scan)
    assert published["findingCount"] == 1
    assert published["resultsRecoveryNeeded"] is False
    assert json.loads((scan.scan_dir / "coverage.json").read_text())["reviews"] == reviews
    assert (scan.scan_dir / "report.md").is_file()
