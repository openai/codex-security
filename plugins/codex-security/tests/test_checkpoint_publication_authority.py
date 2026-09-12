from __future__ import annotations

import copy
import json
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import write_checkpoint


@pytest.mark.parametrize("archived", [False, True], ids=["current", "archived"])
@pytest.mark.parametrize("has_head", [True, False], ids=["committed-head", "legacy"])
@pytest.mark.parametrize("complete", [False, True], ids=["checkpoint", "complete"])
def test_recovery_honors_rejection_committed_before_result_replacement(
    workbench_api, workbench_db, publication_scan, archived, has_head, complete
):
    scan = publication_scan()
    provisional = copy.deepcopy(scan.findings[0])
    provisional["extensions"] = {"candidateId": "candidate-rejected"}
    retained = copy.deepcopy(scan.findings[0])
    retained["identity"]["anchor"] = "independent-finding"
    retained["extensions"] = {"candidateId": "candidate-retained"}
    retained["locations"][0]["startLine"] = 20
    retained["locations"][0]["endLine"] = 21
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result_path = add_worker(workbench_db, scan, status="canceled")
    if archived:
        result_path = result_path.parent / "attempts" / "attempt-1" / "result.json"
        result_path.parent.mkdir(parents=True)
    previous = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [provisional, retained],
        "coverage": scan.coverage,
    }
    result_path.write_text(json.dumps(previous))
    old_checkpoint = write_checkpoint(result_path.parent / "checkpoints", previous)
    rejected = {
        **previous,
        "complete": complete,
        "findings": [retained],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-rejected",
                    "label": "Validated candidate disposition",
                    "disposition": "rejected",
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(result_path.parent / "checkpoints", rejected)
    if has_head:
        (result_path.parent / "checkpoint-head.json").write_text(
            json.dumps({"checkpoint": checkpoint.name})
        )
    saved_bytes = {path: path.read_bytes() for path in (result_path, old_checkpoint, checkpoint)}

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert stopped["findingCount"] == len(findings) == (1 if has_head else 2)
    assert any(finding["identity"]["anchor"] == "independent-finding" for finding in findings)
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())
    if has_head:
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert any(
            surface.get("candidateId") == "candidate-rejected"
            and surface.get("disposition") == "rejected"
            for surface in coverage["surfaces"]
        )
