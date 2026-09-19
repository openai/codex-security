from __future__ import annotations

import hashlib
import json

import pytest
from test_deep_scan_publication_authority import stage_publication
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("publication", ["selected", "mutable", "stale-generation", "unfenced"])
def test_publication_uses_committed_finalization_selection(
    workbench_api, workbench_db, publication_scan, publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    contents = json.dumps(
        {
            "scanId": scan.scan_id,
            "complete": True,
            "findings": scan.findings,
            "coverage": scan.coverage,
        }
    ).encode()
    digest = hashlib.sha256(contents).hexdigest()
    accepted = result.parent / "accepted" / f"{digest}.json"
    accepted.parent.mkdir()
    accepted.write_bytes(contents)
    selection = {
        "version": 1,
        "resultPath": accepted.relative_to(scan.scan_dir).as_posix(),
        "resultSha256": digest,
        "terminalReason": "saturated",
        "omittedWorkerIds": [],
        "selectedAt": scan.timestamp,
    }
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
            "WHERE result_manifest_path = ?",
            (str(result),),
        )
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = ?, finalization_input_json = ?, "
            "workflow_version = 'deep-security-scan/v2' "
            "WHERE scan_id = ?",
            (1 if publication == "unfenced" else 3, json.dumps(selection), scan.scan_id),
        )
    # The accepted bytes survive replacement or deletion of the worker's output.
    result.unlink(missing_ok=True)
    staged = stage_publication(
        scan,
        generation=None
        if publication == "unfenced"
        else 2
        if publication == "stale-generation"
        else 3,
        result_path=result if publication == "mutable" else accepted,
        title="Selected accepted aggregate",
    )
    before = {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")}

    if publication == "selected":
        workbench_api["write_scan_draft"](workbench_db, staged)
        findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
        assert findings[0]["title"] == "Selected accepted aggregate"
    else:
        with pytest.raises(SystemExit, match="coordinator|publication|aggregate"):
            workbench_api["write_scan_draft"](workbench_db, staged)
        assert {path: path.read_bytes() for path in scan.scan_dir.rglob("*.json")} == before
    assert accepted.read_bytes() == contents
    assert (
        json.loads(
            workbench_db.execute(
                "SELECT finalization_input_json FROM deep_scan_runs WHERE scan_id = ?",
                (scan.scan_id,),
            ).fetchone()[0]
        )
        == selection
    )
