from __future__ import annotations

import copy
import json
import uuid
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import add_worker, complete
from test_deep_scan_successful_publication import publication_scan as publication_scan


def stage_publication(scan, *, generation, result_path, title):
    draft_dir = scan.scan_dir / "drafts"
    draft_dir.mkdir(exist_ok=True)
    draft_path = draft_dir / f"{uuid.uuid4()}.json"
    checkpoint_path = draft_dir / f"{uuid.uuid4()}.checkpoint.json"
    findings = copy.deepcopy(scan.findings)
    findings[0]["title"] = title
    draft = {
        "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
        "findings": {"findings": findings},
        "coverage": scan.coverage,
    }
    if generation is not None:
        draft["deepScanPublication"] = {
            "coordinatorGeneration": generation,
            "resultPath": str(result_path),
        }
    draft_path.write_text(json.dumps(draft))
    checkpoint_path.write_text(
        json.dumps({"scanId": scan.scan_id, "findings": findings, "coverage": scan.coverage})
    )
    return Namespace(
        scan_id=scan.scan_id,
        claim_token=None,
        draft_path=str(draft_path),
        checkpoint_path=str(checkpoint_path),
        expected_draft_digest=None,
    )


@pytest.mark.parametrize("stale", ["generation", "aggregate", "unfenced"])
def test_stale_coordinator_cannot_replace_newer_canonical_publication(
    workbench_api, workbench_db, publication_scan, stale
):
    scan = publication_scan()
    old_result = add_worker(workbench_db, scan)
    new_result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 3 WHERE scan_id = ?",
            (scan.scan_id,),
        )
        for result, completed_at in ((old_result, "2026-01-01"), (new_result, "2026-01-02")):
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none', completed_at = ? "
                "WHERE result_manifest_path = ?",
                (completed_at, str(result)),
            )
    current = stage_publication(
        scan, generation=3, result_path=new_result, title="Current accepted aggregate"
    )
    workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, current
    )
    saved = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    }
    old = stage_publication(
        scan,
        generation=None if stale == "unfenced" else 2 if stale == "generation" else 3,
        result_path=old_result if stale == "aggregate" else new_result,
        title="Superseded aggregate",
    )

    with pytest.raises(SystemExit, match="coordinator|aggregate"):
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, old
        )

    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == saved


@pytest.mark.parametrize(
    ("run_status", "accepted_complete", "draft_complete", "rejected"),
    [
        ("succeeded", True, False, True),
        ("running", True, False, False),
        ("succeeded", None, False, False),
        ("succeeded", True, True, False),
    ],
)
def test_legacy_partial_draft_preserves_accepted_completion(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    run_status,
    accepted_complete,
    draft_complete,
    rejected,
):
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = ? WHERE scan_id = ?",
            (run_status, scan.scan_id),
        )
    if accepted_complete is not None:
        result = add_worker(workbench_db, scan)
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' "
                "WHERE result_manifest_path = ?",
                (str(result),),
            )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan.scan_id,
                    "complete": accepted_complete,
                    "findings": scan.findings,
                    "sourceCoverage": scan.coverage,
                }
            )
        )
    if rejected:
        finalizer = workbench_api["_write_prepared_scan_finalization"].__globals__
        write_bytes = finalizer["write_scan_local_bytes"]

        def fail_report(root, relative_path, payload, **kwargs):
            if relative_path == "report.md":
                raise finalizer["ContractError"]("Synthetic report write interruption")
            return write_bytes(root, relative_path, payload, **kwargs)

        with monkeypatch.context() as patch:
            patch.setitem(finalizer, "write_scan_local_bytes", fail_report)
            with pytest.raises(SystemExit, match="Synthetic report write interruption"):
                complete(workbench_api, workbench_db, scan)
    args = stage_publication(scan, generation=None, result_path=None, title="Legacy aggregate")
    draft = json.loads(Path(args.draft_path).read_text())
    draft["manifest"]["scan"]["complete"] = draft_complete
    Path(args.draft_path).write_text(json.dumps(draft))
    artifact_names = ("scan-manifest.json", "findings.json", "coverage.json")
    before = {name: (scan.scan_dir / name).read_bytes() for name in artifact_names}
    writer = workbench_api["saved_results"].write_scan_draft
    if rejected:
        with pytest.raises(SystemExit, match="accepted complete"):
            writer(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args)
        assert {name: (scan.scan_dir / name).read_bytes() for name in artifact_names} == before
        assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"
    else:
        assert writer(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args)["status"] == (
            "draft_written"
        )
