from __future__ import annotations

import copy
import json
import uuid
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


def stage_publication(scan, *, generation, result_path, title, complete=True):
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
    if not complete:
        draft["manifest"]["scan"]["complete"] = False
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


@pytest.mark.parametrize(
    ("stale", "complete"),
    [
        ("generation", True),
        ("generation", False),
        ("aggregate", True),
        ("aggregate", False),
        ("unfenced", True),
    ],
)
def test_stale_coordinator_cannot_replace_newer_canonical_publication(
    workbench_api, workbench_db, publication_scan, stale, complete
):
    scan = publication_scan()
    old_result = add_worker(workbench_db, scan)
    new_result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 3 WHERE scan_id = ?",
            (scan.scan_id,),
        )
        for sequence, result in enumerate((old_result, new_result), start=1):
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none', "
                "prompt_path = ?, completed_at = ? "
                "WHERE result_manifest_path = ?",
                (
                    str(scan.scan_dir / f"dedup-{sequence:04d}" / "prompt.md"),
                    f"2026-01-0{sequence}",
                    str(result),
                ),
            )
    current = stage_publication(
        scan, generation=3, result_path=new_result, title="Current accepted aggregate"
    )
    workbench_api["write_scan_draft"](workbench_db, current)
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
        complete=complete,
    )

    with pytest.raises(SystemExit, match="coordinator|aggregate"):
        workbench_api["write_scan_draft"](workbench_db, old)

    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == saved


@pytest.mark.parametrize("generation", [None, 3], ids=["legacy-generation-one", "current-lease"])
def test_current_publication_replays_without_changing_checkpoint_or_worker_state(
    workbench_api, workbench_db, publication_scan, generation
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = ? WHERE scan_id = ?",
            (generation or 1, scan.scan_id),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    draft = stage_publication(
        scan, generation=generation, result_path=result, title="Accepted aggregate"
    )
    run_before = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    worker_before = dict(workbench_db.execute("SELECT * FROM deep_scan_workers").fetchone())

    workbench_api["write_scan_draft"](workbench_db, draft)
    published = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    }
    replay = workbench_api["write_scan_draft"](workbench_db, draft)

    assert replay == {"scanId": scan.scan_id, "status": "draft_written"}
    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == published
    assert len(list((scan.scan_dir / "checkpoints").glob("*.json"))) == 1
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()) == run_before
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_workers").fetchone()) == worker_before
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["title"] == "Accepted aggregate"
