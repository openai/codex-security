from __future__ import annotations

import copy
import json
import uuid
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker, complete
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
        complete=complete,
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


@pytest.mark.parametrize("generation", [None, 3], ids=["legacy-generation-one", "current-lease"])
def test_current_publication_replays_without_changing_checkpoint_or_worker_state(
    workbench_api, workbench_db, publication_scan, generation, monkeypatch
):
    # Keep replay time fixed while comparing the preserved publication bytes.
    instant = workbench_api["now"]()
    monkeypatch.setattr(workbench_api["_WORKBENCH_DB_CONTEXT"], "now", lambda: instant)
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = ?, status = 'running' "
            "WHERE scan_id = ?",
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

    workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, draft
    )
    published = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    }
    replay = workbench_api["saved_results"].write_scan_draft(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, draft
    )

    assert replay == {"scanId": scan.scan_id, "status": "draft_written"}
    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == published
    # Main retains both the submitted checkpoint and its normalized parent snapshot.
    assert len(list((scan.scan_dir / "checkpoints").glob("*.json"))) == 2
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()) == run_before
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_workers").fetchone()) == worker_before
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["title"] == "Accepted aggregate"


def test_legacy_terminal_aggregate_survives_a_late_partial_draft_after_write_failure(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    scan.coverage["completeness"] = "partial"
    scan.coverage["deferred"] = [
        {"id": "remaining-review", "reason": "The bounded scan retained unfinished review."}
    ]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    finalizer_globals = workbench_api["_write_prepared_scan_finalization"].__globals__
    write_bytes = finalizer_globals["write_scan_local_bytes"]

    def fail_report(scan_dir, relative_path, payload, **kwargs):
        if relative_path == "report.md":
            raise finalizer_globals["ContractError"]("Synthetic report write interruption")
        return write_bytes(scan_dir, relative_path, payload, **kwargs)

    with monkeypatch.context() as patch:
        patch.setitem(finalizer_globals, "write_scan_local_bytes", fail_report)
        with pytest.raises(SystemExit, match="Synthetic report write interruption"):
            complete(workbench_api, workbench_db, scan)

    run = workbench_db.execute(
        "SELECT status, coordinator_generation FROM deep_scan_runs WHERE scan_id = ?",
        (scan.scan_id,),
    ).fetchone()
    assert tuple(run) == ("succeeded", 1)
    assert (
        workbench_db.execute(
            "SELECT status, seal_manifest_digest FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == "running"
    )
    saved = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    }
    late = stage_publication(
        scan, generation=None, result_path=None, title="Late incomplete progress", complete=False
    )
    with pytest.raises(SystemExit, match="terminal|publication"):
        workbench_api["saved_results"].write_scan_draft(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, late
        )
    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == saved
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert [finding["title"] for finding in findings] == [scan.findings[0]["title"]]
    assert (
        json.loads((scan.scan_dir / "coverage.json").read_text())["deferred"]
        == scan.coverage["deferred"]
    )
