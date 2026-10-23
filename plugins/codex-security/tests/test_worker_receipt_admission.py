from __future__ import annotations

import copy
import hashlib
import json
import os
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_partial_coverage_projection import stop_and_recover_projection
from test_saved_deferred_identity import recover, save_worker
from workbench_test_support import saved_draft, write_checkpoint


@pytest.mark.parametrize("reordered", [False, True])
@pytest.mark.parametrize("changed_notes", [False, True])
def test_unselected_pending_checkpoint_links_to_accepted_worker_surface(
    tmp_path: Path, reordered, changed_notes
):
    import workbench_saved_results as saved

    surface = {
        "id": "api",
        "label": "API boundary",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    surfaces = (
        [{**surface, "id": "other", "label": "Other boundary"}, surface] if reordered else [surface]
    )
    accepted = saved_draft("identity-scan", surfaces=surfaces, complete=True)
    worker = save_worker(tmp_path, saved, "reviewer", [], accepted)
    output = tmp_path / "reviewer"
    result_path = output / "result.json"
    selected = write_checkpoint(output / "checkpoints", accepted)
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    for path in (selected, result_path, head):
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
    pending = copy.deepcopy(accepted)
    pending["complete"] = False
    pending["coverage"]["surfaces"].reverse()
    if changed_notes:
        for row in pending["coverage"]["surfaces"]:
            row["notes"] = "Additional review context"
    pending["coverage"]["deferred"] = [
        {"id": "task", "reason": "Check boundary", "surfaceIds": ["api"]}
    ]
    unselected = write_checkpoint(output / "checkpoints", pending)
    os.utime(unselected, ns=(2_000_000_000, 2_000_000_000))
    originals = {path: path.read_bytes() for path in output.rglob("*.json")}
    worker.update(status="succeeded", result_manifest_path=str(result_path))
    recovered = recover(tmp_path, saved, [worker])
    replay = recover(tmp_path, saved, [worker], recovered[0]["scan"]["preservedSources"])
    assert recovered[2] == replay[2]
    coverage = recovered[2]
    reviewed = next(row for row in coverage["surfaces"] if row["label"] == "API boundary")
    task = next(row for row in coverage["deferred"] if row["reason"] == "Check boundary")
    assert task["surfaceIds"] == [reviewed["id"]]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("recorded", [False, True])
@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("archived", [False, True])
def test_stopped_receipt_ownership_requires_a_matching_checkpoint(
    workbench_api, workbench_db, publication_scan, monkeypatch, recorded, retry, archived
):
    scan = publication_scan()
    initial = add_worker(workbench_db, scan)
    worker_id = initial.parent.name
    output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    ref = "artifacts/evidence.txt"
    shared = scan.scan_dir / ref
    shared.parent.mkdir(parents=True, exist_ok=True)
    shared.write_text("Shared evidence\n")
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            "completeness": "complete",
            "explicitExclusions": [],
            "surfaces": [
                {
                    "id": "review",
                    "label": "Reviewed route",
                    "disposition": "no_issue_found",
                    "receiptRefs": [ref],
                    "provenance": {"scanReceiptRefs": [ref]},
                }
            ],
            "deferred": [],
        },
    }
    result.write_text(json.dumps(draft))
    if recorded:
        write_checkpoint(result.parent / "checkpoints", draft)
    local = result.parent / ref
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_text("Local evidence\n")
    if archived:
        archive = output.parent / "attempts" / "attempt-01"
        archive.parent.mkdir()
        output.rename(archive)
        output.mkdir()
        result = archive / "result.json"
        local = archive / ref
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET status = 'running', attempt = 2, result_manifest_path = NULL WHERE id = ?",
                (worker_id,),
            )
    original = result.read_bytes()
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    coverage = stop_and_recover_projection(workbench_api, workbench_db, scan, monkeypatch, retry)
    assert len(coverage["surfaces"]) == 1
    refs = coverage["surfaces"][0]["receiptRefs"]
    selected = shared if recorded else local
    assert refs == [selected.relative_to(scan.scan_dir).as_posix()]
    assert (scan.scan_dir / refs[0]).read_text() == selected.read_text()
    assert result.read_bytes() == original


CANDIDATE_IDS = [
    "candidate-\ud800",
    "candidate-\udfff",
    "candidate-\ud83d\ude00",
    "candidate-\U0001f600",
    "candidate-é",
    "candidate-\\ud800",
    "candidate-A\ud800B\udfffZ",
]


# Produced by the accepted JS draft parser and projectDiscoveryCoverage.
JAVASCRIPT_CANDIDATE_HASHES = [
    "48869f14875acce6da9a25e25db38d5a211fca5b07a2ac85d95dbeb7fbfad817",
    "48869f14875acce6da9a25e25db38d5a211fca5b07a2ac85d95dbeb7fbfad817",
    "a562be8af2b220690ce013d3fdce2d1db00a5cd0fffb191389023b836c65d43c",
    "a562be8af2b220690ce013d3fdce2d1db00a5cd0fffb191389023b836c65d43c",
    "e58295b9114eb779fb2c91d375fe1c103056bfe760954a8fbf7954a84c2cbb6a",
    "f6d3552df9eaff1e1ce7185aa6efb48eff97d5a74a39a44c5a4b7ff55fbe43c4",
    "d80ce56ca1e18843faee20969b09a04c1f32969a104b9ccf050f0a345eeb3912",
]


@pytest.mark.parametrize("index", range(len(CANDIDATE_IDS)))
def test_saved_candidate_projection_matches_javascript_utf8(tmp_path: Path, index: int):
    import workbench_saved_results as saved
    from workbench_validation import javascript_utf8

    candidate = CANDIDATE_IDS[index]
    digest = JAVASCRIPT_CANDIDATE_HASHES[index]
    assert hashlib.sha256(javascript_utf8(candidate)).hexdigest() == digest
    draft = saved_draft(
        "identity-scan",
        complete=True,
        surfaces=[
            {
                "id": "review",
                "label": "Reviewed route",
                "candidateId": candidate,
                "disposition": "no_issue_found",
                "receiptRefs": [],
            }
        ],
    )
    worker = save_worker(tmp_path, saved, "reviewer", [], draft)
    worker["status"] = "succeeded"
    worker["result_manifest_path"] = str(tmp_path / "reviewer" / "result.json")
    result_path = Path(worker["result_manifest_path"])
    original = result_path.read_bytes()
    result = recover(tmp_path, saved, [worker])
    surface = result[2]["surfaces"][0]
    assert surface["candidateId"] == f"reviewer-attempt-1-candidate-{digest}"
    assert surface["provenance"]["candidateId"] == json.loads(json.dumps(candidate))
    assert recover(tmp_path, saved, [worker], result[0]["scan"]["preservedSources"])[2] == result[2]
    assert result_path.read_bytes() == original


@pytest.mark.parametrize("outcome", ["failed", "canceled"])
@pytest.mark.parametrize("changed_checkout", [False, True])
def test_legacy_file_scope_preserves_shared_receipts_when_stopped(
    workbench_api, workbench_db, publication_scan, outcome, changed_checkout
):
    scope = "subdir/extract.py"
    scan = publication_scan(paths=[scope])
    db = workbench_api["_WORKBENCH_DB_CONTEXT"]
    registered = db.require_scan(workbench_db, scan.scan_id)
    assert db.requested_finding_scope(registered) == [(scope, True)]
    legacy_path = (
        Path(__file__).parents[1] / "mcp-app/tests/fixtures/legacy-scoped-worker-receipts.json"
    )
    legacy = json.loads(legacy_path.read_text())
    for draft in legacy.values():
        draft["scanId"] = scan.scan_id
        draft["findings"][0]["locations"][0]["path"] = scope
    legacy["checkpoint"]["findings"][1]["locations"][0]["path"] = f"{scope}/generated"
    initial = add_worker(workbench_db, scan)
    worker_id = initial.parent.name
    output = scan.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
    output.mkdir(parents=True)
    result = output / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(result), worker_id),
        )
    result.write_text(json.dumps(legacy["result"]))
    checkpoint = write_checkpoint(result.parent / "checkpoints", legacy["checkpoint"])
    os.utime(checkpoint, ns=(1_000_000_000, 1_000_000_000))
    os.utime(result, ns=(2_000_000_000, 2_000_000_000))
    ref = "artifacts/evidence.txt"
    shared, local = scan.scan_dir / ref, result.parent / ref
    for path, contents in ((shared, "Shared evidence\n"), (local, "Unrelated local evidence\n")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    original = {path: path.read_bytes() for path in (result, checkpoint, shared, local)}
    if changed_checkout:
        target = Path(registered["target_path"]) / scope
        target.unlink()
        target.mkdir()
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan.scan_dir / name).unlink()
    saved = workbench_api["saved_results"]
    args = Namespace(
        scan_id=scan.scan_id,
        claim_token=None,
        thread_id=None,
        cost_json=None,
        message="Synthetic stopped review.",
        coordinator_generation=None,
    )
    (saved.fail_scan if outcome == "failed" else saved.cancel_scan)(db, workbench_db, args)
    coverage_path = scan.scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    assert len(coverage["surfaces"]) == 1
    assert coverage["surfaces"][0]["receiptRefs"] == [ref]
    assert (
        scan.scan_dir / coverage["surfaces"][0]["receiptRefs"][0]
    ).read_text() == "Shared evidence\n"
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["status"] == outcome
    assert "filePaths" not in manifest["scan"]["scope"]
    assert "filePaths" not in coverage
    published = coverage_path.read_bytes()
    saved.preserve_scan_results(db, workbench_db, args)
    assert coverage_path.read_bytes() == published
    assert {path: path.read_bytes() for path in original} == original
