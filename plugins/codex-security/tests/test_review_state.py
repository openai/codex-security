"""Reconstruct coverage from results that contain review state but have no separate coverage file."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from workbench_test_support import load_script

finalizer = load_script("finalize_scan_contract")
validator = load_script("validate_scan_contract")
history = load_script("workbench_scan_history")
workbench = load_script("workbench_db")
saved_results = load_script("workbench_saved_results")


@pytest.mark.parametrize("unfinished", [False, True])
@pytest.mark.parametrize("prior_review", ["none", "head", "preserved"])
def test_results_without_coverage_file(tmp_path: Path, unfinished: bool, prior_review: str) -> None:
    scan_dir = (tmp_path / "scan").resolve()
    example = Path(__file__).resolve().parents[1] / "examples" / "legacy-completed-scan"
    shutil.copytree(example, scan_dir)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    state = json.loads((scan_dir / "coverage.json").read_text())
    scan = manifest["scan"]
    for key in ("coverageRef", "artifacts", "sealedAt"):
        scan.pop(key)
    state["explicitExclusions"] = [{"pattern": "vendor", "reason": "External code"}]
    state["openQuestions"] = ["Which runtime controls apply?"]
    state["surfaces"] = [
        {
            "id": "rejected-candidate",
            "candidateId": "candidate-1",
            "label": "Authorization check",
            "disposition": "rejected",
            "receiptRefs": [],
            "notes": "The caller checks ownership before access.",
        }
    ]
    if unfinished:
        state["completeness"] = "partial"
        state["deferred"] = [{"id": "task-1", "reason": "Check the background worker"}]
    preserved = {}
    if prior_review != "none":
        previous = {
            "scanId": scan["id"],
            "findings": [],
            "reviewState": {
                "deferred": [{"id": "prior-work", "reason": "Prior incomplete review"}]
            },
        }
        contents = finalizer._json_bytes(previous)
        name = hashlib.sha256(contents).hexdigest() + ".json"
        finalizer.write_scan_local_bytes(scan_dir, "checkpoints/" + name, contents)
        finalizer._write_scan_local_json(scan_dir, "checkpoint-head.json", {"checkpoint": name})
        state["resolvedDeferred"] = [{"id": "prior-work", "reason": "Review completed."}]
        if prior_review == "preserved":
            heads = {}
            sources = saved_results._capture_saved_source(
                scan_dir, "checkpoint-head.json", scan["id"], checkpoint_heads=heads
            )
            scan["preservedSources"] = {path: value[0] for path, value in sources.items()}
            scan["preservedCheckpointHeads"] = heads
        preserved = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in scan_dir.rglob("*.json")
            if path.name == "checkpoint-head.json" or path.parent.name.startswith("checkpoint")
        }
    scan["mode"] = state["mode"]
    scan["reviewState"] = state
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    (scan_dir / "coverage.json").unlink()

    finalizer.finalize_scan(scan_dir)
    result = validator.validate_contract(scan_dir)
    expected = {"excludedPaths": ["vendor"]}
    assert result["review"] == expected
    assert result["manifest"]["scan"]["review"] == expected
    assert "reviewState" not in result["manifest"]["scan"]
    assert "coverageRef" not in result["manifest"]["scan"]
    assert not (scan_dir / "coverage.json").exists()
    checkpoint_artifact = next(
        artifact
        for artifact in result["manifest"]["scan"]["artifacts"]
        if artifact["path"].startswith("artifacts/checkpoints/")
    )
    checkpoint_path = scan_dir / checkpoint_artifact["path"]
    checkpoint_bytes = checkpoint_path.read_bytes()
    assert hashlib.sha256(checkpoint_bytes).hexdigest() == checkpoint_artifact["sha256"]
    checkpoint = json.loads(checkpoint_bytes)
    assert checkpoint["reviewState"]["surfaces"][0]["candidateId"] == "candidate-1"
    assert checkpoint["reviewState"]["deferred"] == state["deferred"]
    assert checkpoint["reviewState"]["openQuestions"] == [
        {"question": "Which runtime controls apply?"}
    ]
    assert "coverage" not in checkpoint
    assert all(
        (path.read_bytes(), path.stat().st_mtime_ns) == value for path, value in preserved.items()
    )
    for key in ("preservedSources", "preservedCheckpointHeads"):
        assert result["manifest"]["scan"].get(key) == scan.get(key)
    report = (scan_dir / "report.md").read_text()
    assert "coverage.json" not in report
    assert "Reviewed Surfaces" not in report
    assert "Review status" not in report

    # Comparison respects exclusions without treating pending review as a failed scan.
    row = {"status": "complete", "target_id": "target"}
    summary_state = finalizer.review_state(result["manifest"]["scan"])
    assert not history.scan_covers_path(
        row, target_id="target", path="vendor/lib.py", coverage=summary_state
    )
    assert history.scan_covers_path(
        row, target_id="target", path="src/api.py", coverage=summary_state
    )
    before = (scan_dir / "scan-manifest.json").read_bytes()
    finalizer.finalize_scan(scan_dir)
    assert (scan_dir / "scan-manifest.json").read_bytes() == before
    row = {
        "id": scan["id"],
        "scan_dir": str(scan_dir),
        "seal_manifest_digest": "sha256:" + hashlib.sha256(before).hexdigest(),
    }
    original_files = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan_dir.rglob("*")
        if path.is_file()
    }
    compared = workbench.coverage_for_comparison(row)
    assert compared["deferred"] == state["deferred"]
    assert original_files == {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in scan_dir.rglob("*")
        if path.is_file()
    }

    old_manifest = copy.deepcopy(result["manifest"])
    old_manifest["scan"]["artifacts"].remove(checkpoint_artifact)
    old_bytes = finalizer._json_bytes(old_manifest)
    (scan_dir / "scan-manifest.json").write_bytes(old_bytes)
    row["seal_manifest_digest"] = "sha256:" + hashlib.sha256(old_bytes).hexdigest()
    old_coverage = workbench.coverage_for_comparison(row)
    assert "deferred" not in old_coverage

    (scan_dir / "scan-manifest.json").write_bytes(before)
    row["seal_manifest_digest"] = "sha256:" + hashlib.sha256(before).hexdigest()
    checkpoint_path.write_bytes(checkpoint_bytes + b" ")
    with pytest.raises(SystemExit, match="sealed artifact changed"):
        workbench.coverage_for_comparison(row)
