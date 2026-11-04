from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from workbench_test_support import load_script

finalizer = load_script("finalize_scan_contract")
validator = load_script("validate_scan_contract")
history = load_script("workbench_scan_history")


@pytest.mark.parametrize("unfinished", [False, True])
def test_results_without_coverage_file(tmp_path: Path, unfinished: bool) -> None:
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
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    checkpoint = json.loads((scan_dir / "checkpoints" / head["checkpoint"]).read_text())
    assert checkpoint["reviewState"]["surfaces"][0]["candidateId"] == "candidate-1"
    assert checkpoint["reviewState"]["deferred"] == state["deferred"]
    assert checkpoint["reviewState"]["openQuestions"] == [
        {"question": "Which runtime controls apply?"}
    ]
    assert "coverage" not in checkpoint
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
