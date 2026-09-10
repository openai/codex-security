from __future__ import annotations

import hashlib
import json
from pathlib import Path

from test_workbench_deep_continuation import completed_deep_fixture
from test_workbench_scan_checkpoints import save, semantic
from workbench_test_support import run_workbench, write_checkpoint


def test_linked_deep_scans_keep_the_parent_threat_model_over_worker_models(tmp_path: Path):
    state, parent, parent_id, child, child_id, _ = completed_deep_fixture(tmp_path)
    for result in parent.glob("artifacts/deep_discovery/*/*/output/result.json"):
        document = semantic(parent_id, [])
        document["complete"] = True
        document["coverage"].update(completeness="complete", deferred=[])
        result.write_text(json.dumps(document))
    for head in parent.glob("artifacts/deep_discovery/*/*/output/checkpoint-head.json"):
        head.unlink()
        (head.parent / "checkpoints" / "old.json").unlink()

    coverage = semantic(parent_id, [])["coverage"]
    coverage["deferred"] = []

    def child_checkpoint(model: dict[str, object]) -> Path:
        snapshot = {
            "scanId": child_id,
            "complete": False,
            "threatModel": model,
            "findings": [],
            "coverage": coverage,
        }
        digest = hashlib.sha256((json.dumps(snapshot, indent=2) + "\n").encode()).hexdigest()
        return child / "checkpoints" / f"{digest}.json"

    # Exercise the merge-order seam: the worker's model is encountered first
    # in content-addressed filename order even when the parent's is newer.
    worker_model, parent_model = sorted(
        [
            {
                "summary": "Model A",
                "assets": ["Stored records"],
                "assumptions": ["Authenticated requests"],
            },
            {
                "summary": "Model B",
                "trustBoundaries": ["Request parsing"],
                "securityObjectives": ["Isolated records"],
            },
        ],
        key=lambda model: child_checkpoint(model).name,
    )
    worker = parent / "artifacts/deep_discovery/workers/discovery-0004/output"
    for root, model in ((worker, worker_model), (parent, parent_model)):
        document = semantic(parent_id, [])
        document["coverage"] = coverage
        document["threatModel"] = model
        save(state, parent_id, write_checkpoint(root / "checkpoints", document))
    run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child_id,
        "--parent-scan-id",
        parent_id,
    )
    assert child_checkpoint(worker_model).is_file()
    assert child_checkpoint(parent_model).is_file()
    assert child_checkpoint(worker_model).name < child_checkpoint(parent_model).name

    def assert_parent_model(root: Path, scan_id: str) -> None:
        manifest = json.loads((root / "scan-manifest.json").read_text())
        assert manifest["scan"]["threatModel"] == parent_model
        checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
        current = next(source for source in checkpoint["sources"] if source["source"] == ".")
        assert current["threatModel"] == parent_model

    assert_parent_model(child, child_id)
    grandchild = tmp_path / "grandchild"
    grandchild.mkdir(mode=0o700)
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", child_id)["recipe"]
    grandchild_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(tmp_path / "repository"),
        "--scan-dir",
        str(grandchild),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        child_id,
    )["scanId"]
    run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        grandchild_id,
        "--parent-scan-id",
        child_id,
    )
    assert_parent_model(grandchild, grandchild_id)
