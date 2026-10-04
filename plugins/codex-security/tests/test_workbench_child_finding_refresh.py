from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from workbench_test_support import (
    checkpoint,
    register,
    run_workbench,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize("change", ["lower", "higher", "history", "unchanged"])
@pytest.mark.parametrize("null_history", [False, True])
def test_recovery_retains_current_child_finding_and_refreshes_source_history(
    tmp_path: Path, change: str, null_history: bool
) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    write_completed_contract(parent_dir, parent["scanId"], target, relative_path="app.py")
    parent_finding = json.loads((parent_dir / "findings.json").read_text())["findings"][0]
    parent_finding["title"] = "Synthetic parent observation"
    parent_finding["severity"] = {"level": "high"}
    if null_history:
        parent_finding["provenance"]["previousFindings"] = None
    (parent_dir / "findings.json").write_text(json.dumps({"findings": [parent_finding]}))
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        finding = copy.deepcopy(parent_finding)
        finding["title"] = f"Synthetic child observation {index}"
        finding["severity"] = {"level": "low" if change == "higher" and index == 1 else "high"}
        write_checkpoint(
            directory / "checkpoints",
            saved_draft(child["scanId"], complete=True, findings=[finding]),
        )
        run_workbench(
            state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic interruption"
        )
        children.append((child, directory))
    checkpoint(state, parent)
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption"
    )["scan"]
    assert stopped["findingCount"] == 3
    assert stopped["resultsRecoveryNeeded"] is False
    original_parent = json.loads((parent_dir / "findings.json").read_text())["findings"]
    unchanged = {
        finding["title"]: finding
        for finding in original_parent
        if finding["title"] != "Synthetic child observation 1"
    }
    child, directory = children[0]
    previous = json.loads((directory / "findings.json").read_text())["findings"][0]
    current = copy.deepcopy(previous)
    if change in {"lower", "higher"}:
        current["severity"] = {"level": "low" if change == "lower" else "high"}
        current["description"] = "Synthetic corrected child evidence."
        current.setdefault("provenance", {})["previousFindings"] = [previous]
    elif change == "history":
        historical = copy.deepcopy(previous)
        historical["severity"] = {"level": "low"}
        historical["description"] = "Synthetic historical evidence."
        current.setdefault("provenance", {})["previousFindings"] = [historical]
    updated_draft = saved_draft(child["scanId"], complete=True, findings=[current])
    updated_draft["coverage"] = {
        **json.loads((directory / "coverage.json").read_text()),
        **updated_draft["coverage"],
    }
    updated = write_checkpoint(directory / "checkpoints", updated_draft)
    (directory / "checkpoint-head.json").write_text(json.dumps({"checkpoint": updated.name}))
    run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
    accepted_child = json.loads((directory / "findings.json").read_text())["findings"][0]
    assert accepted_child["severity"] == current["severity"]
    if change != "unchanged":
        assert accepted_child["provenance"]["previousFindings"]
    original = {
        path: path.read_bytes() for _, child_dir in children for path in child_dir.rglob("*.json")
    }
    first = None
    for recovery in range(3):
        if recovery == 1:
            progress = saved_draft(parent["scanId"], complete=False)
            progress["coverage"]["openQuestions"] = ["Synthetic additional parent review."]
            write_checkpoint(parent_dir / "checkpoints", progress)
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["findingCount"] == 3
        if recovery >= 1:
            coverage = json.loads((parent_dir / "coverage.json").read_text())
            assert {"question": "Synthetic additional parent review."} in coverage["openQuestions"]
        rows = json.loads((parent_dir / "findings.json").read_text())["findings"]
        refreshed = next(row for row in rows if row["title"] == "Synthetic child observation 1")
        assert refreshed["severity"] == accepted_child["severity"]
        assert refreshed.get("description") == accepted_child.get("description")
        assert refreshed["provenance"]["sourceFindings"][0]["finding"] == accepted_child
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        assert {
            row["title"]: row for row in rows if row["title"] != refreshed["title"]
        } == unchanged
        assert len({row["findingId"] for row in rows}) == 3
        if first is not None:
            assert (parent_dir / "findings.json").read_bytes() == first
        first = (parent_dir / "findings.json").read_bytes()
        for path, contents in original.items():
            assert path.read_bytes() == contents
