from __future__ import annotations

import json
from pathlib import Path

import pytest
from workbench_test_support import write_completed_contract


@pytest.mark.parametrize("still_active", [False, True], ids=["resolved", "still-active"])
def test_resolved_deferred_finalization(tmp_path: Path, workbench_api, still_active: bool) -> None:
    write_completed_contract(tmp_path, "generic-closure-finalization", tmp_path)
    coverage_path = tmp_path / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    closure = {"id": "review-closeout", "reason": "All review decisions are recorded."}
    coverage["resolvedDeferred"] = [closure]
    if still_active:
        coverage["completeness"] = "partial"
        coverage["deferred"] = [{"id": closure["id"], "reason": "Still pending."}]
    coverage_path.write_text(json.dumps(coverage))

    finalize = workbench_api["finalize_scan"]
    if still_active:
        with pytest.raises(workbench_api["ContractError"], match="still active"):
            finalize(tmp_path)
        return

    _, _, sealed_coverage = finalize(tmp_path)
    assert sealed_coverage["resolvedDeferred"] == [closure]
    sealed_bytes = coverage_path.read_bytes()
    finalize(tmp_path)
    assert coverage_path.read_bytes() == sealed_bytes
