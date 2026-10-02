from __future__ import annotations

import json
from pathlib import Path

import pytest
from workbench_test_support import register, run_workbench, write_completed_contract


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("replacement", ["none", "cost", "unavailable"])
def test_completion_keeps_saved_cost_unless_replaced(
    tmp_path: Path, monkeypatch, wrapped: bool, replacement: str
) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    unavailable = {"coverage": "unavailable", "source": "codex_rollout", "threadCount": 0}
    usage = {
        "coverage": "complete",
        "source": "codex_rollout",
        "threadCount": 1,
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "reasoningOutputTokens": 0,
        "totalTokens": 15,
    }
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    receipt = {"usage": usage, "cost": cost} if wrapped else cost
    run_workbench(
        state,
        "preserve-scan-results",
        "--scan-id",
        scan["scanId"],
        "--cost-json",
        json.dumps(receipt),
    )
    expected = cost
    arguments = []
    if replacement == "cost":
        expected = {**cost, "estimatedUsd": 0.002}
        arguments = ["--cost-json", json.dumps(expected)]
    elif replacement == "unavailable":
        expected = None
        arguments = ["--cost-json", json.dumps({"usage": unavailable})]
    completed = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"], *arguments)[
        "scan"
    ]
    assert completed["progress"]["status"] == "complete"
    assert completed.get("cost") == expected
    if replacement == "unavailable":
        assert "cost" not in completed
        assert completed["usage"] == unavailable
    elif wrapped:
        assert completed["usage"] == usage
    elif replacement == "none":
        assert completed["usage"]["coverage"] == "unavailable"

    repeated = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])["scan"]
    assert repeated.get("cost") == expected
