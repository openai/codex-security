"""Regression coverage for explicit package scope across scan lifecycle operations."""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import SCRIPT, run_workbench

sys.path.insert(0, str(SCRIPT.parent))
from dependency_scan_depth import select_exact_dependencies
from dependency_scan_selection import selected_dependencies


def package(name: str, version: str = "1.2.3") -> dict[str, str | None]:
    return {
        "ecosystem": "npm",
        "registry": "https://registry.npmjs.org",
        "package": name,
        "oldVersion": None,
        "newVersion": version,
    }


def test_selection_survives_save_start_and_reload(tmp_path: Path) -> None:
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    selected = [package("@scope/direct"), package("transitive", "2.0.0")]
    run_workbench(state, "create-workspace", "--workspace-id", workspace_id)
    saved = run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "full_dependency",
        "--selected-dependencies",
        json.dumps(selected),
    )
    assert saved["selectedDependencies"] == selected
    started = run_workbench(
        state,
        "start-scan",
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    context = run_workbench(state, "get-scan", "--scan-id", started["results"]["scanId"])
    assert context["scan"]["selectedDependencies"] == selected
    assert context["workspace"]["selectedDependencies"] == selected


def test_prompt_scan_does_not_rejoin_a_different_selection(tmp_path: Path) -> None:
    state = tmp_path / "state"
    target = tmp_path / "repo"
    target.mkdir()
    args = (
        "start-prompt-only-scan",
        "--thread-id",
        "fixture-thread",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "full_dependency",
        "--scan-root",
        str(tmp_path / "scans"),
    )
    first = run_workbench(state, *args, "--selected-dependencies", json.dumps([package("one")]))
    repeated = run_workbench(state, *args, "--selected-dependencies", json.dumps([package("one")]))
    different = run_workbench(state, *args, "--selected-dependencies", json.dumps([package("two")]))
    assert repeated["scan"]["scanId"] == first["scan"]["scanId"]
    assert different["scan"]["scanId"] != first["scan"]["scanId"]
    assert (
        run_workbench(state, "get-thread-dependency-selection", "--thread-id", "fixture-thread")[
            "requiresScanId"
        ]
        is True
    )


@pytest.mark.parametrize(
    "selection",
    [
        [],
        [package("one", "^1.2.3")],
        [package("one"), package("one")],
        [package(str(index)) for index in range(21)],
        [{**package("one"), "registry": "https://private.example"}],
    ],
)
def test_invalid_selection_cannot_become_a_full_graph_scan(selection: object) -> None:
    with pytest.raises(ValueError):
        selected_dependencies(selection)


def test_exact_selection_keeps_requested_versions_without_depth_expansion() -> None:
    one = package("example", "1.0.0")
    two = package("example", "2.0.0")
    discovery = {"dependencies": [one, two, package("unselected")]}
    assert select_exact_dependencies(discovery, [two]) == [two]
    with pytest.raises(ValueError, match="current resolved inventory"):
        select_exact_dependencies(discovery, [package("example", "3.0.0")])


def test_selected_versions_follow_semantic_version_prerelease_rules() -> None:
    """Reject numeric prerelease zeros without rejecting valid build metadata."""
    for version in ("1.2.3-01", "1.2.3-alpha.01"):
        with pytest.raises(ValueError, match="exact versions"):
            selected_dependencies([package("example", version)])
    for version in ("1.2.3-alpha.1", "1.2.3-0+build.01"):
        assert selected_dependencies([package("example", version)]) == [package("example", version)]
