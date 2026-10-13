from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
from workbench_test_support import initialize_git_repository, recipe, register, run_workbench


@pytest.mark.parametrize("change", ["directory", "worktree", "revision"])
def test_deep_pass_registration_retains_parent_target_snapshot(tmp_path: Path, change: str) -> None:
    target = tmp_path / "target"
    if change == "directory":
        target.mkdir()
    else:
        initialize_git_repository(target)
    source = target / "README.md"
    source.write_text("Original synthetic source\n")
    state = tmp_path / "state"
    parent_dir = tmp_path / "parent"
    parent = register(state, target, parent_dir, mode="deep")
    accepted = register(
        state, target, parent_dir / "pass-1", parent=parent["scanId"], role="deep_pass"
    )
    if change == "revision":
        # Advance only the revision, keeping working-tree contents identical.
        subprocess.run(
            ["git", "commit", "--allow-empty", "-qm", "Next revision"], cwd=target, check=True
        )
    else:
        source.write_text("Changed synthetic source\n")
    child_dir = parent_dir / "pass-2"
    child_dir.mkdir(mode=0o700)
    rejected = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(child_dir),
        "--parent-scan-id",
        parent["scanId"],
        "--registration-json-stdin",
        input_text=json.dumps({"recipe": recipe(target), "parentScanRole": "deep_pass"}),
        check=False,
    )
    assert "parent's target snapshot" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT id FROM scans WHERE parent_scan_id = ?", (parent["scanId"],)
        ).fetchall() == [(accepted["scanId"],)]
    # A separate rerun may intentionally review the repository after it changes.
    assert register(state, target, tmp_path / "rerun", parent=parent["scanId"])["scanId"]
