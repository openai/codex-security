from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from test_workbench_scan_history import create_cli_scan, run_workbench
from workbench_test_support import initialize_git_repository


@pytest.mark.parametrize("kind", ["directory", "git", "dirty", "working_tree", "refs"])
def test_check_scan_target_matches_recorded_contents(tmp_path: Path, kind: str) -> None:
    repository = tmp_path / "repository"
    state_dir = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    if kind == "directory":
        repository.mkdir()
        (repository / "README.md").write_text("fixture\n")
    else:
        initialize_git_repository(repository)
    source = repository / "README.md"
    if kind in {"dirty", "working_tree"}:
        source.write_text("scanned changes\n")
    original = source.read_bytes()
    scan = create_cli_scan(
        state_dir,
        tmp_path / "results",
        repository,
        complete=False,
        target=(
            {"kind": kind, "paths": [], "base": "HEAD", "head": "HEAD"}
            if kind in {"working_tree", "refs"}
            else None
        ),
    )
    command = ("get-scan", "--scan-id", scan["scanId"])
    checked = run_workbench(state_dir, *command, "--check-target")
    assert checked["scan"]["targetPath"] == str(repository.resolve())

    source.write_text("changed after scan\n")
    # Ordinary history remains readable after the checkout changes.
    assert run_workbench(state_dir, *command)["scan"]["scanId"] == scan["scanId"]
    changed = run_workbench(state_dir, *command, "--check-target", check=False)
    assert changed["returncode"] != 0
    assert "Scan target contents changed" in changed["stderr"]

    source.write_bytes(original)
    assert run_workbench(state_dir, *command, "--check-target")["scan"]["scanId"] == scan["scanId"]


@pytest.mark.parametrize("kind", ["repository", "refs"])
def test_check_scan_target_rejects_changed_revision(tmp_path: Path, kind: str) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    state_dir = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    scan = create_cli_scan(
        state_dir,
        tmp_path / "results",
        repository,
        complete=False,
        target=(
            {"kind": "refs", "paths": [], "base": "HEAD", "head": "HEAD"}
            if kind == "refs"
            else None
        ),
    )
    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "New revision"], cwd=repository, check=True
    )
    changed = run_workbench(
        state_dir, "get-scan", "--scan-id", scan["scanId"], "--check-target", check=False
    )
    assert changed["returncode"] != 0
    assert "Repository HEAD changed" in changed["stderr"]


def test_check_scan_target_rejects_replaced_checkout(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("pass\n")
    state_dir = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)
    repository.rename(tmp_path / "original")
    repository.mkdir()
    (repository / "source.py").write_text("pass\n")

    changed = run_workbench(
        state_dir, "get-scan", "--scan-id", scan["scanId"], "--check-target", check=False
    )
    assert changed["returncode"] != 0
    assert "checkout path was replaced" in changed["stderr"]
