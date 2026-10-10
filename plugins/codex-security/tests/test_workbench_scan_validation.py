from __future__ import annotations

import os
import sqlite3
import subprocess
from contextlib import closing
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
    if kind == "refs":
        source.write_text("committed changes\n")
        subprocess.run(["git", "commit", "-qam", "Scanned revision"], cwd=repository, check=True)
    original = source.read_bytes()
    scan = create_cli_scan(
        state_dir,
        tmp_path / "results",
        repository,
        complete=False,
        target=(
            {
                "kind": kind,
                "paths": [],
                "base": "HEAD^" if kind == "refs" else "HEAD",
                "head": "HEAD",
            }
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
def test_check_scan_target_rejects_changed_revision(
    tmp_path: Path, kind: str, workbench_api
) -> None:
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
    assert "new scan" in changed["stderr"].lower()
    with closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        stored_scan = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan["scanId"],)
        ).fetchone()
    with pytest.raises(SystemExit, match="Regenerate the remediation patch"):
        workbench_api["remediation_checkout_snapshot"](stored_scan)


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


def test_check_scan_target_accepts_legacy_revision_only_git_scan(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    submodule = repository / "submodule"
    revision = initialize_git_repository(submodule)
    subprocess.run(
        ["git", "update-index", "--add", "--cacheinfo", f"160000,{revision},submodule"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "Add submodule"], cwd=repository, check=True)
    state_dir = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)
    with closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as connection:
        connection.execute(
            "UPDATE scans SET target_snapshot_digest = NULL WHERE id = ?", (scan["scanId"],)
        )
        connection.commit()
    command = ("get-scan", "--scan-id", scan["scanId"], "--check-target")
    assert run_workbench(state_dir, *command)["scan"]["scanId"] == scan["scanId"]

    # Revision-only records cannot compare content against an unrecorded digest.
    source = repository / "README.md"
    original = source.read_bytes()
    source.write_text("Changed working-tree content.\n")
    assert run_workbench(state_dir, *command)["scan"]["scanId"] == scan["scanId"]
    source.write_bytes(original)

    submodule_source = submodule / "README.md"
    submodule_original = submodule_source.read_bytes()
    submodule_source.write_text("Changed submodule content.\n")
    dirty_submodule = run_workbench(state_dir, *command, check=False)
    assert dirty_submodule["returncode"] != 0
    assert "Dirty Git submodules" in dirty_submodule["stderr"]
    submodule_source.write_bytes(submodule_original)

    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "New revision"], cwd=repository, check=True
    )
    changed = run_workbench(state_dir, *command, check=False)
    assert changed["returncode"] != 0
    assert "Repository HEAD changed" in changed["stderr"]

    repository.rename(tmp_path / "original")
    repository.mkdir()
    source.write_bytes(original)
    replaced = run_workbench(state_dir, *command, check=False)
    assert replaced["returncode"] != 0
    assert "checkout path was replaced" in replaced["stderr"]


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="Mode permissions require a non-root Unix user",
)
def test_check_legacy_scan_target_does_not_read_unrecorded_contents(
    tmp_path: Path, workbench_api
) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    state_dir = tmp_path / "state"
    (tmp_path / "results").mkdir(mode=0o700)
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)
    command = ("get-scan", "--scan-id", scan["scanId"])
    entry = repository / "unreadable.txt"
    entry.write_text("Synthetic untracked contents.\n")
    mode = entry.stat().st_mode
    entry.chmod(0)
    try:
        assert run_workbench(state_dir, *command)["scan"]["scanId"] == scan["scanId"]
        recorded = run_workbench(state_dir, *command, "--check-target", check=False)
        assert recorded["returncode"] != 0
        assert "Could not read untracked file" in recorded["stderr"]
        with closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as connection:
            connection.execute(
                "UPDATE scans SET target_snapshot_digest = NULL WHERE id = ?", (scan["scanId"],)
            )
            connection.commit()
            connection.row_factory = sqlite3.Row
            stored_scan = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan["scanId"],)
            ).fetchone()
        with pytest.raises(SystemExit, match="Could not read untracked file"):
            workbench_api["remediation_checkout_snapshot"](stored_scan)
        assert (
            run_workbench(state_dir, *command, "--check-target")["scan"]["scanId"] == scan["scanId"]
        )
    finally:
        entry.chmod(mode)
