from __future__ import annotations

import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

import pytest
from test_workbench_scan_history import create_cli_scan
from workbench_test_support import get_scan, initialize_git_repository


def start_validation_scan(
    tmp_path: Path, repository: Path, *, target: dict[str, object] | None = None
) -> tuple[Path, str]:
    state_dir = tmp_path / "state"
    results = tmp_path / "results"
    results.mkdir(mode=0o700)
    scan = create_cli_scan(state_dir, results, repository, complete=False, target=target)
    return state_dir, scan["scanId"]


@pytest.mark.skipif(
    os.name == "nt" or getattr(os, "geteuid", lambda: 0)() == 0,
    reason="Mode permissions require a non-root Unix user",
)
def test_snapshot_reports_unreadable_tracked_file(
    tmp_path: Path, workbench_api, monkeypatch
) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / ".gitattributes").write_bytes(b"* invalid\x1b[2J\xff\n")
    source = repository / "README.md"
    source.write_text("Changed contents.\n")
    mode = source.stat().st_mode
    monkeypatch.setenv("LC_ALL", "C")
    source.chmod(0)
    try:
        with pytest.raises(SystemExit) as error:
            workbench_api["worktree_content_digest"](repository)
    finally:
        source.chmod(mode)
    diagnostic = str(error.value)
    assert "README.md" in diagnostic
    assert "Permission denied" in diagnostic
    assert r"invalid\x1b[2J\xff" in diagnostic


@pytest.mark.parametrize("kind", ["directory", "git", "dirty", "working_tree", "refs"])
def test_check_scan_target_matches_recorded_contents(tmp_path: Path, kind: str) -> None:
    repository = tmp_path / "repository"
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
    state_dir, scan_id = start_validation_scan(
        tmp_path,
        repository,
        target={
            "kind": kind,
            "paths": [],
            "base": "HEAD^" if kind == "refs" else "HEAD",
            "head": "HEAD",
        }
        if kind in {"working_tree", "refs"}
        else None,
    )
    checked = get_scan(state_dir, scan_id, "--check-target")
    assert checked["scan"]["targetPath"] == str(repository.resolve())

    source.write_text("changed after scan\n")
    # Ordinary history remains readable after the checkout changes.
    assert get_scan(state_dir, scan_id)["scan"]["scanId"] == scan_id
    changed = get_scan(state_dir, scan_id, "--check-target", check=False)
    assert changed["returncode"] != 0
    assert "Scan target contents changed" in changed["stderr"]

    source.write_bytes(original)
    assert get_scan(state_dir, scan_id, "--check-target")["scan"]["scanId"] == scan_id


@pytest.mark.parametrize("kind", ["repository", "refs"])
def test_check_scan_target_rejects_changed_revision(
    tmp_path: Path, kind: str, workbench_api
) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    state_dir, scan_id = start_validation_scan(
        tmp_path,
        repository,
        target={"kind": "refs", "paths": [], "base": "HEAD", "head": "HEAD"}
        if kind == "refs"
        else None,
    )
    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "New revision"], cwd=repository, check=True
    )
    changed = get_scan(state_dir, scan_id, "--check-target", check=False)
    assert changed["returncode"] != 0
    assert "Repository HEAD changed" in changed["stderr"]
    assert "new scan" in changed["stderr"].lower()
    with closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        stored_scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    with pytest.raises(SystemExit, match="Regenerate the remediation patch"):
        workbench_api["remediation_checkout_snapshot"](stored_scan)


def test_check_committed_diff_target_rejects_sparse_checkout_after_scan(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    source = repository / "src" / "source.py"
    source.parent.mkdir()
    source.write_text("pass\n")
    subprocess.run(["git", "add", "src/source.py"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Add source"], cwd=repository, check=True)
    state_dir, scan_id = start_validation_scan(
        tmp_path, repository, target={"kind": "refs", "paths": [], "base": "HEAD^", "head": "HEAD"}
    )
    assert get_scan(state_dir, scan_id, "--check-target")["scan"]["scanId"] == scan_id

    subprocess.run(
        ["git", "sparse-checkout", "set", "--no-cone", "/README.md"],
        cwd=repository,
        check=True,
    )
    assert not source.exists()
    subprocess.run(["git", "diff", "--quiet", "HEAD"], cwd=repository, check=True)
    assert get_scan(state_dir, scan_id)["scan"]["scanId"] == scan_id
    changed = get_scan(state_dir, scan_id, "--check-target", check=False)
    assert changed["returncode"] != 0
    assert "full repository checkout" in changed["stderr"]

    subprocess.run(["git", "sparse-checkout", "disable"], cwd=repository, check=True)
    assert source.read_text() == "pass\n"
    assert get_scan(state_dir, scan_id, "--check-target")["scan"]["scanId"] == scan_id


def test_check_scan_target_rejects_replaced_checkout(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "source.py").write_text("pass\n")
    state_dir, scan_id = start_validation_scan(tmp_path, repository)
    repository.rename(tmp_path / "original")
    repository.mkdir()
    (repository / "source.py").write_text("pass\n")

    changed = get_scan(state_dir, scan_id, "--check-target", check=False)
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
    state_dir, scan_id = start_validation_scan(tmp_path, repository)
    with closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as connection:
        connection.execute(
            "UPDATE scans SET target_snapshot_digest = NULL WHERE id = ?", (scan_id,)
        )
        connection.commit()
    assert get_scan(state_dir, scan_id, "--check-target")["scan"]["scanId"] == scan_id

    # Revision-only records cannot compare content against an unrecorded digest.
    source = repository / "README.md"
    original = source.read_bytes()
    source.write_text("Changed working-tree content.\n")
    assert get_scan(state_dir, scan_id, "--check-target")["scan"]["scanId"] == scan_id
    source.write_bytes(original)

    submodule_source = submodule / "README.md"
    submodule_original = submodule_source.read_bytes()
    submodule_source.write_text("Changed submodule content.\n")
    dirty_submodule = get_scan(state_dir, scan_id, "--check-target", check=False)
    assert dirty_submodule["returncode"] != 0
    assert "Dirty Git submodules" in dirty_submodule["stderr"]
    submodule_source.write_bytes(submodule_original)

    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "New revision"], cwd=repository, check=True
    )
    changed = get_scan(state_dir, scan_id, "--check-target", check=False)
    assert changed["returncode"] != 0
    assert "Repository HEAD changed" in changed["stderr"]

    repository.rename(tmp_path / "original")
    repository.mkdir()
    source.write_bytes(original)
    replaced = get_scan(state_dir, scan_id, "--check-target", check=False)
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
    state_dir, scan_id = start_validation_scan(tmp_path, repository)
    entry = repository / "unreadable.txt"
    entry.write_text("Synthetic untracked contents.\n")
    mode = entry.stat().st_mode
    entry.chmod(0)
    try:
        assert get_scan(state_dir, scan_id)["scan"]["scanId"] == scan_id
        recorded = get_scan(state_dir, scan_id, "--check-target", check=False)
        assert recorded["returncode"] != 0
        assert "Could not read untracked file" in recorded["stderr"]
        with closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as connection:
            connection.execute(
                "UPDATE scans SET target_snapshot_digest = NULL WHERE id = ?", (scan_id,)
            )
            connection.commit()
            connection.row_factory = sqlite3.Row
            stored_scan = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        with pytest.raises(SystemExit, match="Could not read untracked file"):
            workbench_api["remediation_checkout_snapshot"](stored_scan)
        assert get_scan(state_dir, scan_id, "--check-target")["scan"]["scanId"] == scan_id
    finally:
        entry.chmod(mode)
