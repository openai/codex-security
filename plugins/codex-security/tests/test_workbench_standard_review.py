"""Exercise sparse file-review declarations against a Standard scan's registered target."""

from __future__ import annotations

import hashlib
import sqlite3
import subprocess
from pathlib import Path

import pytest
from test_workbench_completion_binding import register_cli_scan
from workbench_test_support import initialize_git_repository, load_script


def registered_scan(tmp_path: Path, repo: Path) -> sqlite3.Row:
    state = tmp_path / "state"
    registration = register_cli_scan(
        state, repo, tmp_path / "scan", scan_target={"kind": "paths", "paths": ["src"]}
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute(
            "SELECT * FROM scans WHERE id = ?", (registration["scanId"],)
        ).fetchone()


@pytest.mark.cross_platform
def test_reviewed_file_must_match_the_registered_blob_and_scope(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    source = repo / "src" / "selected.bin"
    payload = b"original\x00bytes"
    source.write_bytes(payload)
    (repo / ".gitignore").write_text("ignored.bin\n")
    (repo / "src" / "ignored.bin").write_bytes(payload)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "Add scoped files"], cwd=repo, check=True)
    scan = registered_scan(tmp_path, repo)
    review = load_script("workbench_standard_review").review_file_digests

    selected = "src/selected.bin"
    assert review(scan, []) == {}
    for malformed in (None, False, 0, {}, "", selected, {selected: True}):
        with pytest.raises(SystemExit):
            review(scan, malformed)
    assert review(scan, [selected]) == {selected: hashlib.sha256(payload).hexdigest()}
    for invalid in (
        "README.md",
        "src/ignored.bin",
        "src/missing",
        "src",
        "src/../src/selected.bin",
    ):
        with pytest.raises(SystemExit):
            review(scan, [selected, invalid])
    source.write_bytes(b"replaced\x00bytes")
    with pytest.raises(SystemExit):
        review(scan, [selected])


@pytest.mark.cross_platform
def test_reviewed_file_must_belong_to_the_saved_directory_snapshot(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / ".ignore").write_text("*.temporary\n")
    for name in ("a", "b", "c"):
        (src / name).write_bytes(name.encode())
    metadata = src / ".svn"
    metadata.mkdir()
    (metadata / "entries").write_bytes(b"a")
    scan = registered_scan(tmp_path, repo)
    review = load_script("workbench_standard_review").review_file_digests

    assert scan["target_revision"] == "unversioned"
    assert review(scan, ["src/a"]) == {"src/a": hashlib.sha256(b"a").hexdigest()}
    with pytest.raises(SystemExit):
        review(scan, ["src/.svn/entries"])
    (src / "b").rename(src / "d")
    with pytest.raises(SystemExit):
        review(scan, ["src/d"])


def test_reviewed_file_rejects_a_symlink_to_matching_bytes(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    selected = repo / "src" / "reviewed"
    selected.write_bytes(b"same bytes")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "Add reviewed file"], cwd=repo, check=True)
    scan = registered_scan(tmp_path, repo)
    outside = tmp_path / "outside"
    outside.write_bytes(selected.read_bytes())
    selected.unlink()
    try:
        selected.symlink_to(outside)
    except OSError:
        pytest.skip("creating a symlink is unavailable")
    review = load_script("workbench_standard_review").review_file_digests
    with pytest.raises(SystemExit):
        review(scan, ["src/reviewed"])


@pytest.mark.cross_platform
def test_exact_reviewed_paths_below_a_subdirectory_target(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    initialize_git_repository(repo)
    target = repo / "component"
    src = target / "src"
    src.mkdir(parents=True)
    (src / "Foo").write_bytes(b"first")
    alias = (src / "fOO").exists()
    if not alias:
        (src / "fOO").write_bytes(b"second")
    # A root-relative lookup would read a different blob from the registered one.
    (repo / "src").mkdir()
    (repo / "src" / "Foo").write_bytes(b"outer")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "Add nested paths"], cwd=repo, check=True)
    scan = registered_scan(tmp_path, target)
    review = load_script("workbench_standard_review").review_file_digests

    expected = {"src/Foo": hashlib.sha256(b"first").hexdigest()}
    if alias:
        with pytest.raises(SystemExit, match="not a regular file in the registered Git tree"):
            review(scan, ["src/fOO"])
    else:
        expected["src/fOO"] = hashlib.sha256(b"second").hexdigest()
    assert review(scan, list(expected)) == expected
