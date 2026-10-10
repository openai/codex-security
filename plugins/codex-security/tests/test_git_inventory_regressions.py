from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
from contextlib import closing
from pathlib import Path

import pytest
from workbench_test_support import initialize_git_repository, load_script


def git(target: Path, *args: str, input: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(target), *args], input=input, capture_output=True, check=True
    ).stdout.strip()


def test_root_commit_message_does_not_supply_diff_parent(tmp_path: Path, workbench_api) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    previous = git(target, "rev-parse", "HEAD").decode()
    git(target, "commit", "--amend", "-qm", f"Synthetic root\n\nparent {previous}")
    head = git(target, "rev-parse", "HEAD").decode()
    diff = workbench_api["require_diff_target"](target, "commit", None, head, None)
    assert diff["baseRevision"] == workbench_api["EMPTY_GIT_TREE"]


def test_blob_batch_preserves_following_blobs_after_tree_and_commit(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    source = target / ("fixture.py" if os.name == "nt" else "line\nbreak.py")
    source.write_bytes(b"print('fixture')\npayload\n")
    git(target, "add", "--", source.name)
    git(target, "commit", "-qm", "Add unusual fixture")
    reader = load_script("workbench_target").git_blob_samples
    assert reader(
        target,
        ["HEAD^{tree}", "HEAD", f"HEAD:{source.name}", "HEAD:missing\nfile", "HEAD:README.md"],
    ) == [
        None,
        None,
        (source.read_bytes(), False),
        None,
        (b"fixture\n", False),
    ]


def test_plain_directory_inventory_ignores_nested_git_metadata(tmp_path: Path) -> None:
    target = tmp_path / "sources"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    nested = target / "nested"
    initialize_git_repository(nested)
    api = load_script("workbench_target")
    before = api.directory_content_digest(target)
    assert api.directory_snapshot_regular_file_count(target) == 2
    (nested / ".git" / "runtime-cache").write_text("bookkeeping\n")
    assert api.directory_content_digest(target) == before
    (nested / "README.md").write_text("changed source\n")
    assert api.directory_content_digest(target) != before


def test_git_directory_inventory_keeps_nested_bare_repository_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    nested = target / "nested.git"
    git(target, "init", "--bare", "--quiet", str(nested))
    (target / ".gitignore").write_text("nested.git/ignored-cache/\n")
    ignored = nested / "ignored-cache"
    ignored.mkdir()
    (ignored / "output.txt").write_text("ignored fixture\n")
    api = load_script("workbench_target")
    monkeypatch.setattr(api, "_WINDOWS", True)

    paths = api.git_directory_snapshot_paths(target)

    assert nested / "HEAD" in paths
    assert nested / "config" in paths
    assert all(ignored not in path.parents for path in paths)
    before = api.directory_content_digest(target)
    (nested / "description").write_text("changed bare repository fixture\n")
    assert api.directory_content_digest(target) != before


def test_excerpt_uses_target_relative_committed_path(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    (target / "app.py").write_text("root version\n")
    nested = target / "package"
    nested.mkdir()
    (nested / "app.py").write_text("package version\n")
    git(target, "add", ".")
    git(target, "commit", "-qm", "Add package")
    scan = {
        "target_revision": git(target, "rev-parse", "HEAD").decode(),
        "target_snapshot_digest": None,
        "diff_target_kind": "commit",
    }
    assert (
        load_script("workbench_source_excerpt").scanned_source_text(scan, nested, "app.py")
        == "package version\n"
    )


def test_working_tree_excerpt_declines_uncommitted_line_content(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    revision = git(target, "rev-parse", "HEAD").decode()
    (target / "README.md").write_text("uncommitted finding line\n")
    scan = {
        "target_revision": revision,
        "target_snapshot_digest": None,
        "diff_target_kind": "working_tree",
        "diff_content_digest": load_script("workbench_target").worktree_content_digest(target),
    }
    assert (
        load_script("workbench_source_excerpt").scanned_source_text(scan, target, "README.md")
        is None
    )


@pytest.mark.skipif(os.name == "nt", reason="Windows paths cannot retain arbitrary non-UTF-8 bytes")
def test_non_utf8_git_subject_and_refs_remain_inspectable(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    tree = git(target, "rev-parse", "HEAD^{tree}")
    commit = (
        b"tree "
        + tree
        + b"\nauthor Fixture <fixture@example.invalid> 1700000000 +0000\ncommitter Fixture <fixture@example.invalid> 1700000000 +0000\n\ncaf\xe9\n"
    )
    oid = git(target, "hash-object", "-t", "commit", "-w", "--stdin", input=commit).decode()
    git(target, "update-ref", "HEAD", oid)
    metadata = load_script("workbench_target").git_target_metadata(target)
    assert metadata["commitSubject"].startswith("caf")
    api = load_script("workbench_finding_workflows")
    connection = sqlite3.connect(":memory:")
    try:
        payload = {"id": "fixture", "action": "source", "repository": str(target)}
        before = api.finding_workflow(connection, payload, "2026-01-01T00:00:00Z")["source"]
        # Packed refs preserve raw bytes without requiring a non-UTF-8 filename.
        (target / ".git" / "packed-refs").write_bytes(oid.encode() + b" refs/heads/caf\xe9\n")
        after = api.finding_workflow(connection, payload, "2026-01-01T00:00:00Z")["source"]
        assert after["refsDigest"] != before["refsDigest"]
    finally:
        connection.close()


def test_dirty_submodule_warning_preserves_the_changed_target_detail(tmp_path: Path) -> None:
    origin = tmp_path / "origin"
    target = tmp_path / "target"
    initialize_git_repository(origin)
    initialize_git_repository(target)
    git(target, "-c", "protocol.file.allow=always", "submodule", "add", str(origin), "child")
    git(target, "commit", "-qam", "Add child")
    api = load_script("workbench_target")
    scan = {
        "target_path": str(target),
        "target_inode": target.stat().st_ino,
        "target_revision": git(target, "rev-parse", "HEAD").decode(),
        "target_snapshot_digest": api.worktree_content_digest(target),
        "diff_target_kind": None,
        "scan_dir": str(tmp_path / "artifacts"),
    }
    (target / "child" / "README.md").write_text("changed child source\n")
    warning = api.scan_target_warning(scan)
    assert "Dirty Git submodules" in warning
    assert "child" in warning
    assert "results were saved" in warning


def test_disabled_git_source_snapshot_does_not_inspect_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = load_script("workbench_finding_workflows")
    (tmp_path / "source.py").write_text("print('fixture')\n")

    def unexpected_git(*args, **kwargs):
        pytest.fail("disabled Git must not inspect revisions or refs")

    monkeypatch.setattr(api, "git_revision", unexpected_git)
    monkeypatch.setattr(api, "git_bytes", unexpected_git)
    with closing(sqlite3.connect(":memory:")) as connection:
        source = api.finding_workflow(
            connection,
            {"id": "fixture", "action": "source", "repository": str(tmp_path), "gitDisabled": True},
            "2026-01-01T00:00:00Z",
        )["source"]
    assert source["revision"] == "unversioned"
    assert source["refsDigest"] == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("mode", ["revisions", "local-patch"])
@pytest.mark.parametrize("replacement", ["symlink", "gitlink"])
def test_diff_inventories_exclude_non_file_type_changes(
    tmp_path: Path, mode: str, replacement: str
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    source = target / "replaced.py"
    source.write_text("old source\n")
    git(target, "add", ".")
    git(target, "commit", "-qm", "Add source fixture")
    base = git(target, "rev-parse", "HEAD").decode()
    if replacement == "symlink":
        source.unlink()
        try:
            source.symlink_to("README.md")
        except OSError:
            pytest.skip("symlinks are unavailable")
    else:
        origin = tmp_path / "origin"
        initialize_git_repository(origin)
        git(target, "rm", "-f", source.name)
        git(
            target, "-c", "protocol.file.allow=always", "submodule", "add", str(origin), source.name
        )
    (target / "visible.py").write_text("value = 1\n")
    git(target, "add", ".")
    if mode == "revisions":
        git(target, "commit", "-qm", "Replace source type")
    inventory_path = tmp_path / "inventory.txt"
    rank_path = tmp_path / "rank.jsonl"
    load_script("generate_in_scope_files").generate_diff_in_scope_files(
        target, base, "HEAD", mode, inventory_path
    )
    load_script("generate_rank_input").make_diff_rank_input(
        argparse.Namespace(
            repo=str(target),
            base=base,
            head="HEAD",
            mode=mode,
            out=str(rank_path),
            area="fixture",
            preview_bytes=1024,
        )
    )
    expected = [".gitmodules", "visible.py"] if replacement == "gitlink" else ["visible.py"]
    assert inventory_path.read_text().splitlines() == expected
    assert [json.loads(line)["path"] for line in rank_path.read_text().splitlines()] == expected
