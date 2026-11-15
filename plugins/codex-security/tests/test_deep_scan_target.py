"""Exercise filesystem failures encountered below a selected Deep Scan directory."""

from __future__ import annotations

import errno
import os
import runpy
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def check_targets():
    script = Path(__file__).resolve().parents[1] / "scripts" / "check_deep_scan_target.py"
    return runpy.run_path(str(script))["check_selected_targets"]


@pytest.mark.cross_platform
def test_nested_read_failure_is_preserved_unless_another_selection_has_content(
    tmp_path, monkeypatch, check_targets
):
    root = tmp_path / "target"
    denied = root / "empty" / "nested"
    denied.mkdir(parents=True)
    failure = PermissionError(errno.EACCES, "Synthetic denied directory", str(denied))
    original = os.scandir

    def scandir(path):
        if Path(path) == denied:
            raise failure
        return original(path)

    monkeypatch.setattr(os, "scandir", scandir)
    with pytest.raises(PermissionError) as caught:
        check_targets(root, ["empty"], [])
    assert caught.value is failure
    (root / "sibling.py").write_text("")
    check_targets(root, ["empty", "sibling.py"], ["sibling.py"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory symlink fixture")
def test_nested_directory_links_are_not_followed(tmp_path, monkeypatch, check_targets):
    root = tmp_path / "target"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    original = os.scandir

    def scandir(path):
        assert Path(path) != outside
        return original(path)

    monkeypatch.setattr(os, "scandir", scandir)
    check_targets(root, ["."], [])


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("filename", "contents", "diagnostic"),
    [
        ("index", b"invalid index", "index"),
        ("config", b"[invalid", "config"),
        ("HEAD", None, "not a git repository"),
    ],
)
def test_git_inventory_failure_is_reported_with_its_diagnostic(
    tmp_path, check_targets, filename, contents, diagnostic
):
    subprocess.run(["git", "-C", tmp_path, "init", "-q"], check=True)
    metadata = tmp_path / ".git" / filename
    if contents is None:
        metadata.unlink()
    else:
        metadata.write_bytes(contents)
    (tmp_path / "selected").mkdir()
    (tmp_path / "selected" / "cache").touch()
    with pytest.raises(OSError, match=diagnostic):
        check_targets(tmp_path, ["selected"], [])
    (tmp_path / "selected.py").touch()
    check_targets(tmp_path, ["selected", "selected.py"], ["selected.py"])


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="requires POSIX permissions")
@pytest.mark.parametrize("tracked", [True, False])
def test_unreadable_child_with_a_readable_sibling(tmp_path, monkeypatch, check_targets, tracked):
    subprocess.run(["git", "-C", tmp_path, "init", "-q"], check=True)
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "child.py").touch()
    if tracked:
        subprocess.run(["git", "-C", tmp_path, "add", "blocked/child.py"], check=True)
    # Git may localize the warning that signals a successful but partial ls-files result.
    monkeypatch.setenv("LC_ALL", "fr_FR.UTF-8")
    monkeypatch.setenv("LANGUAGE", "fr")
    blocked.chmod(0)
    try:
        with pytest.raises(OSError, match="Permission denied"):
            check_targets(tmp_path, ["."], [])
        (tmp_path / "usable.py").touch()
        check_targets(tmp_path, ["."], [])
    finally:
        blocked.chmod(0o700)


@pytest.mark.cross_platform
def test_successful_git_trace_is_not_an_enumeration_error(tmp_path, monkeypatch, check_targets):
    subprocess.run(["git", "-C", tmp_path, "init", "-q"], check=True)
    monkeypatch.setenv("GIT_TRACE", "1")
    with pytest.raises(ValueError, match="target is empty"):
        check_targets(tmp_path, ["."], [])


@pytest.mark.cross_platform
@pytest.mark.parametrize("failure", ["ls-files", "check-ignore"])
def test_windows_directory_query_errors_preserve_usable_sources(
    tmp_path, monkeypatch, check_targets, failure
):
    import workbench_target

    subprocess.run(["git", "-C", tmp_path, "init", "-q"], check=True)
    selected = tmp_path / "selected"
    (selected / "nested" / "child").mkdir(parents=True)
    sibling = tmp_path / "sibling.py"
    sibling.touch()

    def query(target, *args, **kwargs):
        if failure in args:
            return subprocess.CompletedProcess(args, 128, b"", b"fatal: synthetic directory error")
        assert "ls-files" in args
        return subprocess.CompletedProcess(args, 0, b"nested/\0", b"")

    monkeypatch.setattr(workbench_target, "_WINDOWS", True)
    monkeypatch.setattr(workbench_target, "_windows_inventory_query", query)
    with pytest.raises(SystemExit, match="Could not inspect directories"):
        workbench_target.git_directory_snapshot_paths(selected)
    with pytest.raises(OSError, match="synthetic directory error"):
        check_targets(tmp_path, ["selected"], [])
    for scopes in (["selected", sibling.name], [sibling.name, "selected"]):
        check_targets(tmp_path, scopes, [sibling.name])
    (selected / "source.py").touch()
    check_targets(tmp_path, ["selected"], [])
