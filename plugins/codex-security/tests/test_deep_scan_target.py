"""Exercise filesystem failures encountered below a selected Deep Scan directory."""

from __future__ import annotations

import errno
import os
import runpy
import subprocess
from contextlib import contextmanager, nullcontext
from pathlib import Path

import pytest
from workbench_test_support import initialize_git_repository


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


requires_permissions = pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0, reason="requires POSIX permissions"
)


def git(root, *args):
    subprocess.run(["git", "-C", root, *args], check=True)


@contextmanager
def unreadable(path):
    mode = path.stat().st_mode
    path.chmod(0)
    try:
        yield
    finally:
        path.chmod(mode)


@pytest.mark.parametrize(
    ("damage", "diagnostic"),
    [
        pytest.param("index", "index", marks=pytest.mark.cross_platform),
        pytest.param("config", "config", marks=pytest.mark.cross_platform),
        pytest.param("HEAD", "git repository", marks=pytest.mark.cross_platform),
        pytest.param("permissions", "git repository|Permission denied", marks=requires_permissions),
    ],
)
@pytest.mark.parametrize("layout", ["single", "gitlink", "untracked"])
def test_damaged_checkout_does_not_supply_ignored_content(
    tmp_path, check_targets, damage, diagnostic, layout
):
    import workbench_target

    root = tmp_path / "repo"
    initialize_git_repository(root)
    selected = root / "selected"
    selected.mkdir()
    checkout = root
    scopes = ["selected"]
    if layout != "single":
        checkout = selected / "nested"
        initialize_git_repository(checkout)
        if layout == "gitlink":
            git(root, "add", "selected/nested")
        (checkout / "README.md").unlink()
        scopes.extend(["selected/nested", "selected/nested/src"])
    metadata = checkout / ".git"
    if damage == "HEAD":
        (metadata / "config").unlink()  # Optional in a healthy checkout.
    source_dir = root / scopes[-1]
    source_dir.mkdir(exist_ok=True)
    source = source_dir / "source.py"
    source.touch()
    (metadata / "info" / "exclude").write_text("*.ignored\n")
    cache = source_dir / "cache.ignored"
    cache.touch()
    for scope in scopes:
        check_targets(root, [scope], [])
    source.unlink()
    for scope in scopes:
        with pytest.raises(ValueError, match="target is empty"):
            check_targets(root, [scope], [])

    if damage == "HEAD":
        (metadata / damage).unlink()
    elif damage != "permissions":
        (metadata / damage).write_bytes(b"[invalid")
    permissions = unreadable(metadata) if damage == "permissions" else nullcontext()
    with permissions:
        error = PermissionError if damage == "permissions" and layout == "single" else OSError
        for scope in scopes:
            with pytest.raises(error, match=diagnostic):
                check_targets(root, [scope], [])
            check_targets(root, [scope, "README.md"], ["README.md"])
        if layout == "gitlink" and damage != "index":
            assert cache in workbench_target.git_directory_snapshot_paths(selected)
            if damage == "HEAD":
                for scope in scopes[1:]:
                    assert workbench_target.git_directory_snapshot_paths(root / scope) == []
        if layout != "single":
            (selected / "usable.py").touch()
            check_targets(root, ["selected"], [])


@pytest.mark.cross_platform
def test_deinitialized_gitlink_can_supply_ordinary_files(tmp_path, check_targets):
    git(tmp_path, "init", "-q")
    nested = tmp_path / "nested"
    initialize_git_repository(nested)
    git(tmp_path, "add", "nested")
    child = nested / "src"
    child.mkdir()
    source = (nested / "README.md").rename(child / "source")
    (nested / ".git").rename(tmp_path / ".git" / "saved-metadata")
    check_targets(tmp_path, ["."], [])
    for scope in ("nested", "nested/src"):
        with pytest.raises(ValueError, match="target is empty"):
            check_targets(tmp_path, [scope], [])
    source.unlink()
    with pytest.raises(ValueError, match="target is empty"):
        check_targets(tmp_path, ["."], [])


@requires_permissions
@pytest.mark.parametrize("tracked", [True, False])
def test_unreadable_child_with_a_readable_sibling(tmp_path, monkeypatch, check_targets, tracked):
    git(tmp_path, "init", "-q")
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (blocked / "child.py").touch()
    if tracked:
        git(tmp_path, "add", "blocked/child.py")
    # Git may localize the warning that signals a successful but partial ls-files result.
    monkeypatch.setenv("LC_ALL", "fr_FR.UTF-8")
    monkeypatch.setenv("LANGUAGE", "fr")
    with unreadable(blocked):
        with pytest.raises(OSError, match="Permission denied"):
            check_targets(tmp_path, ["."], [])
        (tmp_path / "usable.py").touch()
        check_targets(tmp_path, ["."], [])


@pytest.mark.cross_platform
def test_successful_git_trace_is_not_an_enumeration_error(tmp_path, monkeypatch, check_targets):
    git(tmp_path, "init", "-q")
    monkeypatch.setenv("GIT_TRACE", "1")
    with pytest.raises(ValueError, match="target is empty"):
        check_targets(tmp_path, ["."], [])


@pytest.mark.cross_platform
@pytest.mark.parametrize("failure", ["ls-files", "check-ignore"])
def test_windows_directory_query_errors_preserve_usable_sources(
    tmp_path, monkeypatch, check_targets, failure
):
    import workbench_target

    git(tmp_path, "init", "-q")
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


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("operation", "relative", "code"),
    [
        ("lstat", "denied", errno.EACCES),
        ("iterdir", "denied", errno.EIO),
        ("lstat", "denied/child", errno.EIO),
    ],
)
def test_windows_directory_entry_errors_preserve_partial_inventory(
    tmp_path, monkeypatch, check_targets, operation, relative, code
):
    import workbench_target

    git(tmp_path, "init", "-q")
    (tmp_path / "denied" / "child").mkdir(parents=True)
    source = tmp_path / "README.md"
    source.touch()
    denied = tmp_path / relative
    failure = OSError(code, "Synthetic inventory failure", str(denied))
    original = getattr(Path, operation)

    failures = []

    def inspect(path):
        if path == denied:
            failures.append(path)
            raise failure
        return original(path)

    monkeypatch.setattr(workbench_target, "_WINDOWS", True)
    monkeypatch.setattr(Path, operation, inspect)
    with pytest.raises(OSError) as caught:
        workbench_target.git_directory_snapshot_paths(tmp_path)
    assert caught.value is failure
    failures.clear()
    check_targets(tmp_path, ["."], [])
    assert not failures  # Admission stops before the supplementary Windows inventory.
    source.unlink()
    with pytest.raises(OSError) as caught:
        check_targets(tmp_path, ["."], [])
    assert caught.value is failure


@requires_permissions
def test_unreadable_case_variant_keeps_the_selected_directory_usable(tmp_path, check_targets):
    selected = tmp_path / "selected" / "dirs"
    selected.mkdir(parents=True)
    alias = tmp_path / "SELECTED"
    if alias.exists():
        pytest.skip("requires a case-sensitive filesystem")
    (alias / "dirs").mkdir(parents=True)
    (alias / "dirs" / "hidden").touch()
    (selected / "good").touch()
    git(tmp_path, "init", "-q")
    git(tmp_path, "add", ".")
    with unreadable(alias):
        check_targets(tmp_path, ["selected/dirs"], [])


@pytest.mark.cross_platform
def test_selected_scope_allows_an_empty_git_marker_or_a_valid_gitfile_alias(
    tmp_path, check_targets
):
    root = tmp_path / "repo"
    initialize_git_repository(root)
    selected = root / "selected"
    selected.mkdir()
    (selected / "visible.py").touch()
    git(root, "add", "selected/visible.py")
    marker = selected / ".git"
    marker.mkdir()
    check_targets(root, ["selected"], [])
    marker.rmdir()
    git(root, "config", "core.worktree", root.as_posix())
    marker.write_text("gitdir: ../.git\n")
    check_targets(root, ["selected"], [])


@pytest.mark.cross_platform
def test_directory_on_separate_filesystem_does_not_inherit_checkout(
    tmp_path, monkeypatch, check_targets
):
    import workbench_target

    git(tmp_path, "init", "-q")
    mounted = tmp_path / "mounted"
    selected = mounted / "src"
    selected.mkdir(parents=True)
    source = selected / "source.py"
    source.touch()
    original_stat = Path.stat
    original_git = workbench_target.git_command

    # Emulate a device boundary without mount privileges, and give Git the same discovery ceiling.
    def stat(path, *args, **kwargs):
        result = original_stat(path, *args, **kwargs)
        if path == tmp_path:
            fields = list(result)
            fields[2] += 1  # st_dev
            return os.stat_result(fields)
        return result

    def query(target, *args, **kwargs):
        return original_git(
            target,
            *args,
            **kwargs,
            environment_overrides={"GIT_CEILING_DIRECTORIES": tmp_path.as_posix()},
        )

    monkeypatch.setattr(Path, "stat", stat)
    monkeypatch.setattr(workbench_target, "git_command", query)
    check_targets(mounted, ["src"], [])
    source.unlink()
    with pytest.raises(ValueError, match="target is empty"):
        check_targets(mounted, ["src"], [])
    (mounted / ".git").mkdir()
    (mounted / ".git" / "HEAD").write_text("broken")
    with pytest.raises(OSError, match="git repository"):
        check_targets(mounted, ["src"], [])
