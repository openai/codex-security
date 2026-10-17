from __future__ import annotations

import difflib
import errno
import hashlib
import os
import runpy
import shutil
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, cast

import pytest
from workbench_test_support import initialize_git_repository

WORKBENCH_TARGET = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_target.py")
)
trusted_git_executable = WORKBENCH_TARGET["trusted_git_executable"]
directory_content_digest = cast(Callable[[Path], str], WORKBENCH_TARGET["directory_content_digest"])
worktree_content_digest = cast(Callable[[Path], str], WORKBENCH_TARGET["worktree_content_digest"])
update_digest_field = cast(
    Callable[[Any, bytes, bytes], None], WORKBENCH_TARGET["update_digest_field"]
)


@pytest.fixture(
    params=[
        pytest.param(False, id="emulated"),
        pytest.param(True, id="native", marks=pytest.mark.native_windows),
    ]
)
def junction_factory(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch):
    import workbench_target

    native = request.param
    if native and os.name != "nt":
        pytest.skip("requires native Windows junctions")
    targets: dict[Path, Path] = {}
    modes: dict[Path, int] = {}
    if not native:
        monkeypatch.setattr(workbench_target, "_WINDOWS", True)
        real_lstat = Path.lstat
        real_readlink = os.readlink

        def metadata(path: Path, *args: Any, **kwargs: Any) -> Any:
            result = real_lstat(path, *args, **kwargs)
            if path in targets:
                fields = {key: getattr(result, key) for key in dir(result) if key.startswith("st_")}
                fields["st_reparse_tag"] = 0xA0000003
                fields["st_mode"] = modes.get(path, result.st_mode)
                return SimpleNamespace(**fields)
            return result

        def readlink(path: Any, *args: Any, **kwargs: Any) -> Any:
            if Path(path) in targets:
                return str(targets[Path(path)])
            return real_readlink(path, *args, **kwargs)

        def copy_junction(source: Path, destination: Path) -> None:
            # Emulate the filesystem result, not the native GET/SET implementation.
            if any(destination.iterdir()):
                raise OSError(errno.ENOTEMPTY, "junction destination is not empty")
            mode = destination.lstat().st_mode
            # Windows readonly directories do not impose POSIX child-write permissions.
            os.chmod(destination, stat.S_IMODE(mode) | stat.S_IWUSR)
            shutil.copytree(source, destination, dirs_exist_ok=True)
            os.chmod(destination, 0o755)
            targets[destination] = targets[source]
            modes[destination] = mode

        monkeypatch.setattr(Path, "lstat", metadata)
        monkeypatch.setattr(os, "readlink", readlink)
        monkeypatch.setattr(workbench_target, "copy_directory_junction", copy_junction)

    def create(link: Path, target: Path) -> None:
        if native:
            if link.exists():
                link.rmdir()
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], check=True)
        else:
            shutil.copytree(target, link, dirs_exist_ok=True)
            targets[link] = target

    return create


@pytest.mark.parametrize(
    ("git_repository", "git_exclusion"),
    [
        (None, None),
        ("untracked", None),
        ("indexed", None),
        ("untracked", ".gitignore"),
        ("untracked", ".git/info/exclude"),
        ("nested", ".git/info/exclude"),
    ],
    ids=[
        "plain",
        "git-untracked",
        "git-indexed",
        "gitignore",
        "git-info-exclude",
        "nested-info-exclude",
    ],
)
@pytest.mark.parametrize(
    "change",
    [
        "unchanged",
        "unrelated_file",
        "junction_target",
        "same_content_target",
        "target_contents",
        "target_emptied",
        "target_populated",
    ],
)
def test_reviewed_patch_preserves_junction_boundaries(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    change: str,
    git_repository: str | None,
    git_exclusion: str | None,
) -> None:
    import workbench_db

    source = tmp_path / "source"
    source.mkdir()
    if git_repository:
        subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    junction_root = source
    if git_repository == "nested":
        junction_root = source / "nested"
        initialize_git_repository(junction_root)
    if git_exclusion is not None:
        (junction_root / git_exclusion).write_text("dependencies/linked_directory/\n")
    (junction_root / "dependencies").mkdir()
    junction = junction_root / "dependencies" / "linked_directory"
    outside = tmp_path / "outside"
    outside.mkdir()
    if change != "target_populated":
        (outside / "source.txt").write_text("original contents\n")
    junction_factory(junction, outside)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = b"diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    (source / "app.txt").write_text("before\n")
    if git_repository == "indexed":
        subprocess.run(["git", "add", "."], cwd=source, check=True)
    remediation = {
        "base_revision": "unversioned",
        "base_content_digest": workbench_db.directory_content_digest(source),
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / "app.txt").write_text("after\n")
    if change in {"junction_target", "same_content_target"}:
        junction_target = tmp_path / "other"
        junction_target.mkdir()
        (junction_target / "source.txt").write_text(
            "original contents\n"
            if change == "same_content_target"
            else "different target contents\n"
        )
        junction_factory(junction, junction_target)
    elif change in {"target_contents", "target_populated"}:
        (junction / "source.txt").write_text("changed outside the snapshot boundary\n")
    elif change == "target_emptied":
        (junction / "source.txt").unlink()
    elif change == "unrelated_file":
        (source / "unrelated.txt").write_text("outside the reviewed patch\n")
    if change == "unrelated_file" or (
        change in {"junction_target", "same_content_target"} and git_exclusion is None
    ):
        with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    else:
        assert workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")


@pytest.mark.parametrize(
    ("git_repository", "readonly_target"),
    [(False, False), (True, False), (False, True)],
    ids=["plain", "git", "readonly-empty-target"],
)
def test_reviewed_patch_preserves_readonly_junction(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    git_repository: bool,
    readonly_target: bool,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    if git_repository:
        subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    if readonly_target:
        os.chmod(outside, stat.S_IREAD | stat.S_IEXEC)
    else:
        (outside / "file.txt").write_text("external contents\n")
    outside_mode = outside.stat().st_mode
    junction = source / "linked"
    junction_factory(junction, outside)
    os.chmod(junction, stat.S_IREAD | stat.S_IEXEC)
    try:
        assert not junction.lstat().st_mode & stat.S_IWRITE
        assert outside.stat().st_mode == outside_mode
        assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n")
        assert outside.stat().st_mode == outside_mode
        if not readonly_target:
            assert (outside / "file.txt").read_text() == "external contents\n"
    finally:
        os.chmod(junction, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)


@pytest.mark.parametrize("scope", [".", "component"])
@pytest.mark.parametrize("populated", [False, True])
def test_versioned_reviewed_patch_preserves_nested_junctions(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
    scope: str,
    populated: bool,
) -> None:
    import workbench_db

    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    target = repository / scope
    target.mkdir(exist_ok=True)
    (target / "app.txt").write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-qm", "Add target"], cwd=repository, check=True)
    nested = target / "nested"
    initialize_git_repository(nested)
    outside = tmp_path / "outside"
    outside.mkdir()
    if populated:
        (outside / "external.txt").write_text("outside contents\n")
    junction = nested / "linked"
    junction_factory(junction, outside)
    relative_junction = junction.relative_to(repository)
    original_command = workbench_db.git_command
    original_restore = workbench_db.restore_directory_junctions
    reversed_roots: list[Path] = []
    restored: list[Path] = []

    def command(path, *args, **kwargs):
        if args[0] == "apply":
            copied = kwargs["work_tree"]
            placeholder = copied / relative_junction
            assert placeholder.is_dir()
            assert not getattr(placeholder.lstat(), "st_reparse_tag", 0)
            assert list(placeholder.iterdir()) == []
        result = original_command(path, *args, **kwargs)
        if args[0] == "apply" and result.returncode == 0:
            reversed_roots.append(copied)
        return result

    def restore(source, destination, junctions):
        assert source == repository
        assert reversed_roots == [destination]
        assert relative_junction in junctions
        original_restore(source, destination, junctions)
        restored.append(destination)

    monkeypatch.setattr(workbench_db, "git_command", command)
    monkeypatch.setattr(workbench_db, "restore_directory_junctions", restore)
    assert_reviewed_change(
        target,
        tmp_path,
        "app.txt",
        "before\n",
        "after\n",
        revision=workbench_db.git_revision(target),
    )
    assert len(restored) == 1
    assert sorted(path.name for path in outside.iterdir()) == (
        ["external.txt"] if populated else []
    )
    if populated:
        assert (outside / "external.txt").read_text() == "outside contents\n"


@pytest.mark.parametrize(
    "case",
    [
        "ordering",
        "ignore_add",
        "ignore_remove",
        "git_metadata",
        "git_metadata_crlf",
        "git_metadata_lf",
        "git_objects",
    ],
)
def test_reviewed_patch_restores_junction_git_context(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    case: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    newline = None
    if case in {"git_metadata_crlf", "git_metadata_lf"}:
        global_config = tmp_path / "global.gitconfig"
        global_config.write_text("[core]\n\tautocrlf = false\n")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        subprocess.run(["git", "config", "core.autocrlf", "true"], cwd=source, check=True)
        newline = "\r\n" if case == "git_metadata_crlf" else "\n"
    (source / "src").mkdir()
    (source / "src" / "app.txt").write_text("stable contents\n")
    (source / "src.py").write_text("adjacent contents\n")
    (source / "Alpha.txt").write_text("mixed case ordering\n")
    (source / ".gitignore").write_text("cache/\n")
    (source / "cache").mkdir()
    (source / "cache" / "output.txt").write_text("ignored output\n")
    outside = tmp_path / "outside"
    if case.startswith("git_metadata") or case == "git_objects":
        junction = source / (".git" if case.startswith("git_metadata") else ".git/objects")
        junction.rename(outside)
    else:
        outside.mkdir()
        (outside / "file.txt").write_text("external contents\n")
        junction = source / "linked"
    junction_factory(junction, outside)
    patched = ".gitignore" if case.startswith("ignore_") else "app.txt"
    before = (
        "# fixture\nlinked/\n"
        if case == "ignore_remove"
        else "# fixture\n"
        if case == "ignore_add"
        else "before\n"
    )
    after = (
        "# fixture\nlinked/\n"
        if case == "ignore_add"
        else "# fixture\n"
        if case == "ignore_remove"
        else "after\n"
    )
    metadata = (outside / "config").read_bytes() if case.startswith("git_metadata") else None
    assert_reviewed_change(source, tmp_path, patched, before, after, newline=newline)
    assert outside.is_dir()
    if metadata is not None:
        assert (outside / "config").read_bytes() == metadata
    if newline is not None:
        assert (source / patched).read_bytes() == after.replace("\n", newline).encode()


@pytest.mark.cross_platform
def test_reviewed_patch_preserves_scoped_unborn_lf_bytes(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    initialize_unborn_git_repository(repository)
    attributes = tmp_path / "attributes"
    attributes.write_text("*.txt text eol=crlf\n")
    subprocess.run(
        ["git", "config", "core.attributesFile", str(attributes)], cwd=repository, check=True
    )
    source = repository / "component"
    source.mkdir()

    assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n", newline="\n")

    assert (source / "app.txt").read_bytes() == b"after\n"


def assert_reviewed_change(
    source: Path,
    tmp_path: Path,
    relative: str,
    before: str,
    after: str,
    *,
    newline: str | None = None,
    revision: str = "unversioned",
) -> None:
    import workbench_db

    patch = (
        f"diff --git a/{relative} b/{relative}\n"
        + "".join(
            difflib.unified_diff(
                before.splitlines(True),
                after.splitlines(True),
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
            )
        )
    ).encode()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": revision,
        "scan_dir": str(scan_dir),
    }
    (source / relative).write_text(before, newline=newline)
    revision, digest = workbench_db.remediation_checkout_snapshot(scan)
    remediation = {
        "base_revision": revision,
        "base_content_digest": digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / relative).write_text(after, newline=newline)
    assert workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires native Windows path casing")
def test_native_reviewed_patch_preserves_indexed_junction_spelling(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    subprocess.run(["git", "config", "core.ignorecase", "true"], cwd=source, check=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("external contents\n")
    junction = source / "linked"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)], check=True)
    (source / "app.txt").write_text("before\n")
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    junction.rename(source / "Linked")
    assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n")


def test_indexed_junction_case_aliases_keep_snapshot_identity(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import workbench_target

    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    subprocess.run(["git", "config", "core.ignorecase", "true"], cwd=source, check=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("external contents\n")
    junction = source / "linked"
    junction_factory(junction, outside)
    subprocess.run(["git", "add", "."], cwd=source, check=True)
    metadata = junction.lstat()
    renamed = junction.rename(source / "Linked")
    if not getattr(renamed.lstat(), "st_reparse_tag", 0):
        # Supply case aliases for the emulated junction on a case-sensitive volume.
        real_lstat = Path.lstat
        real_readlink = os.readlink
        monkeypatch.setattr(
            Path,
            "lstat",
            lambda path: metadata if path in (junction, renamed) else real_lstat(path),
        )
        monkeypatch.setattr(
            os,
            "readlink",
            lambda path: str(outside) if Path(path) in (junction, renamed) else real_readlink(path),
        )
    before = workbench_target.directory_content_digest(source)

    (renamed / "new.txt").write_text("new external contents\n")
    assert workbench_target.directory_content_digest(source) == before
    (renamed / "file.txt").unlink()
    (renamed / "new.txt").unlink()
    assert workbench_target.directory_content_digest(source) == before


def test_reverse_patch_cannot_write_through_junction(
    tmp_path: Path, junction_factory: Callable[[Path, Path], None]
) -> None:
    import workbench_db

    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("outside contents\n")
    junction = source / "linked"
    junction_factory(junction, outside)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = b"diff --git a/linked/deleted.txt b/linked/deleted.txt\ndeleted file mode 100644\n--- a/linked/deleted.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-removed\n"
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    remediation = {
        "base_revision": "unversioned",
        "base_content_digest": "different base",
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    with pytest.raises(OSError):
        workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    assert sorted(path.name for path in outside.iterdir()) == ["keep.txt"]
    assert (outside / "keep.txt").read_text() == "outside contents\n"


def test_reverse_patch_cannot_redirect_junction_restoration(
    tmp_path: Path,
    junction_factory: Callable[[Path, Path], None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import workbench_db

    source = tmp_path / "source"
    (source / "dep").mkdir(parents=True)
    original_target = tmp_path / "original"
    original_target.mkdir()
    (original_target / "keep.txt").write_text("original contents\n")
    junction = source / "dep" / "linked"
    junction_factory(junction, original_target)
    os.chmod(junction, stat.S_IREAD | stat.S_IEXEC)
    outside = tmp_path / "outside"
    external = outside / "linked"
    external.mkdir(parents=True)
    original_mode = external.stat().st_mode
    config = tmp_path / "gitconfig"
    config.write_text("[core]\n\tsymlinks = true\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = f"""diff --git a/app.txt b/app.txt
--- a/app.txt
+++ b/app.txt
@@ -1 +1 @@
-before
+after
diff --git a/dep b/dep
deleted file mode 120000
--- a/dep
+++ /dev/null
@@ -1 +0,0 @@
-{outside.as_posix()}
\\ No newline at end of file
diff --git a/dep/linked b/dep/linked
new file mode 160000
index {"0" * 40}..{"1" * 40}
--- /dev/null
+++ b/dep/linked
@@ -0,0 +1 @@
+Subproject commit {"1" * 40}
""".encode()
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    (source / "app.txt").write_text("before\n")
    remediation = {
        "base_revision": "unversioned",
        "base_content_digest": workbench_db.directory_content_digest(source),
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    (source / "app.txt").write_text("after\n")
    try:
        with pytest.raises(SystemExit, match="checkout path was replaced"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
        assert external.lstat().st_mode == original_mode
        assert not getattr(external.lstat(), "st_reparse_tag", 0)
        assert list(external.iterdir()) == []
        assert (original_target / "keep.txt").read_text() == "original contents\n"
    finally:
        os.chmod(junction, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)


def initialize_unborn_git_repository(target: Path) -> None:
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)


def test_windows_inventory_batches_wide_untracked_trees(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_target

    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    monkeypatch.setattr(workbench_target, "_WINDOWS", True)
    run_git = workbench_target.git_command
    calls = 0

    def counted_git(*args: Any, **kwargs: Any):
        nonlocal calls
        calls += 1
        return run_git(*args, **kwargs)

    monkeypatch.setattr(workbench_target, "git_command", counted_git)
    sources = []
    for index in range(16):
        source = target / f"component-{index}" / "src" / "app.py"
        source.parent.mkdir(parents=True)
        source.write_text("print('fixture')\n")
        sources.append(source)
        if index == 0:
            assert workbench_target.git_directory_snapshot_paths(target) == sources
            single_directory_calls = calls
            calls = 0

    assert set(workbench_target.git_directory_snapshot_paths(target)) == set(sources)
    assert calls == single_directory_calls


@pytest.mark.parametrize("change", ["unchanged", "ignored_file", "unrelated_file"])
def test_reviewed_patch_preserves_unborn_git_inventory(tmp_path: Path, change: str) -> None:
    import workbench_db

    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    (source / "src").mkdir()
    app = source / "src" / "app.txt"
    app.write_text("before\n")
    (source / ".gitignore").write_text("ignored-cache/\n")
    cache = source / "ignored-cache"
    cache.mkdir()
    cached_file = cache / "output.txt"
    cached_file.write_text("ignored build output\n")
    subprocess.run(["git", "add", ".gitignore", "src/app.txt"], cwd=source, check=True)
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    patch = (
        b"diff --git a/src/app.txt b/src/app.txt\n"
        b"--- a/src/app.txt\n+++ b/src/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    )
    (scan_dir / "reviewed.patch").write_bytes(patch)
    scan = {
        "target_path": str(source),
        "target_inode": source.stat().st_ino,
        "target_revision": "unversioned",
        "scan_dir": str(scan_dir),
    }
    revision, digest = workbench_db.remediation_checkout_snapshot(scan)
    assert revision == "unversioned"
    remediation = {
        "base_revision": revision,
        "base_content_digest": digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }
    app.write_text("after\n")
    if change == "ignored_file":
        cached_file.write_text("updated ignored build output\n")
    elif change == "unrelated_file":
        (source / "unrelated.txt").write_text("outside the reviewed patch\n")
    if change == "unrelated_file":
        with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    else:
        assert workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")


def add_submodule_gitlink(repository: Path, revision: str, scope: str) -> None:
    subprocess.run(
        [
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{revision},{(Path(scope) / 'submodule').as_posix()}",
        ],
        cwd=repository,
        check=True,
    )


def set_default_subprocess_encoding(monkeypatch: pytest.MonkeyPatch, encoding: str) -> None:
    run = subprocess.run

    def run_with_default_encoding(*args: Any, **kwargs: Any):
        if kwargs.get("text") and kwargs.get("encoding") is None:
            kwargs["encoding"] = encoding
        return run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", run_with_default_encoding)


def test_stale_git_binding_does_not_spawn(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(tmp_path / "missing-git"))

    def unexpected_spawn(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("stale Git binding reached subprocess.run")

    monkeypatch.setattr(subprocess, "run", unexpected_spawn)
    result = WORKBENCH_TARGET["git_command"](tmp_path, "status", text=True)
    assert result.returncode == 127
    assert result.stdout == ""
    assert result.args[0] == "git"


@pytest.mark.parametrize(
    ("encoding", "bom"),
    [("utf-8", b""), ("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")],
)
def test_git_blob_samples_match_full_file_classification_with_bounded_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encoding: str, bom: bytes
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    # The UTF-16 surrogate pair crosses the first 64 KiB sample boundary.
    text = bom + ("a" * 32766 + "😀" + "b" * 32768).encode(encoding)
    contents = {
        "text.bin": text + (b"\0" if bom else b""),
        "binary-tail.bin": text + "\0".encode(encoding),
        "binary-head.bin": b"\0" + text * 32,
        "empty.bin": b"",
        "after.txt": b"after\n",
    }
    for name, content in contents.items():
        (target / name).write_bytes(content)
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "source samples"], cwd=target, check=True)

    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]
    function_globals = git_blob_samples.__globals__
    read_batch_samples = function_globals["_read_git_batch_samples"]
    reads: list[int] = []

    def require_bounded_output(output: Any, names: list[str]):
        assert not output.seekable()
        read = output.read

        def bounded_read(size: int = -1) -> bytes:
            assert 0 <= size <= 64 * 1024
            reads.append(size)
            return read(size)

        output.read = bounded_read
        return read_batch_samples(output, names)

    monkeypatch.setitem(function_globals, "_read_git_batch_samples", require_bounded_output)
    # Both request and response exceed pipe buffers, before the multi-megabyte binary.
    missing = ["HEAD:missing"] * 10_000
    samples = git_blob_samples(target, [*missing, *(f"HEAD:{name}" for name in contents)])

    assert samples == [
        *([None] * len(missing)),
        (text[: 64 * 1024], False),
        (b"", True),
        (b"", True),
        (b"", False),
        (b"after\n", False),
    ]
    assert max(reads) == 64 * 1024


@pytest.mark.parametrize(
    "output",
    [
        b"missing terminator",
        b"object blob invalid\n",
        b"object blob -1\n",
        b"object blob 4\nabc",
        b"object blob 4\nabcd!",
        b"object blob invalid\n" + b"x" * (4 * 1024 * 1024),
        b"object blob 131072\n" + b"x" * (64 * 1024 + 1),
    ],
)
def test_git_blob_samples_reject_incomplete_framing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]

    def git_command(*args: Any, **kwargs: Any):
        remaining = memoryview(output)
        try:
            while remaining:
                written = os.write(kwargs["stdout_file"].fileno(), remaining)
                remaining = remaining[written:]
        except BrokenPipeError:
            return subprocess.CompletedProcess(args, 1)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setitem(git_blob_samples.__globals__, "git_command", git_command)

    assert git_blob_samples(tmp_path, ["HEAD:source"]) == [None]


@pytest.mark.parametrize("output", [b"", b"object blob 4\ntext\n"])
def test_git_blob_samples_reject_git_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]

    def git_command(*args: Any, **kwargs: Any):
        kwargs["stdout_file"].write(output)
        return subprocess.CompletedProcess(args, 1)

    monkeypatch.setitem(git_blob_samples.__globals__, "git_command", git_command)

    assert git_blob_samples(tmp_path, ["HEAD:source"]) == [None]


@pytest.mark.parametrize(
    ("log_encoding", "subject"),
    [
        ("UTF-8", "docs: \u65e5\u672c\u8a9e \ud55c\uad6d\uc5b4 \U0001f527"),
        ("ISO-8859-1", "docs: caf\u00e9"),
    ],
)
@pytest.mark.parametrize("encoding", ["cp932", "cp949"])
def test_git_metadata_preserves_unicode_commit_subject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoding: str,
    log_encoding: str,
    subject: str,
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    subprocess.run(["git", "commit", "--allow-empty", "-qm", subject], cwd=target, check=True)
    subprocess.run(
        ["git", "config", "i18n.logOutputEncoding", log_encoding], cwd=target, check=True
    )
    set_default_subprocess_encoding(monkeypatch, encoding)

    assert WORKBENCH_TARGET["git_target_metadata"](target)["commitSubject"] == subject
    assert WORKBENCH_TARGET["git_bytes"](
        target, "show", "-s", "--format=%s", "HEAD"
    ) == f"{subject}\n".encode("utf-8")


@pytest.mark.parametrize("encoding", ["cp932", "cp949"])
def test_git_output_decodes_repository_paths_as_utf8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    target = tmp_path / "Jos\u00e9-\u65e5\u672c\u8a9e-\ud55c\uad6d\uc5b4"
    initialize_git_repository(target)
    set_default_subprocess_encoding(monkeypatch, encoding)

    output = WORKBENCH_TARGET["git_output"](target, "rev-parse", "--show-toplevel")
    assert Path(output) == target


@pytest.mark.parametrize("suffix", ["", " ", "\t", "\r", "\n"])
def test_git_worktree_preserves_path_whitespace(tmp_path: Path, suffix: str) -> None:
    if os.name == "nt" and suffix:
        pytest.skip("Windows does not support these trailing path characters")
    target = tmp_path / f"target{suffix}"
    revision = initialize_git_repository(target)
    nested = target / "src"
    nested.mkdir()

    assert WORKBENCH_TARGET["git_worktree_context"](target) == (target.resolve(), ".")
    assert WORKBENCH_TARGET["git_worktree_context"](nested) == (target.resolve(), "src")
    metadata = WORKBENCH_TARGET["git_target_metadata"](target)
    assert metadata["reviewChangesSupported"] is True
    assert metadata["revision"] == revision
    assert metadata["branch"] == "main"

    original_digest = worktree_content_digest(target)
    (target / "README.md").write_text("changed after commit\n")
    assert worktree_content_digest(target) != original_digest


@pytest.mark.parametrize(
    ("platform", "stdout", "expected"),
    [
        ("linux", b"/repo\r\n", "/repo\r"),
        ("linux", b"/repo\n\n", "/repo\n"),
        ("win32", b"C:/repo\r\n", "C:/repo"),
        ("win32", b"C:/repo\n", "C:/repo"),
    ],
)
def test_git_output_removes_only_the_record_terminator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    platform: str,
    stdout: bytes,
    expected: str,
) -> None:
    git_output = WORKBENCH_TARGET["git_output"]
    monkeypatch.setitem(git_output.__globals__, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setitem(
        git_output.__globals__,
        "git_command",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, stdout=stdout),
    )

    assert git_output(tmp_path, "rev-parse", "--show-toplevel") == expected


@pytest.mark.cross_platform
@pytest.mark.parametrize("noglob", ["0", "1"])
def test_windows_directory_query_preserves_exclusions_with_inherited_noglob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, noglob: str
) -> None:
    import workbench_target

    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / ".gitignore").write_text("locally-ignored/\n")
    excludes = tmp_path / "global-excludes"
    excludes.write_text("globally-ignored/\n")
    for directory in ["src", "locally-ignored", "globally-ignored"]:
        source = repository / "pkg" / directory
        source.mkdir(parents=True)
        (source / "app.py").write_text("source fixture\n")
    monkeypatch.setattr(workbench_target, "_WINDOWS", True)
    monkeypatch.setenv("GIT_NOGLOB_PATHSPECS", noglob)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(excludes))
    environment = os.environ.copy()

    paths = workbench_target.git_directory_snapshot_paths(repository)

    assert paths is not None
    assert {path.relative_to(repository).as_posix() for path in paths} == {
        ".gitignore",
        "README.md",
        "pkg/src/app.py",
    }
    assert dict(os.environ) == environment


def test_directory_content_digest_uses_git_file_set(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    (target / ".gitignore").write_text("ignored-cache/\n")
    source = target / "app.py"
    source.write_text("print('fixture')\n")
    original_digest = directory_content_digest(target)

    source.write_text("print('changed')\n")
    assert directory_content_digest(target) != original_digest

    source.write_text("print('fixture')\n")
    (target / ".git" / "runtime-cache").write_text("runtime metadata\n")
    ignored_cache = target / "ignored-cache"
    ignored_cache.mkdir()
    (ignored_cache / "build-output").write_text("ignored runtime data\n")

    assert directory_content_digest(target) == original_digest


@pytest.mark.parametrize("scope", [".", "component"])
def test_directory_snapshot_preserves_target_alias_spelling(tmp_path: Path, scope: str) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    (target / "component").mkdir()
    (target / "component" / "app.py").write_text("print('fixture')\n")
    (target / "root.py").write_text("print('root')\n")
    alias = tmp_path / "alias"
    alias.symlink_to(target, target_is_directory=True)
    scoped = target / scope
    selected = alias / scope
    expected = [
        selected / path.relative_to(scoped)
        for path in WORKBENCH_TARGET["git_directory_snapshot_paths"](scoped)
    ]

    paths = WORKBENCH_TARGET["git_directory_snapshot_paths"](selected)
    assert [str(path) for path in paths] == [str(path) for path in expected]
    original_digest = directory_content_digest(selected)
    assert original_digest == directory_content_digest(scoped)
    (selected / "changed.py").write_text("print('changed')\n")
    assert directory_content_digest(selected) == directory_content_digest(scoped)
    assert directory_content_digest(selected) != original_digest


@pytest.mark.parametrize("scope", [".", "component"])
@pytest.mark.parametrize("alias_kind", ["symlink", "case"])
def test_submodule_checks_preserve_target_alias_spelling(
    tmp_path: Path, scope: str, alias_kind: str
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    scoped = target / scope
    scoped.mkdir(exist_ok=True)
    submodule = scoped / "submodule"
    revision = initialize_git_repository(submodule)
    add_submodule_gitlink(target, revision, scope)
    alias = tmp_path / ("alias" if alias_kind == "symlink" else "TARGET")
    if alias_kind == "symlink":
        alias.symlink_to(target, target_is_directory=True)
    elif not alias.exists():
        pytest.skip("filesystem does not support case aliases")
    selected = alias / scope
    entries = WORKBENCH_TARGET["git_submodule_entries"](selected)
    assert entries == ((selected / "submodule", revision),)
    WORKBENCH_TARGET["require_clean_submodule_worktrees"](selected)
    (submodule / "README.md").write_text("changed after commit\n")
    with pytest.raises(SystemExit, match="Dirty Git submodules.*submodule"):
        WORKBENCH_TARGET["require_clean_submodule_worktrees"](selected)


@pytest.mark.parametrize("content_digest", [directory_content_digest, worktree_content_digest])
@pytest.mark.parametrize("alias_kind", ["original", "symlink", "case"])
def test_content_digest_expands_nested_git_repositories(
    tmp_path: Path, content_digest: Callable[[Path], str], alias_kind: str
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    nested = target / "nested"
    initialize_git_repository(nested)
    (nested / ".gitignore").write_text("ignored-cache/\n")
    nested_source = nested / "app.py"
    nested_source.write_text("print('fixture')\n")
    ignored_cache = nested / "ignored-cache"
    ignored_cache.mkdir()
    ignored_output = ignored_cache / "build-output"
    ignored_output.write_text("ignored runtime data\n")
    selected = target
    if alias_kind != "original":
        selected = tmp_path / ("alias" if alias_kind == "symlink" else "TARGET")
        if alias_kind == "symlink":
            selected.symlink_to(target, target_is_directory=True)
        elif not selected.exists():
            pytest.skip("filesystem does not support case aliases")
    original_digest = content_digest(selected)

    nested_source.write_text("print('changed')\n")
    assert content_digest(selected) != original_digest

    nested_source.write_text("print('fixture')\n")
    (nested / "README.md").write_text("changed after commit\n")
    assert content_digest(selected) != original_digest

    (nested / "README.md").write_text("fixture\n")
    (nested / ".git" / "runtime-cache").write_text("runtime metadata\n")
    ignored_output.write_text("changed ignored runtime data\n")
    assert content_digest(selected) == original_digest


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX directory permissions")
@pytest.mark.parametrize("inventory", ["plain", "git", "git-junctions"])
def test_directory_inventory_skips_inaccessible_descendants(
    tmp_path: Path, inventory: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    if inventory != "plain":
        initialize_unborn_git_repository(target)
    else:
        target.mkdir()
    if inventory == "git-junctions":
        monkeypatch.setitem(directory_content_digest.__globals__, "_WINDOWS", True)
    source = target / "app.py"
    source.write_text("before\n")
    inaccessible = target / "unreadable"
    inaccessible.mkdir()
    (inaccessible / "private.txt").write_text("inaccessible fixture\n")
    inaccessible.chmod(0)
    try:
        if os.access(inaccessible, os.R_OK | os.X_OK):
            pytest.skip("directory permissions are not enforced for the current user")
        assert WORKBENCH_TARGET["directory_snapshot_regular_file_count"](target) == 1
        before = directory_content_digest(target)
        source.write_text("after\n")
        assert directory_content_digest(target) != before
    finally:
        inaccessible.chmod(0o700)


def test_directory_content_digest_skips_missing_cached_paths(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    original_digest = directory_content_digest(target)
    cached_source = target / "cached.py"
    cached_source.write_text("print('cached')\n")
    subprocess.run(["git", "add", cached_source.name], cwd=target, check=True)
    cached_source.unlink()

    assert directory_content_digest(target) == original_digest


def test_worktree_content_digest_streams_tracked_binary_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    binary = target / "fixture.bin"
    # Incompressible fixture bytes keep the binary patch larger than one hash read.
    fixture_size = 1024 * 1024 + 17
    binary.write_bytes(hashlib.shake_256(b"original binary fixture").digest(fixture_size))
    subprocess.run(["git", "add", binary.name], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Add binary fixture"], cwd=target, check=True)
    binary.write_bytes(hashlib.shake_256(b"changed binary fixture").digest(fixture_size))

    tracked = subprocess.run(
        [
            "git",
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "HEAD",
            "--",
            ".",
        ],
        cwd=target,
        check=True,
        capture_output=True,
    ).stdout
    assert b"GIT binary patch" in tracked
    assert len(tracked) > 1024 * 1024
    expected = hashlib.sha256()
    update_digest_field(expected, b"format", b"codex-security-snapshot/v1")
    update_digest_field(expected, b"tracked-diff", tracked)

    function_globals = cast(dict[str, Any], cast(Any, worktree_content_digest).__globals__)
    git_command = cast(
        Callable[..., subprocess.CompletedProcess[Any]], function_globals["git_command"]
    )

    def require_streamed_diff(
        repository: Path, *args: str, **kwargs: object
    ) -> subprocess.CompletedProcess[Any]:
        if args and args[0] == "diff":
            assert kwargs.get("stdout_file") is not None
        return git_command(repository, *args, **kwargs)

    monkeypatch.setitem(function_globals, "git_command", require_streamed_diff)

    assert worktree_content_digest(target) == (
        f"codex-security-snapshot/v1:sha256:{expected.hexdigest()}"
    )


def test_windows_git_candidates_reject_batch_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    native = tmp_path / "git.com"
    batch = tmp_path / "git.cmd"
    extensionless = tmp_path / "git-native"
    for candidate in (native, batch, extensionless):
        candidate.write_text("synthetic executable fixture\n")
    native_alias = tmp_path / "trusted.exe"
    batch_alias = tmp_path / "untrusted.exe"
    extensionless_alias = tmp_path / "native-alias.exe"
    native_alias.symlink_to(native)
    batch_alias.symlink_to(batch)
    extensionless_alias.symlink_to(extensionless)
    monkeypatch.setitem(
        trusted_git_executable.__globals__, "sys", SimpleNamespace(platform="win32")
    )
    for candidate, expected in (
        (native, native),
        (native_alias, native_alias),
        (batch, None),
        (batch_alias, None),
        (extensionless, None),
        (extensionless_alias, extensionless_alias),
    ):
        monkeypatch.setenv("CODEX_SECURITY_GIT", str(candidate))
        assert trusted_git_executable(repository) == (str(expected) if expected else None)


@pytest.mark.parametrize("windows", [False, True])
def test_git_discovery_continues_past_repository_tools_and_batch_shims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    repository = tmp_path / "repository"
    repository_bin = repository / "bin"
    repository_bin.mkdir(parents=True)
    (repository / ".git").mkdir()
    batch_bin = tmp_path / "batch-bin"
    host_bin = tmp_path / "host-bin"
    batch_bin.mkdir()
    host_bin.mkdir()
    name = "git.exe" if windows else "git"
    host_git = host_bin / name
    for executable in (repository_bin / name, batch_bin / "git.cmd", host_git):
        executable.write_text("synthetic executable fixture\n")
        executable.chmod(0o700)
    monkeypatch.setitem(
        trusted_git_executable.__globals__,
        "sys",
        SimpleNamespace(platform="win32" if windows else "linux"),
    )
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (repository_bin, batch_bin, host_bin))))
    assert trusted_git_executable(repository) == str(host_git)

    # An explicit unavailable binding must not fall back to a different Git.
    for binding in ("", str(tmp_path / "missing-git")):
        monkeypatch.setenv("CODEX_SECURITY_GIT", binding)
        assert trusted_git_executable(repository) is None
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(repository_bin / name))
    with pytest.raises(SystemExit, match="outside the protected repository"):
        trusted_git_executable(repository)


def test_git_discovery_does_not_invoke_through_repository_directory_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository_bin = repository / "bin"
    repository_bin.mkdir(parents=True)
    (repository / ".git").mkdir()
    host_bin = tmp_path / "host-bin"
    host_bin.mkdir()
    name = "git.exe" if os.name == "nt" else "git"
    host_git = host_bin / name
    host_git.write_text("synthetic host executable\n")
    host_git.chmod(0o700)
    (repository_bin / name).symlink_to(host_git)
    alias = tmp_path / "directory-alias"
    alias.symlink_to(repository_bin, target_is_directory=True)
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (alias, host_bin))))
    assert trusted_git_executable(repository) == str(host_git)
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(alias / name))
    with pytest.raises(SystemExit, match="outside the protected repository"):
        trusted_git_executable(repository)

    host_alias = repository / "host-alias"
    host_alias.symlink_to(host_bin, target_is_directory=True)
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(host_alias / name))
    with pytest.raises(SystemExit, match="outside the protected repository"):
        trusted_git_executable(repository)


def test_git_discovery_preserves_symlink_parent_traversal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    (repository / ".git").mkdir(parents=True)
    tools = tmp_path / "tools"
    version = tmp_path / "versions" / "v1"
    (tools / "bin").mkdir(parents=True)
    (version / "lib").mkdir(parents=True)
    (version / "bin").mkdir()
    (tools / "current").symlink_to(version / "lib", target_is_directory=True)
    name = "git.exe" if os.name == "nt" else "git"
    host_git = version / "bin" / name
    for executable in (tools / "bin" / name, host_git):
        executable.write_text("synthetic executable fixture\n")
        executable.chmod(0o700)
    path_entry = tools / "current" / ".." / "bin"
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", str(path_entry))
    expected = (path_entry / name).resolve(strict=True)
    if os.name != "nt":
        assert expected == host_git
    assert trusted_git_executable(repository) == str(expected)


@pytest.mark.parametrize(
    "name",
    [
        "component with spaces",
        pytest.param(
            "component with spaces ",
            marks=pytest.mark.skipif(os.name == "nt", reason="Windows strips trailing spaces"),
        ),
    ],
)
def test_git_context_retains_scoped_directory_spelling(tmp_path: Path, name: str) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    scoped = target / name
    scoped.mkdir()
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](scoped)
    assert repository.samefile(target)
    assert pathspec == scoped.name


def test_git_target_accepts_filesystem_case_aliases(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    alias = tmp_path / "TARGET"
    if not alias.exists():
        pytest.skip("filesystem does not support case aliases")
    assert WORKBENCH_TARGET["git_target_metadata"](alias)["reviewChangesSupported"]
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](alias)
    assert repository.samefile(target)
    assert pathspec == "."
    scoped = target / "component"
    scoped.mkdir()
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](alias / "COMPONENT")
    assert repository.samefile(target)
    assert (repository / pathspec).samefile(scoped)


@pytest.mark.skipif(os.name == "nt", reason="Windows does not preserve trailing path whitespace")
@pytest.mark.parametrize("sibling_exists", [False, True])
def test_git_context_preserves_trailing_root_whitespace(
    tmp_path: Path, sibling_exists: bool
) -> None:
    target = tmp_path / "target "
    initialize_git_repository(target)
    if sibling_exists:
        initialize_git_repository(tmp_path / "target")
    assert WORKBENCH_TARGET["git_target_metadata"](target)["reviewChangesSupported"]
    repository, pathspec = WORKBENCH_TARGET["git_worktree_context"](target)
    assert repository.samefile(target)
    assert pathspec == "."
    original_digest = worktree_content_digest(target)
    (target / "synthetic.txt").write_text("selected target content\n")
    assert worktree_content_digest(target) != original_digest
    destination = tmp_path / "copied"
    WORKBENCH_TARGET["copy_git_worktree_files"](target, destination, ())
    assert (destination / "synthetic.txt").read_text() == "selected target content\n"


def test_git_context_rejects_an_unrelated_configured_worktree(tmp_path: Path) -> None:
    target = tmp_path / "target"
    unrelated = tmp_path / "unrelated"
    initialize_git_repository(target)
    unrelated.mkdir()
    subprocess.run(["git", "config", "core.worktree", str(unrelated)], cwd=target, check=True)
    with pytest.raises(SystemExit, match="inside its Git working tree"):
        WORKBENCH_TARGET["git_worktree_context"](target)
    with pytest.raises(SystemExit, match="inside its Git working tree"):
        worktree_content_digest(target)
    destination = tmp_path / "copied"
    with pytest.raises(SystemExit, match="inside its Git working tree"):
        WORKBENCH_TARGET["copy_git_worktree_files"](target, destination, ())
    assert not destination.exists()


@pytest.mark.parametrize("scope", [".", "component"])
@pytest.mark.parametrize("alias_kind", ["original", "symlink", "case"])
def test_copy_retains_alias_rooted_gitlink_exclusions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str, alias_kind: str
) -> None:
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    scoped = repository / scope
    scoped.mkdir(exist_ok=True)
    (scoped / "fixture.py").write_text("synthetic = True\n")
    submodule = scoped / "submodule"
    submodule.mkdir()
    add_submodule_gitlink(repository, revision, scope)
    selected = scoped
    if alias_kind != "original":
        alias = tmp_path / ("selected-alias" if alias_kind == "symlink" else "REPOSITORY")
        if alias_kind == "symlink":
            alias.symlink_to(repository, target_is_directory=True)
        elif not alias.exists():
            pytest.skip("filesystem does not support case aliases")
        selected = alias / scope
    entries = WORKBENCH_TARGET["git_submodule_entries"](selected)
    WORKBENCH_TARGET["require_clean_submodule_worktrees"](selected)
    copy = WORKBENCH_TARGET["copy_git_worktree_files"]
    calls = []

    def checked_copy(
        source: Path, destination: Path, excluded: tuple[Path, ...]
    ) -> tuple[Path, list[Path]]:
        assert not source.samefile(submodule), "An excluded uninitialized gitlink was traversed"
        calls.append(source)
        return copy(source, destination, excluded)

    monkeypatch.setitem(copy.__globals__, "copy_git_worktree_files", checked_copy)
    selected_exclusions = tuple(path for path, _ in entries)
    for index, excluded in enumerate({selected_exclusions, (submodule,)}):
        calls.clear()
        copied, junctions = checked_copy(selected, tmp_path / f"copied-{index}", excluded)
        assert len(calls) == 1
        assert junctions == []
        assert (copied / "fixture.py").read_text() == "synthetic = True\n"
        assert not (copied / "submodule").exists()


@pytest.mark.parametrize("replacement", ["directory", "ignored_file", "link"])
@pytest.mark.parametrize("case_insensitive", [False, True])
def test_deleted_candidate_sources_keep_base_blob_when_path_is_recreated(
    tmp_path: Path, replacement: str, case_insensitive: bool
) -> None:
    target = tmp_path / "repository"
    initialize_git_repository(target)
    source = target / "deleted.ts"
    source.write_bytes(b"one\rtwo\r\nthree\nfour")
    subprocess.run(["git", "add", "deleted.ts"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "selected source"], cwd=target, check=True)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    subprocess.run(["git", "rm", "-q", "deleted.ts"], cwd=target, check=True)
    (target / ".git" / "info" / "exclude").write_text("deleted.ts\n")
    if replacement == "directory":
        source.mkdir()
    elif replacement == "ignored_file":
        source.write_text("replacement\n")
    else:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "private.txt").write_text("Synthetic unrelated content.\n")
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(source), str(outside)],
                check=True,
                capture_output=True,
            )
        else:
            source.symlink_to(outside, target_is_directory=True)
    assert (
        dict(WORKBENCH_TARGET["git_changed_paths"](target, revision, revision, "local-patch"))[
            source
        ]
        == "D"
    )
    sources = WORKBENCH_TARGET["candidate_source_lines"](
        target,
        {"kind": "working_tree", "baseRevision": revision, "headRevision": revision},
        ["deleted.ts"],
        ["deleted.ts", "DELETED.TS"],
        case_insensitive=case_insensitive,
    )
    expected = {"deleted.ts": {"path": "deleted.ts", "lineCount": 4}}
    if case_insensitive:
        expected["DELETED.TS"] = expected["deleted.ts"]
    assert sources == expected


@pytest.mark.parametrize("case_insensitive", [False, True])
def test_candidate_aliases_use_selected_tree_and_preserve_ambiguity(
    tmp_path: Path, case_insensitive: bool
) -> None:
    target = tmp_path / "repository"
    initialize_git_repository(target)
    support = target / "Support.ts"
    support.write_text("support\nsecond\n")
    subprocess.run(["git", "add", "Support.ts"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "support source"], cwd=target, check=True)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    for name, mode, content in (
        ("Foo.ts", "100644", b"upper\n"),
        ("foo.ts", "100644", b"lower\nsecond\nthird\n"),
        ("folder/file.ts", "100644", b"nested\n"),
        ("link.ts", "120000", b"Support.ts"),
    ):
        blob = (
            subprocess.check_output(
                ["git", "hash-object", "-w", "--stdin"], cwd=target, input=content
            )
            .decode()
            .strip()
        )
        subprocess.run(
            ["git", "update-index", "--add", "--cacheinfo", f"{mode},{blob},{name}"],
            cwd=target,
            check=True,
        )
    subprocess.run(["git", "commit", "-qm", "selected tree"], cwd=target, check=True)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    support.unlink()
    subprocess.run(
        ["git", "update-index", "--force-remove", "Support.ts", "Foo.ts"], cwd=target, check=True
    )
    subprocess.run(["git", "commit", "-qm", "later tree"], cwd=target, check=True)
    (target / "foo.ts").write_text("different current content\n")
    requested = ["Foo.ts", "foo.ts", "FOO.ts", "SUPPORT.TS", "./SUPPORT.TS", "LINK.TS", "FOLDER"]
    sources = WORKBENCH_TARGET["candidate_source_lines"](
        target,
        {"kind": "range", "baseRevision": base, "headRevision": head},
        ["Foo.ts", "foo.ts"],
        requested,
        case_insensitive=case_insensitive,
    )
    assert sources["Foo.ts"] == {"path": "Foo.ts", "lineCount": 1}
    assert sources["foo.ts"] == {"path": "foo.ts", "lineCount": 3}
    assert sources["FOO.ts"] == {"error": "missing"}
    for name in ("SUPPORT.TS", "./SUPPORT.TS"):
        assert sources[name] == (
            {"path": "Support.ts", "lineCount": 2} if case_insensitive else {"error": "missing"}
        )
    for name in ("LINK.TS", "FOLDER"):
        assert sources[name] == {"error": "not_file" if case_insensitive else "missing"}
