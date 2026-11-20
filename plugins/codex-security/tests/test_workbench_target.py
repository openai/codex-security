"""Exercise Git discovery, snapshot identity, scoped inventory, and patch handling across filesystem aliases."""

from __future__ import annotations

import difflib
import errno
import hashlib
import io
import json
import os
import runpy
import shutil
import sqlite3
import stat
import subprocess
import sys
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
CASE_ALIAS = pytest.param("case", marks=pytest.mark.native_macos)


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("destination", "missing", "binary", "selected", "count"),
    [
        ("new.py", False, False, ("new.py", "R"), 1),
        ("new.py", True, False, ("old.py", "D"), 1),
        ("new.py", True, True, ("old.py", "D"), 0),
        (".svn/new.py", False, False, ("old.py", "D"), 1),
    ],
)
def test_register_local_diff_with_renamed_source(
    tmp_path: Path,
    destination: str,
    missing: bool,
    binary: bool,
    selected: tuple[str, str],
    count: int,
) -> None:
    import workbench_db
    import workbench_target

    target = tmp_path / "repository"
    initialize_git_repository(target)
    (target / "old.py").write_bytes(b"\0binary" if binary else b"historical text\n")
    subprocess.run(["git", "add", "old.py"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "add source"], cwd=target, check=True)
    subprocess.run(["git", "config", "diff.renames", "true"], cwd=target, check=True)
    (target / destination).parent.mkdir(exist_ok=True)
    subprocess.run(["git", "mv", "old.py", destination], cwd=target, check=True)
    if missing:
        subprocess.run(
            ["git", "update-index", "--skip-worktree", destination], cwd=target, check=True
        )
        (target / destination).unlink()

    assert workbench_target.git_changed_paths(target, "HEAD", "HEAD", "local-patch") == [
        (target / selected[0], selected[1])
    ]
    diff = {"kind": "working_tree", "baseRevision": "HEAD", "headRevision": "HEAD"}
    assert workbench_db.scan_scope_file_count(target, ["."], diff) == count


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


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX directory component errors")
def test_recorded_checkout_distinguishes_a_replaced_parent_from_a_missing_path(
    tmp_path: Path,
) -> None:
    import workbench_target

    parent = tmp_path / "projects"
    checkout = parent / "repository"
    checkout.mkdir(parents=True)
    assert workbench_target.require_remediation_target(str(checkout)) == checkout

    checkout.rmdir()
    with pytest.raises(SystemExit, match="no longer accessible"):
        workbench_target.require_remediation_target(str(checkout))
    parent.rmdir()
    parent.write_text("ordinary file")
    with pytest.raises(SystemExit, match="checkout path was replaced"):
        workbench_target.require_remediation_target(str(checkout))


def write_reviewed_patch(
    tmp_path: Path, source: Path, patch: bytes, revision: str = "unversioned"
) -> dict[str, object]:
    from filesystem_identity import serialize_filesystem_identity

    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    (scan_dir / "reviewed.patch").write_bytes(patch)
    return {
        "target_path": str(source),
        "target_inode": serialize_filesystem_identity(source.stat().st_ino),
        "target_revision": revision,
        "scan_dir": str(scan_dir),
    }


def reviewed_remediation(patch: bytes, revision: str, digest: str) -> dict[str, str]:
    return {
        "base_revision": revision,
        "base_content_digest": digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
    }


@pytest.mark.cross_platform
@pytest.mark.parametrize("layout", ["separate", "linked", "unborn", "unborn-root"])
def test_reviewed_patch_uses_long_source_metadata_in_its_private_replay(
    tmp_path: Path, layout: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_db

    # The metadata argument is long in UTF-8 even on hosts with short temporary paths.
    padding = max(1, (230 - len((tmp_path / "metadata-").as_posix().encode("utf-8")) + 2) // 3)
    metadata = tmp_path / ("metadata-" + "界" * padding)
    source = tmp_path / "source"
    if layout == "unborn-root":
        source, metadata = metadata, metadata / ".git"
        subprocess.run(["git", "init", "-q", str(source)], check=True)
    else:
        subprocess.run(
            ["git", "init", "-q", "--separate-git-dir", str(metadata), str(source)], check=True
        )
    subprocess.run(["git", "-C", str(source), "config", "core.autocrlf", "false"], check=True)
    (source / "file.txt").write_bytes(b"before\n")
    revision = "unversioned"
    if layout in {"separate", "linked"}:
        subprocess.run(["git", "-C", str(source), "add", "file.txt"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(source),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=f@example.invalid",
                "commit",
                "-qm",
                "base",
            ],
            check=True,
        )
        if layout == "linked":
            linked = tmp_path / "linked"
            subprocess.run(
                ["git", "-C", str(source), "worktree", "add", "--detach", str(linked)], check=True
            )
            source = linked
        revision = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
        ).strip()
    marker = source / ".git/HEAD" if layout == "unborn-root" else source / ".git"
    original_marker = marker.read_bytes()
    (metadata / "info/exclude").write_bytes(b"ignored.fixture\n")
    (source / "ignored.fixture").write_bytes(b"outside the recorded content\n")
    if os.name == "nt" and revision == "unversioned":
        # The private copy keeps the original gitdir-conditional visibility when using the retry.
        global_config, included, excludes = (
            tmp_path / name for name in ("global", "include", "excludes")
        )
        excludes.write_bytes(b"conditional.fixture\n")
        subprocess.run(
            ["git", "config", "--file", included, "core.excludesFile", excludes.as_posix()],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "config",
                "--file",
                global_config,
                f"includeIf.gitdir:{metadata.as_posix()}.path",
                included.as_posix(),
            ],
            check=True,
        )
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
        (source / "conditional.fixture").write_bytes(b"excluded by the selected Git directory\n")
        ignored = subprocess.check_output(
            ["git", "-C", source, "check-ignore", "conditional.fixture"]
        )
        assert ignored.strip()
    patch = b"diff --git a/file.txt b/file.txt\n--- a/file.txt\n+++ b/file.txt\n@@ -1 +1 @@\n-before\n+after\n"
    scan = write_reviewed_patch(tmp_path, source, patch, revision)
    _, digest = workbench_db.remediation_checkout_snapshot(scan)
    remediation = reviewed_remediation(patch, revision, digest)
    selected_file = source / "file.txt"
    selected_file.write_bytes(b"after\n")
    _, applied_digest = workbench_db.remediation_checkout_snapshot(scan)
    verify = workbench_db.require_reviewed_patch_applied
    assert verify(scan, remediation, "reviewed.patch") == applied_digest
    assert selected_file.read_bytes() == b"after\n"
    selected_file.write_bytes(b"other\n")
    with pytest.raises(SystemExit, match="does not contain the reviewed remediation patch"):
        verify(scan, remediation, "reviewed.patch")
    assert selected_file.read_bytes() == b"other\n"
    selected_file.write_bytes(b"after\n")
    (source / "unrelated.txt").write_bytes(b"keep me\n")
    with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
        verify(scan, remediation, "reviewed.patch")
    assert (source / "unrelated.txt").read_bytes() == b"keep me\n"
    (source / "unrelated.txt").unlink()
    malformed = b"not a patch\n"
    (tmp_path / "scan/reviewed.patch").write_bytes(malformed)
    with pytest.raises(SystemExit, match="does not contain the reviewed remediation patch"):
        verify(scan, reviewed_remediation(malformed, revision, digest), "reviewed.patch")
    assert marker.read_bytes() == original_marker
    assert selected_file.read_bytes() == b"after\n"


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory and file sharing")
def test_replay_gitfile_remains_bound_until_the_private_replay_is_removed(tmp_path: Path) -> None:
    import tempfile
    from contextlib import ExitStack

    import windows_scan_local_files as windows
    import workbench_target

    source = tmp_path / "source"
    foreign = tmp_path / "foreign"
    initialize_git_repository(source)
    initialize_git_repository(foreign)
    metadata = source / ".git"
    stages = tmp_path / "replays"
    stages.mkdir()

    def interrupt_replay():
        with tempfile.TemporaryDirectory(dir=stages) as temporary, ExitStack() as pins:
            scratch = Path(temporary)
            checkout = scratch / "checkout"
            checkout.mkdir()
            (checkout / ".git").write_bytes(f"gitdir: {(foreign / '.git').as_posix()}\n".encode())
            assert windows.pin_replay_metadata(pins, metadata, scratch) == metadata
            with pytest.raises(PermissionError):
                scratch.rename(stages / "elsewhere")
            short = pins.enter_context(windows.pinned_replay_gitfile(checkout, metadata))
            assert (
                Path(
                    workbench_target.git_output(
                        checkout,
                        "rev-parse",
                        "--absolute-git-dir",
                        git_dir=short,
                        work_tree=checkout,
                    )
                )
                == metadata
            )
            with pytest.raises(PermissionError):
                (checkout / short).write_bytes(b"other")
            for path in (metadata, checkout, scratch, checkout / short):
                with pytest.raises(PermissionError):
                    path.rename(path.with_name("replaced"))
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        interrupt_replay()
    assert not list(stages.iterdir())
    assert metadata.is_dir() and (foreign / ".git").is_dir()


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows regular-file and junction checks")
@pytest.mark.parametrize(
    "change", ["foreign-pointer", "changed-patch", "replaced-parent", "writable-scratch"]
)
def test_short_git_reference_refuses_changed_replay_inputs(
    tmp_path: Path, change: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from contextlib import ExitStack

    import windows_scan_local_files as windows
    import workbench_remediation

    metadata, scratch = tmp_path / "metadata", tmp_path / "scratch"
    metadata.mkdir()
    scratch.mkdir()
    worktree = scratch / "checkout"
    worktree.mkdir()
    patch = scratch / "reviewed.patch"
    patch.write_bytes(b"expected")
    expected = "sha256:" + hashlib.sha256(patch.read_bytes()).hexdigest()
    marker = scratch / "reviewed.git"
    if change == "foreign-pointer":
        marker.write_bytes(b"gitdir: foreign\n")
    elif change == "changed-patch":
        patch.write_bytes(b"changed")
    elif change == "replaced-parent":
        alias = tmp_path / "alias"
        subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(scratch)], check=True)
        worktree = alias / "checkout"
    else:
        subprocess.run(["icacls.exe", str(scratch), "/grant", "*S-1-1-0:(WD)"], check=True)
    failed = subprocess.CompletedProcess([], 128, b"", b"fatal: '$GIT_DIR' too big\n")
    monkeypatch.setattr(workbench_remediation, "git_command", lambda *args, **kwargs: failed)
    with ExitStack() as pins:
        selected = windows.pin_replay_metadata(pins, metadata, scratch)
        if change == "writable-scratch":
            assert selected is None
            with pytest.raises(SystemExit, match="Could not bind"):
                workbench_remediation.reverse_reviewed_patch(
                    tmp_path, worktree, metadata, selected, expected, pins, patch, "."
                )
            assert not marker.exists()
            return
        with pytest.raises(SystemExit, match="Could not verify|Patch digest does not match"):
            workbench_remediation.reverse_reviewed_patch(
                tmp_path, worktree, metadata, selected, expected, pins, patch, "."
            )
    if change == "foreign-pointer":
        assert marker.read_bytes() == b"gitdir: foreign\n"
    if change == "replaced-parent":
        assert not marker.exists()


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
    patch = b"diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    scan = write_reviewed_patch(tmp_path, source, patch)
    (source / "app.txt").write_text("before\n")
    if git_repository == "indexed":
        subprocess.run(["git", "add", "."], cwd=source, check=True)
    remediation = reviewed_remediation(
        patch, "unversioned", workbench_db.directory_content_digest(source)
    )
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
    import workbench_remediation

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
    original_command = workbench_remediation.git_command
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

    monkeypatch.setattr(workbench_remediation, "git_command", command)
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
    "link_kind",
    [
        pytest.param("absolute", marks=pytest.mark.cross_platform),
        pytest.param("relative", marks=pytest.mark.cross_platform),
        pytest.param(
            "junction",
            marks=[
                pytest.mark.native_windows,
                pytest.mark.skipif(os.name != "nt", reason="requires native Windows junctions"),
            ],
        ),
    ],
)
@pytest.mark.parametrize("nested", [False, True], ids=["direct", "nested"])
@pytest.mark.parametrize("unrelated_change", [False, True], ids=["reviewed", "unrelated"])
def test_reviewed_patch_does_not_copy_through_indexed_directory_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    link_kind: str,
    nested: bool,
    unrelated_change: bool,
) -> None:
    import workbench_db

    repository = tmp_path / "source" / "repository"
    repository.parent.mkdir()
    revision = initialize_git_repository(repository)
    source = repository / "component"
    link = source / ("linked/nested" if nested else "linked")
    link.mkdir(parents=True)
    (link / "file.txt").write_text("indexed child\n")
    (source / "app.txt").write_text("before\n")
    subprocess.run(["git", "add", "component"], cwd=repository, check=True)
    shutil.rmtree(link)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "file.txt").write_text("original outside contents\n")
    if link_kind == "junction":
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], check=True)
    else:
        link_target = (
            "../" * (4 if nested else 3) + "outside" if link_kind == "relative" else str(outside)
        )
        link.symlink_to(link_target, target_is_directory=True)
    original_link = os.readlink(link)

    staging = tmp_path / "staging"
    sentinel = staging / "outside"
    sentinel.mkdir(parents=True)
    (sentinel / "file.txt").write_text("staged outside sentinel\n")
    # A relative link resolves to this different directory after materialization.
    monkeypatch.setattr(workbench_db.tempfile, "tempdir", str(staging))
    patch = b"diff --git a/app.txt b/app.txt\n--- a/app.txt\n+++ b/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    scan = write_reviewed_patch(tmp_path, source, patch, revision)
    remediation = reviewed_remediation(
        patch, revision, workbench_db.worktree_content_digest(source)
    )
    (source / "app.txt").write_text("after\n")
    if unrelated_change:
        (source / "unrelated.txt").write_text("outside the reviewed patch\n")
        with pytest.raises(SystemExit, match="changes outside the reviewed patch"):
            workbench_db.require_reviewed_patch_applied(scan, remediation, "reviewed.patch")
    else:
        assert workbench_db.require_reviewed_patch_applied(
            scan, remediation, "reviewed.patch"
        ) == workbench_db.worktree_content_digest(source)
    assert (outside / "file.txt").read_text() == "original outside contents\n"
    assert (sentinel / "file.txt").read_text() == "staged outside sentinel\n"
    assert (source / "app.txt").read_text() == "after\n"
    assert os.readlink(link) == original_link
    assert list(staging.iterdir()) == [sentinel]


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


@pytest.mark.parametrize(
    "short_reference",
    [
        pytest.param(False, marks=pytest.mark.cross_platform),
        pytest.param(
            True,
            marks=[
                pytest.mark.native_windows,
                pytest.mark.skipif(os.name != "nt", reason="requires Windows replay binding"),
            ],
        ),
    ],
    ids=["ordinary", "short-reference"],
)
def test_reviewed_patch_preserves_scoped_unborn_lf_bytes(
    tmp_path: Path, short_reference: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import workbench_remediation

    repository = tmp_path / "repository"
    initialize_unborn_git_repository(repository)
    references = []
    reverse = workbench_remediation.reverse_reviewed_patch
    git = workbench_remediation.git_command

    def record_references(*args, **kwargs):
        selected = reverse(*args, **kwargs)
        references.append(selected)
        return selected

    def require_short_reference(target, *args, **kwargs):
        if short_reference and kwargs.get("git_dir") == repository / ".git":
            return subprocess.CompletedProcess([], 128, b"", b"fatal: '$GIT_DIR' too big\n")
        return git(target, *args, **kwargs)

    monkeypatch.setattr(workbench_remediation, "reverse_reviewed_patch", record_references)
    monkeypatch.setattr(workbench_remediation, "git_command", require_short_reference)
    attributes = tmp_path / "attributes"
    attributes.write_text("*.txt text eol=crlf\n")
    subprocess.run(
        ["git", "config", "core.attributesFile", str(attributes)], cwd=repository, check=True
    )
    source = repository / "component"
    source.mkdir()

    assert_reviewed_change(source, tmp_path, "app.txt", "before\n", "after\n", newline="\n")

    assert (source / "app.txt").read_bytes() == b"after\n"
    if short_reference:
        assert references[0][0] is not None


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
    scan = write_reviewed_patch(tmp_path, source, patch, revision)
    (source / relative).write_text(before, newline=newline)
    revision, digest = workbench_db.remediation_checkout_snapshot(scan)
    remediation = reviewed_remediation(patch, revision, digest)
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
    patch = b"diff --git a/linked/deleted.txt b/linked/deleted.txt\ndeleted file mode 100644\n--- a/linked/deleted.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-removed\n"
    scan = write_reviewed_patch(tmp_path, source, patch)
    remediation = reviewed_remediation(patch, "unversioned", "different base")
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
    scan = write_reviewed_patch(tmp_path, source, patch)
    (source / "app.txt").write_text("before\n")
    remediation = reviewed_remediation(
        patch, "unversioned", workbench_db.directory_content_digest(source)
    )
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


@pytest.mark.parametrize("git", [False, True])
def test_directory_snapshots_exclude_svn_metadata(tmp_path: Path, git: bool) -> None:
    target = tmp_path / "target"
    if git:
        initialize_unborn_git_repository(target)
    else:
        target.mkdir()
    source = target / "app.py"
    source.write_text("source\n")
    metadata = [target / ".svn" / "wc.db", target / "nested" / ".svn" / "pristine" / "base"]
    for path in metadata:
        path.parent.mkdir(parents=True)
        path.write_text("metadata\n")
    if git:
        subprocess.run(["git", "add", "--force", "."], cwd=target, check=True)

    original = directory_content_digest(target)
    count_files = WORKBENCH_TARGET["directory_snapshot_regular_file_count"]
    assert count_files(target) == 1
    for path in metadata:
        path.write_text("metadata changed\n")
    assert directory_content_digest(target) == original
    assert count_files(target) == 1
    source.write_text("source changed\n")
    assert directory_content_digest(target) != original


@pytest.mark.parametrize("tracked", [False, True])
@pytest.mark.parametrize("scope", [".", "nested[scope]"])
def test_worktree_snapshots_exclude_svn_metadata(tmp_path: Path, tracked: bool, scope: str) -> None:
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    target = repository / scope
    target.mkdir(exist_ok=True)
    source = target / ".svn-backup" / "app.py"
    source.parent.mkdir()
    source.write_text("source\n")
    metadata = [target / ".svn" / "wc.db", target / "nested" / ".svn" / "entries"]
    for path in metadata:
        path.parent.mkdir(parents=True)
        path.write_text("metadata\n")
    subprocess.run(["git", "add", str(source)], cwd=repository, check=True)
    if tracked:
        subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "Synthetic source and metadata"], cwd=repository, check=True
    )

    original = worktree_content_digest(target)
    for path in metadata:
        path.write_text("updated metadata\n")
    assert worktree_content_digest(target) == original
    source.write_text("updated source\n")
    assert worktree_content_digest(target) != original


@pytest.mark.parametrize("scope", [".svn", "nested/.svn"])
def test_git_directory_snapshots_exclude_svn_junctions(
    tmp_path: Path, junction_factory: Callable[[Path, Path], None], scope: str
) -> None:
    import workbench_target

    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    source = target / "app.py"
    source.write_text("source\n")
    metadata = target / scope
    metadata.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "state").write_text("metadata\n")
    junction_factory(metadata / "linked", outside)

    assert workbench_target.git_directory_snapshot_paths(target) == [source]


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
    patch = (
        b"diff --git a/src/app.txt b/src/app.txt\n"
        b"--- a/src/app.txt\n+++ b/src/app.txt\n@@ -1 +1 @@\n-before\n+after\n"
    )
    scan = write_reviewed_patch(tmp_path, source, patch)
    revision, digest = workbench_db.remediation_checkout_snapshot(scan)
    assert revision == "unversioned"
    remediation = reviewed_remediation(patch, revision, digest)
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
def test_git_blob_binary_flags_match_full_file_classification_with_bounded_reads(
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

    git_blob_binary_flags = WORKBENCH_TARGET["git_blob_binary_flags"]
    function_globals = git_blob_binary_flags.__globals__
    read_batch_samples = function_globals["_read_git_batch_flags"]
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

    monkeypatch.setitem(function_globals, "_read_git_batch_flags", require_bounded_output)
    # Both request and response exceed pipe buffers, before the multi-megabyte binary.
    missing = ["HEAD:missing"] * 10_000
    samples = git_blob_binary_flags(target, [*missing, *(f"HEAD:{name}" for name in contents)])

    assert samples == [
        *([None] * len(missing)),
        False,
        True,
        True,
        False,
        False,
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
    ids=[
        "unterminated-header",
        "invalid-size",
        "negative-size",
        "short-body",
        "invalid-terminator",
        "large-invalid-header",
        "truncated-large-body",
    ],
)
def test_git_blob_binary_flags_reject_incomplete_framing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_binary_flags = WORKBENCH_TARGET["git_blob_binary_flags"]

    def git_command(*args: Any, **kwargs: Any):
        remaining = memoryview(output)
        try:
            while remaining:
                written = os.write(kwargs["stdout_file"].fileno(), remaining)
                remaining = remaining[written:]
        except BrokenPipeError:
            return subprocess.CompletedProcess(args, 1)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setitem(git_blob_binary_flags.__globals__, "git_command", git_command)

    assert git_blob_binary_flags(tmp_path, ["HEAD:source"]) == [None]


@pytest.mark.parametrize("output", [b"", b"object blob 4\ntext\n"])
def test_git_blob_binary_flags_reject_git_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_binary_flags = WORKBENCH_TARGET["git_blob_binary_flags"]

    def git_command(*args: Any, **kwargs: Any):
        kwargs["stdout_file"].write(output)
        return subprocess.CompletedProcess(args, 1)

    monkeypatch.setitem(git_blob_binary_flags.__globals__, "git_command", git_command)

    assert git_blob_binary_flags(tmp_path, ["HEAD:source"]) == [None]


def test_git_blob_binary_flags_work_with_git_before_2_38(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    git_blob_binary_flags = WORKBENCH_TARGET["git_blob_binary_flags"]
    git_command = git_blob_binary_flags.__globals__["git_command"]

    def git_before_2_38(*args: Any, **kwargs: Any):
        # Git before 2.38 rejects cat-file -z with a usage error.
        if "-z" in args:
            return subprocess.CompletedProcess(args, 129)
        return git_command(*args, **kwargs)

    monkeypatch.setitem(git_blob_binary_flags.__globals__, "git_command", git_before_2_38)

    assert git_blob_binary_flags(target, ["HEAD:README.md", "HEAD:missing"]) == [
        False,
        None,
    ]


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


@pytest.mark.cross_platform
def test_git_metadata_ignores_signature_output_in_commit_subject(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    headers = subprocess.check_output(["git", "cat-file", "commit", "HEAD"], cwd=target).split(
        b"\n\n", 1
    )[0]
    # A synthetic signature reproduces Git's extra output without a signing tool.
    commit = headers + (
        b"\ngpgsig -----BEGIN SSH SIGNATURE-----\n synthetic\n -----END SSH SIGNATURE-----"
        b"\n\nSigned subject\n"
    )
    revision = (
        subprocess.check_output(
            ["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=target, input=commit
        )
        .decode()
        .strip()
    )
    subprocess.run(["git", "update-ref", "HEAD", revision], cwd=target, check=True)
    subprocess.run(["git", "config", "log.showSignature", "true"], cwd=target, check=True)

    assert WORKBENCH_TARGET["git_target_metadata"](target)["commitSubject"] == "Signed subject"


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


@pytest.mark.parametrize("pathspec_mode", ["GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS"])
def test_directory_content_digest_uses_git_file_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, pathspec_mode: str
) -> None:
    target = tmp_path / "target"
    initialize_unborn_git_repository(target)
    (target / ".gitignore").write_text("ignored-cache/\n")
    source = target / "app.py"
    source.write_text("print('fixture')\n")
    original_digest = directory_content_digest(target)
    monkeypatch.setenv(pathspec_mode, "1")

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
@pytest.mark.parametrize("alias_kind", ["symlink", CASE_ALIAS])
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
@pytest.mark.parametrize("alias_kind", ["original", "symlink", CASE_ALIAS])
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


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("color.ui", "always"),
        ("color.diff", "always"),
        ("diff.noprefix", "true"),
        ("diff.mnemonicPrefix", "true"),
        ("diff.context", "0"),
        ("diff.algorithm", "histogram"),
        ("diff.indentHeuristic", "false"),
        ("diff.interHunkContext", "20"),
        ("diff.suppressBlankEmpty", "true"),
        ("diff.orderFile", "order"),
        ("diff.renames", "false"),
        ("diff.renameLimit", "1"),
        ("core.quotePath", "false"),
        ("GIT_DIFF_OPTS", "--unified=0"),
    ],
)
def test_git_diff_display_settings_preserve_selected_working_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api: dict[str, Any],
    option: str,
    value: str,
) -> None:
    target = tmp_path / "source"
    initialize_git_repository(target)
    path = target / "café.txt"
    path.write_bytes(b"heading\none\nC\nB\nB\nthree\n")
    lines = target / "z-lines.txt"
    original_lines = ["start", "", *(f"line {n}" for n in range(20)), "end"]
    lines.write_text("\n".join(original_lines) + "\n", encoding="utf-8")
    indent = target / "indent.txt"
    indent.write_bytes(b"\ndone()\ndef sample():\n")
    moved = [("first.txt", "new-first.txt"), ("second.txt", "new-second.txt")]
    for name, _ in moved:
        (target / name).write_text(
            "".join(f"{name} line {n}\n" for n in range(20)), encoding="utf-8"
        )
    subprocess.run(["git", "add", "--", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Track fixture"], cwd=target, check=True)
    indent.write_bytes(b"\ndone()\ndone()\ndef sample():\n")
    for name, destination in moved:
        subprocess.run(["git", "mv", name, destination], cwd=target, check=True)
        with (target / destination).open("ab") as stream:
            stream.write(b"added line\n")
        subprocess.run(["git", "add", "--", destination], cwd=target, check=True)
    path.write_bytes(b"heading\none\nB\nC\nC\nthree\n")
    original_lines[0] = "changed start"
    original_lines[-1] = "changed end"
    lines.write_text("\n".join(original_lines) + "\n", encoding="utf-8")
    if option == "diff.orderFile":
        order_file = tmp_path / "diff order"
        order_file.write_text(lines.name + "\n", encoding="utf-8", newline="\n")
        value = str(order_file)
    selected = workbench_api["require_diff_target"](target, "working_tree", None, None, None)
    if option == "GIT_DIFF_OPTS":
        monkeypatch.setenv(option, value)
    else:
        subprocess.run(["git", "config", "--local", option, value], cwd=target, check=True)

    # Reproduce a stored digest generated by a previous version with this setting.
    old_patch = subprocess.check_output(
        ["git", "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "HEAD"],
        cwd=target,
    )
    old_hash = hashlib.sha256()
    update_digest_field(old_hash, b"format", b"codex-security-snapshot/v1")
    update_digest_field(old_hash, b"tracked-diff", old_patch)
    legacy = f"codex-security-snapshot/v1:sha256:{old_hash.hexdigest()}"
    assert legacy != selected["contentDigest"]

    def validate(digest: str | None) -> str:
        return workbench_api["require_diff_target"](target, "working_tree", None, None, digest)[
            "contentDigest"
        ]

    assert validate(None) == selected["contentDigest"]
    assert validate(selected["contentDigest"]) == selected["contentDigest"]
    assert validate(legacy) == legacy

    path.write_bytes(b"new source content\n")
    for digest in (selected["contentDigest"], legacy):
        with pytest.raises(SystemExit, match="contents changed"):
            validate(digest)


@pytest.mark.cross_platform
@pytest.mark.parametrize("display", ["log", "diff"])
def test_git_submodule_display_preserves_selected_working_content(
    tmp_path: Path, workbench_api: dict[str, Any], display: str
) -> None:
    target = tmp_path / "parent"
    initialize_git_repository(target)
    child = target / "submodule"
    initial = initialize_git_repository(child)
    add_submodule_gitlink(target, initial, ".")
    subprocess.run(["git", "commit", "-qm", "Pin child"], cwd=target, check=True)

    def advance_child(content: str) -> None:
        (child / "README.md").write_text(content + "\n", encoding="utf-8")
        subprocess.run(["git", "commit", "-qam", content], cwd=child, check=True)
        subprocess.run(["git", "add", "--", "submodule"], cwd=target, check=True)

    advance_child("Selected child")
    require_target = workbench_api["require_diff_target"]
    selected = require_target(target, "working_tree", None, None, None)["contentDigest"]
    diff = ["git", "diff", "HEAD", "--", "submodule"]
    original = subprocess.check_output(diff, cwd=target)
    subprocess.run(["git", "config", "--local", "diff.submodule", display], cwd=target, check=True)
    configured = subprocess.check_output(diff, cwd=target)
    assert configured != original
    assert require_target(target, "working_tree", None, None, selected)["contentDigest"] == selected

    advance_child("Changed child")
    with pytest.raises(SystemExit, match="contents changed"):
        require_target(target, "working_tree", None, None, selected)


@pytest.mark.cross_platform
@pytest.mark.parametrize(
    ("key", "value", "binary"),
    [
        ("diff.python.xfuncname", "^class.*$", False),
        ("diff.python.binary", "true", False),
        ("diff.Mixed=driver.binary", "true", False),
        ("diff.python.binary", "false", True),
        ("core.compression", "0", True),
    ],
)
def test_git_driver_settings_preserve_selected_working_content(
    tmp_path: Path, workbench_api: dict[str, Any], key: str, value: str, binary: bool
) -> None:
    target = tmp_path / "source"
    initialize_git_repository(target)
    driver = "Mixed=driver" if key == "diff.Mixed=driver.binary" else "python"
    (target / ".gitattributes").write_bytes(f"*.py diff={driver}\n".encode())
    source = target / "example.py"
    initial = (
        b"class Example:\n    def sample(self):\n"
        + b"".join(f"        a = {n}\n".encode() for n in range(24))
        + (b"\0" + b"abcde" * 4096 if binary else b"")
    )
    source.write_bytes(initial)
    subprocess.run(["git", "add", "--", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Track example"], cwd=target, check=True)
    source.write_bytes(initial.replace(b"a = 15", b"a = 42"))
    require_target = workbench_api["require_diff_target"]
    selected = require_target(target, "working_tree", None, None, None)["contentDigest"]
    args = ["git", "diff", "--binary", "--full-index", "HEAD"]
    original = subprocess.check_output(args, cwd=target)
    subprocess.run(["git", "config", "--local", key, value], cwd=target, check=True)
    configured = subprocess.check_output(args, cwd=target)
    assert configured != original
    assert require_target(target, "working_tree", None, None, selected)["contentDigest"] == selected
    assert require_target(target, "working_tree", None, None, None)["contentDigest"] == selected
    legacy_hash = hashlib.sha256()
    update_digest_field(legacy_hash, b"format", b"codex-security-snapshot/v1")
    update_digest_field(legacy_hash, b"tracked-diff", configured)
    legacy = f"codex-security-snapshot/v1:sha256:{legacy_hash.hexdigest()}"
    assert require_target(target, "working_tree", None, None, legacy)["contentDigest"] == legacy
    source.write_bytes(initial + b"actual change\n")
    for digest in (selected, legacy):
        with pytest.raises(SystemExit, match="contents changed"):
            require_target(target, "working_tree", None, None, digest)


def test_snapshot_keeps_hunk_coordinates_and_long_source_lines() -> None:
    header = b"@@ -12,4 +12,5 @@"
    # The next read starts with a header-shaped string in the middle of an added line.
    long_line = b"+" + b"x" * (1024 * 1024 - 1) + header + b" literal content\n"
    patch = header + b" def sample():\n" + long_line + header + b"\n"
    chunks = WORKBENCH_TARGET["_canonical_patch_chunks"](io.BytesIO(patch))
    assert b"".join(chunks) == header + b"\n" + long_line + header + b"\n"


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
        if "diff" in args:
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


@pytest.mark.cross_platform
@pytest.mark.parametrize("windows", [False, True])
def test_scoped_git_discovery_pins_all_target_roots_and_restores_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    first, second, host = (tmp_path / name for name in ("first", "second", "host"))
    for root in (first, second, host):
        root.mkdir()
    for repository in (first, second):
        (repository / ".git").mkdir()
    name = "git.exe" if windows else "git"
    for root in (second, host):
        (root / name).write_text("synthetic executable fixture\n")
        (root / name).chmod(0o700)
    monkeypatch.setitem(
        trusted_git_executable.__globals__,
        "sys",
        SimpleNamespace(platform="win32" if windows else "linux"),
    )
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (second, host))))
    with WORKBENCH_TARGET["scoped_git_discovery"](lambda: (first, second)):
        assert trusted_git_executable(first) == str(host / name)
        monkeypatch.setenv("PATH", str(second))
        assert trusted_git_executable(second) == str(host / name)
    assert trusted_git_executable(first) == str(second / name)


@pytest.mark.cross_platform
@pytest.mark.parametrize("windows", [False, True])
def test_unvalidated_workspace_paths_exclude_tools_without_blocking_host_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool
) -> None:
    repository, candidate, host = (tmp_path / name for name in ("repository", "candidate", "host"))
    (repository / ".git").mkdir(parents=True)
    host.mkdir()
    name = "git.exe" if windows else "git"
    (host / name).write_text("synthetic executable fixture\n")
    (host / name).chmod(0o700)
    monkeypatch.setitem(
        trusted_git_executable.__globals__,
        "sys",
        SimpleNamespace(platform="win32" if windows else "linux"),
    )
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (candidate, host))))
    for exists in (False, True):
        if exists:
            candidate.mkdir()
            (candidate / name).write_text("synthetic repository executable fixture\n")
            (candidate / name).chmod(0o700)
        with WORKBENCH_TARGET["scoped_git_discovery"](
            lambda: (repository,), recorded_git_roots=lambda: (candidate,)
        ):
            assert trusted_git_executable(repository) == str(host / name)


@pytest.mark.cross_platform
@pytest.mark.parametrize("windows", [False, True])
@pytest.mark.parametrize("recorded", [False, True])
def test_scoped_git_discovery_excludes_unavailable_target_ancestor_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, windows: bool, recorded: bool
) -> None:
    repository, historical, host = (
        tmp_path / name for name in ("repository", "historical", "host")
    )
    (repository / ".git").mkdir(parents=True)
    surviving = historical / "surviving"
    surviving.mkdir(parents=True)
    host.mkdir()
    name = "git.exe" if windows else "git"
    for root in (historical, host):
        (root / name).write_text("synthetic executable fixture\n")
        (root / name).chmod(0o700)
    monkeypatch.setitem(
        trusted_git_executable.__globals__,
        "sys",
        SimpleNamespace(platform="win32" if windows else "linux"),
    )
    monkeypatch.delenv("CODEX_SECURITY_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join(map(str, (historical, host))))
    saved = surviving if recorded else surviving / "missing"
    with WORKBENCH_TARGET["scoped_git_discovery"](
        lambda: (repository, saved),
        recorded_git_roots=lambda: None if recorded else (),
    ):
        assert trusted_git_executable(repository) is None

    # A recorded outer boundary keeps the historical shim excluded after target deletion.
    with WORKBENCH_TARGET["scoped_git_discovery"](
        lambda: (repository, saved), recorded_git_roots=lambda: (historical,)
    ):
        assert trusted_git_executable(repository) == str(host / name)

    # The caller can still explicitly select a tool outside the current repository.
    monkeypatch.setenv("CODEX_SECURITY_GIT", str(historical / name))
    with WORKBENCH_TARGET["scoped_git_discovery"](
        lambda: (repository, saved),
        recorded_git_roots=lambda: None if recorded else (),
    ):
        assert trusted_git_executable(repository) == str(historical / name)


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX executable shim")
@pytest.mark.parametrize("operation", ["current-query", "missing-query", "missing-migration"])
@pytest.mark.parametrize("shim_directory", [".", "bin"])
@pytest.mark.parametrize("configured", [False, True])
def test_workbench_commands_exclude_saved_checkout_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api: dict[str, Any],
    operation: str,
    shim_directory: str,
    configured: bool,
) -> None:
    host_git = shutil.which("git")
    assert host_git is not None
    requested, historical = (tmp_path / name for name in ("requested", "historical"))
    for repository in (requested, historical):
        initialize_git_repository(repository)
    historical_target = historical
    if operation.startswith("missing-"):
        shutil.rmtree(historical / ".git")
        (historical / "surviving").mkdir()
        historical_target = historical / "surviving" / "missing"
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        apply_migrations = workbench_api["apply_migrations"]
        with monkeypatch.context() as migration_patch:
            if operation == "missing-migration":
                # Reproduce a database written before repository identities were recorded.
                migration_patch.setitem(
                    apply_migrations.__globals__,
                    "MIGRATIONS",
                    tuple(
                        migration for migration in workbench_api["MIGRATIONS"] if migration[0] < 53
                    ),
                )
            apply_migrations(connection)
        connection.executemany(
            "INSERT INTO security_targets(id, current_path, display_name, created_at, updated_at) "
            "VALUES (?, ?, 'Saved checkout', 'created', 'updated')",
            [("requested", str(requested)), ("historical", str(historical_target))],
        )
    marker = tmp_path / "repository-git-ran"
    tools = historical / shim_directory
    tools.mkdir(exist_ok=True)
    executable = tools / "git"
    executable.write_text(
        '#!/bin/sh\nprintf invoked > "$WORKBENCH_GIT_MARKER"\nexec "$WORKBENCH_HOST_GIT" "$@"\n'
    )
    executable.chmod(0o700)
    environment = {key: value for key, value in os.environ.items() if key != "CODEX_SECURITY_GIT"}
    environment.update(
        CODEX_SECURITY_STATE_DIR=str(state),
        PATH=str(tools) + os.pathsep + os.environ.get("PATH", ""),
        WORKBENCH_GIT_MARKER=str(marker),
        WORKBENCH_HOST_GIT=host_git,
    )
    if configured:
        environment["CODEX_SECURITY_GIT"] = host_git
    arguments = (
        ["list-scans"]
        if operation == "missing-migration"
        else ["list-global-findings", "--repository", str(requested)]
    )
    script = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
    completed = subprocess.run(
        [sys.executable, str(script), *arguments],
        cwd=requested,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    key = "scans" if operation == "missing-migration" else "findings"
    assert json.loads(completed.stdout)[key] == []
    assert not marker.exists()
    if operation == "missing-migration":
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            identities = dict(
                connection.execute("SELECT id, repository_identity FROM security_targets")
            )
            assert (identities["requested"] is not None) is configured
            assert identities["historical"] is None


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX executable shim")
@pytest.mark.parametrize(
    "evidence",
    [
        "identity",
        "generation",
        "revision",
        "legacy-revision",
        "legacy-unborn",
        "legacy-workspace",
        "legacy-directory",
        "directory",
    ],
)
@pytest.mark.parametrize("configured", [False, True])
def test_saved_git_boundary_removal_does_not_select_its_parent_tool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api: dict[str, Any],
    evidence: str,
    configured: bool,
) -> None:
    from workbench_target_state import repository_identity

    host_git = shutil.which("git")
    assert host_git is not None
    requested, historical = (tmp_path / name for name in ("requested", "historical"))
    initialize_git_repository(requested)
    if evidence in {"legacy-unborn", "legacy-workspace"}:
        subprocess.run([host_git, "init", "-q", str(historical)], check=True)
        revision = WORKBENCH_TARGET["git_revision"](historical)
        assert revision == "unversioned"
    elif evidence in {"directory", "legacy-directory"}:
        historical.mkdir()
        revision = "unversioned"
    else:
        revision = initialize_git_repository(historical)
    saved = historical / "surviving" / "component"
    saved.mkdir(parents=True)
    identity = repository_identity(saved)
    if identity is None and evidence in {"identity", "generation"}:
        pytest.skip("filesystem does not expose repository generation evidence")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        apply_migrations = workbench_api["apply_migrations"]
        with monkeypatch.context() as migration_patch:
            if evidence.startswith("legacy-"):
                last_version = 52 if evidence == "legacy-revision" else 60
                migration_patch.setitem(
                    apply_migrations.__globals__,
                    "MIGRATIONS",
                    tuple(item for item in workbench_api["MIGRATIONS"] if item[0] <= last_version),
                )
            apply_migrations(connection)
        register = workbench_api["register_security_target"]
        historical_id = register(connection, str(saved)).target_id
        if not evidence.startswith("legacy-") or evidence == "legacy-revision":
            register(connection, str(requested))
        if evidence in {"identity", "generation", "revision"}:
            # These rows predate recorded roots, but retain distinct kinds of Git evidence.
            connection.execute(
                "UPDATE security_targets SET git_checkout_root = NULL, repository_identity = ? "
                "WHERE id = ?",
                (identity if evidence == "identity" else None, historical_id),
            )
        if evidence != "identity":
            connection.execute(
                "INSERT INTO workspaces(id, target_id, target_path, created_at, updated_at) "
                "VALUES ('workspace', ?, ?, 'created', 'updated')",
                (historical_id, str(saved)),
            )
        if evidence not in {"identity", "legacy-workspace"}:
            connection.execute(
                "INSERT INTO scans(id, workspace_id, target_id, target_path, target_revision, "
                "scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) "
                "VALUES ('scan', 'workspace', ?, ?, ?, '.', 'standard', "
                "?, 'complete', 'reporting', 'created', 'created', 'updated')",
                (
                    historical_id,
                    str(saved),
                    "unversioned" if evidence == "generation" else revision,
                    str(tmp_path / "saved-scan"),
                ),
            )
            if evidence == "generation":
                connection.execute("UPDATE scans SET repository_generation = ?", (identity,))
    if evidence not in {"directory", "legacy-directory"}:
        shutil.rmtree(historical / ".git")
    tools = (
        tmp_path / "host-tools"
        if evidence in {"directory", "legacy-directory"}
        else historical / "bin"
    )
    tools.mkdir()
    executable = tools / "git"
    executable.write_text('#!/bin/sh\nprintf invoked > "$0.ran"\nexec "$WORKBENCH_HOST_GIT" "$@"\n')
    executable.chmod(0o700)
    environment = {key: value for key, value in os.environ.items() if key != "CODEX_SECURITY_GIT"}
    environment.update(
        CODEX_SECURITY_STATE_DIR=str(state),
        PATH=str(tools) + os.pathsep + os.environ.get("PATH", ""),
        WORKBENCH_HOST_GIT=host_git,
    )
    pinned = tmp_path / "trusted-git"
    if configured:
        shutil.copy(executable, pinned)
        environment["CODEX_SECURITY_GIT"] = str(pinned)
    script = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
    completed = subprocess.run(
        [sys.executable, str(script), "list-scans", "--repository", str(requested)],
        cwd=requested,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(completed.stdout)["scans"] == []
    assert executable.with_suffix(".ran").exists() is (evidence == "directory" and not configured)
    assert pinned.with_suffix(".ran").exists() is configured
    if evidence == "legacy-directory":
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            register(connection, str(saved))
            assert (
                connection.execute(
                    "SELECT git_checkout_root FROM security_targets WHERE id = ?", (historical_id,)
                ).fetchone()[0]
                is None
            )
    if evidence == "legacy-revision":
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            identities = dict(
                connection.execute("SELECT current_path, repository_identity FROM security_targets")
            )
        assert (identities[str(requested)] is not None) is configured
        assert identities[str(saved)] is None


@pytest.mark.skipif(os.name == "nt", reason="uses a POSIX executable shim")
@pytest.mark.parametrize(("migrate", "configured"), [(False, False), (True, False), (True, True)])
@pytest.mark.parametrize("spelling", ["absolute", "tilde"])
def test_new_workspace_skips_git_in_its_unregistered_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api: dict[str, Any],
    migrate: bool,
    configured: bool,
    spelling: str,
) -> None:
    host_git = shutil.which("git")
    assert host_git is not None
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    tools = repository / "bin"
    tools.mkdir()
    marker = tmp_path / "repository-git-ran"
    executable = tools / "git"
    executable.write_text(
        '#!/bin/sh\nprintf invoked > "$WORKBENCH_GIT_MARKER"\nexec "$WORKBENCH_HOST_GIT" "$@"\n'
    )
    executable.chmod(0o700)
    state = tmp_path / "state"
    if migrate:
        saved = tmp_path / "saved"
        initialize_git_repository(saved)
        state.mkdir(mode=0o700)
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            apply_migrations = workbench_api["apply_migrations"]
            with monkeypatch.context() as migration_patch:
                migration_patch.setitem(
                    apply_migrations.__globals__,
                    "MIGRATIONS",
                    tuple(item for item in workbench_api["MIGRATIONS"] if item[0] < 54),
                )
                apply_migrations(connection)
            connection.execute(
                "INSERT INTO security_targets(id, current_path, display_name, created_at, updated_at) "
                "VALUES ('saved', ?, 'Saved checkout', '2099-01-01T00:00:00Z', '2099-01-01T00:00:00Z')",
                (str(saved),),
            )
    caller = tmp_path / "caller"
    caller.mkdir()
    environment = {key: value for key, value in os.environ.items() if key != "CODEX_SECURITY_GIT"}
    environment.update(
        CODEX_SECURITY_STATE_DIR=str(state),
        PATH=str(tools) + os.pathsep + os.environ.get("PATH", ""),
        WORKBENCH_GIT_MARKER=str(marker),
        WORKBENCH_HOST_GIT=host_git,
    )
    if configured:
        environment["CODEX_SECURITY_GIT"] = host_git
    script = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
    requested_path = (
        str(repository)
        if spelling == "absolute"
        else "~/" + os.path.relpath(repository, Path.home())
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "create-workspace",
            "--workspace-id",
            "00000000-0000-4000-8000-000000000001",
            "--target-path",
            requested_path,
        ],
        cwd=caller,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(completed.stdout)["targetPath"] == str(repository)
    assert not marker.exists()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        identities = dict(
            connection.execute("SELECT current_path, repository_identity FROM security_targets")
        )
        assert len(identities) == (2 if migrate else 1)
        if migrate:
            assert (identities[str(saved)] is not None) is configured
        # Only an explicit Git can inspect a state with an unknown legacy boundary.
        assert (identities[str(repository)] is not None) is (configured or not migrate)


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


@pytest.mark.native_macos
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


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="Windows symlinks record the target type")
def test_copy_git_worktree_preserves_dangling_windows_directory_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    initialize_unborn_git_repository(source)
    link = source / "directory-link"
    link.symlink_to("missing", target_is_directory=True)

    destination = tmp_path / "copy"
    WORKBENCH_TARGET["copy_git_worktree_files"](source, destination, ())

    copied = destination / link.name
    assert os.readlink(copied) == os.readlink(link)
    assert copied.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_DIRECTORY


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory sharing")
@pytest.mark.parametrize(
    "case",
    [
        "in-tree",
        "separate",
        "localized",
        "scoped",
        "failed-retry",
        "check-ignore-unmatched",
        "different-pointer",
        "case-marker",
        "relative-pointer",
        "conditional",
        "scoped-conditional",
        "deep-gitfile",
    ],
)
def test_windows_root_inventory_retries_the_selected_git_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    import ctypes

    import workbench_target

    if len(tmp_path.drive) != 2 or ctypes.windll.kernel32.GetDriveTypeW(tmp_path.anchor) != 3:
        pytest.skip("requires an ordinary fixed local drive")
    source = tmp_path / "source"
    initialize_git_repository(source)
    metadata = source / ".git"
    worktree = source
    if case != "in-tree":
        worktree = tmp_path / "checkout"
        worktree.mkdir()
        spelling = metadata.as_posix()
        if case == "different-pointer":
            spelling = (tmp_path / "other-metadata").as_posix()
        if case == "relative-pointer":
            spelling = os.path.relpath(metadata, worktree)
        marker_name = ".GIT" if case == "case-marker" else ".git"
        (worktree / marker_name).write_text(f"gitdir: {spelling}\n", encoding="utf-8")
    cwd = worktree
    expected = b"README.md\0"
    scoped = case in {"scoped", "scoped-conditional"}
    if scoped:
        scope = Path("component[ab]", "nested")
        cwd = worktree / scope
        cwd.mkdir(parents=True)
        (source / scope).mkdir(parents=True)
        (source / scope / "selected.txt").write_text("selected\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "--", (scope / "selected.txt").as_posix()], cwd=source, check=True
        )
        expected = b"selected.txt\0"
    if case == "deep-gitfile":
        while len(os.fsencode(os.path.relpath(worktree / ".git", cwd))) <= len(
            os.fsencode(worktree / ".git")
        ):
            cwd /= "d"
        cwd.mkdir(parents=True)
    native = workbench_target.git_command
    args = ("ls-files", "--cached", "-z", "--", ".")
    marker = Path("..", "..", ".git") if scoped else Path(".git")
    if case == "deep-gitfile":
        marker = worktree / ".git"
    expected_status = 0
    input_data = None
    overrides = {"GIT_TRACE_SETUP": "1"}
    if case == "check-ignore-unmatched":
        for name in ("visible one", "visible two"):
            (worktree / name).mkdir()
        (worktree / ".gitignore").write_text("!visible one/\n!visible two/\n", encoding="utf-8")
        args = ("--no-literal-pathspecs", "check-ignore", "-z", "--stdin")
        input_data = b"visible one\0visible two\0"
        overrides["GIT_NOGLOB_PATHSPECS"] = "0"
        expected_status = 1
        expected = b""
    if case in {"conditional", "scoped-conditional"}:
        excludes = tmp_path / "ignore"
        excludes.write_text("visible.fixture\n", encoding="utf-8")
        include = tmp_path / "included"
        include.write_text(f'[core]\n  excludesFile = "{excludes.as_posix()}"\n', encoding="utf-8")
        config = tmp_path / "gitconfig"
        pattern = "./source/.git" if scoped else "./checkout/**"
        config.write_text(f'[includeIf "gitdir:{pattern}"]\n  path = included\n', encoding="utf-8")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
        monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        (cwd / "visible.fixture").write_text("selected\n", encoding="utf-8")
        args = ("ls-files", "--others", "--exclude-standard", "-z", "--", "visible.fixture")
        expected = b"" if scoped else b"visible.fixture\0"
    english = subprocess.CompletedProcess([], 128, b"", b"fatal: '$GIT_DIR' too big\n")
    first = (
        subprocess.CompletedProcess([], 128, b"", b"fatal: '$GIT_DIR' zu gro\xc3\x9f\n")
        if case == "localized"
        else english
    )
    calls = []

    def reject_long_argument(target, *args, **kwargs):
        directory = kwargs["git_dir"]
        calls.append(directory)
        assert str(target) == str(cwd) and str(kwargs["work_tree"]) == str(worktree)
        if directory == metadata:
            return (
                english if (kwargs["environment_overrides"] or {}).get("LC_ALL") == "C" else first
            )
        assert directory == marker
        assert kwargs["environment_overrides"] == overrides
        assert kwargs["input_data"] == input_data
        with pytest.raises(PermissionError):
            metadata.rename(source / "moved")
        if scoped:
            for pinned in (cwd, cwd.parent):
                with pytest.raises(PermissionError):
                    pinned.rename(pinned.with_name("moved"))
        if worktree != source:
            with pytest.raises(PermissionError), (worktree / ".git").open("r+b"):
                pass
        if case == "failed-retry":
            return subprocess.CompletedProcess([], 1, b"", b"fixture read failed")
        if case == "deep-gitfile":
            return subprocess.CompletedProcess([], 0, expected, b"trace verified gitfile")
        return native(target, *args, **kwargs)

    monkeypatch.setattr(workbench_target, "git_command", reject_long_argument)
    result = workbench_target._windows_inventory_query(
        cwd,
        *args,
        git_dir=metadata,
        work_tree=worktree,
        input_data=input_data,
        environment_overrides=overrides.copy(),
    )
    if case in {"different-pointer", "relative-pointer", "case-marker"}:
        assert result is first and calls == [metadata]
    else:
        initial = [metadata, metadata] if case == "localized" else [metadata]
        assert calls == [*initial, marker]
        if case == "failed-retry":
            assert result is first
        else:
            assert result.returncode == expected_status and result.stdout == expected
            assert b"trace" in result.stderr


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows path semantics")
def test_root_git_marker_declines_unsupported_paths_without_opening_directories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import windows_scan_local_files as windows_files

    monkeypatch.setattr(
        windows_files, "_GetDriveTypeW", lambda anchor: 4 if anchor == "D:\\" else 3
    )

    def unexpected_open(*_args, **_kwargs):
        pytest.fail("unsupported paths must be declined before opening directories")

    monkeypatch.setattr(windows_files, "_open_directory", unexpected_open)
    for target, metadata in (
        (r"C:\repo", r"D:\metadata"),
        (r"C:\repo", r"\\server.invalid\share\metadata"),
        (r"\\?\C:\repo", r"\\?\C:\metadata"),
        (r"\\server.invalid\share\repo", r"\\server.invalid\share\metadata"),
        (r"C:checkout", r"C:\metadata"),
        ("C:\\", r"C:\metadata"),
    ):
        with windows_files.pinned_root_git_marker(Path(target), Path(metadata)) as selected:
            assert selected is None
    root = Path(r"C:\repo")
    for cwd in (Path(r"C:\repo-other\scope"), root / ".." / "scope", Path(r"D:\repo\scope")):
        with windows_files.pinned_root_git_marker(cwd, root / ".git", work_tree=root) as selected:
            assert selected is None


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows drive semantics")
def test_root_git_marker_pins_the_checkout_and_metadata_on_independent_fixed_drives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import MagicMock

    import windows_scan_local_files as windows_files

    root, metadata = Path(r"C:\worktree"), Path(r"D:\metadata")
    scope = root / "selected"
    marker = tmp_path / "gitfile"
    marker.write_bytes(f"gitdir: {metadata.as_posix()}\n".encode())
    drives = []
    opened = []

    def fixed_drive(anchor):
        drives.append(anchor)
        return 3

    def open_fixture(path):
        opened.append(path)
        return MagicMock(value=path)

    monkeypatch.setattr(windows_files, "_GetDriveTypeW", fixed_drive)
    monkeypatch.setattr(windows_files, "_open_directory", open_fixture)

    monkeypatch.setattr(windows_files, "_final_path", windows_files._extended_path)

    def open_marker(parent, name, context):
        assert (parent, name) == (root, ".git")
        return os.open(marker, os.O_RDONLY | os.O_BINARY), name

    monkeypatch.setattr(windows_files, "open_read_fd_with_path", open_marker)
    with windows_files.pinned_root_git_marker(scope, metadata, work_tree=root) as selected:
        assert selected == Path("..", ".git")
        assert opened == [
            Path(root.anchor),
            root,
            scope,
            Path(metadata.anchor),
            metadata,
        ]
    assert set(drives) == {root.anchor, metadata.anchor}


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory junctions")
@pytest.mark.parametrize("inside_scope", [False, True])
def test_root_git_marker_refuses_a_reparse_ancestor_before_descending(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inside_scope: bool
) -> None:
    import _winapi
    import ctypes

    import windows_scan_local_files as windows_files

    if len(tmp_path.drive) != 2 or ctypes.windll.kernel32.GetDriveTypeW(tmp_path.anchor) != 3:
        pytest.skip("requires an ordinary fixed local drive")
    cwd = tmp_path / "checkout"
    cwd.mkdir()
    ordinary = tmp_path / "ordinary"
    (ordinary / "metadata").mkdir(parents=True)
    link = (cwd if inside_scope else tmp_path) / "link"
    _winapi.CreateJunction(str(ordinary), str(link))
    metadata = cwd / ".git" if inside_scope else link / "metadata"
    scope = link / "metadata" if inside_scope else cwd
    if inside_scope:
        metadata.mkdir()
    visited = []
    open_directory = windows_files._open_directory
    resolve = Path.resolve

    def observe(path, **kwargs):
        assert link not in path.parents
        visited.append(path)
        return open_directory(path, **kwargs)

    def no_link_resolution(path, *args, **kwargs):
        assert path != link and link not in path.parents
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(windows_files, "_open_directory", observe)
    monkeypatch.setattr(Path, "resolve", no_link_resolution)
    with windows_files.pinned_root_git_marker(scope, metadata, work_tree=cwd) as selected:
        assert selected is None
    assert link in visited


@pytest.mark.native_windows
@pytest.mark.skipif(os.name != "nt", reason="requires Windows Git directory inventory")
def test_long_git_metadata_keeps_nested_directory_inventory_scoped(tmp_path: Path) -> None:
    import _winapi
    import ctypes

    import workbench_target

    if len(tmp_path.drive) != 2 or ctypes.windll.kernel32.GetDriveTypeW(tmp_path.anchor) != 3:
        pytest.skip("requires an ordinary fixed local drive")
    seed = tmp_path / "seed"
    initialize_git_repository(seed)
    subprocess.run(["git", "config", "core.longpaths", "true"], cwd=seed, check=True)
    # More than 220 UTF-8 bytes in --git-dir without requiring a long Win32 component.
    checkout = tmp_path / ("界" * 75)
    shutil.copytree(seed, checkout)
    scope = checkout / "selected[ab]" / "component"
    scope.mkdir(parents=True)
    (scope / "source.txt").write_text("selected\n")
    (checkout / "selecteda").mkdir()
    (checkout / "selecteda" / "outside.txt").write_text("sibling\n")
    (checkout / ".gitignore").write_text("ignored/\n")
    (scope / "ignored").mkdir()
    (scope / "ignored" / "excluded.txt").write_text("ignored\n")
    external = tmp_path / "external"
    external.mkdir()
    _winapi.CreateJunction(str(external), str(scope / "empty-junction"))

    assert set(workbench_target.git_directory_snapshot_paths(scope)) == {
        scope / "source.txt",
        scope / "empty-junction",
    }


def test_copy_skips_index_paths_under_a_directory_replaced_by_a_file(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    (target / "config").mkdir()
    (target / "config" / "settings.py").write_text("tracked = True\n")
    subprocess.run(["git", "add", "config"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Add config"], cwd=target, check=True)
    shutil.rmtree(target / "config")
    (target / "config").write_text("replacement file\n")
    destination = tmp_path / "copied"
    WORKBENCH_TARGET["copy_git_worktree_files"](target, destination, ())
    assert (destination / "config").read_text() == "replacement file\n"


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
@pytest.mark.parametrize("alias_kind", ["original", "symlink", CASE_ALIAS])
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


@pytest.mark.cross_platform
def test_candidate_sources_disambiguate_revision_from_worktree_filename(tmp_path: Path) -> None:
    target = tmp_path / "repository"
    revision = initialize_git_repository(target)
    (target / revision).write_text("synthetic revision-named file\n")
    subprocess.run(["git", "rm", "-q", "README.md"], cwd=target, check=True)

    sources = WORKBENCH_TARGET["candidate_source_lines"](
        target,
        {"kind": "working_tree", "baseRevision": revision, "headRevision": revision},
        ["README.md"],
        ["README.md"],
    )

    assert sources == {"README.md": {"path": "README.md", "lineCount": 1}}


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
