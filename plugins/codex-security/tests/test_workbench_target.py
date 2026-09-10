from __future__ import annotations

import hashlib
import runpy
import subprocess
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, cast

import pytest
from workbench_test_support import initialize_git_repository

WORKBENCH_TARGET = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "workbench_target.py")
)
directory_content_digest = cast(Callable[[Path], str], WORKBENCH_TARGET["directory_content_digest"])
worktree_content_digest = cast(Callable[[Path], str], WORKBENCH_TARGET["worktree_content_digest"])
update_digest_field = cast(
    Callable[[Any, bytes, bytes], None], WORKBENCH_TARGET["update_digest_field"]
)


def initialize_unborn_git_repository(target: Path) -> None:
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)


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
    monkeypatch.setattr(subprocess, "_text_encoding", lambda: encoding)

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
    monkeypatch.setattr(subprocess, "_text_encoding", lambda: encoding)

    output = WORKBENCH_TARGET["git_output"](target, "rev-parse", "--show-toplevel")
    assert Path(output) == target


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


@pytest.mark.parametrize("include_ignored", [False, True])
def test_snapshot_exclusions_preserve_case_distinct_source_entries(
    tmp_path: Path, include_ignored: bool
) -> None:
    class WindowsEqualityPath(type(Path())):
        # Exercise Windows equality with actual case-sensitive filesystem entries.
        def __hash__(self):
            return hash(PureWindowsPath(str(self)))

        def __eq__(self, other):
            return PureWindowsPath(str(self)) == PureWindowsPath(str(other))

    target = WindowsEqualityPath(tmp_path / "target")
    initialize_unborn_git_repository(target)
    managed = target / "state" / "dedupe"
    source = target / "state" / "Dedupe"
    managed.mkdir(parents=True)
    if source.exists():
        pytest.skip("The fixture filesystem does not support case-distinct directories")
    source.mkdir()
    assert managed == source
    assert not managed.samefile(source)
    generated = managed / "review.json"
    generated.write_text('{"saved":1}\n')
    code = source / "index.ts"
    code.write_text("export const value = 1;\n")

    def snapshot():
        return WORKBENCH_TARGET["directory_content_digest"](
            target, excluded=(managed,), include_ignored=include_ignored
        )

    original = snapshot()
    generated.write_text('{"saved":2}\n')
    (managed / "new-review.json").write_text('{"saved":3}\n')
    assert snapshot() == original
    code.write_text("export const value = 2;\n")
    assert snapshot() != original


@pytest.mark.parametrize("include_ignored", [False, True])
def test_snapshot_exclusions_follow_case_aliases_of_the_repository(
    tmp_path: Path, include_ignored: bool
) -> None:
    target = tmp_path / "Repo"
    initialize_unborn_git_repository(target)
    alias = tmp_path / "repo"
    if not alias.exists():
        alias.symlink_to(target, target_is_directory=True)
    assert target.samefile(alias)

    class CaseAliasPath(type(Path())):
        # A case-insensitive POSIX filesystem preserves lexical case in resolve()
        # and relative_to(). A real directory alias supplies the same file identity
        # when this fixture runs on a case-sensitive filesystem.
        def resolve(self, strict=False):
            super().resolve(strict=strict)
            return self.absolute()

        def relative_to(self, other, **kwargs):
            return PurePosixPath(self.as_posix()).relative_to(
                PurePosixPath(Path(other).as_posix()), **kwargs
            )

    managed = target / "state" / "dedupe"
    managed.mkdir(parents=True)
    generated = managed / "review.json"
    generated.write_text('{"saved":1}\n')
    source = target / "index.ts"
    source.write_text("export const value = 1;\n")
    excluded = CaseAliasPath(alias / "state" / "dedupe")
    assert managed.samefile(excluded)

    def snapshot():
        return WORKBENCH_TARGET["directory_content_digest"](
            target, excluded=(excluded,), include_ignored=include_ignored
        )

    original = snapshot()
    generated.write_text('{"saved":2}\n')
    (managed / "new-review.json").write_text('{"saved":3}\n')
    assert snapshot() == original
    source.write_text("export const value = 2;\n")
    assert snapshot() != original


@pytest.mark.parametrize("content_digest", [directory_content_digest, worktree_content_digest])
def test_content_digest_expands_nested_git_repositories(
    tmp_path: Path, content_digest: Callable[[Path], str]
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
    original_digest = content_digest(target)

    nested_source.write_text("print('changed')\n")
    assert content_digest(target) != original_digest

    nested_source.write_text("print('fixture')\n")
    (nested / "README.md").write_text("changed after commit\n")
    assert content_digest(target) != original_digest

    (nested / "README.md").write_text("fixture\n")
    (nested / ".git" / "runtime-cache").write_text("runtime metadata\n")
    ignored_output.write_text("changed ignored runtime data\n")
    assert content_digest(target) == original_digest


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
