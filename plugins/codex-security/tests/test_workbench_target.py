from __future__ import annotations

import hashlib
import os
import runpy
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


def initialize_unborn_git_repository(target: Path) -> None:
    target.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=target, check=True)


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
def test_git_blob_samples_bound_reads_and_classify_full_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encoding: str, bom: bytes
) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    # The UTF-16 surrogate pair crosses the first 64 KiB sample boundary.
    text = bom + ("a" * 32766 + "😀" + "b" * 32768).encode(encoding)
    contents = {
        "text.bin": text + (b"\0" if bom else b""),
        "binary-tail.bin": text + "\0".encode(encoding),
        "binary-head.bin": b"\0" + text,
        "empty.bin": b"",
        "after.txt": b"after\n",
    }
    for name, content in contents.items():
        (target / name).write_bytes(content)
    subprocess.run(["git", "add", "."], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "source samples"], cwd=target, check=True)

    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]
    function_globals = git_blob_samples.__globals__
    git_command = function_globals["git_command"]
    reads: list[int] = []

    def require_bounded_output(repository: Path, *args: str, **kwargs: Any):
        output = kwargs["stdout_file"]
        result = git_command(repository, *args, **kwargs)
        read = output.read

        def bounded_read(size: int = -1) -> bytes:
            assert 0 <= size <= 64 * 1024
            reads.append(size)
            return read(size)

        output.read = bounded_read
        return result

    monkeypatch.setitem(function_globals, "git_command", require_bounded_output)
    samples = git_blob_samples(
        target,
        ["HEAD:missing", *(f"HEAD:{name}" for name in contents)],
    )

    assert samples == [
        None,
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
        b"object blob invalid\0",
        b"object blob -1\0",
        b"object blob 4\0abc",
        b"object blob 4\0abcd!",
    ],
)
def test_git_blob_samples_reject_incomplete_framing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: bytes
) -> None:
    git_blob_samples = WORKBENCH_TARGET["git_blob_samples"]

    def git_command(*args: Any, **kwargs: Any):
        kwargs["stdout_file"].write(output)
        return subprocess.CompletedProcess(args, 0)

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
