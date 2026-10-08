"""Target inspection and content-integrity helpers for the security workbench."""

from __future__ import annotations

import argparse
import codecs
import hashlib
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, BinaryIO

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import stored_filesystem_identity_matches
from rank_preview import DEFAULT_PREVIEW_READ_BYTES, is_binary_sample
from workbench_constants import GIT_REPOSITORY_ENVIRONMENT


def committed_diff_snapshot_digest(kind: str, base_revision: str, head_revision: str) -> str:
    digest = hashlib.sha256(
        f"codex-security-diff/v1\0{kind}\0{base_revision}\0{head_revision}".encode()
    ).hexdigest()
    return f"codex-security-snapshot/v1:sha256:{digest}"


def diff_snapshot_digest(scan: sqlite3.Row, manifest: dict[str, Any] | None) -> str | None:
    if scan["diff_target_kind"] == "working_tree":
        return scan["diff_content_digest"]
    if scan["diff_target_kind"] in {"commit", "range"}:
        manifest_scan = manifest.get("scan") if manifest is not None else None
        # Preserve the recorded digest when recovery rebuilds a sealed manifest.
        if isinstance(manifest_scan, dict) and (
            manifest_scan.get("sealedAt") is not None or manifest_scan.get("artifacts")
        ):
            target = manifest_scan.get("target")
            return target.get("snapshotDigest") if isinstance(target, dict) else None
        return committed_diff_snapshot_digest(
            scan["diff_target_kind"], scan["diff_base_revision"], scan["diff_head_revision"]
        )
    return None


def git_output(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str | None:
    completed = git_command(target, *args, text=False, git_dir=git_dir, work_tree=work_tree)
    output = os.fsdecode(completed.stdout)
    if sys.platform == "win32" and output.endswith("\r\n"):
        output = output[:-2]
    else:
        output = output.removesuffix("\n")
    return output if completed.returncode == 0 and output else None


def git_bytes(
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> bytes | None:
    completed = git_command(target, *args, text=False, git_dir=git_dir, work_tree=work_tree)
    return completed.stdout if completed.returncode == 0 else None


def git_blob_samples(
    target: Path,
    object_names: list[str],
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> list[tuple[bytes, bool] | None]:
    """Sample ordered blobs and classify all their bytes without buffering the batch."""
    if not object_names:
        return []

    request = b"\0".join(os.fsencode(name) for name in object_names) + b"\0"
    read_fd, write_fd = os.pipe()
    with (
        ThreadPoolExecutor(max_workers=1) as reader,
        os.fdopen(read_fd, "rb") as output,
        os.fdopen(write_fd, "wb") as sink,
    ):

        def read_samples() -> list[tuple[bytes, bool] | None]:
            # Closing the reader also unblocks Git if framing is invalid.
            with output:
                return _read_git_batch_samples(output, len(object_names))

        samples = reader.submit(read_samples)
        try:
            completed = git_command(
                target,
                "cat-file",
                "--batch",
                "-Z",
                text=False,
                input_data=request,
                git_dir=git_dir,
                work_tree=work_tree,
                stdout_file=sink,
            )
        finally:
            # Git may fail before producing all requested records.
            sink.close()
        if completed.returncode != 0:
            return [None] * len(object_names)
        try:
            return samples.result()
        except ValueError:
            return [None] * len(object_names)


def _read_git_batch_samples(output: BinaryIO, count: int) -> list[tuple[bytes, bool] | None]:
    """Read NUL-framed headers, then sample each length-delimited blob."""
    samples: list[tuple[bytes, bool] | None] = []
    for _ in range(count):
        size = _git_batch_blob_size(_read_nul_field(output))
        if size is None:
            samples.append(None)
            continue
        samples.append(_read_git_blob_sample(output, size))
    return samples


def _read_nul_field(output: BinaryIO) -> bytes:
    """Read one NUL-terminated protocol field."""
    field = bytearray()
    while char := output.read(1):
        if char == b"\0":
            return bytes(field)
        field.extend(char)
    raise ValueError("missing NUL terminator")


def _git_batch_blob_size(header: bytes) -> int | None:
    """Return a blob header's byte count, or ``None`` for a non-blob record."""
    fields = header.rsplit(b" ", 2)
    if len(fields) != 3 or fields[1] != b"blob":
        return None
    try:
        size = int(fields[2])
    except ValueError as error:
        raise ValueError("invalid blob size") from error
    if size < 0:
        raise ValueError("invalid blob size")
    return size


def _read_git_blob_sample(output: BinaryIO, size: int) -> tuple[bytes, bool]:
    sample_size = min(size, DEFAULT_PREVIEW_READ_BYTES)
    sample = output.read(sample_size)
    if len(sample) != sample_size:
        raise ValueError("truncated blob")
    binary = is_binary_sample(sample)
    bom = sample[:2] if sample.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else b""
    remaining = size - sample_size
    while remaining:
        chunk_size = min(remaining, DEFAULT_PREVIEW_READ_BYTES)
        chunk = output.read(chunk_size)
        if len(chunk) != chunk_size:
            raise ValueError("truncated blob")
        # Even-sized reads keep UTF-16 code units aligned; preserve the original byte order.
        if not binary:
            binary = is_binary_sample(bom + chunk) if bom else b"\0" in chunk
        remaining -= chunk_size
    if output.read(1) != b"\0":
        raise ValueError("missing blob terminator")
    return (b"", True) if binary else (sample, False)


def _protected_repository_root(target: Path) -> Path:
    root = target.resolve()
    if root.is_file():
        root = root.parent
    protected = root
    for ancestor in (root, *root.parents):
        try:
            (ancestor / ".git").lstat()
        except FileNotFoundError:
            continue
        protected = ancestor
    return protected


def trusted_git_executable(protected_root: Path) -> str | None:
    """Validate host-selected Git, or discover Git for a direct plugin invocation."""
    configured = os.environ.get("CODEX_SECURITY_GIT")
    windows = sys.platform == "win32"
    if configured is None:
        names = ("git.exe", "git.com") if windows else ("git",)
        candidates = (
            Path(entry.strip('"') if windows else entry) / name
            for entry in os.get_exec_path()
            for name in names
        )
    elif not configured:
        return None
    else:
        candidate = Path(configured)
        if not candidate.is_absolute():
            raise SystemExit("CODEX_SECURITY_GIT must name an absolute trusted executable.")
        candidates = iter((candidate,))

    try:
        repository = _protected_repository_root(protected_root)
    except (OSError, RuntimeError):
        return None

    for candidate in candidates:
        try:
            lexical = Path(os.path.abspath(candidate))
            invocation = candidate.parent.resolve(strict=True) / candidate.name
            canonical = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if (
            not canonical.is_file()
            or not os.access(canonical, os.F_OK if windows else os.X_OK)
            or (
                windows
                and (
                    candidate.suffix.lower() not in {".exe", ".com"}
                    or canonical.suffix.lower() in {".bat", ".cmd"}
                )
            )
        ):
            continue
        if any(
            path == repository or repository in path.parents
            for path in (lexical, invocation, canonical)
        ):
            if configured is not None:
                raise SystemExit("CODEX_SECURITY_GIT must stay outside the protected repository.")
            continue
        return str(invocation)
    return None


def git_command(
    target: Path,
    *args: str,
    text: bool,
    input_data: str | bytes | None = None,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
    stdout_file: BinaryIO | None = None,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    if (git_dir is None) != (work_tree is None):
        raise ValueError("git_dir and work_tree must be provided together")
    environment = os.environ.copy()
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    executable = trusted_git_executable(target)
    # Repository-local config is untrusted; fsmonitor may name an executable hook.
    command = [
        executable or "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "i18n.logOutputEncoding=UTF-8",
        "-C",
        str(target),
    ]
    if git_dir is not None and work_tree is not None:
        command.extend(["--git-dir", str(git_dir), "--work-tree", str(work_tree)])
    full_command = [*command, *args]
    if executable is None:
        empty_output = "" if text else b""
        return subprocess.CompletedProcess(full_command, 127, empty_output, empty_output)
    try:
        output_options = (
            {"capture_output": True}
            if stdout_file is None
            else {"stdout": stdout_file, "stderr": subprocess.PIPE}
        )
        return subprocess.run(
            full_command,
            check=False,
            env=environment,
            text=text,
            encoding="utf-8" if text else None,
            errors="surrogateescape" if text else None,
            input=input_data,
            **output_options,
        )
    except FileNotFoundError:
        # Git is optional for Codebase scans. Treat an unavailable executable like
        # any other failed Git probe so the target falls back to a directory snapshot.
        empty_output = "" if text else b""
        return subprocess.CompletedProcess(full_command, 127, empty_output, empty_output)


def _update_digest_field_header(digest: Any, label: bytes, value_size: int) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(value_size.to_bytes(8, "big"))


def update_digest_field(digest: Any, label: bytes, value: bytes) -> None:
    _update_digest_field_header(digest, label, len(value))
    digest.update(value)


def _update_digest_field_from_git(
    digest: Any,
    label: bytes,
    target: Path,
    *args: str,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> bool:
    with tempfile.TemporaryFile() as output:
        completed = git_command(
            target,
            *args,
            text=False,
            git_dir=git_dir,
            work_tree=work_tree,
            stdout_file=output,
        )
        if completed.returncode != 0:
            return False
        output.seek(0, os.SEEK_END)
        value_size = output.tell()
        _update_digest_field_header(digest, label, value_size)
        output.seek(0)
        for chunk in iter(lambda: output.read(1024 * 1024), b""):
            digest.update(chunk)
    return True


def worktree_content_digest(target: Path) -> str:
    require_clean_submodule_worktrees(target)
    repository, pathspec = git_worktree_context(target)
    return worktree_content_digest_for_context(repository, pathspec)


def remediation_checkout_snapshot(
    scan: sqlite3.Row, *, expected_revision: str | None = None
) -> tuple[str, str | None]:
    target = require_scan_target_identity(scan)
    revision = git_revision(target)
    required_revision = expected_revision or scan["target_revision"]
    if revision != required_revision:
        raise SystemExit(
            "Repository HEAD changed. Regenerate the remediation patch against the current checkout."
        )
    content_digest = (
        worktree_content_digest(target)
        if revision != "unversioned"
        else directory_content_digest(target, excluded=(Path(scan["scan_dir"]),))
    )
    return revision, content_digest


def worktree_content_digest_for_context(
    repository: Path,
    pathspec: str,
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    tracked_ok = _update_digest_field_from_git(
        digest,
        b"tracked-diff",
        repository,
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "HEAD",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    untracked = git_bytes(
        repository,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    if not tracked_ok or untracked is None:
        raise SystemExit("Could not snapshot the selected working-tree changes.")
    for raw_path in sorted(path for path in untracked.split(b"\0") if path):
        relative_path = os.fsdecode(raw_path)
        path = (work_tree or repository) / relative_path
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
        update_digest_field(digest, b"untracked-path", raw_path)
        update_digest_field(
            digest,
            b"untracked-mode",
            str(stat.S_IMODE(metadata.st_mode)).encode(),
        )
        if stat.S_ISLNK(metadata.st_mode):
            update_digest_field(digest, b"untracked-kind", b"symlink")
            update_digest_field(
                digest,
                b"untracked-content",
                os.fsencode(os.readlink(path)),
            )
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"untracked-kind", b"directory")
            update_digest_field(
                digest,
                b"untracked-content",
                directory_content_digest(path.resolve()).encode(),
            )
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read untracked file: {relative_path}") from exc
            update_digest_field(digest, b"untracked-kind", b"file")
            update_digest_field(
                digest,
                b"untracked-size",
                str(content_size).encode(),
            )
            update_digest_field(
                digest,
                b"untracked-content-sha256",
                content_digest.digest(),
            )
        else:
            raise SystemExit(f"Unsupported untracked file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def git_worktree_context(target: Path) -> tuple[Path, str]:
    root = git_output(target, "rev-parse", "--show-toplevel")
    if root is None:
        raise SystemExit("Could not inspect the selected Git working tree.")
    repository = Path(root).resolve()
    prefix = git_bytes(target, "rev-parse", "--show-prefix")
    if prefix is None:
        raise SystemExit("Could not inspect the selected Git working tree.")
    pathspec = os.fsdecode(prefix.removesuffix(b"\n")).removesuffix("/") or "."
    scoped = (repository / pathspec).resolve()
    try:
        if not scoped.is_relative_to(repository) or not scoped.samefile(target):
            raise ValueError("Git working tree does not contain the selected target")
    except (OSError, ValueError) as exc:
        raise SystemExit("Scan target must stay inside its Git working tree.") from exc
    return repository, pathspec


def git_submodule_entries(target: Path) -> tuple[tuple[Path, str], ...]:
    repository, pathspec = git_worktree_context(target)
    staged = git_bytes(repository, "ls-files", "--stage", "-z", "--", pathspec)
    if staged is None:
        raise SystemExit("Could not inspect Git submodules in the selected working tree.")
    entries = []
    for record in (item for item in staged.split(b"\0") if item):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, _ = metadata.split(b" ", 2)
        except ValueError as exc:
            raise SystemExit(
                "Could not inspect Git submodules in the selected working tree."
            ) from exc
        if mode != b"160000":
            continue
        relative_path = Path(os.fsdecode(raw_path)).relative_to(pathspec)
        entries.append((target / relative_path, object_id.decode("ascii")))
    return tuple(entries)


def require_clean_submodule_worktrees(target: Path) -> None:
    for submodule, expected_revision in git_submodule_entries(target):
        relative_path = str(submodule.relative_to(target))
        if not submodule.exists():
            continue
        try:
            (submodule / ".git").lstat()
        except FileNotFoundError:
            continue
        root = git_output(submodule, "rev-parse", "--show-toplevel")
        try:
            is_initialized = root is not None and Path(root).samefile(submodule)
        except OSError:
            is_initialized = False
        if not is_initialized:
            raise SystemExit(
                f"Could not inspect initialized Git submodule contents: {relative_path}"
            )
        if git_output(submodule, "rev-parse", "HEAD") != expected_revision:
            raise SystemExit(
                "Initialized Git submodules must be checked out at the revision recorded "
                f"by the parent repository: {relative_path}"
            )
        status = git_bytes(
            submodule,
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=none",
        )
        if status is None:
            raise SystemExit(f"Could not inspect Git submodule contents: {relative_path}")
        if status:
            raise SystemExit(
                f"Dirty Git submodules are not supported for remediation integrity checks: {relative_path}"
            )
        require_clean_submodule_worktrees(submodule)


def clean_worktree_content_digest() -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    update_digest_field(digest, b"tracked-diff", b"")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def _has_linked_parent(scope: Path, path: Path) -> bool:
    ancestor = scope
    for component in path.relative_to(scope).parts[:-1]:
        ancestor /= component
        metadata = ancestor.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
            return True
    return False


def git_directory_snapshot_paths(target: Path) -> list[Path] | None:
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None:
        return None
    repository, pathspec = git_worktree_context(target)
    scope = repository / pathspec
    scope_depth = len(Path(pathspec).parts)
    matching_prefixes: dict[str, bool] = {}
    listing_args: list[str] = []
    inventory_pathspec = pathspec
    if scope_depth:
        if any(
            not character.isascii() and character.lower() != character.upper()
            for character in pathspec
        ):
            # Git's icase pathspecs do not cover Unicode case aliases.
            inventory_pathspec = "."
        else:
            listing_args.append("--no-literal-pathspecs")
            inventory_pathspec = f":(icase,literal){pathspec}"
    listed = git_bytes(
        repository,
        *listing_args,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        inventory_pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    paths: list[Path] = []
    for raw_path in (raw_path for raw_path in listed.split(b"\0") if raw_path):
        relative = Path(os.fsdecode(raw_path))
        if scope_depth:
            if len(relative.parts) <= scope_depth:
                continue
            # Git's index spelling can differ after a case-only directory rename.
            # Compare each scope-depth prefix once, without following symlink leaves.
            prefix = repository.joinpath(*relative.parts[:scope_depth])
            key = str(prefix)
            if key not in matching_prefixes:
                try:
                    matching_prefixes[key] = prefix.samefile(scope)
                except (FileNotFoundError, NotADirectoryError):
                    matching_prefixes[key] = False
            # realpath spelling is not a filesystem identity on case-insensitive
            # POSIX volumes; WindowsPath equality also folds distinct names.
            if not matching_prefixes[key]:
                continue
        path = target.joinpath(*relative.parts[scope_depth:])
        try:
            # The index can retain descendants of a directory replaced by a link.
            if _has_linked_parent(target, path):
                continue
            metadata = path.lstat()
        except (FileNotFoundError, NotADirectoryError):
            # The index can retain deleted paths, including directory-to-file replacements.
            continue
        paths.append(path)
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        nested_repository_root = git_output(path, "rev-parse", "--show-toplevel")
        if nested_repository_root is not None and Path(nested_repository_root).samefile(path):
            nested_paths = git_directory_snapshot_paths(path)
            if nested_paths is not None:
                paths.extend(nested_paths)
                continue
        paths.extend(
            nested_path
            for nested_path in path.rglob("*")
            if ".git" not in nested_path.relative_to(path).parts
        )
    return sorted({str(path): path for path in paths}.values(), key=str)


def source_directory_snapshot_paths(target: Path) -> list[Path]:
    paths: list[Path] = []
    pending = [target]
    while pending:
        for path in pending.pop().iterdir():
            if path.name == ".git":
                continue
            paths.append(path)
            metadata = path.lstat()
            # Name-surrogate reparse points include Windows directory junctions.
            if (
                stat.S_ISDIR(metadata.st_mode)
                and not getattr(metadata, "st_reparse_tag", 0) & 0x20000000
            ):
                pending.append(path)
    return sorted(paths)


def directory_content_digest(
    target: Path, *, excluded: tuple[Path, ...] = (), include_ignored: bool = False
) -> str:
    excluded_relative = [
        path.relative_to(target) for path in excluded if path.is_relative_to(target)
    ]
    paths = (
        source_directory_snapshot_paths(target)
        if include_ignored
        else git_directory_snapshot_paths(target)
    )
    if paths is None:
        paths = sorted(target.rglob("*"))
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-directory/v1")
    for path in paths:
        relative_path = path.relative_to(target)
        if any(relative_path.is_relative_to(path) for path in excluded_relative):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not read local file: {relative_path}") from exc
        raw_path = os.fsencode(relative_path.as_posix())
        update_digest_field(digest, b"path", raw_path)
        update_digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode())
        if stat.S_ISLNK(metadata.st_mode) or (
            include_ignored and getattr(metadata, "st_reparse_tag", 0) & 0x20000000
        ):
            update_digest_field(digest, b"kind", b"symlink")
            update_digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            update_digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise SystemExit(f"Could not read local file: {relative_path}") from exc
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(content_size).encode())
            update_digest_field(digest, b"content-sha256", content_digest.digest())
        else:
            raise SystemExit(f"Unsupported local file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def directory_snapshot_regular_file_count(target: Path) -> int:
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = sorted(target.rglob("*"))
    count = 0
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not inspect local file: {path.relative_to(target)}") from exc
        if stat.S_ISREG(metadata.st_mode):
            count += 1
    return count


def copy_directory_excluding(source: Path, destination: Path, excluded: tuple[Path, ...]) -> None:
    excluded_relative = [
        path.relative_to(source) for path in excluded if path.is_relative_to(source)
    ]

    def ignored(directory: str, names: list[str]) -> list[str]:
        relative = Path(directory).relative_to(source)
        return [
            path.name
            for path in excluded_relative
            if path.parent == relative and path.name in names
        ]

    shutil.copytree(source, destination, symlinks=True, ignore=ignored)


def copy_git_worktree_files(source: Path, destination: Path, excluded: tuple[Path, ...]) -> Path:
    repository, pathspec = git_worktree_context(source)
    listed = git_bytes(
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    excluded_relative = []
    for path in excluded:
        try:
            relative_path = path.relative_to(repository)
        except ValueError:
            try:
                relative_path = Path(pathspec) / path.relative_to(source)
            except ValueError:
                continue
        excluded_relative.append(relative_path)
    destination.mkdir()
    for raw_path in sorted(path for path in listed.split(b"\0") if path):
        relative = Path(os.fsdecode(raw_path))
        if any(relative.is_relative_to(path) for path in excluded_relative):
            continue
        source_path = repository / relative
        try:
            metadata = source_path.lstat()
        except FileNotFoundError:
            continue
        destination_path = destination / relative
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        if stat.S_ISLNK(metadata.st_mode):
            destination_path.symlink_to(os.readlink(source_path))
        elif stat.S_ISREG(metadata.st_mode):
            shutil.copy2(source_path, destination_path, follow_symlinks=False)
        elif stat.S_ISDIR(metadata.st_mode):
            nested_git_dir = git_output(source_path, "rev-parse", "--absolute-git-dir")
            if nested_git_dir is None:
                raise SystemExit(f"Could not inspect nested Git working tree: {relative}")
            copy_git_worktree_files(source_path, destination_path, excluded)
            (destination_path / ".git").write_text(f"gitdir: {nested_git_dir}\n", encoding="utf-8")
        else:
            raise SystemExit(f"Unsupported Git working-tree file type: {relative}")
    copied_target = destination if pathspec == "." else destination / pathspec
    copied_target.mkdir(parents=True, exist_ok=True)
    return copied_target


def git_revision(target: Path) -> str:
    return git_output(target, "rev-parse", "HEAD") or "unversioned"


def git_target_metadata(target: Path) -> dict[str, Any]:
    is_git = git_output(target, "rev-parse", "--git-dir") is not None
    is_worktree = git_output(target, "rev-parse", "--is-inside-work-tree") == "true"
    revision = git_output(target, "rev-parse", "--verify", "HEAD")
    repository_root = git_output(target, "rev-parse", "--show-toplevel") if is_worktree else None
    supported = (
        is_git
        and is_worktree
        and revision is not None
        and repository_root is not None
        and Path(repository_root).samefile(target)
    )
    metadata: dict[str, Any] = {
        "hasHead": revision is not None,
        "isGit": is_git,
        "isWorktree": is_worktree,
        "reviewChangesSupported": supported,
    }
    if not is_git:
        return metadata
    branch = git_output(target, "symbolic-ref", "--quiet", "--short", "HEAD")
    metadata.update({"branch": branch, "detachedHead": revision is not None and branch is None})
    if revision is not None:
        subject = git_bytes(target, "show", "-s", "--format=%s", "HEAD")
        metadata.update(
            {
                "commitSubject": (subject or b"").decode("utf-8").strip() or None,
                "revision": revision,
                "shortRevision": revision[:7],
            }
        )
    return metadata


def require_remediation_target(value: str) -> Path:
    stored = Path(value).expanduser()
    if not stored.is_absolute():
        raise SystemExit("Remediation target must be an absolute local directory path.")
    try:
        resolved = stored.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise SystemExit(
            "Remediation is unavailable because the selected checkout is no longer accessible."
        ) from exc
    if resolved != stored or not stored.is_dir():
        raise SystemExit(
            "Remediation is unavailable because the selected checkout path was replaced. Start a new scan."
        )
    return stored


def require_scan_target_identity(scan: sqlite3.Row) -> Path:
    target = require_remediation_target(scan["target_path"])
    expected_inode = scan["target_inode"]
    if expected_inode is None:
        raise SystemExit(
            "Remediation is unavailable because this scan does not record checkout identity. "
            "Start a new scan."
        )
    try:
        metadata = target.stat()
    except OSError as exc:
        raise SystemExit(
            "Remediation is unavailable because the selected checkout is no longer accessible."
        ) from exc
    if not stored_filesystem_identity_matches(expected_inode, metadata.st_ino):
        raise SystemExit(
            "Remediation is unavailable because the selected checkout path was replaced. "
            "Start a new scan."
        )
    return target


def require_git_worktree_head(target: Path) -> str:
    metadata = git_target_metadata(target)
    if not metadata["isGit"] or not metadata["isWorktree"] or not metadata["hasHead"]:
        raise SystemExit("Review changes requires a non-bare Git worktree with a resolvable HEAD.")
    return str(metadata["revision"])


def scan_target_warning(scan: sqlite3.Row) -> str | None:
    if scan["diff_target_kind"] != "working_tree" and not scan["target_snapshot_digest"]:
        return None
    try:
        target = require_scan_target_identity(scan)
        if scan["target_revision"] == "unversioned":
            if (
                directory_content_digest(target, excluded=(Path(scan["scan_dir"]),))
                != scan["target_snapshot_digest"]
            ):
                return (
                    "Directory contents changed while the scan was running; "
                    "results were saved for the original snapshot."
                )
            return None
        if git_revision(target) == "unversioned":
            return (
                "The scanned Git repository became unavailable while the scan was running; "
                "results were saved for the original revision."
            )
        working_tree = scan["diff_target_kind"] == "working_tree"
        expected_head = scan["diff_head_revision"] if working_tree else scan["target_revision"]
        if require_git_worktree_head(target) != expected_head:
            return (
                "Repository HEAD changed while the scan was running; "
                "results were saved for the original revision."
            )
        expected_digest = (
            scan["diff_content_digest"] if working_tree else scan["target_snapshot_digest"]
        )
        if worktree_content_digest(target) != expected_digest:
            return (
                "Working-tree contents changed while the scan was running; "
                "results were saved for the original snapshot."
            )
    except (OSError, SystemExit):
        return (
            "The scan target became unavailable while the scan was running; "
            "results were saved for the original revision or snapshot."
        )
    return None


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
