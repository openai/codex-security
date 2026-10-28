"""Target inspection and content-integrity helpers for the security workbench."""

from __future__ import annotations

import argparse
import codecs
import errno
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, NamedTuple

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import stored_filesystem_identity_matches
from windows_scan_local_files import copy_directory_junction
from workbench_constants import GIT_REPOSITORY_ENVIRONMENT

SOURCE_METADATA_DIRECTORIES = {".git", ".svn"}
_WINDOWS = os.name == "nt"


class UnreadableLocalFile(SystemExit):
    """Source contents are unavailable for an optional review cache."""


class UnsupportedLocalFileType(SystemExit):
    """An entry cannot be read as source content for a review cache."""


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
    retain_samples: bool = True,
    check: bool = False,
) -> list[tuple[bytes, bool] | None]:
    """Sample ordered blobs and classify all their bytes without buffering the batch."""
    if not object_names:
        return []

    # Git before 2.38 rejects -z, so only names with line breaks need it.
    nul_input = any("\n" in name or "\r" in name for name in object_names)
    separator = b"\0" if nul_input else b"\n"
    request = separator.join(os.fsencode(name) for name in object_names) + separator
    read_fd, write_fd = os.pipe()
    with (
        ThreadPoolExecutor(max_workers=1) as reader,
        os.fdopen(read_fd, "rb") as output,
        os.fdopen(write_fd, "wb") as sink,
    ):

        def read_samples() -> list[tuple[bytes, bool] | None]:
            # Closing the reader also unblocks Git if framing is invalid.
            with output:
                return _read_git_batch_samples(output, object_names, retain_samples=retain_samples)

        samples = reader.submit(read_samples)
        try:
            completed = git_command(
                target,
                "cat-file",
                "--batch",
                *(["-z"] if nul_input else []),
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
            if check:
                completed.check_returncode()
            return [None] * len(object_names)
        try:
            result = samples.result()
        except ValueError:
            result = [None] * len(object_names)
        if check and None in result and completed.stderr:
            raise SystemExit(
                f"Unable to read committed diff blob: {object_names[result.index(None)]}\n"
                + os.fsdecode(completed.stderr).strip()
            )
        return result


def _read_git_batch_samples(
    output: BinaryIO, object_names: list[str], *, retain_samples: bool = True
) -> list[tuple[bytes, bool] | None]:
    """Read the older-Git-compatible -z protocol without buffering blob bodies."""
    samples: list[tuple[bytes, bool] | None] = []
    for name in object_names:
        header = output.readline()
        raw_name = os.fsencode(name)
        # Missing lookups echo the whole request, including any embedded newlines.
        if header and raw_name.startswith(header):
            header += output.read(len(raw_name) - len(header)) + output.readline()
        if header in (raw_name + b" missing\n", raw_name + b" ambiguous\n"):
            samples.append(None)
            continue
        fields = header.split(b" ")
        if len(fields) != 3 or not header.endswith(b"\n"):
            raise ValueError("invalid batch header")
        size = int(fields[2])
        if size < 0:
            raise ValueError("invalid blob size")
        # Consume non-blob objects too, so subsequent records stay aligned.
        sample = _read_source_sample(output, size)
        if output.read(1) != b"\n":
            raise ValueError("missing blob terminator")
        if not retain_samples:
            sample = (b"", sample[1])
        samples.append(sample if fields[1] == b"blob" else None)
    return samples


def _is_binary_sample(data: bytes) -> bool:
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "\0" in data.decode("utf-16", errors="ignore")
    return b"\0" in data


def _read_source_sample(output: BinaryIO, size: int, *, drain: bool = True) -> tuple[bytes, bool]:
    read_size = 64 * 1024
    sample_size = min(size, read_size)
    sample = output.read(sample_size)
    if len(sample) != sample_size:
        raise ValueError("truncated blob")
    binary = _is_binary_sample(sample)
    bom = sample[:2] if sample.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else b""
    remaining = size - sample_size
    while remaining:
        if binary and not drain:
            break
        chunk_size = min(remaining, read_size)
        chunk = output.read(chunk_size)
        if len(chunk) != chunk_size:
            raise ValueError("truncated blob")
        # Even-sized reads keep UTF-16 code units aligned; preserve the original byte order.
        if not binary:
            binary = _is_binary_sample(bom + chunk) if bom else b"\0" in chunk
        remaining -= chunk_size
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


def _git_configuration_environment(environment: dict[str, str]) -> dict[str, str]:
    canonical = str.upper if _WINDOWS else str
    bridge = next(
        (name for name in environment if canonical(name) == "CODEX_SECURITY_GIT_ENVIRONMENT_FILE"),
        None,
    )
    selected: dict[str, str] = {}
    for source in (
        json.loads(Path(environment[bridge]).read_text(encoding="utf-8"))
        if bridge is not None
        else {},
        environment,
    ):
        for name, value in source.items():
            key = canonical(name)
            if isinstance(value, str) and re.fullmatch(
                r"GIT_CONFIG_(?:GLOBAL|SYSTEM|NOSYSTEM|PARAMETERS|COUNT|(?:KEY|VALUE)_\d+)"
                r"|GIT_ATTR_(?:SOURCE|NOSYSTEM)|GIT_NO_REPLACE_OBJECTS|GIT_REPLACE_REF_BASE|XDG_CONFIG_HOME",
                key,
            ):
                selected[key] = value
    return selected


def git_inspection_environment(
    environment: dict[str, str], executable: str, target: Path
) -> dict[str, str]:
    """Keep inline Git behavior settings without forwarding HTTP authentication."""
    environment = environment.copy()
    configuration = _git_configuration_environment(environment)
    if _WINDOWS:
        for name in tuple(environment):
            if name.upper() in configuration:
                del environment[name]
    environment.update(configuration)
    for name in tuple(environment):
        if re.fullmatch(r"CODEX_SECURITY_GIT_ENVIRONMENT(?:_FILE)?", name, re.IGNORECASE):
            del environment[name]

    def authentication_header(key: str) -> bool:
        return re.fullmatch(r"http(?:\..*)?\.extraheader", key, re.IGNORECASE) is not None

    header_indexes = [
        match[1]
        for name, value in environment.items()
        if (match := re.fullmatch(r"GIT_CONFIG_KEY_(\d+)", name)) and authentication_header(value)
    ]
    if not header_indexes and not environment.get("GIT_CONFIG_PARAMETERS"):
        return environment

    def parser_environment(
        source: dict[str, str], *, parameters_only: bool = False
    ) -> dict[str, str]:
        selected = source.copy()
        for name in tuple(selected):
            key = name.upper() if _WINDOWS else name
            if (
                key in GIT_REPOSITORY_ENVIRONMENT
                or key == "GIT_CONFIG"
                or (
                    parameters_only and re.fullmatch(r"GIT_CONFIG_(?:COUNT|(?:KEY|VALUE)_\d+)", key)
                )
            ):
                del selected[name]
        selected["GIT_NO_LAZY_FETCH"] = "1"
        selected["GIT_ALLOW_PROTOCOL"] = ""
        return selected

    def run(args: list[str], selected: dict[str, str]) -> bytes:
        completed = subprocess.run(
            [executable, "--no-pager", "-C", str(target), *args],
            env=selected,
            capture_output=True,
            check=False,
        )
        completed.check_returncode()
        return completed.stdout

    def command_settings(output: bytes) -> list[tuple[str, str | None]]:
        fields = output.split(b"\0")
        settings: list[tuple[str, str | None]] = []
        for index in range(0, len(fields) - 1, 2):
            if fields[index] != b"command line:":
                continue
            # Git rejects LF in command-setting keys. File subsection keys may
            # contain it, so discard other scopes before splitting the record.
            key, separator, value = fields[index + 1].partition(b"\n")
            settings.append((os.fsdecode(key), os.fsdecode(value) if separator else None))
        return settings

    parser_args = ["config", "--null", "--list", "--show-origin", "--no-includes"]
    # Validate first so removing a header cannot hide malformed native settings.
    full = command_settings(run(parser_args, parser_environment(environment)))
    parameters = command_settings(
        run(parser_args, parser_environment(environment, parameters_only=True))
    )
    count = len(full) - len(parameters)
    original = environment.copy()
    for index in header_indexes:
        environment.pop(f"GIT_CONFIG_KEY_{index}", None)
        environment.pop(f"GIT_CONFIG_VALUE_{index}", None)
    if (
        count > 0
        and any(authentication_header(key) for key, _ in full[:count])
        and all(
            f"GIT_CONFIG_KEY_{index}" in original and f"GIT_CONFIG_VALUE_{index}" in original
            for index in range(count)
        )
    ):
        retained: list[tuple[str, str]] = []
        for index in range(count):
            key, value = original[f"GIT_CONFIG_KEY_{index}"], original[f"GIT_CONFIG_VALUE_{index}"]
            environment.pop(f"GIT_CONFIG_KEY_{index}", None)
            environment.pop(f"GIT_CONFIG_VALUE_{index}", None)
            if not authentication_header(key):
                retained.append((key, value))
        environment["GIT_CONFIG_COUNT"] = str(len(retained))
        for index, (key, value) in enumerate(retained):
            environment[f"GIT_CONFIG_KEY_{index}"] = key
            environment[f"GIT_CONFIG_VALUE_{index}"] = value
    if any(authentication_header(key) for key, _ in parameters):
        selected = parser_environment(environment, parameters_only=True)
        selected.pop("GIT_CONFIG_PARAMETERS", None)

        def quote(arguments: list[str]) -> str:
            try:
                return os.fsdecode(run(["rev-parse", "--sq-quote", *arguments], selected)).strip()
            except OSError as error:
                # Native quoting can exceed argv space even when the original
                # single PARAMETERS environment value fits.
                if (error.errno != errno.E2BIG and getattr(error, "winerror", None) != 206) or len(
                    arguments
                ) < 2:
                    raise
                middle = len(arguments) // 2
                return quote(arguments[:middle]) + " " + quote(arguments[middle:])

        pieces: list[str] = []
        pending: list[str] = []
        for key, value in parameters:
            if authentication_header(key):
                continue
            # Keep legacy quoting for older Git. An '=' inside the key needs
            # the separate key/value form already accepted by the native parser.
            if "=" not in key:
                pending.append(key if value is None else f"{key}={value}")
                continue
            if pending:
                pieces.append(quote(pending))
                pending.clear()
            pieces.append(quote([key]) + "=" + ("" if value is None else quote([value])))
        if pending:
            pieces.append(quote(pending))
        environment["GIT_CONFIG_PARAMETERS"] = " ".join(pieces)
    return environment


def git_command(
    target: Path,
    *args: str,
    text: bool,
    input_data: str | bytes | None = None,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
    stdout_file: BinaryIO | None = None,
    stdin_file: BinaryIO | None = None,
    pathspec_environment: dict[str, str] | None = None,
    ignore_config_file: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    if (git_dir is None) != (work_tree is None):
        raise ValueError("git_dir and work_tree must be provided together")
    executable = trusted_git_executable(target)
    environment = os.environ.copy()
    try:
        if executable is not None:
            environment = git_inspection_environment(environment, executable, target)
    except subprocess.CalledProcessError as exc:
        return subprocess.CompletedProcess(
            exc.cmd,
            exc.returncode,
            "" if text else b"",
            os.fsdecode(exc.stderr or b"") if text else exc.stderr,
        )
    except FileNotFoundError:
        executable = None
    for name in GIT_REPOSITORY_ENVIRONMENT:
        environment.pop(name, None)
    if ignore_config_file:
        environment.pop("GIT_CONFIG", None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    if pathspec_environment is not None:
        environment.update(pathspec_environment)
    # Local inspection must not fetch objects through a configured transport.
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_ALLOW_PROTOCOL"] = ""
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
        if stdin_file is not None:
            output_options["stdin"] = stdin_file
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


class _GitChange(NamedTuple):
    name: str
    status: str
    base_blob: str
    head_blob: str
    source_name: str | None = None


def _git_paths_output(repo: Path, args: list[str], names: list[str]) -> bytes:
    if not names:
        return b""
    try:
        result = git_command(
            repo, *args, "--", *names, text=False, pathspec_environment={"GIT_ICASE_PATHSPECS": "0"}
        )
    except OSError as error:
        # Retry only an actual native argument-length failure, without a path cap.
        if (error.errno != errno.E2BIG and getattr(error, "winerror", None) != 206) or len(
            names
        ) < 2:
            raise
        middle = len(names) // 2
        return _git_paths_output(repo, args, names[:middle]) + _git_paths_output(
            repo, args, names[middle:]
        )
    result.check_returncode()
    return result.stdout


def _worktree_object_hashes(repo: Path, names: list[str]) -> dict[str, bytes]:
    try:
        output = _git_paths_output(repo, ["hash-object"], names)
    except subprocess.CalledProcessError:
        readable = []
        for name in names:
            try:
                if _local_diff_status(repo, repo / name, "M", {}) != "M":
                    continue
                with (repo / name).open("rb") as source:
                    source.read(1)
            except OSError:
                continue
            readable.append(name)
        if len(readable) == len(names):
            raise
        return _worktree_object_hashes(repo, readable)
    return dict(zip(names, output.splitlines()))


def _unchanged_worktree_files(repo: Path, candidates: dict[str, bytes]) -> set[str]:
    if not candidates:
        return set()
    replacements = git_command(repo, "replace", "-l", "--format=short", text=False)
    replacements.check_returncode()
    replaced = {oid.lower() for oid in replacements.stdout.splitlines()} & set(candidates.values())
    if replaced and "GIT_NO_REPLACE_OBJECTS" not in _git_configuration_environment(os.environ):
        enabled = git_command(
            repo,
            "config",
            "--bool",
            "--get",
            "core.useReplaceRefs",
            text=False,
            ignore_config_file=True,
        )
        if enabled.returncode != 1:
            enabled.check_returncode()
        if enabled.returncode == 1 or enabled.stdout.strip() != b"false":
            # Hashes and status compare index OIDs without replacement refs.
            # Preserve Git's selected change when its base uses a replacement.
            candidates = {name: oid for name, oid in candidates.items() if oid not in replaced}
    hashes = _worktree_object_hashes(repo, list(candidates))
    unchanged = {
        name for name, oid in candidates.items() if name not in hashes or hashes[name] == oid
    }
    remaining = [name for name in candidates if name not in unchanged]
    indexed = {}
    for record in _git_paths_output(repo, ["ls-files", "--stage", "-z"], remaining).split(b"\0"):
        if not record:
            continue
        metadata, _, name = record.partition(b"\t")
        fields = metadata.split()
        if fields[2] == b"0":
            indexed[os.fsdecode(name)] = fields[1]
    matching = [name for name in remaining if indexed.get(name) == candidates[name]]
    # Git's loaded index preserves automatic EOL rules; inspect only eligible
    # selected paths and leave the original index untouched.
    status = _git_paths_output(
        repo,
        [
            "--no-optional-locks",
            "status",
            "--porcelain",
            "-z",
            "--untracked-files=no",
            "--ignore-submodules=all",
            "--no-renames",
        ],
        matching,
    )
    dirty = {os.fsdecode(record[3:]) for record in status.split(b"\0") if record}
    unchanged.update(set(matching) - dirty)
    return unchanged


def _run_git_changes(repo: Path, diff_args: list[str], *, local: bool = False) -> list[_GitChange]:
    """Return changed regular files from the selected side of each change."""
    result = git_command(
        repo,
        # Raw inspection must not refresh the full index, including excluded metadata.
        *(["-c", "diff.autoRefreshIndex=false"] if local else []),
        *(["--no-literal-pathspecs"] if local else []),
        "diff",
        "--ignore-submodules=all",
        "--raw",
        "--no-abbrev",
        "-z",
        "--diff-filter=ACMRDT",
        *diff_args,
        "--",
        *([":(top,glob,exclude)**/.svn", ":(top,glob,exclude)**/.svn/**"] if local else []),
        text=False,
        pathspec_environment={"GIT_ICASE_PATHSPECS": "0"} if local else None,
    )
    result.check_returncode()
    fields = result.stdout.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()

    changed: list[_GitChange] = []
    candidates: dict[str, bytes] = {}
    index = 0
    linked_prefixes: dict[str, bool] = {}
    while index < len(fields):
        metadata = fields[index].split()
        status = chr(metadata[-1][0])
        index += 1
        source_name = os.fsdecode(fields[index]) if status == "R" else None
        if status in {"C", "R"}:
            index += 1
        name = os.fsdecode(fields[index])
        index += 1
        selected_mode = metadata[0].removeprefix(b":") if status == "D" else metadata[1]
        if selected_mode.startswith(b"100"):
            if (
                local
                and status == "M"
                and metadata[0].removeprefix(b":") == metadata[1]
                and not metadata[3].strip(b"0")
                and _local_diff_status(repo, repo / name, status, linked_prefixes) == status
            ):
                # Raw worktree records can reflect only stale index stat data.
                # Normalize eligible text without opening the older base blob or
                # making Git buffer files the inventory already excludes as binary.
                try:
                    source = (repo / name).open("rb")
                except OSError:
                    continue
                with source:
                    try:
                        _, binary = _read_source_sample(
                            source, os.fstat(source.fileno()).st_size, drain=False
                        )
                    except (OSError, ValueError):
                        continue
                    if not binary:
                        candidates[name] = metadata[2]
            changed.append(
                _GitChange(name, status, metadata[2].decode(), metadata[3].decode(), source_name)
            )
    unchanged = _unchanged_worktree_files(repo, candidates)
    return [change for change in changed if change.name not in unchanged]


def _git_changes(repo: Path, base: str, head: str, mode: str) -> list[_GitChange]:
    if mode == "revisions":
        return _run_git_changes(repo, [f"{base}..{head}"])
    if mode == "local-patch":
        unstaged = _run_git_changes(repo, [base], local=True)
        staged = _run_git_changes(repo, ["--cached", base], local=True)
        untracked = git_command(
            repo,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            text=False,
        )
        untracked.check_returncode()
        # Preserve Git spelling even when it is not a valid Windows filesystem path.
        combined = {change.name: change for change in staged}
        combined.update((change.name, change) for change in unstaged)
        linked_prefixes: dict[str, bool] = {}
        for relative in untracked.stdout.split(b"\0"):
            if not relative or relative.endswith(b"/"):
                continue
            name = os.fsdecode(relative)
            if not SOURCE_METADATA_DIRECTORIES.isdisjoint(PurePosixPath(name).parts):
                continue
            if _local_diff_status(repo, repo / name, "A", linked_prefixes) is not None:
                combined[name] = _GitChange(name, "A", "", "")
        changes: dict[str, _GitChange] = {}
        for name, change in combined.items():
            if not SOURCE_METADATA_DIRECTORIES.isdisjoint(PurePosixPath(name).parts):
                continue
            selected = _local_diff_status(repo, repo / name, change.status, linked_prefixes)
            if selected is None and change.status == "R" and change.source_name is not None:
                changes.setdefault(
                    change.source_name,
                    _GitChange(change.source_name, "D", change.base_blob, ""),
                )
            elif selected is not None:
                changes[name] = change._replace(status=selected)
        return sorted(changes.values())
    raise SystemExit(f"Unknown diff mode: {mode}")


def git_changed_path_names(repo: Path, base: str, head: str, mode: str) -> list[tuple[str, str]]:
    return [(change.name, change.status) for change in _git_changes(repo, base, head, mode)]


def git_changed_paths(repo: Path, base: str, head: str, mode: str) -> list[tuple[Path, str]]:
    return [
        (repo / name, status) for name, status in git_changed_path_names(repo, base, head, mode)
    ]


def _local_diff_status(
    repo: Path, path: Path, status: str, linked_prefixes: dict[str, bool]
) -> str | None:
    if status == "D":
        return status
    try:
        if _directory_link_boundary(repo, path, linked_prefixes) != path:
            # A junction can expose a modified base file outside the selected view.
            return "D" if status == "M" else None
        return status if stat.S_ISREG(path.lstat().st_mode) else None
    except (FileNotFoundError, NotADirectoryError):
        return None


def diff_scope_file_count(target: Path, diff_target: dict[str, str]) -> int:
    """Count the text paths selected by the diff inventory for coverage."""
    base, head = diff_target["baseRevision"], diff_target["headRevision"]
    local = diff_target["kind"] == "working_tree"
    try:
        changes = _git_changes(target, base, head, "local-patch" if local else "revisions")
    except subprocess.CalledProcessError as exc:
        detail = os.fsdecode(exc.stderr or b"").strip() or str(exc)
        raise SystemExit(f"could not resolve the selected Git changes: {detail}") from exc

    text_paths: set[str] = set()
    committed: dict[str, str] = {}
    for change in changes:
        name, status = change.name, change.status
        if not local or status == "D":
            committed[name] = change.base_blob if status == "D" else change.head_blob
        else:
            path = target / name
            try:
                if not path.resolve().is_relative_to(target):
                    continue
                with path.open("rb") as source:
                    _, binary = _read_source_sample(
                        source, os.fstat(source.fileno()).st_size, drain=False
                    )
            except (OSError, ValueError):
                # The inventory skips unreadable working-tree files.
                continue
            if not binary:
                text_paths.add(name)
    object_ids = list(dict.fromkeys(committed.values()))
    try:
        samples = git_blob_samples(target, object_ids, retain_samples=False, check=True)
    except subprocess.CalledProcessError as exc:
        detail = os.fsdecode(exc.stderr or b"").strip() or str(exc)
        raise SystemExit(f"could not read the selected Git blobs: {detail}") from exc
    samples_by_id = dict(zip(object_ids, samples))
    for change in changes:
        name, status = change.name, change.status
        if name not in committed:
            continue
        sample = samples_by_id[committed[name]]
        if sample is None:
            raise SystemExit(
                f"Unable to read committed diff blob: {base if status == 'D' else head}:{name}"
            )
        if not sample[1]:
            text_paths.add(name)
    if any("\r" in name or "\n" in name for name in text_paths):
        raise SystemExit("Git changes contain a path that cannot fit in the file inventory")
    return len(text_paths)


def candidate_source_lines(
    target: Path,
    diff_target: dict[str, str],
    paths: list[str],
    locations: list[str],
    case_insensitive: bool = False,
) -> dict[str, dict[str, Any]]:
    """Resolve candidate sources in the same selected view as the diff inventory."""
    base, head = diff_target["baseRevision"], diff_target["headRevision"]
    local = diff_target["kind"] == "working_tree"
    changed = {
        path.relative_to(target).as_posix(): status
        for path, status in git_changed_paths(
            target, base, head, "local-patch" if local else "revisions"
        )
    }
    selected_names = set(changed)
    aliases: dict[str, str | None] = {}
    if case_insensitive:
        if not local:
            tree = git_command(target, "ls-tree", "-r", "-t", "-z", "--name-only", head, text=False)
            tree.check_returncode()
            selected_names.update(os.fsdecode(name) for name in tree.stdout.split(b"\0") if name)
        for name in selected_names:
            key = name.lower()
            aliases[key] = None if key in aliases and aliases[key] != name else name
    location_set = set(locations)
    result: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    for raw in dict.fromkeys([*paths, *locations]):
        path = PurePosixPath(raw)
        if not raw or path.is_absolute() or ".." in path.parts or "\0" in raw:
            raise ValueError("path: expected a repository-relative path without traversal")
        name = path.as_posix()
        if case_insensitive and name not in selected_names:
            selected = aliases.get(name.lower(), name)
            if selected is None:
                result[raw] = {"error": "missing"}
                continue
            name = selected
        deleted = changed.get(name) == "D"
        if local and not deleted:
            continue
        revision = base if deleted else head
        if name not in changed:
            entry = git_command(target, "ls-tree", "-z", revision, "--", name, text=False)
            entry.check_returncode()
            metadata = next(
                (
                    row.partition(b"\t")[0].split()
                    for row in entry.stdout.split(b"\0")
                    if row.partition(b"\t")[2] == os.fsencode(name)
                ),
                [],
            )
            if not metadata or not metadata[0].startswith(b"100"):
                result[raw] = {"error": "not_file" if metadata else "missing"}
                continue
        source: dict[str, Any] = {"path": name}
        if raw in location_set:
            if name not in counts:
                blob = git_command(target, "cat-file", "blob", f"{revision}:{name}", text=False)
                blob.check_returncode()
                data = blob.stdout
                counts[name] = len(re.split(rb"\r\n|[\r\n]", data)) - int(
                    not data or data.endswith((b"\r", b"\n"))
                )
            source["lineCount"] = counts[name]
        result[raw] = source
    return result


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
    scan: sqlite3.Row,
    *,
    expected_revision: str | None = None,
    head_changed_message: str = (
        "Repository HEAD changed. Regenerate the remediation patch against the current checkout."
    ),
) -> tuple[str, str | None]:
    target = require_scan_target_identity(scan)
    revision = git_revision(target)
    required_revision = expected_revision or scan["target_revision"]
    if revision != required_revision:
        raise SystemExit(head_changed_message)
    content_digest = (
        worktree_content_digest(target)
        if revision != "unversioned"
        else directory_content_digest(target, excluded=(Path(scan["scan_dir"]),))
    )
    return revision, content_digest


def require_scan_target_unchanged(scan: sqlite3.Row) -> None:
    head_changed_message = "Repository HEAD changed. Run a new scan before validating its findings."
    if (
        scan["diff_target_kind"] not in {"working_tree", "commit", "range"}
        and scan["target_snapshot_digest"] is None
        and scan["mode"] != "diff"
        and scan["target_revision"] != "unversioned"
    ):
        # Legacy Git records bind only the revision, not working-tree contents.
        target = require_scan_target_identity(scan)
        if git_revision(target) != scan["target_revision"]:
            raise SystemExit(head_changed_message)
        require_clean_submodule_worktrees(target)
        return
    _, current_digest = remediation_checkout_snapshot(
        scan, head_changed_message=head_changed_message
    )
    if scan["diff_target_kind"] == "working_tree":
        expected_digest = scan["diff_content_digest"]
    elif scan["diff_target_kind"] in {"commit", "range"}:
        tracked = git_bytes(Path(scan["target_path"]), "ls-files", "-t", "-z")
        if tracked is None:
            raise SystemExit("Could not inspect tracked files in the scan target.")
        if any(entry.startswith(b"S ") for entry in tracked.split(b"\0")):
            raise SystemExit(
                "Committed-diff scans require a full repository checkout. "
                "Sparse checkouts are not supported; materialize skipped tracked files and retry."
            )
        expected_digest = clean_worktree_content_digest()
    else:
        expected_digest = scan["target_snapshot_digest"]
    if current_digest != expected_digest:
        raise SystemExit(
            "Scan target contents changed since the scan. "
            "Run a new scan before validating its findings."
        )


def worktree_content_digest_for_context(
    repository: Path,
    pathspec: str,
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
) -> str:
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-snapshot/v1")
    source_pathspecs = [
        f":(literal){pathspec}",
        ":(top,glob,exclude)**/.svn",
        ":(top,glob,exclude)**/.svn/**",
    ]
    tracked_ok = _update_digest_field_from_git(
        digest,
        b"tracked-diff",
        repository,
        "--no-literal-pathspecs",
        "diff",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "HEAD",
        "--",
        *source_pathspecs,
        git_dir=git_dir,
        work_tree=work_tree,
    )
    untracked = git_bytes(
        repository,
        "--no-literal-pathspecs",
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        *source_pathspecs,
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


def _directory_link_boundary(target: Path, path: Path, linked_prefixes: dict[str, bool]) -> Path:
    # The index can retain descendants of a directory replaced by a link.
    # Keep the link's identity in snapshots without following its contents.
    prefix = target
    for component in path.relative_to(target).parts[:-1]:
        prefix /= component
        key = str(prefix)
        if key not in linked_prefixes:
            metadata = prefix.lstat()
            linked_prefixes[key] = bool(
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_reparse_tag", 0) & 0x20000000
            )
        if linked_prefixes[key]:
            return prefix
    return path


def git_directory_snapshot_paths(target: Path) -> list[Path] | None:
    repository_root = git_output(target, "rev-parse", "--show-toplevel")
    if repository_root is None:
        return None
    repository, pathspec = git_worktree_context(target)
    scope = repository / pathspec
    scope_depth = len(Path(pathspec).parts)
    matching_prefixes: dict[str, bool] = {}
    linked_prefixes: dict[str, bool] = {}
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
        "-t",
        "-z",
        "--",
        inventory_pathspec,
    )
    if listed is None:
        raise SystemExit("Could not inspect files in the selected Git working tree.")
    paths: list[Path] = []
    junctions: dict[tuple[int, int], Path] = {}
    nested_worktrees: set[tuple[int, int]] = set()
    for entry in (entry for entry in listed.split(b"\0") if entry):
        relative = Path(os.fsdecode(entry[2:]))
        if not SOURCE_METADATA_DIRECTORIES.isdisjoint(relative.parts):
            continue
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
            path = _directory_link_boundary(target, path, linked_prefixes)
            metadata = path.lstat()
        except (FileNotFoundError, NotADirectoryError):
            # The index can retain deleted paths, including directory-to-file replacements.
            continue
        if getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
            # Case aliases share the link's identity. Prefer the stable index
            # spelling over untracked descendants added in its external target.
            identity = metadata.st_dev, metadata.st_ino
            if entry[:1] != b"?" or identity not in junctions:
                junctions[identity] = path
            continue
        paths.append(path)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or getattr(metadata, "st_reparse_tag", 0) & 0x20000000
        ):
            continue
        nested_repository_root = git_output(path, "rev-parse", "--show-toplevel")
        if nested_repository_root is not None and Path(nested_repository_root).samefile(path):
            nested_paths = git_directory_snapshot_paths(path)
            if nested_paths is not None:
                nested_worktrees.add((metadata.st_dev, metadata.st_ino))
                paths.extend(nested_paths)
                continue
        paths.extend(source_directory_snapshot_paths(path))

    if _WINDOWS:
        # Git omits empty untracked directories from its file listing. Inventory
        # junction identities independently of whether their targets contain files.
        git_directory = git_output(target, "rev-parse", "--absolute-git-dir")
        if git_directory is None:
            raise SystemExit("Could not inspect the selected Git working tree.")
        directories = git_bytes(
            target,
            "--no-literal-pathspecs",
            "ls-files",
            "--others",
            "--directory",
            "--exclude-standard",
            "-z",
            "--",
            # Seed only eligible descendants, never the selected directory itself.
            ":(glob)**/*/",
            git_dir=Path(git_directory),
            work_tree=repository,
        )
        if directories is None:
            raise SystemExit("Could not inspect directories in the selected Git working tree.")
        pending = [target / os.fsdecode(path) for path in directories.split(b"\0") if path]
        while pending:
            children: list[Path] = []
            for path in pending:
                if not SOURCE_METADATA_DIRECTORIES.isdisjoint(path.relative_to(target).parts):
                    continue
                try:
                    path = _directory_link_boundary(target, path, linked_prefixes)
                    metadata = path.lstat()
                except (FileNotFoundError, NotADirectoryError):
                    continue
                if getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
                    junctions.setdefault((metadata.st_dev, metadata.st_ino), path)
                elif stat.S_ISLNK(metadata.st_mode):
                    paths.append(path)
                elif stat.S_ISDIR(metadata.st_mode):
                    if (metadata.st_dev, metadata.st_ino) in nested_worktrees:
                        # Its own inventory already applied its repository exclusions.
                        continue
                    try:
                        children.extend(path.iterdir())
                    except PermissionError:
                        # Match Git's treatment of unreadable descendants.
                        continue
            candidates: dict[bytes, Path] = {}
            for path in children:
                if os.path.normcase(path.name) in SOURCE_METADATA_DIRECTORIES:
                    continue
                try:
                    metadata = path.lstat()
                except (FileNotFoundError, NotADirectoryError, PermissionError):
                    continue
                if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
                    continue
                relative = (Path(pathspec) / path.relative_to(target)).as_posix()
                candidates[os.fsencode(relative)] = path
            if not candidates:
                break
            # Filter a directory level at once, retaining the outer repository context.
            ignored = git_command(
                repository,
                "--no-literal-pathspecs",
                "check-ignore",
                "-z",
                "--stdin",
                text=False,
                input_data=b"\0".join(candidates) + b"\0",
                git_dir=Path(git_directory),
                work_tree=repository,
                pathspec_environment={
                    "GIT_NOGLOB_PATHSPECS": "0",
                },
            )
            if ignored.returncode not in (0, 1):
                raise SystemExit("Could not inspect directories in the selected Git working tree.")
            excluded = set(ignored.stdout.split(b"\0"))
            pending = [path for raw, path in candidates.items() if raw not in excluded]
    paths.extend(junctions.values())
    return sorted({str(path): path for path in paths}.values(), key=str)


def source_directory_snapshot_paths(
    target: Path,
    excluded: tuple[Path, ...] = (),
    *,
    include_git_metadata: bool = False,
    onerror: Callable[[OSError], None] | None = None,
) -> list[Path]:
    paths: list[Path] = []
    for directory, directories, files in os.walk(
        target, topdown=True, followlinks=False, onerror=onerror
    ):
        parent = Path(directory)
        for name in directories[:]:
            path = parent / name
            if (
                name in SOURCE_METADATA_DIRECTORIES and not include_git_metadata
            ) or path in excluded:
                directories.remove(name)
                continue
            paths.append(path)
            # Name-surrogate reparse points include Windows directory junctions.
            if getattr(path.lstat(), "st_reparse_tag", 0) & 0x20000000:
                directories.remove(name)
        paths.extend(
            parent / name
            for name in files
            if (name not in SOURCE_METADATA_DIRECTORIES or include_git_metadata)
            and parent / name not in excluded
        )
    return sorted(paths)


def directory_content_digest(
    target: Path,
    *,
    excluded: tuple[Path, ...] = (),
    include_ignored: bool = False,
    include_git_metadata: bool = False,
) -> str:
    def raise_walk_error(error: OSError) -> None:
        raise error

    excluded_relative = [
        path.relative_to(target) for path in excluded if path.is_relative_to(target)
    ]
    paths = (
        source_directory_snapshot_paths(
            target, excluded, include_git_metadata=include_git_metadata, onerror=raise_walk_error
        )
        if include_ignored
        else git_directory_snapshot_paths(target)
    )
    if paths is None:
        paths = source_directory_snapshot_paths(target, excluded)
    digest = hashlib.sha256()
    update_digest_field(digest, b"format", b"codex-security-directory/v1")
    for path in paths:
        relative_path = path.relative_to(target)
        if any(relative_path.is_relative_to(path) for path in excluded_relative):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise UnreadableLocalFile(f"Could not read local file: {relative_path}") from exc
        mode = metadata.st_mode
        link_target = (
            os.readlink(path)
            if stat.S_ISLNK(mode) or getattr(metadata, "st_reparse_tag", 0) & 0x20000000
            else None
        )
        raw_path = os.fsencode(relative_path.as_posix())
        update_digest_field(digest, b"path", raw_path)
        update_digest_field(digest, b"mode", str(stat.S_IMODE(mode)).encode())
        if link_target is not None:
            update_digest_field(digest, b"kind", b"symlink")
            update_digest_field(digest, b"content", os.fsencode(link_target))
        elif stat.S_ISDIR(mode):
            update_digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(mode):
            content_digest = hashlib.sha256()
            content_size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        content_size += len(chunk)
            except OSError as exc:
                raise UnreadableLocalFile(f"Could not read local file: {relative_path}") from exc
            update_digest_field(digest, b"kind", b"file")
            update_digest_field(digest, b"size", str(content_size).encode())
            update_digest_field(digest, b"content-sha256", content_digest.digest())
        else:
            raise UnsupportedLocalFileType(f"Unsupported local file type: {relative_path}")
    return f"codex-security-snapshot/v1:sha256:{digest.hexdigest()}"


def directory_snapshot_regular_file_count(target: Path) -> int:
    paths = git_directory_snapshot_paths(target)
    if paths is None:
        paths = source_directory_snapshot_paths(target)
    count = 0
    for path in paths:
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise SystemExit(f"Could not inspect local file: {path.relative_to(target)}") from exc
        if stat.S_ISREG(metadata.st_mode):
            count += 1
    return count


def copy_directory_excluding(
    source: Path, destination: Path, excluded: tuple[Path, ...]
) -> list[Path]:
    excluded_relative = [
        path.relative_to(source) for path in excluded if path.is_relative_to(source)
    ]

    junctions: list[Path] = []

    def ignored(directory: str, names: list[str]) -> list[str]:
        relative = Path(directory).relative_to(source)
        skipped = [
            path.name
            for path in excluded_relative
            if path.parent == relative and path.name in names
        ]
        for name in names:
            if name in skipped:
                continue
            path = Path(directory) / name
            metadata = path.lstat()
            if (
                stat.S_ISDIR(metadata.st_mode)
                and getattr(metadata, "st_reparse_tag", 0) & 0x20000000
            ):
                junctions.append(relative / name)
                skipped.append(name)
        return skipped

    shutil.copytree(source, destination, symlinks=True, ignore=ignored)

    # Empty placeholders retain parent directories while a patch is reversed.
    for path in junctions:
        (destination / path).mkdir()
    return junctions


def restore_directory_junctions(source: Path, destination: Path, junctions: list[Path]) -> None:
    # Recreate links only after patch application can no longer write through them.
    destination = destination.resolve()
    for path in junctions:
        placeholder = require_remediation_target(str(destination / path))
        os.chmod(placeholder, stat.S_IMODE((source / path).lstat().st_mode))
        copy_directory_junction(source / path, placeholder)


def copy_git_worktree_files(
    source: Path, destination: Path, excluded: tuple[Path, ...]
) -> tuple[Path, list[Path]]:
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
    junctions: set[Path] = set()
    nested_worktrees: list[Path] = []
    linked_prefixes: dict[str, bool] = {}
    copied: set[Path] = set()
    for raw_path in sorted(path for path in listed.split(b"\0") if path):
        relative = Path(os.fsdecode(raw_path))
        if any(relative.is_relative_to(path) for path in excluded_relative):
            continue
        source_path = repository / relative
        try:
            source_path = _directory_link_boundary(repository, source_path, linked_prefixes)
            relative = source_path.relative_to(repository)
            metadata = source_path.lstat()
        except FileNotFoundError:
            continue
        if relative in copied:
            continue
        copied.add(relative)
        if stat.S_ISDIR(metadata.st_mode) and getattr(metadata, "st_reparse_tag", 0) & 0x20000000:
            junctions.add(relative)
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
            _, nested_junctions = copy_git_worktree_files(source_path, destination_path, excluded)
            junctions.update(relative / path for path in nested_junctions)
            nested_worktrees.append(relative)
            (destination_path / ".git").write_text(f"gitdir: {nested_git_dir}\n", encoding="utf-8")
        else:
            raise SystemExit(f"Unsupported Git working-tree file type: {relative}")
    if _WINDOWS:
        for path in git_directory_snapshot_paths(source) or []:
            relative = Path(pathspec) / path.relative_to(source)
            if any(
                relative.is_relative_to(root) for root in [*excluded_relative, *nested_worktrees]
            ):
                continue
            metadata = path.lstat()
            if (
                stat.S_ISDIR(metadata.st_mode)
                and getattr(metadata, "st_reparse_tag", 0) & 0x20000000
            ):
                junctions.add(relative)
    for path in junctions:
        (destination / path).mkdir(parents=True, exist_ok=True)
    copied_target = destination if pathspec == "." else destination / pathspec
    copied_target.mkdir(parents=True, exist_ok=True)
    return copied_target, sorted(junctions)


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
        subject = git_bytes(target, "show", "-s", "--no-show-signature", "--format=%s", "HEAD")
        metadata.update(
            {
                "commitSubject": (subject or b"").decode("utf-8", errors="replace").strip() or None,
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
    except (OSError, SystemExit) as error:
        return (
            f"Could not verify the scan target after scanning: {error}; "
            "results were saved for the original revision or snapshot."
        )
    return None


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
