#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


class MaterializationError(RuntimeError):
    pass


def run_git(
    repository: Path,
    *arguments: str,
    expected_returncodes: tuple[int, ...] = (0,),
) -> bytes:
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_LITERAL_PATHSPECS": "1"},
    )
    if result.returncode not in expected_returncodes:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise MaterializationError(message or f"git exited with {result.returncode}")
    return result.stdout


def git_diff_arguments() -> list[str]:
    return [
        "-c",
        "diff.algorithm=myers",
        "-c",
        "core.quotePath=true",
        "diff",
        "--binary",
        "--full-index",
        "--no-color",
        "--no-ext-diff",
        "--no-textconv",
        "--no-renames",
        "-O/dev/null",
        "--src-prefix=a/",
        "--dst-prefix=b/",
    ]


def status(repository: Path) -> bytes:
    return run_git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )


def repository_root(repository: Path) -> Path:
    return Path(os.fsdecode(run_git(repository, "rev-parse", "--show-toplevel").strip())).resolve()


def relative_paths(payload: bytes) -> list[bytes]:
    return [path for path in payload.split(b"\0") if path]


def decode_path(raw_path: bytes) -> str:
    try:
        return raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MaterializationError("path is not valid UTF-8; supply an immutable patch") from error


def ensure_output_is_outside_repository(output: Path, repository: Path) -> None:
    resolved_parent = output.parent.resolve(strict=True)
    resolved_output = resolved_parent / output.name
    if resolved_output == repository or repository in resolved_output.parents:
        raise MaterializationError(f"output must be outside the subject repository: {output}")
    if resolved_output.exists() and not resolved_output.is_file():
        raise MaterializationError(f"output must be a regular file path: {output}")


def stage_output(path: Path, payload: bytes) -> Path:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary.write(payload)
            temporary_path = Path(temporary.name)
        return temporary_path
    except BaseException:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()
        raise


def move_to_backup(path: Path) -> Path:
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        backup_path = Path(temporary.name)
    backup_path.unlink()
    path.replace(backup_path)
    return backup_path


def publish_outputs(outputs: list[tuple[Path, bytes]]) -> None:
    staged: dict[Path, Path] = {}
    backups: dict[Path, Path] = {}
    published: set[Path] = set()
    succeeded = False
    try:
        for path, payload in outputs:
            staged[path] = stage_output(path, payload)
        for path, _payload in outputs:
            if path.exists():
                backups[path] = move_to_backup(path)
        for path, _payload in outputs:
            staged[path].replace(path)
            published.add(path)
        succeeded = True
    except OSError as error:
        rollback_errors: list[str] = []
        for path, _payload in reversed(outputs):
            try:
                if path in published:
                    path.unlink(missing_ok=True)
                backup_path = backups.get(path)
                if backup_path is not None and backup_path.exists():
                    backup_path.replace(path)
            except OSError as rollback_error:
                rollback_errors.append(f"{path}: {rollback_error}")
        if rollback_errors:
            details = "; ".join(rollback_errors)
            raise MaterializationError(
                f"output publication failed and rollback was incomplete: {details}"
            ) from error
        raise
    finally:
        for temporary_path in staged.values():
            temporary_path.unlink(missing_ok=True)
        if succeeded:
            for backup_path in backups.values():
                backup_path.unlink(missing_ok=True)


def validate_index_state(repository: Path, status_payload: bytes) -> None:
    if run_git(repository, "ls-files", "--unmerged", "-z"):
        raise MaterializationError("unmerged index entries require a supplied immutable patch")
    for entry in relative_paths(run_git(repository, "ls-files", "-v", "-z")):
        marker = entry[:1]
        if marker == b"S" or marker.islower():
            path = decode_path(entry[2:])
            raise MaterializationError(
                f"skip-worktree or assume-unchanged entry requires a supplied immutable patch: {path}"
            )
    if any(entry.startswith(b" A ") for entry in relative_paths(status_payload)):
        raise MaterializationError("intent-to-add entries require a supplied immutable patch")


def tracked_paths(repository: Path, base_revision: str) -> list[bytes]:
    return relative_paths(
        run_git(
            repository,
            "-c",
            "core.quotePath=true",
            "-c",
            "diff.orderFile=",
            "diff",
            "--name-only",
            "-z",
            "--no-renames",
            "-O/dev/null",
            base_revision,
            "--",
        )
    )


def untracked_paths(repository: Path) -> list[bytes]:
    return sorted(
        relative_paths(run_git(repository, "ls-files", "--others", "--exclude-standard", "-z"))
    )


def index_modes(repository: Path, paths: list[bytes]) -> dict[bytes, bytes]:
    if not paths:
        return {}
    entries = relative_paths(
        run_git(
            repository,
            "ls-files",
            "--stage",
            "-z",
            "--",
            *(decode_path(path) for path in paths),
        )
    )
    modes: dict[bytes, bytes] = {}
    for entry in entries:
        metadata, raw_path = entry.split(b"\t", 1)
        mode, _object_name, stage = metadata.split(b" ", 2)
        if stage == b"0":
            modes[raw_path] = mode
    return modes


def base_modes(repository: Path, base_revision: str, paths: list[bytes]) -> dict[bytes, bytes]:
    if not paths:
        return {}
    entries = relative_paths(
        run_git(
            repository,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            base_revision,
            "--",
            *(decode_path(path) for path in paths),
        )
    )
    modes: dict[bytes, bytes] = {}
    for entry in entries:
        metadata, raw_path = entry.split(b"\t", 1)
        mode, _object_type, _object_name = metadata.split(b" ", 2)
        modes[raw_path] = mode
    return modes


def validate_changed_paths(
    repository: Path,
    base_revision: str,
    tracked: list[bytes],
    untracked: list[bytes],
) -> None:
    current_modes = index_modes(repository, tracked)
    previous_modes = base_modes(repository, base_revision, tracked)
    for raw_path in tracked:
        path = decode_path(raw_path)
        modes = {current_modes.get(raw_path), previous_modes.get(raw_path)}
        if b"160000" in modes:
            raise MaterializationError(
                f"submodule changes require a supplied immutable patch: {path}"
            )
        if b"120000" in modes:
            raise MaterializationError(
                f"symlink changes require a supplied immutable patch: {path}"
            )
    for raw_path in untracked:
        path = Path(decode_path(raw_path))
        absolute_path = repository / path
        if absolute_path.is_symlink() or not absolute_path.is_file():
            raise MaterializationError(
                f"untracked path requires a supplied immutable patch artifact: {path}"
            )


def fingerprint_paths(repository: Path, paths: list[bytes]) -> str:
    fingerprint = hashlib.sha256()
    for raw_path in sorted(set(paths)):
        path = repository / decode_path(raw_path)
        fingerprint.update(len(raw_path).to_bytes(8, "big"))
        fingerprint.update(raw_path)
        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            fingerprint.update(b"missing")
            continue
        if not stat.S_ISREG(path_stat.st_mode):
            raise MaterializationError(
                f"non-regular changed path requires a supplied immutable patch: {path}"
            )
        content_digest = hashlib.sha256()
        with path.open("rb") as file:
            before = os.fstat(file.fileno())
            while chunk := file.read(1024 * 1024):
                content_digest.update(chunk)
            after = os.fstat(file.fileno())
        before_identity = (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ino)
        after_identity = (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ino)
        if before_identity != after_identity:
            raise MaterializationError(f"changed path mutated while being read: {path}")
        fingerprint.update(stat.S_IMODE(path_stat.st_mode).to_bytes(4, "big"))
        fingerprint.update(content_digest.digest())
    return fingerprint.hexdigest()


def materialize(repository: Path, base: str) -> tuple[bytes, dict[str, object]]:
    base_revision = (
        run_git(
            repository,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{base}^{{commit}}",
        )
        .decode("ascii")
        .strip()
    )
    status_before = status(repository)
    validate_index_state(repository, status_before)

    diff_arguments = git_diff_arguments()
    tracked = tracked_paths(repository, base_revision)
    untracked = untracked_paths(repository)
    validate_changed_paths(repository, base_revision, tracked, untracked)
    fingerprint_before = fingerprint_paths(repository, tracked + untracked)

    tracked_patch = run_git(repository, *diff_arguments, base_revision, "--")
    patch_parts = [tracked_patch]
    for raw_path in untracked:
        patch_parts.append(
            run_git(
                repository,
                *diff_arguments,
                "--no-index",
                "--",
                "/dev/null",
                decode_path(raw_path),
                expected_returncodes=(0, 1),
            )
        )

    patch = b"".join(patch_parts)
    if not patch:
        raise MaterializationError("working tree has no materialized changes")
    status_after = status(repository)
    validate_index_state(repository, status_after)
    tracked_after = tracked_paths(repository, base_revision)
    untracked_after = untracked_paths(repository)
    fingerprint_after = fingerprint_paths(repository, tracked_after + untracked_after)
    if (
        status_after != status_before
        or tracked_after != tracked
        or untracked_after != untracked
        or fingerprint_after != fingerprint_before
    ):
        raise MaterializationError("working tree changed during patch materialization")

    changed_paths = sorted(set(tracked + untracked))
    subject = {
        "repository": os.fspath(repository),
        "baseRevision": base_revision,
        "patchDigest": f"sha256:{hashlib.sha256(patch).hexdigest()}",
        "changedFiles": [decode_path(path) for path in changed_paths],
        "materialization": {
            "method": "git_working_tree_v1",
            "commandArguments": [
                "--repository",
                os.fspath(repository),
                "--base",
                base,
            ],
            "artifactBytes": len(patch),
        },
    }
    return patch, subject


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Materialize a deterministic Git working-tree patch for risk assessment."
    )
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--patch-output", required=True, type=Path)
    parser.add_argument("--subject-output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    patch_output = arguments.patch_output.resolve(strict=False)
    subject_output = arguments.subject_output.resolve(strict=False)
    try:
        repository = repository_root(arguments.repository.resolve(strict=True))
        ensure_output_is_outside_repository(patch_output, repository)
        ensure_output_is_outside_repository(subject_output, repository)
        if patch_output == subject_output:
            raise MaterializationError("patch and subject outputs must be different paths")
        patch, subject = materialize(repository, arguments.base)
        publish_outputs(
            [
                (patch_output, patch),
                (
                    subject_output,
                    (json.dumps(subject, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                ),
            ]
        )
    except (MaterializationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(subject["patchDigest"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
