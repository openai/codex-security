#!/usr/bin/env python3
"""Generate the shared, deterministically ordered security-scan file inventory."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


class InventoryError(ValueError):
    """Raised when the repository, scope, or inventory cannot be used safely."""


def windows_stream_component(path: Path) -> str | None:
    """Return the first NTFS alternate-data-stream component."""

    if os.name != "nt":
        return None
    return next(
        (
            component
            for component in path.parts
            if component != path.anchor and ":" in component
        ),
        None,
    )


def resolve_repository(value: str) -> Path:
    """Resolve the repository once so every scope is bound to its real root."""
    try:
        repository = Path(value).expanduser().resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--repo: cannot resolve repository: {value}") from error
    if not repository.is_dir():
        raise InventoryError(f"--repo: expected a directory: {repository}")
    return repository


def resolve_scope(repository: Path, value: str) -> str:
    """Preserve ripgrep's relative path spelling while rejecting escaped scopes."""
    if not value or "\0" in value:
        raise InventoryError("--scope: expected a non-empty file or directory")

    requested = Path(value).expanduser()
    stream = windows_stream_component(requested)
    if stream is not None:
        raise InventoryError(
            f"--scope: NTFS alternate data streams are not supported: {stream}"
        )
    scope = requested if requested.is_absolute() else repository / requested
    try:
        resolved = scope.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--scope: path does not exist: {value}") from error

    try:
        relative = resolved.relative_to(repository)
    except ValueError as error:
        raise InventoryError(f"--scope: path must remain inside --repo: {value}") from error

    if not resolved.is_dir() and not resolved.is_file():
        raise InventoryError(f"--scope: expected a file or directory: {value}")

    if requested.is_absolute():
        return relative.as_posix() if relative.parts else "."
    return value


def resolve_output(value: str) -> Path:
    """Reject direct symlink outputs without constraining the artifact root."""
    if not value or "\0" in value:
        raise InventoryError("--out: expected an inventory file path")
    requested = Path(value).expanduser()
    if requested.is_symlink():
        raise InventoryError("--out: refusing to replace a symbolic link")
    try:
        output = requested.resolve(strict=False)
    except (OSError, ValueError) as error:
        raise InventoryError(f"--out: cannot resolve inventory path: {value}") from error
    if output.exists() and not output.is_file():
        raise InventoryError(f"--out: expected a regular file path: {output}")
    return output


def generate_in_scope_files(repository: Path, scope: str, output: Path) -> int:
    """Atomically write the exact ripgrep inventory sorted as ``LC_ALL=C``."""
    command = [
        "rg",
        "--files",
        "--hidden",
        "--path-separator",
        "/",
        "--glob",
        "!.git/**",
        "--",
        scope,
    ]
    with tempfile.TemporaryFile(mode="w+b") as inventory:
        try:
            result = subprocess.run(
                command,
                cwd=repository,
                stdout=inventory,
                stderr=subprocess.PIPE,
                check=False,
            )
        except OSError as error:
            raise InventoryError(f"could not run ripgrep: {error}") from error

        if result.returncode not in (0, 1):
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            message = f"ripgrep exited with status {result.returncode}"
            if detail:
                message = f"{message}: {detail}"
            raise InventoryError(message)

        if (repository / ".git").exists():
            try:
                tracked = subprocess.run(
                    [
                        "git",
                        "ls-files",
                        "--cached",
                        "--ignored",
                        "--exclude-standard",
                        "-z",
                        "--",
                        scope,
                    ],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except OSError:
                tracked = None
            if tracked is not None and tracked.returncode == 0:
                prefix = b"./" if scope == "." or scope.startswith("./") else b""
                for path in tracked.stdout.split(b"\0"):
                    candidate = repository / os.fsdecode(path)
                    if path and candidate.is_file() and not candidate.is_symlink():
                        inventory.write(prefix + path + b"\n")

        inventory.seek(0)
        rows = sorted(inventory)

    return write_inventory(output, rows)


def committed_changed_paths(repository: Path, base: str, head: str) -> list[tuple[Path, str]]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "diff",
            "--raw",
            "-z",
            "--diff-filter=ACMRD",
            f"{base}..{head}",
        ],
        capture_output=True,
        check=True,
    )
    fields = result.stdout.split(b"\0")
    changed: list[tuple[Path, str]] = []
    index = 0
    while index < len(fields) - 1:
        metadata = fields[index].split()
        status = chr(metadata[-1][0])
        index += 1
        if status in {"C", "R"}:
            index += 1
        path = os.fsdecode(fields[index])
        index += 1
        selected_mode = metadata[0].removeprefix(b":") if status == "D" else metadata[1]
        if selected_mode != b"120000":
            changed.append((repository / path, status))
    return changed


def generate_diff_in_scope_files(
    repository: Path,
    base: str,
    head: str,
    mode: str,
    output: Path,
) -> int:
    """Reuse the existing diff selection without generating previews or duplicate worklists."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from generate_rank_input import git_changed_paths, path_is_excluded
    from rank_preview import (
        DEFAULT_PREVIEW_BYTES,
        TEXT_CODE_EXTENSIONS,
        is_binary_sample,
        preview_for,
    )
    from workbench_target import git_blob_bytes

    rows: list[bytes] = []
    try:
        changed = (
            committed_changed_paths(repository, base, head)
            if mode == "revisions"
            else git_changed_paths(repository, base, head, mode)
        )
        eligible = [
            (path, status)
            for path, status in changed
            if not path_is_excluded(path.relative_to(repository))
            and path.suffix.lower() in TEXT_CODE_EXTENSIONS
        ]
        revision_paths = [
            path.relative_to(repository)
            for path, status in eligible
            if mode == "revisions" and status != "D"
        ]
        revision_blobs = dict(
            zip(
                revision_paths,
                git_blob_bytes(
                    repository,
                    [f"{head}:{path.as_posix()}" for path in revision_paths],
                ),
            )
        )

        for path, status in eligible:
            relative = path.relative_to(repository)
            if status != "D":
                if mode == "revisions":
                    contents = revision_blobs[relative]
                    if contents is None:
                        raise InventoryError(
                            f"could not read committed diff blob: {head}:{relative.as_posix()}"
                        )
                    if is_binary_sample(contents):
                        continue
                elif (
                    path.is_symlink()
                    or not path.is_file()
                    or preview_for(path, DEFAULT_PREVIEW_BYTES)[1]
                ):
                    continue
            relative_path = relative.as_posix()
            if "\n" in relative_path or "\r" in relative_path:
                raise InventoryError(
                    "Git changes contain a path that cannot fit in the file inventory"
                )
            rows.append(f"{relative_path}\n".encode())
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None)
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        message = detail.strip() if isinstance(detail, str) and detail.strip() else str(error)
        raise InventoryError(f"could not resolve the selected Git changes: {message}") from error

    return write_inventory(output, sorted(set(rows)))


def write_inventory(output: Path, rows: list[bytes]) -> int:
    """Replace a complete inventory atomically, keeping failures from corrupting the old one."""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.writelines(rows)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="Repository root.")
    parser.add_argument("--scope", required=True, help="File or directory within the repository.")
    parser.add_argument("--out", required=True, help="Destination for the file inventory.")
    parser.add_argument("--diff-base", help="Authoritative Git base for a changed-file inventory.")
    parser.add_argument("--diff-head", default="HEAD", help="Authoritative Git head revision.")
    parser.add_argument(
        "--diff-mode",
        choices=("revisions", "local-patch"),
        default="revisions",
        help="Use committed revisions or the current staged and unstaged patch.",
    )
    args = parser.parse_args()

    try:
        repository = resolve_repository(args.repo)
        scope = resolve_scope(repository, args.scope)
        output = resolve_output(args.out)
        if args.diff_base is None:
            count = generate_in_scope_files(repository, scope, output)
        elif scope not in (".", "./"):
            raise InventoryError("--scope: diff scans must use the repository root")
        else:
            count = generate_diff_in_scope_files(
                repository,
                args.diff_base,
                args.diff_head,
                args.diff_mode,
                output,
            )
    except (OSError, ValueError) as error:
        print(f"generate_in_scope_files: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(f"Recorded {count} in-scope files.")


if __name__ == "__main__":
    main()
