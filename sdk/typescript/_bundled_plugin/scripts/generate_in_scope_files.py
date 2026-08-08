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
    """Atomically inventory visible files and ignored files tracked by Git."""
    command = [
        "rg",
        "--no-config",
        "--files",
        "--hidden",
        "--no-require-git",
        "--no-ignore-parent",
        "--no-ignore-global",
        "--glob",
        "!.git/**",
    ]
    for name in (".gitignore", ".ignore", ".rgignore"):
        ignore = repository / name
        if ignore.is_file() and not ignore.is_symlink():
            command.extend(["--ignore-file", str(ignore)])
    command.extend(["--", scope])
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

        inventory.seek(0)
        rows = set(inventory)

    environment = os.environ.copy()
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment["GIT_LITERAL_PATHSPECS"] = "1"
    environment["LC_ALL"] = "C"
    git = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.excludesFile={os.devnull}",
        "--literal-pathspecs",
    ]
    try:
        worktree = subprocess.run(
            [*git, "rev-parse", "--is-inside-work-tree"],
            cwd=repository,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
    except OSError as error:
        if (repository / ".git").exists():
            raise InventoryError(f"could not inspect Git worktree: {error}") from error
        worktree = None

    if worktree is not None and worktree.returncode:
        detail = worktree.stderr.decode("utf-8", errors="replace").strip()
        if worktree.returncode == 128 and "not a git repository" in detail.lower():
            worktree = None
        else:
            message = f"git rev-parse exited with status {worktree.returncode}"
            if detail:
                message = f"{message}: {detail}"
            raise InventoryError(message)

    if worktree is not None and worktree.stdout.strip() == b"true":
        prefix = b"./" if scope == "." or scope.startswith("./") else b""
        listed: list[bytes] = []
        for arguments in (["--cached"], ["--others", "--exclude-standard"]):
            try:
                result = subprocess.run(
                    [*git, "ls-files", *arguments, "-z", "--", scope],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=environment,
                    check=False,
                )
            except OSError as error:
                raise InventoryError(f"could not list repository files: {error}") from error
            if result.returncode:
                detail = result.stderr.decode("utf-8", errors="replace").strip()
                message = f"git ls-files exited with status {result.returncode}"
                if detail:
                    message = f"{message}: {detail}"
                raise InventoryError(message)
            listed.append(result.stdout)

        def normalized(path: bytes) -> bytes:
            return path.replace(b"\\", b"/") if os.name == "nt" else path

        allowed = {
            normalized(prefix + relative)
            for collection in listed
            for relative in collection.split(b"\0")
            if relative
        }
        nested_worktrees = tuple(path for path in allowed if path.endswith(b"/"))
        explicitly_ignored = False
        if scope not in (".", "./"):
            ignored_environment = environment.copy()
            ignored_environment.pop("GIT_LITERAL_PATHSPECS", None)
            explicit_path = scope if scope.startswith("./") else f"./{scope}"
            try:
                ignored = subprocess.run(
                    [*git[:-1], "check-ignore", "--quiet", "--no-index", "--", explicit_path],
                    cwd=repository,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=ignored_environment,
                    check=False,
                )
            except OSError as error:
                raise InventoryError(f"could not inspect scoped Git ignores: {error}") from error
            if ignored.returncode not in (0, 1):
                detail = ignored.stderr.decode("utf-8", errors="replace").strip()
                message = f"git check-ignore exited with status {ignored.returncode}"
                if detail:
                    message = f"{message}: {detail}"
                raise InventoryError(message)
            explicitly_ignored = ignored.returncode == 0

        if not explicitly_ignored:
            rows = {
                row
                for row in rows
                if (path := normalized(row.rstrip(b"\r\n"))) in allowed
                or any(path.startswith(worktree) for worktree in nested_worktrees)
            }
        recorded = {normalized(row.rstrip(b"\r\n")) for row in rows}

        for relative in listed[0].split(b"\0"):
            if not relative:
                continue
            candidate = repository / os.fsdecode(relative)
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                candidate.resolve(strict=True).relative_to(repository)
            except (OSError, ValueError):
                continue
            relative_path = prefix + relative
            key = normalized(relative_path)
            if key not in recorded:
                rows.add(relative_path + b"\n")
                recorded.add(key)

    rows = sorted(rows)

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
    args = parser.parse_args()

    try:
        repository = resolve_repository(args.repo)
        scope = resolve_scope(repository, args.scope)
        output = resolve_output(args.out)
        count = generate_in_scope_files(repository, scope, output)
    except (OSError, ValueError) as error:
        print(f"generate_in_scope_files: {error}", file=sys.stderr)
        raise SystemExit(2) from error

    print(f"Recorded {count} in-scope files.")


if __name__ == "__main__":
    main()
