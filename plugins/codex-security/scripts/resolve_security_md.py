#!/usr/bin/env python3
"""Concatenate the SECURITY.md files that apply to a scan path."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

MAX_SECURITY_MD_BYTES = 1024 * 1024


class ResolutionError(ValueError):
    """Raised when a SECURITY.md chain cannot be resolved."""


def _inside(path: Path, root: Path, label: str) -> Path:
    try:
        return path.relative_to(root)
    except ValueError as exc:
        raise ResolutionError(f"{label} is outside the scan root: {path}") from exc


def _resolve_root(repo: Path) -> Path:
    try:
        root = repo.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ResolutionError(f"scan root does not exist: {repo}") from exc
    if not root.is_dir():
        raise ResolutionError(f"scan root is not a directory: {root}")
    return root


def list_security_md(repo: Path) -> list[str]:
    """Return a stable, safely framed inventory without traversing Git metadata."""
    root = _resolve_root(repo)

    def raise_walk_error(error: OSError) -> None:
        raise error

    policies: list[str] = []
    for directory, subdirectories, filenames in os.walk(
        root, onerror=raise_walk_error, followlinks=False
    ):
        safe_subdirectories: list[str] = []
        for name in sorted(subdirectories):
            if name == ".git":
                continue
            directory_stat = (Path(directory) / name).stat(follow_symlinks=False)
            if not stat.S_ISDIR(directory_stat.st_mode):
                continue
            reparse_point = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            if getattr(directory_stat, "st_file_attributes", 0) & reparse_point:
                continue
            safe_subdirectories.append(name)
        subdirectories[:] = safe_subdirectories
        if "SECURITY.md" not in filenames:
            continue
        policy = Path(directory) / "SECURITY.md"
        if policy.is_file() or policy.is_symlink():
            policies.append(policy.relative_to(root).as_posix())
    return sorted(policies)


def resolve_security_md(repo: Path, scope: Path) -> str:
    """Return applicable SECURITY.md files, concatenated root to leaf."""
    root = _resolve_root(repo)

    requested_scope = scope.expanduser()
    if not requested_scope.is_absolute():
        requested_scope = root / requested_scope
    try:
        resolved_scope = requested_scope.resolve(strict=True)
    except OSError as exc:
        raise ResolutionError(f"scan scope does not exist: {requested_scope}") from exc
    _inside(resolved_scope, root, "scan scope")

    target_directory = resolved_scope if resolved_scope.is_dir() else resolved_scope.parent
    relative_directory = _inside(target_directory, root, "scan scope")
    directories = [root]
    current = root
    for part in relative_directory.parts:
        current /= part
        directories.append(current)

    sections: list[str] = []
    for directory in directories:
        policy = directory / "SECURITY.md"
        if not policy.is_file():
            continue
        resolved_policy = policy.resolve(strict=True)
        _inside(resolved_policy, root, "SECURITY.md")
        try:
            with resolved_policy.open("rb") as policy_file:
                policy_bytes = policy_file.read(MAX_SECURITY_MD_BYTES + 1)
            if len(policy_bytes) > MAX_SECURITY_MD_BYTES:
                raise ResolutionError(f"SECURITY.md exceeds 1 MiB: {policy}")
            content = policy_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ResolutionError(f"SECURITY.md is not valid UTF-8: {policy}") from exc
        if not content.strip():
            continue

        source = policy.relative_to(root).as_posix()
        section = f"## SECURITY.md source: {json.dumps(source)}\n\n{content}"
        if not section.endswith("\n"):
            section += "\n"
        sections.append(section)

    return "\n".join(sections)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path, help="scan root directory")
    parser.add_argument(
        "--list",
        action="store_true",
        help="write a JSON inventory of repository policy paths",
    )
    parser.add_argument(
        "--scope",
        type=Path,
        help="existing file or directory within the scan root",
    )
    parser.add_argument("--out", default=Path("-"), type=Path, help="output path, or - for stdout")
    args = parser.parse_args()
    if args.list and args.scope is not None:
        parser.error("--list cannot be combined with --scope")
    if not args.list and args.scope is None:
        parser.error("--scope is required unless --list is specified")
    return args


def main() -> int:
    args = parse_args()
    try:
        guidance = (
            json.dumps(list_security_md(args.repo), ensure_ascii=True) + "\n"
            if args.list
            else resolve_security_md(args.repo, args.scope)
        )
        if args.out == Path("-"):
            sys.stdout.buffer.write(guidance.encode("utf-8"))
        else:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(guidance, encoding="utf-8")
    except (OSError, ResolutionError) as exc:
        print(f"resolve_security_md.py: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
