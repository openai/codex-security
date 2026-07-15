#!/usr/bin/env python3
"""Concatenate the SECURITY.md files that apply to a scan path."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


class ResolutionError(ValueError):
    """Raised when a SECURITY.md chain cannot be resolved."""


def _inside(path: Path, root: Path, label: str) -> Path:
    try:
        return path.relative_to(root)
    except ValueError as exc:
        raise ResolutionError(f"{label} is outside the scan root: {path}") from exc


def resolve_security_md(repo: Path, scope: Path) -> str:
    """Return applicable SECURITY.md files, concatenated root to leaf."""
    try:
        root = repo.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ResolutionError(f"scan root does not exist: {repo}") from exc
    if not root.is_dir():
        raise ResolutionError(f"scan root is not a directory: {root}")

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
            content = policy.read_bytes().decode("utf-8")
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
        "--scope",
        required=True,
        type=Path,
        help="existing file or directory within the scan root",
    )
    parser.add_argument("--out", required=True, type=Path, help="output Markdown path, or -")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        guidance = resolve_security_md(args.repo, args.scope)
        if args.out == Path("-"):
            sys.stdout.write(guidance)
        else:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(guidance, encoding="utf-8")
    except (OSError, ResolutionError) as exc:
        print(f"resolve_security_md.py: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
