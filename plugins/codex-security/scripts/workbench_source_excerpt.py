"""Read bounded finding source excerpts from sealed Git revisions."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_source_scopes import (
    load_source_scopes,
    normalized_path_component,
    offline_git_bytes,
    relative_path,
    safe_source_path,
    source_object_for_path,
)
from workbench_target import clean_worktree_content_digest

CONTEXT_LINES = 3
MAX_BYTES = 16_000
MAX_LINES = 60


def finding_source_excerpt(
    scan: sqlite3.Row,
    target: Path | None,
    locations: list[dict[str, Any]],
    scopes: list[str],
) -> str | None:
    if target is None or not locations or scan["target_revision"] == "unversioned":
        return None
    snapshot = scan["target_snapshot_digest"]
    if snapshot is not None and snapshot != clean_worktree_content_digest():
        return None
    locations = [
        location
        for location in locations
        if isinstance(path := location.get("path"), str)
        and isinstance(location.get("startLine"), int)
        and safe_source_path(target, path) is not None
    ]
    if not locations:
        return None
    try:
        context = load_source_scopes(scan, target, scopes)
    except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
        return None
    if context is None:
        return None
    repository, tree, records = context
    indexed: dict[tuple[str, ...], list[dict[str, str]]] = {}
    for record in records:
        for name in ("path", "canonicalPath"):
            parts = tuple(
                normalized_path_component(part) for part in PurePosixPath(record[name]).parts
            )
            indexed.setdefault(parts, []).append(record)
    lengths = sorted({len(parts) for parts in indexed})

    def source_object(path: str) -> str | None:
        parsed = relative_path(path)
        if parsed is None:
            return None
        parts = tuple(normalized_path_component(part) for part in parsed.parts)
        try:
            for length in lengths:
                if length > len(parts):
                    break
                for record in indexed.get(parts[:length], []):
                    object_id = source_object_for_path(repository, tree, target, path, record)
                    if object_id is not None:
                        return object_id
        except (OSError, RuntimeError, SystemExit, UnicodeError, ValueError):
            pass
        return None

    locations.sort(
        key=lambda location: (
            location.get("role") != "root_control",
            "root_control" not in str(location.get("role") or "").lower(),
        )
    )
    for location in locations:
        object_id = source_object(location["path"])
        if object_id is not None:
            break
    else:
        return None
    start_line, end_line = location["startLine"], location.get("endLine")
    source = scanned_source_text(repository, object_id)
    if not source or "\0" in source:
        return None
    lines = source.splitlines()
    if start_line < 1 or start_line > len(lines):
        return None
    last_affected_line = end_line if isinstance(end_line, int) else start_line
    excerpt_start = max(1, start_line - CONTEXT_LINES)
    excerpt_end = min(
        len(lines),
        max(start_line, last_affected_line) + CONTEXT_LINES,
        excerpt_start + MAX_LINES - 1,
    )
    width = len(str(excerpt_end))
    excerpt = "\n".join(
        f"{line_number:>{width}}  {lines[line_number - 1]}"
        for line_number in range(excerpt_start, excerpt_end + 1)
    )
    return excerpt.encode("utf-8")[:MAX_BYTES].decode("utf-8", errors="ignore")


def scanned_source_text(repository: Path, object_id: str) -> str | None:
    try:
        content = offline_git_bytes(repository, "cat-file", "blob", object_id)
    except (OSError, RuntimeError, SystemExit):
        return None
    return content.decode("utf-8", errors="replace") if content is not None else None


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
