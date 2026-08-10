"""Read bounded finding source excerpts from sealed Git revisions."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path, PurePosixPath
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_target import clean_worktree_content_digest, git_bytes, git_output

CONTEXT_LINES = 3
MAX_BYTES = 16_000
MAX_FILE_BYTES = 1_048_576
MAX_LINES = 60


def finding_source_excerpt(
    scan: sqlite3.Row,
    target: Path | None,
    locations: list[dict[str, Any]],
) -> str | None:
    if target is None or not locations:
        return None
    location = next(
        (
            candidate
            for candidate in locations
            if "root_control" in str(candidate.get("role") or "").lower()
        ),
        locations[0],
    )
    path = location.get("path")
    start_line = location.get("startLine")
    end_line = location.get("endLine")
    if not isinstance(path, str) or not isinstance(start_line, int):
        return None
    source = scanned_source_text(scan, target, path)
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
    encoded = excerpt.encode("utf-8")[:MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def scanned_source_text(scan: sqlite3.Row, target: Path, path: str) -> str | None:
    if safe_source_path(target, path) is None:
        return None
    revision = scan["target_revision"]
    if revision == "unversioned":
        return None
    snapshot_digest = scan["target_snapshot_digest"]
    if snapshot_digest is not None and snapshot_digest != clean_worktree_content_digest():
        return None
    object_name = f"{revision}:{path}"
    size = git_output(target, "cat-file", "-s", object_name)
    if size is None or not size.isdigit() or int(size) > MAX_FILE_BYTES:
        return None
    content = git_bytes(target, "cat-file", "blob", object_name)
    return content.decode("utf-8", errors="replace") if content is not None else None


def safe_source_path(target: Path, relative_path: str) -> Path | None:
    if "\\" in relative_path:
        return None
    parsed = PurePosixPath(relative_path)
    if parsed.is_absolute() or ".." in parsed.parts:
        return None
    try:
        path = (target / parsed.as_posix()).resolve()
        path.relative_to(target)
    except (OSError, RuntimeError, ValueError):
        return None
    return path


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
