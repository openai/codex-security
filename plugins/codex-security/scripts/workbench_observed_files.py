"""Persist repository files identified in saved tool output, separately from review coverage."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path, PureWindowsPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_source_scopes import relative_path


def observed_files_summary(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT observed_files_read_at,
               (SELECT COUNT(*) FROM scan_observed_files WHERE scan_id = scans.id) AS file_count
        FROM scans WHERE id = ?
        """,
        (scan_id,),
    ).fetchone()
    return {
        "count": row["file_count"] if row["observed_files_read_at"] is not None else None,
        "observedAt": row["observed_files_read_at"],
    }


def record_observed_files(
    connection: sqlite3.Connection, scan_id: str, payload: object, timestamp: str
) -> dict[str, Any]:
    if not isinstance(payload, dict) or not isinstance(payload.get("files"), list):
        raise SystemExit("Observed files must contain a files array.")
    records = []
    for entry in payload["files"]:
        if not isinstance(entry, dict):
            raise SystemExit("Each observed file must include path, threadId, and callId.")
        path, thread_id, call_id = (entry.get(key) for key in ("path", "threadId", "callId"))
        if not all(isinstance(value, str) and value for value in (path, thread_id, call_id)):
            raise SystemExit("Each observed file must include path, threadId, and callId.")
        parsed = relative_path(path)
        if (
            parsed is None
            or not parsed.parts
            or parsed.as_posix() != path
            or PureWindowsPath(path).drive
            or "\0" in path
        ):
            raise SystemExit("Observed file paths must be normalized repository-relative paths.")
        records.append((scan_id, path, thread_id, call_id))
    with connection:
        connection.executemany(
            """
            INSERT INTO scan_observed_files (scan_id, path, thread_id, call_id)
            VALUES (?, ?, ?, ?) ON CONFLICT (scan_id, path) DO NOTHING
            """,
            records,
        )
        connection.execute(
            "UPDATE scans SET observed_files_read_at = ? WHERE id = ?", (timestamp, scan_id)
        )
        return observed_files_summary(connection, scan_id)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
