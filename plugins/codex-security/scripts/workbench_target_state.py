"""Persist stable Codex Security target identities."""

from __future__ import annotations

import argparse
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def stable_target_id(target: Path) -> str:
    digest = hashlib.sha256(f"local-workspace\0{target}".encode()).hexdigest()
    return f"target_sha256_{digest}"


def backfill_security_targets(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        """
        SELECT target_path FROM workspaces WHERE target_path IS NOT NULL
        UNION
        SELECT target_path FROM scans
        """
    ).fetchall()
    for row in rows:
        target_path = row["target_path"]
        target_id = ensure_security_target(connection, target_path)
        connection.execute(
            "UPDATE workspaces SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
            (target_id, target_path),
        )
        connection.execute(
            "UPDATE scans SET target_id = ? WHERE target_path = ? AND target_id IS NULL",
            (target_id, target_path),
        )


def ensure_security_target(connection: sqlite3.Connection, target_path: str) -> str:
    existing = connection.execute(
        "SELECT id FROM security_targets WHERE current_path = ?",
        (target_path,),
    ).fetchone()
    if existing is not None:
        return str(existing["id"])
    target_id = stable_target_id(Path(target_path))
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    connection.execute(
        """
        INSERT OR IGNORE INTO security_targets (
            id, current_path, display_name, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (target_id, target_path, Path(target_path).name, timestamp, timestamp),
    )
    return target_id


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
