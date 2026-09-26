"""Shared scan-start helpers for the Codex Security workbench."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from filesystem_identity import serialize_filesystem_identity
from finalize_scan_contract import ContractError, _read_scan_local_json, write_scan_local_bytes
from workbench.storage import scan_completion_lock
from workbench_feedback import get_scan_feedback
from workbench_target import (
    directory_content_digest,
    git_revision,
    worktree_content_digest,
)
from workbench_validation import optional_text, user_text

COMPOSITION_CHECKPOINT = "artifacts/deep-scan/checkpoint.json"


def read_composition_checkpoint(scan: sqlite3.Row) -> dict[str, Any] | None:
    scan_dir = Path(scan["scan_dir"])
    try:
        (scan_dir / COMPOSITION_CHECKPOINT).lstat()
    except FileNotFoundError:
        return None
    with scan_completion_lock(scan["id"]):
        checkpoint = _read_scan_local_json(scan_dir, COMPOSITION_CHECKPOINT, "Deep Scan checkpoint")
    if checkpoint.get("version") != 2:
        raise ContractError("Unsupported Deep Scan checkpoint version.")
    return checkpoint


def composition_children(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[sqlite3.Row]:
    checkpoint = read_composition_checkpoint(scan)
    if checkpoint is None:
        return []
    directories = {str(Path(scan["scan_dir"]) / item["directory"]) for item in checkpoint["passes"]}
    return [
        child
        for child in connection.execute(
            "SELECT * FROM scans WHERE parent_scan_id = ? AND mode = 'standard' ORDER BY started_at, id",
            (scan["id"],),
        )
        if child["scan_dir"] in directories
    ]


def composition_child_ids(connection: sqlite3.Connection) -> set[str]:
    children = connection.execute(
        "SELECT children.id, children.scan_dir, parents.scan_dir AS parent_scan_dir "
        "FROM scans AS children JOIN scans AS parents ON parents.id = children.parent_scan_id "
        "WHERE parents.mode = 'deep' AND children.mode = 'standard'"
    )
    return {
        child["id"]
        for child in children
        if Path(child["scan_dir"]).parent
        == Path(child["parent_scan_dir"]) / "artifacts/deep-scan/passes"
    }


def create_scan_directory(directory: Path) -> None:
    """Create new output ancestors with the permissions required by the ordinary runner."""
    missing = []
    current = directory
    while not current.exists():
        missing.append(current)
        if current == current.parent:
            break
        current = current.parent
    for path in reversed(missing):
        path.mkdir(mode=0o700, exist_ok=True)


def safe_segment(value: str) -> str:
    segment = "".join(
        character if character.isalnum() or character in "._-" else "-" for character in value
    )
    return segment.strip("-") or "scan"


def compact_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def scan_target_identity(
    target: Path,
    diff_target: dict[str, str] | None,
    *,
    metadata: os.stat_result | None = None,
) -> tuple[str, str | None, int | str, int | str]:
    if metadata is None:
        metadata = target.stat()
    revision = diff_target["headRevision"] if diff_target else git_revision(target)
    snapshot_digest = None
    if diff_target is None:
        snapshot_digest = (
            directory_content_digest(target)
            if revision == "unversioned"
            else worktree_content_digest(target)
        )
    return (
        revision,
        snapshot_digest,
        serialize_filesystem_identity(metadata.st_dev),
        serialize_filesystem_identity(metadata.st_ino),
    )


def scan_diff_identity(
    diff_target: dict[str, str] | None,
) -> tuple[str | None, str | None, str | None, str | None]:
    if diff_target is None:
        return (None, None, None, None)
    return (
        diff_target["kind"],
        diff_target["baseRevision"],
        diff_target["headRevision"],
        diff_target.get("contentDigest"),
    )


def stored_diff_target(row: sqlite3.Row) -> dict[str, str] | None:
    if not row["diff_target_kind"]:
        return None
    target = {
        "baseRevision": row["diff_base_revision"],
        "headRevision": row["diff_head_revision"],
        "kind": row["diff_target_kind"],
    }
    if row["diff_content_digest"]:
        target["contentDigest"] = row["diff_content_digest"]
    return target


def archive_scan(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    scan_dir: Path,
    timestamp: str,
    canonical_directory: Callable[[Path], Path],
) -> None:
    archived_scan_dir = (
        canonical_directory(Path(args.archived_scan_dir).expanduser())
        if args.archived_scan_dir is not None
        else None
    )
    if archived_scan_dir is not None and (
        not args.archive_existing
        or archived_scan_dir.parent != scan_dir.parent
        or not archived_scan_dir.name.startswith(f"{scan_dir.name}.previous-")
    ):
        raise SystemExit("The archived scan must be a previous sibling of the scan directory.")

    previous_scan = connection.execute(
        "SELECT id, status FROM scans WHERE scan_dir = ?", (str(scan_dir),)
    ).fetchone()
    if previous_scan is None:
        return
    if not args.archive_existing:
        raise SystemExit(
            "The scan artifact directory belongs to an existing scan. "
            "Use --archive-existing to preserve that scan and start a new one."
        )
    if previous_scan["status"] == "running":
        raise SystemExit("Cannot archive the output of a running scan.")
    scans = connection.execute(
        """
        WITH RECURSIVE descendants AS (
            SELECT id, scan_dir FROM scans WHERE id = ?
            UNION
            SELECT scans.id, scans.scan_dir FROM scans
            JOIN descendants ON scans.parent_scan_id = descendants.id
        )
        SELECT id, scan_dir FROM descendants
        """,
        (previous_scan["id"],),
    ).fetchall()
    scans = [scan for scan in scans if Path(scan["scan_dir"]).is_relative_to(scan_dir)]
    artifacts = [
        artifact
        for scan in scans
        for artifact in connection.execute(
            "SELECT scan_id, kind, path FROM scan_artifacts WHERE scan_id = ?", (scan["id"],)
        )
    ]
    if archived_scan_dir is None:
        if artifacts:
            raise SystemExit(
                "The archived scan directory is required to preserve existing scan artifacts."
            )
        archived_scan_dir = Path(
            tempfile.mkdtemp(prefix=f"{scan_dir.name}.previous-", dir=scan_dir.parent)
        ).resolve()
    for scan in scans:
        relative_directory = Path(scan["scan_dir"]).relative_to(scan_dir)
        connection.execute(
            "UPDATE scans SET scan_dir = ?, updated_at = ? WHERE id = ?",
            (str(archived_scan_dir / relative_directory), timestamp, scan["id"]),
        )
    for artifact in artifacts:
        try:
            relative_path = Path(artifact["path"]).relative_to(scan_dir)
        except ValueError:
            continue
        connection.execute(
            "UPDATE scan_artifacts SET path = ? WHERE scan_id = ? AND kind = ?",
            (
                str(archived_scan_dir / relative_path),
                artifact["scan_id"],
                artifact["kind"],
            ),
        )


def insert_running_scan(
    connection: sqlite3.Connection,
    *,
    scan_id: str,
    workspace: sqlite3.Row,
    target: Path,
    scope: str,
    diff_target: dict[str, str] | None,
    target_identity: tuple[str, str | None, int | str, int | str],
    target_root: Path,
    target_summary: str | None,
    scope_file_count: int,
    timestamp: str,
    handoff_status: str = "pending",
    model: str | None = None,
    reasoning_effort: str | None = None,
    scan_dir: Path | None = None,
) -> str:
    revision = target_identity[0]
    native_scan = scan_dir is None
    user_context = user_text(workspace["user_context"])
    if scan_dir is None:
        scan_dir = Path(
            tempfile.mkdtemp(
                prefix=f"{safe_segment(revision)}_{compact_timestamp()}_",
                dir=target_root,
            )
        ).resolve()
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_id, target_path, target_revision, target_snapshot_digest,
            target_device, target_inode, scope, mode, user_context,
            deep_scan_owner_thread_id, diff_target_kind, diff_base_revision,
            diff_head_revision, diff_content_digest, target_summary, scan_dir, model,
            reasoning_effort, status, phase, handoff_status, started_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            'running', 'preflight', ?, ?, ?, ?)
        """,
        (
            scan_id,
            workspace["id"],
            workspace["target_id"],
            str(target),
            *target_identity,
            scope,
            workspace["default_mode"],
            user_context,
            workspace["thread_id"] if workspace["default_mode"] == "deep" else None,
            diff_target["kind"] if diff_target else None,
            diff_target["baseRevision"] if diff_target else None,
            diff_target["headRevision"] if diff_target else None,
            diff_target.get("contentDigest") if diff_target else None,
            target_summary,
            str(scan_dir),
            optional_text(model, maximum=200),
            optional_text(reasoning_effort, maximum=32),
            handoff_status,
            timestamp,
            timestamp,
            timestamp,
        ),
    )
    connection.execute(
        """
        INSERT INTO scan_progress (
            scan_id, scope_file_count, review_items_total, review_items_completed,
            reportable_findings_count, updated_at
        ) VALUES (?, ?, 0, 0, 0, ?)
        """,
        (scan_id, scope_file_count, timestamp),
    )
    connection.execute(
        "UPDATE workspaces SET active_scan_id = ?, updated_at = ? WHERE id = ?",
        (scan_id, timestamp, workspace["id"]),
    )
    if native_scan:
        scan = next(connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)))
        false_positives = get_scan_feedback(connection, scan)["falsePositives"]
        if false_positives:
            write_scan_local_bytes(
                scan_dir,
                "artifacts/01_context/false_positive_feedback.json",
                (json.dumps(false_positives, allow_nan=False) + "\n").encode(),
            )
    return scan_id


def main() -> None:
    argparse.ArgumentParser(description=__doc__).parse_args()


if __name__ == "__main__":
    main()
