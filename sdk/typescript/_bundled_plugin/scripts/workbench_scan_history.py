"""Scan history projection for the native Codex Security workbench."""

import argparse
import sqlite3
from typing import Any, Callable


def list_workspace_scans(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    require_workspace: Callable[[sqlite3.Connection, str], sqlite3.Row],
) -> dict[str, Any]:
    workspace = require_workspace(connection, args.workspace_id)
    total = connection.execute(
        "SELECT COUNT(*) FROM scans WHERE workspace_id = ?", (workspace["id"],)
    ).fetchone()[0]
    rows = connection.execute(
        """
        SELECT id, mode, status, phase, scope, target_revision,
            seal_manifest_digest, started_at, completed_at, canceled_at,
            updated_at, failure_message
        FROM scans
        WHERE workspace_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (workspace["id"], args.limit, args.offset),
    ).fetchall()
    next_offset = args.offset + len(rows)
    return {
        "limit": args.limit,
        "nextOffset": next_offset if next_offset < total else None,
        "offset": args.offset,
        "scans": [
            {
                "canceledAt": row["canceled_at"],
                "completedAt": row["completed_at"],
                "failureMessage": row["failure_message"],
                "mode": row["mode"],
                "phase": row["phase"],
                "scanId": row["id"],
                "scope": row["scope"],
                "sealed": row["seal_manifest_digest"] is not None,
                "startedAt": row["started_at"],
                "status": "canceled" if row["canceled_at"] else row["status"],
                "targetRevision": row["target_revision"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ],
        "total": total,
        "workspaceId": workspace["id"],
    }


def list_scans(connection: sqlite3.Connection) -> dict[str, Any]:
    rows = connection.execute(
        """
        SELECT
            scans.*,
            progress.reportable_findings_count,
            progress.scope_file_count,
            progress.review_items_completed,
            progress.review_items_total,
            progress.updated_at AS progress_updated_at,
            (
                SELECT COUNT(*)
                FROM finding_occurrences AS occurrences
                WHERE occurrences.scan_id = scans.id
            ) AS finding_count
        FROM scans
        JOIN scan_progress AS progress ON progress.scan_id = scans.id
        ORDER BY
            CASE WHEN scans.status = 'running' AND scans.canceled_at IS NULL THEN 0 ELSE 1 END,
            MAX(scans.updated_at, progress.updated_at) DESC,
            scans.started_at DESC,
            scans.id
        """
    ).fetchall()
    return {
        "scans": [
            {
                "continuationThreadId": row["continuation_thread_id"],
                "findingCount": row["finding_count"],
                "handoffStatus": row["handoff_status"],
                "mode": row["mode"],
                "progress": {
                    "candidates": {"reportable": row["reportable_findings_count"]},
                    "coverage": {
                        "closedRows": row["review_items_completed"],
                        "filesTotal": row["scope_file_count"],
                        "worklistRows": row["review_items_total"],
                    },
                    "phase": row["phase"],
                    "status": "canceled" if row["canceled_at"] else row["status"],
                    "updatedAt": row["progress_updated_at"],
                },
                "scanId": row["id"],
                "scope": row["scope"],
                "targetId": row["target_id"],
                "targetPath": row["target_path"],
                "targetSummary": row["target_summary"],
                "updatedAt": max(row["updated_at"], row["progress_updated_at"]),
            }
            for row in rows
        ]
    }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
