"""Scan history projection for the native Codex Security workbench."""

import argparse
import fnmatch
import os
import sqlite3
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from workbench_constants import FINDINGS_PAGE_MAX


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


def list_scans(
    connection: sqlite3.Connection, args: argparse.Namespace | None = None
) -> dict[str, Any]:
    clauses: list[str] = []
    values: list[Any] = []
    if args is not None and args.repository:
        repository = str(Path(args.repository).expanduser().resolve())
        clauses.append(
            "(scans.target_path = ? OR scans.target_id IN "
            "(SELECT id FROM security_targets WHERE current_path = ?))"
        )
        values.extend((repository, repository))
    if args is not None and args.scan_root:
        scan_root = str(Path(args.scan_root).expanduser().resolve())
        prefix = scan_root.rstrip(os.sep) + os.sep
        clauses.append("(scans.scan_dir = ? OR substr(scans.scan_dir, 1, ?) = ?)")
        values.extend((scan_root, len(prefix), prefix))
    if args is not None and args.target_id:
        clauses.append("scans.target_id = ?")
        values.append(args.target_id)
    if args is not None and args.mode:
        clauses.append("scans.mode = ?")
        values.append(args.mode)
    if args is not None and args.status:
        if args.status == "canceled":
            clauses.append("scans.canceled_at IS NOT NULL")
        else:
            clauses.append("scans.status = ? AND scans.canceled_at IS NULL")
            values.append(args.status)
    if args is not None and args.query:
        query = args.query.strip().casefold()
        if query:
            clauses.append(
                "(instr(lower(scans.target_path), ?) > 0 "
                "OR instr(lower(COALESCE(scans.target_summary, '')), ?) > 0 "
                "OR instr(lower(scans.scope), ?) > 0 "
                "OR instr(lower(scans.mode), ?) > 0)"
            )
            values.extend((query, query, query, query))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    paginated = args is not None and (args.limit is not None or args.offset != 0)
    limit = min(args.limit or FINDINGS_PAGE_MAX, FINDINGS_PAGE_MAX) if paginated else None
    pagination = "LIMIT ? OFFSET ?" if paginated else ""
    if limit is not None:
        values.extend((limit + 1, args.offset))
    rows = connection.execute(
        f"""
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
        {where}
        ORDER BY
            CASE WHEN scans.status = 'running' AND scans.canceled_at IS NULL THEN 0 ELSE 1 END,
            MAX(scans.updated_at, progress.updated_at) DESC,
            scans.started_at DESC,
            scans.id
        {pagination}
        """,
        values,
    ).fetchall()
    result = {
        "scans": [
            {
                "completedAt": row["completed_at"],
                "continuationThreadId": row["continuation_thread_id"],
                "findingCount": row["finding_count"],
                "handoffStatus": row["handoff_status"],
                "mode": row["mode"],
                "parentScanId": row["parent_scan_id"],
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
                "recipeAvailable": row["recipe_json"] is not None,
                "scanDir": row["scan_dir"],
                "scanId": row["id"],
                "scope": row["scope"],
                "startedAt": row["started_at"],
                "targetId": row["target_id"],
                "targetPath": row["target_path"],
                "targetRevision": row["target_revision"],
                "targetSummary": row["target_summary"],
                "updatedAt": max(row["updated_at"], row["progress_updated_at"]),
            }
            for row in rows[:limit]
        ]
    }
    if limit is not None:
        result.update(
            {
                "limit": limit,
                "nextOffset": args.offset + limit if len(rows) > limit else None,
                "offset": args.offset,
            }
        )
    return result


def compare_scans(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
) -> dict[str, Any]:
    before = require_scan(connection, args.before_scan_id)
    after = require_scan(connection, args.after_scan_id)
    if before["status"] != "complete" or after["status"] != "complete":
        raise SystemExit("Only completed scans can be compared.")
    after_coverage = read_coverage(after)
    comparable = (
        before["target_id"] == after["target_id"]
        and after_coverage.get("completeness") == "complete"
    )
    before_findings = _scan_findings(connection, before["id"])
    after_findings = _scan_findings(connection, after["id"])
    findings: list[dict[str, Any]] = []
    summary = {status: 0 for status in ("new", "persisting", "resolved", "reopened", "unknown")}

    for finding_id in sorted(before_findings.keys() | after_findings.keys()):
        previous = before_findings.get(finding_id)
        current = after_findings.get(finding_id)
        selected = current if current is not None else previous
        if selected is None:
            continue
        item = {
            "findingId": finding_id,
            "path": selected["relative_path"],
            "severity": selected["severity"],
            "title": selected["title"],
        }
        if previous is None:
            status = "new"
        elif current is not None:
            status = (
                "reopened"
                if previous["triage_status"] == "closed"
                and previous["close_reason"] == "already_fixed"
                and current["triage_status"] == "open"
                else "persisting"
            )
        elif not comparable:
            status = "unknown"
            item["reason"] = "The later scan has a different target or incomplete coverage."
        elif not scan_covers_path(
            after,
            target_id=before["target_id"],
            path=previous["relative_path"],
            coverage=after_coverage,
        ):
            status = "unknown"
            item["reason"] = "The affected path was excluded or outside the later scope."
        else:
            status = "resolved"
        if previous is not None:
            item["beforeOccurrenceId"] = previous["id"]
        if current is not None:
            item["afterOccurrenceId"] = current["id"]
            item["triage"] = {
                "closeReason": current["close_reason"],
                "status": current["triage_status"],
            }
        item["status"] = status
        findings.append(item)
        summary[status] += 1

    return {
        "afterScanId": after["id"],
        "beforeScanId": before["id"],
        "comparable": comparable,
        "coverage": {"afterCompleteness": after_coverage.get("completeness")},
        "findings": findings,
        "summary": summary,
    }


def _scan_findings(connection: sqlite3.Connection, scan_id: str) -> dict[str, sqlite3.Row]:
    rows = connection.execute(
        """
        SELECT occurrences.id, occurrences.finding_id, occurrences.title, occurrences.severity,
            COALESCE(triage.status, 'open') AS triage_status, triage.close_reason,
            (
                SELECT locations.relative_path
                FROM finding_locations AS locations
                WHERE locations.occurrence_id = occurrences.id
                ORDER BY CASE WHEN locations.role = 'root_control' THEN 0 ELSE 1 END,
                    locations.sort_order
                LIMIT 1
            ) AS relative_path
        FROM finding_occurrences AS occurrences
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        WHERE occurrences.scan_id = ?
        """,
        (scan_id,),
    )
    return {row["finding_id"]: row for row in rows}


def scan_covers_path(
    scan: sqlite3.Row,
    *,
    target_id: str,
    path: str | None,
    coverage: dict[str, Any],
) -> bool:
    if (
        scan["status"] != "complete"
        or scan["target_id"] != target_id
        or coverage.get("completeness") != "complete"
    ):
        return False
    if not isinstance(path, str) or not path:
        return False
    included = coverage.get("includePaths")
    if not isinstance(included, list) or not any(
        isinstance(scope, str) and _path_within(path, scope) for scope in included
    ):
        return False
    excluded = coverage.get("excludePaths")
    if not isinstance(excluded, list):
        return False
    if any(isinstance(scope, str) and _path_matches(path, scope) for scope in excluded):
        return False
    exclusions = coverage.get("explicitExclusions")
    if not isinstance(exclusions, list):
        return False
    if any(
        isinstance(exclusion, dict)
        and isinstance(exclusion.get("pattern"), str)
        and _path_matches(path, exclusion["pattern"])
        for exclusion in exclusions
    ):
        return False
    return True


def _path_within(path: str, scope: str) -> bool:
    candidate = PurePosixPath(path)
    parent = PurePosixPath(scope)
    return parent == PurePosixPath(".") or candidate == parent or parent in candidate.parents


def _path_matches(path: str, pattern: str) -> bool:
    return _path_within(path, pattern) or fnmatch.fnmatchcase(path, pattern)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
