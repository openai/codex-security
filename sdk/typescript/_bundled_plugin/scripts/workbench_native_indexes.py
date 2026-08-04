"""Read-only native findings and repository indexes for the Security workbench."""

import argparse
import sqlite3
import sys
from collections import Counter
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import workbench_scan_history as scan_history
from workbench_constants import FINDING_SUMMARY_BYTES, FINDING_TITLE_BYTES, FINDINGS_PAGE_MAX
from workbench_validation import bounded_output_text


def list_global_findings(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    limit = min(args.limit, FINDINGS_PAGE_MAX)
    query = args.query.strip().casefold() if args.query else ""
    findings = (
        row
        for row in _indexed_findings(connection)
        if (args.target_id is None or row["target_id"] == args.target_id)
        and (args.severity is None or row["severity"] == args.severity)
        and (args.status is None or row["status"] == args.status)
        and (
            not query
            or any(
                query in value.casefold()
                for value in (
                    row["title"],
                    row["summary"],
                    row["target_path"],
                    row["location_path"],
                )
                if value is not None
            )
        )
    )
    rows = list(islice(findings, args.offset, args.offset + limit + 1))
    has_more = len(rows) > limit
    return {
        "findings": [
            {
                "createdAt": row["created_at"],
                "findingId": row["finding_id"],
                "locationPath": row["location_path"],
                "occurrenceCount": row["occurrence_count"],
                "occurrenceId": row["occurrence_id"],
                "scanId": row["scan_id"],
                "scope": row["scope"],
                "severity": {"level": row["severity"]},
                "status": row["status"],
                "summary": bounded_output_text(row["summary"], FINDING_SUMMARY_BYTES),
                "targetId": row["target_id"],
                "targetPath": row["target_path"],
                "title": bounded_output_text(row["title"], FINDING_TITLE_BYTES),
                "updatedAt": row["updated_at"],
            }
            for row in rows[:limit]
        ],
        "limit": limit,
        "nextOffset": args.offset + limit if has_more else None,
        "offset": args.offset,
    }


def _indexed_findings(connection: sqlite3.Connection) -> Iterator[sqlite3.Row]:
    yield from connection.execute(
        """
        WITH ranked_findings AS (
            SELECT
                occurrences.id AS occurrence_id,
                occurrences.finding_id,
                occurrences.severity,
                occurrences.created_at,
                scans.id AS scan_id,
                scans.target_id,
                targets.current_path AS target_path,
                scans.scope,
                MAX(scans.updated_at, COALESCE(triage.updated_at, '')) AS updated_at,
                COALESCE(triage.status, 'open') AS status,
                COUNT(*) OVER (
                    PARTITION BY scans.target_id, occurrences.finding_id
                ) AS occurrence_count,
                ROW_NUMBER() OVER (
                    PARTITION BY scans.target_id, occurrences.finding_id
                    ORDER BY occurrences.created_at DESC, occurrences.id DESC
                ) AS occurrence_rank
            FROM finding_occurrences AS occurrences
            JOIN scans ON scans.id = occurrences.scan_id
            JOIN security_targets AS targets ON targets.id = scans.target_id
            LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        )
        SELECT
            selected_findings.*,
            occurrences.title,
            occurrences.summary,
            (
                SELECT locations.relative_path
                FROM finding_locations AS locations
                WHERE locations.occurrence_id = selected_findings.occurrence_id
                ORDER BY
                    CASE WHEN locations.role = 'root_control' THEN 0 ELSE 1 END,
                    locations.sort_order
                LIMIT 1
            ) AS location_path
        FROM ranked_findings AS selected_findings
        JOIN finding_occurrences AS occurrences
            ON occurrences.id = selected_findings.occurrence_id
        WHERE selected_findings.occurrence_rank = 1
        ORDER BY
            CASE selected_findings.status WHEN 'open' THEN 0 ELSE 1 END,
            CASE selected_findings.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                WHEN 'informational' THEN 4
                ELSE 5
            END,
            selected_findings.created_at DESC,
            selected_findings.occurrence_id
        """,
    )


def list_repositories(
    connection: sqlite3.Connection,
    args: argparse.Namespace | None = None,
) -> dict[str, Any]:
    scans = scan_history.list_scans(connection)["scans"]
    scans_by_id = {scan["scanId"]: scan for scan in scans}
    scan_count_by_target: dict[str, int] = {}
    for scan in scans:
        target_id = scan["targetId"]
        scan_count_by_target[target_id] = scan_count_by_target.get(target_id, 0) + 1

    latest_scan_by_target: dict[str, dict[str, Any]] = {}
    for row in connection.execute(
        "SELECT id, target_id FROM scans ORDER BY started_at DESC, id DESC"
    ):
        latest_scan_by_target.setdefault(row["target_id"], scans_by_id[row["id"]])

    open_findings_by_target = Counter(
        row["target_id"] for row in _indexed_findings(connection) if row["status"] == "open"
    )
    targets = {row["id"]: row for row in connection.execute("SELECT * FROM security_targets")}
    repositories = [
        {
            "checkoutAvailable": Path(target["current_path"]).is_dir(),
            "displayName": target["display_name"],
            "latestScan": latest_scan,
            "openFindingsCount": open_findings_by_target.get(target_id, 0),
            "scanCount": scan_count_by_target[target_id],
            "targetId": target_id,
            "targetPath": target["current_path"],
        }
        for target_id, latest_scan in latest_scan_by_target.items()
        if (target := targets.get(target_id)) is not None
    ]
    if args is None:
        return {"repositories": repositories}

    query = args.query.strip().casefold() if args.query else ""
    repositories = [
        repository
        for repository in repositories
        if (args.target_id is None or repository["targetId"] == args.target_id)
        and args.status != "not_scanned"
        and (args.status != "open_findings" or repository["openFindingsCount"] > 0)
        and (
            not query
            or query in repository["displayName"].casefold()
            or query in repository["targetPath"].casefold()
        )
    ]
    if args.limit is None and args.offset == 0:
        return {"repositories": repositories}

    limit = min(args.limit or FINDINGS_PAGE_MAX, FINDINGS_PAGE_MAX)
    page = repositories[args.offset : args.offset + limit]
    next_offset = args.offset + len(page)
    return {
        "repositories": page,
        "limit": limit,
        "nextOffset": next_offset if next_offset < len(repositories) else None,
        "offset": args.offset,
    }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
