"""Read-only native findings and repository indexes for the Security workbench."""

import argparse
import os
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
from workbench_validation import bounded_output_text, timestamp_key


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
                "confirmedInLatestScan": row["confirmed_in_latest_scan"],
                "createdAt": row["created_at"],
                "findingId": row["finding_id"],
                "knownSince": row["known_since"],
                "knownScanIds": row["known_scan_ids"],
                "locationPath": row["location_path"],
                "matchedFindingIds": row["matched_finding_ids"],
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


def _indexed_findings(connection: sqlite3.Connection) -> Iterator[dict[str, Any]]:
    parents: dict[tuple[str, str], tuple[str, str]] = {}

    def group(identity: tuple[str, str]) -> tuple[str, str]:
        while identity in parents:
            identity = parents[identity]
        return identity

    for match in connection.execute(
        """
        SELECT before_scans.target_id, before.finding_id AS before_finding_id,
            after.finding_id AS after_finding_id
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
        JOIN scans AS before_scans ON before_scans.id = before.scan_id
        JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
        JOIN scans AS after_scans ON after_scans.id = after.scan_id
        WHERE before_scans.target_id = after_scans.target_id
        """
    ):
        before = group((match["target_id"], match["before_finding_id"]))
        after = group((match["target_id"], match["after_finding_id"]))
        if before != after:
            parents[after] = before

    latest_scan_by_target = dict(
        connection.execute(
            "SELECT target_id, id FROM scans WHERE status = 'complete' ORDER BY julianday(upper(started_at)), id"
        )
    )

    grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
    for row in connection.execute(
        """
        SELECT
            occurrences.id AS occurrence_id,
            occurrences.finding_id,
            occurrences.severity,
            occurrences.created_at,
            scans.id AS scan_id,
            scans.started_at AS scan_started_at,
            scans.target_id,
            targets.current_path AS target_path,
            scans.scope,
            scans.updated_at,
            triage.status AS decision_status,
            triage.close_reason,
            triage.updated_at AS decision_updated_at,
            occurrences.title,
            occurrences.summary,
            (
                SELECT locations.relative_path
                FROM finding_locations AS locations
                WHERE locations.occurrence_id = occurrences.id
                ORDER BY
                    CASE WHEN locations.role = 'root_control' THEN 0 ELSE 1 END,
                    locations.sort_order
                LIMIT 1
            ) AS location_path
        FROM finding_occurrences AS occurrences
        JOIN scans ON scans.id = occurrences.scan_id
        JOIN security_targets AS targets ON targets.id = scans.target_id
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        """,
    ):
        grouped.setdefault(group((row["target_id"], row["finding_id"])), []).append(row)

    findings = []
    for occurrences in grouped.values():
        latest = max(
            occurrences,
            key=lambda row: (timestamp_key(row["created_at"]), row["occurrence_id"]),
        )
        decision = max(
            (row for row in occurrences if row["decision_status"] is not None),
            key=lambda row: (timestamp_key(row["decision_updated_at"]), row["occurrence_id"]),
            default=None,
        )
        status = decision["decision_status"] if decision is not None else "open"
        if (
            status == "closed"
            and decision["close_reason"] == "already_fixed"
            and timestamp_key(latest["created_at"]) > timestamp_key(decision["decision_updated_at"])
        ):
            status = "open"
        scans = sorted(
            {(row["scan_started_at"], row["scan_id"]) for row in occurrences},
            key=lambda scan: (timestamp_key(scan[0]), scan[1]),
        )
        findings.append(
            {
                **dict(latest),
                "confirmed_in_latest_scan": any(
                    row["scan_id"] == latest_scan_by_target.get(row["target_id"])
                    for row in occurrences
                ),
                "known_since": scans[0][0],
                "known_scan_ids": [scan_id for _, scan_id in scans],
                "matched_finding_ids": sorted({row["finding_id"] for row in occurrences}),
                "occurrence_count": len(occurrences),
                "status": status,
                "updated_at": (
                    max(
                        latest["updated_at"],
                        decision["decision_updated_at"],
                        key=lambda value: (timestamp_key(value), value),
                    )
                    if decision is not None
                    else latest["updated_at"]
                ),
            }
        )

    findings.sort(key=lambda finding: finding["occurrence_id"])
    findings.sort(
        key=lambda finding: (
            finding["status"] == "open",
            -scan_history.SEVERITY_ORDER.get(finding["severity"], 5),
            timestamp_key(finding["created_at"]),
        ),
        reverse=True,
    )
    yield from findings


def list_repositories(
    connection: sqlite3.Connection,
    args: argparse.Namespace | None = None,
) -> dict[str, Any]:
    scan_count_by_target = Counter()
    latest_by_target: dict[str, tuple[sqlite3.Row, dict[str, Any] | None]] = {}
    for row in connection.execute(
        f"""
        SELECT targets.id AS repository_id, targets.display_name, targets.current_path,
               {scan_history.SCAN_SUMMARY_COLUMNS}
        FROM security_targets AS targets
        LEFT JOIN scans ON scans.target_id = targets.id
            AND scans.id IN (SELECT scan_id FROM scan_progress)
        LEFT JOIN scan_progress AS progress ON progress.scan_id = scans.id
        ORDER BY julianday(upper(scans.started_at)) DESC, scans.id DESC, targets.id
        """
    ).fetchall():
        scan = scan_history.scan_summary(row) if row["id"] is not None else None
        target_id = row["repository_id"]
        if scan is not None:
            scan_count_by_target[target_id] += 1
        latest_by_target.setdefault(target_id, (row, scan))

    open_findings_by_target = Counter(
        row["target_id"] for row in _indexed_findings(connection) if row["status"] == "open"
    )
    repositories = [
        {
            "displayName": target["display_name"],
            "latestScan": latest_scan,
            "openFindingsCount": open_findings_by_target[target_id]
            if latest_scan is not None
            else 0,
            "scanCount": scan_count_by_target[target_id],
            "targetId": target_id,
            "targetPath": target["current_path"],
        }
        for target_id, (target, latest_scan) in latest_by_target.items()
    ]
    pagination = {}
    if args is not None:
        query = args.query.strip().casefold() if args.query else ""
        repositories = [
            repository
            for repository in repositories
            if (args.target_id is None or repository["targetId"] == args.target_id)
            and (args.status != "scanned" or repository["scanCount"] > 0)
            and (args.status != "not_scanned" or repository["scanCount"] == 0)
            and (args.status != "open_findings" or repository["openFindingsCount"] > 0)
            and (
                not query
                or query in repository["displayName"].casefold()
                or query in repository["targetPath"].casefold()
            )
        ]
        if args.limit is not None or args.offset:
            limit = args.limit or FINDINGS_PAGE_MAX
            end = args.offset + limit
            pagination = {
                "limit": limit,
                "nextOffset": end if end < len(repositories) else None,
                "offset": args.offset,
            }
            repositories = repositories[args.offset : end]
    for repository in repositories:
        path = os.path.expanduser(repository["targetPath"])
        try:
            repository["checkoutAvailable"] = Path(path).is_absolute() and os.path.isdir(
                os.path.realpath(path)
            )
        except (OSError, RecursionError):
            repository["checkoutAvailable"] = False
    return {"repositories": repositories, **pagination}


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
