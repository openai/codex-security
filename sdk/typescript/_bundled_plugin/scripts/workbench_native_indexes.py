"""Read-only native findings and repository indexes for the Security workbench."""

import argparse
import sqlite3
import sys
from collections import Counter
from collections.abc import Callable, Iterator
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
    *,
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
) -> dict[str, Any]:
    limit = min(args.limit, FINDINGS_PAGE_MAX)
    query = args.query.strip().casefold() if args.query else ""
    selected_ids = args.target_id
    target_ids = (
        {selected_ids}
        if isinstance(selected_ids, str)
        else set(selected_ids)
        if selected_ids is not None
        else None
    )
    selected_paths = getattr(args, "target_path", None)
    target_paths = (
        {selected_paths}
        if isinstance(selected_paths, str)
        else set(selected_paths)
        if selected_paths is not None
        else None
    )
    findings = (
        row
        for row in _active_findings(
            connection,
            read_coverage,
            target_ids=target_ids,
            target_paths=target_paths,
            query=query,
        )
        if (
            (target_ids is None and target_paths is None)
            or (target_ids is not None and row["target_id"] in target_ids)
            or (target_paths is not None and row["target_path"] in target_paths)
        )
        and (args.severity is None or row["severity"] == args.severity)
        and (args.status is None or row["status"] == args.status)
        and (
            not query
            or any(
                query in value.casefold()
                for value in (
                    row["title"],
                    row["summary"],
                    row["target_path"]
                    if target_ids is None and target_paths is None
                    else None,
                    row["location_path"],
                )
                if value is not None
            )
            or row["secondary_location_match"]
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


def _active_findings(
    connection: sqlite3.Connection,
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
    *,
    target_ids: set[str] | None = None,
    target_paths: set[str] | None = None,
    query: str = "",
) -> Iterator[sqlite3.Row]:
    target_filters = []
    target_values = []
    if target_ids:
        placeholders = ", ".join("?" for _ in target_ids)
        target_filters.append(f"targets.id IN ({placeholders})")
        target_values.extend(target_ids)
    if target_paths is not None:
        placeholders = ", ".join("?" for _ in target_paths)
        target_filters.append(f"scans.target_path IN ({placeholders})")
        target_values.extend(target_paths)
    target_filter = "" if not target_filters else "AND (" + " OR ".join(target_filters) + ")"
    current_owner_only = (
        "AND NOT (scans.target_id IS NULL AND EXISTS ("
        "SELECT 1 FROM security_targets AS path_owner "
        "WHERE path_owner.current_path = scans.target_path))"
    )
    scan_columns = {
        column["name"] for column in connection.execute("PRAGMA table_info(scans)")
    }
    if {"target_device", "target_inode"}.issubset(scan_columns):
        latest_identity = (
            "FROM scans AS ownership_scan "
            "WHERE ownership_scan.target_id = scans.target_id "
            "AND ownership_scan.target_device IS NOT NULL "
            "AND ownership_scan.target_inode IS NOT NULL "
            "ORDER BY ownership_scan.started_at DESC, ownership_scan.id DESC LIMIT 1"
        )
        current_owner_only += (
            " AND (scans.target_id IS NULL OR ("
            f"scans.target_device IS (SELECT ownership_scan.target_device {latest_identity}) "
            f"AND scans.target_inode IS (SELECT ownership_scan.target_inode {latest_identity})"
            "))"
        )
    completed_scans_by_target: dict[str, list[sqlite3.Row]] = {}
    for scan in connection.execute(
        f"""
        SELECT scans.*, COALESCE(targets.id, scans.target_path) AS indexed_target_id
        FROM scans
        LEFT JOIN security_targets AS targets ON targets.id = scans.target_id
        WHERE scans.status = 'complete' AND scans.seal_manifest_digest IS NOT NULL
            {target_filter} {current_owner_only}
        ORDER BY scans.started_at DESC, scans.id DESC
        """,
        target_values,
    ):
        completed_scans_by_target.setdefault(scan["indexed_target_id"], []).append(scan)

    coverage_by_scan_id: dict[str, dict[str, Any] | None] = {}
    if query:
        connection.create_function("codex_security_casefold", 1, str.casefold, deterministic=True)
    secondary_location_match = (
        "EXISTS ("
        "SELECT 1 FROM finding_locations AS searched_locations "
        "WHERE searched_locations.occurrence_id = selected_findings.occurrence_id "
        "AND instr(codex_security_casefold(searched_locations.relative_path), ?) > 0)"
        if query
        else "0"
    )
    rows = connection.execute(
        f"""
        WITH ranked_findings AS (
            SELECT
                occurrences.id AS occurrence_id,
                occurrences.finding_id,
                occurrences.severity,
                occurrences.created_at,
                scans.id AS scan_id,
                scans.started_at AS scan_started_at,
                targets.id AS target_id,
                COALESCE(targets.id, scans.target_path) AS indexed_target_id,
                COALESCE(targets.current_path, scans.target_path) AS target_path,
                scans.scope,
                MAX(scans.updated_at, COALESCE(triage.updated_at, '')) AS updated_at,
                COALESCE(triage.status, 'open') AS status,
                COUNT(*) OVER (
                    PARTITION BY COALESCE(targets.id, scans.target_path), occurrences.finding_id
                ) AS occurrence_count,
                ROW_NUMBER() OVER (
                    PARTITION BY COALESCE(targets.id, scans.target_path), occurrences.finding_id
                    ORDER BY scans.started_at DESC, scans.id DESC,
                        occurrences.created_at DESC, occurrences.id DESC
                ) AS occurrence_rank
            FROM finding_occurrences AS occurrences
            JOIN scans ON scans.id = occurrences.scan_id
            LEFT JOIN security_targets AS targets ON targets.id = scans.target_id
            LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
            WHERE 1 = 1 {target_filter} {current_owner_only}
        )
        SELECT
            selected_findings.*,
            occurrences.title,
            occurrences.summary,
            {secondary_location_match} AS secondary_location_match,
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
        [*target_values, *([query] if query else [])],
    )
    for row in rows:
        resolved = False
        for scan in completed_scans_by_target.get(row["indexed_target_id"], ()):
            if (scan["started_at"], scan["id"]) <= (
                row["scan_started_at"],
                row["scan_id"],
            ):
                break
            if scan["id"] not in coverage_by_scan_id:
                try:
                    coverage_by_scan_id[scan["id"]] = read_coverage(scan)
                except SystemExit as error:
                    message = str(error)
                    if message == (
                        "Scan directory must be an existing canonical non-symlink directory."
                    ):
                        try:
                            Path(scan["scan_dir"]).lstat()
                        except FileNotFoundError:
                            coverage_by_scan_id[scan["id"]] = None
                        else:
                            raise
                    elif (
                        "missing" in message.lower()
                        or ": expected a regular file inside the scan directory." in message
                        or ": invalid JSON:" in message
                        or ": expected a JSON object." in message
                    ):
                        coverage_by_scan_id[scan["id"]] = None
                    else:
                        raise
            coverage = coverage_by_scan_id[scan["id"]]
            if coverage is None:
                continue
            comparable_scan = (
                scan
                if scan["target_id"] == row["indexed_target_id"]
                else {**dict(scan), "target_id": row["indexed_target_id"]}
            )
            if scan_history.scan_covers_path(
                comparable_scan,
                target_id=row["indexed_target_id"],
                path=row["location_path"],
                coverage=coverage,
            ):
                resolved = True
                break
        if not resolved:
            yield row


def list_repositories(
    connection: sqlite3.Connection,
    args: argparse.Namespace | None = None,
    *,
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
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
        row["target_id"]
        for row in _active_findings(connection, read_coverage)
        if row["status"] == "open"
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
