"""Read-only native findings and repository indexes for the Security workbench."""

import argparse
import os
import sqlite3
import sys
from collections.abc import Iterator
from functools import cache
from itertools import islice
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import workbench_scan_history as scan_history
from workbench_constants import (
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
    FINDINGS_PAGE_MAX,
    PRIMARY_FINDING_LOCATION_SQL,
)
from workbench_target_state import RepositoryIdentityCache, RepositoryScanScope
from workbench_validation import bounded_output_text, timestamp_key


def list_global_findings(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Return a page of indexed findings after applying the requested filters, with nextOffset for continuation."""
    limit = min(args.limit, FINDINGS_PAGE_MAX)
    query = args.query.strip().casefold() if args.query else ""
    identities = RepositoryIdentityCache(connection)
    repository = getattr(args, "repository", None)
    requested = None
    if repository is not None:
        repository = identities.history_path(str(Path(repository).expanduser().absolute()))
        requested = identities.for_path(repository)
        scan_scope = identities.scope_for_path(repository)
    else:
        scan_scope = None if args.target_id is None else identities.scope(args.target_id)
        target = identities.targets.get(args.target_id)
        if identities.supports_identity and target is not None:
            requested = identities.for_row(target)
    findings = (
        row
        for row in _indexed_findings(connection, identities=identities, scan_scope=scan_scope)
        if (args.severity is None or row["severity"] == args.severity)
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
        "projectionAvailable": requested is None or requested.ownership_matches,
    }


def _legacy_generations(
    connection: sqlite3.Connection, identities: RepositoryIdentityCache
) -> dict[str, str]:
    return (
        {
            row["target_id"]: row["generation"]
            for row in connection.execute(
                "SELECT target_id, MIN(repository_generation) AS generation FROM scans "
                "WHERE repository_generation IS NOT NULL GROUP BY target_id "
                "HAVING COUNT(DISTINCT repository_generation) = 1"
            )
        }
        if identities.supports_generation
        else {}
    )


def _indexed_findings(
    connection: sqlite3.Connection,
    *,
    identities: RepositoryIdentityCache | None = None,
    scan_scope: RepositoryScanScope | None = None,
    legacy_generations: dict[str, str] | None = None,
) -> Iterator[dict[str, Any]]:
    identities = identities or RepositoryIdentityCache(connection)

    def scope_sql(alias: str) -> tuple[str, tuple[str, ...]]:
        return (
            scan_scope.sql(alias, supports_generation=identities.supports_generation)
            if scan_scope is not None
            else ("1", ())
        )

    def generation_sql(alias: str) -> str:
        return f"{alias}.repository_generation" if identities.supports_generation else "NULL"

    if legacy_generations is None:
        legacy_generations = _legacy_generations(connection, identities)

    def repository_group(
        row: sqlite3.Row, prefix: str = "", *, infer_legacy: bool = True
    ) -> tuple[str, str]:
        target_id = row[prefix + "target_id"]
        generation = row[prefix + "repository_generation"]
        if generation is None and infer_legacy:
            generation = legacy_generations.get(target_id)
        return ("repository", generation) if generation is not None else ("target", target_id)

    target_filter, target_values = scope_sql("scans")
    before_filter, before_values = scope_sql("before_scans")
    after_filter, after_values = scope_sql("after_scans")
    before_generation = generation_sql("before_scans")
    after_generation = generation_sql("after_scans")
    # Check the saved generations before inferring groups for legacy scans.
    # If either generation is missing, only the same target can share a match.
    matches = connection.execute(
        f"""
        SELECT before_scans.target_id AS before_target_id,
            after_scans.target_id AS after_target_id,
            {before_generation} AS before_repository_generation,
            {after_generation} AS after_repository_generation,
            before.finding_id AS before_finding_id,
            after.finding_id AS after_finding_id
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
        JOIN scans AS before_scans ON before_scans.id = before.scan_id
        JOIN security_targets AS before_targets ON before_targets.id = before_scans.target_id
        JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
        JOIN scans AS after_scans ON after_scans.id = after.scan_id
        JOIN security_targets AS after_targets ON after_targets.id = after_scans.target_id
        WHERE {before_filter} AND {after_filter}
            AND COALESCE({before_generation} = {after_generation},
                         before_scans.target_id = after_scans.target_id)
        """,
        (*before_values, *after_values),
    )

    aliases = scan_history._finding_aliases(
        (
            (repository_group(match, "before_"), match["before_finding_id"]),
            (repository_group(match, "after_"), match["after_finding_id"]),
        )
        for match in matches
    )
    completion_column = (
        "scans.completion_sequence" if "completion_sequence" in identities.scan_columns else "NULL"
    )
    completed_at_column = (
        "scans.completed_at" if "completed_at" in identities.scan_columns else "NULL"
    )
    completed_scans = sorted(
        connection.execute(
            f"""
            SELECT scans.target_id, scans.id, scans.started_at,
                {generation_sql("scans")} AS repository_generation,
                {completed_at_column} AS completed_at,
                {completion_column} AS completion_sequence
            FROM scans
            JOIN security_targets AS targets ON targets.id = scans.target_id
            WHERE scans.status = 'complete' AND {target_filter}
            """,
            target_values,
        ),
        key=scan_history._scan_completion_order,
    )
    latest_scan_by_repository = {repository_group(row): row for row in completed_scans}
    selected_latest_scan_id = completed_scans[-1]["id"] if completed_scans else None

    grouped: dict[tuple[tuple[str, str], str], list[sqlite3.Row]] = {}
    for row in connection.execute(
        f"""
        SELECT
            occurrences.id AS occurrence_id,
            occurrences.finding_id,
            occurrences.severity,
            occurrences.created_at,
            scans.id AS scan_id,
            scans.started_at AS scan_started_at,
            scans.target_id,
            {generation_sql("scans")} AS repository_generation,
            targets.current_path AS target_path,
            scans.scope,
            scans.updated_at,
            triage.status AS decision_status,
            triage.close_reason,
            triage.updated_at AS decision_updated_at,
            occurrences.title,
            occurrences.summary,
            (SELECT relative_path {PRIMARY_FINDING_LOCATION_SQL}) AS location_path
        FROM finding_occurrences AS occurrences
        JOIN scans ON scans.id = occurrences.scan_id
        JOIN security_targets AS targets ON targets.id = scans.target_id
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        WHERE {target_filter}
        """,
        target_values,
    ):
        key = (repository_group(row), row["finding_id"])
        grouped.setdefault(aliases.get(key, key), []).append(row)

    # When a match group spans current targets, keep decisions within each verified
    # generation or legacy target in that group. Scoped queries already select their history.
    finding_groups = []
    for occurrences in grouped.values():
        current_targets = {
            row["target_id"] for row in occurrences if row["repository_generation"] is not None
        }
        if len(current_targets) <= 1 or scan_scope is not None:
            finding_groups.append(occurrences)
            continue
        partitions: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in occurrences:
            partitions.setdefault(repository_group(row, infer_legacy=False), []).append(row)
        finding_groups.extend(partitions.values())

    findings = []
    for occurrences in finding_groups:
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
        component_latest_scan = max(
            (
                latest_scan_by_repository[repository]
                for repository in {repository_group(row) for row in occurrences}
                if repository in latest_scan_by_repository
            ),
            key=scan_history._scan_completion_order,
            default=None,
        )
        latest_scan_id = (
            selected_latest_scan_id
            if scan_scope is not None
            else component_latest_scan["id"]
            if component_latest_scan is not None
            else None
        )
        findings.append(
            {
                **dict(latest),
                "close_reason": decision["close_reason"] if decision is not None else None,
                "confirmed_in_latest_scan": any(
                    row["scan_id"] == latest_scan_id for row in occurrences
                ),
                "known_since": scans[0][0],
                "known_scan_ids": [scan_id for _, scan_id in scans],
                "matched_finding_ids": sorted({row["finding_id"] for row in occurrences}),
                "matched_occurrence_ids": sorted({row["occurrence_id"] for row in occurrences}),
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
    """Return tracked targets with scan summaries, finding counts, and current checkout availability."""
    by_target: dict[str, dict[str, Any]] = {}
    latest_rows: dict[str, sqlite3.Row] = {}
    for row in connection.execute(
        f"""
        SELECT targets.id AS repository_id, targets.display_name, targets.current_path,
               {scan_history.SCAN_SUMMARY_COLUMNS}
        FROM security_targets AS targets
        LEFT JOIN scans ON scans.target_id = targets.id
            AND scans.id IN (SELECT scan_id FROM scan_progress)
        LEFT JOIN scan_progress AS progress ON progress.scan_id = scans.id
        LEFT JOIN scan_lifecycles AS lifecycle ON lifecycle.scan_id = scans.id
        ORDER BY julianday(upper(scans.started_at)) DESC, scans.id DESC, targets.id
        """
    ).fetchall():
        target_id = row["repository_id"]
        if target_id not in by_target:
            by_target[target_id] = {
                "displayName": row["display_name"],
                "latestScan": None,
                "openFindingsCount": 0,
                "scanCount": 0,
                "targetId": target_id,
                "targetPath": row["current_path"],
            }
        if row["id"] is None:
            continue
        repository = by_target[target_id]
        scan = scan_history.scan_summary(row)
        repository["scanCount"] += 1
        previous = latest_rows.get(target_id)
        if previous is None or (
            previous["status"] == row["status"] == "complete"
            and scan_history._scan_completion_order(row)
            > scan_history._scan_completion_order(previous)
        ):
            latest_rows[target_id] = row
            repository["latestScan"] = scan

    identities = RepositoryIdentityCache(connection)
    legacy_generations = _legacy_generations(connection, identities)

    @cache
    def open_findings_count(target_id: str) -> int:
        if not by_target[target_id]["scanCount"]:
            return 0
        scope = identities.scope(target_id)
        if not scope.available:
            return 0
        return sum(
            row["status"] == "open"
            for row in _indexed_findings(
                connection,
                identities=identities,
                scan_scope=scope,
                legacy_generations=legacy_generations,
            )
        )

    repositories = list(by_target.values())
    pagination = {}
    if args is not None:
        query = args.query.strip().casefold() if args.query else ""
        repositories = [
            repository
            for repository in repositories
            if (args.target_id is None or repository["targetId"] == args.target_id)
            and (args.status != "scanned" or repository["scanCount"] > 0)
            and (args.status != "not_scanned" or repository["scanCount"] == 0)
            and (
                not query
                or query in repository["displayName"].casefold()
                or query in repository["targetPath"].casefold()
            )
            and (args.status != "open_findings" or open_findings_count(repository["targetId"]) > 0)
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
        repository["openFindingsCount"] = open_findings_count(repository["targetId"])
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
