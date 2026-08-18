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
from workbench_target_state import (
    RepositoryIdentityCache,
    RepositoryScanScope,
    scan_repository_group,
)
from workbench_validation import bounded_output_text


def repository_target_ids(
    connection: sqlite3.Connection,
    target_id: str,
    *,
    identities: RepositoryIdentityCache | None = None,
) -> set[str]:
    return (identities or RepositoryIdentityCache(connection)).target_ids(target_id)


def list_global_findings(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
) -> dict[str, Any]:
    limit = min(args.limit, FINDINGS_PAGE_MAX)
    query = args.query.strip().casefold() if args.query else ""
    identities = RepositoryIdentityCache(connection)
    repository = getattr(args, "repository", None)
    requested = None
    if repository is not None:
        repository = str(Path(repository).expanduser().resolve())
        requested = identities.for_path(repository)
        scan_scope = identities.scope_for_path(repository)
    else:
        scan_scope = (
            None if args.target_id is None else identities.scope(args.target_id)
        )
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


def _indexed_findings(
    connection: sqlite3.Connection,
    *,
    identities: RepositoryIdentityCache | None = None,
    scan_scope: RepositoryScanScope | None = None,
) -> Iterator[dict[str, Any]]:
    identities = identities or RepositoryIdentityCache(connection)

    def scope_sql(alias: str) -> tuple[str, tuple[str, ...]]:
        return scan_scope.sql(
            alias, supports_generation=identities.supports_generation
        ) if scan_scope is not None else ("1", ())

    def generation_sql(alias: str) -> str:
        return f"{alias}.repository_generation" if identities.supports_generation else "NULL"

    target_filter, target_values = scope_sql("scans")
    before_filter, before_values = scope_sql("before_scans")
    after_filter, after_values = scope_sql("after_scans")
    parents: dict[
        tuple[tuple[str, str], str], tuple[tuple[str, str], str]
    ] = {}

    def group(identity: tuple[tuple[str, str], str]) -> tuple[tuple[str, str], str]:
        while identity in parents:
            identity = parents[identity]
        return identity

    for match in connection.execute(
        f"""
        SELECT before_scans.target_id AS before_target_id,
            after_scans.target_id AS after_target_id,
            {generation_sql("before_scans")} AS before_generation,
            {generation_sql("after_scans")} AS after_generation,
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
        """,
        (*before_values, *after_values),
    ):
        before_repository = scan_repository_group({
            "target_id": match["before_target_id"],
            "repository_generation": match["before_generation"],
        })
        after_repository = scan_repository_group({
            "target_id": match["after_target_id"],
            "repository_generation": match["after_generation"],
        })
        if before_repository != after_repository:
            continue
        before = group(
            (
                before_repository,
                match["before_finding_id"],
            )
        )
        after = group(
            (
                after_repository,
                match["after_finding_id"],
            )
        )
        if before != after:
            parents[after] = before

    completion_column = (
        "scans.completion_sequence"
        if "completion_sequence" in identities.scan_columns else "NULL"
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
    latest_scan_by_repository = {
        scan_repository_group(row): row["id"] for row in completed_scans
    }
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
            MAX(scans.updated_at, COALESCE(triage.updated_at, '')) AS updated_at,
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
        WHERE {target_filter}
        """,
        target_values,
    ):
        grouped.setdefault(
            group(
                (
                    scan_repository_group(row),
                    row["finding_id"],
                )
            ),
            [],
        ).append(row)

    findings = []
    for occurrences in grouped.values():
        latest = max(occurrences, key=lambda row: (row["created_at"], row["occurrence_id"]))
        decision = max(
            (row for row in occurrences if row["decision_status"] is not None),
            key=lambda row: (row["decision_updated_at"], row["occurrence_id"]),
            default=None,
        )
        status = decision["decision_status"] if decision is not None else "open"
        if (
            status == "closed"
            and decision["close_reason"] == "already_fixed"
            and latest["created_at"] > decision["decision_updated_at"]
        ):
            status = "open"
        scans = sorted({(row["scan_started_at"], row["scan_id"]) for row in occurrences})
        latest_scan_id = (
            selected_latest_scan_id if scan_scope is not None
            else latest_scan_by_repository.get(scan_repository_group(latest))
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
                "occurrence_count": len(occurrences),
                "status": status,
                "updated_at": max(
                    latest["updated_at"],
                    decision["decision_updated_at"] if decision is not None else "",
                ),
            }
        )

    findings.sort(key=lambda finding: finding["occurrence_id"])
    findings.sort(
        key=lambda finding: (
            finding["status"] == "open",
            -scan_history.SEVERITY_ORDER.get(finding["severity"], 5),
            finding["created_at"],
        ),
        reverse=True,
    )
    yield from findings


def list_repositories(
    connection: sqlite3.Connection,
    args: argparse.Namespace | None = None,
) -> dict[str, Any]:
    scans = scan_history.list_scans(connection)["scans"]
    identities = RepositoryIdentityCache(connection)
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

    targets = {row["id"]: row for row in connection.execute("SELECT * FROM security_targets")}
    query = args.query.strip().casefold() if args is not None and args.query else ""
    selected_targets = [
        (target_id, latest_scan, target)
        for target_id, latest_scan in latest_scan_by_target.items()
        if (target := targets.get(target_id)) is not None
        and (args is None or args.target_id is None or target_id == args.target_id)
        and (args is None or args.status != "not_scanned")
        and (
            not query
            or query in target["display_name"].casefold()
            or query in target["current_path"].casefold()
        )
    ]
    scopes = {
        target_id: identities.scope(target_id)
        for target_id, _, _ in selected_targets
    }
    open_findings_by_group = Counter(
        scan_repository_group(row)
        for row in _indexed_findings(connection, identities=identities)
        if row["status"] == "open"
    ) if any(
        scope.available and not scope.exact_target for scope in scopes.values()
    ) else Counter()

    def open_findings_count(scope: RepositoryScanScope) -> int:
        if not scope.available:
            return 0
        if scope.exact_target:
            return sum(
                row["status"] == "open"
                for row in _indexed_findings(
                    connection, identities=identities, scan_scope=scope
                )
            )
        return (
            open_findings_by_group[("repository", scope.generation)]
            if identities.supports_generation and scope.generation is not None else 0
        ) + (
            open_findings_by_group[("target", scope.target_id)] if scope.target_id else 0
        )

    repositories = [
        {
            "checkoutAvailable": Path(target["current_path"]).is_dir(),
            "displayName": target["display_name"],
            "latestScan": latest_scan,
            "openFindingsCount": open_findings_count(scopes[target_id]),
            "scanCount": scan_count_by_target[target_id],
            "targetId": target_id,
            "targetPath": target["current_path"],
        }
        for target_id, latest_scan, target in selected_targets
    ]
    if args is None:
        return {"repositories": repositories}

    repositories = [
        repository
        for repository in repositories
        if args.status != "open_findings" or repository["openFindingsCount"] > 0
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
