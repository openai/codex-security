"""Read-only native findings and repository indexes for the Security workbench."""

import argparse
import json
import os
import sqlite3
import sys
from collections.abc import Callable, Iterator
from functools import cache
from itertools import islice
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import workbench_scan_history as scan_history
from workbench_constants import (
    DEFAULT_PAGE_SIZE,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
    PRIMARY_FINDING_LOCATION_SQL,
)
from workbench_target_state import (
    RepositoryIdentityCache,
    RepositoryScanScope,
    scan_repository_group,
)
from workbench_validation import bounded_output_text, timestamp_key


def list_global_findings(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    read_coverage: Callable | None = None,
) -> dict[str, Any]:
    """Return a page of indexed findings after applying the requested filters, with nextOffset for continuation."""
    limit = args.limit
    query = args.query.strip().casefold() if args.query else ""
    identities = RepositoryIdentityCache(connection)
    repository = getattr(args, "repository", None)
    requested = None
    scan_scope = None
    allowed_ids = None
    if repository is not None:
        repository = identities.history_path(str(Path(repository).expanduser().absolute()))
        requested = identities.for_path(repository)
        if (
            requested.stored_identity
            or identities.supports_generation
            and requested.ownership_matches
            and (requested.live_identity or requested.target_id)
        ):
            scan_scope = identities.scope_for_path(repository)
        else:
            clauses, parameters = scan_history.repository_scan_scope(
                connection, repository, identities=identities
            )
            allowed_ids = {
                row[0]
                for row in connection.execute(
                    f"SELECT scans.id FROM scans WHERE {' AND '.join(clauses)}", parameters
                )
            }
    elif args.target_id is not None or getattr(args, "target_path", None) is not None:
        ids = [args.target_id] if isinstance(args.target_id, str) else args.target_id or []
        paths = getattr(args, "target_path", None)
        if isinstance(paths, str):
            paths = [paths]
        if len(ids) == 1 and not paths:
            scan_scope = identities.scope(ids[0])
            target = identities.targets.get(ids[0])
            if target is not None:
                requested = identities.for_row(target)
                if not identities.supports_generation:
                    scan_scope = RepositoryScanScope(target_id=ids[0], exact_target=True)
        else:
            allowed_ids = {
                row[0]
                for row in connection.execute(
                    "SELECT id FROM scans WHERE target_id IN (SELECT value FROM json_each(?)) "
                    "OR target_path IN (SELECT value FROM json_each(?))",
                    (json.dumps(ids), json.dumps(paths or [])),
                )
            }
    findings = (
        row
        for row in _indexed_findings(
            connection,
            identities=identities,
            scan_scope=scan_scope,
            allowed_scan_ids=allowed_ids,
            query=query,
        )
        if (args.severity is None or row["severity"] == args.severity)
        and (args.status is None or row["status"] == args.status)
        and (
            not query
            or row["query_match"]
            or (repository is None and query in row["target_path"].casefold())
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
    allowed_scan_ids: set[str] | None = None,
    through_scan_sequence: int | None = None,
    exclude_scan_id: str | None = None,
    require_current_owners: bool = False,
    query: str = "",
) -> Iterator[dict[str, Any]]:
    identities = identities or RepositoryIdentityCache(connection)

    selected_filter, selected_values = (
        scan_scope.sql("scans", supports_generation=identities.supports_generation)
        if scan_scope is not None
        else ("1", ())
    )
    if allowed_scan_ids is not None:
        selected_filter += " AND scans.id IN (SELECT value FROM json_each(?))"
        selected_values = (*selected_values, json.dumps(sorted(allowed_scan_ids)))
    selected_filter += " AND (scans.status = 'complete' OR (scans.status = 'failed' AND scans.seal_manifest_digest IS NOT NULL))"
    if exclude_scan_id is not None:
        selected_filter += " AND scans.id != ?"
        selected_values = (*selected_values, exclude_scan_id)
    admitted = json.dumps(
        [
            row["id"]
            for row in connection.execute(
                f"SELECT scans.*, scans.rowid AS scan_sequence FROM scans WHERE {selected_filter}",
                selected_values,
            )
            if (
                not require_current_owners
                and scan_scope is not None
                and scan_scope.generation is not None
                and row["repository_generation"] == scan_scope.generation
            )
            or scan_history.scan_has_current_owner(connection, row, identities)
        ]
    )

    def scope_sql(alias: str) -> tuple[str, tuple]:
        clause, values = (
            scan_scope.sql(alias, supports_generation=identities.supports_generation)
            if scan_scope is not None
            else ("1", ())
        )
        return f"{clause} AND {alias}.id IN (SELECT value FROM json_each(?))", (*values, admitted)

    def generation_sql(alias: str) -> str:
        return f"{alias}.repository_generation" if identities.supports_generation else "NULL"

    if legacy_generations is None:
        legacy_generations = _legacy_generations(connection, identities)

    def repository_group(scan: sqlite3.Row | dict) -> tuple[str, str]:
        identity = scan_repository_group(scan)
        if identity == ("target", None):
            return ("path", scan["target_path"])
        generation = legacy_generations.get(scan["target_id"])
        return (
            ("repository", generation)
            if identity[0] == "target" and generation is not None
            else identity
        )

    target_filter, target_values = scope_sql("scans")
    if through_scan_sequence is not None:
        target_filter += " AND scans.rowid <= ?"
        target_values = (*target_values, through_scan_sequence)
    parents: dict[tuple[tuple[str, str], str], tuple[tuple[str, str], str]] = {}

    def group(identity: tuple[tuple[str, str], str]) -> tuple[tuple[str, str], str]:
        while identity in parents:
            identity = parents[identity]
        return identity

    before_filter, before_values = scope_sql("before_scans")
    after_filter, after_values = scope_sql("after_scans")
    for match in connection.execute(
        f"""
        SELECT before_scans.target_id AS before_target_id, before_scans.target_path AS before_path,
            after_scans.target_id AS after_target_id, after_scans.target_path AS after_path,
            {generation_sql("before_scans")} AS before_generation,
            {generation_sql("after_scans")} AS after_generation,
            before.finding_id AS before_finding_id,
            after.finding_id AS after_finding_id
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
        JOIN scans AS before_scans ON before_scans.id = before.scan_id
        JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
        JOIN scans AS after_scans ON after_scans.id = after.scan_id
        WHERE {before_filter} AND {after_filter}
        """,
        (*before_values, *after_values),
    ):
        if match["before_target_id"] != match["after_target_id"] and (
            match["before_generation"] is None or match["after_generation"] is None
        ):
            continue
        before_repository = repository_group(
            {
                "target_id": match["before_target_id"],
                "target_path": match["before_path"],
                "repository_generation": match["before_generation"],
            }
        )
        after_repository = repository_group(
            {
                "target_id": match["after_target_id"],
                "target_path": match["after_path"],
                "repository_generation": match["after_generation"],
            }
        )
        if before_repository != after_repository and (
            match["before_target_id"] is None
            or match["before_target_id"] != match["after_target_id"]
            or match["before_generation"] is not None
            and match["after_generation"] is not None
        ):
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
        "scans.completion_sequence" if "completion_sequence" in identities.scan_columns else "NULL"
    )
    completed_at_column = (
        "scans.completed_at" if "completed_at" in identities.scan_columns else "NULL"
    )
    completed_scans = sorted(
        connection.execute(
            f"""
            SELECT scans.target_id, scans.id, scans.target_path, scans.started_at,
                {generation_sql("scans")} AS repository_generation,
                {completed_at_column} AS completed_at,
                {completion_column} AS completion_sequence
            FROM scans
            WHERE scans.status = 'complete' AND {target_filter}
            """,
            target_values,
        ),
        key=scan_history._scan_completion_order,
    )
    latest_scan_by_repository = {repository_group(row): row for row in completed_scans}
    selected_latest_scan_id = completed_scans[-1]["id"] if completed_scans else None

    if query:
        connection.create_function("codex_security_casefold", 1, str.casefold, deterministic=True)
    secondary_match = (
        "EXISTS (SELECT 1 FROM finding_locations WHERE occurrence_id = occurrences.id "
        "AND instr(codex_security_casefold(relative_path), ?) > 0)"
        if query
        else "0"
    )
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
            COALESCE(targets.current_path, scans.target_path) AS target_path,
            scans.scope,
            scans.updated_at,
            triage.status AS decision_status,
            triage.close_reason,
            triage.updated_at AS decision_updated_at,
            COALESCE(
                (SELECT MAX(decisions.decision_sequence)
                 FROM finding_decisions AS decisions
                 WHERE decisions.occurrence_id = occurrences.id),
                triage.rowid
            ) AS decision_sequence,
            (SELECT decisions.scan_sequence
             FROM finding_decisions AS decisions
             WHERE decisions.occurrence_id = occurrences.id
             ORDER BY decisions.decision_sequence DESC LIMIT 1) AS decision_scan_sequence,
            (SELECT decisions.admission_sequence
             FROM finding_decisions AS decisions
             WHERE decisions.occurrence_id = occurrences.id
             ORDER BY decisions.decision_sequence DESC LIMIT 1) AS decision_admission_sequence,
            scans.rowid AS scan_sequence,
            admissions.sequence AS admission_sequence,
            COALESCE(scans.target_id, scans.target_path) AS indexed_target_id,
            occurrences.title,
            occurrences.summary, {secondary_match} AS secondary_location_match,
            (SELECT relative_path {PRIMARY_FINDING_LOCATION_SQL}) AS location_path
        FROM finding_occurrences AS occurrences
        JOIN scans ON scans.id = occurrences.scan_id
        LEFT JOIN security_targets AS targets ON targets.id = scans.target_id
        LEFT JOIN scan_admissions AS admissions ON admissions.scan_id = scans.id
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        WHERE {target_filter}
        """,
        ((query,) if query else ()) + target_values,
    ):
        grouped.setdefault(
            group(
                (
                    repository_group(row),
                    row["finding_id"],
                )
            ),
            [],
        ).append(row)

    # Global comparisons do not bind legacy history across current targets. A scoped
    # projection already admits only its own target's legacy rows and decisions.
    for identity, occurrences in list(grouped.items()):
        current_targets = {
            row["target_id"] for row in occurrences if row["repository_generation"] is not None
        }
        if len(current_targets) <= 1 or scan_scope is not None:
            continue
        current = []
        for row in occurrences:
            if row["repository_generation"] is None:
                legacy_identity = (scan_repository_group(row), identity[1])
                grouped.setdefault(legacy_identity, []).append(row)
            else:
                current.append(row)
        grouped[identity] = current

    findings = []
    for occurrences in grouped.values():
        latest = max(
            occurrences,
            key=lambda row: (timestamp_key(row["created_at"]), row["occurrence_id"]),
        )
        decision = max(
            (row for row in occurrences if row["decision_status"] is not None),
            key=lambda row: (row["decision_sequence"], row["occurrence_id"]),
            default=None,
        )
        status = decision["decision_status"] if decision is not None else "open"
        if (
            status == "closed"
            and decision["close_reason"] in {"already_fixed", "false_positive"}
            and (
                any(
                    row["admission_sequence"] is not None
                    and row["admission_sequence"] > decision["decision_admission_sequence"]
                    for row in occurrences
                )
                if decision["decision_admission_sequence"] is not None
                else (
                    any(
                        row["scan_sequence"] > decision["decision_scan_sequence"]
                        for row in occurrences
                    )
                    if decision["decision_scan_sequence"] is not None
                    else (
                        decision["close_reason"] == "already_fixed"
                        and timestamp_key(latest["created_at"])
                        > timestamp_key(decision["decision_updated_at"])
                    )
                )
            )
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
                "decision_occurrence_id": decision["occurrence_id"]
                if decision is not None
                else None,
                **{
                    key: decision[key] if decision is not None else None
                    for key in (
                        "decision_status",
                        "decision_scan_sequence",
                        "decision_admission_sequence",
                        "decision_updated_at",
                    )
                },
                "occurrences": occurrences,
                "query_match": bool(query)
                and any(
                    query in item["title"].casefold()
                    or query in item["summary"].casefold()
                    or item["secondary_location_match"]
                    for item in occurrences
                ),
                "close_reason": decision["close_reason"] if decision is not None else None,
                "confirmed_in_latest_scan": any(
                    row["scan_id"] == latest_scan_id for row in occurrences
                ),
                "known_since": scans[0][0],
                "known_scan_ids": [scan_id for _, scan_id in scans],
                "matched_finding_ids": sorted({row["finding_id"] for row in occurrences}),
                "occurrence_ids": {row["occurrence_id"] for row in occurrences},
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


def indexed_scan_findings(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
    through_scan: sqlite3.Row | None = None,
    include_resolved: bool = True,
    verification_occurrence_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    if not connection.execute(
        "SELECT 1 FROM finding_occurrences WHERE scan_id = ? LIMIT 1", (scan["id"],)
    ).fetchone():
        return {}
    identities = RepositoryIdentityCache(connection)
    scope = identities.scope_for_scan(scan) if scan["target_id"] else None
    if scan["target_id"] and not identities.supports_generation:
        scope = RepositoryScanScope(target_id=scan["target_id"], exact_target=True)
    elif scope is not None and identities.for_row(scan).missing:
        generation = scan["repository_generation"] if identities.supports_generation else None
        scope = RepositoryScanScope(generation=generation, target_id=scan["target_id"])
    allowed = (
        None
        if scope is not None
        else {
            row[0]
            for row in connection.execute(
                "SELECT id FROM scans WHERE target_id IS NULL AND target_path = ?",
                (scan["target_path"],),
            )
        }
    )
    through = (
        None
        if through_scan is None
        else connection.execute(
            "SELECT MAX(rowid) FROM scans WHERE id IN (?, ?)", (scan["id"], through_scan["id"])
        ).fetchone()[0]
    )
    indexed = _indexed_findings(
        connection,
        identities=identities,
        scan_scope=scope,
        allowed_scan_ids=allowed,
        through_scan_sequence=through,
        require_current_owners=True,
    )
    coverage_by_scan_id: dict[str, tuple[sqlite3.Row, dict[str, Any] | None]] = {}
    uncertain_occurrence_ids: set[str] | None = None

    def superseded_for_verification(finding, later_scan, finding_group):
        nonlocal uncertain_occurrence_ids
        if (
            finding["scan_sequence"] >= later_scan["scan_sequence"]
            or finding["indexed_target_id"] != later_scan["indexed_target_id"]
        ):
            return False
        if finding_group["decision_status"] == "open" and (
            later_scan["admission_sequence"] <= finding_group["decision_admission_sequence"]
            if finding_group["decision_admission_sequence"] is not None
            else (
                later_scan["scan_sequence"] <= finding_group["decision_scan_sequence"]
                if finding_group["decision_scan_sequence"] is not None
                else timestamp_key(later_scan["started_at"])
                <= timestamp_key(finding_group["decision_updated_at"])
            )
        ):
            return False
        if uncertain_occurrence_ids is None:
            admitted = json.dumps(sorted(finding_group["known_scan_ids"]))
            uncertain_occurrence_ids = {
                match[f"{side}OccurrenceId"]
                for comparison in connection.execute(
                    "SELECT result_json FROM scan_comparisons "
                    "WHERE before_scan_id IN (SELECT value FROM json_each(?)) "
                    "OR after_scan_id IN (SELECT value FROM json_each(?))",
                    (admitted, admitted),
                )
                for match in json.loads(comparison["result_json"]).get("uncertain", [])
                for side in ("before", "after")
            }
        if finding_group["occurrence_ids"] & uncertain_occurrence_ids:
            return False
        scan_id = later_scan["id"]
        if scan_id not in coverage_by_scan_id:
            scan = later_scan
            coverage = None
            if (
                scan["status"] == "complete"
                and scan["mode"] != "diff"
                and scan["seal_manifest_digest"] is not None
            ):
                try:
                    coverage = read_coverage(scan)
                except SystemExit as error:
                    cause: BaseException | None = error
                    while cause is not None and not isinstance(cause, FileNotFoundError):
                        cause = cause.__cause__
                    message = str(error)
                    if isinstance(cause, FileNotFoundError):
                        pass
                    elif message == (
                        "Scan directory must be an existing canonical non-symlink directory."
                    ):
                        try:
                            Path(scan["scan_dir"]).lstat()
                        except FileNotFoundError:
                            pass
                        else:
                            raise
                    elif not (
                        message.startswith("missing required contract artifact: ")
                        or message.endswith(": expected a regular file inside the scan directory.")
                    ):
                        raise
            coverage_by_scan_id[scan_id] = scan, coverage
        scan, coverage = coverage_by_scan_id[scan_id]
        return (
            coverage is not None
            and coverage.get("completeness", "complete") == "complete"
            and not coverage.get("deferred")
            and not any(
                surface.get("disposition") == "needs_follow_up"
                for surface in coverage.get("surfaces", [])
            )
            and scan_history.scan_covers_path(
                {**dict(scan), "target_id": later_scan["indexed_target_id"]},
                target_id=finding["indexed_target_id"],
                path=finding["location_path"],
                coverage=coverage,
            )
        )

    result = {}
    for row in indexed:
        row["active_occurrence_ids"] = row["occurrence_ids"]
        if verification_occurrence_id in row["occurrence_ids"]:
            verification_scans = connection.execute(
                "SELECT scans.*, rowid AS scan_sequence, "
                "(SELECT sequence FROM scan_admissions WHERE scan_id = scans.id) AS admission_sequence, "
                "COALESCE(target_id, target_path) AS indexed_target_id "
                "FROM scans WHERE id IN (SELECT value FROM json_each(?)) ORDER BY rowid DESC",
                (json.dumps(row["known_scan_ids"]),),
            ).fetchall()
            row["active_occurrence_ids"] = {
                item["occurrence_id"]
                for item in row["occurrences"]
                if not any(
                    superseded_for_verification(item, later, row) for later in verification_scans
                )
            }
        result.update(dict.fromkeys(row["occurrence_ids"], row))
    return result


def list_repositories(
    connection: sqlite3.Connection,
    args: argparse.Namespace | None = None,
    *,
    read_coverage: Callable | None = None,
) -> dict[str, Any]:
    """Return tracked targets with scan summaries, finding counts, and current checkout availability."""
    identities = RepositoryIdentityCache(connection)
    by_target: dict[str, dict[str, Any]] = {}
    scans_by_target: dict[str, list[sqlite3.Row]] = {}
    for row in connection.execute(
        f"""
        SELECT targets.id AS repository_id, targets.display_name, targets.current_path,
               {scan_history.SCAN_SUMMARY_COLUMNS}, scans.rowid AS scan_sequence
        FROM security_targets AS targets
        LEFT JOIN scans ON scans.target_id = targets.id
            AND scans.id IN (SELECT scan_id FROM scan_progress)
        LEFT JOIN scan_progress AS progress ON progress.scan_id = scans.id
        LEFT JOIN scan_lifecycles AS lifecycle ON lifecycle.scan_id = scans.id
        ORDER BY julianday(upper(scans.started_at)) DESC, scans.id DESC, targets.id
        """,
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
        if row["id"] is not None:
            scans_by_target.setdefault(target_id, []).append(row)

    @cache
    def populate_scan_summary(target_id: str) -> None:
        repository = by_target[target_id]
        latest = None
        for row in scans_by_target.get(target_id, []):
            if not scan_history.scan_has_current_owner(connection, row, identities):
                continue
            summary = scan_history.scan_summary(row)
            repository["scanCount"] += 1
            if latest is None or (
                latest["status"] == row["status"] == "complete"
                and scan_history._scan_completion_order(row)
                > scan_history._scan_completion_order(latest)
            ):
                latest = row
                repository["latestScan"] = summary

    legacy_generations = _legacy_generations(connection, identities)

    @cache
    def open_findings_count(target_id: str) -> int:
        populate_scan_summary(target_id)
        if not by_target[target_id]["scanCount"]:
            return 0
        scope = (
            identities.scope(target_id)
            if identities.supports_generation
            else RepositoryScanScope(target_id=target_id, exact_target=True)
        )
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
            and (args.status != "scanned" or repository["targetId"] in scans_by_target)
            and (args.status != "not_scanned" or repository["targetId"] not in scans_by_target)
            and (
                not query
                or query in repository["displayName"].casefold()
                or query in repository["targetPath"].casefold()
            )
            and (args.status != "open_findings" or open_findings_count(repository["targetId"]) > 0)
        ]
        if args.limit is not None or args.offset:
            limit = args.limit or DEFAULT_PAGE_SIZE
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
