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
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]] | None = None,
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
    repository = getattr(args, "repository", None)
    indexed_findings = (
        _indexed_findings(connection)
        if read_coverage is None
        else _indexed_active_findings(
            connection,
            read_coverage,
            target_ids=target_ids,
            target_paths=target_paths,
            repository=repository,
            query=query,
            include_resolved=getattr(args, "include_resolved", False),
        )
    )
    findings = (
        row
        for row in indexed_findings
        if (
            (target_ids is None and target_paths is None)
            or (target_ids is not None and row["target_id"] in target_ids)
            or (target_paths is not None and row["target_path"] in target_paths)
        )
        and (args.severity is None or row["severity"] == args.severity)
        and (args.status is None or row["status"] == args.status)
        and (
            not query
            or row.get(
                "active_query_match",
                any(
                    query in value.casefold()
                    for value in (row["title"], row["summary"], row["location_path"])
                    if value is not None
                ),
            )
            or (
                target_ids is None
                and target_paths is None
                and repository is None
                and query in row["target_path"].casefold()
            )
            or row.get("secondary_location_match", 0)
        )
    )
    rows = list(islice(findings, args.offset, args.offset + limit + 1))
    has_more = len(rows) > limit
    return {
        "findings": [
            {
                "confirmedInLatestScan": row.get("confirmed_in_latest_scan", True),
                "createdAt": row["created_at"],
                "findingId": row["finding_id"],
                "knownSince": row.get("known_since", row["scan_started_at"]),
                "knownScanIds": row.get("known_scan_ids", [row["scan_id"]]),
                "locationPath": row["location_path"],
                "matchedFindingIds": row.get("matched_finding_ids", [row["finding_id"]]),
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


def _indexed_findings(
    connection: sqlite3.Connection,
    allowed_scan_ids: set[str] | None = None,
    *,
    allow_cross_target_matches: bool = False,
) -> Iterator[dict[str, Any]]:
    parents: dict[tuple[str, str], tuple[str, str]] = {}
    compatible_scan_pairs: dict[tuple[str, str], bool] = {}
    include_targetless = allowed_scan_ids is not None

    def target_identity(alias: str) -> str:
        if include_targetless:
            return f"COALESCE({alias}.target_id, {alias}.target_path)"
        return f"{alias}.target_id"

    target_join = "LEFT JOIN" if include_targetless else "JOIN"
    target_path = (
        "COALESCE(targets.current_path, scans.target_path)"
        if include_targetless
        else "targets.current_path"
    )
    legacy_matches = (
        "OR (before_scans.target_id IS NULL AND after_scans.target_id IS NULL "
        "AND before_scans.target_path = after_scans.target_path)"
        if include_targetless
        else ""
    )

    def group(identity: tuple[str, str]) -> tuple[str, str]:
        while identity in parents:
            identity = parents[identity]
        return identity

    for match in connection.execute(
        f"""
        SELECT {target_identity("before_scans")} AS before_target_id,
            {target_identity("after_scans")} AS after_target_id,
            before_scans.id AS before_scan_id, after_scans.id AS after_scan_id,
            before.finding_id AS before_finding_id, after.finding_id AS after_finding_id
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
        JOIN scans AS before_scans ON before_scans.id = before.scan_id
        JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
        JOIN scans AS after_scans ON after_scans.id = after.scan_id
        WHERE before_scans.target_id = after_scans.target_id
            {legacy_matches}
            OR (? AND before_scans.target_id IS NOT NULL AND after_scans.target_id IS NOT NULL)
        """,
        (allow_cross_target_matches,),
    ):
        if allowed_scan_ids is not None and (
            match["before_scan_id"] not in allowed_scan_ids
            or match["after_scan_id"] not in allowed_scan_ids
        ):
            continue
        if match["before_target_id"] != match["after_target_id"]:
            pair = (match["before_scan_id"], match["after_scan_id"])
            if pair not in compatible_scan_pairs:
                scans = [
                    connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
                    for scan_id in pair
                ]
                compatible_scan_pairs[pair] = scan_history._same_registered_repository(
                    connection, *scans
                )
            if not compatible_scan_pairs[pair]:
                continue
        before = group((match["before_target_id"], match["before_finding_id"]))
        after = group((match["after_target_id"], match["after_finding_id"]))
        if before != after:
            parents[after] = before

    latest_scan_by_target = {
        row["indexed_target_id"]: row["id"]
        for row in connection.execute(
            f"SELECT {target_identity('scans')} AS indexed_target_id, id FROM scans "
            "WHERE status = 'complete' ORDER BY rowid"
        )
        if allowed_scan_ids is None or row["id"] in allowed_scan_ids
    }

    grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
    for row in connection.execute(
        f"""
        SELECT
            occurrences.id AS occurrence_id,
            occurrences.finding_id,
            occurrences.severity,
            occurrences.created_at,
            scans.id AS scan_id,
            scans.started_at AS scan_started_at,
            scans.rowid AS scan_sequence,
            scans.target_id,
            {target_identity("scans")} AS indexed_target_id,
            {target_path} AS target_path,
            scans.scope,
            MAX(scans.updated_at, COALESCE(triage.updated_at, '')) AS updated_at,
            triage.status AS decision_status,
            triage.close_reason,
            triage.updated_at AS decision_updated_at,
            COALESCE(
                (SELECT MAX(decisions.rowid)
                 FROM finding_decisions AS decisions
                 WHERE decisions.occurrence_id = occurrences.id),
                triage.rowid
            ) AS decision_sequence,
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
        {target_join} security_targets AS targets ON targets.id = scans.target_id
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        WHERE targets.id IS NOT NULL OR scans.target_id IS NULL
        """
    ):
        if allowed_scan_ids is None or row["scan_id"] in allowed_scan_ids:
            grouped.setdefault(group((row["indexed_target_id"], row["finding_id"])), []).append(row)

    findings = []
    for occurrences in grouped.values():
        latest = max(
            occurrences,
            key=lambda row: (row["scan_sequence"], row["created_at"], row["occurrence_id"]),
        )
        decision = max(
            (row for row in occurrences if row["decision_status"] is not None),
            key=lambda row: (row["decision_sequence"], row["occurrence_id"]),
            default=None,
        )
        status = decision["decision_status"] if decision is not None else "open"
        if (
            status == "closed"
            and decision["close_reason"] == "already_fixed"
            and latest["scan_sequence"] > decision["scan_sequence"]
        ):
            status = "open"
        scans = sorted(
            {
                (row["scan_sequence"], row["scan_started_at"], row["scan_id"])
                for row in occurrences
            }
        )
        findings.append(
            {
                **dict(latest),
                "confirmed_in_latest_scan": latest_scan_by_target.get(latest["indexed_target_id"])
                == latest["scan_id"],
                "decision_occurrence_id": decision["occurrence_id"] if decision is not None else None,
                "known_since": scans[0][1],
                "known_scan_ids": [scan_id for _, _, scan_id in scans],
                "matched_finding_ids": sorted({row["finding_id"] for row in occurrences}),
                "occurrence_count": len(occurrences),
                "occurrence_ids": {row["occurrence_id"] for row in occurrences},
                "status": status,
                "updated_at": max(
                    latest["updated_at"],
                    decision["decision_updated_at"] if decision is not None else "",
                ),
            }
        )

    yield from _sorted_findings(findings)


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings.sort(key=lambda finding: finding["occurrence_id"])
    findings.sort(
        key=lambda finding: (
            finding["status"] == "open",
            -scan_history.SEVERITY_ORDER.get(finding["severity"], 5),
            finding["created_at"],
        ),
        reverse=True,
    )
    return findings


def _indexed_active_findings(
    connection: sqlite3.Connection,
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
    **settings: Any,
) -> Iterator[dict[str, Any]]:
    allowed_scan_ids: set[str] = set()
    query = settings.get("query", "")
    active = {
        row["occurrence_id"]: row
        for row in _active_findings(
            connection,
            read_coverage,
            allowed_scan_ids=allowed_scan_ids,
            **settings,
        )
    }
    combined = []
    for row in _indexed_findings(
        connection,
        allowed_scan_ids,
        allow_cross_target_matches=bool(settings.get("repository")),
    ):
        matched = [
            active.pop(occurrence_id)
            for occurrence_id in row["occurrence_ids"]
            if occurrence_id in active
        ]
        if matched:
            representative = max(
                matched,
                key=lambda finding: (
                    finding["scan_sequence"],
                    finding["created_at"],
                    finding["occurrence_id"],
                ),
            )
            combined.append(
                {
                    **row,
                    **representative,
                    "status": row["status"],
                    "updated_at": row["updated_at"],
                    "occurrence_count": row["occurrence_count"],
                    "active_query_match": any(
                        query in finding["title"].casefold()
                        or query in finding["summary"].casefold()
                        for finding in matched
                    ),
                    "secondary_location_match": any(
                        finding["secondary_location_match"] for finding in matched
                    ),
                }
            )
    combined.extend(active.values())
    yield from _sorted_findings(combined)


def _active_findings(
    connection: sqlite3.Connection,
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
    *,
    target_ids: set[str] | None = None,
    target_paths: set[str] | None = None,
    repository: str | None = None,
    query: str = "",
    include_resolved: bool = False,
    allowed_scan_ids: set[str] | None = None,
) -> Iterator[dict[str, Any]]:
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
    repository_clauses, repository_values, _, _ = (
        scan_history.repository_scan_scope(connection, repository)
        if repository is not None
        else ([], [], [], [])
    )
    repository_filter = (
        "AND (" + " AND ".join(repository_clauses) + ")" if repository_clauses else ""
    )
    target_values.extend(repository_values)
    connection.create_function(
        "codex_security_path_contains",
        2,
        lambda root, path: Path(path).is_relative_to(root),
        deterministic=True,
    )
    current_owner_only = (
        "AND NOT (scans.target_id IS NULL AND EXISTS ("
        "SELECT 1 FROM security_targets AS path_owner "
        "WHERE codex_security_path_contains(path_owner.current_path, scans.target_path)))"
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
            "ORDER BY ownership_scan.rowid DESC LIMIT 1"
        )
        current_owner_only += (
            " AND (scans.target_id IS NULL "
            "OR (scans.target_device IS NULL AND scans.target_inode IS NULL) OR ("
            f"scans.target_device IS (SELECT ownership_scan.target_device {latest_identity}) "
            f"AND scans.target_inode IS (SELECT ownership_scan.target_inode {latest_identity})"
            "))"
        )
        replaced_targets = []
        transitioned_targets = []
        ownership_epochs = []
        for target in connection.execute("SELECT id, current_path FROM security_targets"):
            checkout = Path(target["current_path"])
            if not checkout.exists():
                recorded_ownership = scan_history._recorded_target_ownership(
                    connection, target["id"]
                )
                if recorded_ownership is not None and recorded_ownership[1] is not None:
                    transitioned_targets.append(target["id"])
                    ownership_epochs.append((target["id"], recorded_ownership[1]))
                continue
            verified = scan_history._verified_target_metadata(connection, target["id"], checkout)
            if verified is None:
                replaced_targets.append(target["id"])
            elif verified[0] is not None:
                epoch_start = scan_history._ownership_epoch_start(
                    connection, target["id"], verified[0]
                )
                if epoch_start is not None:
                    transitioned_targets.append(target["id"])
                    ownership_epochs.append((target["id"], epoch_start))
        if replaced_targets:
            placeholders = ", ".join("?" for _ in replaced_targets)
            current_owner_only += (
                f" AND (scans.target_id IS NULL OR scans.target_id NOT IN ({placeholders}))"
            )
            target_values.extend(replaced_targets)
        if transitioned_targets:
            placeholders = ", ".join("?" for _ in transitioned_targets)
            current_owner_only += (
                " AND (scans.target_id IS NULL "
                f"OR scans.target_id NOT IN ({placeholders}) "
                "OR scans.target_device IS NOT NULL OR scans.target_inode IS NOT NULL)"
            )
            target_values.extend(transitioned_targets)
        for target_id, epoch_start in ownership_epochs:
            current_owner_only += " AND (scans.target_id IS NOT ? OR scans.rowid > ?)"
            target_values.extend((target_id, epoch_start))
    completed_scans_by_target: dict[str, list[sqlite3.Row]] = {}
    for scan in connection.execute(
        f"""
        SELECT scans.*, scans.rowid AS scan_sequence,
            COALESCE(targets.id, scans.target_path) AS indexed_target_id
        FROM scans
        LEFT JOIN security_targets AS targets ON targets.id = scans.target_id
        WHERE scans.status = 'complete'
            {target_filter} {repository_filter} {current_owner_only}
        ORDER BY scans.rowid DESC
        """,
        target_values,
    ):
        completed_scans_by_target.setdefault(scan["indexed_target_id"], []).append(scan)
        if allowed_scan_ids is not None:
            allowed_scan_ids.add(scan["id"])

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
                scans.seal_manifest_digest,
                scans.started_at AS scan_started_at,
                scans.rowid AS scan_sequence,
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
                    ORDER BY scans.rowid DESC,
                        occurrences.created_at DESC, occurrences.id DESC
                ) AS occurrence_rank
            FROM finding_occurrences AS occurrences
            JOIN scans ON scans.id = occurrences.scan_id
            LEFT JOIN security_targets AS targets ON targets.id = scans.target_id
            LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
            WHERE 1 = 1 {target_filter} {repository_filter} {current_owner_only}
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
        completed_scans = completed_scans_by_target.get(row["indexed_target_id"], ())
        finding = {
            **dict(row),
            "confirmed_in_latest_scan": (
                completed_scans[0]["id"] == row["scan_id"] if completed_scans else True
            ),
        }
        if include_resolved:
            if allowed_scan_ids is not None and row["seal_manifest_digest"] is not None:
                allowed_scan_ids.add(row["scan_id"])
            yield finding
            continue
        resolved = False
        for scan in completed_scans:
            if scan["scan_sequence"] <= row["scan_sequence"]:
                break
            if scan["seal_manifest_digest"] is None:
                continue
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
                    elif message.startswith("missing required contract artifact: ") or message.endswith(
                        ": expected a regular file inside the scan directory."
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
            if allowed_scan_ids is not None and row["seal_manifest_digest"] is not None:
                allowed_scan_ids.add(row["scan_id"])
            yield finding


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
        "SELECT id, target_id FROM scans ORDER BY rowid DESC"
    ):
        latest_scan_by_target.setdefault(row["target_id"], scans_by_id[row["id"]])

    open_findings_by_target = Counter(
        row["target_id"]
        for row in _indexed_active_findings(connection, read_coverage)
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
