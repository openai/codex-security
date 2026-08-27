"""Scan history projection for the native Codex Security workbench."""

import argparse
import fnmatch
import json
import os
import sqlite3
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_projection import SEVERITY_ORDER
from workbench_constants import FINDINGS_PAGE_MAX
from workbench_scan_usage import stored_scan_cost_fields
from workbench_target import git_output


def _windows_path_key(value: str) -> str:
    return os.path.normcase(os.path.realpath(value))


def _same_repository(
    before: sqlite3.Row,
    after: sqlite3.Row,
    *,
    after_identity: tuple[str | None, tuple[str, str] | None] | None = None,
) -> bool:
    if before["target_id"] == after["target_id"]:
        return True
    before_target = Path(before["target_path"])
    after_target = Path(after["target_path"])
    before_git_dir = git_output(
        before_target, "rev-parse", "--path-format=absolute", "--git-common-dir"
    )
    after_git_dir = (
        git_output(after_target, "rev-parse", "--path-format=absolute", "--git-common-dir")
        if after_identity is None
        else after_identity[0]
    )
    if (
        before_git_dir is not None
        and after_git_dir is not None
        and Path(before_git_dir).resolve() == Path(after_git_dir).resolve()
    ):
        return True
    before_origin = _repository_origin(before_target)
    return before_origin is not None and before_origin == (
        _repository_origin(after_target) if after_identity is None else after_identity[1]
    )


def _repository_origin(target: Path) -> tuple[str, str] | None:
    remote = git_output(target, "remote", "get-url", "origin")
    if remote is None:
        return None
    if "://" in remote:
        try:
            parsed = urlsplit(remote)
            port = parsed.port
        except ValueError:
            return None
        if parsed.scheme not in {"https", "ssh"} or parsed.hostname is None:
            return None
        if parsed.query or parsed.fragment:
            return None
        host = parsed.hostname
        if port is not None and port != {"https": 443, "ssh": 22}[parsed.scheme]:
            host = f"{host}:{port}"
        path = parsed.path
    else:
        authority, separator, path = remote.partition(":")
        if not separator or "?" in path or "#" in path:
            return None
        host = authority.rsplit("@", 1)[-1]
    path = path.strip("/").removesuffix(".git")
    return (host.lower(), path) if host and path else None


def list_scans(
    connection: sqlite3.Connection, args: argparse.Namespace | None = None
) -> dict[str, Any]:
    if os.name == "nt":
        connection.create_function("codex_security_path_key", 1, _windows_path_key)
    clauses: list[str] = []
    values: list[Any] = []
    if args is not None and args.repository:
        repository = Path(args.repository).expanduser().resolve()
        requested_repository = connection.execute(
            """
            SELECT COALESCE((SELECT id FROM security_targets WHERE current_path = ?), '') AS target_id,
                ? AS target_path
            """,
            (str(repository), str(repository)),
        ).fetchone()
        requested_identity = (
            git_output(repository, "rev-parse", "--path-format=absolute", "--git-common-dir"),
            _repository_origin(repository),
        )
        related_target_ids = [
            target["target_id"]
            for target in connection.execute(
                "SELECT id AS target_id, current_path AS target_path FROM security_targets"
            )
            if _same_repository(target, requested_repository, after_identity=requested_identity)
        ]
        repository_clauses = ["scans.target_path = ?"]
        values.append(str(repository))
        if related_target_ids:
            placeholders = ", ".join("?" for _ in related_target_ids)
            repository_clauses.append(f"scans.target_id IN ({placeholders})")
            values.extend(related_target_ids)
        clauses.append(f"({' OR '.join(repository_clauses)})")
    if args is not None and args.scan_root:
        scan_root = str(Path(args.scan_root).expanduser().resolve())
        prefix = scan_root.rstrip(os.sep) + os.sep
        if os.name == "nt":
            scan_root = _windows_path_key(scan_root)
            prefix = scan_root.rstrip(os.sep) + os.sep
            clauses.append(
                "(codex_security_path_key(scans.scan_dir) = ? "
                "OR substr(codex_security_path_key(scans.scan_dir), 1, ?) = ?)"
            )
        else:
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
                **stored_scan_cost_fields(row["cost_json"]),
                "findingCount": row["finding_count"],
                "handoffStatus": row["handoff_status"],
                "mode": row["mode"],
                "model": row["model"],
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
                "reasoningEffort": row["reasoning_effort"],
                "scanDir": row["scan_dir"],
                "scanId": row["id"],
                "scope": row["scope"],
                "startedAt": row["started_at"],
                "targetId": row["target_id"],
                "targetPath": row["target_path"],
                "targetRevision": row["target_revision"],
                "targetSummary": row["target_summary"],
                "updatedAt": max(row["updated_at"], row["progress_updated_at"]),
                **(
                    {"warnings": json.loads(row["completion_warnings_json"])}
                    if row["completion_warnings_json"] != "[]"
                    else {}
                ),
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


def list_unmatched_scan_pairs(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    backfill_finding_details: Callable[[sqlite3.Connection, sqlite3.Row], None],
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
) -> dict[str, Any]:
    repository = Path(args.repository).expanduser().resolve()
    requested = connection.execute(
        """
        SELECT COALESCE((SELECT id FROM security_targets WHERE current_path = ?), '') AS target_id,
            ? AS target_path
        """,
        (str(repository), str(repository)),
    ).fetchone()
    selected = [
        scan
        for scan in connection.execute(
            "SELECT * FROM scans WHERE status = 'complete' ORDER BY started_at, id"
        )
        if Path(scan["target_path"]).resolve() == repository or _same_repository(scan, requested)
    ]

    available = []
    for scan in selected:
        try:
            read_coverage(scan)
        except SystemExit:
            continue
        available.append(scan)

    saved_pairs = {
        (row["before_scan_id"], row["after_scan_id"])
        for row in connection.execute("SELECT before_scan_id, after_scan_id FROM scan_comparisons")
    }
    batches = []
    skipped = 0
    matching_findings: dict[str, list[dict[str, Any]]] = {}
    for index, after in enumerate(available):
        previous = [
            before
            for before in available[:index]
            if args.force or (before["id"], after["id"]) not in saved_pairs
        ]
        skipped += index - len(previous)
        if not previous:
            continue
        for scan in (*previous, after):
            if scan["id"] not in matching_findings:
                backfill_finding_details(connection, scan)
                matching_findings[scan["id"]] = [
                    _matching_input(row)
                    for row in _scan_findings(connection, scan["id"]).values()
                ]
        batches.append(
            {
                "afterFindings": matching_findings[after["id"]],
                "afterScanId": after["id"],
                "beforeScans": [
                    {
                        "findings": matching_findings[before["id"]],
                        "scanId": before["id"],
                    }
                    for before in previous
                ],
            }
        )
    return {
        "batches": batches,
        "repository": str(repository),
        "scanCount": len(selected),
        "skippedPairs": skipped,
        "unavailableScans": len(selected) - len(available),
    }


def compare_scans(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
    backfill_finding_details: Callable[[sqlite3.Connection, sqlite3.Row], None] | None = None,
    include_matching_inputs: bool = False,
    require_matches: bool = False,
) -> dict[str, Any]:
    before = require_scan(connection, args.before_scan_id)
    after = require_scan(connection, args.after_scan_id)
    if before["id"] == after["id"]:
        raise SystemExit("Select two different scans to compare.")
    if before["status"] != "complete" or after["status"] != "complete":
        raise SystemExit("Only completed scans can be compared.")
    if not _same_repository(before, after):
        raise SystemExit("Semantic scan comparisons require the same repository target.")
    cached = connection.execute(
        "SELECT result_json FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
        (before["id"], after["id"]),
    ).fetchone()
    if cached is None and require_matches:
        reversed_comparison = connection.execute(
            "SELECT 1 FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
            (after["id"], before["id"]),
        ).fetchone()
        if reversed_comparison is not None:
            raise SystemExit(
                "These scans are in the wrong order. Run "
                f"'codex-security scans compare {after['id']} {before['id']}'."
            )
        raise SystemExit(
            "No saved matches for these scans. Run 'codex-security scans match BEFORE AFTER' first."
        )
    if include_matching_inputs and backfill_finding_details is not None:
        backfill_finding_details(connection, before)
        backfill_finding_details(connection, after)
    after_coverage = read_coverage(after)
    comparable = after_coverage.get("completeness") == "complete"
    before_findings = _scan_findings(connection, before["id"])
    after_findings = _scan_findings(connection, after["id"])
    matches = json.loads(cached["result_json"]) if cached is not None else None
    groups = _finding_groups(before_findings, after_findings, matches)
    uncertain = (
        {
            (side, match[f"{side}OccurrenceId"]): match["reason"]
            for match in matches.get("uncertain", [])
            for side in ("before", "after")
        }
        if matches is not None
        else {}
    )
    findings: list[dict[str, Any]] = []
    summary = {status: 0 for status in ("new", "persisting", "resolved", "reopened", "unknown")}

    for previous_rows, current_rows, match_reason in groups:
        previous = previous_rows[0] if previous_rows else None
        current = (
            min(current_rows, key=lambda row: SEVERITY_ORDER[row["severity"]])
            if current_rows
            else None
        )
        selected = current if current is not None else previous
        if selected is None:
            continue
        item = {
            "findingId": selected["finding_id"],
            "path": selected["relative_path"],
            "severity": selected["severity"],
            "title": selected["title"],
        }
        if previous is None:
            uncertain_reason = uncertain.get(("after", current["id"])) if current else None
            if uncertain_reason is None:
                status = "new"
            else:
                status = "unknown"
                item["reason"] = uncertain_reason
        elif current is not None:
            status = (
                "reopened"
                if any(
                    row["triage_status"] == "closed" and row["close_reason"] == "already_fixed"
                    for row in previous_rows
                )
                and any(row["triage_status"] == "open" for row in current_rows)
                else "persisting"
            )
            if match_reason is not None:
                item["matchReason"] = match_reason
        elif (uncertain_reason := uncertain.get(("before", previous["id"]))) is not None:
            status = "unknown"
            item["reason"] = uncertain_reason
        elif not comparable:
            status = "unknown"
            item["reason"] = "The later scan has incomplete coverage."
        elif not scan_covers_path(
            after,
            target_id=after["target_id"],
            path=previous["relative_path"],
            coverage=after_coverage,
        ):
            status = "unknown"
            item["reason"] = "The affected path was excluded or outside the later scope."
        else:
            status = "resolved"
        if len(previous_rows) == 1:
            item["beforeOccurrenceId"] = previous["id"]
        elif previous_rows:
            item["beforeOccurrenceIds"] = [row["id"] for row in previous_rows]
        if len(current_rows) == 1:
            item["afterOccurrenceId"] = current["id"]
        elif current_rows:
            item["afterOccurrenceIds"] = [row["id"] for row in current_rows]
        if current is not None:
            item["triage"] = {
                "closeReason": current["close_reason"],
                "status": current["triage_status"],
            }
        item["status"] = status
        findings.append(item)
        summary[status] += 1

    result = {
        "afterScanId": after["id"],
        "beforeScanId": before["id"],
        "comparable": comparable,
        "coverage": {"afterCompleteness": after_coverage.get("completeness")},
        "findings": findings,
        "repository": before["target_path"],
        "summary": summary,
    }
    if include_matching_inputs:
        result["matchingCached"] = cached is not None
        result["matchingInputs"] = {
            "before": [_matching_input(row) for row in before_findings.values()],
            "after": [_matching_input(row) for row in after_findings.values()],
        }
    return result


def save_scan_comparison(
    connection: sqlite3.Connection,
    args: argparse.Namespace,
    *,
    now: Callable[[], str],
    require_scan: Callable[[sqlite3.Connection, str], sqlite3.Row],
    read_coverage: Callable[[sqlite3.Row], dict[str, Any]],
) -> dict[str, Any]:
    before = require_scan(connection, args.before_scan_id)
    after = require_scan(connection, args.after_scan_id)
    if before["id"] == after["id"]:
        raise SystemExit("Select two different scans to compare.")
    if before["status"] != "complete" or after["status"] != "complete":
        raise SystemExit("Only completed scans can be compared.")
    if not _same_repository(before, after):
        raise SystemExit("Semantic scan comparisons require the same repository target.")
    read_coverage(after)
    before_findings = _scan_findings(connection, before["id"])
    after_findings = _scan_findings(connection, after["id"])
    matches_json = sys.stdin.read() if args.matches_json_stdin else args.matches_json
    try:
        payload = json.loads(matches_json)
    except (TypeError, ValueError) as exc:
        raise SystemExit("Scan comparison matches must be a valid JSON object.") from exc
    if not isinstance(payload, dict) or set(payload) != {"matches", "uncertain"}:
        raise SystemExit("Scan comparison matches must contain matches and uncertain arrays.")
    if not isinstance(payload["matches"], list) or not isinstance(payload["uncertain"], list):
        raise SystemExit("Scan comparison matches must contain matches and uncertain arrays.")
    allowed = {
        "before": {row["id"] for row in before_findings.values()},
        "after": {row["id"] for row in after_findings.values()},
    }
    consumed: dict[str, set[str]] = {"before": set(), "after": set()}
    for match in payload["matches"]:
        for side in ("before", "after"):
            occurrences = match[f"{side}OccurrenceIds"]
            unique = set(occurrences)
            if (
                not occurrences
                or len(unique) != len(occurrences)
                or not unique.issubset(allowed[side])
                or not consumed[side].isdisjoint(unique)
            ):
                raise SystemExit("Scan comparison matches must identify distinct scan findings.")
            consumed[side].update(unique)
    uncertain_pairs = set()
    for match in payload["uncertain"]:
        pair = (match["beforeOccurrenceId"], match["afterOccurrenceId"])
        if (
            pair[0] not in allowed["before"] - consumed["before"]
            or pair[1] not in allowed["after"] - consumed["after"]
            or pair in uncertain_pairs
        ):
            raise SystemExit("Uncertain scan comparison matches must identify distinct findings.")
        uncertain_pairs.add(pair)
    timestamp = now()
    with connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM scan_comparisons WHERE before_scan_id = ? AND after_scan_id = ?",
            (before["id"], after["id"]),
        )
        connection.execute(
            """
            INSERT INTO scan_comparisons (
                before_scan_id, after_scan_id, result_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                before["id"],
                after["id"],
                json.dumps(payload, allow_nan=False, sort_keys=True),
                timestamp,
                timestamp,
            ),
        )
        connection.executemany(
            """
            INSERT INTO scan_comparison_matches (
                before_scan_id, after_scan_id, before_occurrence_id, after_occurrence_id, reason
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                (before["id"], after["id"], previous, current, match["reason"])
                for match in payload["matches"]
                for previous in match["beforeOccurrenceIds"]
                for current in match["afterOccurrenceIds"]
            ),
        )
    return compare_scans(connection, args, require_scan=require_scan, read_coverage=read_coverage)


def finding_matches(
    connection: sqlite3.Connection, occurrence_id: str, scan_id: str, started_at: str
) -> tuple[list[dict[str, Any]], str, list[str]]:
    rows = connection.execute(
        """
        SELECT matches.after_scan_id AS scan_id, occurrences.id AS occurrence_id, occurrences.finding_id,
            occurrences.title, matches.reason
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS occurrences ON occurrences.id = matches.after_occurrence_id
        WHERE matches.before_occurrence_id = ?
        UNION
        SELECT matches.before_scan_id AS scan_id, occurrences.id AS occurrence_id, occurrences.finding_id,
            occurrences.title, matches.reason
        FROM scan_comparison_matches AS matches
        JOIN finding_occurrences AS occurrences ON occurrences.id = matches.before_occurrence_id
        WHERE matches.after_occurrence_id = ?
        ORDER BY scan_id, occurrence_id
        """,
        (occurrence_id, occurrence_id),
    ).fetchall()
    known_scans = [(started_at, scan_id)]
    if rows:
        known_scans = [
            (row["started_at"], row["scan_id"])
            for row in connection.execute(
                """
                WITH RECURSIVE linked_occurrences(occurrence_id) AS (
                    SELECT ?
                    UNION
                    SELECT CASE
                        WHEN matches.before_occurrence_id = linked.occurrence_id
                            THEN matches.after_occurrence_id
                        ELSE matches.before_occurrence_id
                    END
                    FROM scan_comparison_matches AS matches
                    JOIN linked_occurrences AS linked
                        ON matches.before_occurrence_id = linked.occurrence_id
                        OR matches.after_occurrence_id = linked.occurrence_id
                )
                SELECT DISTINCT scans.started_at, scans.id AS scan_id
                FROM linked_occurrences AS linked
                JOIN finding_occurrences AS occurrences ON occurrences.id = linked.occurrence_id
                JOIN scans ON scans.id = occurrences.scan_id
                ORDER BY scans.started_at, scans.id
                """,
                (occurrence_id,),
            )
        ]
    known_scan_ids = [known_scans[0][1]]
    if len(known_scans) > 1:
        known_scan_ids.append(known_scans[-1][1])
    return (
        [
            {
                "findingId": row["finding_id"],
                "occurrenceId": row["occurrence_id"],
                "reason": row["reason"],
                "scanId": row["scan_id"],
                "title": row["title"],
            }
            for row in rows
        ],
        known_scans[0][0],
        known_scan_ids,
    )


def _finding_groups(
    before_findings: dict[str, sqlite3.Row],
    after_findings: dict[str, sqlite3.Row],
    matches: dict[str, Any] | None,
) -> list[tuple[list[sqlite3.Row], list[sqlite3.Row], str | None]]:
    rows = {
        side: {row["id"]: row for row in findings.values()}
        for side, findings in (("before", before_findings), ("after", after_findings))
    }
    consumed: dict[str, set[str]] = {"before": set(), "after": set()}
    result = []
    for match in matches["matches"] if matches is not None else []:
        previous = [rows["before"][value] for value in match["beforeOccurrenceIds"]]
        current = [rows["after"][value] for value in match["afterOccurrenceIds"]]
        consumed["before"].update(match["beforeOccurrenceIds"])
        consumed["after"].update(match["afterOccurrenceIds"])
        result.append((previous, current, match["reason"]))
    result.extend(
        ([row], [], None) for key, row in rows["before"].items() if key not in consumed["before"]
    )
    result.extend(
        ([], [row], None) for key, row in rows["after"].items() if key not in consumed["after"]
    )
    return sorted(
        result,
        key=lambda group: (
            (group[1] or group[0])[0]["finding_id"],
            (group[1] or group[0])[0]["id"],
        ),
    )


def _matching_input(row: sqlite3.Row) -> dict[str, Any]:
    finding = json.loads(row["details_json"])
    return {
        **finding,
        "findingId": row["finding_id"],
        "occurrenceId": row["id"],
        "remediation": row["remediation"],
        "severity": {"level": row["severity"], **finding.get("severity", {})},
        "summary": row["summary"],
        "title": row["title"],
    }


def finding_occurrence_rows(
    connection: sqlite3.Connection,
    scan_id: str,
    *,
    offset: int,
    limit: int,
    query: str | None = None,
    severity: str | None = None,
    status: str | None = None,
) -> list[sqlite3.Row]:
    conditions, values = finding_occurrence_conditions(
        scan_id, query=query, severity=severity, status=status
    )
    return connection.execute(
        f"""
        SELECT
            occurrences.id,
            occurrences.finding_id,
            occurrences.title,
            occurrences.summary,
            occurrences.severity,
            occurrences.confidence,
            occurrences.remediation,
            occurrences.details_json,
            occurrences.created_at
        FROM finding_occurrences AS occurrences
        LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        WHERE {conditions}
        ORDER BY
            CASE occurrences.severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                WHEN 'informational' THEN 4
                ELSE 5
            END,
            occurrences.created_at,
            occurrences.id
        LIMIT ? OFFSET ?
        """,
        (*values, limit, offset),
    ).fetchall()


def finding_occurrence_conditions(
    scan_id: str,
    *,
    query: str | None,
    severity: str | None,
    status: str | None,
) -> tuple[str, list[str]]:
    conditions = ["occurrences.scan_id = ?"]
    values = [scan_id]
    if severity is not None:
        conditions.append("occurrences.severity = ?")
        values.append(severity)
    if status is not None:
        conditions.append("COALESCE(triage.status, 'open') = ?")
        values.append(status)
    if query:
        search = query.strip().casefold()
        if search:
            conditions.append(
                "(instr(lower(occurrences.title), ?) > 0 "
                "OR instr(lower(occurrences.summary), ?) > 0 "
                "OR EXISTS ("
                "SELECT 1 FROM finding_locations AS locations "
                "WHERE locations.occurrence_id = occurrences.id "
                "AND instr(lower(locations.relative_path), ?) > 0))"
            )
            values.extend((search, search, search))
    return " AND ".join(conditions), values


def _scan_findings(connection: sqlite3.Connection, scan_id: str) -> dict[str, sqlite3.Row]:
    rows = connection.execute(
        """
        SELECT occurrences.*,
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
