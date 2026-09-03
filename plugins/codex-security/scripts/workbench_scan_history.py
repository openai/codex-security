"""Scan history projection for the native Codex Security workbench."""

import argparse
import fnmatch
import json
import os
import sqlite3
import sys
from collections.abc import Iterable, Iterator
from itertools import chain
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
    if before["target_id"] is not None and before["target_id"] == after["target_id"]:
        return True
    before_target = Path(before["target_path"])
    after_target = Path(after["target_path"])
    if before_target.resolve() == after_target.resolve():
        return True
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
        if _same_repository(scan, requested)
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
    known_links: list[sqlite3.Row] | None = None
    for index, after in enumerate(available):
        previous = [
            before
            for before in available[:index]
            if args.force or (before["id"], after["id"]) not in saved_pairs
        ]
        skipped += index - len(previous)
        if not previous:
            continue
        if known_links is None:
            known_links = (
                []
                if args.force
                else _saved_finding_links(connection, {scan["id"] for scan in selected})
            )
        for scan in (*previous, after):
            if scan["id"] not in matching_findings:
                backfill_finding_details(connection, scan)
                matching_findings[scan["id"]] = [
                    _matching_input(row) for row in _scan_findings(connection, scan["id"]).values()
                ]
        known_groups = _known_finding_groups(
            known_links,
            {
                scan["id"]
                for scan in selected
                if (scan["started_at"], scan["id"]) <= (after["started_at"], after["id"])
            },
        )
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
                **({"knownFindingGroups": known_groups} if known_groups else {}),
            }
        )
    return {
        "batches": batches,
        "repository": str(repository),
        "scanCount": len(selected),
        "skippedPairs": skipped,
        "unavailableScans": len(selected) - len(available),
    }


def _saved_finding_links(connection: sqlite3.Connection, scan_ids: set[str]) -> list[sqlite3.Row]:
    return [
        row
        for row in _rows_for_ids(
            connection,
            """
            SELECT before.scan_id AS before_scan_id, before.finding_id AS before_finding_id,
                after.scan_id AS after_scan_id, after.finding_id AS after_finding_id
            FROM scan_comparison_matches AS matches
            JOIN finding_occurrences AS before ON before.id = matches.before_occurrence_id
            JOIN finding_occurrences AS after ON after.id = matches.after_occurrence_id
            WHERE matches.before_scan_id IN ({placeholders})
            ORDER BY matches.before_scan_id, after.scan_id, before.finding_id, after.finding_id
            """,
            sorted(scan_ids),
        )
        if row["before_scan_id"] in scan_ids and row["after_scan_id"] in scan_ids
    ]


def _finding_aliases(links: Iterable[tuple[str, str]]) -> dict[str, str]:
    parents: dict[str, str] = {}

    def root(value: str) -> str:
        parents.setdefault(value, value)
        while parents[value] != value:
            parents[value] = parents[parents[value]]
            value = parents[value]
        return value

    for before_id, after_id in links:
        parents[root(after_id)] = root(before_id)
    return {finding_id: root(finding_id) for finding_id in parents}


def _known_finding_groups(links: list[sqlite3.Row], scan_ids: set[str]) -> list[list[str]]:
    aliases = _finding_aliases(
        (link["before_finding_id"], link["after_finding_id"])
        for link in links
        if link["before_scan_id"] in scan_ids and link["after_scan_id"] in scan_ids
    )
    groups: dict[str, list[str]] = {}
    for finding_id, identity in aliases.items():
        groups.setdefault(identity, []).append(finding_id)
    return sorted(sorted(group) for group in groups.values() if len(group) > 1)


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
    saved_matches = matches["matches"] if matches is not None else []
    occurrences = {
        row["id"]: row for row in chain(before_findings.values(), after_findings.values())
    }
    aliases = _confirmed_finding_aliases(connection, occurrences)
    groups = _finding_groups(before_findings, after_findings, saved_matches, aliases)
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
        previous = (
            min(previous_rows, key=lambda row: SEVERITY_ORDER[row["severity"]])
            if previous_rows
            else None
        )
        current = (
            min(current_rows, key=lambda row: SEVERITY_ORDER[row["severity"]])
            if current_rows
            else None
        )
        selected = current if current is not None else previous
        item = {
            "findingId": selected["finding_id"],
            "path": selected["relative_path"],
            "severity": selected["severity"],
            "title": selected["title"],
        }
        side = "after" if current_rows else "before"
        uncertain_reason = next(
            (
                uncertain[(side, row["id"])]
                for row in current_rows or previous_rows
                if (side, row["id"]) in uncertain
            ),
            None,
        )
        if previous is None:
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
        elif uncertain_reason is not None:
            status = "unknown"
            item["reason"] = uncertain_reason
        elif not comparable:
            status = "unknown"
            item["reason"] = "The later scan has incomplete coverage."
        elif not all(
            scan_covers_path(
                after,
                target_id=after["target_id"],
                path=row["relative_path"],
                coverage=after_coverage,
            )
            for row in previous_rows
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
    if matches is not None and matches.get("related"):
        related = _separate_finding_pairs(matches["related"], occurrences, aliases)
        if related:
            result["related"] = [
                {
                    **pair,
                    "beforeTitle": occurrences[pair["beforeOccurrenceId"]]["title"],
                    "afterTitle": occurrences[pair["afterOccurrenceId"]]["title"],
                }
                for pair in related
            ]
    if include_matching_inputs:
        known_scan_ids = {
            scan["id"]
            for scan in connection.execute(
                "SELECT * FROM scans WHERE status = 'complete' "
                "AND (started_at < ? OR (started_at = ? AND id <= ?))",
                (after["started_at"], after["started_at"], after["id"]),
            )
            if _same_repository(scan, after)
        }
        excluded_pairs = {(before["id"], after["id"]), (after["id"], before["id"])}
        known_groups = _known_finding_groups(
            [
                link
                for link in _saved_finding_links(connection, known_scan_ids)
                if (link["before_scan_id"], link["after_scan_id"]) not in excluded_pairs
            ],
            known_scan_ids,
        )
        result["matchingCached"] = cached is not None
        result["matchingInputs"] = {
            "before": [_matching_input(row) for row in before_findings.values()],
            "after": [_matching_input(row) for row in after_findings.values()],
            **({"knownFindingGroups": known_groups} if known_groups else {}),
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
    matches_json = (
        sys.stdin.read() if getattr(args, "matches_json_stdin", False) else args.matches_json
    )
    try:
        payload = json.loads(matches_json)
    except (TypeError, ValueError) as exc:
        raise SystemExit("Scan comparison matches must be a valid JSON object.") from exc
    if (
        not isinstance(payload, dict)
        or not {"matches", "uncertain"}.issubset(payload)
        or set(payload) - {"matches", "uncertain", "related"}
    ):
        raise SystemExit("Scan comparison matches must contain matches and uncertain arrays.")
    if any(
        not isinstance(payload.get(key, []), list) for key in ("matches", "uncertain", "related")
    ):
        raise SystemExit("Scan comparison matches must contain matches and uncertain arrays.")
    allowed = {
        "before": {row["id"] for row in before_findings.values()},
        "after": {row["id"] for row in after_findings.values()},
    }
    consumed: dict[str, dict[str, int]] = {"before": {}, "after": {}}
    for group, match in enumerate(payload["matches"]):
        if (
            not isinstance(match, dict)
            or match.get("confidence") != "high"
            or not isinstance(match.get("reason"), str)
            or not match["reason"].strip()
        ):
            raise SystemExit("Scan comparison matches must have high confidence and a reason.")
        for side in ("before", "after"):
            occurrences = match.get(f"{side}OccurrenceIds")
            if not isinstance(occurrences, list) or any(
                not isinstance(value, str) for value in occurrences
            ):
                raise SystemExit("Scan comparison matches must identify distinct scan findings.")
            unique = set(occurrences)
            if (
                not occurrences
                or len(unique) != len(occurrences)
                or not unique.issubset(allowed[side])
                or not unique.isdisjoint(consumed[side])
            ):
                raise SystemExit("Scan comparison matches must identify distinct scan findings.")
            consumed[side].update((occurrence_id, group) for occurrence_id in unique)
    uncertain_pairs = set()
    for match in payload["uncertain"]:
        if not _valid_finding_pair(match):
            raise SystemExit("Uncertain scan comparison matches must identify distinct findings.")
        pair = (match["beforeOccurrenceId"], match["afterOccurrenceId"])
        if (
            pair[0] not in allowed["before"]
            or pair[0] in consumed["before"]
            or pair[1] not in allowed["after"]
            or pair[1] in consumed["after"]
            or pair in uncertain_pairs
        ):
            raise SystemExit("Uncertain scan comparison matches must identify distinct findings.")
        uncertain_pairs.add(pair)
    related_pairs = set()
    for match in payload.get("related", []):
        if not _valid_finding_pair(match):
            raise SystemExit("Related scan comparison findings must identify distinct findings.")
        pair = (match["beforeOccurrenceId"], match["afterOccurrenceId"])
        group = consumed["before"].get(pair[0])
        if (
            pair[0] not in allowed["before"]
            or pair[1] not in allowed["after"]
            or (group is not None and group == consumed["after"].get(pair[1]))
            or pair in uncertain_pairs
            or pair in related_pairs
        ):
            raise SystemExit("Related scan comparison findings must identify distinct findings.")
        related_pairs.add(pair)
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


def _valid_finding_pair(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"beforeOccurrenceId", "afterOccurrenceId", "reason"}
        and all(isinstance(item, str) and item.strip() for item in value.values())
    )


def _rows_for_ids(
    connection: sqlite3.Connection, query: str, ids: Iterable[str]
) -> Iterator[sqlite3.Row]:
    values = tuple(dict.fromkeys(ids))
    getlimit = getattr(connection, "getlimit", None)
    # Python 3.10 lacks getlimit; 999 is SQLite's older host-parameter limit.
    limit = getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER) if getlimit else 999
    for start in range(0, len(values), limit):
        batch = values[start : start + limit]
        yield from connection.execute(
            query.format(placeholders=", ".join("?" for _ in batch)), batch
        )


# Stable finding IDs already include the target identity. Follow their indexed
# occurrences instead of resolving repository paths or scanning every saved link.
_FINDING_NEIGHBORS_SQL = """
    FROM linked
    CROSS JOIN finding_occurrences AS source
        ON source.finding_id = linked.finding_id
    CROSS JOIN scan_comparison_matches AS matches
        ON matches.before_occurrence_id = source.id OR matches.after_occurrence_id = source.id
    CROSS JOIN finding_occurrences AS neighbor ON neighbor.id = CASE
        WHEN matches.before_occurrence_id = source.id THEN matches.after_occurrence_id
        ELSE matches.before_occurrence_id END
"""
# Traverse only the selected findings' components, including recurring stable IDs.
_LINKED_FINDINGS_SQL = f"""
    WITH RECURSIVE linked(finding_id) AS (
        SELECT occurrences.finding_id
        FROM finding_occurrences AS occurrences
        WHERE occurrences.id IN ({{placeholders}})
        UNION
        SELECT neighbor.finding_id
        {_FINDING_NEIGHBORS_SQL}
    )
"""


def _confirmed_finding_aliases(
    connection: sqlite3.Connection, occurrence_ids: Iterable[str]
) -> dict[str, str]:
    query = f"""
        {_LINKED_FINDINGS_SQL}
        SELECT DISTINCT linked.finding_id AS before_finding_id,
            neighbor.finding_id AS after_finding_id
        {_FINDING_NEIGHBORS_SQL}
    """
    return _finding_aliases(
        (row["before_finding_id"], row["after_finding_id"])
        for row in _rows_for_ids(connection, query, occurrence_ids)
    )


def _separate_finding_pairs(
    pairs: list[dict[str, Any]],
    occurrences: dict[str, sqlite3.Row],
    aliases: dict[str, str],
) -> list[dict[str, Any]]:
    def identity(occurrence_id: str) -> str:
        finding_id = occurrences[occurrence_id]["finding_id"]
        return aliases.get(finding_id, finding_id)

    return [
        pair
        for pair in pairs
        if identity(pair["beforeOccurrenceId"]) != identity(pair["afterOccurrenceId"])
    ]


def finding_relations(
    connection: sqlite3.Connection, scan_id: str, occurrence_ids: Iterable[str]
) -> dict[str, list[dict[str, Any]]]:
    selected = set(occurrence_ids)
    if not selected:
        return {}
    pairs = []
    for comparison in connection.execute(
        "SELECT before_scan_id, after_scan_id, result_json FROM scan_comparisons "
        "WHERE before_scan_id = ? OR after_scan_id = ? "
        "ORDER BY before_scan_id, after_scan_id",
        (scan_id, scan_id),
    ):
        side = "before" if comparison["before_scan_id"] == scan_id else "after"
        other = "after" if side == "before" else "before"
        for pair in json.loads(comparison["result_json"]).get("related", []):
            if pair[f"{side}OccurrenceId"] in selected:
                pairs.append(
                    {
                        "beforeOccurrenceId": pair[f"{side}OccurrenceId"],
                        "afterOccurrenceId": pair[f"{other}OccurrenceId"],
                        "afterScanId": comparison[f"{other}_scan_id"],
                        "reason": pair["reason"],
                    }
                )
    occurrences = {
        row["id"]: row
        for row in _rows_for_ids(
            connection,
            "SELECT id, finding_id, scan_id, title FROM finding_occurrences "
            "WHERE id IN ({placeholders})",
            (pair[key] for pair in pairs for key in ("beforeOccurrenceId", "afterOccurrenceId")),
        )
    }
    pairs = [
        pair
        for pair in pairs
        if pair["beforeOccurrenceId"] in occurrences
        and occurrences[pair["beforeOccurrenceId"]]["scan_id"] == scan_id
        and pair["afterOccurrenceId"] in occurrences
        and occurrences[pair["afterOccurrenceId"]]["scan_id"] == pair["afterScanId"]
    ]
    result: dict[str, list[dict[str, Any]]] = {}
    aliases = _confirmed_finding_aliases(connection, (pair["beforeOccurrenceId"] for pair in pairs))
    for pair in _separate_finding_pairs(pairs, occurrences, aliases):
        finding = occurrences[pair["afterOccurrenceId"]]
        result.setdefault(pair["beforeOccurrenceId"], []).append(
            {
                "findingId": finding["finding_id"],
                "occurrenceId": finding["id"],
                "reason": pair["reason"],
                "scanId": pair["afterScanId"],
                "title": finding["title"],
            }
        )
    return result


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
    linked_rows = list(
        _rows_for_ids(
            connection,
            f"""
            {_LINKED_FINDINGS_SQL}
            SELECT occurrences.id AS occurrence_id, occurrences.finding_id, occurrences.title,
                scans.started_at, scans.id AS scan_id
            FROM linked
            CROSS JOIN finding_occurrences AS occurrences
                ON occurrences.finding_id = linked.finding_id
            CROSS JOIN scans ON scans.id = occurrences.scan_id
            """,
            (occurrence_id,),
        )
    )
    known_scans = sorted(
        {(started_at, scan_id)} | {(row["started_at"], row["scan_id"]) for row in linked_rows}
    )
    included = {occurrence_id, *(row["occurrence_id"] for row in rows)}
    rows.extend(
        {
            **row,
            "reason": "The findings share a stable identity or a previously confirmed link.",
        }
        for row in linked_rows
        if row["occurrence_id"] not in included
    )
    rows.sort(key=lambda row: (row["scan_id"], row["occurrence_id"]))
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
    matches: list[dict[str, Any]],
    aliases: dict[str, str],
) -> list[tuple[list[sqlite3.Row], list[sqlite3.Row], str | None]]:
    rows = {
        side: {row["id"]: row for row in findings.values()}
        for side, findings in (("before", before_findings), ("after", after_findings))
    }
    groups: dict[str, tuple[list[sqlite3.Row], list[sqlite3.Row], list[str]]] = {}

    def group(row: sqlite3.Row) -> tuple[list[sqlite3.Row], list[sqlite3.Row], list[str]]:
        finding_id = row["finding_id"]
        return groups.setdefault(aliases.get(finding_id, finding_id), ([], [], []))

    for match in matches:
        group(rows["before"][match["beforeOccurrenceIds"][0]])[2].append(match["reason"])
    for index, side in enumerate(("before", "after")):
        occurrence_ids = dict.fromkeys(
            chain(
                (value for match in matches for value in match[f"{side}OccurrenceIds"]),
                rows[side],
            )
        )
        for occurrence_id in occurrence_ids:
            row = rows[side][occurrence_id]
            group(row)[index].append(row)
    result = [
        (
            previous,
            current,
            (
                " ".join(dict.fromkeys(reasons))
                if reasons
                else "The findings share a stable identity or a previously confirmed link."
            )
            if previous and current
            else None,
        )
        for previous, current, reasons in groups.values()
    ]
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
