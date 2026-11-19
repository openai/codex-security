"""Replay reviewed scan findings from accepted checkpoints and their final seal."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from collections.abc import Iterable, Iterator
from itertools import count, islice
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _derived_finding_identity_rows,
    finding_candidate_id,
    finding_within_scope,
)
from workbench.retained_records import _ensure_finding_identities
from workbench.saved_sources import _latest_iteration, _read_saved_result
from workbench_constants import (
    FINDING_LOCATION_PATH_BYTES,
    FINDING_LOCATIONS_LIMIT,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
    FINDING_VALIDATION_PREVIEW_BYTES,
    FINDINGS_PAGE_MAX,
)
from workbench_scan_history import read_history_seal
from workbench_source_scopes import requested_exclude_paths
from workbench_validation import bounded_output_text

_FINAL_FEED_WARNING = (
    "Could not save final finding updates. The feed will replay the indexed result."
)


def _supports_feed(scan: sqlite3.Row) -> bool:
    return scan["mode"] in {"standard", "diff", "deep"} and scan["launch_kind"] != "import"


def preview(finding: dict[str, Any]) -> dict[str, Any]:
    validation = finding.get("validation") or {}
    summary = validation.get("summary", "") if isinstance(validation, dict) else ""
    return {
        "title": bounded_output_text(finding["title"], FINDING_TITLE_BYTES),
        "summary": bounded_output_text(finding["summary"], FINDING_SUMMARY_BYTES),
        "severity": finding["severity"]["level"],
        "validation": bounded_output_text(summary, FINDING_VALIDATION_PREVIEW_BYTES),
        "locations": [
            {
                "file": bounded_output_text(row["path"], FINDING_LOCATION_PATH_BYTES),
                "line": row["startLine"],
            }
            for row in finding["locations"][:FINDING_LOCATIONS_LIMIT]
        ],
    }


def record_finding_updates(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    manifest: dict[str, Any],
    findings: dict[str, Any],
    *,
    final: bool,
) -> None:
    """Append semantic changes under the caller's serialized publication transaction."""
    if not _supports_feed(scan):
        return
    scan_data = manifest["scan"]
    if scan_data.get("scope", {}).get("validationMode") == "custom_pending":
        return
    if not final and json.loads(scan["recipe_json"] or "{}").get("validationMode") == "custom":
        return
    if final:
        # Completion already verified and indexed these identities.
        findings_by_id = ((finding["findingId"], finding) for finding in findings["findings"])
    else:
        findings_by_id = (
            (finding_id, finding)
            for _, finding, finding_id, _, _ in _derived_finding_identity_rows(manifest, findings)
        )
    # Deep batches and final results replace the full set. Other checkpoints
    # withdraw only the candidates explicitly rejected by this review.
    rejected = None
    if not final and scan["mode"] != "deep":
        rejected = {
            surface["candidateId"]
            for surface in scan_data.get("reviewState", {}).get("surfaces", [])
            if surface.get("disposition") in {"rejected", "not_applicable"}
            and surface.get("candidateId")
        }
    connection.executemany(
        """INSERT INTO scan_finding_updates
           (scan_id,cursor,finding_id,candidate_id,kind,preview_json,fields_json,changed_json)
           VALUES (:scan_id,:cursor,:finding_id,:candidate_id,:kind,:preview_json,:fields_json,:changed_json)""",
        _finding_changes(connection, scan["id"], findings_by_id, final=final, rejected=rejected),
    )


def _finding_changes(
    connection: sqlite3.Connection,
    scan_id: str,
    findings_by_id: Iterable[tuple[str, dict[str, Any]]],
    *,
    final: bool,
    rejected: set[str] | None = None,
) -> Iterator[dict[str, Any]]:
    # SQLite returns the columns from the row attaining MAX(cursor); cursors are unique.
    rows = connection.execute(
        """SELECT finding_id, candidate_id, preview_json, fields_json, kind, MAX(cursor) AS cursor
           FROM scan_finding_updates WHERE scan_id = ? GROUP BY finding_id ORDER BY finding_id""",
        (scan_id,),
    )
    previous = {row["finding_id"]: row for row in rows}
    cursors = count(max((row["cursor"] for row in previous.values()), default=0) + 1)
    for finding_id, finding in findings_by_id:
        old = previous.pop(finding_id, None)
        hashes = _assessment_hashes(finding)
        previous_kind = old["kind"] if old is not None else None
        changed = []
        if previous_kind not in {None, "withdrawn"}:
            prior = json.loads(old["fields_json"])
            changed = sorted(
                key for key in prior.keys() | hashes.keys() if prior.get(key) != hashes.get(key)
            )
        kind = None
        if final and previous_kind != "finalized":
            kind = "finalized"
        elif previous_kind in {None, "withdrawn"}:
            kind = "reviewed"
        if not kind and not changed:
            continue
        entry = {
            "scan_id": scan_id,
            "finding_id": finding_id,
            "candidate_id": finding_candidate_id(finding),
            "preview_json": json.dumps(preview(finding), allow_nan=False, sort_keys=True),
            "fields_json": json.dumps(hashes),
            "changed_json": None,
        }
        if changed:
            yield {
                **entry,
                "kind": "updated",
                "changed_json": json.dumps(changed),
                "cursor": next(cursors),
            }
        if kind:
            yield {**entry, "kind": kind, "cursor": next(cursors)}

    for row in previous.values():
        if row["kind"] != "withdrawn" and (rejected is None or row["candidate_id"] in rejected):
            yield {
                **row,
                "scan_id": scan_id,
                "cursor": next(cursors),
                "kind": "withdrawn",
                "changed_json": None,
            }


def _assessment_hashes(finding: dict[str, Any]) -> dict[str, str]:
    hashes = {}
    for key, value in finding.items():
        if key in {"occurrenceId", "findingId", "fingerprints"}:
            continue
        if key == "provenance" and isinstance(value, dict):
            # Saved draft revisions aren't changes to the current assessment.
            value = {name: item for name, item in value.items() if name != "previousFindings"}
        hashes[key] = hashlib.sha256(
            json.dumps(value, allow_nan=False, sort_keys=True).encode()
        ).hexdigest()
    return hashes


def record_final_finding_updates(connection, scan, manifest, findings, warnings):
    """Keep an auxiliary write failure from rolling back a valid scan and its index."""
    connection.execute("SAVEPOINT final_finding_updates")
    try:
        record_finding_updates(connection, scan, manifest, findings, final=True)
    except (sqlite3.Error, ValueError, KeyError, TypeError) as exc:
        if not connection.in_transaction:
            raise
        connection.execute("ROLLBACK TO final_finding_updates")
        warnings.append(f"{_FINAL_FEED_WARNING} {exc}")
    connection.execute("RELEASE final_finding_updates")


def record_deep_iteration_updates(connection, scan, run, result_path, requested_finding_scope):
    """Journal the selected cumulative pass inside the transaction admitting its workers."""
    root = Path(scan["scan_dir"])
    if run["manifest_path"] == str(root / "scan-manifest.json"):
        return
    connection.execute("SAVEPOINT deep_iteration_updates")
    try:
        selected = _latest_iteration(
            connection.execute(
                "SELECT * FROM deep_scan_workers WHERE scan_id = ? AND kind = 'dedup'",
                (scan["id"],),
            )
        )
        if selected is None or selected["result_manifest_path"] != result_path:
            return
        draft, _, _ = _read_saved_result(
            root, Path(result_path).relative_to(root).as_posix(), scan["id"], kind="dedup"
        )
        if draft.get("complete") is False:
            return
        scope = requested_finding_scope(scan)
        exclusions = requested_exclude_paths(scan)
        findings = [f for f in draft["findings"] if finding_within_scope(f, scope, exclusions)]
        # The terminal publisher allocates identities after filtering the union.
        _ensure_finding_identities(findings, deep=True)
        manifest = {
            "scan": {
                "id": scan["id"],
                "target": {"targetId": scan["target_id"]},
                "scope": draft.get("scope", {}),
            }
        }
        record_finding_updates(
            connection,
            scan,
            manifest,
            {"scanId": scan["id"], "findings": findings},
            final=False,
        )
    except (sqlite3.Error, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        if not connection.in_transaction:
            raise
        connection.execute("ROLLBACK TO deep_iteration_updates")
        print(f"Could not record Deep Scan finding updates: {exc}", file=sys.stderr)
    finally:
        if connection.in_transaction:
            connection.execute("RELEASE deep_iteration_updates")


def list_finding_updates(
    wb: Any, connection: sqlite3.Connection, args: argparse.Namespace
) -> dict[str, Any]:
    # Observe status and the last page under the same SQLite snapshot.
    connection.execute("BEGIN")
    with connection:
        scan = wb.require_scan(connection, args.scan_id)
        return finding_update_page(wb, connection, scan, args.after_cursor, args.limit)


def finding_update_page(
    wb: Any, connection: sqlite3.Connection, scan: sqlite3.Row, after: int, limit: int
) -> dict[str, Any]:
    if not _supports_feed(scan):
        raise SystemExit(
            "Live finding updates are available for local Standard, diff, and Deep scans."
        )
    if limit > FINDINGS_PAGE_MAX:
        raise SystemExit(f"Finding updates limit cannot exceed {FINDINGS_PAGE_MAX}.")
    rows = connection.execute(
        """SELECT cursor, finding_id, kind, preview_json, changed_json FROM scan_finding_updates
           WHERE scan_id = ? AND cursor > ? ORDER BY cursor LIMIT ?""",
        (scan["id"], after, limit + 1),
    ).fetchall()
    # A failed optional terminal write leaves the live history intact. Reconstruct
    # only its missing suffix from the immutable occurrence index, including withdrawals.
    replay_terminal = scan["status"] == "complete" and any(
        warning.startswith(_FINAL_FEED_WARNING)
        for warning in json.loads(scan["completion_warnings_json"])
    )
    if (
        scan["status"] == "complete"
        and not rows
        and not connection.execute(
            "SELECT 1 FROM scan_finding_updates WHERE scan_id = ? LIMIT 1", (scan["id"],)
        ).fetchone()
    ):
        updates = _indexed_updates(
            wb, connection, scan, after, limit + 1, legacy=not replay_terminal
        )
    else:
        if replay_terminal and len(rows) <= limit:
            indexed = connection.execute(
                "SELECT finding_id, details_json FROM finding_occurrences WHERE scan_id = ? ORDER BY id",
                (scan["id"],),
            )
            findings_by_id = ((r["finding_id"], json.loads(r["details_json"])) for r in indexed)
            suffix = _finding_changes(connection, scan["id"], findings_by_id, final=True)
            remaining = limit + 1 - len(rows)
            rows.extend(islice((row for row in suffix if row["cursor"] > after), remaining))
        updates = []
        for row in rows:
            update = {
                "cursor": row["cursor"],
                "findingId": row["finding_id"],
                "kind": row["kind"],
                **json.loads(row["preview_json"]),
            }
            if row["changed_json"]:
                update["changedFields"] = json.loads(row["changed_json"])
            updates.append(update)
    page = updates[:limit]
    return {
        "scanId": scan["id"],
        "status": "canceled" if scan["canceled_at"] else scan["status"],
        "updates": page,
        "nextCursor": page[-1]["cursor"] if page else after,
        "hasMore": len(updates) > limit,
    }


def _indexed_updates(wb, connection, scan, after, limit, *, legacy):
    """A scan with no live journal has one final event per indexed occurrence."""
    indexed = connection.execute(
        """SELECT id, finding_id, title, severity, summary, details_json
           FROM finding_occurrences WHERE scan_id = ? ORDER BY id LIMIT ? OFFSET ?""",
        (scan["id"], limit, after),
    ).fetchall()
    if not indexed:
        return []
    if legacy:
        # Older indexes do not say whether custom validation was still pending.
        try:
            scan_dir = wb.require_canonical_scan_directory(Path(scan["scan_dir"]))
            sealed_scan, _ = read_history_seal(wb, scan, scan_dir)
        except (ContractError, OSError, SystemExit):
            return []
        if sealed_scan["scope"].get("validationMode") == "custom_pending":
            return []
    updates = []
    for i, row in enumerate(indexed, after + 1):
        finding = json.loads(row["details_json"])
        if not finding:
            locations = connection.execute(
                "SELECT relative_path AS path, start_line AS startLine FROM finding_locations "
                "WHERE occurrence_id = ? ORDER BY sort_order LIMIT ?",
                (row["id"], FINDING_LOCATIONS_LIMIT),
            )
            finding = {
                "title": row["title"],
                "summary": row["summary"],
                "severity": {"level": row["severity"]},
                "locations": [dict(location) for location in locations],
            }
        updates.append(
            {
                "cursor": i,
                "findingId": row["finding_id"],
                "kind": "finalized",
                **preview(finding),
            }
        )
    return updates


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
