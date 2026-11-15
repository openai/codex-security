"""Persist finding triage decisions and load reviewed false-positive feedback for a scan."""

from __future__ import annotations

import argparse
import sqlite3
import sys
import uuid
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from workbench_constants import (
    FINDING_LOCATION_PATH_BYTES,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
    PRIMARY_FINDING_LOCATION_SQL,
)
from workbench_native_indexes import _indexed_findings, _legacy_generations
from workbench_target_state import RepositoryIdentityCache
from workbench_validation import bounded_output_text


def record_finding_decision(
    connection: sqlite3.Connection,
    occurrence_id: str,
    status: str,
    close_reason: str | None,
    note: str | None,
    fixed_revision: str | None,
    timestamp: str,
) -> None:
    """Record a change to the current triage state and append its audit entry in the caller's transaction."""
    previous_triage = connection.execute(
        "SELECT status, close_reason, note, fixed_revision FROM finding_triage WHERE occurrence_id = ?",
        (occurrence_id,),
    ).fetchone()
    # A client that only knows the legacy fields can replay a close after evidence was added.
    if (
        fixed_revision is None
        and close_reason == "already_fixed"
        and previous_triage is not None
        and previous_triage["fixed_revision"] is not None
        and note in (None, previous_triage["note"])
    ):
        fixed_revision = previous_triage["fixed_revision"]
        note = previous_triage["note"]
    decision = (status, close_reason, note, fixed_revision)
    if previous_triage is not None and tuple(previous_triage) == decision:
        return
    connection.execute(
        """
        INSERT INTO finding_decisions (
            id, occurrence_id, status, close_reason, note, fixed_revision, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), occurrence_id, *decision, timestamp),
    )
    connection.execute(
        """
        INSERT INTO finding_triage (occurrence_id, status, close_reason, note, fixed_revision, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(occurrence_id) DO UPDATE SET
            status = excluded.status,
            close_reason = excluded.close_reason,
            note = excluded.note,
            fixed_revision = excluded.fixed_revision,
            updated_at = excluded.updated_at
        """,
        (occurrence_id, *decision, timestamp),
    )


def get_scan_feedback(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    """Return reviewed false-positive decisions from other completed scans of the same target.

    For each finding, include the latest decision only if it closes the finding as a
    false positive with a nonblank reason. Prefer the root-control location in its preview.
    """
    identities = RepositoryIdentityCache(connection)
    scope = identities.scope_for_scan(scan)
    if not scope.available:
        return {"scanId": scan["id"], "targetId": scan["target_id"], "falsePositives": []}

    legacy_generations = _legacy_generations(connection, identities)
    indexed_findings = {
        occurrence_id: finding
        for finding in _indexed_findings(
            connection,
            identities=identities,
            scan_scope=scope,
            legacy_generations=legacy_generations,
        )
        for occurrence_id in finding["matched_occurrence_ids"]
    }
    source_filter, source_values = scope.sql(
        "source_scans", supports_generation=identities.supports_generation
    )
    source_generation = (
        "source_scans.repository_generation" if identities.supports_generation else "NULL"
    )
    legacy_generation = legacy_generations.get(scope.target_id)
    decision_generation = (
        f"COALESCE({source_generation}, ?)" if legacy_generation is not None else source_generation
    )
    decision_values = (
        (legacy_generation, legacy_generation) if legacy_generation is not None else ()
    )
    rows = connection.execute(
        f"""
        WITH ranked_decisions AS (
            SELECT occurrences.id AS occurrence_id, findings.id AS finding_id, findings.fingerprint, findings.rule_id,
                findings.identity_anchor, findings.identity_instance, occurrences.title,
                occurrences.summary, COALESCE(triage.status, 'open') AS triage_status,
                triage.close_reason, triage.note,
                COALESCE(triage.updated_at, source_scans.completed_at) AS updated_at,
                source_scans.id AS source_scan_id,
                source_scans.target_id,
                {source_generation} AS repository_generation,
                source_scans.completed_at AS source_completed_at,
                locations.relative_path, locations.start_line, locations.end_line, locations.role,
                ROW_NUMBER() OVER (
                    PARTITION BY findings.id, {decision_generation},
                        CASE WHEN {decision_generation} IS NULL THEN source_scans.target_id END
                    ORDER BY
                        julianday(upper(COALESCE(triage.updated_at, source_scans.completed_at))) DESC,
                        julianday(upper(source_scans.completed_at)) DESC,
                        source_scans.id DESC, occurrences.id DESC
                ) AS decision_rank
            FROM finding_occurrences AS occurrences
            JOIN findings ON findings.id = occurrences.finding_id
            JOIN scans AS source_scans ON source_scans.id = occurrences.scan_id
            LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
            JOIN finding_locations AS locations ON locations.id = (
                SELECT id {PRIMARY_FINDING_LOCATION_SQL}
            )
            WHERE {source_filter}
                AND source_scans.id != ?
                AND source_scans.status = 'complete'
        )
        SELECT *
        FROM ranked_decisions
        WHERE decision_rank = 1
            AND triage_status = 'closed'
            AND close_reason = 'false_positive'
            AND note IS NOT NULL
            AND trim(note) != ''
        ORDER BY julianday(upper(updated_at)) DESC,
            julianday(upper(source_completed_at)) DESC,
            source_scan_id DESC, finding_id DESC
        """,
        (*decision_values, *source_values, scan["id"]),
    )
    false_positives = []
    reviewed_components: set[str] = set()
    for row in rows:
        finding = indexed_findings.get(row["occurrence_id"])
        if (
            finding is None
            or finding["status"] != "closed"
            or finding["close_reason"] != "false_positive"
            or finding["occurrence_id"] in reviewed_components
        ):
            continue
        reviewed_components.add(finding["occurrence_id"])

        identity = {"anchor": row["identity_anchor"]}
        if row["identity_instance"] is not None:
            identity["instance"] = row["identity_instance"]
        location = {
            "path": bounded_output_text(row["relative_path"], FINDING_LOCATION_PATH_BYTES),
            "startLine": row["start_line"],
            "endLine": row["end_line"],
        }
        if row["role"] is not None:
            location["role"] = row["role"]
        false_positives.append(
            {
                "findingId": row["finding_id"],
                "fingerprint": row["fingerprint"],
                "ruleId": row["rule_id"],
                "identity": identity,
                "title": bounded_output_text(row["title"], FINDING_TITLE_BYTES),
                "summary": bounded_output_text(row["summary"], FINDING_SUMMARY_BYTES),
                "reason": row["note"],
                "locations": [location],
                "sourceScanId": row["source_scan_id"],
                "updatedAt": row["updated_at"],
            }
        )
    return {"scanId": scan["id"], "targetId": scan["target_id"], "falsePositives": false_positives}


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
