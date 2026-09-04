"""Load reviewed false-positive feedback for a security scan."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from workbench_constants import (
    FINDING_LOCATION_PATH_BYTES,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
)
from workbench_native_indexes import _indexed_findings
from workbench_target_state import RepositoryIdentityCache, scan_repository_group
from workbench_validation import bounded_output_text


def get_scan_feedback(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    identities = RepositoryIdentityCache(connection)
    scope = identities.scope_for_scan(scan)
    if not scope.available:
        return {"scanId": scan["id"], "targetId": scan["target_id"], "falsePositives": []}

    indexed_findings = {
        (scan_repository_group(finding), finding_id): finding
        for finding in _indexed_findings(connection, identities=identities, scan_scope=scope)
        for finding_id in finding["matched_finding_ids"]
    }
    source_filter, source_values = scope.sql(
        "source_scans", supports_generation=identities.supports_generation
    )
    source_generation = (
        "source_scans.repository_generation" if identities.supports_generation else "NULL"
    )
    rows = connection.execute(
        f"""
        WITH ranked_decisions AS (
            SELECT findings.id AS finding_id, findings.fingerprint, findings.rule_id,
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
                    PARTITION BY findings.id, {source_generation},
                        CASE WHEN {source_generation} IS NULL THEN source_scans.target_id END
                    ORDER BY COALESCE(triage.updated_at, source_scans.completed_at) DESC,
                        source_scans.completed_at DESC,
                        source_scans.id DESC, occurrences.id DESC
                ) AS decision_rank
            FROM finding_occurrences AS occurrences
            JOIN findings ON findings.id = occurrences.finding_id
            JOIN scans AS source_scans ON source_scans.id = occurrences.scan_id
            LEFT JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
            JOIN finding_locations AS locations ON locations.id = (
                SELECT candidate.id
                FROM finding_locations AS candidate
                WHERE candidate.occurrence_id = occurrences.id
                ORDER BY CASE WHEN candidate.role = 'root_control' THEN 0 ELSE 1 END,
                    candidate.sort_order
                LIMIT 1
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
        ORDER BY updated_at DESC, source_completed_at DESC, source_scan_id DESC, finding_id DESC
        """,
        (*source_values, scan["id"]),
    )
    false_positives = []
    reviewed_components: set[str] = set()
    for row in rows:
        finding = indexed_findings.get((scan_repository_group(row), row["finding_id"]))
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
        if len(false_positives) == 50:
            break
    return {"scanId": scan["id"], "targetId": scan["target_id"], "falsePositives": false_positives}


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
