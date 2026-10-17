"""Load reviewed false-positive feedback for a security scan."""

from __future__ import annotations

import argparse
import json
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
from workbench_finding_results import finding_triage_result
from workbench_native_indexes import _indexed_findings
from workbench_scan_history import saved_repository_target_ids
from workbench_validation import bounded_output_text


def get_scan_feedback(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    connection.create_function(
        "codex_security_finding_group",
        2,
        lambda occurrence_id, finding_id: f"finding:{finding_id}",
        deterministic=True,
    )
    source_ids = {
        row["id"]
        for row in connection.execute(
            "SELECT id FROM scans WHERE (status = 'complete' "
            "OR (status = 'failed' AND seal_manifest_digest IS NOT NULL)) AND id != ? "
            "AND target_id IN (SELECT value FROM json_each(?))",
            (scan["id"], json.dumps(sorted(saved_repository_target_ids(connection, scan)))),
        )
    }
    closed_decisions = {}
    for finding in _indexed_findings(connection, source_ids, allow_cross_target_matches=True):
        triage = finding_triage_result(connection, finding["occurrence_id"], finding)
        if triage["status"] == "closed" and triage.get("closeReason") == "false_positive":
            closed_decisions.update(
                (finding_id, triage) for finding_id in finding["matched_finding_ids"]
            )
    connection.create_function(
        "codex_security_feedback_note",
        1,
        lambda finding_id: closed_decisions.get(finding_id, {}).get("note"),
        deterministic=True,
    )
    connection.create_function(
        "codex_security_feedback_updated_at",
        1,
        lambda finding_id: closed_decisions.get(finding_id, {}).get("updatedAt"),
        deterministic=True,
    )
    rows = connection.execute(
        """
        WITH ranked_decisions AS (
            SELECT findings.id AS finding_id, findings.fingerprint, findings.rule_id,
                findings.identity_anchor, findings.identity_instance, occurrences.title,
                occurrences.summary, codex_security_feedback_note(findings.id) AS note,
                COALESCE(codex_security_feedback_updated_at(findings.id),
                    source_scans.completed_at) AS updated_at,
                source_scans.id AS source_scan_id,
                source_scans.completed_at AS source_completed_at,
                locations.relative_path, locations.start_line, locations.end_line, locations.role,
                ROW_NUMBER() OVER (
                    PARTITION BY findings.id
                    ORDER BY julianday(upper(COALESCE(codex_security_feedback_updated_at(findings.id),
                            source_scans.completed_at))) DESC,
                        julianday(upper(source_scans.completed_at)) DESC,
                        source_scans.id DESC, occurrences.id DESC
                ) AS decision_rank
            FROM finding_occurrences AS occurrences
            JOIN findings ON findings.id = occurrences.finding_id
            JOIN scans AS source_scans ON source_scans.id = occurrences.scan_id
            JOIN finding_locations AS locations ON locations.id = (
                SELECT candidate.id
                FROM finding_locations AS candidate
                WHERE candidate.occurrence_id = occurrences.id
                ORDER BY CASE WHEN candidate.role = 'root_control' THEN 0 ELSE 1 END,
                    candidate.sort_order
                LIMIT 1
            )
            WHERE source_scans.target_id = ?
                AND source_scans.id != ?
                AND source_scans.id IN (SELECT value FROM json_each(?))
                AND findings.id IN (SELECT value FROM json_each(?))
        )
        SELECT *
        FROM ranked_decisions
        WHERE decision_rank = 1
            AND note IS NOT NULL
            AND trim(note) != ''
        ORDER BY julianday(upper(updated_at)) DESC,
            julianday(upper(source_completed_at)) DESC,
            source_scan_id DESC, finding_id DESC
        LIMIT 50
        """,
        (
            scan["target_id"],
            scan["id"],
            json.dumps(sorted(source_ids)),
            json.dumps(sorted(closed_decisions)),
        ),
    )
    false_positives = []
    for row in rows:
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
