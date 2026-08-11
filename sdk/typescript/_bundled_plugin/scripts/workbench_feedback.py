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

from finalize_scan_contract import write_scan_local_bytes
from workbench_constants import (
    FINDING_LOCATION_PATH_BYTES,
    FINDING_SUMMARY_BYTES,
    FINDING_TITLE_BYTES,
)
from workbench_validation import bounded_output_text


def get_scan_feedback(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    rows = connection.execute(
        """
        WITH ranked_decisions AS (
            SELECT occurrences.id AS occurrence_id,
                findings.id AS finding_id, findings.fingerprint, findings.rule_id,
                findings.identity_anchor, findings.identity_instance, occurrences.title,
                occurrences.summary, COALESCE(triage.status, 'open') AS triage_status,
                triage.close_reason, triage.note,
                COALESCE(triage.updated_at, source_scans.completed_at) AS updated_at,
                source_scans.id AS source_scan_id,
                source_scans.completed_at AS source_completed_at,
                locations.relative_path, locations.start_line, locations.end_line, locations.role,
                ROW_NUMBER() OVER (
                    PARTITION BY findings.id
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
            WHERE source_scans.target_id = ?
                AND source_scans.id != ?
                AND source_scans.status = 'complete'
        )
        SELECT ranked_decisions.*, occurrences.details_json
        FROM ranked_decisions
        JOIN finding_occurrences AS occurrences ON occurrences.id = ranked_decisions.occurrence_id
        WHERE decision_rank = 1
            AND (triage_status = 'open' OR (close_reason = 'false_positive' AND trim(note) != ''))
        ORDER BY updated_at DESC, source_completed_at DESC, source_scan_id DESC, finding_id DESC
        """,
        (scan["target_id"], scan["id"]),
    )
    false_positives = []
    previous_findings = []
    for row in rows:
        if row["triage_status"] == "open":
            previous_findings.append(
                json.loads(row["details_json"])
                or {
                    "findingId": row["finding_id"],
                    "ruleId": row["rule_id"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "locations": [
                        {
                            "path": row["relative_path"],
                            "startLine": row["start_line"],
                            "endLine": row["end_line"],
                        }
                    ],
                }
            )
            continue
        if len(false_positives) == 50:
            continue
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
    return {
        "scanId": scan["id"],
        "targetId": scan["target_id"],
        "falsePositives": false_positives,
        "previousFindings": previous_findings,
    }


def write_scan_feedback(connection: sqlite3.Connection, scan: sqlite3.Row) -> None:
    feedback = get_scan_feedback(connection, scan)
    for filename, findings in (
        ("false_positive_feedback.json", feedback["falsePositives"]),
        ("previous_findings.json", feedback["previousFindings"]),
    ):
        if findings:
            write_scan_local_bytes(
                Path(scan["scan_dir"]),
                f"artifacts/01_context/{filename}",
                (json.dumps(findings, allow_nan=False) + "\n").encode(),
            )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
