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
    PRIMARY_FINDING_LOCATION_SQL,
)
from workbench_native_indexes import _indexed_findings
from workbench_target_state import RepositoryIdentityCache
from workbench_validation import bounded_output_text


def get_scan_feedback(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    """Return reviewed false-positive decisions from other completed scans of the same target.

    For each finding, include the latest decision only if it closes the finding as a
    false positive with a nonblank reason. Prefer the root-control location in its preview.
    """
    identities = RepositoryIdentityCache(connection)
    scope = identities.scope_for_scan(scan)
    if not scope.available:
        return {"scanId": scan["id"], "targetId": scan["target_id"], "falsePositives": []}

    reviewed = {
        finding["decision_occurrence_id"]
        for finding in _indexed_findings(
            connection,
            identities=identities,
            scan_scope=scope,
            exclude_scan_id=scan["id"],
        )
        if finding["status"] == "closed" and finding["close_reason"] == "false_positive"
    }
    rows = connection.execute(
        f"""
        SELECT findings.id AS finding_id, findings.fingerprint, findings.rule_id,
            findings.identity_anchor, findings.identity_instance, occurrences.title,
            occurrences.summary, triage.note, triage.updated_at,
            source_scans.id AS source_scan_id,
            locations.relative_path, locations.start_line, locations.end_line, locations.role
        FROM finding_occurrences AS occurrences
        JOIN findings ON findings.id = occurrences.finding_id
        JOIN scans AS source_scans ON source_scans.id = occurrences.scan_id
        JOIN finding_triage AS triage ON triage.occurrence_id = occurrences.id
        JOIN finding_locations AS locations ON locations.id = (SELECT id {PRIMARY_FINDING_LOCATION_SQL})
        WHERE occurrences.id IN (SELECT value FROM json_each(?)) AND source_scans.id != ?
            AND (source_scans.status = 'complete' OR (source_scans.status = 'failed' AND source_scans.seal_manifest_digest IS NOT NULL))
            AND trim(triage.note) != ''
        ORDER BY julianday(upper(triage.updated_at)) DESC,
            julianday(upper(source_scans.completed_at)) DESC, source_scans.id DESC, findings.id DESC
        """,
        (json.dumps(sorted(reviewed)), scan["id"]),
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
