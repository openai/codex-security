from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import run_workbench


@pytest.mark.parametrize("existing_assessment", [False, True])
def test_read_only_classification_recovers_missing_legacy_rows(
    tmp_path: Path, workbench_api, existing_assessment: bool
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    database = state / "workbench.sqlite3"
    scan_id = "00000000-0000-4000-8000-000000000001"
    other_scan = "00000000-0000-4000-8000-000000000002"
    finding_ids = ["saved", "missing", "other-scan"]
    timestamp = "2026-09-01T00:00:00Z"
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        workbench_api["apply_schema_migrations"](
            connection,
            tuple(item for item in workbench_api["MIGRATIONS"] if item[0] <= 42),
            workbench_api["now"],
            workbench_api["backfill_security_targets"],
        )
        connection.execute(
            "INSERT INTO scan_severity_classifications (scan_id, finding_ids_json, assessed_at) "
            "VALUES (?, ?, ?)",
            (scan_id, json.dumps(finding_ids), timestamp),
        )
        for finding_id in finding_ids:
            connection.execute(
                "INSERT INTO findings "
                "(id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
                "VALUES (?, ?, 'rule', 'anchor', ?, ?)",
                (finding_id, finding_id, timestamp, timestamp),
            )
            original_scan = other_scan if finding_id == "other-scan" else scan_id
            occurrence = (
                "occ_" + hashlib.sha256(f"{original_scan}\0{finding_id}".encode()).hexdigest()[:24]
            )
            connection.execute(
                "INSERT INTO finding_severity_assessments "
                "(finding_id, occurrence_id, input_sha256, assessed_at, source, decision, "
                "level, rationale) VALUES (?, ?, 'digest', ?, 'existing-severity', "
                "'assessed', 'high', 'Legacy assessment')",
                (finding_id, occurrence, timestamp),
            )
        if existing_assessment:
            connection.execute(
                "INSERT INTO scan_severity_assessments "
                "SELECT ?, assessment.* FROM finding_severity_assessments AS assessment "
                "WHERE finding_id = 'saved'",
                (scan_id,),
            )
            connection.execute(
                "UPDATE scan_severity_assessments SET rationale = 'Current assessment'"
            )
    before = database.read_bytes()
    result = run_workbench(state, "read-severity-classification", "--scan-id", scan_id)
    assert [row["findingId"] for row in result["assessments"]] == ["saved", "missing"]
    assert result["assessments"][0]["rationale"] == (
        "Current assessment" if existing_assessment else "Legacy assessment"
    )
    assert result["assessments"][1]["rationale"] == "Legacy assessment"
    assert database.read_bytes() == before
