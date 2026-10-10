"""Reusable severity checkpoints and the assessments saved for each scan."""

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

# Some plugin hosts launch Python with safe-path isolation enabled.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_finding_index import upsert_finding

FIELDS = {
    "findingId": "finding_id",
    "occurrenceId": "occurrence_id",
    "inputSha256": "input_sha256",
    "rubricSha256": "rubric_sha256",
    "knowledgeBaseSha256": "knowledge_base_sha256",
    "assessedAt": "assessed_at",
    "source": "source",
    "decision": "decision",
    "level": "level",
    "rubricLabel": "rubric_label",
    "rationale": "rationale",
    "confidence": "confidence",
    "reviewTrigger": "review_trigger",
}


def assessments(
    connection: sqlite3.Connection, finding_ids: list[str], scan_id: str | None = None
) -> list[dict[str, Any]]:
    table = "finding_severity_assessments" if scan_id is None else "scan_severity_assessments"
    scope = "" if scan_id is None else "WHERE assessment.scan_id = ?"
    parameters = (
        (json.dumps(finding_ids),) if scan_id is None else (json.dumps(finding_ids), scan_id)
    )
    # Keep selected IDs first so each assessment is a primary-key lookup.
    rows = connection.execute(
        f"""SELECT assessment.* FROM json_each(?) AS selected
        CROSS JOIN {table} AS assessment ON assessment.finding_id = selected.value
        {scope} ORDER BY selected.key""",
        parameters,
    )
    return [{key: row[column] for key, column in FIELDS.items()} for row in rows]


def checkpoint(
    connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    if payload["action"] == "begin":
        with connection:
            connection.execute(
                """INSERT INTO scan_severity_classifications (
                    scan_id, finding_ids_json, assessed_at, rubric_sha256, knowledge_base_sha256
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    finding_ids_json = excluded.finding_ids_json,
                    assessed_at = excluded.assessed_at,
                    rubric_sha256 = excluded.rubric_sha256,
                    knowledge_base_sha256 = excluded.knowledge_base_sha256""",
                (
                    payload["scanId"],
                    json.dumps(payload["findingIds"]),
                    payload["assessedAt"],
                    payload["rubricSha256"],
                    payload["knowledgeBaseSha256"],
                ),
            )
            rows = connection.execute(
                """SELECT * FROM (
                    SELECT assessment.*, selected.key AS finding_order,
                        ROW_NUMBER() OVER (PARTITION BY assessment.finding_id
                            ORDER BY (assessment.scan_id = ?) DESC, assessment.assessed_at DESC, assessment.scan_id) AS rank
                    FROM json_each(?) AS selected
                    JOIN scan_severity_assessments AS assessment
                        ON assessment.finding_id = selected.key
                        AND assessment.input_sha256 = selected.value
                    WHERE assessment.rubric_sha256 IS ?
                        AND assessment.knowledge_base_sha256 IS ?
                ) WHERE rank = 1 ORDER BY finding_order""",
                (
                    payload["scanId"],
                    json.dumps(payload["inputs"]),
                    payload["rubricSha256"],
                    payload["knowledgeBaseSha256"],
                ),
            )
            return {
                "assessments": [
                    {key: row[column] for key, column in FIELDS.items()} for row in rows
                ]
            }
    if payload["action"] != "save":
        raise SystemExit("Unknown severity checkpoint action.")
    finding = payload["finding"]
    assessment = {**payload["assessment"], "assessedAt": timestamp}
    with connection:
        # External scan directories may not have been indexed on this machine.
        if (
            connection.execute(
                "SELECT 1 FROM findings WHERE id = ?", (finding["findingId"],)
            ).fetchone()
            is None
        ):
            upsert_finding(connection, finding, timestamp)
        row = {
            "scan_id": payload["scanId"],
            **{column: assessment[key] for key, column in FIELDS.items()},
        }
        columns = ", ".join(row)
        parameters = ", ".join("?" for _ in row)
        updates = ", ".join(f"{column} = excluded.{column}" for column in row)
        conflict = f"DO UPDATE SET {updates}"
        if payload.get("reused"):
            conflict += " WHERE " + " OR ".join(
                f"scan_severity_assessments.{column} IS NOT excluded.{column}"
                for column in ("input_sha256", "rubric_sha256", "knowledge_base_sha256")
            )
        connection.execute(
            f"INSERT INTO scan_severity_assessments ({columns}) VALUES ({parameters}) "
            f"ON CONFLICT(scan_id, finding_id) {conflict}",
            tuple(row.values()),
        )
    return {}


def read_classification(database: Path, scan_id: str) -> dict[str, Any]:
    uri = f"file:{quote(str(database), safe='')}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=5)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                "AND name = 'scan_severity_classifications'"
            ).fetchone()
            is None
        ):
            return {}
        row = connection.execute(
            "SELECT * FROM scan_severity_classifications WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return {}
        finding_ids = json.loads(row["finding_ids_json"])
        has_scan_assessments = (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'scan_severity_assessments'"
            ).fetchone()
            is not None
        )
        return {
            "scanId": scan_id,
            "findingIds": finding_ids,
            "assessedAt": row["assessed_at"],
            "rubricSha256": row["rubric_sha256"],
            "knowledgeBaseSha256": row["knowledge_base_sha256"],
            "assessments": assessments(
                connection, finding_ids, scan_id if has_scan_assessments else None
            ),
        }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
