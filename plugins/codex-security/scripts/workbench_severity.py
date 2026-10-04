"""Reusable severity checkpoints and the assessments saved for each scan."""

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

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
    rows = connection.execute(
        f"""SELECT assessment.* FROM json_each(?) AS selected
        JOIN {table} AS assessment ON assessment.finding_id = selected.value
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
            return {
                "assessments": assessments(connection, payload["findingIds"], payload["scanId"])
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
        connection.execute(
            f"INSERT INTO scan_severity_assessments ({columns}) VALUES ({parameters}) "
            f"ON CONFLICT(scan_id, finding_id) DO UPDATE SET {updates}",
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
        saved = assessments(connection, finding_ids, scan_id if has_scan_assessments else None)
        if has_scan_assessments:
            from finalize_scan_contract import _stable_id

            by_finding = {assessment["findingId"]: assessment for assessment in saved}
            missing = [finding_id for finding_id in finding_ids if finding_id not in by_finding]
            legacy = connection.execute(
                """SELECT assessment.*, finding.fingerprint
                FROM json_each(?) AS selected
                JOIN finding_severity_assessments AS assessment
                    ON assessment.finding_id = selected.value
                JOIN findings AS finding ON finding.id = assessment.finding_id""",
                (json.dumps(missing),),
            )
            for assessment in legacy:
                # Match migration 46 without changing a database opened for publication.
                if assessment["occurrence_id"] == _stable_id(
                    "occ", scan_id, assessment["fingerprint"]
                ):
                    by_finding[assessment["finding_id"]] = {
                        key: assessment[column] for key, column in FIELDS.items()
                    }
            saved = [
                by_finding[finding_id] for finding_id in finding_ids if finding_id in by_finding
            ]
        return {
            "scanId": scan_id,
            "findingIds": finding_ids,
            "assessedAt": row["assessed_at"],
            "rubricSha256": row["rubric_sha256"],
            "knowledgeBaseSha256": row["knowledge_base_sha256"],
            "assessments": saved,
        }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
