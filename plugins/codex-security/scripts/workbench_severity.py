"""Per-finding severity checkpoints and the selection requested for each scan."""

import argparse
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

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


def assessments(connection: sqlite3.Connection, finding_ids: list[str]) -> list[dict[str, Any]]:
    rows = connection.execute(
        """SELECT assessment.* FROM json_each(?) AS selected
        JOIN finding_severity_assessments AS assessment ON assessment.finding_id = selected.value
        ORDER BY selected.key""",
        (json.dumps(finding_ids),),
    )
    return [{key: row[column] for key, column in FIELDS.items()} for row in rows]


def write_progress(connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str) -> None:
    progress = dict(payload["progress"])
    if payload.get("registeredScan"):
        progress["registeredScan"] = True
    connection.execute(
        """INSERT INTO severity_classification_runs
        (id, scan_id, progress_json, started_at, updated_at) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            progress_json = excluded.progress_json, updated_at = excluded.updated_at""",
        (
            payload["runId"],
            payload["scanId"],
            json.dumps(progress, allow_nan=False),
            timestamp,
            timestamp,
        ),
    )


def checkpoint(
    connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    if payload["action"] == "source":
        scan = connection.execute(
            "SELECT scan_dir, status, canceled_at FROM scans WHERE id = ?", (payload["scanId"],)
        ).fetchone()
        # Saved-scan selection requires completed history, even when a
        # prepare-only interruption already left sealed directory artifacts.
        registered = scan is not None and scan["status"] == "complete" and not scan["canceled_at"]
        if registered:
            try:
                registered = os.path.samefile(scan["scan_dir"], payload["scanDirectory"])
            except OSError:
                # A copied directory can outlive its original registered output.
                registered = False
        return {"registeredScan": registered}
    if payload["action"] == "progress":
        with connection:
            write_progress(connection, payload, timestamp)
        return {}
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
            return {"assessments": assessments(connection, payload["findingIds"])}
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
        columns = ", ".join(FIELDS.values())
        parameters = ", ".join("?" for _ in FIELDS)
        updates = ", ".join(f"{column} = excluded.{column}" for column in FIELDS.values())
        connection.execute(
            f"""INSERT INTO finding_severity_assessments ({columns})
            VALUES ({parameters})
            ON CONFLICT(finding_id) DO UPDATE SET
            {updates}""",
            tuple(assessment[key] for key in FIELDS),
        )
    if "progress" in payload:
        try:
            with connection:
                write_progress(connection, payload, timestamp)
        except Exception:
            # Keep the required assessment even if optional progress cannot commit.
            pass
    return {}


def latest_progress(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT run.id, run.progress_json, run.started_at, run.updated_at, scan.scan_dir "
        "FROM severity_classification_runs AS run LEFT JOIN scans AS scan ON scan.id = run.scan_id "
        "WHERE run.scan_id = ? ORDER BY run.started_at DESC, run.rowid DESC LIMIT 1",
        (scan_id,),
    ).fetchone()
    if row is None:
        return None
    progress = json.loads(row["progress_json"])
    registered_scan = progress.pop("registeredScan", False)
    if row["scan_dir"] is not None and registered_scan:
        # Follow archived registered scans; preserve explicitly selected copies.
        progress["scanDirectory"] = row["scan_dir"]
    return {
        **progress,
        "runId": row["id"],
        "startedAt": row["started_at"],
        "updatedAt": row["updated_at"],
    }


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
        return {
            "scanId": scan_id,
            "findingIds": finding_ids,
            "assessedAt": row["assessed_at"],
            "rubricSha256": row["rubric_sha256"],
            "knowledgeBaseSha256": row["knowledge_base_sha256"],
            "assessments": assessments(connection, finding_ids),
        }


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
