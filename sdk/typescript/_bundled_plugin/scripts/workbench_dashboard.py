"""Read-only dashboard projections. Scans and imported findings need no workflow."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from workbench_findings import list_dedupe_groups
from workbench_finding_workflows import read_workflow


SCAN_RECORDS = """
SELECT scans.id, scans.target_path AS title,
    json_array(COALESCE(scans.target_id, scans.target_path)) AS repositoryIds,
    scans.target_path AS repositoryPath, scans.id AS scanId, scans.mode,
    CASE WHEN scans.canceled_at IS NOT NULL THEN 'canceled'
         WHEN scans.status = 'complete' THEN 'completed' ELSE scans.status END AS status,
    'scan' AS stage, scans.started_at AS createdAt,
    MAX(scans.updated_at, COALESCE(progress.updated_at, scans.updated_at)) AS updatedAt,
    CASE WHEN scans.status = 'complete' THEN
        (SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = scans.id)
        ELSE progress.reportable_findings_count END AS findingCount
FROM scans LEFT JOIN scan_progress AS progress ON progress.scan_id = scans.id
"""

WORKFLOW_RECORDS = """
SELECT workflows.id, workflows.id AS title,
    CASE WHEN COALESCE(scans.target_id, workflows.scope_repository_id,
                       scans.target_path, workflows.repository_path) IS NULL
         THEN '[]' ELSE json_array(COALESCE(scans.target_id,
             workflows.scope_repository_id, scans.target_path, workflows.repository_path)) END AS repositoryIds,
    COALESCE(scans.target_path, workflows.repository_path) AS repositoryPath,
    workflows.scan_id AS scanId, scans.mode,
    CASE stage WHEN 'scan' THEN scan_status WHEN 'publish' THEN publish_status
         ELSE dedupe_status END AS status, stage,
    workflows.created_at AS createdAt, workflows.updated_at AS updatedAt,
    CASE WHEN scans.id IS NOT NULL AND scans.status = 'complete' THEN
        (SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = scans.id) END AS findingCount,
    json_extract(results_json, '$.publish.findingCount') AS publishedCount,
    CASE WHEN dedupe_status = 'completed' THEN
        json_array_length(json_extract(results_json, '$.dedupe.uniqueFindingIds')) END AS uniqueCount
FROM (
    SELECT *, CASE WHEN scan_status != 'completed' THEN 'scan'
        WHEN publish_status != 'completed' THEN 'publish'
        ELSE 'dedupe' END AS stage FROM finding_workflows
) AS workflows LEFT JOIN scans ON scans.id = workflows.scan_id
"""

FINDING_RECORDS = """
SELECT findings.id, json_extract(details_json, '$.title') AS title,
    COALESCE(repositories.ids, '[]') AS repositoryIds,
    json_extract(details_json, '$.severity.level') AS severity,
    findings.created_at AS createdAt, findings.updated_at AS updatedAt
FROM findings LEFT JOIN (
    SELECT finding_id, json_group_array(repository_id) AS ids
    FROM finding_repositories GROUP BY finding_id
) AS repositories ON repositories.finding_id = findings.id
WHERE details_json IS NOT NULL
"""

GROUP_RECORDS = """
SELECT groups.id, groups.id AS title,
    (SELECT json_group_array(DISTINCT repository_id)
     FROM finding_dedupe_group_members AS members
     JOIN finding_repositories ON finding_repositories.finding_id = members.finding_id
     WHERE members.group_id = groups.id) AS repositoryIds,
    groups.created_at AS createdAt, groups.created_at AS updatedAt,
    (SELECT COUNT(*) FROM finding_dedupe_group_members WHERE group_id = groups.id) AS memberCount
FROM finding_dedupe_groups AS groups
"""

RECORDS = {
    "scans": SCAN_RECORDS,
    "workflows": WORKFLOW_RECORDS,
    "findings": FINDING_RECORDS,
    "groups": GROUP_RECORDS,
}


def item(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    result["repositoryIds"] = json.loads(result["repositoryIds"])
    return result


def scan_detail(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        """SELECT scans.*, progress.review_items_completed, progress.review_items_total,
        progress.reportable_findings_count, progress.deep_review_pass,
        MAX(scans.updated_at, COALESCE(progress.updated_at, scans.updated_at)) AS last_update
        FROM scans LEFT JOIN scan_progress AS progress ON progress.scan_id = scans.id
        WHERE scans.id = ?""", (scan_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "scanId": row["id"], "repositoryPath": row["target_path"],
        "repositoryId": row["target_id"], "revision": row["target_revision"],
        "scope": row["scope"], "mode": row["mode"],
        "status": "canceled" if row["canceled_at"] else (
            "completed" if row["status"] == "complete" else row["status"]),
        "phase": row["phase"], "startedAt": row["started_at"],
        "completedAt": row["completed_at"], "updatedAt": row["last_update"],
        "scanDir": row["scan_dir"], "error": row["failure_message"],
        "progress": {
            "reviewed": row["review_items_completed"], "total": row["review_items_total"],
            "reportable": row["reportable_findings_count"], "deepPass": row["deep_review_pass"],
        },
        "findingIds": [r[0] for r in connection.execute(
            "SELECT finding_id FROM finding_occurrences WHERE scan_id = ? ORDER BY finding_id",
            (scan_id,),
        )],
        "workflowIds": [r[0] for r in connection.execute(
            "SELECT id FROM finding_workflows WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        )],
    }


def detail(connection: sqlite3.Connection, view: str, selected: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"item": selected}
    selected_id = selected["id"]
    if view == "scans":
        result["scan"] = scan_detail(connection, selected_id)
    elif view == "workflows":
        state = read_workflow(connection, selected_id)
        result["workflow"] = state
        scan = scan_detail(connection, state["scanId"]) if state.get("scanId") else None
        if scan is not None:
            result["scan"] = scan
    elif view == "findings":
        result["finding"] = json.loads(connection.execute(
            "SELECT details_json FROM findings WHERE id = ?", (selected_id,),
        ).fetchone()[0])
        result["groups"] = list_dedupe_groups(connection, selected_id)["groups"]
        result["scanIds"] = [r[0] for r in connection.execute(
            "SELECT scan_id FROM finding_occurrences WHERE finding_id = ? ORDER BY scan_id",
            (selected_id,),
        )]
    else:
        result["group"] = {
            "groupId": selected_id, "createdAt": selected["createdAt"],
            "findingIds": [r[0] for r in connection.execute(
                "SELECT finding_id FROM finding_dedupe_group_members WHERE group_id = ? ORDER BY finding_id",
                (selected_id,),
            )],
        }
    return result


def dashboard(connection: sqlite3.Connection, query: dict[str, Any]) -> dict[str, Any]:
    """One snapshot, no scan recovery, artifact reads, model calls, or writes."""
    view = query["view"]
    records = RECORDS[view]
    clauses: list[str] = []
    values: list[Any] = []
    if query.get("query"):
        columns = ["id", "title", "repositoryIds"]
        if view in {"scans", "workflows"}:
            columns.extend(("scanId", "repositoryPath"))
        clauses.append("(" + " OR ".join(f"instr(lower(COALESCE({c}, '')), lower(?)) > 0" for c in columns) + ")")
        values.extend([query["query"]] * len(columns))
    if query.get("repository"):
        clauses.append("EXISTS (SELECT 1 FROM json_each(repositoryIds) WHERE value = ?)")
        values.append(query["repository"])
    if view in {"scans", "workflows"}:
        for field in ("status", "stage"):
            if query.get(field):
                clauses.append(f"{field} = ?")
                values.append(query[field])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    order = "createdAt DESC, id" if query["sort"] == "newest" else "updatedAt DESC, id"
    if query["sort"] == "activity" and view in {"scans", "workflows"}:
        order = "CASE WHEN status = 'running' THEN 0 ELSE 1 END, " + order
    connection.execute("BEGIN")
    with connection:
        scan_counts = dict(connection.execute(f"SELECT status, COUNT(*) FROM ({SCAN_RECORDS}) GROUP BY status"))
        workflow_counts = dict(connection.execute(
            f"SELECT CASE WHEN status = 'running' THEN stage ELSE status END, COUNT(*) "
            f"FROM ({WORKFLOW_RECORDS}) GROUP BY 1"
        ))
        repositories = connection.execute(f"""
            SELECT id, MAX(label) AS label FROM (
                SELECT COALESCE(target_id, target_path) AS id, target_path AS label FROM scans
                UNION ALL
                SELECT repository_id, COALESCE(targets.display_name, repository_id)
                FROM finding_repositories LEFT JOIN security_targets AS targets ON targets.id = repository_id
                UNION ALL
                SELECT repository.value, COALESCE(repositoryPath, repository.value)
                FROM ({WORKFLOW_RECORDS}), json_each(repositoryIds) AS repository
            ) WHERE id IS NOT NULL GROUP BY id ORDER BY label, id
        """).fetchall()
        total = connection.execute(f"SELECT COUNT(*) FROM ({records}) {where}", values).fetchone()[0]
        rows = connection.execute(
            f"SELECT * FROM ({records}) {where} ORDER BY {order} LIMIT ? OFFSET ?",
            (*values, query["limit"], query["offset"]),
        ).fetchall()
        selected = connection.execute(
            f"SELECT * FROM ({records}) WHERE id = ?", (query["id"],),
        ).fetchone() if query.get("id") else None
        next_offset = query["offset"] + len(rows)
        return {
            "overview": {
                "scans": scan_counts, "workflows": workflow_counts,
                "findings": connection.execute("SELECT COUNT(*) FROM findings WHERE details_json IS NOT NULL").fetchone()[0],
                "groups": connection.execute("SELECT COUNT(*) FROM finding_dedupe_groups").fetchone()[0],
            },
            "repositories": [dict(row) for row in repositories],
            "items": [item(row) for row in rows], "total": total,
            "limit": query["limit"], "offset": query["offset"],
            "nextOffset": next_offset if next_offset < total else None,
            "detail": detail(connection, view, item(selected)) if selected is not None else None,
        }
