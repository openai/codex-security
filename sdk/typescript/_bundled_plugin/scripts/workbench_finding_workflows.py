"""Durable state for the opt-in local scan, publication, and dedupe workflow."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

WORKFLOW_BINDINGS = {
    "repositoryPath": "repository_path",
    "scanRequestDigest": "scan_request_digest",
    "scanId": "scan_id",
    "scanDir": "scan_dir",
    "artifactDigest": "artifact_digest",
    "destination": "destination",
}
WORKFLOW_STAGES = ("scan", "publish", "dedupe")


def read_workflow(connection: sqlite3.Connection, workflow_id: str) -> dict[str, Any] | None:
    row = connection.execute(
        "SELECT * FROM finding_workflows WHERE id = ?", (workflow_id,)
    ).fetchone()
    if row is None:
        return None
    state = {"id": row["id"], "stages": {}}
    for field, column in WORKFLOW_BINDINGS.items():
        if row[column] is not None:
            state[field] = row[column]
    if row["scope_repository_id"] is not None:
        state["scope"] = {"repositoryId": row["scope_repository_id"]}
    elif row["scope_all_repositories"] is not None:
        state["scope"] = {"allRepositories": bool(row["scope_all_repositories"])}
    results = json.loads(row["results_json"])
    for stage in WORKFLOW_STAGES:
        current = {"status": row[f"{stage}_status"]}
        if row[f"{stage}_error"] is not None:
            current["error"] = row[f"{stage}_error"]
        if stage in results:
            current["result"] = results[stage]
        state["stages"][stage] = current
    if "dedupePendingWrite" in results:
        state["stages"]["dedupe"]["pendingWrite"] = results["dedupePendingWrite"]
    return state


def save_workflow(connection: sqlite3.Connection, state: dict[str, Any], timestamp: str) -> None:
    values = {"id": state["id"]}
    values.update({column: state.get(field) for field, column in WORKFLOW_BINDINGS.items()})
    scope = state.get("scope", {})
    values.update(
        scope_repository_id=scope.get("repositoryId"),
        scope_all_repositories=scope.get("allRepositories"),
    )
    results = {}
    for stage in WORKFLOW_STAGES:
        current = state["stages"][stage]
        values[f"{stage}_status"] = current["status"]
        values[f"{stage}_error"] = current.get("error")
        if "result" in current:
            results[stage] = current["result"]
    if "pendingWrite" in state["stages"]["dedupe"]:
        results["dedupePendingWrite"] = state["stages"]["dedupe"]["pendingWrite"]
    values.update(
        results_json=json.dumps(results, allow_nan=False), created_at=timestamp, updated_at=timestamp
    )
    updates = ", ".join(
        f"{column} = excluded.{column}" for column in values if column not in {"id", "created_at"}
    )
    connection.execute(
        f"INSERT INTO finding_workflows ({', '.join(values)}) "
        f"VALUES ({', '.join('?' for _ in values)}) ON CONFLICT(id) DO UPDATE SET {updates}",
        tuple(values.values()),
    )


def bind_workflow(state: dict[str, Any], binding: dict[str, Any]) -> None:
    for field, value in binding.items():
        if field not in WORKFLOW_BINDINGS and field != "scope":
            raise SystemExit("Unknown workflow binding.")
        if field in state and state[field] != value:
            raise SystemExit(
                f"Workflow {state['id']} is already bound to a different {field}. "
                "Use another --workflow-id."
            )
        state[field] = value


def register_workflow_scan(
    connection: sqlite3.Connection, workflow_id: str, scan_id: str, scan_dir: str, timestamp: str
) -> None:
    """Called inside the scan-registration transaction, before model execution."""
    state = read_workflow(connection, workflow_id)
    if state is None:
        raise SystemExit("The workflow must be started before registering its scan.")
    if state["stages"]["scan"]["status"] == "completed":
        raise SystemExit("The workflow scan is already complete.")
    previous = state.get("scanId")
    if previous is not None:
        row = connection.execute("SELECT status FROM scans WHERE id = ?", (previous,)).fetchone()
        if row is not None and row["status"] == "complete":
            raise SystemExit("Reuse the workflow's completed scan instead of registering another.")
    state["scanId"] = scan_id
    state["scanDir"] = scan_dir
    save_workflow(connection, state, timestamp)


def finding_workflow(
    connection: sqlite3.Connection, payload: dict[str, Any], timestamp: str
) -> dict[str, Any]:
    workflow_id = payload["id"]
    if not isinstance(workflow_id, str) or not workflow_id.strip():
        raise SystemExit("workflowId must be a nonempty string.")
    if payload["action"] == "get":
        return {"workflow": read_workflow(connection, workflow_id)}
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        state = read_workflow(connection, workflow_id)
        if state is None:
            state = {
                "id": workflow_id,
                "stages": {stage: {"status": "pending"} for stage in WORKFLOW_STAGES},
            }
        bind_workflow(state, payload.get("binding", {}))
        action = payload["action"]
        if action != "bind":
            stage = payload["stage"]
            if stage not in state["stages"]:
                raise SystemExit("Unknown workflow stage.")
            current = state["stages"][stage]
            if current["status"] != "completed":
                if action == "begin":
                    current["status"] = "running"
                elif action == "complete":
                    state["stages"][stage] = {"status": "completed", "result": payload["result"]}
                elif action == "fail":
                    current.update(status="failed", error=payload["error"])
                else:
                    raise SystemExit("Unknown workflow action.")
        save_workflow(connection, state, timestamp)
        return {"workflow": state}
