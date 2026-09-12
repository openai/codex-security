"""Measure scan-owned Codex token usage from the live thread graph."""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

TOKEN_FIELDS = {
    "input_tokens": "inputTokens",
    "cached_input_tokens": "cachedInputTokens",
    "cache_write_input_tokens": "cacheWriteInputTokens",
    "output_tokens": "outputTokens",
    "reasoning_output_tokens": "reasoningOutputTokens",
    "total_tokens": "totalTokens",
}
STATE_DATABASE_NAME = re.compile(r"state_(\d+)\.sqlite")
STATE_DATABASE_TIMEOUT_SECONDS = 1.0


@dataclass(frozen=True)
class RolloutSession:
    thread_id: str
    parent_thread_id: str | None
    path: Path


def stored_scan_cost_fields(value: str | None) -> dict[str, Any]:
    """Project measured usage without changing the existing legacy cost contract."""

    if value is None:
        return {}
    stored = json.loads(value, parse_constant=_reject_nonstandard_json_number)
    if not isinstance(stored, dict):
        return {}
    if "usage" not in stored:
        return {"cost": stored}
    return {
        "usage": stored["usage"],
        **({"cost": stored["cost"]} if isinstance(stored.get("cost"), dict) else {}),
    }


def measured_scan_cost_json(usage: Mapping[str, Any]) -> str:
    """Keep usage in the already-migrated scans.cost_json column."""

    return json.dumps({"usage": dict(usage)}, separators=(",", ":"), allow_nan=False)


def reconcile_completed_scan_cost(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    cost_json: str,
) -> None:
    """Persist authoritative SDK cost without discarding measured worker usage."""

    existing = json.loads(scan["cost_json"]) if scan["cost_json"] is not None else {}
    if isinstance(existing, dict) and "usage" in existing:
        cost_json = json.dumps(
            {**existing, "cost": json.loads(cost_json)},
            separators=(",", ":"),
            allow_nan=False,
        )
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'complete'",
            (cost_json, scan["id"]),
        )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def collect_scan_usage(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    thread_id: str | None = None,
    completed_at: str | None = None,
) -> dict[str, Any]:
    """Count only complete, attributable rollout events inside this scan's window."""

    attribution = scan_execution_attribution(connection, scan)
    if attribution and attribution.get("legacy"):
        attribution = None
    roots = (
        list(
            dict.fromkeys(
                [
                    *(
                        [attribution["owner"]["threadId"]]
                        if attribution["owner"].get("threadId")
                        else []
                    ),
                    *attribution["executionThreadIds"],
                ]
            )
        )
        if attribution
        else _scan_root_thread_ids(connection, scan, thread_id)
    )
    if not roots:
        return _unavailable_usage("scan_thread_unavailable")

    warnings: set[str] = set()
    current_database = _codex_state_database()
    worker_codex_home = None
    if scan["mode"] == "deep":
        # Deep orchestration imports the owner-capture helper from this module;
        # its settings reader is available once completion starts.
        from deep_scan_workbench import read_deep_scan_execution_settings

        try:
            settings = read_deep_scan_execution_settings(Path(scan["scan_dir"]))
            worker_codex_home = Path(settings["codexHome"])
        except SystemExit:
            # Legacy scans may have no recorded home. Keep usage best effort.
            pass
    groups = [(current_database, roots)]
    if worker_codex_home is not None:
        worker_roots = set(
            _scan_root_thread_ids(connection, scan, None, include_owner_threads=False)
        )
        # Workers retain their Codex home, but inherit an explicit current
        # SQLite home. Their earlier and resumed sessions can be in either index.
        worker_database = _codex_state_database(worker_codex_home)
        if worker_database != current_database:
            groups.append((worker_database, [root for root in roots if root in worker_roots]))
    if not any(database is not None for database, _ in groups):
        return _unavailable_usage("codex_state_unavailable")

    started_at = _timestamp(scan["started_at"])
    stopped_at = _timestamp(completed_at or scan["completed_at"])
    if started_at is None:
        return _unavailable_usage("scan_window_unavailable")

    sessions: dict[str, list[RolloutSession]] = {}
    missing_thread_ids: set[str] = set()
    seen_thread_ids: set[str] = set()
    for state_database, group_roots in groups:
        if not group_roots:
            continue
        try:
            if state_database is None:
                raise FileNotFoundError("Codex state is unavailable")
            discovered, missing = _discover_rollout_sessions(
                state_database,
                group_roots,
                warnings,
                descendant_roots=set(attribution["executionThreadIds"]) if attribution else None,
            )
        except (OSError, sqlite3.Error, ValueError):
            warnings.add("codex_state_unavailable")
            missing_thread_ids.update(group_roots)
            continue
        missing_thread_ids.update(missing)
        for session in discovered:
            copies = sessions.setdefault(session.thread_id, [])
            if session not in copies:
                copies.append(session)
            seen_thread_ids.add(session.thread_id)

    # Absence from one known index is not missing usage when another has it.
    missing_thread_ids.difference_update(seen_thread_ids)
    if not missing_thread_ids:
        warnings.difference_update({"scan_root_unavailable", "codex_state_unavailable"})

    if not sessions:
        return _unavailable_usage(
            "codex_state_unavailable"
            if "codex_state_unavailable" in warnings
            else "scan_thread_unavailable",
            warnings=warnings,
        )

    total = _empty_token_usage()
    observed_thread_count = 0
    accepted_thread_ids: set[str] = set()
    excluded_thread_ids: set[str] = set()
    model_usage: dict[str | None, dict[str, int]] = {}
    for copies in sessions.values():
        session = copies[0]
        owner_turn_id = None
        if (
            attribution
            and session.thread_id not in attribution["executionThreadIds"]
            and session.parent_thread_id is None
        ):
            owner = attribution["owner"]
            if session.thread_id != owner.get("threadId") or not owner.get("turnId"):
                missing_thread_ids.add(session.thread_id)
                warnings.add("scan_owner_turn_unavailable")
                continue
            owner_turn_id = owner["turnId"]
        if session.parent_thread_id in excluded_thread_ids:
            excluded_thread_ids.add(session.thread_id)
            continue
        if (
            session.parent_thread_id is not None
            and session.parent_thread_id not in accepted_thread_ids
        ):
            missing_thread_ids.add(session.thread_id)
            warnings.add("thread_lineage_incomplete")
            continue
        try:
            session_usage, session_warnings = _read_rollout_copies_usage(
                copies,
                started_at=started_at,
                completed_at=stopped_at,
                owner_turn_id=owner_turn_id,
                model_usage=model_usage,
            )
        except (OSError, UnicodeError, ValueError):
            missing_thread_ids.add(session.thread_id)
            warnings.add("rollout_unavailable")
            continue
        if "thread_outside_scan_window" in session_warnings:
            excluded_thread_ids.add(session.thread_id)
            continue
        warnings.update(session_warnings)
        if "thread_identity_mismatch" in session_warnings or (
            "thread_ownership_unavailable" in session_warnings
        ):
            missing_thread_ids.add(session.thread_id)
            continue
        accepted_thread_ids.add(session.thread_id)
        if "token_usage_unavailable" in session_warnings:
            missing_thread_ids.add(session.thread_id)
            continue
        observed_thread_count += 1
        _add_token_usage(total, session_usage)

    if not observed_thread_count:
        return _unavailable_usage("scan_thread_unavailable", warnings=warnings)

    result: dict[str, Any] = {
        "coverage": "partial" if missing_thread_ids or warnings else "complete",
        "source": "codex_rollout",
        **total,
        "threadCount": observed_thread_count,
    }
    if missing_thread_ids:
        result["missingThreadCount"] = len(missing_thread_ids)
    if warnings:
        result["warnings"] = sorted(warnings)
    if attribution or any(model is not None for model in model_usage):
        result["modelUsage"] = [{"model": model, **usage} for model, usage in model_usage.items()]
    return result


def _read_rollout_copies_usage(
    copies: list[RolloutSession],
    *,
    started_at: datetime,
    completed_at: datetime | None,
    owner_turn_id: str | None,
    model_usage: dict[str | None, dict[str, int]],
) -> tuple[dict[str, int], set[str]]:
    readings = []
    for session in copies:
        local_models: dict[str | None, dict[str, int]] = {}
        try:
            usage, warnings = _read_rollout_usage(
                session,
                started_at=started_at,
                completed_at=completed_at,
                owner_turn_id=owner_turn_id,
                model_usage=local_models,
            )
        except (OSError, UnicodeError, ValueError):
            continue
        readings.append((usage, warnings, local_models))
    if not readings:
        raise ValueError("No readable rollout copy.")
    attributable = [
        reading
        for reading in readings
        if not reading[1].intersection(
            {
                "thread_identity_mismatch",
                "thread_ownership_unavailable",
                "thread_outside_scan_window",
                "token_usage_unavailable",
            }
        )
    ]
    # Restored indexes can reference a prefix and its complete continuation.
    # Keep totals and model attribution from the same copy, counting it once.
    usage, warnings, selected_models = max(
        attributable or readings, key=lambda reading: reading[0]["totalTokens"]
    )
    for model, tokens in selected_models.items():
        _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), tokens)
    return usage, warnings


def _scan_root_thread_ids(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    supplied_thread_id: str | None,
    *,
    include_owner_threads: bool = True,
) -> list[str]:
    candidates: list[str | None] = [supplied_thread_id]
    if include_owner_threads:
        if "continuation_thread_id" in scan.keys():
            candidates.append(scan["continuation_thread_id"])
        if "deep_scan_owner_thread_id" in scan.keys():
            candidates.append(scan["deep_scan_owner_thread_id"])
        workspace = connection.execute(
            "SELECT thread_id FROM workspaces WHERE id = ?",
            (scan["workspace_id"],),
        ).fetchone()
        if workspace is not None:
            candidates.append(workspace["thread_id"])
    if scan["mode"] == "deep":
        candidates.extend(
            row["sdk_thread_id"]
            for row in connection.execute(
                """
                SELECT sdk_thread_id FROM deep_scan_attempt_sessions WHERE scan_id = ?
                UNION
                SELECT sdk_thread_id FROM deep_scan_workers
                WHERE scan_id = ? AND sdk_thread_id IS NOT NULL
                ORDER BY sdk_thread_id
                """,
                (scan["id"], scan["id"]),
            )
        )
    roots: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip() and candidate not in seen:
            roots.append(candidate)
            seen.add(candidate)
    return roots


def _scan_execution_thread_ids(connection: sqlite3.Connection, scan: sqlite3.Row) -> list[str]:
    # CLI recipes identify dedicated executions; Desktop continuations can be shared.
    return _scan_root_thread_ids(
        connection,
        scan,
        scan["continuation_thread_id"] if scan["recipe_json"] is not None else None,
        include_owner_threads=False,
    )


def capture_scan_usage_owner(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    """Bind the active native turn once; joining a scan does not bind later conversation work."""
    roots = _scan_root_thread_ids(connection, scan, None)
    owner = roots[0] if roots else None
    result = {
        "threadId": owner,
        "turnId": None,
        "startedAt": scan["started_at"],
        "dedicated": scan["recipe_json"] is not None,
    }
    database = _codex_state_database()
    if owner is None or database is None:
        return result
    try:
        sessions, _ = _discover_rollout_sessions(database, [owner], set(), descendant_roots=set())
        if not sessions:
            return result
        with sessions[0].path.open("rb") as source:
            for line in source:
                if not line.endswith(b"\n"):
                    continue
                event = json.loads(line)
                payload = event.get("payload")
                if not isinstance(payload, dict):
                    continue
                if event.get("type") == "turn_context" or (
                    event.get("type") == "event_msg" and payload.get("type") == "task_started"
                ):
                    turn_id = payload.get("turn_id")
                    if isinstance(turn_id, str):
                        result["turnId"] = turn_id
                elif event.get("type") == "event_msg" and payload.get("type") == "task_complete":
                    result["turnId"] = None
    except (OSError, ValueError, sqlite3.Error):
        # Accounting availability must not prevent a scan from starting.
        pass
    return result


def scan_execution_attribution(
    connection: sqlite3.Connection, scan: sqlite3.Row
) -> dict[str, Any] | None:
    if scan["mode"] != "deep":
        return None
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
    ).fetchone()
    if run is None:
        return None
    owner_json = run["usage_owner_json"] if "usage_owner_json" in run.keys() else None
    legacy = False
    if owner_json is None:
        legacy = (
            connection.execute(
                "SELECT 1 FROM deep_scan_attempts WHERE scan_id = ? LIMIT 1", (scan["id"],)
            ).fetchone()
            is None
        )
        roots = _scan_root_thread_ids(connection, scan, None)
        owner = {
            "threadId": roots[0] if roots else None,
            "turnId": None,
            "startedAt": scan["started_at"],
            "dedicated": scan["recipe_json"] is not None,
        }
    else:
        owner = json.loads(owner_json)
    executions = _scan_execution_thread_ids(connection, scan)
    if owner.get("dedicated") and owner.get("threadId") not in executions:
        executions.append(owner["threadId"])
    return {
        "formatVersion": 1,
        **({"legacy": True} if legacy else {}),
        "executionThreadIds": executions,
        "owner": owner,
        "startedAt": scan["started_at"],
        "completedAt": scan["completed_at"],
    }


def scan_execution_fields(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    return {
        "threadIds": _scan_root_thread_ids(connection, scan, None),
        "executionThreadIds": _scan_execution_thread_ids(connection, scan),
        "executionAttribution": scan_execution_attribution(connection, scan),
    }


def _codex_state_database(worker_codex_home: Path | None = None) -> Path | None:
    configured_home = os.environ.get("CODEX_HOME", "").strip()
    current_home = Path(configured_home).expanduser() if configured_home else Path.home() / ".codex"
    codex_home = worker_codex_home if worker_codex_home is not None else current_home
    same_home = worker_codex_home is None or codex_home.resolve() == current_home.resolve()
    configured_database = os.environ.get("CODEX_STATE_DB", "").strip() if same_home else ""
    if configured_database:
        path = Path(configured_database).expanduser()
        return path.resolve() if path.is_file() and os.access(path, os.R_OK) else None

    configured_sqlite_home = os.environ.get("CODEX_SQLITE_HOME", "").strip() if same_home else ""
    search_roots = [
        *([Path(configured_sqlite_home).expanduser()] if configured_sqlite_home else []),
        codex_home,
        codex_home / "sqlite",
    ]
    seen: set[Path] = set()
    for search_root in search_roots:
        try:
            resolved_root = search_root.resolve()
            if resolved_root in seen:
                continue
            seen.add(resolved_root)
            candidates = [
                (int(match.group(1)), path)
                for path in resolved_root.glob("state_*.sqlite")
                if (match := STATE_DATABASE_NAME.fullmatch(path.name)) is not None
                and path.is_file()
                and os.access(path, os.R_OK)
            ]
        except (OSError, RuntimeError, ValueError):
            continue
        if candidates:
            return max(candidates, key=lambda item: item[0])[1].resolve()
    return None


def _discover_rollout_sessions(
    state_database: Path,
    roots: list[str],
    warnings: set[str],
    *,
    descendant_roots: set[str] | None = None,
) -> tuple[list[RolloutSession], set[str]]:
    database = sqlite3.connect(
        state_database.as_uri() + "?mode=ro",
        uri=True,
        timeout=STATE_DATABASE_TIMEOUT_SECONDS,
    )
    try:
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only = ON")
        _require_state_columns(database, "threads", {"id", "rollout_path"})
        _require_state_columns(
            database,
            "thread_spawn_edges",
            {"parent_thread_id", "child_thread_id"},
        )
        sessions: list[RolloutSession] = []
        seen_thread_ids: set[str] = set()
        missing_thread_ids: set[str] = set()
        for root in roots:
            row = database.execute(
                "SELECT id, rollout_path FROM threads WHERE id = ?",
                (root,),
            ).fetchone()
            if row is None:
                missing_thread_ids.add(root)
                warnings.add("scan_root_unavailable")
                continue
            if root not in seen_thread_ids:
                path = _rollout_path(row["rollout_path"])
                if path is None:
                    missing_thread_ids.add(root)
                    warnings.add("rollout_unavailable")
                    continue
                sessions.append(RolloutSession(root, None, path))
                seen_thread_ids.add(root)
            if descendant_roots is not None and root not in descendant_roots:
                continue
            descendants = database.execute(
                """
                WITH RECURSIVE descendants(
                    depth, parent_thread_id, child_thread_id, ancestry, cycle
                ) AS (
                    SELECT
                        1,
                        edges.parent_thread_id,
                        edges.child_thread_id,
                        '|' || edges.parent_thread_id || '|' || edges.child_thread_id || '|',
                        edges.parent_thread_id = edges.child_thread_id
                    FROM thread_spawn_edges AS edges
                    WHERE edges.parent_thread_id = ?

                    UNION ALL

                    SELECT
                        descendants.depth + 1,
                        edges.parent_thread_id,
                        edges.child_thread_id,
                        descendants.ancestry || edges.child_thread_id || '|',
                        instr(descendants.ancestry, '|' || edges.child_thread_id || '|') > 0
                    FROM thread_spawn_edges AS edges
                    JOIN descendants ON edges.parent_thread_id = descendants.child_thread_id
                    WHERE descendants.cycle = 0
                )
                SELECT
                    descendants.depth,
                    descendants.parent_thread_id,
                    descendants.child_thread_id,
                    descendants.cycle,
                    threads.rollout_path
                FROM descendants
                LEFT JOIN threads ON threads.id = descendants.child_thread_id
                ORDER BY descendants.depth, descendants.child_thread_id
                """,
                (root,),
            )
            for descendant in descendants:
                child_id = descendant["child_thread_id"]
                parent_id = descendant["parent_thread_id"]
                if not isinstance(child_id, str) or not isinstance(parent_id, str):
                    warnings.add("thread_lineage_incomplete")
                    continue
                if descendant["cycle"]:
                    missing_thread_ids.add(child_id)
                    warnings.add("thread_lineage_cycle")
                    continue
                if child_id in seen_thread_ids:
                    continue
                path = _rollout_path(descendant["rollout_path"])
                if path is None:
                    missing_thread_ids.add(child_id)
                    warnings.add("rollout_unavailable")
                    continue
                sessions.append(RolloutSession(child_id, parent_id, path))
                seen_thread_ids.add(child_id)
        return sessions, missing_thread_ids
    finally:
        database.close()


def _require_state_columns(
    connection: sqlite3.Connection,
    table: str,
    required: set[str],
) -> None:
    statements = {
        "threads": "PRAGMA table_info(threads)",
        "thread_spawn_edges": "PRAGMA table_info(thread_spawn_edges)",
    }
    columns = {str(row["name"]) for row in connection.execute(statements[table])}
    if not required.issubset(columns):
        raise ValueError("Codex state graph does not expose the required thread columns.")


def _rollout_path(value: object) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            return None

        if resolved == candidate:
            return resolved

        if sys.platform == "darwin" and candidate.parts[1] in {"var", "tmp"}:
            expected = Path("/private", *candidate.parts[1:])
            if resolved == expected:
                return resolved
    except (OSError, RuntimeError):
        return None
    return None


def _read_rollout_usage(
    session: RolloutSession,
    *,
    started_at: datetime,
    completed_at: datetime | None,
    owner_turn_id: str | None = None,
    model_usage: dict[str | None, dict[str, int]] | None = None,
) -> tuple[dict[str, int], set[str]]:
    total = _empty_token_usage()
    counter_total = _empty_token_usage()
    warnings: set[str] = set()
    previous = _empty_token_usage()
    boundary_reached = False
    usage_observed = False
    current_turn_id: str | None = None
    current_model: str | None = None
    response_ids: set[str] = set()
    response_usage_observed = False
    response_tokens = 0
    expected_response_tokens = 0
    local_models: dict[str | None, dict[str, int]] = {}

    with session.path.open("rb") as source:
        for line_number, raw_line in enumerate(source, start=1):
            if not raw_line.endswith(b"\n"):
                warnings.add("rollout_record_incomplete")
                continue
            try:
                event = json.loads(raw_line)
            except (UnicodeError, ValueError):
                if line_number == 1:
                    raise ValueError("The rollout session metadata is unreadable.") from None
                if boundary_reached:
                    warnings.add("rollout_record_invalid")
                continue
            if not isinstance(event, dict):
                if boundary_reached:
                    warnings.add("rollout_record_invalid")
                continue
            payload = event.get("payload")
            if event.get("type") in {"session_meta", "turn_context"} and isinstance(payload, dict):
                model = payload.get("model")
                if isinstance(model, str) and model:
                    current_model = model
            if line_number == 1:
                if event.get("type") != "session_meta" or not isinstance(payload, dict):
                    warnings.add("thread_identity_mismatch")
                    return total, warnings
                recorded_id = payload.get("id") or payload.get("session_id")
                if recorded_id != session.thread_id:
                    warnings.add("thread_identity_mismatch")
                    return total, warnings
                recorded_parent = _session_parent_thread_id(payload)
                if session.parent_thread_id is not None:
                    if recorded_parent != session.parent_thread_id:
                        warnings.add("thread_identity_mismatch")
                        return total, warnings
                boundary_reached = (
                    session.parent_thread_id is None
                    and not recorded_parent
                    and not payload.get("forked_from_id")
                )
                continue

            if not isinstance(payload, dict):
                continue
            if event.get("type") == "turn_context" or (
                event.get("type") == "event_msg" and payload.get("type") == "task_started"
            ):
                current_turn_id = payload.get("turn_id")
            if not boundary_reached:
                if _is_owned_task_start(session.thread_id, event, payload):
                    task_started_at = _timestamp(event.get("timestamp"))
                    if task_started_at is None:
                        warnings.add("thread_ownership_unavailable")
                        return total, warnings
                    if task_started_at < started_at or (
                        completed_at is not None and task_started_at > completed_at
                    ):
                        warnings.add("thread_outside_scan_window")
                        return total, warnings
                    boundary_reached = True
                elif event.get("type") == "event_msg" and payload.get("type") == "token_count":
                    inherited_usage = _token_snapshot(payload)
                    if inherited_usage is not None:
                        previous = inherited_usage
                continue
            if event.get("type") == "token_usage_record":
                response_id = payload.get("response_id")
                usage = _token_snapshot({"info": {"total_token_usage": payload.get("usage")}})
                if (
                    not isinstance(response_id, str)
                    or usage is None
                    or payload.get("thread_id", session.thread_id) != session.thread_id
                    or response_id in response_ids
                ):
                    continue
                response_ids.add(response_id)
                cumulative = _token_snapshot(
                    {"info": {"total_token_usage": payload.get("thread_token_usage")}}
                )
                if cumulative is not None:
                    expected_response_tokens = max(
                        expected_response_tokens, cumulative["totalTokens"]
                    )
                if not response_usage_observed:
                    response_usage_observed = True
                    total = _empty_token_usage()
                    local_models = {}
                response_tokens += usage["totalTokens"]
                timestamp = _timestamp(event.get("timestamp"))
                if timestamp is None:
                    warnings.add("token_record_invalid")
                    continue
                if timestamp < started_at or (
                    completed_at is not None and timestamp > completed_at
                ):
                    continue
                if (
                    owner_turn_id is not None
                    and payload.get("turn_id", current_turn_id) != owner_turn_id
                ):
                    continue
                usage_observed = True
                model = payload.get("model", current_model)
                if not isinstance(model, str):
                    model = None
                _add_token_usage(total, usage)
                _add_token_usage(local_models.setdefault(model, _empty_token_usage()), usage)
                continue
            if event.get("type") != "event_msg" or payload.get("type") != "token_count":
                continue
            # Native rate-limit updates can carry no token usage.
            if "info" in payload and payload["info"] is None:
                continue
            timestamp = _timestamp(event.get("timestamp"))
            snapshot = _token_snapshot(payload)
            if timestamp is None or snapshot is None:
                warnings.add("token_record_invalid")
                continue
            if snapshot["totalTokens"] < previous["totalTokens"]:
                warnings.add("token_counter_regressed")
                continue
            delta = {key: max(0, value - previous[key]) for key, value in snapshot.items()}
            previous = snapshot
            if timestamp < started_at:
                continue
            if completed_at is not None and timestamp > completed_at:
                continue
            if owner_turn_id is not None and current_turn_id != owner_turn_id:
                continue
            usage_observed = True
            if not response_usage_observed:
                local_models.setdefault(current_model, _empty_token_usage())
            if delta["totalTokens"] <= 0:
                continue
            _add_token_usage(counter_total, delta)
            if not response_usage_observed:
                _add_token_usage(total, delta)
                _add_token_usage(
                    local_models.setdefault(current_model, _empty_token_usage()), delta
                )

    if counter_total["totalTokens"] > total["totalTokens"]:
        remainder = {key: max(0, value - total[key]) for key, value in counter_total.items()}
        total = dict(counter_total)
        _add_token_usage(local_models.setdefault(None, _empty_token_usage()), remainder)
    if response_usage_observed:
        warnings.discard("token_counter_regressed")
    if expected_response_tokens > response_tokens:
        warnings.add("token_receipts_incomplete")
    if model_usage is not None:
        for model, usage in local_models.items():
            _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), usage)
    if not boundary_reached:
        warnings.add("thread_ownership_unavailable")
    elif not usage_observed:
        warnings.add("token_usage_unavailable")
    return total, warnings


def _session_parent_thread_id(payload: Mapping[str, Any]) -> str | None:
    source = payload.get("source")
    if isinstance(source, dict):
        subagent = source.get("subagent")
        if isinstance(subagent, dict):
            thread_spawn = subagent.get("thread_spawn")
            if isinstance(thread_spawn, dict):
                parent = thread_spawn.get("parent_thread_id")
                if isinstance(parent, str) and parent:
                    return parent
    for key in ("parent_thread_id", "forked_from_id"):
        parent = payload.get(key)
        if isinstance(parent, str) and parent:
            return parent
    return None


def _is_owned_task_start(
    thread_id: str,
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
) -> bool:
    if event.get("type") != "event_msg" or payload.get("type") != "task_started":
        return False
    turn_id = payload.get("turn_id")
    if not isinstance(turn_id, str) or not turn_id:
        return False
    # Fresh Codex worker thread/turn IDs use a same-process monotonic UUIDv7 generator.
    thread_order = _uuid7_order(thread_id)
    turn_order = _uuid7_order(turn_id)
    if thread_order is None:
        return True
    return turn_order is not None and turn_order >= thread_order


def _uuid7_order(value: str) -> int | None:
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return None
    return parsed.int if parsed.version == 7 else None


def _token_snapshot(payload: Mapping[str, Any]) -> dict[str, int] | None:
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    usage = info.get("total_token_usage")
    if not isinstance(usage, dict):
        return None
    cache_write = usage.get("cache_write_input_tokens", usage.get("cache_write_tokens", 0))
    legacy_cache_write = usage.get("cache_write_tokens")
    input_tokens = usage.get("input_tokens")
    cached_input_tokens = usage.get("cached_input_tokens", 0)
    if (
        cache_write == 0
        and type(legacy_cache_write) is int
        and legacy_cache_write > 0
        and type(input_tokens) is int
        and type(cached_input_tokens) is int
        and cached_input_tokens + legacy_cache_write <= input_tokens
    ):
        cache_write = legacy_cache_write
    result: dict[str, int] = {}
    for source_key, result_key in TOKEN_FIELDS.items():
        value = (
            cache_write if source_key == "cache_write_input_tokens" else usage.get(source_key, 0)
        )
        if type(value) is not int or value < 0:
            return None
        if source_key in {"input_tokens", "output_tokens", "total_tokens"} and (
            source_key not in usage
        ):
            return None
        result[result_key] = value
    if result["cachedInputTokens"] + result["cacheWriteInputTokens"] > result["inputTokens"]:
        return None
    result["totalTokens"] = result["inputTokens"] + result["outputTokens"]
    return result


def _empty_token_usage() -> dict[str, int]:
    return {field: 0 for field in TOKEN_FIELDS.values()}


def _add_token_usage(target: dict[str, int], addition: Mapping[str, int]) -> None:
    for key in TOKEN_FIELDS.values():
        target[key] += addition[key]


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = (
            datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
            if value.endswith("Z")
            else datetime.fromisoformat(value)
        )
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None


def _unavailable_usage(reason: str, *, warnings: set[str] | None = None) -> dict[str, Any]:
    return {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": sorted({reason, *(warnings or set())}),
    }


def _reject_nonstandard_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
