"""Measure scan-owned Codex token usage from the live thread graph."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sqlite3
import sys
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote

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


@dataclass
class RolloutUsage:
    tokens: dict[str, int]
    warnings: set[str]
    tokens_updated_at: datetime | None
    rate_limits: dict[str, dict[str, Any]]


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
    with connection:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'complete'",
            (cost_json, scan["id"]),
        )


def collect_scan_usage(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    *,
    thread_id: str | None = None,
    completed_at: str | None = None,
    completed_turn_id: str | None = None,
) -> dict[str, Any]:
    """Count attributable receipts and flag observable gaps inside the scan window."""

    completion_thread_id = thread_id
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
    parent_ids = set(_scan_root_thread_ids(connection, scan, thread_id, include_workers=False))
    worker_directories = _scan_worker_directories(connection, scan)
    if not roots and not worker_directories:
        return _unavailable_usage("scan_thread_unavailable")

    warnings: set[str] = set()
    current_database = _codex_state_database()
    worker_codex_home = None
    if scan["mode"] == "deep":
        # Only the workbench-bound original settings select a worker log home.
        from deep_scan_workbench import (
            recorded_deep_scan_execution_settings,
            validate_deep_scan_execution_settings,
        )

        run = connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
        ).fetchone()
        saved = recorded_deep_scan_execution_settings(run) if run is not None else None
        if saved is not None:
            try:
                settings = validate_deep_scan_execution_settings(saved)
                worker_codex_home = Path(settings["codexHome"])
            except SystemExit:
                # Legacy scans may have no recorded home. Keep usage best effort.
                pass
    groups = [(current_database, roots)]
    worker_roots: set[str] = set()
    if worker_codex_home is not None:
        worker_roots = set(
            _scan_root_thread_ids(connection, scan, None, include_owner_threads=False)
        )
        # Workers retain their Codex home, but inherit an explicit current
        # SQLite home. Their earlier and resumed sessions can be in either index.
        worker_database = _codex_state_database(worker_codex_home)
        if worker_database != current_database:
            groups.append((worker_database, [root for root in roots if root in worker_roots]))
    if not any(database is not None for database, _ in groups) and not worker_roots:
        return _unavailable_usage("codex_state_unavailable")

    started_at = _timestamp(scan["started_at"])
    observed_at = datetime.now(timezone.utc)
    stopped_at = _timestamp(completed_at or scan["completed_at"]) or observed_at
    if started_at is None:
        return _unavailable_usage("scan_window_unavailable")

    execution_thread_ids = set(attribution["executionThreadIds"]) if attribution else set()
    sessions: dict[str, list[RolloutSession]] = {}
    missing_thread_ids: set[str] = set()
    seen_thread_ids: set[str] = set()
    for state_database, group_roots in groups:
        if not group_roots and not worker_directories:
            continue
        try:
            if state_database is None:
                raise FileNotFoundError("Codex state is unavailable")
            discovered, missing = _discover_rollout_sessions(
                state_database,
                group_roots,
                warnings,
                descendant_roots=set(attribution["executionThreadIds"]) if attribution else None,
                worker_directories=worker_directories,
                started_at=started_at,
                completed_at=stopped_at,
            )
        except (OSError, sqlite3.Error, ValueError):
            warnings.add("codex_state_unavailable")
            missing_thread_ids.update(group_roots)
            continue
        missing_thread_ids.update(missing)
        for session in discovered:
            if session.parent_thread_id is None and session.thread_id not in roots:
                execution_thread_ids.add(session.thread_id)
            copies = sessions.setdefault(session.thread_id, [])
            if session not in copies:
                copies.append(session)
            seen_thread_ids.add(session.thread_id)

    if worker_codex_home is not None and worker_roots:
        # An external SQLite location can change on recovery. Native rollouts
        # still live in the recorded worker home; they retain their lineage.
        for session in _discover_recorded_worker_sessions(worker_codex_home, worker_roots):
            copies = sessions.setdefault(session.thread_id, [])
            if session not in copies:
                copies.append(session)
            seen_thread_ids.add(session.thread_id)

    # Absence from one known index is not missing usage when another has it.
    missing_thread_ids.difference_update(seen_thread_ids)
    if not missing_thread_ids:
        warnings.difference_update(
            {"scan_root_unavailable", "codex_state_unavailable", "rollout_unavailable"}
        )

    if not sessions:
        return _unavailable_usage(
            "codex_state_unavailable"
            if "codex_state_unavailable" in warnings
            else "scan_thread_unavailable",
            warnings=warnings,
        )

    by_role = {role: {**_empty_token_usage(), "threadCount": 0} for role in ("parent", "workers")}
    rate_limits: dict[str, dict[str, Any]] = {}
    tokens_updated_at = None
    accepted_thread_ids: set[str] = set()
    measured_thread_ids: set[str] = set()
    excluded_thread_ids: set[str] = set()
    model_usage: dict[str | None, dict[str, int]] = {}
    children: dict[str | None, list[str]] = {}
    for thread_id, copies in sessions.items():
        children.setdefault(copies[0].parent_thread_id, []).append(thread_id)
    pending = deque(
        thread_id
        for thread_id, copies in sessions.items()
        if copies[0].parent_thread_id not in sessions
    )
    ordered_thread_ids: list[str] = []
    while pending:
        thread_id = pending.popleft()
        ordered_thread_ids.append(thread_id)
        pending.extend(children.get(thread_id, []))
    # Keep unresolved lineage in the existing accounting checks as well.
    ordered = set(ordered_thread_ids)
    ordered_thread_ids.extend(thread_id for thread_id in sessions if thread_id not in ordered)
    for thread_id in ordered_thread_ids:
        copies = sessions[thread_id]
        session = copies[0]
        owner_turn_id = None
        if (
            attribution
            and session.thread_id not in execution_thread_ids
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
            usage = _read_rollout_copies_usage(
                copies,
                started_at=started_at,
                completed_at=stopped_at,
                owner_turn_id=owner_turn_id,
                completed_turn_id=(
                    completed_turn_id if session.thread_id == completion_thread_id else None
                ),
                model_usage=model_usage,
                is_scan_owner=(
                    scan["mode"] == "deep"
                    and session.thread_id == scan["deep_scan_owner_thread_id"]
                ),
            )
        except (OSError, UnicodeError, ValueError):
            missing_thread_ids.add(session.thread_id)
            warnings.add("rollout_unavailable")
            continue
        if "thread_outside_scan_window" in usage.warnings:
            excluded_thread_ids.add(session.thread_id)
            continue
        warnings.update(usage.warnings)
        if "thread_identity_mismatch" in usage.warnings or (
            "thread_ownership_unavailable" in usage.warnings
        ):
            missing_thread_ids.add(session.thread_id)
            continue
        accepted_thread_ids.add(session.thread_id)
        for key, snapshot in usage.rate_limits.items():
            if key not in rate_limits or snapshot["observedAt"] > rate_limits[key]["observedAt"]:
                rate_limits[key] = snapshot
        if "token_usage_unavailable" in usage.warnings:
            missing_thread_ids.add(session.thread_id)
            continue
        measured_thread_ids.add(session.thread_id)
        role = by_role["parent" if session.thread_id in parent_ids else "workers"]
        _add_token_usage(role, usage.tokens)
        role["threadCount"] += 1
        if usage.tokens_updated_at is not None:
            tokens_updated_at = max(
                tokens_updated_at or usage.tokens_updated_at, usage.tokens_updated_at
            )

    if not accepted_thread_ids:
        return _unavailable_usage("scan_thread_unavailable", warnings=warnings)
    if not measured_thread_ids:
        return _unavailable_usage(
            "token_usage_unavailable", warnings=warnings, rate_limits=rate_limits
        )

    if any(
        usage["cachedInputTokens"] + usage["cacheWriteInputTokens"] > usage["inputTokens"]
        or usage["totalTokens"] != usage["inputTokens"] + usage["outputTokens"]
        for usage in by_role.values()
    ):
        return _unavailable_usage(
            "token_breakdown_unavailable", warnings=warnings, rate_limits=rate_limits
        )

    if completed_turn_id is not None and tokens_updated_at is not None:
        stopped_at = max(stopped_at, tokens_updated_at)
    result: dict[str, Any] = {
        "coverage": "partial" if missing_thread_ids or warnings else "complete",
        "source": "codex_rollout",
        **{key: sum(role[key] for role in by_role.values()) for key in TOKEN_FIELDS.values()},
        "threadCount": len(measured_thread_ids),
        "byRole": by_role,
        "window": {"startedAt": started_at.isoformat(), "endedAt": stopped_at.isoformat()},
        "observedAt": observed_at.isoformat(),
        "accountRateLimits": [rate_limits[key] for key in sorted(rate_limits)],
    }
    if tokens_updated_at is not None:
        result["tokensUpdatedAt"] = tokens_updated_at.isoformat()
    if missing_thread_ids:
        result["missingThreadCount"] = len(missing_thread_ids)
    if warnings:
        result["warnings"] = sorted(warnings)
    if model_usage and (attribution or any(model is not None for model in model_usage)):
        result["modelUsage"] = [{"model": model, **usage} for model, usage in model_usage.items()]
    return result


def _read_rollout_copies_usage(
    copies: list[RolloutSession],
    *,
    started_at: datetime,
    completed_at: datetime | None,
    owner_turn_id: str | None,
    completed_turn_id: str | None = None,
    model_usage: dict[str | None, dict[str, int]],
    is_scan_owner: bool = False,
) -> RolloutUsage:
    readings = []
    for session in copies:
        local_models: dict[str | None, dict[str, int]] = {}
        try:
            usage, parsed_events = _read_rollout_usage_with_extent(
                session,
                started_at=started_at,
                completed_at=completed_at,
                owner_turn_id=owner_turn_id,
                completed_turn_id=completed_turn_id,
                model_usage=local_models,
                is_scan_owner=is_scan_owner,
            )
        except (OSError, UnicodeError, ValueError):
            continue
        readings.append((usage, local_models, parsed_events))
    if not readings:
        raise ValueError("No readable rollout copy.")
    attributable = [
        reading
        for reading in readings
        if not reading[0].warnings.intersection(
            {
                "thread_identity_mismatch",
                "thread_ownership_unavailable",
                "thread_outside_scan_window",
                "token_usage_unavailable",
            }
        )
    ]
    # Restored indexes can reference a prefix and its complete continuation.
    # Equal totals can precede later cache corrections or model receipts. Prefer
    # the parsed continuation, keeping all accounting from that one copy.
    usage, selected_models, _ = max(
        attributable or readings,
        key=lambda reading: (
            reading[0].tokens["totalTokens"],
            reading[2],
            "rollout_record_incomplete" not in reading[0].warnings,
        ),
    )
    for model, tokens in selected_models.items():
        _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), tokens)
    return usage


def _scan_root_thread_ids(
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    supplied_thread_id: str | None,
    *,
    include_owner_threads: bool = True,
    include_workers: bool = True,
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
    if include_workers and scan["mode"] == "deep":
        candidates.extend(
            row["sdk_thread_id"]
            for row in connection.execute(
                """
                SELECT sdk_thread_id FROM deep_scan_attempt_sessions WHERE scan_id = ?
                UNION
                SELECT sdk_thread_id FROM deep_scan_workers
                WHERE scan_id = ? AND sdk_thread_id IS NOT NULL
                UNION
                SELECT sdk_thread_id FROM deep_scan_worker_threads WHERE scan_id = ?
                ORDER BY sdk_thread_id
                """,
                (scan["id"], scan["id"], scan["id"]),
            )
        )
    roots: dict[str, None] = {}
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            roots[candidate] = None
    return list(roots)


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
        legacy = True
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
    from deep_scan_workbench import (
        DEEP_SCAN_WORKFLOW_VERSION,
        recorded_deep_scan_execution_settings,
        validate_deep_scan_execution_settings,
    )

    saved_settings = recorded_deep_scan_execution_settings(run)
    worker_home = {}
    if saved_settings is not None:
        worker_home["workerCodexHome"] = validate_deep_scan_execution_settings(saved_settings)[
            "codexHome"
        ]
    elif run["workflow_version"] == DEEP_SCAN_WORKFLOW_VERSION:
        worker_home["workerCodexHome"] = None
    return {
        "formatVersion": 1,
        **({"legacy": True} if legacy else {}),
        "executionThreadIds": executions,
        "owner": owner,
        "startedAt": scan["started_at"],
        "completedAt": scan["completed_at"],
        **worker_home,
    }


def scan_execution_fields(connection: sqlite3.Connection, scan: sqlite3.Row) -> dict[str, Any]:
    return {
        "threadIds": _scan_root_thread_ids(connection, scan, None),
        "executionThreadIds": _scan_execution_thread_ids(connection, scan),
        "executionAttribution": scan_execution_attribution(connection, scan),
    }


def _scan_worker_directories(connection: sqlite3.Connection, scan: sqlite3.Row) -> set[str]:
    if scan["mode"] != "deep":
        return set()
    return {
        row["artifact_dir"]
        if row["kind"] == "discovery"
        else str(Path(scan["scan_dir"]) / "artifacts")
        for row in connection.execute(
            "SELECT kind, artifact_dir FROM deep_scan_workers "
            "WHERE scan_id = ? AND kind IN ('discovery', 'dedup')",
            (scan["id"],),
        )
    }


def _codex_state_database(worker_codex_home: Path | None = None) -> Path | None:
    configured_home = os.environ.get("CODEX_HOME", "")
    current_home = Path(configured_home) if configured_home.strip() else Path.home() / ".codex"
    codex_home = worker_codex_home if worker_codex_home is not None else current_home
    same_home = worker_codex_home is None or codex_home.resolve() == current_home.resolve()
    configured_database = os.environ.get("CODEX_STATE_DB", "").strip() if same_home else ""
    if configured_database:
        path = Path(configured_database).expanduser()
        return path.resolve() if path.is_file() and os.access(path, os.R_OK) else None

    configured_sqlite_home = os.environ.get("CODEX_SQLITE_HOME", "") if same_home else ""
    search_roots = [
        *([Path(configured_sqlite_home)] if configured_sqlite_home.strip() else []),
        codex_home,
        codex_home / "sqlite",
    ]
    seen: set[Path] = set()
    for search_root in search_roots:
        try:
            if search_root.parts[:1] == ("~",):
                search_root = search_root.expanduser()
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
    worker_directories: set[str] | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
) -> tuple[list[RolloutSession], set[str]]:
    database = sqlite3.connect(
        f"file:{quote(str(state_database), safe='')}?mode=ro",
        uri=True,
        timeout=STATE_DATABASE_TIMEOUT_SECONDS,
    )
    try:
        database.row_factory = sqlite3.Row
        database.execute("PRAGMA query_only = ON")
        for table, required in (
            ("threads", {"id", "rollout_path"}),
            ("thread_spawn_edges", {"parent_thread_id", "child_thread_id"}),
        ):
            columns = {str(row["name"]) for row in database.execute(f"PRAGMA table_info({table})")}
            if not required.issubset(columns):
                raise ValueError("Codex state graph does not expose the required thread columns.")
        sessions: dict[str, RolloutSession] = {}
        missing_thread_ids: set[str] = set()
        root_ids = dict.fromkeys(roots)
        worker_directories = worker_directories or set()
        started_millisecond = (
            started_at.replace(microsecond=started_at.microsecond // 1000 * 1000)
            if started_at is not None
            else None
        )
        completed_timestamp = int(completed_at.timestamp()) if completed_at is not None else None
        directory_expression = "cwd"
        if worker_directories and os.name == "nt":
            from windows_scan_local_files import _normalized_windows_path

            database.create_function(
                "codex_security_path_key", 1, _normalized_windows_path, deterministic=True
            )
            directory_expression = "codex_security_path_key(cwd)"
            worker_directories = {_normalized_windows_path(value) for value in worker_directories}
        for directory in sorted(worker_directories):
            for row in database.execute(
                "SELECT id FROM threads WHERE cwd IS NOT NULL "
                f"AND {directory_expression} = ? AND created_at >= ? "
                "AND (? IS NULL OR created_at <= ?) ORDER BY id",
                (directory, int(started_at.timestamp()), completed_timestamp, completed_timestamp),
            ):
                root_ids[row["id"]] = None
        for root in root_ids:
            row = database.execute(
                "SELECT id, rollout_path FROM threads WHERE id = ?",
                (root,),
            ).fetchone()
            if row is None:
                missing_thread_ids.add(root)
                warnings.add("scan_root_unavailable")
                continue
            path = _rollout_path(row["rollout_path"])
            if path is None:
                missing_thread_ids.add(root)
                warnings.add("rollout_unavailable")
                continue
            if root not in roots:
                try:
                    with path.open("rb") as source:
                        metadata = json.loads(source.readline())
                except (OSError, ValueError):
                    missing_thread_ids.add(root)
                    warnings.add("rollout_unavailable")
                    continue
                if (
                    isinstance(metadata, dict)
                    and metadata.get("type") == "session_meta"
                    and isinstance(payload := metadata.get("payload"), dict)
                    and (payload.get("id") or payload.get("session_id")) == root
                    and (created_at := _timestamp(payload.get("timestamp"))) is not None
                    and created_at < started_millisecond
                ):
                    continue
            sessions[root] = RolloutSession(root, None, path)
            if descendant_roots is not None and root in roots and root not in descendant_roots:
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
                if child_id in sessions:
                    continue
                path = _rollout_path(descendant["rollout_path"])
                if path is None:
                    missing_thread_ids.add(child_id)
                    warnings.add("rollout_unavailable")
                    continue
                sessions[child_id] = RolloutSession(child_id, parent_id, path)
        return list(sessions.values()), missing_thread_ids
    finally:
        database.close()


def _discover_recorded_worker_sessions(codex_home: Path, roots: set[str]) -> list[RolloutSession]:
    codex_home = codex_home.resolve()
    recorded: dict[str, list[RolloutSession]] = {}
    children: dict[str, set[str]] = {}
    for candidate in sorted(
        candidate
        for directory in ("sessions", "archived_sessions")
        for candidate in (codex_home / directory).rglob("*.jsonl")
    ):
        path = _rollout_path(str(candidate))
        if path is None:
            continue
        try:
            with path.open("rb") as stream:
                metadata = json.loads(stream.readline())
        except (OSError, UnicodeError, ValueError):
            continue
        if not isinstance(metadata, dict) or metadata.get("type") != "session_meta":
            continue
        payload = metadata.get("payload")
        if not isinstance(payload, dict):
            continue
        thread_id = payload.get("id") or payload.get("session_id")
        if not isinstance(thread_id, str):
            continue
        parent_id = _session_parent_thread_id(payload)
        recorded.setdefault(thread_id, []).append(RolloutSession(thread_id, parent_id, path))
        if parent_id is not None:
            children.setdefault(parent_id, set()).add(thread_id)

    sessions: list[RolloutSession] = []
    included = set(roots)
    pending = deque(sorted(roots))
    while pending:
        thread_id = pending.popleft()
        for session in recorded.get(thread_id, []):
            sessions.append(
                RolloutSession(
                    thread_id,
                    None if thread_id in roots else session.parent_thread_id,
                    session.path,
                )
            )
        for child_id in sorted(children.get(thread_id, set()) - included):
            included.add(child_id)
            pending.append(child_id)
    return sessions


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
    completed_turn_id: str | None = None,
    is_scan_owner: bool = False,
) -> RolloutUsage:
    usage, _ = _read_rollout_usage_with_extent(
        session,
        started_at=started_at,
        completed_at=completed_at,
        owner_turn_id=owner_turn_id,
        completed_turn_id=completed_turn_id,
        model_usage=model_usage,
        is_scan_owner=is_scan_owner,
    )
    return usage


def _read_rollout_usage_with_extent(
    session: RolloutSession,
    *,
    started_at: datetime,
    completed_at: datetime | None,
    owner_turn_id: str | None = None,
    completed_turn_id: str | None = None,
    model_usage: dict[str | None, dict[str, int]] | None = None,
    is_scan_owner: bool = False,
) -> tuple[RolloutUsage, int]:
    parsed_events = 0
    result = RolloutUsage(_empty_token_usage(), set(), None, {})
    total = _empty_token_usage()
    counter_total = _empty_token_usage()
    warnings = result.warnings
    previous = _empty_token_usage()
    boundary_reached = False
    session_started_at: datetime | None = None
    current_turn_id: str | None = None
    current_model: str | None = None
    response_ids: set[str] = set()
    response_usage_observed = False
    response_tokens = 0
    expected_response_tokens = 0
    response_epoch_owned = False
    local_models: dict[str | None, dict[str, int]] = {}
    finished_total = _empty_token_usage()
    finished_models: dict[str | None, dict[str, int]] = {}
    observed_response_usage = _empty_token_usage()
    native_receipts = False
    completed_turn_measured = False
    direct_control_session = False
    started_turns: set[str] = set()
    open_turns: set[str] = set()
    closed_turns: set[str] = set()
    measured_turns: set[str] = set()

    def finish_turn() -> None:
        nonlocal total, counter_total, local_models, response_usage_observed, native_receipts
        # Turn receipts supersede overlapping legacy counters. Older receipts
        # lack a turn total, so retain the measured counter remainder as unknown-model usage.
        remainder = (
            {key: max(0, value - total[key]) for key, value in counter_total.items()}
            if not native_receipts
            else _empty_token_usage()
        )
        remainder["cachedInputTokens"] = min(
            remainder["cachedInputTokens"], remainder["inputTokens"]
        )
        remainder["cacheWriteInputTokens"] = min(
            remainder["cacheWriteInputTokens"],
            remainder["inputTokens"] - remainder["cachedInputTokens"],
        )
        remainder["reasoningOutputTokens"] = min(
            remainder["reasoningOutputTokens"], remainder["outputTokens"]
        )
        remainder["totalTokens"] = remainder["inputTokens"] + remainder["outputTokens"]
        if remainder["totalTokens"] > 0:
            if response_usage_observed:
                warnings.add("token_receipts_incomplete")
            _add_token_usage(total, remainder)
            _add_token_usage(local_models.setdefault(None, _empty_token_usage()), remainder)
        if response_usage_observed:
            warnings.discard("token_counter_regressed")
        _add_token_usage(finished_total, total)
        for model, usage in local_models.items():
            _add_token_usage(finished_models.setdefault(model, _empty_token_usage()), usage)
        total = _empty_token_usage()
        counter_total = _empty_token_usage()
        local_models = {}
        response_usage_observed = False
        native_receipts = False

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
            if isinstance(payload, dict):
                parsed_events += 1
            if event.get("type") in {"session_meta", "turn_context"} and isinstance(payload, dict):
                model = payload.get("model")
                if isinstance(model, str) and model:
                    current_model = model
            if line_number == 1:
                if event.get("type") != "session_meta" or not isinstance(payload, dict):
                    warnings.add("thread_identity_mismatch")
                    return result, parsed_events
                session_started_at = _timestamp(payload.get("timestamp"))
                recorded_id = payload.get("id") or payload.get("session_id")
                if recorded_id != session.thread_id:
                    warnings.add("thread_identity_mismatch")
                    return result, parsed_events
                recorded_parent = _session_parent_thread_id(payload)
                if session.parent_thread_id is not None:
                    if recorded_parent != session.parent_thread_id:
                        warnings.add("thread_identity_mismatch")
                        return result, parsed_events
                boundary_reached = (
                    session.parent_thread_id is None
                    and not recorded_parent
                    and not payload.get("forked_from_id")
                )
                # prepareCliDeepScanSession creates this owner through app-server
                # without a model turn, so its initial token usage is known zero.
                direct_control_session = (
                    boundary_reached
                    and is_scan_owner
                    and payload.get("originator") == "codex_security_deep_scan"
                )
                continue

            if not isinstance(payload, dict):
                continue
            if not boundary_reached:
                if _is_owned_task_start(session.thread_id, event, payload, session_started_at):
                    task_started_at = _timestamp(event.get("timestamp"))
                    if task_started_at is None:
                        warnings.add("thread_ownership_unavailable")
                        return result, parsed_events
                    if task_started_at < started_at or (
                        completed_at is not None
                        and task_started_at > completed_at
                        and payload.get("turn_id") != completed_turn_id
                    ):
                        warnings.add("thread_outside_scan_window")
                        return result, parsed_events
                    boundary_reached = True
                elif event.get("type") == "event_msg" and payload.get("type") == "token_count":
                    inherited_usage = _token_snapshot(payload)
                    if inherited_usage is not None:
                        previous = inherited_usage
                if not boundary_reached:
                    continue
            if event.get("type") == "event_msg" and payload.get("type") == "task_started":
                # The same owner can resume as a model-backed coordinator. Only
                # a provably post-scan turn leaves the original control zero intact.
                task_started_at = _timestamp(event.get("timestamp"))
                if (
                    completed_at is None
                    or task_started_at is None
                    or task_started_at <= completed_at
                    or (
                        completed_turn_id is not None
                        and payload.get("turn_id") == completed_turn_id
                    )
                ):
                    direct_control_session = False
            if event.get("type") == "turn_context" or (
                event.get("type") == "event_msg" and payload.get("type") == "task_started"
            ):
                next_turn_id = payload.get("turn_id")
                if (
                    completed_turn_id is not None
                    and current_turn_id == completed_turn_id
                    and next_turn_id != completed_turn_id
                ):
                    break
                if next_turn_id != current_turn_id:
                    finish_turn()
                    observed_response_usage = _empty_token_usage()
                current_turn_id = next_turn_id
                if event.get("type") == "event_msg" and (
                    owner_turn_id is None or current_turn_id == owner_turn_id
                ):
                    timestamp = _timestamp(event.get("timestamp"))
                    if (
                        not isinstance(current_turn_id, str)
                        or not current_turn_id
                        or timestamp is None
                    ):
                        warnings.add("turn_record_invalid")
                    elif (
                        completed_at is None
                        or timestamp <= completed_at
                        or current_turn_id == completed_turn_id
                    ):
                        started_turns.add(current_turn_id)
                        open_turns.add(current_turn_id)
                continue
            if event.get("type") == "event_msg" and payload.get("type") in {
                "task_complete",
                "turn_aborted",
            }:
                timestamp = _timestamp(event.get("timestamp"))
                terminal_turn_id = payload.get("turn_id") or current_turn_id
                if (
                    not isinstance(terminal_turn_id, str)
                    or not terminal_turn_id
                    or timestamp is None
                ):
                    warnings.add("turn_record_invalid")
                elif (owner_turn_id is None or terminal_turn_id == owner_turn_id) and (
                    completed_at is None
                    or timestamp <= completed_at
                    or terminal_turn_id == completed_turn_id
                ):
                    open_turns.discard(terminal_turn_id)
                    if timestamp >= started_at:
                        if terminal_turn_id in started_turns:
                            closed_turns.add(terminal_turn_id)
                        if payload.get("type") == "turn_aborted":
                            # Later successful work does not recover interrupted request usage.
                            warnings.add("turn_interrupted")
            if (
                completed_turn_id is not None
                and event.get("type") == "event_msg"
                and payload.get("type") == "task_complete"
                and payload.get("turn_id") == completed_turn_id
            ):
                break
            if event.get("type") == "compacted":
                timestamp = _timestamp(event.get("timestamp"))
                if (
                    timestamp is not None
                    and timestamp >= started_at
                    and (
                        completed_at is None
                        or timestamp <= completed_at
                        or (completed_turn_id is not None and current_turn_id == completed_turn_id)
                    )
                    and (owner_turn_id is None or current_turn_id == owner_turn_id)
                    and "compaction_response_id" not in payload
                    and not response_usage_observed
                ):
                    warnings.add("compaction_usage_unavailable")
                # Later receipt counters describe a new compaction epoch and cannot
                # account for missing receipts from the earlier one.
                if response_epoch_owned and expected_response_tokens > response_tokens:
                    warnings.add("token_receipts_incomplete")
                response_tokens = 0
                expected_response_tokens = 0
                response_epoch_owned = False
                continue
            if event.get("type") == "token_usage_record":
                response_id = payload.get("response_id")
                usage = _usage_counts(payload.get("usage"))
                timestamp = _timestamp(event.get("timestamp"))
                if not isinstance(payload.get("thread_id"), str):
                    warnings.add("token_record_invalid")
                    continue
                if payload.get("thread_id") != session.thread_id:
                    continue
                if (
                    not isinstance(response_id, str)
                    or not response_id
                    or usage is None
                    or timestamp is None
                ):
                    warnings.add("token_record_invalid")
                    continue
                is_completion_turn = (
                    completed_turn_id is not None and payload.get("turn_id") == completed_turn_id
                )
                if completed_at is not None and timestamp > completed_at and not is_completion_turn:
                    continue
                if current_turn_id is None:
                    current_turn_id = payload.get("turn_id")
                    if isinstance(current_turn_id, str) and (
                        owner_turn_id is None or current_turn_id == owner_turn_id
                    ):
                        open_turns.add(current_turn_id)
                if response_id in response_ids:
                    continue
                response_ids.add(response_id)
                turn_usage = _usage_counts(payload.get("turn_token_usage"))
                _add_token_usage(observed_response_usage, usage)
                cumulative = _usage_counts(payload.get("thread_token_usage"))
                if cumulative is not None and turn_usage is None:
                    expected_response_tokens = max(
                        expected_response_tokens, cumulative["totalTokens"]
                    )
                response_tokens += usage["totalTokens"]
                receipt_turn_id = payload.get("turn_id")
                if isinstance(receipt_turn_id, str):
                    measured_turns.add(receipt_turn_id)
                if timestamp < started_at:
                    if turn_usage is not None:
                        observed_response_usage = turn_usage
                    continue
                if (
                    owner_turn_id is not None
                    and payload.get("turn_id", current_turn_id) != owner_turn_id
                ):
                    continue
                if current_turn_id is None:
                    current_turn_id = payload.get("turn_id")
                if turn_usage is not None:
                    native_receipts = True
                    if any(
                        turn_usage[key] > observed_response_usage[key]
                        for key in TOKEN_FIELDS.values()
                    ):
                        warnings.add("token_record_incomplete")
                else:
                    response_epoch_owned = True
                if is_completion_turn:
                    completed_turn_measured = True
                if not response_usage_observed:
                    response_usage_observed = True
                    total = _empty_token_usage()
                    local_models = {}
                result.tokens_updated_at = max(result.tokens_updated_at or timestamp, timestamp)
                model = payload.get("model", current_model)
                if not isinstance(model, str):
                    model = None
                _add_token_usage(total, usage)
                _add_token_usage(local_models.setdefault(model, _empty_token_usage()), usage)
                continue
            if event.get("type") != "event_msg" or payload.get("type") != "token_count":
                continue
            # Native rate-limit updates can carry no token usage.
            timestamp = _timestamp(event.get("timestamp"))
            in_window = (
                timestamp is not None
                and timestamp >= started_at
                and (
                    completed_at is None
                    or timestamp <= completed_at
                    or (completed_turn_id is not None and current_turn_id == completed_turn_id)
                )
            )
            if in_window and (owner_turn_id is None or current_turn_id == owner_turn_id):
                rate_limits = _rate_limit_snapshot(payload.get("rate_limits"), timestamp)
                if rate_limits is not None:
                    key = rate_limits["limitId"]
                    if (
                        key not in result.rate_limits
                        or rate_limits["observedAt"] >= result.rate_limits[key]["observedAt"]
                    ):
                        result.rate_limits[key] = rate_limits
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
            is_completion_turn = (
                completed_turn_id is not None and current_turn_id == completed_turn_id
            )
            if completed_at is not None and timestamp > completed_at and not is_completion_turn:
                continue
            if owner_turn_id is not None and current_turn_id != owner_turn_id:
                continue
            if isinstance(current_turn_id, str):
                measured_turns.add(current_turn_id)
            if timestamp < started_at:
                continue
            if is_completion_turn:
                completed_turn_measured = True
            result.tokens_updated_at = max(result.tokens_updated_at or timestamp, timestamp)
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

    finish_turn()

    if response_epoch_owned and expected_response_tokens > response_tokens:
        warnings.add("token_receipts_incomplete")
    if model_usage is not None:
        for model, usage in finished_models.items():
            _add_token_usage(model_usage.setdefault(model, _empty_token_usage()), usage)
    if not boundary_reached:
        warnings.add("thread_ownership_unavailable")
    elif result.tokens_updated_at is None and not direct_control_session:
        warnings.add("token_usage_unavailable")
    if completed_turn_id is not None:
        open_turns.discard(completed_turn_id)
    if open_turns:
        warnings.add("turn_in_progress")
    if boundary_reached and result.tokens_updated_at is None and not direct_control_session:
        warnings.add("token_record_missing")
    if closed_turns - measured_turns:
        warnings.add("token_record_missing")
    if completed_turn_id is not None and not completed_turn_measured:
        warnings.add("completion_turn_unavailable")
    result.tokens = finished_total
    return result, parsed_events


def _rate_limit_snapshot(value: object, timestamp: datetime) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, Any] = {
        "limitId": value.get("limit_id") or "codex",
        "observedAt": timestamp.isoformat(),
    }
    for name in ("primary", "secondary"):
        window = value.get(name)
        if window is None:
            result[name] = None
            continue
        if not isinstance(window, dict):
            return None
        result[name] = {
            "usedPercent": window.get("used_percent"),
            "windowMinutes": window.get("window_minutes"),
            "resetsAt": window.get("resets_at"),
        }
    return result if valid_account_rate_limit(result) else None


def valid_account_rate_limit(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "limitId",
        "observedAt",
        "primary",
        "secondary",
    }:
        return False
    if not isinstance(value["limitId"], str) or _timestamp(value["observedAt"]) is None:
        return False
    for name in ("primary", "secondary"):
        window = value[name]
        if window is None:
            continue
        if not isinstance(window, dict) or set(window) != {
            "usedPercent",
            "windowMinutes",
            "resetsAt",
        }:
            return False
        percent = window["usedPercent"]
        if type(percent) not in (int, float) or not math.isfinite(percent):
            return False
        if any(
            window[key] is not None and type(window[key]) is not int
            for key in ("windowMinutes", "resetsAt")
        ):
            return False
    return True


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
    session_started_at: datetime | None,
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
        task_started_at = payload.get("started_at")
        return (
            type(task_started_at) in {int, float}
            and session_started_at is not None
            and task_started_at >= math.floor(session_started_at.timestamp())
        )
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
    return _usage_counts(info.get("total_token_usage"))


def _usage_counts(usage: object) -> dict[str, int] | None:
    if not isinstance(usage, dict):
        return None
    cache_write = usage.get("cache_write_input_tokens", usage.get("cache_write_tokens", 0))
    legacy_cache_write = usage.get("cache_write_tokens")
    input_tokens = usage.get("input_tokens")
    cached_input_tokens = usage.get("cached_input_tokens", 0)
    if (
        type(cache_write) is int
        and cache_write == 0
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
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _unavailable_usage(
    reason: str,
    *,
    warnings: set[str] | None = None,
    rate_limits: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "coverage": "unavailable",
        "source": "codex_rollout",
        "threadCount": 0,
        "warnings": sorted({reason, *(warnings or set())}),
    }
    if rate_limits:
        result["accountRateLimits"] = [rate_limits[key] for key in sorted(rate_limits)]
    return result


def _reject_nonstandard_json_number(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
