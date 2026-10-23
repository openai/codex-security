"""Project saved worker coverage and reconcile its published parent copies."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _normalize_unsealed_open_questions,
    _require_portable_relative_path,
)


def _saved_coverage_id(item: dict[str, Any]) -> str:
    if candidate_id := item.get("candidateId"):
        return candidate_id
    payload = json.dumps(
        item, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return f"saved-{hashlib.sha256(payload).hexdigest()[:16]}"


def _project_worker_coverage_row(item: Any, worker_id: str | None, field: str) -> Any:
    row = copy.deepcopy(item)
    if worker_id is None or not isinstance(row, dict):
        return row
    row["workerId"] = worker_id
    if field == "openQuestions":
        return row
    # Reconcile raw checkpoint identities first. Anonymous output rows use the
    # existing content identity, never their position in an earlier snapshot.
    row.setdefault("id", _saved_coverage_id(row))
    if isinstance(row.get("id"), str):
        row["id"] = f"{worker_id}/{row['id']}"
    if field == "deferred" and isinstance(row.get("surfaceIds"), list):
        row["surfaceIds"] = [
            f"{worker_id}/{identity}" if isinstance(identity, str) else identity
            for identity in row["surfaceIds"]
        ]
    return row


def _coverage_comparison_row(row: Any, field: str) -> Any:
    if field == "surfaces" and isinstance(row, dict):
        row = {"receiptRefs": [], **row}
        if isinstance(row["receiptRefs"], list):
            refs = []
            for ref in row["receiptRefs"]:
                if isinstance(ref, str):
                    try:
                        ref = _require_portable_relative_path(ref, "Saved coverage receipt")
                    except ContractError:
                        pass  # Leave malformed refs to the existing per-record recovery.
                refs.append(ref)
            row["receiptRefs"] = refs
        return row
    if field == "openQuestions":
        coverage = {"openQuestions": [copy.deepcopy(row)]}
        _normalize_unsealed_open_questions(coverage)
        return next(iter(coverage["openQuestions"]), row)
    return row


def _aggregate_worker_coverage_rows(rows: list[Any], worker_id: str, field: str) -> list[Any]:
    """Match accepted aggregate IDs without changing raw recovery identities."""
    reserved = {
        row["id"] for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    emitted: set[str] = set()
    projected = []
    for index, original in enumerate(rows):
        row = copy.deepcopy(original)
        if isinstance(row, dict) and field != "openQuestions":
            generated = not isinstance(row.get("id"), str)
            identity = str(index) if generated else row["id"]
            base = identity
            if generated or identity in emitted:
                suffix = 2
                while identity in reserved:
                    identity = f"{base}-{suffix}"
                    suffix += 1
            reserved.add(identity)
            emitted.add(identity)
            row["id"] = identity
        projected.append(
            _coverage_comparison_row(_project_worker_coverage_row(row, worker_id, field), field)
        )
    return projected


def _prepare_worker_coverage_recovery(
    sources: list[tuple[str, dict[str, Any], str | None]],
    parent: dict[str, Any] | None,
    source_order: dict[str, tuple[int, int]],
    *,
    enabled: bool,
) -> tuple[
    bool, list[tuple[dict[str, Any], str, dict[str, Any], dict[str, Any], dict[str, Any] | None]]
]:
    """Put bound worker evidence in parent coordinates without changing source files."""
    workers = {owner for _, _, owner in sources if owner is not None}
    parents = [
        draft
        for _, draft, owner in sorted(
            sources, key=lambda source: source_order[source[0]], reverse=True
        )
        if owner is None
    ]
    if parent is not None:
        # Prefer the selected parent over historical copies of a task's surface.
        parents.insert(0, parent)
    fields = ("surfaces", "explicitExclusions", "deferred", "openQuestions")
    if not enabled:
        enabled = any(
            isinstance(row, dict)
            and isinstance(row.get("workerId"), str)
            and row["workerId"] in workers
            and (
                field == "openQuestions"
                or (isinstance(row.get("id"), str) and row["id"].startswith(f"{row['workerId']}/"))
            )
            for draft in parents
            for field in fields
            for row in (
                draft["coverage"].get(field, [])
                if isinstance(draft["coverage"].get(field, []), list)
                else []
            )
        )
    if not enabled:
        return False, []
    projected: dict[str, list[Any]] = {field: [] for field in fields}
    surface_sources: list[tuple[dict[str, Any], dict[str, Any]]] = []
    task_sources: list[tuple[dict[str, Any], dict[str, Any]]] = []
    surface_links: list[
        tuple[dict[str, Any], str, dict[str, Any], dict[str, Any], dict[str, Any] | None]
    ] = []
    for relative, draft, owner in sources:
        if owner is None:
            continue
        directory = Path(relative).parent
        if directory.name == "checkpoints":
            directory = directory.parent
        for field in fields:
            rows = draft["coverage"].get(field, [])
            if not isinstance(rows, list):
                continue
            for index, row in enumerate(rows):
                if field == "openQuestions" and isinstance(row, str):
                    row = {"question": row}
                    rows[index] = row
                if not isinstance(row, dict):
                    continue
                row["workerId"] = owner
                if field == "surfaces" and isinstance(row.get("receiptRefs"), list):
                    refs = []
                    for ref in row["receiptRefs"]:
                        if isinstance(ref, str):
                            try:
                                normalized = _require_portable_relative_path(
                                    ref, "Worker coverage receipt"
                                )
                            except ContractError:
                                pass  # Leave malformed refs to the existing per-record recovery.
                            else:
                                if normalized.startswith("artifacts/"):
                                    ref = f"{directory.as_posix()}/{normalized}"
                        refs.append(ref)
                    row["receiptRefs"] = refs
                if field == "surfaces":
                    row.setdefault("receiptRefs", [])
            aggregate_rows = _aggregate_worker_coverage_rows(rows, owner, field)
            projected[field].extend(aggregate_rows)
            if field in {"surfaces", "deferred"}:
                originals = surface_sources if field == "surfaces" else task_sources
                originals.extend(
                    (aggregate, row)
                    for aggregate, row in zip(aggregate_rows, rows)
                    if isinstance(aggregate, dict) and isinstance(row, dict)
                )
    # A canonical aggregate contains copies of the same worker evidence. Let
    # the existing per-worker chronology reconcile those originals exactly once.
    # Keep parent-only evidence when its bound worker source is unavailable.
    for draft in parents:
        if not draft["coverage"]:
            continue
        for field in fields:
            rows = draft["coverage"].get(field, [])
            if isinstance(rows, list):
                if field == "surfaces":
                    tasks = draft["coverage"].get("deferred", [])
                    for row in rows:
                        if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                            continue
                        matching_sources = [
                            original
                            for aggregate, original in surface_sources
                            if aggregate == _coverage_comparison_row(row, field)
                        ]
                        if not matching_sources:
                            continue
                        for task in tasks if isinstance(tasks, list) else []:
                            if (
                                isinstance(task, dict)
                                and isinstance(task.get("surfaceIds"), list)
                                and row["id"] in task["surfaceIds"]
                            ):
                                surface_links.extend(
                                    (
                                        task,
                                        row["id"],
                                        source,
                                        row,
                                        next(
                                            (
                                                original
                                                for aggregate, original in task_sources
                                                if aggregate == task
                                            ),
                                            None,
                                        ),
                                    )
                                    for source in matching_sources
                                )
                draft["coverage"][field] = [
                    row
                    for row in rows
                    if _coverage_comparison_row(row, field) not in projected[field]
                ]
    return True, surface_links
