"""Project saved worker coverage and reconcile its published parent copies."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _normalize_unsealed_open_questions,
    _require_portable_relative_path,
    _require_str,
    _validate_schema_node,
    open_scan_local_file_descriptor,
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


def _candidate_scoped(row: dict[str, Any]) -> bool:
    return row.get("candidateScoped") is True or any(
        key in row for key in ("candidateId", "candidate", "finding")
    )


def _deferred_candidate_id(
    row: dict[str, Any],
    owner: str | None,
    ambiguous_deferred: set[tuple[str | None, str]],
) -> str | None:
    identity = row.get("candidateId") or row.get("id")
    if not isinstance(identity, str):
        return None
    if (owner, identity) in ambiguous_deferred and not _candidate_scoped(row):
        return None
    return identity


def _generic_surface_updates(
    sources: list[tuple[str, dict[str, Any], str | None]],
    source_order: dict[str, tuple[int, int]],
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    resolved_candidates: dict[tuple[str | None, str], str],
    reopened_generic: set[tuple[str | None, str]],
    surface_schema: dict[str, Any],
    deferred_rows: dict[str, list[Any]],
    ambiguous_deferred: set[tuple[str | None, str]],
    *,
    surface_is_retained: Callable[[str, str | None, dict[str, Any]], bool],
    eligible_receipt_sources: set[str],
    receipt_root: Path | None = None,
    receipt_warnings: list[str] | None = None,
    fallback_surfaces: list[dict[str, Any]] | None = None,
) -> tuple[set[int], list[tuple[str | None, dict[str, Any], set[int]]]]:
    if not closed_deferred and not reopened_generic and receipt_root is None:
        return set(), []

    def receipt_error(ref: Any) -> ContractError | None:
        if receipt_root is None or not isinstance(ref, str):
            return ContractError("Saved coverage receipt is unavailable.")
        try:
            descriptor = open_scan_local_file_descriptor(
                receipt_root, ref, "Saved coverage receipt"
            )
            os.close(descriptor)
        except ContractError as exc:
            return exc
        return None

    def linked(row: dict[str, Any], identity: str | None) -> bool:
        surface_ids = row.get("surfaceIds", [])
        return identity is not None and (
            row.get("id") == identity or (isinstance(surface_ids, list) and identity in surface_ids)
        )

    saved_surfaces: dict[tuple[str | None, str], list[tuple[str, dict[str, Any]]]] = {}
    for relative, draft, owner in sources:
        rows = draft["coverage"].get("surfaces", [])
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                saved_surfaces.setdefault((owner, row["id"]), []).append((relative, row))
    replaced: set[int] = set()
    updates: list[tuple[str | None, dict[str, Any], set[int]]] = []
    # Current selections across all surfaces take precedence over historical refs.
    receipt_paths: dict[str, str] = {}
    retained_surfaces: dict[tuple[str | None, str], dict[str, Any]] = {}
    if receipt_root is not None:
        receipt_surfaces: list[tuple[str | None, dict[str, Any]]] = []
        for key, matches in saved_surfaces.items():
            retained = [
                match for match in matches if surface_is_retained(match[0], key[0], match[1])
            ]
            if not retained:
                continue
            latest_source, latest_surface = max(retained, key=lambda match: source_order[match[0]])
            retained_surfaces[key] = latest_surface
            receipt_surfaces.extend(
                (key[0], row)
                for relative, row in retained
                if source_order[relative] == source_order[latest_source]
            )
        for relative, draft, owner in sources:
            rows = draft["coverage"].get("surfaces", [])
            for row in rows if isinstance(rows, list) else []:
                if (
                    isinstance(row, dict)
                    and "id" not in row
                    and surface_is_retained(relative, owner, row)
                ):
                    receipt_surfaces.append((owner, row))
        receipt_surfaces.extend((None, row) for row in fallback_surfaces or [])
        for owner, latest_surface in receipt_surfaces:
            # Recovery repairs disposition and receipts before validating row
            # metadata. A row discarded there cannot reserve a receipt spelling.
            metadata = _project_worker_coverage_row(latest_surface, owner, "surfaces")
            metadata.setdefault("id", _saved_coverage_id(metadata))
            metadata.update(disposition="needs_follow_up", receiptRefs=[])
            try:
                _require_str(metadata, "id", "coverage.surfaces")
                _validate_schema_node(metadata, surface_schema, "coverage.surfaces")
            except ContractError:
                continue
            refs = latest_surface.get("receiptRefs", [])
            for ref in refs if isinstance(refs, list) else []:
                if receipt_error(ref) is None:
                    normalized = _require_portable_relative_path(ref, "Saved coverage receipt")
                    receipt_paths.setdefault(normalized.lower(), normalized)
    for relative, draft, owner in sources:
        closed_ids = {
            identity
            for (saved_owner, identity), (_, _, source) in closed_deferred.items()
            if saved_owner == owner and source == relative
        }
        reopened_ids = {
            identity
            for (saved_owner, identity), (_, _, source) in active_deferred.items()
            if saved_owner == owner and source == relative and (owner, identity) in reopened_generic
        }
        if not closed_ids and not reopened_ids and receipt_root is None:
            continue
        current = draft["coverage"].get("surfaces", [])
        for surface in current if isinstance(current, list) else []:
            if not isinstance(surface, dict):
                continue
            reopening = surface.get("disposition") == "needs_follow_up"
            work_ids = reopened_ids if reopening else closed_ids
            repair_only = not work_ids
            if repair_only and receipt_root is None:
                continue
            identity = surface.get("id")
            if not isinstance(identity, str):
                continue
            matches = saved_surfaces[(owner, identity)]
            # Receipt repair alone cannot close or reopen a saved surface.
            if repair_only and any(
                row.get("disposition") != surface.get("disposition") for _, row in matches
            ):
                continue
            # Older writers could assign one ID to distinct surfaces in a draft.
            # A closure cannot identify which of those observations it replaces.
            by_source = dict(matches)
            if any(row != by_source[saved_path] for saved_path, row in matches):
                continue
            if any(_candidate_scoped(row) for _, row in matches):
                continue
            if any(
                row is not surface
                and source_order[saved_path] >= source_order[relative]
                and row.get("disposition") != surface.get("disposition")
                for saved_path, row in matches
            ):
                continue

            if not reopening and any(
                saved_owner == owner
                and (
                    not isinstance(row.get("id") or row.get("candidateId"), str)
                    or (
                        isinstance(row.get("id"), str)
                        and (owner, row["id"]) in ambiguous_deferred
                        and not _candidate_scoped(row)
                    )
                )
                and linked(row, identity)
                for saved_path, _, saved_owner in sources
                for row in deferred_rows[saved_path]
                if isinstance(row, dict)
            ):
                continue
            if not reopening and any(
                saved_owner == owner
                and (owner, deferred_id) not in closed_deferred
                and (
                    (candidate_id := _deferred_candidate_id(row, owner, ambiguous_deferred)) is None
                    or (owner, candidate_id) not in resolved_candidates
                )
                and linked(row, identity)
                for (saved_owner, deferred_id), (_, row, _) in active_deferred.items()
            ):
                continue
            # An accepted checkpoint can update a saved surface by ID without
            # optional surfaceIds links on its generic task.
            receipt_matches = [
                (saved_path, row)
                for saved_path, row in matches
                if receipt_root is None
                or saved_path in eligible_receipt_sources
                or surface_is_retained(saved_path, owner, row)
            ]
            if not receipt_matches:
                continue
            latest_surface = max(receipt_matches, key=lambda match: source_order[match[0]])[1]
            target = retained_surfaces.get((owner, identity)) if repair_only else latest_surface
            if target is None:
                continue
            update = copy.deepcopy(target)
            # Historical evidence can repair a retained row without promoting
            # an unselected observation's label, notes, or other metadata.
            refs = copy.deepcopy(latest_surface.get("receiptRefs", []))
            update["receiptRefs"] = refs
            replaced_receipt = False
            replacement_paths = dict(receipt_paths)
            if isinstance(refs, list):
                repaired = (
                    not reopening and bool(refs) and all(receipt_error(ref) is None for ref in refs)
                )
                if repaired:
                    for ref in refs:
                        normalized = _require_portable_relative_path(ref, "Saved coverage receipt")
                        key = normalized.lower()
                        if key in replacement_paths and replacement_paths[key] != normalized:
                            repaired = False
                            break
                        replacement_paths[key] = normalized
                for _, row in receipt_matches:
                    previous_refs = row.get("receiptRefs", [])
                    for ref in previous_refs if isinstance(previous_refs, list) else []:
                        if ref not in refs:
                            failure = receipt_error(ref) if repaired else None
                            replaceable = failure is not None and isinstance(
                                failure.__cause__, FileNotFoundError
                            )
                            if repaired and isinstance(ref, str):
                                try:
                                    normalized = _require_portable_relative_path(
                                        ref, "Saved coverage receipt"
                                    )
                                except ContractError as error:
                                    failure = error
                                    replaceable = True
                                else:
                                    key = normalized.lower()
                                    previous = replacement_paths.get(key)
                                    if previous is not None and previous != normalized:
                                        failure = ContractError(
                                            f"Saved coverage receipt: duplicate artifact path: {previous} and {normalized}"
                                        )
                                        replaceable = True
                                    elif not replaceable:
                                        replacement_paths[key] = normalized
                            if replaceable:
                                replaced_receipt = True
                                if receipt_warnings is not None:
                                    receipt_warnings.append(
                                        f"Replaced invalid saved coverage receipt {ref}: {failure}"
                                    )
                                continue
                            refs.append(ref)
            if repair_only and not replaced_receipt:
                continue
            try:
                _validate_schema_node(update, surface_schema, "coverage.surfaces")
            except ContractError:
                continue
            replaced_sources = {
                id(row)
                for _, row in matches
                if reopening
                or row.get("disposition") in {"needs_follow_up", surface.get("disposition")}
            }
            replaced.update(replaced_sources)
            existing = next(
                (entry for entry in updates if entry[0] == owner and entry[1] == update), None
            )
            if existing is None:
                receipt_paths.update(replacement_paths)
                updates.append((owner, update, replaced_sources))
            else:
                existing[2].update(replaced_sources)
    return replaced, updates
