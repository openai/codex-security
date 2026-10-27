"""Resolve accepted worker receipt references without changing their ownership."""

from __future__ import annotations

import copy
import os
import re
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _require_portable_relative_path,
    _require_str,
    _validate_schema_node,
    open_scan_local_file_descriptor,
    path_within_scope,
)
from workbench.saved_coverage import _project_worker_coverage_row, _saved_coverage_id


def _checkpoint_head_directory(relative: str) -> Path | None:
    path = Path(relative)
    if path.name == "checkpoint-head.json":
        return path.parent
    if path.parent.name == "checkpoint-heads":
        return path.parent.parent
    return None


def _is_source_order_snapshot(relative: str) -> bool:
    path = Path(relative)
    return path.parent == Path("source-order") and bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
    )


def capture_receipt_checkpoints(
    relative: str,
    kind: str | None,
    captured: dict[str, tuple[str, int]],
    checkpoint_paths: Callable[[str], list[str]],
    read_checkpoint: Callable[[str], tuple[dict[str, Any], str, int]],
) -> dict[str, tuple[str, int]]:
    """Bind a captured worker result to checkpoints visible after reading it."""
    if kind == "discovery" and Path(relative).name == "result.json":
        directory = (Path(relative).parent / "checkpoints").as_posix()
        for path in checkpoint_paths(directory):
            try:
                _, digest, observed = read_checkpoint(path)
            except (ContractError, OSError, ValueError):
                continue
            captured[path] = (digest, observed)
    return captured


def receipt_checkpoints(
    relative: str,
    worker_id: str | None,
    known: dict[str, str | None],
    checkpoint_paths: Callable[[str], list[str]],
) -> dict[str, str]:
    """Capture host checkpoints written after enumeration but before result.json."""
    if worker_id is None or Path(relative).name != "result.json":
        return {}
    directory = (Path(relative).parent / "checkpoints").as_posix()
    added = {path: worker_id for path in checkpoint_paths(directory) if path not in known}
    known.update(added)
    return added


def retain_recorded_receipt_ownership(
    sources: list[tuple[str, dict[str, Any], str | None]],
    digest: Callable[[Any], str],
    include_paths: Sequence[str],
    finding_scope: Sequence[tuple[str, bool]] | None = None,
) -> None:
    # Checkpoints are written by the host tool; direct result files can be authored
    # without it. Compare the entire payload within the same worker attempt.
    def payload_digest(draft: dict[str, Any]) -> str:
        return digest({key: value for key, value in draft.items() if key != "handoffClaimToken"})

    scope = (
        finding_scope if finding_scope is not None else [(path, False) for path in include_paths]
    )
    recorded: dict[Path, set[str]] = {}
    for relative, draft, worker_id in sources:
        directory = Path(relative).parent
        if worker_id is not None and directory.name == "checkpoints":
            payloads = recorded.setdefault(directory.parent, set())
            payloads.add(payload_digest(draft))
            if "." not in include_paths:
                # Legacy writers saved the checkpoint before filtering inherited findings.
                scoped = [
                    finding
                    for finding in draft["findings"]
                    if isinstance(finding, dict)
                    and isinstance(finding.get("locations"), list)
                    and any(
                        isinstance(location, dict)
                        and isinstance(location.get("path"), str)
                        and any(
                            PurePosixPath(location["path"]) == PurePosixPath(path)
                            if is_file
                            else path_within_scope(location["path"], path)
                            for path, is_file in scope
                        )
                        for location in finding["locations"]
                    )
                ]
                payloads.add(payload_digest({**draft, "findings": scoped}))
    for relative, draft, worker_id in sources:
        directory = Path(relative).parent
        if worker_id is None or directory.name == "checkpoints":
            continue
        if payload_digest(draft) in recorded.get(directory, set()):
            continue
        surfaces = draft["reviewState"].get("surfaces", [])
        for surface in surfaces if isinstance(surfaces, list) else []:
            if isinstance(surface, dict) and isinstance(surface.get("provenance"), dict):
                surface["provenance"].pop("scanReceiptRefs", None)


def resolve_coverage_receipts(
    scan_dir: Path, item: dict[str, Any], worker: Any, relative: str
) -> Any:
    refs = item.get("receiptRefs", [])
    if not isinstance(refs, list):
        return refs
    directory = Path(relative).parent
    if directory.name == "checkpoints":
        directory = directory.parent
    output = Path(worker["artifact_dir"]).relative_to(scan_dir)
    worker_prefix = (output.parent if output.name == "output" else output).as_posix() + "/"
    active_prefix = output.as_posix() + "/"
    if directory != output:
        refs = [
            f"{directory.as_posix()}/{Path(ref).as_posix()[len(active_prefix) :]}"
            if isinstance(ref, str) and Path(ref).as_posix().startswith(active_prefix)
            else ref
            for ref in refs
        ]

    def scan_receipt(ref: str) -> bool:
        try:
            descriptor = open_scan_local_file_descriptor(scan_dir, ref, "coverage receipt")
        except (ContractError, OSError):
            return False
        os.close(descriptor)
        return True

    def qualified_receipt(ref: Any) -> Any:
        if not isinstance(ref, str):
            return ref
        try:
            normalized = _require_portable_relative_path(ref, "Worker coverage receipt")
        except ContractError:
            return ref  # Leave malformed references to per-record recovery.
        if not normalized.startswith("artifacts/"):
            # A worker prefix must not make result.json a valid coverage receipt.
            return ref
        ref = normalized
        provenance = item.get("provenance")
        inherited_scan_refs = (
            provenance.get("scanReceiptRefs", []) if isinstance(provenance, dict) else []
        )
        if ref.startswith(worker_prefix) or (
            isinstance(inherited_scan_refs, list) and ref in inherited_scan_refs
        ):
            return ref
        local_ref = Path(f"{directory}/{ref}").as_posix()
        return local_ref if scan_receipt(local_ref) or not scan_receipt(ref) else ref

    return [qualified_receipt(ref) for ref in refs]


def _deferred_candidate_id(
    row: dict[str, Any],
    owner: str | None,
    ambiguous_deferred: set[tuple[str | None, str]],
) -> str | None:
    identity = row.get("candidateId") or row.get("id")
    if not isinstance(identity, str):
        return None
    if (owner, identity) in ambiguous_deferred and not any(
        key in row for key in ("candidateId", "candidate", "finding")
    ):
        return None
    return identity


def _generic_surface_updates(
    sources: list[tuple[str, dict[str, Any], str | None]],
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    resolved_candidates: dict[tuple[str | None, str], str],
    reopened_generic: set[tuple[str | None, str]],
    surface_schema: dict[str, Any],
    deferred_rows: dict[str, list[Any]],
    ambiguous_deferred: set[tuple[str | None, str]],
    record_source: Any,
    record_order: Any,
    surface_receipts: Any,
    *,
    canonical_rows: set[int] | None = None,
    coverage_sources: dict[int, tuple[dict[str, Any], list[str]]] | None = None,
    surface_is_retained: Any = None,
    eligible_receipt_sources: set[str] | None = None,
    receipt_root: Path | None = None,
    receipt_warnings: list[str] | None = None,
    fallback_surfaces: list[dict[str, Any]] | None = None,
) -> tuple[set[int], list[tuple[str, str | None, dict[str, Any], dict[str, Any]]]]:
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

    def record_key(field: str, owner: str | None, row: dict[str, Any]) -> tuple[str | None, Any]:
        source_owner, original = record_source(field, owner, row)
        identity = original.get("id")
        return source_owner, identity if isinstance(identity, str) else None

    def linked(row: dict[str, Any], identity: str | None, owner: str | None) -> bool:
        _, row = record_source("deferred", owner, row)
        surface_ids = row.get("surfaceIds", [])
        return identity is not None and (
            row.get("id") == identity or (isinstance(surface_ids, list) and identity in surface_ids)
        )

    saved_surfaces: dict[tuple[str | None, str], list[tuple[str, dict[str, Any]]]] = {}
    for relative, draft, owner in sources:
        rows = draft["reviewState"].get("surfaces", [])
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                saved_surfaces.setdefault(record_key("surfaces", owner, row), []).append(
                    (relative, row)
                )
    replaced: set[int] = set()
    updates: list[tuple[str, str | None, dict[str, Any], dict[str, Any]]] = []
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
            latest_source, latest_surface = max(
                retained, key=lambda match: record_order(match[0], key[0], match[1])
            )
            retained_surfaces[key] = latest_surface
            receipt_surfaces.extend(
                (key[0], row)
                for relative, row in retained
                if record_order(relative, key[0], row)
                == record_order(latest_source, key[0], latest_surface)
            )
        for relative, draft, owner in sources:
            rows = draft["reviewState"].get("surfaces", [])
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
        current = draft["reviewState"].get("surfaces", [])
        for surface in current if isinstance(current, list) else []:
            if not isinstance(surface, dict):
                continue
            surface_owner, identity = record_key("surfaces", owner, surface)
            closed_ids = {
                identity
                for (saved_owner, identity), (_, _, source) in closed_deferred.items()
                if saved_owner == surface_owner and source == relative
            }
            reopened_ids = {
                identity
                for (saved_owner, identity), (_, _, source) in active_deferred.items()
                if saved_owner == surface_owner
                and source == relative
                and (owner, identity) in reopened_generic
            }
            reopening = surface.get("disposition") == "needs_follow_up"
            work_ids = reopened_ids if reopening else closed_ids
            repair_only = not work_ids
            if repair_only and receipt_root is None:
                continue
            if not isinstance(identity, str):
                continue
            matches = saved_surfaces[(surface_owner, identity)]
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
            if any(
                "candidateId" in row or "candidate" in row or "finding" in row for _, row in matches
            ):
                continue
            if any(
                row is not surface
                and record_order(saved_path, surface_owner, row)
                >= record_order(relative, surface_owner, surface)
                and row.get("disposition") != surface.get("disposition")
                for saved_path, row in matches
            ):
                continue

            if not reopening and any(
                saved_owner == surface_owner
                and (
                    not isinstance(row.get("id") or row.get("candidateId"), str)
                    or (
                        isinstance(row.get("id"), str)
                        and (owner, row["id"]) in ambiguous_deferred
                        and not any(key in row for key in ("candidateId", "candidate", "finding"))
                    )
                )
                and linked(row, identity, saved_owner)
                for saved_path, _, saved_owner in sources
                for row in deferred_rows[saved_path]
                if isinstance(row, dict)
            ):
                continue
            if not reopening and any(
                saved_owner == surface_owner
                and (owner, deferred_id) not in closed_deferred
                and (
                    (candidate_id := _deferred_candidate_id(row, owner, ambiguous_deferred)) is None
                    or (owner, candidate_id) not in resolved_candidates
                )
                and linked(row, identity, saved_owner)
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
            latest_relative, latest_surface = max(
                receipt_matches, key=lambda match: record_order(match[0], surface_owner, match[1])
            )
            target = (
                retained_surfaces.get((surface_owner, identity)) if repair_only else latest_surface
            )
            if target is None:
                continue
            update = copy.deepcopy(target)
            # Historical evidence can repair a retained row without promoting
            # an unselected observation's label, notes, or other metadata.
            refs = copy.deepcopy(surface_receipts(latest_relative, latest_surface))
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
                for saved_relative, row in receipt_matches:
                    previous_refs = surface_receipts(saved_relative, row)
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
            entry = (latest_relative, surface_owner, latest_surface, update)
            if entry not in updates:
                receipt_paths.update(replacement_paths)
                updates.append(entry)
            retained = next(
                entry[3]
                for entry in updates
                if entry[:3] == (latest_relative, surface_owner, latest_surface)
                and entry[3] == update
            )
            if coverage_sources is not None:
                from workbench.retained_coverage import _inherit_coverage_sources

                _inherit_coverage_sources(
                    retained,
                    [latest_surface, *(row for _, row in matches if id(row) in replaced_sources)],
                    coverage_sources,
                )
            if canonical_rows is not None and id(latest_surface) in canonical_rows:
                canonical_rows.add(id(retained))
    return replaced, updates
