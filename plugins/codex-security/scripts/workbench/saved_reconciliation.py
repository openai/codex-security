"""Reconcile saved finding identities and deferred coverage observations."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_json,
    _require_portable_relative_path,
    _require_str,
    _validate_resolved_deferred,
    _validate_schema_node,
    finding_candidate_id,
    open_scan_local_file_descriptor,
)
from workbench.saved_coverage import (
    _project_worker_coverage_row,
    _saved_coverage_id,
)


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def _finding_key(finding: dict[str, Any]) -> str:
    # Wording and evidence may improve between checkpoints; distinct source locations
    # must not collide merely because two workers chose the same semantic identity.
    provenance = finding.get("provenance")
    identity = (
        provenance.get("preservedIdentity", finding.get("identity"))
        if isinstance(provenance, dict)
        else finding.get("identity")
    )
    if not isinstance(identity, dict):
        normalized = dict(finding)
        normalized.pop("identity", None)
        _ensure_finding_identity(normalized)
        identity = normalized["identity"]
    identity = {key: identity[key] for key in ("anchor", "instance") if key in identity}
    return _digest([finding.get("ruleId"), identity, _finding_locations(finding)])


def _finding_locations(finding: dict[str, Any]) -> list[tuple[Any, Any, Any]]:
    locations = finding.get("locations", [])
    return sorted(
        (
            (
                location.get("path"),
                location.get("startLine"),
                location.get("endLine", location.get("startLine")),
            )
            for location in (locations if isinstance(locations, list) else [])
            if isinstance(location, dict)
        ),
        key=_encoded,
    )


def _worker_candidate_key(worker_id: str, candidate_id: str, finding: dict[str, Any]) -> str:
    """Identify one worker-local candidate without merging unrelated locations."""
    provenance = finding.get("provenance")
    identity = (
        provenance.get("preservedIdentity", finding.get("identity"))
        if isinstance(provenance, dict)
        else finding.get("identity")
    )
    if not isinstance(identity, dict):
        normalized = dict(finding)
        _ensure_finding_identity(normalized)
        identity = normalized.get("identity")
    anchor = identity.get("anchor") if isinstance(identity, dict) else None
    instance = identity.get("instance") if isinstance(identity, dict) else None
    return _digest([worker_id, candidate_id, finding.get("ruleId"), anchor, instance])


def _finding_content(finding: dict[str, Any]) -> dict[str, Any]:
    """Return substantive finding content without generated identity or provenance."""
    return {
        key: value
        for key, value in finding.items()
        if key not in {"findingId", "occurrenceId", "fingerprints", "identity", "provenance"}
    }


def _ensure_finding_identity(finding: Any, *, candidate_only: bool = False) -> None:
    if not isinstance(finding, dict) or "identity" in finding:
        return
    if candidate_only and not finding_candidate_id(finding):
        return
    extensions = finding.get("extensions")
    source = str(
        (extensions.get("candidateId") if isinstance(extensions, dict) else None)
        or finding.get("title")
        or "finding"
    )
    anchor = re.sub(r"[^a-z0-9._/-]+", "-", source.lower()).strip("._/-") or "finding"
    finding["identity"] = {"anchor": anchor}


def _saved_worker_owner(provenance: Any, owner: str | None) -> str | None:
    worker_id = provenance.get("workerId") if isinstance(provenance, dict) else None
    return owner or (worker_id if isinstance(worker_id, str) and worker_id else None)


def _retained_findings(
    finding: dict[str, Any],
    owner: str | None = None,
    *,
    source_owners: set[str] | None = None,
) -> Iterator[tuple[dict[str, Any], str | None]]:
    """Yield canonical and historical findings with their saved worker context."""
    pending = [(finding, owner, owner is not None)]
    seen: set[int] = set()
    while pending:
        current, owner, bound_owner = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        provenance = current.get("provenance")
        if isinstance(provenance, dict):
            # Registered sources keep their bound owner; unbound parent history
            # can carry a different worker on each retained observation.
            owner = (
                _saved_worker_owner(provenance, owner)
                if bound_owner
                else _saved_worker_owner(provenance, None) or owner
            )
        yield current, owner
        if not isinstance(provenance, dict):
            continue
        previous = provenance.get("previousFindings")
        if isinstance(previous, list):
            pending.extend(
                (item, owner, bound_owner) for item in reversed(previous) if isinstance(item, dict)
            )
        sources = provenance.get("sourceFindings")
        if isinstance(sources, list):
            for source in reversed(sources):
                if not isinstance(source, dict) or not isinstance(source.get("finding"), dict):
                    continue
                reference = source.get("id")
                source_owner = reference.rsplit(":", 1)[0] if isinstance(reference, str) else None
                source_bound = source_owners is not None and source_owner in source_owners
                pending.append(
                    (
                        source["finding"],
                        source_owner if source_bound else owner,
                        bound_owner or source_bound,
                    )
                )


def _deferred_rows(coverage: dict[str, Any]) -> list[Any]:
    rows = coverage.get("deferred", [])
    return rows if isinstance(rows, list) else []


def _resolved_deferred_rows(draft: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, Any]]:
    if draft.get("complete") is False:
        return []
    coverage = draft["coverage"]
    rows = coverage.get("resolvedDeferred", [])
    try:
        # Invalid closure metadata cannot discard the evidence it names.
        _validate_schema_node(rows, schema, "coverage.resolvedDeferred")
        _validate_resolved_deferred({**coverage, "deferred": _deferred_rows(coverage)})
    except ContractError:
        return []
    return rows


def _merge_tied_parent_observations(
    current: dict[str, Any], previous: dict[str, Any]
) -> dict[str, Any]:
    merged = copy.deepcopy(current)
    for finding in previous["findings"]:
        if finding not in merged["findings"]:
            merged["findings"].append(copy.deepcopy(finding))
    coverage = merged["coverage"]
    # A union with semantic checkpoint rows is no longer a canonical document.
    coverage.pop("documentType", None)
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        rows = previous["coverage"].get(field, [])
        output = coverage.setdefault(field, [])
        if isinstance(rows, list) and isinstance(output, list):
            for row in rows:
                if row not in output:
                    output.append(copy.deepcopy(row))
    pending_ids = {
        identity
        for row in _deferred_rows(coverage)
        if isinstance(row, dict)
        for identity in (row.get("id"), row.get("candidateId"))
        if isinstance(identity, str)
    }
    closure_schema = _read_json(
        Path(__file__).resolve().parents[2] / "schemas" / "coverage.schema.json"
    )["properties"]["resolvedDeferred"]
    closures = {}
    for observed in (current, previous):
        for row in _resolved_deferred_rows(observed, closure_schema):
            if row["id"] not in pending_ids:
                closures.setdefault(row["id"], copy.deepcopy(row))
    coverage.pop("resolvedDeferred", None)
    if closures:
        coverage["resolvedDeferred"] = list(closures.values())
    if current.get("complete") is False or previous.get("complete") is False:
        merged["complete"] = False
    coverage.pop("completeness", None)
    return merged


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
            if any(
                "candidateId" in row or "candidate" in row or "finding" in row for _, row in matches
            ):
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
                        and not any(key in row for key in ("candidateId", "candidate", "finding"))
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
                or row.get("disposition") in ("needs_follow_up", surface.get("disposition"))
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
