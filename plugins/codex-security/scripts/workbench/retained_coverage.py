"""Retain semantic scan drafts without rerunning analysis or changing run state."""

from __future__ import annotations

import copy
import os
import re
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _has_identity_text,
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
from workbench.saved_sources import (
    _digest,
    _encoded,
)

_FINDING_IDENTITY_SCHEMA = _read_json(
    Path(__file__).resolve().parents[2] / "schemas" / "findings.schema.json"
)["properties"]["findings"]["items"]["properties"]["identity"]


import hashlib
from pathlib import PurePosixPath

from finalize_scan_contract import (
    _finding_strength,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _require_safe_json_value,
    _validate_current_findings,
    write_scan_local_bytes,
)
from workbench.saved_coverage import _prepare_worker_coverage_recovery
from workbench.saved_sources import (
    _capture_parent_observation,
    _capture_saved_source,
    _checkpoint_head_directory,
    _checkpoint_paths,
    _freeze_source_times,
    _frozen_source_times,
    _is_source_order_snapshot,
    _latest_successful_reducer,
    _parent_publication_ancestors,
    _read_saved_parent_result,
    _read_saved_result,
    _worker_outputs,
)
from workbench_target import committed_diff_snapshot_digest
from workbench_validation import path_within_scope


def _finding_identity(finding: dict[str, Any]) -> Any:
    provenance = finding.get("provenance")
    if isinstance(provenance, dict) and "preservedIdentity" in provenance:
        try:
            _validate_schema_node(
                provenance["preservedIdentity"], _FINDING_IDENTITY_SCHEMA, "finding.identity"
            )
        except ContractError:
            pass
        else:
            return provenance["preservedIdentity"]
    return finding.get("identity")


def _finding_key(finding: dict[str, Any], owner: str | None = None) -> str:
    # Wording and evidence may improve between checkpoints; distinct source locations
    # must not collide merely because two workers chose the same semantic identity.
    provenance = finding.get("provenance")
    identity = _finding_identity(finding)
    if not isinstance(identity, dict):
        normalized = dict(finding)
        normalized.pop("identity", None)
        _ensure_finding_identity(normalized)
        identity = normalized["identity"]
    owner = provenance.get("workerId", owner) if isinstance(provenance, dict) else owner
    parts = [finding.get("ruleId"), identity, _finding_locations(finding)]
    if owner is not None and finding_candidate_id(finding):
        parts.append(owner)
    return _digest(parts)


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


def _worker_candidate_key(
    worker_id: str, candidate_id: str, finding: dict[str, Any]
) -> tuple[str, str, Any, Any, Any]:
    """Identify one worker-local candidate without merging unrelated locations."""
    identity = _finding_identity(finding)
    if not isinstance(identity, dict):
        normalized = dict(finding)
        _ensure_finding_identity(normalized)
        identity = normalized.get("identity")
    anchor = identity.get("anchor") if isinstance(identity, dict) else None
    instance = identity.get("instance") if isinstance(identity, dict) else None
    return worker_id, candidate_id, finding.get("ruleId"), anchor, instance


def _finding_content(finding: dict[str, Any]) -> dict[str, Any]:
    """Return substantive finding content without generated identity or provenance."""
    return {
        key: value
        for key, value in finding.items()
        if key not in {"findingId", "occurrenceId", "fingerprints", "identity", "provenance"}
    }


def _identity_candidate(finding: dict[str, Any]) -> str | None:
    return next(
        (
            value
            for section in (finding.get("extensions"), finding.get("provenance"))
            if isinstance(section, dict) and _has_identity_text(value := section.get("candidateId"))
        ),
        None,
    )


def _ensure_finding_identity(finding: Any) -> None:
    _ensure_finding_identities([finding])


def _semantic_identifier(value: str, fallback: str) -> str:
    normalized = re.sub(r"[\u0300-\u036f]", "", unicodedata.normalize("NFKD", value))
    identifier = re.sub(r"[^a-z0-9._/-]+", "-", normalized.lower())
    return re.sub(r"^[^a-z0-9]+|-+$", "", identifier) or fallback


def _semantic_identity_key(finding: dict[str, Any], identity: Any = None) -> bytes:
    identity = finding.get("identity") if identity is None else identity
    if isinstance(identity, dict):
        identity = {key: identity.get(key) for key in ("anchor", "instance")}
    return _encoded([finding.get("ruleId"), identity])


def _ensure_finding_identities(findings: list[Any], *, deep: bool = False) -> None:
    """Use the same candidate, anchor and sibling rules as draft publication."""
    anchors: dict[int, Any] = {}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        identity = finding.get("identity")
        if "identity" in finding:
            anchors[index] = identity.get("anchor") if isinstance(identity, dict) else None
            continue
        candidate = _identity_candidate(finding)
        anchors[index] = _semantic_identifier(
            candidate or str(finding.get("title") or "finding"), f"finding-{index + 1}"
        )
    counts = Counter(
        _digest([findings[index].get("ruleId"), anchor]) for index, anchor in anchors.items()
    )

    authored = {
        _semantic_identity_key(finding)
        for finding in findings
        if isinstance(finding, dict) and "identity" in finding
    }
    generated = []
    for index, anchor in anchors.items():
        finding = findings[index]
        if "identity" in finding:
            continue
        identity = {"anchor": anchor}
        extensions = finding.get("extensions")
        sibling = next(
            (
                value
                for field in ("reportId", "ledgerRowId")
                if isinstance(extensions, dict)
                and _has_identity_text(value := extensions.get(field))
            ),
            None,
        )
        if sibling or counts[_digest([finding.get("ruleId"), anchor])] > 1:
            identity["instance"] = _semantic_identifier(
                sibling or str(finding.get("title") or "finding"), f"finding-{index + 1}"
            )
        finding["identity"] = identity
        generated.append(finding)

    reserved = {
        _semantic_identity_key(finding) for finding in findings if isinstance(finding, dict)
    }
    used = set() if deep else authored.copy()
    generated_ids = {id(finding) for finding in generated}
    for finding in findings if deep else generated:
        key = _semantic_identity_key(finding)
        if key in used or (id(finding) in generated_ids and key in authored):
            identity = finding["identity"]
            if id(finding) not in generated_ids:
                finding.setdefault("provenance", {}).setdefault(
                    "preservedIdentity", copy.deepcopy(identity)
                )
            base_instance = identity.get("instance", "saved")
            suffix = 2
            while True:
                identity["instance"] = f"{base_instance}-{suffix}"
                key = _semantic_identity_key(finding)
                if key not in reserved:
                    reserved.add(key)
                    break
                suffix += 1
        used.add(key)


def _retained_findings(finding: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield canonical and historical findings without trusting candidate IDs."""
    pending = [finding]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        yield current
        provenance = current.get("provenance")
        if not isinstance(provenance, dict):
            continue
        previous = provenance.get("previousFindings")
        if isinstance(previous, list):
            pending.extend(item for item in reversed(previous) if isinstance(item, dict))
        sources = provenance.get("sourceFindings")
        if isinstance(sources, list):
            pending.extend(
                source["finding"]
                for source in reversed(sources)
                if isinstance(source, dict) and isinstance(source.get("finding"), dict)
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


def _inherit_coverage_sources(
    row: Any,
    originals: list[Any],
    sources: dict[int, tuple[dict[str, Any], list[str]]],
) -> None:
    if not isinstance(row, dict):
        return
    for original in originals:
        saved = sources.get(id(original))
        if saved is None:
            continue
        # Retain the object as well as its ID while copies are reconciled.
        paths = sources.setdefault(id(row), (row, []))[1]
        for relative in saved[1]:
            if relative not in paths:
                paths.append(relative)


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
    canonical_rows: set[int],
    coverage_sources: dict[int, tuple[dict[str, Any], list[str]]],
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
            retained = next(
                entry[1] for entry in updates if entry[0] == owner and entry[1] == update
            )
            _inherit_coverage_sources(
                retained,
                [latest_surface, *(row for _, row in matches if id(row) in replaced_sources)],
                coverage_sources,
            )
            if id(latest_surface) in canonical_rows:
                canonical_rows.add(id(retained))
    return replaced, updates


def merge_saved_results(
    scan_dir: Path,
    scan_id: str,
    binding: dict[str, Any],
    workers: list[Any],
    warnings: list[str],
    *,
    stopped: bool,
    reason: str,
    scan_mode: str | None = None,
    frozen_source_digests: dict[str, str] | None = None,
    allow_frozen_legacy_parent: bool = False,
    frozen_model_source: str | None = None,
    selected_model_source: list[str] | None = None,
    finding_scope: list[tuple[str, bool]] | None = None,
    preserve_canonical_parent: bool = False,
    project_worker_coverage: bool = False,
    created_paths: set[str] | None = None,
    current_contract: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Read only bound parent/worker files; return an unsealed loss-preserving union."""
    initial_warnings = set(warnings)
    parent_context: dict[str, str] = {}
    try:
        source_times = _frozen_source_times(
            scan_dir, scan_id, frozen_source_digests or {}, parent_context
        )
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
    parent: dict[str, Any] | None = None
    parent_manifest: dict[str, Any] | None = None
    parent_is_canonical = False
    parent_modified = 0
    if frozen_source_digests is None or allow_frozen_legacy_parent:
        try:
            parent_manifest, parent = _read_saved_parent_result(scan_dir, scan_id)
            # Without an accepted head, file-authored coverage is a full replacement.
            parent_modified = (scan_dir / "coverage.json").lstat().st_mtime_ns
            parent_is_canonical = True
        except (ContractError, OSError, ValueError) as exc:
            if not stopped:
                raise
            if (scan_dir / "scan-manifest.json").exists():
                warnings.append(f"Could not read the saved parent draft: {exc}")
            parent_manifest = None
            parent = None
        if parent_manifest is not None and parent is not None and not preserve_canonical_parent:
            parent_scan = parent_manifest["scan"]
            try:
                _, _, head_modified = _read_saved_result(scan_dir, "checkpoint-head.json", scan_id)
            except (ContractError, OSError, ValueError):
                head_modified = None
            if head_modified is not None:
                # A partial tool publication must not outrank its accepted head.
                parent_modified = min(
                    (scan_dir / name).lstat().st_mtime_ns
                    for name in ("findings.json", "coverage.json", "scan-manifest.json")
                )
            if not parent_scan.get("sealedAt") or allow_frozen_legacy_parent:
                payload = _encoded(parent)
                parent_digest = hashlib.sha256(payload).hexdigest()
                parent_checkpoint = f"checkpoints/{parent_digest}.json"
                parent_context["canonical"] = parent_checkpoint
                parent_context["canonicalObservedAtNs"] = str(parent_modified)
                checkpoint_path = scan_dir / parent_checkpoint
                if not checkpoint_path.exists():
                    if created_paths is not None and not os.path.lexists(checkpoint_path):
                        created_paths.add(parent_checkpoint)
                    write_scan_local_bytes(scan_dir, parent_checkpoint, payload)
                    # A recovery copy must not appear newer than the review it copies.
                    os.utime(checkpoint_path, ns=(parent_modified, parent_modified))
                captured = (
                    _capture_saved_source(
                        scan_dir, "checkpoint-head.json", scan_id, created_paths=created_paths
                    )
                    if head_modified is not None
                    else _capture_parent_observation(
                        scan_dir,
                        checkpoint_path.name,
                        parent_modified,
                        allow_frozen_legacy_parent,
                        created_paths=created_paths,
                    )
                )
                if head_modified is not None or allow_frozen_legacy_parent:
                    parent_context["head"] = next(iter(captured))
                if frozen_source_digests is not None:
                    frozen_source_digests = {
                        **frozen_source_digests,
                        parent_checkpoint: parent_digest,
                        **{path: value[0] for path, value in captured.items()},
                    }

    sources: list[tuple[str, dict[str, Any], str | None]] = []
    parent_preserved_sources: dict[str, str] = {}
    source_digests: dict[str, str] = {}
    source_order: dict[str, tuple[int, int]] = {}
    worker_attempts: dict[str, tuple[str, int]] = {}
    saved_heads: dict[str, str] = {}
    saved_inputs: dict[str, str] = {}
    if parent_manifest:
        recorded = parent_manifest["scan"].get("preservedSources", {})
        if isinstance(recorded, dict):
            parent_preserved_sources = recorded
            source_digests.update(parent_preserved_sources)
            if frozen_source_digests is None:
                source_times.update(_frozen_source_times(scan_dir, scan_id, recorded))
    paths: dict[str, str | None] = {}
    reducer_paths: set[str] = set()
    current_results: set[str] = set()
    reducer_outputs: list[tuple[Any, str, list[str], int]] = []
    reducer = _latest_successful_reducer(workers)
    latest_reducer: str | None = None
    if reducer is not None:
        try:
            latest_reducer = Path(reducer["result_manifest_path"]).relative_to(scan_dir).as_posix()
            paths[latest_reducer] = None
            reducer_paths.add(latest_reducer)
        except ValueError:
            warnings.append("Skipped a reducer result outside the scan directory.")

    def checkpoints(directory: str, worker_id: str | None, attempt: int = 0) -> None:
        if worker_id is not None:
            root = Path(directory).parent.as_posix()
            worker_attempts[root] = (worker_id, attempt)
            paths[f"{root}/checkpoint-head.json"] = worker_id
        head_snapshots = (Path(directory).parent / "checkpoint-heads").as_posix()
        for saved_directory in (directory, head_snapshots):
            paths.update(dict.fromkeys(_checkpoint_paths(scan_dir, saved_directory), worker_id))

    if not preserve_canonical_parent:
        paths["checkpoint-head.json"] = None
        checkpoints("checkpoints", None)
    for worker in workers:
        try:
            outputs = _worker_outputs(scan_dir, worker)
        except (TypeError, ValueError):
            warnings.append("Skipped a worker checkpoint outside the scan directory.")
            continue
        if worker["kind"] == "dedup":
            for directory, attempt in outputs:
                checkpoint_paths = _checkpoint_paths(scan_dir, f"{directory}/checkpoints")
                if not checkpoint_paths:
                    continue
                result_path = f"{directory}/result.json"
                retained_paths = [result_path, *checkpoint_paths]
                paths.update(dict.fromkeys(retained_paths))
                reducer_paths.update(retained_paths)
                reducer_outputs.append((worker, result_path, checkpoint_paths, attempt))
            continue
        if worker["kind"] != "discovery":
            continue
        output, attempt = outputs[0]
        paths[f"{output}/result.json"] = worker["id"]
        current_results.add(f"{output}/result.json")
        for archived, archived_attempt in outputs[1:]:
            paths[f"{archived}/result.json"] = worker["id"]
            checkpoints(f"{archived}/checkpoints", worker["id"], archived_attempt)
        checkpoints(f"{output}/checkpoints", worker["id"], attempt)
        if worker["result_manifest_path"]:
            try:
                current_path = Path(worker["result_manifest_path"]).relative_to(scan_dir).as_posix()
                paths[current_path] = worker["id"]
                current_results.add(current_path)
            except ValueError:
                warnings.append("Skipped a worker result outside the scan directory.")

    if frozen_source_digests is None:
        for relative, worker_id in list(paths.items()):
            if Path(relative).name != "checkpoint-head.json":
                continue
            del paths[relative]
            try:
                captured = _capture_saved_source(
                    scan_dir, relative, scan_id, created_paths=created_paths
                )
                if relative == "checkpoint-head.json" and frozen_source_digests is None:
                    parent_context["head"] = next(iter(captured))
                paths.update({path: worker_id for path in captured})
            except (ContractError, OSError, ValueError) as exc:
                if (scan_dir / relative).exists() and not (
                    relative == "checkpoint-head.json" and parent is not None
                ):
                    warnings.append(f"Preserved unreadable checkpoint {relative}: {exc}")

    if frozen_source_digests is not None:
        source_digests.update(
            {
                path: digest
                for path, digest in frozen_source_digests.items()
                if _is_source_order_snapshot(path)
            }
        )
        paths = {
            relative: worker_id
            for relative, worker_id in paths.items()
            if relative in frozen_source_digests
        }
        current_results.intersection_update(frozen_source_digests)
        if latest_reducer not in frozen_source_digests:
            latest_reducer = None

    discarded_by_source: dict[str, list[str]] = {}
    for relative, worker_id in paths.items():
        try:
            draft, digest, observed = _read_saved_result(
                scan_dir, relative, scan_id, kind="dedup" if relative in reducer_paths else None
            )
            if frozen_source_digests is not None and frozen_source_digests[relative] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            source_digests[relative] = digest
            source_times.setdefault(relative, observed)
            source_order[relative] = (0, source_times[relative])
            if _checkpoint_head_directory(relative) is not None:
                saved_heads[relative] = draft["checkpoint"]
                if isinstance(draft.get("inputCheckpoint"), str):
                    saved_inputs[relative] = draft["inputCheckpoint"]
                continue
            if preserve_canonical_parent and worker_id is not None:
                # Recover imported records without relaxing canonical parent validation.
                if "complete" in draft and not isinstance(draft["complete"], bool):
                    draft["complete"] = False
                    warnings.append(
                        f"{relative}: Invalid complete marker; retained as a progress checkpoint."
                    )
                schema_dir = Path(__file__).resolve().parents[2] / "schemas"
                if "threatModel" in draft:
                    try:
                        model = draft["threatModel"]
                        if isinstance(model, dict):
                            model = {**model, "origin": "recovered"}
                        schema = _read_json(schema_dir / "scan-manifest.schema.json")
                        _validate_schema_node(
                            model,
                            schema["properties"]["scan"]["properties"]["threatModel"],
                            "threatModel",
                            schema,
                        )
                        _require_safe_json_value(model, "threatModel")
                    except ContractError as exc:
                        draft.pop("threatModel")
                        warnings.append(f"{relative}: Skipped malformed threat model: {exc}.")
                directory = Path(relative).parent
                if directory.name == "checkpoints":
                    directory = directory.parent
                recovered_findings = []
                for index, finding in enumerate(draft["findings"]):
                    needs_identity = isinstance(finding, dict) and "identity" not in finding
                    _ensure_finding_identity(finding)
                    recovered = {"scanId": scan_id, "findings": [finding]}
                    source_warnings: list[str] = []
                    discarded = _recover_unsealed_findings(
                        {"scan": {"id": scan_id, "target": binding["target"]}},
                        recovered,
                        schema_dir,
                        scan_dir / directory,
                        source_warnings,
                    )
                    if recovered["findings"]:
                        try:
                            _validate_current_findings(recovered, schema_dir)
                        except ContractError as exc:
                            warning = f"Skipped malformed finding: {exc}."
                            source_warnings.append(warning)
                            discarded.append(warning)
                            recovered["findings"] = []
                    if discarded:
                        discarded_by_source.setdefault(relative, []).extend(discarded)
                    for recovered_finding in recovered["findings"]:
                        if needs_identity:
                            # Reconcile anonymous revisions before assigning sibling identities.
                            recovered_finding.pop("identity", None)
                        writeup = recovered_finding.pop("writeup", None)
                        if writeup is not None:
                            source_warnings.append(
                                "Retained worker writeup at "
                                f"{directory.as_posix()}/{writeup['reportPath']}; "
                                "the parent report renders this finding inline."
                            )
                    recovered_findings.extend(recovered["findings"])
                    warnings.extend(
                        f"{relative} finding {index + 1}: {warning}" for warning in source_warnings
                    )
                draft["findings"] = recovered_findings
                for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
                    rows = draft["coverage"].get(field)
                    if not isinstance(rows, list):
                        continue
                    for index, row in enumerate(rows):
                        if field == "openQuestions" and isinstance(row, str):
                            row = rows[index] = {"question": row}
                        if not isinstance(row, dict):
                            continue
                        row["workerId"] = worker_id
                        refs = row.get("receiptRefs")
                        if not isinstance(refs, list):
                            continue
                        for ref_index, ref in enumerate(refs):
                            if not isinstance(ref, str):
                                continue
                            try:
                                normalized = _require_portable_relative_path(ref, "receiptRef")
                            except ContractError:
                                # Keep malformed references for the finalizer's diagnostics.
                                continue
                            if normalized.startswith("artifacts/"):
                                refs[ref_index] = f"{directory.as_posix()}/{normalized}"
            # Recovery expects coverage, but reducer results only contain findings
            # and context. Add an empty value after hashing the original result.
            sources.append((relative, {"coverage": {}, **draft}, worker_id))
        except (ContractError, OSError, ValueError) as exc:
            if (scan_dir / relative).exists():
                warnings.append(f"Preserved unreadable checkpoint {relative}: {exc}")
    if frozen_source_digests is not None:
        if frozen_source_digests.keys() - source_digests.keys():
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.")

    # Frozen observations retain checkpoint selection even if a worker moves its head.
    headed_workers = {
        worker_attempts[_checkpoint_head_directory(head).as_posix()][0]
        for head in saved_heads
        if _checkpoint_head_directory(head) != Path(".")
    }
    for relative, _, worker_id in sources:
        if worker_id not in headed_workers:
            continue
        directory = Path(relative).parent
        if directory.name == "checkpoints":
            directory = directory.parent
        _, attempt = worker_attempts.get(directory.as_posix(), (worker_id, 0))
        source_order[relative] = (attempt, source_order[relative][1])
    selected_observations: dict[str, tuple[int, int]] = {}
    parent_heads: list[tuple[int, str]] = []
    for head, checkpoint in saved_heads.items():
        directory = _checkpoint_head_directory(head)
        selected = (directory / "checkpoints" / checkpoint).as_posix()
        if selected not in source_order:
            raise ContractError("Checkpoint head is outside the saved source set.")
        observed = source_order[head][1]
        if directory == Path("."):
            order = (0, max(source_order[selected][1], observed))
            parent_heads.append((observed, selected))
        else:
            _, attempt = worker_attempts[directory.as_posix()]
            order = (attempt, observed)
        selected_observations[selected] = max(selected_observations.get(selected, order), order)
    source_order.update(selected_observations)

    drafts_by_path = {relative: draft for relative, draft, _ in sources}
    if frozen_source_digests is not None and "canonical" in parent_context:
        canonical = parent_context["canonical"]
        parent = drafts_by_path[canonical]
        parent_modified = int(
            parent_context.get("canonicalObservedAtNs", source_order[canonical][1])
        )
        parent_is_canonical = True
    if "head" in parent_context:
        head = parent_context["head"]
        parent_heads = [(source_order[head][1], f"checkpoints/{saved_heads[head]}")]
    latest_reducer_key = (
        (reducer["completed_at"] or "", reducer["id"], int(reducer["attempt"] or 0))
        if reducer is not None and latest_reducer in drafts_by_path
        else None
    )
    if latest_reducer_key is None:
        latest_reducer = None
    for worker, result_path, checkpoint_paths, attempt in reducer_outputs:
        result = drafts_by_path.get(result_path)
        if result is None or not any(
            drafts_by_path.get(checkpoint_path) == result for checkpoint_path in checkpoint_paths
        ):
            continue
        current_results.add(result_path)
        candidate_key = (worker["completed_at"] or "", worker["id"], attempt)
        if latest_reducer_key is None or candidate_key > latest_reducer_key:
            latest_reducer_key = candidate_key
            latest_reducer = result_path

    if parent_heads:
        latest_observation = max(observed for observed, _ in parent_heads)
        for observed, parent_path in parent_heads:
            if observed != latest_observation:
                continue
            draft = drafts_by_path[parent_path]
            modified = source_order[parent_path][1]
            if parent is None or modified > parent_modified:
                parent = draft
                parent_modified = modified
                parent_is_canonical = False
            elif modified == parent_modified and draft != parent:
                parent = _merge_tied_parent_observations(parent, draft)
                parent_is_canonical = False
    parent_is_root = parent is not None
    if parent is None and latest_reducer is not None:
        parent = drafts_by_path[latest_reducer]

    if preserve_canonical_parent:
        project_worker_coverage, surface_links = False, []
    else:
        project_worker_coverage, surface_links = _prepare_worker_coverage_recovery(
            sources, parent, source_order, enabled=project_worker_coverage
        )
    # Keep the actual retained row even when recovery adds previous findings.
    linked_surface_sources = {id(surface) for _, _, surface, _, _ in surface_links}
    linked_surface_outputs: dict[int, dict[str, Any]] = {}
    worker_row_owners: dict[int, str] = {}
    worker_surface_outputs: dict[tuple[str, str], dict[int, dict[str, Any]]] = {}

    def record_coverage_owner(retained: Any, item: Any, owner: str | None, field: str) -> None:
        # Parent aggregates can carry worker metadata without originating in
        # that worker's retained source. Track the actual source of output rows.
        if project_worker_coverage and owner is not None and isinstance(retained, dict):
            worker_row_owners[id(retained)] = owner
            if field == "surfaces" and isinstance(item.get("id"), str):
                worker_surface_outputs.setdefault((owner, item["id"]), {})[id(retained)] = retained

    def append_coverage_row(output: list[Any], item: Any, owner: str | None, field: str) -> Any:
        retained = _project_worker_coverage_row(
            item, owner if project_worker_coverage else None, field
        )
        if retained not in output:
            output.append(retained)
        retained = output[output.index(retained)]
        record_coverage_owner(retained, item, owner, field)
        _inherit_coverage_sources(retained, [item], coverage_sources)
        if preserve_canonical_parent:
            if id(item) in canonical_rows:
                canonical_rows.add(id(retained))
            if field == "surfaces":
                retained_surface_rows.add(id(item))
        return retained

    def linked_tasks(
        task: dict[str, Any],
        published_id: str,
        source_task: dict[str, Any] | None,
        candidates: list[tuple[str | None, Any]],
    ) -> list[Any]:
        expected = (
            _project_worker_coverage_row(source_task, source_task["workerId"], "deferred")
            if source_task is not None
            else None
        )
        return [
            retained
            for owner, retained in candidates
            if retained == task
            or (
                expected is not None
                and owner == expected["workerId"]
                and isinstance(retained, dict)
                and retained.get("id") == expected.get("id")
                and isinstance(retained.get("surfaceIds"), list)
                and published_id in retained["surfaceIds"]
            )
        ]

    def linked_surface(surface, outputs, named_outputs):
        retained = outputs.get(id(surface))
        if (
            retained is None
            and isinstance(owner := surface.get("workerId"), str)
            and isinstance(identity := surface.get("id"), str)
        ):
            matches = named_outputs.get((owner, identity), {})
            if len(matches) == 1:
                retained = next(iter(matches.values()))
        return retained

    all_sources = ([("parent", parent, None)] if parent else []) + sources
    # Older checkpoints can omit IDs already assigned in their published output.
    for field in ("deferred", "surfaces"):
        named_rows: dict[str | None, list[dict[str, Any]]] = {}
        for _, draft, owner in all_sources:
            rows = draft["coverage"].get(field, [])
            named_rows.setdefault(owner, []).extend(
                row
                for row in (rows if isinstance(rows, list) else [])
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            )
        for _, draft, owner in all_sources:
            rows = draft["coverage"].get(field, [])
            if not isinstance(rows, list):
                continue
            reserved = {
                row["id"]
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            }
            for row in rows:
                if not isinstance(row, dict) or "id" in row:
                    continue
                if field == "deferred" and any(
                    key in row for key in ("candidateId", "candidate", "finding")
                ):
                    continue
                content = {"receiptRefs": [], **row} if field == "surfaces" else row
                identity = next(
                    (
                        named["id"]
                        for named in named_rows[owner]
                        if named["id"] not in reserved
                        and {
                            **({"receiptRefs": []} if field == "surfaces" else {}),
                            **{key: value for key, value in named.items() if key != "id"},
                        }
                        == content
                    ),
                    None,
                )
                if identity is not None:
                    row["id"] = identity
                    reserved.add(identity)

    # A discarded local surface must not fall back to another source's reused ID.
    surface_ids_by_source: dict[tuple[str, str], list[str]] = {
        (relative, row["id"]): []
        for relative, draft, _ in all_sources
        for row in (
            draft["coverage"].get("surfaces", [])
            if isinstance(draft["coverage"].get("surfaces"), list)
            else []
        )
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    discarded_coverage_sources: set[str] = set()
    if preserve_canonical_parent:
        for relative, draft, worker_id in sources:
            if worker_id is None:
                continue
            for field in ("surfaces", "explicitExclusions", "deferred"):
                rows = draft["coverage"].get(field)
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        row.setdefault("id", _saved_coverage_id(row))
                        if field == "surfaces":
                            row.setdefault("receiptRefs", [])
            source_warnings = []
            discarded_fields = _recover_unsealed_coverage(
                draft["coverage"],
                Path(__file__).resolve().parents[2] / "schemas",
                scan_dir,
                source_warnings,
                discarded_by_source.get(relative, []),
                # Reconcile local IDs and valid outcomes against worker history below.
                worker_draft=True,
            )
            if discarded_fields & {
                "surfaces",
                "explicitExclusions",
                "deferred",
                "resolvedDeferred",
            }:
                discarded_coverage_sources.add(relative)
            for row in draft["coverage"]["deferred"]:
                row["workerId"] = worker_id
            warnings.extend(f"{relative}: {warning}" for warning in source_warnings)

    if parent is None and not sources:
        return None
    if (
        parent_manifest
        and parent_manifest["scan"].get("sealedAt")
        and parent_manifest["scan"].get("status") == binding["status"]
        and parent_manifest["scan"].get("preservedSources") == source_digests
        and all(warning in initial_warnings for warning in warnings)
    ):
        return None

    if (
        frozen_source_digests is None
        or any(_is_source_order_snapshot(path) for path in source_digests)
        or allow_frozen_legacy_parent
    ):
        _freeze_source_times(
            scan_dir,
            scan_id,
            source_digests,
            source_times,
            parent_context,
            created_paths=created_paths,
        )

    target_kind = binding["allowedTargetKinds"][0]
    if (
        target_kind == "git_worktree"
        and "snapshotDigest" not in binding["target"]
        and "git_revision" in binding["allowedTargetKinds"]
    ):
        target_kind = "git_revision"
    target = {"kind": target_kind, **binding["target"]}
    if target["kind"] == "git_diff" and "snapshotDigest" not in target:
        diff_kind = {"commit": "commit", "branch_diff": "range"}[binding["coverageMode"]]
        target["snapshotDigest"] = committed_diff_snapshot_digest(
            diff_kind, target["baseRevision"], target["headRevision"]
        )
    manifest = (
        copy.deepcopy(parent_manifest)
        if parent_manifest
        else {"scan": {"target": target, "scope": binding["scope"]}}
    )
    for key in ("sealedAt", "artifacts"):
        manifest["scan"].pop(key, None)
    manifest["scan"]["preservedSources"] = source_digests
    # Completion follows the selected parent, including legacy terminal drafts
    # that omit the optional marker, rather than an older canonical manifest.
    if parent is not None:
        manifest["scan"].pop("complete", None)
        if "complete" in parent:
            manifest["scan"]["complete"] = parent["complete"]
        for key in ("scope", "threatModel"):
            if isinstance(parent.get(key), dict):
                manifest["scan"][key] = copy.deepcopy(parent[key])
        if isinstance(manifest["scan"].get("scope"), dict):
            manifest["scan"]["scope"].update(copy.deepcopy(binding["scope"]))
    model_checks: dict[str, dict[str, Any] | None] = {}

    def recovered_model(
        relative: str, draft: dict[str, Any], owner: str | None
    ) -> dict[str, Any] | None:
        if relative not in model_checks:
            model = copy.deepcopy(draft.get("threatModel"))
            if isinstance(model, dict) and owner is not None:
                model["origin"] = "recovered"
            schema = _read_json(
                Path(__file__).resolve().parents[2] / "schemas/scan-manifest.schema.json"
            )
            try:
                _require_safe_json_value(model, f"Saved threat model {relative}")
                _validate_schema_node(
                    model,
                    schema["properties"]["scan"]["properties"]["threatModel"],
                    f"Saved threat model {relative}",
                    schema,
                )
            except ContractError as exc:
                warnings.append(f"Skipped malformed saved threat model {relative}: {exc}")
                model = None
            model_checks[relative] = model
        return model_checks[relative]

    if "threatModel" in manifest["scan"]:
        model = recovered_model("parent", manifest["scan"], None)
        if model is None:
            manifest["scan"].pop("threatModel")
        else:
            manifest["scan"]["threatModel"] = model

    if frozen_model_source is not None:
        # Publication retries retain a valid choice from the frozen source set.
        model = drafts_by_path.get(frozen_model_source, {}).get("threatModel")
        if not isinstance(model, dict):
            raise ContractError("Frozen stopped-scan model source is unavailable.")
        model = recovered_model(
            frozen_model_source, drafts_by_path[frozen_model_source], paths[frozen_model_source]
        )
        if model is not None:
            manifest["scan"]["threatModel"] = model
        if selected_model_source is not None:
            selected_model_source[:] = [] if model is None else [frozen_model_source]
    coverage = (
        copy.deepcopy(parent["coverage"])
        if parent and parent["coverage"]
        else {
            "mode": binding["coverageMode"],
            "inventoryStrategy": "diff"
            if binding["coverageMode"] in {"commit", "branch_diff", "working_tree"}
            else "scoped_path"
            if binding["coverageMode"] == "scoped_path"
            else "repository",
            **binding["scope"],
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        }
    )
    if isinstance(coverage.get("openQuestions"), list):
        coverage["openQuestions"] = [
            {"question": item.strip()} if isinstance(item, str) else item
            for item in coverage["openQuestions"]
        ]
    # Closure reconciliation can reuse original parent rows instead of their copies.
    canonical_rows = (
        {
            id(item)
            for parent_coverage in (
                (coverage, parent["coverage"]) if preserve_canonical_parent else (coverage,)
            )
            for field in ("surfaces", "explicitExclusions", "deferred")
            for item in (
                parent_coverage.get(field) if isinstance(parent_coverage.get(field), list) else []
            )
        }
        if parent_is_canonical
        else set()
    )
    # Links use source-local IDs until all retained surfaces receive their final IDs.
    coverage_sources: dict[int, tuple[dict[str, Any], list[str]]] = {}
    source_owners = {relative: owner for relative, _, owner in all_sources}
    retained_surface_rows: set[int] = set()
    for relative, draft, _ in all_sources:
        for field in ("surfaces", "deferred"):
            rows = draft["coverage"].get(field)
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    paths_for_row = coverage_sources.setdefault(id(row), (row, []))[1]
                    if relative not in paths_for_row:
                        paths_for_row.append(relative)
    if parent:
        for field in ("surfaces", "deferred"):
            rows, originals = coverage.get(field), parent["coverage"].get(field)
            if isinstance(rows, list) and isinstance(originals, list):
                for row, original in zip(rows, originals):
                    _inherit_coverage_sources(row, [original], coverage_sources)
                if field == "surfaces":
                    retained_surface_rows.update(id(original) for original in originals)

    findings: list[dict[str, Any]] = []
    finding_positions: dict[str, tuple[int, dict[str, Any] | None]] = {}
    canonical_finding_keys: set[str] = set()
    represented: dict[str, str | None] = {}
    represented_candidates: dict[tuple[str, str, Any, Any, Any], str | None] = {}
    represented_history: dict[str, set[str]] = {}
    represented_candidate_history: dict[tuple[str, str, Any, Any, Any], set[str]] = {}
    rejected_history: dict[tuple[str, str], list[dict[str, Any]]] = {}
    stopped_parent_seal = bool(
        stopped and parent_manifest and parent_manifest["scan"].get("sealedAt")
    )

    # A damaged canonical row must not replace a checkpoint's established identity.
    legacy_identities: dict[str, dict[str, Any] | None] = {}
    legacy_identity_sources: set[str] = set()

    def legacy_identity_key(finding: dict[str, Any], owner: str | None) -> str:
        content = _finding_content(finding)
        locations = content.get("locations")
        if isinstance(locations, list):
            content["locations"] = sorted(
                [
                    {**row, "endLine": row.get("endLine", row.get("startLine"))}
                    if isinstance(row, dict)
                    else row
                    for row in locations
                ],
                key=_encoded,
            )
        return _digest([owner, _identity_candidate(finding), content])

    def restore_legacy_identity(
        finding: Any, normalized: Any = None, *, allow_synthesis: bool = True
    ) -> None:
        if isinstance(finding, dict) and "identity" not in finding:
            provenance = finding.get("provenance")
            owner = provenance.get("workerId") if isinstance(provenance, dict) else None
            key = legacy_identity_key(finding, owner)
            identity = legacy_identities.get(key)
            if identity is not None:
                finding["identity"] = copy.deepcopy(identity)
            allow_synthesis = allow_synthesis or key in legacy_identity_sources
        if not allow_synthesis:
            return
        if isinstance(finding, dict) and isinstance(normalized, dict):
            finding.setdefault("identity", normalized["identity"])
        else:
            _ensure_finding_identity(finding)

    def finding_within_scope(finding: dict[str, Any]) -> bool:
        locations = finding.get("locations", [])
        return isinstance(locations, list) and any(
            isinstance(location, dict)
            and isinstance(location.get("path"), str)
            and any(
                PurePosixPath(location["path"]) == PurePosixPath(path)
                if is_file
                else path_within_scope(location["path"], path)
                for path, is_file in (
                    finding_scope
                    if finding_scope is not None
                    else [(path, False) for path in binding["scope"]["includePaths"]]
                )
            )
            for location in locations
        )

    valid_findings: dict[bytes, bool] = {}

    def valid_finding(value: Any) -> bool:
        # Use the finalizer's own per-record recovery before a draft can suppress
        # an earlier checkpoint. Invalid latest records must not hide valid history.
        document = {"scanId": scan_id, "findings": [copy.deepcopy(value)]}
        if isinstance(document["findings"][0], dict):
            restore_legacy_identity(document["findings"][0])
        key = _encoded(document["findings"][0])
        if key in valid_findings:
            return valid_findings[key]
        _recover_unsealed_findings(
            {"scan": {"id": scan_id, "target": binding["target"]}},
            document,
            Path(__file__).resolve().parents[2] / "schemas",
            scan_dir,
            [],
            current_contract=current_contract,
        )
        valid_findings[key] = bool(document["findings"])
        return valid_findings[key]

    for _, draft, owner in all_sources:
        for value in draft["findings"]:
            if not isinstance(value, dict):
                continue
            for saved in _retained_findings(value):
                identity = saved.get("identity")
                provenance = saved.get("provenance")
                saved_owner = (
                    provenance.get("workerId", owner) if isinstance(provenance, dict) else owner
                )
                key = legacy_identity_key(saved, saved_owner)
                if "identity" in saved:
                    legacy_identity_sources.add(key)
                if not isinstance(identity, dict) or not valid_finding(saved):
                    continue
                if key not in legacy_identities:
                    legacy_identities[key] = identity
                elif legacy_identities[key] != identity:
                    legacy_identities[key] = None

    source_order["parent"] = (0, parent_modified)
    deferred_rows = {
        relative: _deferred_rows(draft["coverage"]) for relative, draft, _ in all_sources
    }
    # Accepted heads can replace equal tasks before they reach output coalescing.
    equivalent_tasks: dict[str | None, list[dict[str, Any]]] = {}
    for relative, _, owner in all_sources:
        known = equivalent_tasks.setdefault(owner, [])
        for row in deferred_rows[relative]:
            if not isinstance(row, dict):
                continue
            for previous in known:
                if previous == row:
                    _inherit_coverage_sources(previous, [row], coverage_sources)
                    coverage_sources[id(row)] = (row, coverage_sources[id(previous)][1])
                    break
            else:
                known.append(row)
    # A legacy source can contain independent tasks with the same explicit ID.
    # Later rewrites cannot make an ID-only closure identify one of those tasks.
    ambiguous_deferred: set[tuple[str | None, str]] = set()
    for relative, _, owner in all_sources:
        by_id: dict[str, dict[str, Any]] = {}
        candidate_aliases = {
            identity
            for row in deferred_rows[relative]
            if isinstance(row, dict)
            and any(key in row for key in ("candidateId", "candidate", "finding"))
            for identity in (row.get("id"), row.get("candidateId"))
            if isinstance(identity, str)
        }
        for row in deferred_rows[relative]:
            if not isinstance(row, dict) or not isinstance(identity := row.get("id"), str):
                continue
            if any(key in row for key in ("candidateId", "candidate", "finding")):
                continue
            if identity in candidate_aliases or (identity in by_id and row != by_id[identity]):
                ambiguous_deferred.add((owner, identity))
            by_id[identity] = row
    current_drafts = ([("parent", parent, None)] if parent else []) + [
        source for source in sources if source[0] in current_results | selected_observations.keys()
    ]
    # Generic closures belong to one logical scan or worker, just like candidates.
    # Keep them when recovering a terminal checkpoint without its canonical write.
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}

    candidate_ids: set[tuple[str | None, str]] = set()
    accepted_deferred_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}
    coverage_schema = _read_json(
        Path(__file__).resolve().parents[2] / "schemas" / "coverage.schema.json"
    )["properties"]
    for relative, draft, owner in all_sources:
        order = source_order[relative]
        for item in deferred_rows[relative]:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("candidateId"), str) or "candidate" in item or "finding" in item:
                candidate_ids.update(
                    (owner, identity)
                    for identity in (item.get("id"), item.get("candidateId"))
                    if isinstance(identity, str)
                )
            identity = item.get("id") or item.get("candidateId")
            if isinstance(identity, str):
                key = (owner, identity)
                previous = active_deferred.get(key)
                if previous is None or order > previous[0]:
                    active_deferred[key] = (order, item, relative)
                if (
                    relative == "parent"
                    or relative in current_results
                    or relative in selected_observations
                ):
                    try:
                        # A malformed update cannot discard valid saved evidence.
                        _validate_schema_node(
                            item, coverage_schema["deferred"]["items"], "coverage.deferred"
                        )
                    except ContractError:
                        continue
                    accepted_deferred_orders[key] = max(
                        accepted_deferred_orders.get(key, order), order
                    )
        for closure in _resolved_deferred_rows(draft, coverage_schema["resolvedDeferred"]):
            key = (owner, closure["id"])
            previous = closed_deferred.get(key)
            if previous is None or order > previous[0]:
                # The parent comes first, preserving its reason on equal timestamps.
                closed_deferred[key] = (order, closure, relative)
    reopened_rows: list[tuple[str | None, dict[str, Any]]] = []
    reopened_generic: set[tuple[str | None, str]] = set()
    for key, (order, _, _) in list(closed_deferred.items()):
        # Equal timestamps cannot distinguish closure from reopened work.
        reopened = [
            active
            for (owner, identity), active in active_deferred.items()
            if owner == key[0]
            and (identity == key[1] or active[1].get("candidateId") == key[1])
            and active[0] >= order
        ]
        if key in candidate_ids or key in ambiguous_deferred or reopened:
            del closed_deferred[key]
        for _, item, _ in reopened:
            reopened_rows.append((key[0], item))
            if key not in candidate_ids:
                reopened_generic.add(key)
    # Retain every distinct ambiguous task even when a terminal result supersedes
    # its source. Existing output ID normalization keeps each row distinct.
    for relative, _, owner in all_sources:
        for row in deferred_rows[relative]:
            if (
                isinstance(row, dict)
                and isinstance(identity := row.get("id"), str)
                and (owner, identity) in ambiguous_deferred
                and not any(key in row for key in ("candidateId", "candidate", "finding"))
                and (owner, row) not in reopened_rows
            ):
                reopened_rows.append((owner, row))
    parent_closures = [
        closure for (owner, _), (_, closure, _) in closed_deferred.items() if owner is None
    ]
    coverage.pop("resolvedDeferred", None)
    if parent_closures:
        coverage["resolvedDeferred"] = copy.deepcopy(parent_closures)
        if parent:
            coverage["deferred"] = [
                row
                for row in deferred_rows["parent"]
                if not isinstance(row, dict)
                or not isinstance(row.get("id"), str)
                or (None, row["id"]) not in closed_deferred
            ]
    resolved: dict[tuple[str | None, str], str] = {}

    ordered_candidates = {
        (owner, identity)
        for owner, row in reopened_rows
        if (identity := _deferred_candidate_id(row, owner, ambiguous_deferred)) is not None
        and (owner, identity) in candidate_ids
    }
    ordered_outcomes: dict[tuple[str | None, str], tuple[tuple[int, int], str]] = {}

    outcomes: list[tuple[str, str | None, str, str]] = []
    for relative, draft, owner in current_drafts:
        for finding in draft["findings"]:
            if (
                isinstance(finding, dict)
                and valid_finding(finding)
                and (candidate_id := finding_candidate_id(finding))
            ):
                outcomes.append((relative, owner, candidate_id, "reported"))
        for field in ("surfaces", "explicitExclusions"):
            items = draft["coverage"].get(field, [])
            for item in items if isinstance(items, list) else []:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                    and item.get("disposition") in ("rejected", "not_applicable")
                ):
                    outcomes.append((relative, owner, item["candidateId"], item["disposition"]))
    ordered_candidates.update(
        (owner, candidate_id)
        for relative, owner, candidate_id, _ in outcomes
        if owner is not None and relative in selected_observations
    )
    # Reopened work and selected checkpoint outcomes follow the saved source order.
    for relative, owner, candidate_id, disposition in outcomes:
        key = (owner, candidate_id)
        if key not in ordered_candidates:
            if relative == "parent" or relative in current_results:
                resolved.setdefault(key, disposition)
            continue
        order = source_order[relative]
        if any(
            saved_owner == owner
            and _deferred_candidate_id(row, owner, ambiguous_deferred) == candidate_id
            and modified >= order
            for (saved_owner, _), (modified, row, _) in active_deferred.items()
        ):
            continue
        if key not in ordered_outcomes or order > ordered_outcomes[key][0]:
            resolved[key] = disposition
            ordered_outcomes[key] = (order, relative)
    # Only the current parent may claim that another worker finding was absorbed.
    # A superseded checkpoint must not suppress a newer independent result.
    if parent:
        for finding in parent["findings"]:
            if valid_finding(finding):
                canonical = copy.deepcopy(finding)
                restore_legacy_identity(canonical)
                canonical_key = _finding_key(canonical)
                for retained in _retained_findings(finding):
                    retained_key = _finding_key(retained)
                    if retained is not finding:
                        represented_history.setdefault(retained_key, set()).add(
                            _digest(_finding_content(retained))
                        )
                    previous_key = represented.get(retained_key)
                    if retained_key not in represented:
                        represented[retained_key] = canonical_key
                    elif previous_key != canonical_key:
                        # Ambiguous history cannot suppress an independent source.
                        represented[retained_key] = None
                originals = finding["provenance"].get("sourceFindings", [])
                for original in originals if isinstance(originals, list) else []:
                    if isinstance(original, dict) and isinstance(original.get("finding"), dict):
                        source_id = original.get("id")
                        candidate_id = finding_candidate_id(original["finding"])
                        if isinstance(source_id, str) and ":" in source_id and candidate_id:
                            candidate_key = _worker_candidate_key(
                                source_id.rsplit(":", 1)[0],
                                candidate_id,
                                original["finding"],
                            )
                            previous_key = represented_candidates.get(candidate_key)
                            if candidate_key not in represented_candidates:
                                represented_candidates[candidate_key] = canonical_key
                            elif previous_key != canonical_key:
                                # Candidate ids are only authoritative within one
                                # logical worker. Multiple canonical owners make
                                # that worker-local identity ambiguous.
                                represented_candidates[candidate_key] = None
                            represented_candidate_history.setdefault(candidate_key, set()).add(
                                _digest(_finding_content(original["finding"]))
                            )
    selected_terminal_orders: dict[str, tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if (
            worker_id is not None
            and relative in selected_observations
            and draft.get("complete") is not False
            and relative not in discarded_by_source
            and relative not in discarded_coverage_sources
        ):
            order = source_order[relative]
            selected_terminal_orders[worker_id] = max(
                selected_terminal_orders.get(worker_id, order), order
            )
    terminal_worker_orders: dict[str | None, tuple[int, int]] = {}
    terminal_coverage_orders: dict[str | None, tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if (
            relative in current_results
            and draft.get("complete") is not False
            and relative not in discarded_by_source
        ):
            order = source_order[relative]
            terminal_worker_orders[worker_id] = max(
                terminal_worker_orders.get(worker_id, order), order
            )
            if relative not in discarded_coverage_sources:
                terminal_coverage_orders[worker_id] = max(
                    terminal_coverage_orders.get(worker_id, order), order
                )
    # Reconcile raw records before generating context-dependent publication IDs.
    logical_rows: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
    row_groups: dict[tuple[str, int], dict[str, Any]] = {}
    published_groups: list[dict[str, Any]] = []

    def identifiers(value: dict[str, Any]) -> tuple[Any, Any]:
        extensions = value.get("extensions")
        return tuple(
            identifier if _has_identity_text(identifier) else None
            for identifier in (
                extensions.get(field) if isinstance(extensions, dict) else None
                for field in ("reportId", "ledgerRowId")
            )
        )

    def distinct_reports(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
        return (
            left is not None
            and right is not None
            and any(
                a is not None and b is not None and a != b
                for a, b in zip(
                    identifiers(left["latest"]), identifiers(right["latest"]), strict=True
                )
            )
        )

    def raw_owner(value: dict[str, Any], source_owner: str | None) -> str | None:
        if source_owner is not None:
            return source_owner
        provenance = value.get("provenance", {})
        owner = provenance.get("workerId")
        return owner if isinstance(owner, str) else source_owner

    def raw_scope(value: dict[str, Any]) -> tuple[Any, ...]:
        # Match scanFindingIdentity's primary location for anonymous reports.
        location = value["locations"][0]
        return (
            value.get("ruleId"),
            location["path"],
            location["startLine"],
            location.get("endLine"),
        )

    def same_owner(left: str | None, right: str | None) -> bool:
        # Canonical recovery needs identity or recorded lineage to absorb worker evidence.
        return left == right or (not preserve_canonical_parent and (left is None or right is None))

    def same_raw_finding(left: dict[str, Any], right: dict[str, Any]) -> bool:
        if isinstance(left.get("identity"), dict) and isinstance(right.get("identity"), dict):
            return _semantic_identity_key(left, _finding_identity(left)) == _semantic_identity_key(
                right, _finding_identity(right)
            )
        candidates = (_identity_candidate(left), _identity_candidate(right))
        if all(candidates) and candidates[0] != candidates[1]:
            return False
        pairs = list(zip(identifiers(left), identifiers(right), strict=True))
        if any(a is not None for a, _ in pairs) and any(b is not None for _, b in pairs):
            if not any(a is not None and b is not None for a, b in pairs) or any(
                a is not None and b is not None and a != b for a, b in pairs
            ):
                return False
        return True

    def same_raw_value(left: Any, right: Any) -> bool:
        if isinstance(left, dict):
            return (
                isinstance(right, dict)
                and left.keys() == right.keys()
                and all(same_raw_value(value, right[key]) for key, value in left.items())
            )
        if isinstance(left, list):
            return (
                isinstance(right, list)
                and len(left) == len(right)
                and all(same_raw_value(a, b) for a, b in zip(left, right, strict=True))
            )
        # JSON numbers compare by value, but booleans are a distinct scalar type.
        return isinstance(left, bool) == isinstance(right, bool) and left == right

    def same_raw_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
        def content(value: dict[str, Any]) -> dict[str, Any]:
            result = _finding_content(value)
            if isinstance(result.get("extensions"), dict):
                result["extensions"] = {
                    key: value
                    for key, value in result["extensions"].items()
                    if key not in {"candidateId", "reportId", "ledgerRowId"}
                }
                if not result["extensions"]:
                    result.pop("extensions")
            return result

        return same_raw_value(content(left), content(right))

    def contains_raw_value(current: Any, previous: Any) -> bool:
        if isinstance(previous, dict):
            return isinstance(current, dict) and all(
                key in current and contains_raw_value(current[key], value)
                for key, value in previous.items()
            )
        if isinstance(previous, list):
            return isinstance(current, list) and all(
                any(contains_raw_value(item, value) for item in current) for value in previous
            )
        return isinstance(current, bool) == isinstance(previous, bool) and current == previous

    def finding_source_order(source, within_worker: bool = False):
        relative, draft, _ = source
        attempt, modified = source_order[relative]
        return (
            draft.get("complete") is not False,
            attempt if within_worker else 0,
            modified,
            relative in selected_observations,
            relative in current_results,
            relative == "parent",
        )

    terminal_findings: dict[str, list[dict[str, Any]]] = {}
    # A reducer replaces only its claimed batch, not the whole parent scan.
    parent_sources = {
        relative
        for relative, _, _ in all_sources
        if Path(relative).parent == Path("checkpoints") or (relative == "parent" and parent_is_root)
    }
    projected_paths = {
        relative
        for relative, draft, _ in all_sources
        if relative in parent_sources
        and (
            relative == "parent"
            or relative == parent_context.get("canonical")
            # The semantic tool schema forbids this host-owned projection field.
            or draft["coverage"].get("mode") == binding["coverageMode"]
        )
    }
    projected_parents = [draft for relative, draft, _ in all_sources if relative in projected_paths]

    def same_published_finding(left: dict[str, Any], right: dict[str, Any]) -> bool:
        if not valid_finding(left) or not valid_finding(right):
            return False
        return (
            same_raw_value(_finding_content(left), _finding_content(right))
            and (
                "identity" not in left
                or same_raw_value(_finding_identity(left), _finding_identity(right))
            )
            and same_raw_value(
                {
                    key: value
                    for key, value in left.get("provenance", {}).items()
                    if key not in ("previousFindings", "preservedIdentity")
                },
                {
                    key: value
                    for key, value in right.get("provenance", {}).items()
                    if key not in ("previousFindings", "preservedIdentity")
                },
            )
        )

    def represented_by_parent(values: list[dict[str, Any]], draft: dict[str, Any]) -> bool:
        remaining = [row for row in draft["findings"] if isinstance(row, dict)]
        for value in values:
            match = next(
                (
                    index
                    for index, row in enumerate(remaining)
                    if same_published_finding(value, row)
                ),
                None,
            )
            if match is None:
                return False
            remaining.pop(match)
        return True

    terminal_sources: set[str] = set()
    for relative, draft, _ in all_sources:
        if (
            scan_mode == "deep"
            and not allow_frozen_legacy_parent
            and relative in parent_sources
            and draft.get("complete") is not False
            and all(valid_finding(value) for value in draft["findings"])
        ):
            terminal_sources.add(relative)
            if relative not in projected_paths:
                identified = copy.deepcopy(draft["findings"])
                _ensure_finding_identities(identified)
                terminal_findings[relative] = identified
    # Legacy projections alone do not record the submitted replacement batch.
    if not terminal_findings:
        terminal_sources.clear()
    head_path = (
        f"checkpoints/{saved_heads[parent_context['head']]}"
        if "head" in parent_context and not allow_frozen_legacy_parent
        else None
    )
    head_input = saved_inputs.get(parent_context.get("head"))
    ancestors = _parent_publication_ancestors(head_input, drafts_by_path)
    committed_parent = parent
    committed_path = "parent" if parent_is_root else None
    if head_path and (
        not parent_is_canonical or any(parent == drafts_by_path.get(path) for path in ancestors)
    ):
        committed_path = head_path
        committed_parent = drafts_by_path[head_path]
    committed_time = source_order.get(committed_path, (0, 0))[1]
    pending_terminals = set()
    superseded_terminals = set()
    unordered_terminals = set()
    for relative, values in terminal_findings.items():
        publication = drafts_by_path[relative].get("publication")
        if isinstance(publication, dict):
            previous = publication.get("previousCheckpoint")
            if Path(relative).name == head_input:
                continue
            if (
                f"checkpoints/{previous}" if previous is not None else None
            ) != head_path or publication.get("previousInputCheckpoint") != head_input:
                superseded_terminals.add(relative)
                continue
            pending_terminals.add(relative)
        elif not any(represented_by_parent(values, draft) for draft in projected_parents):
            # Legacy inputs have no causal link to an accepted publication. A
            # backdated observation cannot prove that accepted findings were removed.
            if source_order[relative][1] >= committed_time:
                pending_terminals.add(relative)
            else:
                unordered_terminals.add(relative)
    terminal_cutoffs = (
        {committed_path}
        if committed_path in terminal_sources
        else terminal_sources - superseded_terminals
    )
    terminal_parent_time = max(
        (source_order[relative][1] for relative in pending_terminals or terminal_cutoffs),
        default=None,
    )
    pending_terminals = {
        relative
        for relative in pending_terminals
        if source_order[relative][1] == terminal_parent_time
    }
    for relative in pending_terminals | unordered_terminals:
        identified = copy.deepcopy(drafts_by_path[relative]["findings"])
        _ensure_finding_identities(identified, deep=True)
        terminal_findings[relative] = identified
    current_findings = [
        previous
        for value in (committed_parent["findings"] if committed_parent else [])
        if isinstance(value, dict)
        for previous in _retained_findings(value)
    ]
    replaced_findings = [
        value
        for draft in projected_parents
        for value in draft["findings"]
        if isinstance(value, dict)
        and (
            pending_terminals
            or (
                terminal_sources
                and not any(
                    same_published_finding(value, previous) for previous in current_findings
                )
            )
        )
    ]

    def replaced_parent_finding(relative: str, owner: str | None, value: Any) -> bool:
        if (
            owner is not None
            or relative in pending_terminals | unordered_terminals
            or not isinstance(value, dict)
        ):
            return False
        return any(same_published_finding(value, previous) for previous in replaced_findings)

    terminal_worker_attempts: dict[str, int] = {}
    if terminal_parent_time is not None:
        for relative, _, owner in all_sources:
            attempt, modified = source_order[relative]
            if owner is not None and modified <= terminal_parent_time:
                terminal_worker_attempts[owner] = max(
                    terminal_worker_attempts.get(owner, attempt), attempt
                )

    def precedes_terminal_parent(relative: str, owner: str | None) -> bool:
        attempt, modified = source_order[relative]
        return relative in superseded_terminals or (
            relative not in unordered_terminals
            and terminal_parent_time is not None
            and (
                modified < terminal_parent_time
                or attempt < terminal_worker_attempts.get(owner, attempt)
            )
        )

    finding_sources = [
        source for source in all_sources if not precedes_terminal_parent(source[0], source[2])
    ]
    # Publication chronology spans workers; attempt numbers only order one worker's revisions.
    for source in sorted(finding_sources, key=lambda item: finding_source_order(item)[2:]):
        relative, draft, source_owner = source
        explicit_identity_counts = Counter(
            _semantic_identity_key(sibling, _finding_identity(sibling))
            for sibling in draft["findings"]
            if isinstance(sibling, dict)
            and isinstance(sibling.get("identity"), dict)
            and ((relative == "parent" and parent_is_canonical) or finding_within_scope(sibling))
        )
        pending = []
        for index, value in enumerate(draft["findings"]):
            if (
                not isinstance(value, dict)
                or replaced_parent_finding(relative, source_owner, value)
                or not valid_finding(value)
                or (
                    not (relative == "parent" and parent_is_canonical)
                    and not finding_within_scope(value)
                )
            ):
                continue
            owner = raw_owner(value, source_owner)
            scope = raw_scope(value)
            candidate = finding_candidate_id(value)
            scopes = [scope, (scope[0], candidate)] if candidate else [scope]
            publication_identity = (
                _finding_identity(
                    value if "identity" in value else terminal_findings[relative][index]
                )
                if relative in terminal_findings
                else None
            )
            matches = [
                group
                for group in {
                    key: group
                    for saved_scope in scopes
                    for key, group in logical_rows.get(saved_scope, {}).items()
                }.values()
                if same_owner(owner, group["owner"])
                and (
                    publication_identity is None
                    or group["identity"] is None
                    or _semantic_identity_key(value, group["identity"])
                    == _semantic_identity_key(value, publication_identity)
                )
                and (
                    (relative == "parent" and parent_is_canonical)
                    or group["identity"] is None
                    or "identity" not in value
                    or _semantic_identity_key(value, group["identity"])
                    == _semantic_identity_key(value, _finding_identity(value))
                )
                and all(same_raw_finding(value, previous) for previous in group["rows"])
            ]
            ranked = []
            for group in matches:
                latest = group["latest"]
                if (
                    isinstance(value.get("identity"), dict)
                    and explicit_identity_counts[
                        _semantic_identity_key(value, _finding_identity(value))
                    ]
                    == 1
                    and group["identity"] is not None
                    and _semantic_identity_key(value, _finding_identity(value))
                    == _semantic_identity_key(value, group["identity"])
                ):
                    rank = 4
                elif (
                    owner == group["owner"]
                    and same_raw_content(value, latest)
                    and _identity_candidate(value) == _identity_candidate(latest)
                    and identifiers(value) == identifiers(latest)
                ):
                    rank = 3
                elif any(same_raw_content(value, previous) for previous in group["rows"]):
                    rank = 2
                elif (
                    latest.get("title") == value.get("title")
                    and raw_scope(latest) == scope
                    and all(
                        previous is None or current == previous
                        for current, previous in zip(
                            identifiers(value), identifiers(latest), strict=True
                        )
                    )
                ):
                    rank = 1
                else:
                    rank = 0
                ranked.append((group, rank))
            pending.append((index, value, owner, scopes, ranked))
        assigned = {}
        claimed = set()
        for index, value, owner, _, matches in pending:
            for group, _ in matches:
                if (
                    group["key"] not in claimed
                    and owner == group["owner"]
                    and same_raw_value(value, group["latest"])
                ):
                    assigned[index] = group
                    claimed.add(group["key"])
                    break
        for rank in (4, 3, 2, 1, 0):
            identity_claims = {
                group["key"]
                for index, _, _, _, matches in pending
                for group, score in matches
                if score == 4 and assigned.get(index) is group
            }
            options = {
                index: [
                    group
                    for group, score in matches
                    if score >= rank
                    and (
                        group["key"] not in claimed
                        or (rank == 0 and group["key"] not in identity_claims)
                    )
                ]
                for index, _, _, _, matches in pending
                if index not in assigned
            }
            counts = {}
            for groups in options.values():
                for group in groups:
                    counts[group["key"]] = counts.get(group["key"], 0) + 1
            chosen = {
                index: groups[0]
                for index, groups in options.items()
                if len(groups) == 1
                and groups[0]["key"] not in claimed
                and counts[groups[0]["key"]] == 1
            }
            assigned.update(chosen)
            claimed.update(group["key"] for group in chosen.values())
        current_groups: list[tuple[int, dict[str, Any]]] = []
        for index, value, owner, scopes, _ in pending:
            match = assigned.get(index)
            if match is None:
                match = {
                    "owner": owner,
                    "rows": [],
                    "identity": None,
                    "key": f"raw:{len(row_groups)}",
                }
            for saved_scope in scopes:
                logical_rows.setdefault(saved_scope, {})[match["key"]] = match
            if match["owner"] is None:
                match["owner"] = owner
            if not any(same_raw_value(value, previous) for previous in match["rows"]):
                match["rows"].append(value)
            observations = match.setdefault("observations", {})
            previous = observations.get(source_owner)
            if previous is None or (
                finding_source_order(source, True),
                _finding_strength(value),
            ) > (
                finding_source_order(previous[0], True),
                _finding_strength(previous[1]),
            ):
                observations[source_owner] = (source, value)
                match["latest"] = max(
                    observations.values(),
                    key=lambda observation: (
                        finding_source_order(observation[0]),
                        _finding_strength(observation[1]),
                    ),
                )[1]
            if relative in terminal_findings:
                match["identity"] = copy.deepcopy(
                    _finding_identity(
                        value if "identity" in value else terminal_findings[relative][index]
                    )
                )
            elif "identity" in value and (match["identity"] is None or relative == "parent"):
                match["identity"] = copy.deepcopy(_finding_identity(value))
            row_groups[(relative, index)] = match
            current_groups.append((index, match))
        if source_owner is None:
            current_ordered = [
                group for _, group in sorted(current_groups, key=lambda item: item[0])
            ]
            ordered = current_ordered + [
                group for group in published_groups if group not in current_ordered
            ]
            normalized = []
            for group in ordered:
                value = copy.deepcopy(group["latest"])
                if group["identity"] is not None:
                    value["identity"] = copy.deepcopy(group["identity"])
                normalized.append(value)
            _ensure_finding_identities(normalized)
            for group, value in zip(ordered, normalized, strict=True):
                group["identity"] = value["identity"]
            published_groups = ordered

    # A later worker draft can collapse raw duplicates that it fully contains.
    # Keep established identities and any evidence absent from the newer report.
    contained_groups = set()
    for group in {group["key"]: group for group in row_groups.values()}.values():
        owner = group["owner"]
        previous = group["observations"].get(owner)
        if owner is None or group["identity"] is not None or previous is None:
            continue
        for current in logical_rows.get(raw_scope(group["latest"]), {}).values():
            observed = current["observations"].get(owner)
            if (
                current["owner"] == owner
                and observed is not None
                and finding_source_order(observed[0], True)
                > finding_source_order(previous[0], True)
                and all(contains_raw_value(current["latest"], row) for row in group["rows"])
            ):
                contained_groups.add(group["key"])
                break

    # An absorbed source represents every reconciled version of that worker report.
    for groups in logical_rows.values():
        for group in groups.values():
            destinations = set()
            for value in group["rows"]:
                history_key = _finding_key(value)
                if _digest(_finding_content(value)) in represented_history.get(history_key, set()):
                    destinations.add(represented.get(history_key))
                elif group["owner"] and (candidate_id := finding_candidate_id(value)):
                    candidate_key = _worker_candidate_key(group["owner"], candidate_id, value)
                    if _digest(_finding_content(value)) in represented_candidate_history.get(
                        candidate_key, set()
                    ):
                        destinations.add(represented_candidates[candidate_key])
            if len(destinations) == 1 and None not in destinations:
                group["parent_key"] = destinations.pop()

    generated_worker_findings: list[dict[str, Any]] = []

    def source_coverage_selection(
        relative: str,
        worker_id: str | None,
    ) -> tuple[bool, set[str], bool, bool, bool]:
        worker_result_order = terminal_worker_orders.get(worker_id)
        selected_coverage_superseded = worker_id in selected_terminal_orders and (
            source_order[relative] < selected_terminal_orders[worker_id]
            or (
                relative in current_results
                and source_order[relative] <= selected_terminal_orders[worker_id]
            )
        )
        selected_candidates = {
            candidate_id
            for (owner, candidate_id), (_, source) in ordered_outcomes.items()
            if owner == worker_id and source == relative
        }
        superseded = (
            worker_id is None
            and parent is not None
            and parent.get("complete") is not False
            and relative != "parent"
            and source_order[relative] <= (0, parent_modified)
            and (not stopped_parent_seal or relative in parent_preserved_sources)
        ) or (
            relative not in current_results
            and worker_result_order is not None
            and (
                relative not in selected_observations
                or source_order[relative] < worker_result_order
            )
        )
        worker_coverage_order = terminal_coverage_orders.get(worker_id)
        coverage_superseded = (
            superseded
            if worker_id is None
            else (
                relative not in current_results
                and worker_coverage_order is not None
                and (
                    relative not in selected_observations
                    or source_order[relative] < worker_coverage_order
                )
            )
        )
        # A failed result write can leave pending work outside the accepted result.
        accepted_order = (
            (0, parent_modified)
            if worker_id is None and parent is not None
            else worker_coverage_order
        )
        retain_pending = (
            coverage_superseded
            and (worker_id in headed_workers or (worker_id is None and parent_heads))
            and accepted_order is not None
            and source_order[relative] >= accepted_order
            and any(isinstance(row, dict) for row in deferred_rows[relative])
        )
        return (
            selected_coverage_superseded,
            selected_candidates,
            superseded,
            retain_pending,
            coverage_superseded,
        )

    def coverage_row_is_retained(
        field: str,
        item: Any,
        worker_id: str | None,
        selection: tuple[bool, set[str], bool, bool, bool],
    ) -> bool:
        (
            selected_coverage_superseded,
            selected_candidates,
            superseded,
            retain_pending,
            coverage_superseded,
        ) = selection
        # A selected terminal checkpoint replaces ordinary coverage, while
        # candidate evidence and pending tasks retain their own reconciliation.
        if (
            selected_coverage_superseded
            and field != "deferred"
            and not (
                isinstance(item, dict)
                and any(key in item for key in ("candidateId", "candidate", "finding"))
            )
        ):
            return False
        # A selected outcome must retain its evidence even if its result write failed.
        if coverage_superseded and not (
            isinstance(item, dict)
            and (
                (field == "deferred" and retain_pending)
                or (
                    isinstance(item.get("candidateId"), str)
                    and item["candidateId"] in selected_candidates
                    and item.get("disposition") == resolved.get((worker_id, item["candidateId"]))
                )
            )
        ):
            return False
        if (
            isinstance(item, dict)
            and isinstance(
                identity := _deferred_candidate_id(item, worker_id, ambiguous_deferred)
                if field == "deferred"
                else item.get("candidateId"),
                str,
            )
            and (worker_id, identity) in resolved
            and (field == "deferred" or item.get("disposition") == "needs_follow_up")
        ):
            return False
        return True

    ambiguous_surface_ids = {
        (owner, identity)
        for owner, row in reopened_rows
        if isinstance(row.get("id"), str)
        and (owner, row["id"]) in ambiguous_deferred
        and not any(key in row for key in ("candidateId", "candidate", "finding"))
        for identity in [
            row["id"],
            *(row.get("surfaceIds", []) if isinstance(row.get("surfaceIds", []), list) else []),
        ]
        if isinstance(identity, str)
    }
    for _, draft, owner in all_sources:
        surfaces = draft["coverage"].get("surfaces", [])
        by_id: dict[str, dict[str, Any]] = {}
        for surface in surfaces if isinstance(surfaces, list) else []:
            if not isinstance(surface, dict) or not isinstance(identity := surface.get("id"), str):
                continue
            if identity in by_id and surface != by_id[identity]:
                ambiguous_surface_ids.add((owner, identity))
            by_id[identity] = surface

    replaced_deferred = {
        id(row)
        for relative, _, owner in all_sources
        for row in deferred_rows[relative]
        if isinstance(row, dict)
        and isinstance(identity := row.get("id"), str)
        and (key := (owner, identity)) not in candidate_ids
        and key not in ambiguous_deferred
        and (updated := accepted_deferred_orders.get(key)) is not None
        and updated > source_order[relative]
    }
    fallback_surfaces = []
    if surface_links and isinstance(coverage.get("surfaces"), list):
        # Plan the surviving associations before historical receipts can claim
        # a spelling needed by a surface that must be restored for its task.
        prospective_tasks = []
        prospective_surfaces = {}
        prospective_named = {}
        for relative, draft, owner in all_sources:
            selection = source_coverage_selection(relative, owner)
            for row in deferred_rows[relative]:
                if (
                    coverage_row_is_retained("deferred", row, owner, selection)
                    and id(row) not in replaced_deferred
                    and not (
                        isinstance(row, dict)
                        and isinstance(row.get("id"), str)
                        and (owner, row["id"]) in closed_deferred
                    )
                ):
                    prospective_tasks.append(
                        (owner, _project_worker_coverage_row(row, owner, "deferred"))
                    )
            rows = draft["coverage"].get("surfaces", [])
            for row in rows if isinstance(rows, list) else []:
                if owner is None or not isinstance(row, dict):
                    continue
                emitted = coverage_row_is_retained("surfaces", row, owner, selection)
                ambiguous = (
                    isinstance(row.get("id"), str)
                    and (owner, row["id"]) in ambiguous_surface_ids
                    and row.get("disposition") == "needs_follow_up"
                    and not any(key in row for key in ("candidateId", "candidate", "finding"))
                )
                if not emitted and not ambiguous:
                    continue
                projected = _project_worker_coverage_row(row, owner, "surfaces")
                if isinstance(row.get("id"), str):
                    named = prospective_named.setdefault((owner, row["id"]), {})
                    projected = next(
                        (existing for existing in named.values() if existing == projected),
                        projected,
                    )
                    named[id(projected)] = projected
                if emitted:
                    prospective_surfaces[id(row)] = projected
        prospective_tasks.extend(
            (owner, _project_worker_coverage_row(row, owner, "deferred"))
            for owner, row in reopened_rows
            if (owner, _deferred_candidate_id(row, owner, ambiguous_deferred)) not in resolved
        )
        bound = {
            (id(retained), published_id)
            for task, published_id, surface, _, task_source in surface_links
            if linked_surface(surface, prospective_surfaces, prospective_named) is not None
            for retained in linked_tasks(task, published_id, task_source, prospective_tasks)
        }
        for task, published_id, _, parent_surface, task_source in surface_links:
            for retained in linked_tasks(task, published_id, task_source, prospective_tasks):
                key = (id(retained), published_id)
                if key not in bound:
                    fallback_surfaces.append(parent_surface)
                    bound.add(key)

    replaced_surfaces, surface_updates = _generic_surface_updates(
        all_sources,
        source_order,
        closed_deferred,
        active_deferred,
        resolved,
        reopened_generic,
        coverage_schema["surfaces"]["items"],
        deferred_rows,
        ambiguous_deferred,
        canonical_rows,
        coverage_sources,
        receipt_root=scan_dir if project_worker_coverage else None,
        receipt_warnings=warnings,
        fallback_surfaces=fallback_surfaces,
        surface_is_retained=lambda relative, owner, row: coverage_row_is_retained(
            "surfaces", row, owner, source_coverage_selection(relative, owner)
        ),
        eligible_receipt_sources={
            relative
            for relative, draft, _ in all_sources
            if draft.get("complete") is not False or relative in selected_observations
        },
    )
    replaced_rows = {
        "surfaces": replaced_surfaces,
        "deferred": replaced_deferred,
    }
    for field, replaced in replaced_rows.items():
        if parent and isinstance(coverage.get(field), list):
            previous = parent["coverage"].get(field, [])
            if isinstance(previous, list):
                removed_parent = [row for row in previous if id(row) in replaced]
                coverage[field] = [row for row in coverage[field] if row not in removed_parent]
    if isinstance(coverage.get("surfaces"), list):
        for owner, surface, replaced_sources in surface_updates:
            retained = append_coverage_row(coverage["surfaces"], surface, owner, "surfaces")
            for source_id in replaced_sources & linked_surface_sources:
                linked_surface_outputs[source_id] = retained
        for surface in coverage["surfaces"]:
            if isinstance(surface, dict):
                surface.setdefault("receiptRefs", [])

    # Reopened work survives a superseded checkpoint, but current candidate
    # outcomes still apply. Parent closures cannot remove another worker's row.
    for owner, item in reopened_rows:
        if (identity := _deferred_candidate_id(item, owner, ambiguous_deferred)) is not None and (
            owner,
            identity,
        ) in resolved:
            continue
        pending = coverage.setdefault("deferred", [])
        if isinstance(pending, list):
            append_coverage_row(pending, item, owner, "deferred")
    for _, draft, owner in all_sources:
        surfaces = draft["coverage"].get("surfaces", [])
        for surface in surfaces if isinstance(surfaces, list) else []:
            if (
                isinstance(surface, dict)
                and isinstance(surface.get("id"), str)
                and (owner, surface["id"]) in ambiguous_surface_ids
                and surface.get("disposition") == "needs_follow_up"
                and not any(key in surface for key in ("candidateId", "candidate", "finding"))
                and isinstance(coverage.get("surfaces"), list)
            ):
                retained = append_coverage_row(
                    coverage["surfaces"],
                    {**surface, "receiptRefs": surface.get("receiptRefs", [])},
                    owner,
                    "surfaces",
                )
                _inherit_coverage_sources(retained, [surface], coverage_sources)
                retained_surface_rows.add(id(surface))
    for relative, draft, worker_id in all_sources:
        selection = source_coverage_selection(relative, worker_id)
        (
            selected_coverage_superseded,
            selected_candidates,
            superseded,
            retain_pending,
            coverage_superseded,
        ) = selection
        skip_superseded_findings = (
            superseded
            and not stopped
            and all(valid_finding(finding) for finding in (parent["findings"] if parent else []))
        )
        if (
            skip_superseded_findings
            and coverage_superseded
            and not selected_candidates
            and not retain_pending
        ):
            continue
        if (
            not skip_superseded_findings
            and "threatModel" not in manifest["scan"]
            and isinstance(draft.get("threatModel"), dict)
        ):
            model = recovered_model(relative, draft, worker_id)
            model_path = relative
            checkpoint_dir = Path(relative).parent
            prefer_worker_head = worker_id is not None and (
                checkpoint_dir.name == "checkpoints" or draft.get("complete") is False
            )
            if worker_id is not None:
                if checkpoint_dir.name != "checkpoints":
                    checkpoint_dir /= "checkpoints"
                selected_models = [
                    path
                    for path in selected_observations
                    if Path(path).parent == checkpoint_dir
                    and isinstance(drafts_by_path[path].get("threatModel"), dict)
                    and recovered_model(path, drafts_by_path[path], worker_id) is not None
                ]
                if selected_models:
                    head_path = max(selected_models, key=source_order.__getitem__)
                    current = drafts_by_path[head_path]
                    # A terminal checkpoint is committed before result.json is replaced.
                    # Use the admitted observation, including its frozen ordering on retries.
                    if not prefer_worker_head and current.get("complete") is not False:
                        prefer_worker_head = source_order[head_path] >= source_order[relative]
                    if prefer_worker_head:
                        model = recovered_model(head_path, current, worker_id)
                        model_path = head_path
            if model is not None:
                manifest["scan"]["threatModel"] = model
                if selected_model_source is not None and worker_id is not None:
                    selected_model_source[:] = [model_path]
        normalized_findings = copy.deepcopy(draft["findings"])
        _ensure_finding_identities(
            [finding for finding in normalized_findings if valid_finding(finding)]
        )
        for index, (value, normalized) in enumerate(
            zip(draft["findings"], normalized_findings, strict=True)
        ):
            if precedes_terminal_parent(relative, worker_id) or replaced_parent_finding(
                relative, worker_id, value
            ):
                continue
            _ensure_finding_identity(normalized)
            group = row_groups.get((relative, index))
            if group is not None and group["key"] in contained_groups:
                continue
            if skip_superseded_findings and not (
                isinstance(value, dict)
                and (candidate_id := finding_candidate_id(value)) in selected_candidates
                and resolved.get((worker_id, candidate_id)) == "reported"
            ):
                continue
            if relative == "parent" and parent_is_canonical:
                finding = copy.deepcopy(value)
                group = row_groups.get((relative, index))
                restore_legacy_identity(
                    finding,
                    group or normalized,
                    allow_synthesis=stopped
                    or (isinstance(finding, dict) and _identity_candidate(finding) is not None)
                    or (group is not None and any("identity" in row for row in group["rows"])),
                )
                provenance = finding.get("provenance") if isinstance(finding, dict) else None
                owner = provenance.get("workerId") if isinstance(provenance, dict) else None
                candidate_id = finding_candidate_id(finding) if isinstance(finding, dict) else None
                if (
                    stopped_parent_seal
                    and isinstance(owner, str)
                    and candidate_id
                    and resolved.get((owner, candidate_id)) in ("rejected", "not_applicable")
                ):
                    rejected_history.setdefault((owner, candidate_id), []).append(finding)
                    continue
                if valid_finding(finding):
                    key = _finding_key(finding)
                    if group is not None:
                        key = group.setdefault("merge_key", key)
                    finding_positions.setdefault(key, (len(findings), group))
                    if preserve_canonical_parent:
                        canonical_finding_keys.add(key)
                findings.append(finding)
                continue
            if (
                relative != "parent"
                and parent
                and value in parent["findings"]
                and not precedes_terminal_parent("parent", None)
                and not replaced_parent_finding("parent", None, value)
            ):
                continue
            if not isinstance(value, dict):
                warnings.append(f"Retained malformed finding evidence in {relative}.")
                continue
            finding = copy.deepcopy(value)
            candidate_id = finding_candidate_id(finding)
            if relative != "parent" and resolved.get((worker_id, candidate_id)) in {
                "rejected",
                "not_applicable",
            }:
                if preserve_canonical_parent:
                    rejected_history.setdefault((worker_id, candidate_id), []).append(finding)
                surfaces = coverage.get("surfaces")
                for item in surfaces if isinstance(surfaces, list) else []:
                    if (
                        isinstance(item, dict)
                        and item.get("candidateId") == candidate_id
                        and (not preserve_canonical_parent or item.get("workerId") == worker_id)
                    ):
                        if not isinstance(item.get("previousFindings"), list):
                            item["previousFindings"] = []
                        history = item["previousFindings"]
                        if not any(
                            isinstance(previous, dict)
                            and _finding_key(previous) == _finding_key(finding)
                            and _finding_content(previous) == _finding_content(finding)
                            for previous in history
                        ):
                            history.append(finding)
                continue
            for key in ("findingId", "occurrenceId", "fingerprints"):
                finding.pop(key, None)
            if not finding_within_scope(finding):
                warnings.append(f"Skipped out-of-scope finding from {relative}.")
                continue
            provenance = finding.setdefault("provenance", {"source": "local_plugin"})
            if not isinstance(provenance, dict):
                findings.append(finding)
                continue
            if worker_id:
                provenance.setdefault("workerId", worker_id)
            group = row_groups.get((relative, index))
            if relative in terminal_findings:
                terminal = terminal_findings[relative][index]
                finding["identity"] = copy.deepcopy(terminal["identity"])
                if "preservedIdentity" in terminal.get("provenance", {}):
                    provenance.setdefault(
                        "preservedIdentity",
                        copy.deepcopy(terminal["provenance"]["preservedIdentity"]),
                    )
            elif group is not None and group["identity"] is not None:
                finding.setdefault("identity", copy.deepcopy(group["identity"]))
            if worker_id is not None and "identity" not in finding:
                generated_worker_findings.append(finding)
            finding.setdefault("identity", normalized["identity"])
            if not valid_finding(finding):
                findings.append(finding)
                continue
            # Terminal siblings remain separate even when their preserved authored
            # identities and locations coincide. Worker revisions reuse the group.
            key = (
                group["key"]
                if group is not None
                and (group["identity"] is None or relative in terminal_findings)
                else _finding_key(finding)
            )
            if group is not None:
                key = group.setdefault("merge_key", key)
                # Distinct reconciled reports may share an anchor and source location.
                if key in finding_positions and distinct_reports(group, finding_positions[key][1]):
                    key = group["merge_key"] = group["key"]
                key = group.get("parent_key", key)
            represented_by_parent = False
            if relative != "parent":
                history_key = _finding_key(value)
                # A singleton key is not evidence that a new batch sibling was
                # absorbed. Only recorded content may reuse that historical edge.
                if _digest(_finding_content(value)) not in represented_history.get(
                    history_key, set()
                ):
                    history_key = key
                if history_key in represented:
                    mapped_key = represented[history_key]
                    historical_contents = represented_history.get(history_key, set())
                elif worker_id and candidate_id:
                    candidate_key = _worker_candidate_key(worker_id, candidate_id, finding)
                    mapped_key = represented_candidates.get(candidate_key)
                    historical_contents = represented_candidate_history.get(candidate_key, set())
                else:
                    mapped_key = None
                    historical_contents = set()
                if mapped_key is not None:
                    key = mapped_key
                    represented_by_parent = _digest(_finding_content(value)) in historical_contents
            if key in finding_positions:
                position, retained_group = finding_positions[key]
                retained = findings[position]
                for field in ("anchor", "instance"):
                    if field in retained["identity"]:
                        finding["identity"][field] = retained["identity"][field]
                    else:
                        finding["identity"].pop(field, None)
                if finding != retained:
                    if (
                        key not in canonical_finding_keys
                        and not represented_by_parent
                        and (
                            value is group["latest"]
                            if group is not None and group is retained_group
                            else _finding_strength(finding) > _finding_strength(retained)
                        )
                    ):
                        previous = copy.deepcopy(retained)
                        previous_history = previous["provenance"].pop("previousFindings", [])
                        if "preservedIdentity" in retained["provenance"]:
                            finding["provenance"]["preservedIdentity"] = copy.deepcopy(
                                retained["provenance"]["preservedIdentity"]
                            )
                        retained = finding
                        findings[position] = retained
                        finding_positions[key] = (position, group)
                    else:
                        previous = copy.deepcopy(value)
                        previous_history = previous.get("provenance", {}).pop(
                            "previousFindings", []
                        )
                    retained_provenance = retained["provenance"]
                    for field in ("sourceFindingIds", "sourceFindings", "originalCandidates"):
                        values = retained_provenance.get(field, [])
                        values = list(values) if isinstance(values, list) else []
                        previous_values = previous.get("provenance", {}).get(field, [])
                        for item in previous_values if isinstance(previous_values, list) else []:
                            if item not in values:
                                values.append(copy.deepcopy(item))
                        if values:
                            retained_provenance[field] = values
                    retained_history = retained_provenance.get("previousFindings")
                    history = (
                        [item for item in retained_history if isinstance(item, dict)]
                        if isinstance(retained_history, list)
                        else []
                    )
                    for original in [
                        *(previous_history if isinstance(previous_history, list) else []),
                        previous,
                    ]:
                        if not isinstance(original, dict):
                            continue
                        owner = retained_provenance.get("workerId", worker_id)
                        source_key = _finding_key(original, owner)
                        source_content = _finding_content(original)
                        already_retained = any(
                            source_key == _finding_key(historical, owner)
                            and source_content == _finding_content(historical)
                            for historical in _retained_findings(retained)
                        )
                        if (
                            not already_retained
                            and original not in history
                            and original != retained
                        ):
                            history.append(original)
                    if history or retained_history is not None:
                        retained_provenance["previousFindings"] = history
                continue
            finding_positions[key] = (len(findings), group)
            findings.append(finding)
        if coverage_superseded and not selected_candidates and not retain_pending:
            continue
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
            if coverage_superseded and field not in {"surfaces", "explicitExclusions", "deferred"}:
                continue
            items = draft["coverage"].get(field, [])
            if field == "deferred":
                items = deferred_rows[relative]
            if not isinstance(items, list):
                continue
            output = coverage.setdefault(field, [])
            if not isinstance(output, list):
                # Keep malformed canonical collections for the existing finalizer's
                # recovery and warnings rather than silently changing its contract.
                continue
            for item in items:
                source_item = original_item = item
                if not coverage_row_is_retained(field, item, worker_id, selection):
                    continue
                if id(item) in replaced_rows.get(field, ()):
                    continue
                if (
                    field == "deferred"
                    and isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                    and (worker_id, item["id"]) in closed_deferred
                ):
                    continue
                if field == "openQuestions" and isinstance(item, str):
                    item = {"question": item.strip()}
                if (
                    field == "surfaces"
                    and isinstance(item, dict)
                    and item.get("disposition") in ("rejected", "not_applicable")
                    and isinstance(item.get("candidateId"), str)
                    and (history_findings := rejected_history.get((worker_id, item["candidateId"])))
                ):
                    item = copy.deepcopy(item)
                    if not isinstance(item.get("previousFindings"), list):
                        item["previousFindings"] = []
                    history = item["previousFindings"]
                    for finding in history_findings:
                        if not any(
                            isinstance(previous, dict)
                            and _finding_key(previous) == _finding_key(finding)
                            and _finding_content(previous) == _finding_content(finding)
                            for previous in history
                        ):
                            history.append(copy.deepcopy(finding))
                if field == "surfaces" and isinstance(item, dict):
                    item = {**item, "receiptRefs": item.get("receiptRefs", [])}
                if isinstance(item, dict) and "id" not in item:
                    semantic_item = dict(item)
                    existing = next(
                        (
                            row
                            for row in output
                            if isinstance(row, dict)
                            and {key: value for key, value in row.items() if key != "id"}
                            == semantic_item
                        ),
                        None,
                    )
                    if existing is not None:
                        if project_worker_coverage and worker_id is not None:
                            worker_row_owners[id(existing)] = worker_id
                        if field == "surfaces" and id(source_item) in linked_surface_sources:
                            linked_surface_outputs[id(source_item)] = existing
                        _inherit_coverage_sources(existing, [original_item], coverage_sources)
                        if field == "surfaces":
                            retained_surface_rows.add(id(original_item))
                        continue
                retained = append_coverage_row(output, item, worker_id, field)
                _inherit_coverage_sources(retained, [original_item], coverage_sources)
                if field == "surfaces":
                    retained_surface_rows.add(id(original_item))
                if field == "surfaces" and id(source_item) in linked_surface_sources:
                    linked_surface_outputs[id(source_item)] = retained

    # Generate new worker identities from the retained collection, as a normal
    # Deep parent does. Authored, restored and canonical identities stay stable.
    generated_worker_ids = {id(finding) for finding in generated_worker_findings}
    for finding in generated_worker_findings:
        finding.pop("identity", None)

    def publication_order(item):
        _, group = item
        source, value = group["observations"][group["owner"]]
        index = next(index for index, row in enumerate(source[1]["findings"]) if row is value)
        return finding_source_order(source, True), -index

    identity_order = list(findings)
    for owner in {group["owner"] for _, group in finding_positions.values() if group is not None}:
        positions = [
            (position, group)
            for position, group in finding_positions.values()
            if group is not None and group["owner"] == owner and group["identity"] is None
        ]

        for (position, _), (published_position, _) in zip(
            positions, sorted(positions, key=publication_order, reverse=True), strict=True
        ):
            identity_order[position] = findings[published_position]
    identity_order = [
        finding
        for finding in identity_order
        if valid_finding(finding) and ("identity" in finding or id(finding) in generated_worker_ids)
    ]
    _ensure_finding_identities(identity_order)

    identities: dict[bytes, list[tuple[str, dict[str, Any] | None, str | None]]] = {}
    retained_groups = {
        position: group for position, group in finding_positions.values() if group is not None
    }
    reserved_identities = {_semantic_identity_key(finding) for finding in identity_order}
    for position, finding in enumerate(findings):
        if not valid_finding(finding):
            continue
        identity = finding.get("identity")
        if not isinstance(identity, dict):
            continue
        key = _semantic_identity_key(finding)
        variant = _finding_key(finding)
        group = retained_groups.get(position)
        previous = next(
            (
                entry
                for entry in identities.get(key, [])
                if entry[0] == variant and not distinct_reports(group, entry[1])
            ),
            None,
        )
        if previous is not None and previous[2] is not None:
            if identity.get("instance") != previous[2]:
                finding.setdefault("provenance", {}).setdefault(
                    "preservedIdentity", copy.deepcopy(identity)
                )
                identity["instance"] = previous[2]
        elif previous is None and key in identities:
            finding.setdefault("provenance", {}).setdefault(
                "preservedIdentity", copy.deepcopy(identity)
            )
            base_instance = identity.get("instance", "saved")
            suffix = 2
            while True:
                identity["instance"] = f"{base_instance}-{suffix}"
                distinct = _semantic_identity_key(finding)
                if distinct not in reserved_identities:
                    reserved_identities.add(distinct)
                    break
                suffix += 1
        identities.setdefault(key, []).append((variant, group, identity.get("instance")))
    recovered_worker_ids = {worker_id for _, _, worker_id in sources if worker_id is not None}
    surface_positions: dict[str, int] = {}
    resolved_surface_targets: dict[tuple[str | None, str], list[str]] = {}

    def remember_surface_id(item: dict[str, Any], local_id: str) -> None:
        final_id = item["id"]
        surface_positions.setdefault(final_id, len(surface_positions))
        shadowed_alias = (
            project_worker_coverage
            and id(item) not in named_surface_outputs
            and (named := worker_surfaces.get((worker_row_owners.get(id(item)), local_id)))
            is not None
            and id(named) in named_surface_outputs
        )
        for relative in coverage_sources.get(id(item), (item, []))[1]:
            # A candidate-derived ID cannot claim a link explicitly naming another surface.
            if not shadowed_alias:
                targets = surface_ids_by_source.setdefault((relative, local_id), [])
                if final_id not in targets:
                    targets.append(final_id)
            candidate_id = item.get("candidateId")
            if isinstance(candidate_id, str):
                key = (source_owners[relative], candidate_id)
                if key in resolved and resolved[key] == item.get("disposition"):
                    targets = resolved_surface_targets.setdefault(key, [])
                    if final_id not in targets:
                        targets.append(final_id)

    # Bind links to retained output objects before their IDs become unique.
    # Candidate metadata can give an anonymous row the same preliminary ID as
    # another surface, so only the final surface ID can be used for its links.
    retained_surface_links: dict[int, tuple[dict[str, Any], dict[str, dict[str, Any]]]] = {}
    output_tasks = coverage.get("deferred", [])
    task_candidates = [
        (worker_row_owners.get(id(row)), row)
        for row in (output_tasks if isinstance(output_tasks, list) else [])
    ]
    for task, published_id, surface, _, task_source in surface_links:
        retained_surface = linked_surface(surface, linked_surface_outputs, worker_surface_outputs)
        if retained_surface is None or not isinstance(retained_surface.get("id"), str):
            continue
        for retained_task in linked_tasks(task, published_id, task_source, task_candidates):
            _, links = retained_surface_links.setdefault(id(retained_task), (retained_task, {}))
            links.setdefault(published_id, retained_surface)
    # A newer worker checkpoint may omit a surface still needed by a retained
    # task. Restore its parent copy only when no worker replacement survived.
    for task, published_id, surface, parent_surface, task_source in surface_links:
        for retained_task in linked_tasks(task, published_id, task_source, task_candidates):
            _, links = retained_surface_links.setdefault(id(retained_task), (retained_task, {}))
            if published_id not in links and isinstance(coverage.get("surfaces"), list):
                retained_surface = append_coverage_row(
                    coverage["surfaces"], parent_surface, None, "surfaces"
                )
                record_coverage_owner(
                    retained_surface, surface, surface.get("workerId"), "surfaces"
                )
                links[published_id] = retained_surface
    if project_worker_coverage:
        worker_surfaces: dict[tuple[str, str], dict[str, Any]] = {}
        named_surface_outputs = {
            identity for outputs in worker_surface_outputs.values() for identity in outputs
        }
        surfaces = coverage.get("surfaces", [])
        for surface in surfaces if isinstance(surfaces, list) else []:
            if not isinstance(surface, dict):
                continue
            owner, identity = worker_row_owners.get(id(surface)), surface.get("id")
            if isinstance(owner, str) and isinstance(identity, str):
                key = (owner, identity)
                existing = worker_surfaces.get(key)
                # An anonymous candidate ID can collide with an explicit surface ID.
                # Bind a named worker link to the explicitly named source.
                if existing is None or (
                    id(surface) in named_surface_outputs
                    and id(existing) not in named_surface_outputs
                ):
                    worker_surfaces[key] = surface
        for task in output_tasks if isinstance(output_tasks, list) else []:
            if (
                not isinstance(task, dict)
                or (owner := worker_row_owners.get(id(task))) is None
                or not isinstance(task.get("surfaceIds"), list)
            ):
                continue
            for identity in task["surfaceIds"]:
                if (
                    isinstance(identity, str)
                    and (surface := worker_surfaces.get((owner, identity))) is not None
                ):
                    _, links = retained_surface_links.setdefault(id(task), (task, {}))
                    links.setdefault(identity, surface)
    for field in ("surfaces", "explicitExclusions", "deferred"):
        used: set[str] = set()
        items = coverage.setdefault(field, [])
        reserved = {
            row["id"]
            for row in (items if isinstance(items, list) else [])
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        }
        normalized_items = []
        for item in items if isinstance(items, list) else []:
            normalized_items.append(item)
            if not isinstance(item, dict):
                continue
            if id(item) in canonical_rows:
                if isinstance(item.get("id"), str):
                    used.add(item["id"])
                    if field == "surfaces":
                        remember_surface_id(item, item["id"])
                continue
            item.setdefault("id", _saved_coverage_id(item))
            if not isinstance(item["id"], str):
                # Preserve malformed rows for per-record recovery, including frozen replay.
                continue
            local_id = item["id"]
            scoped = (
                preserve_canonical_parent
                and isinstance(worker_id := item.get("workerId"), str)
                and worker_id in recovered_worker_ids
            )
            if scoped:
                # Resolve worker-local candidate/deferred history before scoping IDs.
                item["id"] = f"{worker_id}/{item['id']}"
            if isinstance(item.get("surfaceIds"), list):
                links: list[Any] = []
                for surface_id in item["surfaceIds"]:
                    targets: list[str] = []
                    declared = False
                    if field == "deferred" and isinstance(surface_id, str):
                        for relative in coverage_sources.get(id(item), (item, []))[1]:
                            source_key = (relative, surface_id)
                            history_keys = [source_key]
                            if source_key not in surface_ids_by_source:
                                # A deferred-only checkpoint can refer to an earlier
                                # observation from this logical worker, including retries.
                                # Reused IDs can denote several retained observations.
                                history_keys = [
                                    (historical, surface_id)
                                    for historical, _, owner in all_sources
                                    if owner == source_owners[relative]
                                    and source_order[historical] <= source_order[relative]
                                ]
                            for key in history_keys:
                                declared |= key in surface_ids_by_source
                                for target in surface_ids_by_source.get(key, []):
                                    if target not in targets:
                                        targets.append(target)
                    if targets:
                        targets.sort(key=surface_positions.__getitem__)
                        for target in targets:
                            if target not in links:
                                links.append(target)
                    elif not declared:
                        links.append(
                            f"{worker_id}/{surface_id}"
                            if scoped and isinstance(surface_id, str)
                            else surface_id
                        )
                item["surfaceIds"] = links
            if scoped:
                if item in normalized_items[:-1]:
                    # A previous finish may have published files before its DB commit.
                    if field == "surfaces":
                        remember_surface_id(item, local_id)
                    normalized_items.pop()
                    continue
            if item["id"] in used:
                if project_worker_coverage:
                    base = item["id"]
                    suffix = 2
                    while item["id"] in used or item["id"] in reserved:
                        item["id"] = f"{base}-{suffix}"
                        suffix += 1
                else:
                    item["id"] = f"{item['id']}-{_digest(item)[:16]}"
            if preserve_canonical_parent and item in normalized_items[:-1]:
                if field == "surfaces":
                    remember_surface_id(item, local_id)
                normalized_items.pop()
                continue
            used.add(item["id"])
            if field == "surfaces":
                item.setdefault("receiptRefs", [])
                remember_surface_id(item, local_id)
        if preserve_canonical_parent and isinstance(items, list):
            coverage[field] = normalized_items
        if field == "surfaces":
            # Candidate resolution replaces pending surfaces independently of generic
            # tasks. Preserve their original links, even when the outcome changes ID
            # or a distinct retained surface shares the old source-local ID.
            for relative, draft, owner in all_sources:
                originals = draft["coverage"].get("surfaces", [])
                for original in originals if isinstance(originals, list) else []:
                    if (
                        not isinstance(original, dict)
                        or id(original) in retained_surface_rows
                        or original.get("disposition") != "needs_follow_up"
                        or not isinstance(local_id := original.get("id"), str)
                        or not isinstance(candidate_id := original.get("candidateId"), str)
                    ):
                        continue
                    targets = surface_ids_by_source.setdefault((relative, local_id), [])
                    for target in resolved_surface_targets.get((owner, candidate_id), []):
                        if target not in targets:
                            targets.append(target)
    for task, links in retained_surface_links.values():
        task["surfaceIds"] = [
            links[identity]["id"] if isinstance(identity, str) and identity in links else identity
            for identity in task["surfaceIds"]
        ]
    coverage.pop("completeness", None)
    if stopped:
        if not isinstance(coverage.get("deferred"), list):
            coverage["deferred"] = []
        item = {"id": "scan-stopped", "reason": reason}
        if item not in coverage["deferred"]:
            coverage["deferred"].append(item)
    return manifest, {"findings": findings}, coverage
