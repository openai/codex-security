"""Retain semantic scan drafts without rerunning analysis or changing run state."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re
import sqlite3
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    PreparedScanFinalization,
    RecoverableContractError,
    _contract_json_bytes,
    _finding_strength,
    _populate_unsealed_artifact_envelope,
    _populate_unsealed_manifest_envelope,
    _prepare_scan_finalization,
    _read_json,
    _read_saved_threat_model,
    _read_scan_local_json,
    _read_scan_local_json_bytes,
    _recover_unsealed_findings,
    _remove_scan_local_file_if_exists,
    _require_portable_relative_path,
    _require_str,
    _validate_completion_binding,
    _validate_resolved_deferred,
    _validate_schema_node,
    _write_prepared_scan_finalization,
    finalize_scan,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
    write_threat_model_projection_if_possible,
)
from workbench.saved_coverage import (
    _merge_reviewed_surface_receipts,
    _prepare_worker_coverage_recovery,
    _project_worker_coverage_row,
    _saved_coverage_id,
)
from workbench.saved_sources import (
    _accepted_source_digests as _accepted_source_digests,
)
from workbench.saved_sources import (
    _capture_saved_source as _capture_saved_source,
)
from workbench.saved_sources import (
    _checkpoint_head_directory as _checkpoint_head_directory,
)
from workbench.saved_sources import (
    _checkpoint_paths as _checkpoint_paths,
)
from workbench.saved_sources import (
    _digest as _digest,
)
from workbench.saved_sources import (
    _encode_retained_sources as _encode_retained_sources,
)
from workbench.saved_sources import (
    _encoded as _encoded,
)
from workbench.saved_sources import (
    _freeze_source_times as _freeze_source_times,
)
from workbench.saved_sources import (
    _frozen_source_times as _frozen_source_times,
)
from workbench.saved_sources import (
    _is_source_order_snapshot as _is_source_order_snapshot,
)
from workbench.saved_sources import (
    _latest_successful_reducer as _latest_successful_reducer,
)
from workbench.saved_sources import (
    _parent_scan_draft as _parent_scan_draft,
)
from workbench.saved_sources import (
    _read_saved_parent_result as _read_saved_parent_result,
)
from workbench.saved_sources import (
    _read_saved_result as _read_saved_result,
)
from workbench.saved_sources import (
    _recovery_source_digests as _recovery_source_digests,
)
from workbench.saved_sources import (
    _retained_source_state as _retained_source_state,
)
from workbench.saved_sources import (
    _saved_results_changed as _saved_results_changed,
)
from workbench.saved_sources import (
    _saved_workers as _saved_workers,
)
from workbench.saved_sources import (
    _source_digests as _source_digests,
)
from workbench.saved_sources import (
    _worker_checkpoint_heads as _worker_checkpoint_heads,
)
from workbench.saved_sources import (
    _worker_outputs as _worker_outputs,
)
from workbench_constants import PHASES
from workbench_source_coverage import retain_unmerged_review_coverage
from workbench_target import committed_diff_snapshot_digest
from workbench_validation import (
    has_verified_selected_result,
    latest_publication_reducer,
    path_within_scope,
)

_PUBLISHED_OUTPUTS = (
    "findings.json",
    "coverage.json",
    "scan-manifest.json",
    "report.md",
    "threatmodel.md",
    "report.html",
    "exports/results.sarif",
)
_PUBLICATION_FOLLOW_UP_WARNING = (
    "Saved scan evidence remains on disk; result publication needs follow-up:"
)
_RESERVED_ARTIFACT_PATHS = json.loads(
    Path(__file__).with_name("reserved_artifact_paths.json").read_text(encoding="utf-8")
)


def threat_model_fields(db: Any, scan: sqlite3.Row) -> dict[str, Any]:
    scan_dir = Path(scan["scan_dir"])
    fields: dict[str, Any] = {"threatModelAvailable": False}
    try:
        db.require_recorded_manifest_digest(scan, scan_dir)
        db.verify_manifest_binding(
            scan, _read_scan_local_json(scan_dir, db.ARTIFACTS["manifest"], "scan manifest")
        )
        saved_model = _read_saved_threat_model(scan_dir)
        if saved_model is not None:
            description = saved_model[0]
            fields.update(
                threatModelAvailable=True,
                threatModelProvenance=description["provenance"],
            )
            if description["path"] is not None:
                fields["threatModelPath"] = description["path"]
    except (ContractError, OSError, SystemExit):
        # Unavailable optional model data must not prevent reading the saved scan.
        pass
    return fields


def refresh_completed_scan(
    db: Any,
    connection: sqlite3.Connection,
    scan: sqlite3.Row,
    cost_json: str | None,
    *,
    prepare_only: bool = False,
) -> dict[str, Any]:
    warnings = json.loads(scan["completion_warnings_json"])
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    db.verify_manifest_binding(scan, db.read_json_object(scan_dir / db.ARTIFACTS["manifest"]))
    try:
        accepted = prepare_only and has_verified_selected_result(db, connection, scan)
        manifest, _, coverage = finalize_scan(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            projection_warnings=warnings,
        )
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    db.verify_manifest_binding(scan, manifest)
    manifest_digest = db.published_manifest_digest(scan_dir, manifest)
    db.pin_legacy_manifest_digest(connection, scan["id"], manifest_digest)
    if cost_json is not None and scan["recipe_json"] is not None:
        db.scan_usage.reconcile_completed_scan_cost(connection, scan, cost_json)
    if warnings != json.loads(scan["completion_warnings_json"]):
        with connection:
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                (json.dumps(warnings), scan["id"]),
            )
    context = db.completed_scan_context(connection, scan["id"], coverage)
    if prepare_only:
        context["acceptedFindings"] = accepted
    return context


def validate_sealed_budget_draft(
    db: Any, scan: sqlite3.Row, scan_dir: Path, manifest: dict[str, Any]
) -> None:
    # The seal can reach disk before parent completion commits. Validate
    # it without changing bytes; the existing finalizer commits replay.
    try:
        _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            completion_binding=db.workbench_completion_binding(scan, scan["started_at"], manifest),
        )
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc


def scan_results_recovery_needed(db: Any, connection: Any, scan: Any) -> bool:
    if scan["status"] != "failed" or scan["canceled_at"] is not None:
        return False
    warnings = json.loads(scan["completion_warnings_json"])
    if any(
        isinstance(warning, str) and warning.startswith(_PUBLICATION_FOLLOW_UP_WARNING)
        for warning in warnings
    ):
        return True
    publication_error = connection.execute(
        "SELECT publication_error_message FROM deep_scan_runs WHERE scan_id = ?",
        (scan["id"],),
    ).fetchone()
    if publication_error is not None and publication_error["publication_error_message"]:
        return True
    return _saved_results_changed(db, connection, scan)


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
    locations = finding.get("locations", [])
    if not isinstance(locations, list):
        locations = []
    return _digest(
        [
            finding.get("ruleId"),
            identity,
            sorted(
                (
                    (
                        location.get("path"),
                        location.get("startLine"),
                        location.get("endLine", location.get("startLine")),
                    )
                    for location in locations
                    if isinstance(location, dict)
                ),
                key=_encoded,
            ),
        ]
    )


def _worker_candidate_key(
    worker_id: str, candidate_id: str, finding: dict[str, Any]
) -> tuple[str, str, Any, Any, Any]:
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
    return worker_id, candidate_id, finding.get("ruleId"), anchor, instance


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


def _ensure_finding_identities(findings: list[dict[str, Any]]) -> None:
    def key(finding: dict[str, Any]) -> bytes:
        identity = finding["identity"]
        return _encoded(
            [finding.get("ruleId"), identity.get("anchor"), identity.get("instance", "")]
        )

    # Reserve authored identities even when they follow a generated sibling.
    reserved = {
        key(finding)
        for finding in findings
        if isinstance(finding, dict) and isinstance(finding.get("identity"), dict)
    }
    for finding in findings:
        if not isinstance(finding, dict) or "identity" in finding:
            continue
        _ensure_finding_identity(finding)
        suffix = 2
        while key(finding) in reserved:
            finding["identity"]["instance"] = f"saved-{suffix}"
            suffix += 1
        reserved.add(key(finding))


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
        Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
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


@contextmanager
def preserve_parent_head_on_error(scan_dir: Path) -> Iterator[None]:
    """Keep rejected completion attempts from becoming accepted parent observations."""
    head_path = scan_dir / "checkpoint-head.json"
    previous = None
    try:
        head_path.lstat()
    except FileNotFoundError:
        pass
    else:
        descriptor = open_scan_local_file_descriptor(
            scan_dir, "checkpoint-head.json", "Saved parent checkpoint head"
        )
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            previous = (handle.read(), metadata)
    directories = ("checkpoints", "checkpoint-heads")
    previous_files = {
        relative for directory in directories for relative in _checkpoint_paths(scan_dir, directory)
    }
    try:
        yield
    except BaseException:
        if previous is None:
            _remove_scan_local_file_if_exists(scan_dir, "checkpoint-head.json")
        else:
            payload, metadata = previous
            write_scan_local_bytes(scan_dir, "checkpoint-head.json", payload)
            os.utime(head_path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        current_files = {
            relative
            for directory in directories
            for relative in _checkpoint_paths(scan_dir, directory)
        }
        for relative in current_files - previous_files:
            _remove_scan_local_file_if_exists(scan_dir, relative)
        raise


def merge_saved_results(
    scan_dir: Path,
    scan_id: str,
    binding: dict[str, Any],
    workers: list[Any],
    warnings: list[str],
    *,
    stopped: bool,
    reason: str,
    frozen_source_digests: dict[str, str] | None = None,
    checkpoint_heads: dict[str, str] | None = None,
    allow_frozen_legacy_parent: bool = False,
    accepted_source_digests: dict[str, str] | None = None,
    frozen_model_source: str | None = None,
    selected_model_source: list[str] | None = None,
    project_worker_coverage: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Read only bound parent/worker files; return an unsealed loss-preserving union."""
    initial_warnings = set(warnings)
    try:
        source_times = _frozen_source_times(scan_dir, scan_id, frozen_source_digests or {})
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
    if checkpoint_heads is None:
        checkpoint_heads = _worker_checkpoint_heads(
            scan_dir, workers, scan_id, accepted_source_digests
        )
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
        if parent_manifest is not None and parent is not None:
            parent_scan = parent_manifest["scan"]
            try:
                previous_head, _, head_modified = _read_saved_result(
                    scan_dir, "checkpoint-head.json", scan_id
                )
            except (ContractError, OSError, ValueError):
                head_modified = None
            if head_modified is not None:
                # A partial tool publication must not outrank its accepted head.
                parent_modified = min(
                    (scan_dir / name).lstat().st_mtime_ns
                    for name in ("findings.json", "coverage.json", "scan-manifest.json")
                )
            if not parent_scan.get("sealedAt") or allow_frozen_legacy_parent:
                head_path = scan_dir / "checkpoint-head.json"
                tied_observations = False
                if head_modified == parent_modified:
                    previous_parent, _, _ = _read_saved_result(
                        scan_dir, f"checkpoints/{previous_head['checkpoint']}", scan_id
                    )
                    if previous_parent != parent:
                        # Tied observations cannot decide which pending work came last.
                        parent = _merge_tied_parent_observations(parent, previous_parent)
                        parent_is_canonical = False
                        tied_observations = True
                payload = _encoded(parent)
                parent_digest = hashlib.sha256(payload).hexdigest()
                parent_checkpoint = f"checkpoints/{parent_digest}.json"
                checkpoint_path = scan_dir / parent_checkpoint
                if not checkpoint_path.exists():
                    write_scan_local_bytes(scan_dir, parent_checkpoint, payload)
                    # A recovery copy must not appear newer than the review it copies.
                    os.utime(checkpoint_path, ns=(parent_modified, parent_modified))
                if head_modified is None or head_modified < parent_modified or tied_observations:
                    write_scan_local_bytes(
                        scan_dir,
                        "checkpoint-head.json",
                        _encoded({"checkpoint": checkpoint_path.name}),
                    )
                    os.utime(head_path, ns=(parent_modified, parent_modified))
                if frozen_source_digests is not None:
                    captured = _capture_saved_source(scan_dir, "checkpoint-head.json", scan_id)
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
    accepted_reducer = latest_reducer

    def checkpoints(directory: str, worker_id: str | None, attempt: int = 0) -> None:
        if worker_id is not None:
            root = Path(directory).parent.as_posix()
            worker_attempts[root] = (worker_id, attempt)
            paths[f"{root}/checkpoint-head.json"] = worker_id
        head_snapshots = (Path(directory).parent / "checkpoint-heads").as_posix()
        for saved_directory in (directory, head_snapshots):
            paths.update(dict.fromkeys(_checkpoint_paths(scan_dir, saved_directory), worker_id))

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
                captured = _capture_saved_source(scan_dir, relative, scan_id)
                paths.update({path: worker_id for path in captured})
            except (ContractError, OSError, ValueError) as exc:
                if (scan_dir / relative).exists():
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

    for relative, worker_id in paths.items():
        try:
            draft, digest, observed = _read_saved_result(
                scan_dir,
                relative,
                scan_id,
                kind="dedup" if relative in reducer_paths else None,
                accepted_source_digests=accepted_source_digests,
            )
            if frozen_source_digests is not None and frozen_source_digests[relative] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            source_digests[relative] = digest
            source_times.setdefault(relative, observed)
            source_order[relative] = (0, source_times[relative])
            if _checkpoint_head_directory(relative) is not None:
                saved_heads[relative] = draft["checkpoint"]
                continue
            # The host supplies reducer coverage separately from model output.
            # Preserve the digest of the original accepted document.
            if relative in reducer_paths:
                draft = {
                    **draft,
                    "coverage": draft.get("sourceCoverage", draft.get("coverage", {})),
                }
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
    if "sourceCoverage" not in drafts_by_path.get(accepted_reducer, {}):
        accepted_reducer = None
    accepted_coverage = drafts_by_path.get(accepted_reducer, {}).get("coverage", {})
    reviewed_attempts = {
        (review.get("workerId"), review.get("attempt"))
        for review in accepted_coverage.get("reviews", [])
        if isinstance(review, dict)
    }
    reviewed_workers = {
        worker["id"]
        for worker in workers
        if {"status", "merge_state", "attempt"}.issubset(worker.keys())
        and worker["status"] == "succeeded"
        and worker["merge_state"] == "merged"
        and (worker["id"], worker["attempt"]) in reviewed_attempts
    }
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
    if parent is None and latest_reducer is not None:
        parent = drafts_by_path[latest_reducer]

    project_worker_coverage, surface_links = _prepare_worker_coverage_recovery(
        sources,
        parent,
        source_order,
        enabled=project_worker_coverage,
        preserve_workers=reviewed_workers,
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

    if parent is None and not sources:
        return None
    if (
        parent_manifest
        and parent_manifest["scan"].get("sealedAt")
        and parent_manifest["scan"].get("status") == binding["status"]
        and parent_manifest["scan"].get("preservedSources") == source_digests
        and parent_manifest["scan"].get("preservedCheckpointHeads", {}) == checkpoint_heads
        and all(warning in initial_warnings for warning in warnings)
    ):
        return None

    if (
        frozen_source_digests is None
        or any(_is_source_order_snapshot(path) for path in source_digests)
        or allow_frozen_legacy_parent
    ):
        _freeze_source_times(scan_dir, scan_id, source_digests, source_times)

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
    manifest["scan"]["preservedCheckpointHeads"] = checkpoint_heads
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
    if frozen_model_source is not None:
        # Publication retries retain the choice made with the frozen source set.
        model = drafts_by_path.get(frozen_model_source, {}).get("threatModel")
        if not isinstance(model, dict):
            raise ContractError("Frozen stopped-scan model source is unavailable.")
        manifest["scan"]["threatModel"] = copy.deepcopy(model)
        if paths[frozen_model_source] is not None:
            manifest["scan"]["threatModel"]["origin"] = "recovered"
        if selected_model_source is not None:
            selected_model_source[:] = [frozen_model_source]
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
    canonical_rows = (
        {
            id(item)
            for field in ("surfaces", "explicitExclusions", "deferred")
            for item in (coverage.get(field) if isinstance(coverage.get(field), list) else [])
        }
        if parent_is_canonical
        else set()
    )
    findings: list[dict[str, Any]] = []
    finding_positions: dict[str, int] = {}
    represented: dict[str, str | None] = {}
    represented_candidates: dict[tuple[str, str, Any, Any, Any], str | None] = {}
    represented_history: dict[str, set[str]] = {}
    represented_candidate_history: dict[tuple[str, str, Any, Any, Any], set[str]] = {}
    rejected_history: dict[tuple[str, str], list[dict[str, Any]]] = {}
    stopped_parent_seal = bool(
        stopped and parent_manifest and parent_manifest["scan"].get("sealedAt")
    )

    def valid_finding(value: Any) -> bool:
        # Use the finalizer's own per-record recovery before a draft can suppress
        # an earlier checkpoint. Invalid latest records must not hide valid history.
        document = {"scanId": scan_id, "findings": [copy.deepcopy(value)]}
        if isinstance(document["findings"][0], dict):
            _ensure_finding_identity(document["findings"][0], candidate_only=True)
        _recover_unsealed_findings(
            {"scan": {"id": scan_id, "target": binding["target"]}},
            document,
            Path(__file__).resolve().parent.parent / "schemas",
            scan_dir,
            [],
        )
        return bool(document["findings"])

    all_sources = ([("parent", parent, None)] if parent else []) + sources

    def coverage_candidate(
        owner: str | None, item: dict[str, Any], identity: Any = None
    ) -> tuple[str | None, Any]:
        provenance = item.get("provenance")
        if owner is None and isinstance(provenance, dict):
            return provenance.get("workerId"), provenance.get(
                "candidateId", identity if identity is not None else item.get("candidateId")
            )
        return owner, identity if identity is not None else item.get("candidateId")

    source_order["parent"] = (0, parent_modified)
    deferred_rows = {
        relative: _deferred_rows(draft["coverage"]) for relative, draft, _ in all_sources
    }
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
        source
        for source in sources
        if source[0] in current_results | selected_observations.keys()
        or source[0] == accepted_reducer
    ]
    # Generic closures belong to one logical scan or worker, just like candidates.
    # Keep them when recovering a terminal checkpoint without its canonical write.
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}

    candidate_ids: set[tuple[str | None, str]] = set()
    accepted_deferred_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}
    coverage_schema = _read_json(
        Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
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
                    and item.get("disposition") in {"rejected", "not_applicable"}
                ):
                    candidate_owner, candidate_id = coverage_candidate(owner, item)
                    outcomes.append((relative, candidate_owner, candidate_id, item["disposition"]))
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
                canonical_key = _finding_key(finding)
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
        ):
            order = source_order[relative]
            selected_terminal_orders[worker_id] = max(
                selected_terminal_orders.get(worker_id, order), order
            )
    terminal_worker_orders: dict[str | None, tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if relative in current_results and draft.get("complete") is not False:
            order = source_order[relative]
            terminal_worker_orders[worker_id] = max(
                terminal_worker_orders.get(worker_id, order), order
            )

    def source_coverage_selection(
        relative: str,
        worker_id: str | None,
    ) -> tuple[bool, set[str], bool, bool]:
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
        # A failed result write can leave pending work outside the accepted result.
        accepted_order = (
            (0, parent_modified)
            if worker_id is None and parent is not None
            else worker_result_order
        )
        retain_pending = (
            superseded
            and (worker_id in headed_workers or (worker_id is None and parent_heads))
            and accepted_order is not None
            and source_order[relative] >= accepted_order
            and any(isinstance(row, dict) for row in deferred_rows[relative])
        )
        return selected_coverage_superseded, selected_candidates, superseded, retain_pending

    def coverage_row_is_retained(
        field: str,
        item: Any,
        worker_id: str | None,
        selection: tuple[bool, set[str], bool, bool],
        relative: str,
    ) -> bool:
        selected_coverage_superseded, selected_candidates, superseded, retain_pending = selection
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
        if (
            superseded
            and relative != accepted_reducer
            and not (
                isinstance(item, dict)
                and (
                    (field == "deferred" and retain_pending)
                    or (
                        isinstance(item.get("candidateId"), str)
                        and item["candidateId"] in selected_candidates
                        and item.get("disposition")
                        == resolved.get((worker_id, item["candidateId"]))
                    )
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
            and coverage_candidate(worker_id, item, identity) in resolved
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
                    coverage_row_is_retained("deferred", row, owner, selection, relative)
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
                emitted = coverage_row_is_retained("surfaces", row, owner, selection, relative)
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
        receipt_root=scan_dir if project_worker_coverage else None,
        receipt_warnings=warnings,
        fallback_surfaces=fallback_surfaces,
        surface_is_retained=lambda relative, owner, row: coverage_row_is_retained(
            "surfaces", row, owner, source_coverage_selection(relative, owner), relative
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
        if owner in reviewed_workers:
            continue
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
                owner not in reviewed_workers
                and isinstance(surface, dict)
                and isinstance(surface.get("id"), str)
                and (owner, surface["id"]) in ambiguous_surface_ids
                and surface.get("disposition") == "needs_follow_up"
                and not any(key in surface for key in ("candidateId", "candidate", "finding"))
                and isinstance(coverage.get("surfaces"), list)
            ):
                append_coverage_row(
                    coverage["surfaces"],
                    {**surface, "receiptRefs": surface.get("receiptRefs", [])},
                    owner,
                    "surfaces",
                )
    for relative, draft, worker_id in all_sources:
        selection = source_coverage_selection(relative, worker_id)
        selected_coverage_superseded, selected_candidates, superseded, retain_pending = selection
        skip_superseded_findings = (
            superseded
            and not stopped
            and all(valid_finding(finding) for finding in (parent["findings"] if parent else []))
        )
        if skip_superseded_findings and not selected_candidates and not retain_pending:
            continue
        if (
            not skip_superseded_findings
            and "threatModel" not in manifest["scan"]
            and isinstance(draft.get("threatModel"), dict)
        ):
            model = draft["threatModel"]
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
                ]
                if selected_models:
                    head_path = max(selected_models, key=source_order.__getitem__)
                    current = drafts_by_path[head_path]
                    # A terminal checkpoint is committed before result.json is replaced.
                    # Use the admitted observation, including its frozen ordering on retries.
                    if not prefer_worker_head and current.get("complete") is not False:
                        prefer_worker_head = source_order[head_path] >= source_order[relative]
                    if prefer_worker_head:
                        model = current["threatModel"]
                        model_path = head_path
            manifest["scan"]["threatModel"] = copy.deepcopy(model)
            if worker_id is not None:
                manifest["scan"]["threatModel"]["origin"] = "recovered"
            if selected_model_source is not None and worker_id is not None:
                selected_model_source[:] = [model_path]
        for value in draft["findings"]:
            if skip_superseded_findings and not (
                isinstance(value, dict)
                and (candidate_id := finding_candidate_id(value)) in selected_candidates
                and resolved.get((worker_id, candidate_id)) == "reported"
            ):
                continue
            if relative == "parent" and parent_is_canonical:
                finding = copy.deepcopy(value)
                _ensure_finding_identity(finding, candidate_only=True)
                provenance = finding.get("provenance") if isinstance(finding, dict) else None
                owner = provenance.get("workerId") if isinstance(provenance, dict) else None
                candidate_id = finding_candidate_id(finding) if isinstance(finding, dict) else None
                if (
                    stopped_parent_seal
                    and isinstance(owner, str)
                    and candidate_id
                    and resolved.get((owner, candidate_id)) in {"rejected", "not_applicable"}
                ):
                    rejected_history.setdefault((owner, candidate_id), []).append(finding)
                    continue
                if valid_finding(finding):
                    finding_positions.setdefault(_finding_key(finding), len(findings))
                findings.append(finding)
                continue
            if relative != "parent" and parent and value in parent["findings"]:
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
                surfaces = coverage.get("surfaces")
                for item in surfaces if isinstance(surfaces, list) else []:
                    if isinstance(item, dict) and item.get("candidateId") == candidate_id:
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
            locations = finding.get("locations", [])
            if not isinstance(locations, list) or not any(
                isinstance(location, dict)
                and isinstance(location.get("path"), str)
                and any(
                    path_within_scope(location["path"], path)
                    for path in binding["scope"]["includePaths"]
                )
                for location in locations
            ):
                warnings.append(f"Skipped out-of-scope finding from {relative}.")
                continue
            provenance = finding.setdefault("provenance", {"source": "local_plugin"})
            if not isinstance(provenance, dict):
                findings.append(finding)
                continue
            if worker_id:
                provenance.setdefault("workerId", worker_id)
            _ensure_finding_identity(finding)
            if not valid_finding(finding):
                findings.append(finding)
                continue
            key = _finding_key(finding)
            represented_by_parent = False
            if relative != "parent":
                if key in represented:
                    mapped_key = represented[key]
                    historical_contents = represented_history.get(key, set())
                elif worker_id and candidate_id:
                    candidate_key = _worker_candidate_key(worker_id, candidate_id, finding)
                    if candidate_key not in represented_candidates:
                        represented_candidates[candidate_key] = key
                    mapped_key = represented_candidates[candidate_key]
                    historical_contents = represented_candidate_history.get(candidate_key, set())
                else:
                    mapped_key = None
                    historical_contents = set()
                if mapped_key is not None:
                    key = mapped_key
                    represented_by_parent = _digest(_finding_content(value)) in historical_contents
            if key in finding_positions:
                retained = findings[finding_positions[key]]
                if finding != retained:
                    if not represented_by_parent and _finding_strength(finding) > _finding_strength(
                        retained
                    ):
                        previous = copy.deepcopy(retained)
                        previous_history = previous["provenance"].pop("previousFindings", [])
                        retained = finding
                        findings[finding_positions[key]] = retained
                    else:
                        previous = copy.deepcopy(value)
                        previous_history = previous.get("provenance", {}).pop(
                            "previousFindings", []
                        )
                    retained_provenance = retained["provenance"]
                    retained_history = retained_provenance.get("previousFindings")
                    history = (
                        [item for item in retained_history if isinstance(item, dict)]
                        if isinstance(retained_history, list)
                        else []
                    )
                    retained_provenance["previousFindings"] = history
                    for original in [
                        *(previous_history if isinstance(previous_history, list) else []),
                        previous,
                    ]:
                        if not isinstance(original, dict):
                            continue
                        source_key = _finding_key(original)
                        source_content = _finding_content(original)
                        already_retained = any(
                            source_key == _finding_key(historical)
                            and source_content == _finding_content(historical)
                            for historical in _retained_findings(retained)
                        )
                        if (
                            not already_retained
                            and original not in history
                            and original != retained
                        ):
                            history.append(original)
                continue
            finding_positions[key] = len(findings)
            findings.append(finding)
        if worker_id in reviewed_workers or (
            superseded
            and relative != accepted_reducer
            and not selected_candidates
            and not retain_pending
        ):
            continue
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions", "reviews"):
            if (
                superseded
                and relative != accepted_reducer
                and field not in {"surfaces", "explicitExclusions", "deferred"}
            ):
                continue
            if field == "reviews" and field not in draft["coverage"]:
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
                source_item = item
                if not coverage_row_is_retained(field, item, worker_id, selection, relative):
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
                    and item.get("disposition") in {"rejected", "not_applicable"}
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
                        continue
                retained = append_coverage_row(output, item, worker_id, field)
                if field == "surfaces" and id(source_item) in linked_surface_sources:
                    linked_surface_outputs[id(source_item)] = retained

    _merge_reviewed_surface_receipts(
        coverage, worker_row_owners, reviewed_workers, reviewed_attempts
    )

    identities: dict[str, str] = {}
    for finding in findings:
        if not valid_finding(finding):
            continue
        identity = finding.get("identity")
        if not isinstance(identity, dict):
            continue
        key = _encoded([finding.get("ruleId"), identity]).decode()
        variant = _finding_key(finding)
        if key in identities and identities[key] != variant:
            finding.setdefault("provenance", {})["preservedIdentity"] = copy.deepcopy(identity)
            identity["instance"] = f"{identity.get('instance', 'saved')}-{variant[:16]}"
        identities[key] = variant
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
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            if id(item) in canonical_rows:
                if isinstance(item.get("id"), str):
                    used.add(item["id"])
                continue
            item.setdefault("id", _saved_coverage_id(item))
            if not isinstance(item["id"], str):
                # Preserve malformed rows for per-record recovery, including frozen replay.
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
            used.add(item["id"])
            if field == "surfaces":
                item.setdefault("receiptRefs", [])
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


def budget_exhausted_draft(
    db: Any,
    scan: sqlite3.Row,
    scan_dir: Path,
    candidates: list[dict[str, Any]],
    warning: str,
    contract: dict[str, Any],
    *,
    before_selection: bool = False,
    accepted_result: dict[str, Any] | None = None,
    unmerged_workers: list[sqlite3.Row] = (),
    draft_documents: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    documents = dict(zip(names, copy.deepcopy(draft_documents))) if draft_documents else {}
    if draft_documents is None:
        for name in names:
            path = db.artifact_path(scan_dir, name, required=False)
            if path is not None:
                documents[name] = db.read_json_object(path)
    interrupted_documents = {}
    if documents and len(documents) != 3:
        if not before_selection or set(documents) not in (
            {"findings.json"},
            {"findings.json", "coverage.json"},
        ):
            raise SystemExit("Budget-exhausted scan contains an incomplete canonical scan draft.")
        interrupted_documents = documents
        documents = {}

    if documents:
        manifest = documents["scan-manifest.json"]
        findings = documents["findings.json"]
        coverage = documents["coverage.json"]
        if not isinstance(manifest.get("scan"), dict) or not isinstance(
            findings.get("findings"), list
        ):
            raise SystemExit("Budget-exhausted scan contains an invalid canonical scan draft.")
        for key in ("surfaces", "explicitExclusions", "deferred"):
            if not isinstance(coverage.get(key), list):
                raise SystemExit("Budget-exhausted scan contains invalid canonical coverage.")
        if manifest["scan"].get("sealedAt") is not None or manifest["scan"].get("artifacts"):
            if before_selection:
                raise SystemExit(
                    "Budget-exhausted scan cannot replace an already sealed scan draft."
                )
            # Completion verifies sealed bytes directly from disk.
            return manifest, findings, coverage
    else:
        target_contract = contract["target"]
        target: dict[str, Any] = {
            "kind": target_contract["allowedKinds"][0],
            "targetId": target_contract["targetId"],
            "displayName": target_contract["displayName"],
        }
        if scan["target_revision"] != "unversioned":
            target["revision"] = scan["target_revision"]
        if "requiredSnapshotDigest" in target_contract:
            target["snapshotDigest"] = target_contract["requiredSnapshotDigest"]
        manifest = {
            "scan": {
                "target": target,
                "scope": {"limitations": [warning]},
            }
        }
        findings = {"findings": []}
        coverage = {
            "inventoryStrategy": (
                "scoped_path" if db.expected_coverage_mode(scan) == "scoped_path" else "repository"
            ),
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        }

    if before_selection:
        # Unmerged discoveries remain in their accepted artifacts. Only the
        # committed reducer may contribute findings to this partial result.
        findings = {
            "findings": copy.deepcopy(accepted_result["findings"]) if accepted_result else []
        }
        _ensure_finding_identities(findings["findings"])
        if accepted_result is not None:
            coverage = accepted_result["sourceCoverage"]
            if "threatModel" in accepted_result:
                manifest["scan"]["threatModel"] = accepted_result["threatModel"]
            if "scope" in accepted_result:
                manifest["scan"]["scope"].update(copy.deepcopy(accepted_result["scope"]))
        limitations = manifest["scan"]["scope"].setdefault("limitations", [])
        if warning not in limitations:
            limitations.append(warning)

    for worker in unmerged_workers:
        retain_unmerged_budget_coverage(scan, scan_dir, coverage, worker)

    findings_by_candidate = {
        candidate_id
        for finding in findings["findings"]
        if isinstance(finding, dict)
        and isinstance(candidate_id := finding_candidate_id(finding), str)
    }
    existing_deferred = {
        item.get("candidateId", item.get("id"))
        for item in coverage["deferred"]
        if isinstance(item, dict) and isinstance(item.get("candidateId", item.get("id")), str)
    }
    existing_surfaces = {
        item.get("id")
        for item in coverage["surfaces"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        if candidate_id in findings_by_candidate or candidate_id in existing_deferred:
            continue
        paths = list(dict.fromkeys(location["path"] for location in candidate["locations"]))
        surface_id = f"candidate-{candidate_id}"
        validation = candidate.get("validation")
        validation = validation.get("disposition") if isinstance(validation, dict) else None
        attack = candidate.get("attack_path")
        attack = attack.get("decision") if isinstance(attack, dict) else None
        disposition = (
            "needs_follow_up"
            if validation == "deferred" or attack == "deferred"
            else "not_applicable"
            if validation == "not_applicable"
            else "rejected"
            if validation == "suppressed" or attack == "ignore"
            else "needs_follow_up"
        )
        if surface_id not in existing_surfaces:
            coverage["surfaces"].append(
                {
                    "id": surface_id,
                    "label": candidate["summary"],
                    "disposition": disposition,
                    "notes": candidate["evidence"],
                    "receiptRefs": [],
                }
            )
            existing_surfaces.add(surface_id)
        if disposition != "needs_follow_up":
            continue
        coverage["deferred"].append(
            {
                "id": candidate_id,
                "candidateId": candidate_id,
                "reason": (
                    "Validation was deferred because the scan reached its cost limit: "
                    f"{candidate['summary']}. Evidence: {candidate['evidence']}"
                ),
                "paths": paths,
                "surfaceIds": [surface_id],
            }
        )
    if not any(
        isinstance(item, dict)
        and isinstance(reason := item.get("reason"), str)
        and (
            reason == "Validation was deferred because the scan reached its cost limit."
            or reason.startswith(
                "Validation was deferred because the scan reached its cost limit: "
            )
        )
        for item in coverage["deferred"]
    ):
        coverage["deferred"].append(
            {
                "id": "scan-cost-limit",
                "reason": "Validation was deferred because the scan reached its cost limit.",
            }
        )
    coverage.pop("completeness", None)
    outputs = (
        ("findings.json", findings),
        ("coverage.json", coverage),
        ("scan-manifest.json", manifest),
    )
    # Process death can leave a prefix of these derived writes before SQLite
    # commits. Recover only bytes whose documents match the accepted inputs.
    if any(
        interrupted_documents[name] != payload
        for name, payload in outputs
        if name in interrupted_documents
    ):
        raise SystemExit("Budget-exhausted scan contains an incomplete canonical scan draft.")
    for name, payload in outputs:
        try:
            write_scan_local_bytes(
                scan_dir,
                name,
                (json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n").encode(),
            )
        except (ContractError, OSError, TypeError, ValueError) as exc:
            raise SystemExit(f"Budget-exhausted scan draft could not be saved: {exc}") from exc
    return manifest, findings, coverage


def retain_unmerged_budget_coverage(
    scan: sqlite3.Row, scan_dir: Path, coverage: dict[str, Any], worker: sqlite3.Row
) -> None:
    """Keep each unmerged review's obligations; its findings remain evidence only."""
    relative = Path(worker["accepted_result_path"]).relative_to(scan_dir).as_posix()
    draft, _, _ = _read_saved_result(
        scan_dir,
        relative,
        scan["id"],
        accepted_source_digests={worker["accepted_result_path"]: worker["accepted_result_sha256"]},
    )
    retain_unmerged_review_coverage(scan_dir, coverage, worker, draft)


def coverage_for_comparison(db: Any, scan: Any) -> dict[str, Any]:
    if scan["seal_manifest_digest"] is None:
        raise SystemExit("Only sealed scans can be compared.")
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    try:
        prepared = _prepare_scan_finalization(scan_dir)
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    if not prepared.was_sealed or prepared.manifest["scan"]["id"] != scan["id"]:
        raise SystemExit("Only sealed scans can be compared.")
    return prepared.coverage


def _snapshot_published_outputs(scan_dir: Path) -> dict[str, tuple[bytes, os.stat_result] | None]:
    snapshots: dict[str, tuple[bytes, os.stat_result] | None] = {}
    for relative in _PUBLISHED_OUTPUTS:
        descriptor = -1
        try:
            descriptor = open_scan_local_file_descriptor(
                scan_dir, relative, "Published scan output"
            )
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                metadata = os.fstat(handle.fileno())
                snapshots[relative] = (handle.read(), metadata)
        except ContractError:
            path = scan_dir / relative
            if path.exists() or path.is_symlink():
                if relative == "threatmodel.md":
                    # This optional projection will not replace an unsafe destination.
                    continue
                raise
            snapshots[relative] = None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return snapshots


def _restore_published_outputs(
    scan_dir: Path, snapshots: dict[str, tuple[bytes, os.stat_result] | None]
) -> None:
    for relative, snapshot in snapshots.items():
        if snapshot is None:
            path = scan_dir / relative
            if path.exists() or path.is_symlink():
                _remove_scan_local_file_if_exists(scan_dir, relative)
        else:
            contents, metadata = snapshot
            write_scan_local_bytes(scan_dir, relative, contents)
            # Saved-result selection uses mtime; rollback must preserve its ordering.
            os.utime(scan_dir / relative, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))


@contextmanager
def preserve_deep_deadline_draft(db: Any, connection: Any, scan: Any) -> Iterator[None]:
    """Recover a settled, zero-accepted Deep deadline without sealing the parent."""
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    snapshots = _snapshot_published_outputs(scan_dir)
    warnings = json.loads(scan["completion_warnings_json"])
    binding = db.workbench_completion_binding(scan, db.now())
    with preserve_parent_head_on_error(scan_dir):
        try:
            documents = merge_saved_results(
                scan_dir,
                scan["id"],
                binding,
                connection.execute(
                    "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
                    (scan["id"],),
                ).fetchall(),
                warnings,
                stopped=True,
                reason=(
                    "The configured discovery time limit elapsed before any source review completed. "
                    "Saved findings and pending review were preserved without a completed reduction."
                ),
                project_worker_coverage=True,
            )
            if documents is None:
                raise ContractError("Deep Scan deadline has no saved parent draft.")
            documents[0]["scan"].pop("complete", None)
            # Validate recovered evidence against the current finding contract,
            # scope, source lineage, and receipts before admitting this draft.
            prepared = _prepare_scan_finalization(
                scan_dir,
                expected_coverage_mode=db.expected_coverage_mode(scan),
                completion_binding=binding,
                recover_unsealed=True,
                draft_documents=documents,
            )
            warnings.extend(prepared.warnings)
            manifest, findings, coverage = prepared.manifest, prepared.findings, prepared.coverage
            manifest["scan"].pop("sealedAt", None)
            manifest["scan"].pop("artifacts", None)
            checkpoint = _parent_scan_draft(scan["id"], manifest["scan"], findings, coverage)
            contents = _encoded(checkpoint)
            name = f"{hashlib.sha256(contents).hexdigest()}.json"
            write_scan_local_bytes(scan_dir, f"checkpoints/{name}", contents)
            write_scan_local_bytes(scan_dir, "checkpoint-head.json", _encoded({"checkpoint": name}))
            for filename, document in (
                ("findings.json", findings),
                ("coverage.json", coverage),
                ("scan-manifest.json", manifest),
            ):
                write_scan_local_bytes(scan_dir, filename, _encoded(document))
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                (json.dumps(list(dict.fromkeys(warnings))), scan["id"]),
            )
            yield
        except BaseException:
            _restore_published_outputs(scan_dir, snapshots)
            raise


def preserve_scan_results_locked(
    db: Any,
    connection: Any,
    scan_id: str,
    *,
    recovery_source_digests: dict[str, str] | None = None,
    recovery_checkpoint_heads: dict[str, str] | None = None,
    include_parent_with_recovery: bool = False,
) -> bool:
    """Publish or verify retained terminal results through the workbench host."""
    scan = db.require_scan(connection, scan_id)
    if scan["status"] != "failed":
        return False
    frozen_source_digests: dict[str, str] | None = None
    checkpoint_heads = recovery_checkpoint_heads
    model_source: list[str] = []
    saved_model_source: str | None = None
    raw_frozen_sources = scan["retained_source_digests_json"]
    if raw_frozen_sources is not None:
        frozen_source_digests, saved_model_source = _retained_source_state(
            json.loads(raw_frozen_sources)
        )
        if saved_model_source is not None:
            model_source.append(saved_model_source)
    if recovery_source_digests is not None:
        frozen_source_digests = recovery_source_digests
    elif raw_frozen_sources is not None:
        raw_checkpoint_heads = scan["retained_checkpoint_heads_json"]
        checkpoint_heads = (
            json.loads(raw_checkpoint_heads) if raw_checkpoint_heads is not None else {}
        )
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    deep_run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if deep_run is not None:
        db.deep_scan.require_supported_deep_scan(deep_run)
    outcome = (
        "canceled"
        if scan["canceled_at"]
        else "interrupted"
        if deep_run and deep_run["status"] == "interrupted"
        else "failed"
    )
    stored_warnings = json.loads(scan["completion_warnings_json"])
    publication_follow_up_warnings = [
        warning
        for warning in stored_warnings
        if isinstance(warning, str) and warning.startswith(_PUBLICATION_FOLLOW_UP_WARNING)
    ]
    warnings = [
        warning for warning in stored_warnings if warning not in publication_follow_up_warnings
    ]

    def record_publication(manifest: dict[str, Any], findings: dict[str, Any]) -> None:
        retained_sources = _source_digests(
            manifest.get("scan", {}).get("preservedSources"),
            "Stopped scan source digests could not be frozen.",
        )
        digest = db.published_manifest_digest(scan_dir, manifest)
        timestamp = db.now()
        with connection:
            for kind, filename in db.ARTIFACTS.items():
                path = db.artifact_path(scan_dir, filename, required=True)
                connection.execute(
                    "INSERT OR REPLACE INTO scan_artifacts "
                    "(scan_id, kind, path, created_at) VALUES (?, ?, ?, ?)",
                    (scan_id, kind, str(path), scan["completed_at"]),
                )
            # Delete only vanished occurrences; stable IDs retain triage and remediation.
            existing_ids = {
                row["id"]
                for row in connection.execute(
                    "SELECT id FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
                )
            }
            retained_ids = {finding["occurrenceId"] for finding in findings["findings"]}
            connection.executemany(
                "DELETE FROM finding_occurrences WHERE id = ? AND scan_id = ?",
                ((occurrence_id, scan_id) for occurrence_id in existing_ids - retained_ids),
            )
            db.index_findings(connection, scan_id, findings, scan["completed_at"])
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = ?, retained_source_digests_json = ?, "
                "retained_checkpoint_heads_json = ?, "
                "completion_warnings_json = ?, "
                "updated_at = ? WHERE id = ? AND status = 'failed'",
                (
                    digest,
                    _encode_retained_sources(retained_sources, model_source),
                    json.dumps(
                        manifest["scan"].get("preservedCheckpointHeads", {}), sort_keys=True
                    ),
                    json.dumps(list(dict.fromkeys(warnings))),
                    timestamp,
                    scan_id,
                ),
            )
            connection.execute(
                "UPDATE scan_progress SET reportable_findings_count = ?, updated_at = ? "
                "WHERE scan_id = ?",
                (len(findings["findings"]), timestamp, scan_id),
            )

    existing_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
    existing_scan = db.read_json_object(existing_path).get("scan", {}) if existing_path else {}
    existing = None
    if scan["seal_manifest_digest"] is not None or (
        isinstance(existing_scan, dict)
        and (
            existing_scan.get("sealedAt") is not None or existing_scan.get("artifacts") is not None
        )
    ):
        db.require_recorded_manifest_digest(scan, scan_dir)
        existing, existing_findings, _ = finalize_scan(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            projection_warnings=warnings,
        )
        db.verify_manifest_binding(scan, existing)
        if existing_scan.get("status") == outcome:
            existing_sources = existing_scan.get("preservedSources")
            existing_heads = existing_scan.get("preservedCheckpointHeads", {})
            if frozen_source_digests is None:
                frozen_source_digests = _source_digests(
                    existing_sources, "Stopped scan source digests could not be frozen."
                )
                checkpoint_heads = existing_heads
            if existing_sources == frozen_source_digests and existing_heads == checkpoint_heads:
                if (
                    raw_frozen_sources is not None
                    and scan["seal_manifest_digest"] is not None
                    and not publication_follow_up_warnings
                    and warnings == stored_warnings
                ):
                    return True
                record_publication(existing, existing_findings)
                return True
            if recovery_source_digests is None:
                raise ContractError("Stopped scan sources changed after terminal publication.")
    binding = {
        **db.workbench_completion_binding(scan, scan["completed_at"], existing),
        "status": outcome,
    }
    if recovery_source_digests is not None:
        model_source.clear()
    documents = merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        _saved_workers(connection, scan_id),
        warnings,
        stopped=True,
        reason=(
            f"Scan {outcome}; saved findings and pending review were preserved. "
            f"{scan['failure_message'] or ''}"
        ).strip(),
        frozen_source_digests=frozen_source_digests,
        checkpoint_heads=checkpoint_heads,
        accepted_source_digests=_accepted_source_digests(connection, scan_id),
        frozen_model_source=model_source[0] if model_source else None,
        selected_model_source=model_source,
        project_worker_coverage=scan["mode"] == "deep",
        allow_frozen_legacy_parent=(
            include_parent_with_recovery
            or (
                recovery_source_digests is None
                and frozen_source_digests == {}
                and isinstance(existing_scan, dict)
                and existing_scan.get("sealedAt") is not None
                and "preservedSources" not in existing_scan
            )
        ),
    )
    if documents is None:
        unpublished_warnings = list(dict.fromkeys([*warnings, *publication_follow_up_warnings]))
        if unpublished_warnings != stored_warnings:
            with connection:
                connection.execute(
                    "UPDATE scans SET completion_warnings_json = ?, updated_at = ? "
                    "WHERE id = ? AND status = 'failed'",
                    (json.dumps(unpublished_warnings), db.now(), scan_id),
                )
        return False
    if frozen_source_digests is None or (
        recovery_source_digests is None and saved_model_source is None and model_source
    ):
        retained_sources = _source_digests(
            documents[0].get("scan", {}).get("preservedSources"),
            "Stopped scan source digests could not be frozen.",
        )
        with connection:
            connection.execute(
                "UPDATE scans SET retained_source_digests_json = ?, retained_checkpoint_heads_json = ? "
                "WHERE id = ? AND retained_source_digests_json IS ?",
                (
                    _encode_retained_sources(retained_sources, model_source),
                    json.dumps(
                        documents[0]["scan"].get("preservedCheckpointHeads", {}), sort_keys=True
                    ),
                    scan_id,
                    raw_frozen_sources,
                ),
            )
    prepared = _prepare_scan_finalization(
        scan_dir,
        expected_coverage_mode=db.expected_coverage_mode(scan),
        completion_binding=binding,
        recover_unsealed=True,
        draft_documents=documents,
        finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
    )
    warnings.extend(prepared.warnings)
    snapshots = _snapshot_published_outputs(scan_dir)
    try:
        manifest, findings, _ = _write_prepared_scan_finalization(
            prepared, projection_warnings=warnings
        )
        db.verify_manifest_binding(scan, manifest)
        record_publication(manifest, findings)
    except BaseException:
        _restore_published_outputs(scan_dir, snapshots)
        raise
    return True


def recover_scan_results(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    with db.scan_completion_lock(scan_id):
        scan = db.require_scan(connection, scan_id)
        if scan["status"] != "failed":
            raise SystemExit("Only a stopped scan can recover terminal results.")
        if scan["canceled_at"] is not None:
            raise SystemExit("Canceled scans cannot recover terminal results.")
        recovery_source_digests, include_parent, checkpoint_heads = _recovery_source_digests(
            db, connection, scan
        )
        if not preserve_scan_results_locked(
            db,
            connection,
            scan_id,
            recovery_source_digests=recovery_source_digests,
            recovery_checkpoint_heads=checkpoint_heads,
            include_parent_with_recovery=include_parent,
        ):
            raise SystemExit("No saved stopped-scan results were available to recover.")
        db.deep_scan.clear_deep_scan_publication_failure(connection, scan_id)
    return db.scan_context(connection, scan_id)


def preserve_scan_results(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    with db.scan_completion_lock(scan_id):
        scan = db.require_scan(connection, scan_id)
        if scan["status"] != "failed":
            raise SystemExit("Only a stopped scan can preserve terminal results.")
        workspace = db.require_workspace(connection, scan["workspace_id"])
        owner = (
            scan["continuation_thread_id"]
            or scan["deep_scan_owner_thread_id"]
            or workspace["thread_id"]
        )
        if args.thread_id is not None and args.thread_id != owner:
            raise SystemExit("Saved results can only be published from the owning Codex thread.")
        if args.coordinator_generation is not None:
            if args.thread_id is None:
                raise SystemExit("A coordinator result refresh requires its owning thread.")
            db.deep_scan.require_current_coordinator(
                db.deep_scan.require_deep_scan_run(connection, scan_id), args
            )
        else:
            db.handoff.require_current_continuation(
                scan,
                args.claim_token,
                error_message="Saved results are owned by another continuation.",
            )
        published = preserve_scan_results_locked(db, connection, scan_id)
        if not published and scan["canceled_at"] is not None:
            raise SystemExit("Saved scan results could not be published or verified.")
        if published:
            db.deep_scan.clear_deep_scan_publication_failure(connection, scan_id)
    return db.scan_context(connection, scan_id)


def read_or_save_artifact(args: Any) -> dict[str, Any]:
    """Read or publish supplemental bytes through verified filesystem handles."""
    root = Path(args.artifact_root)
    if args.command == "read-artifact":
        descriptor = open_scan_local_file_descriptor(root, args.artifact_path, "Saved artifact")
        with os.fdopen(descriptor, "rb") as source:
            return {"content": base64.b64encode(source.read()).decode("ascii")}
    write_scan_local_bytes(root, args.artifact_path, sys.stdin.buffer.read())
    return {"path": str(root / args.artifact_path)}


def save_scan_artifact(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    """Publish supplemental bytes under the same lock as finalization and recovery."""
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    with db.scan_completion_lock(scan_id):
        scan = db.require_scan(connection, scan_id)
        db.handoff.require_current_continuation(
            scan,
            args.claim_token,
            error_message="Scan artifacts are owned by another continuation.",
        )
        if scan["status"] != "running" or scan["seal_manifest_digest"] is not None:
            raise SystemExit("The scan stopped; its artifacts cannot be modified.")
        scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
        manifest_path = db.artifact_path(scan_dir, "scan-manifest.json", required=False)
        if manifest_path is not None:
            manifest = db.read_json_object(manifest_path).get("scan", {})
            if manifest.get("sealedAt") is not None or manifest.get("artifacts") is not None:
                raise SystemExit("The scan is sealed; its artifacts cannot be modified.")
        output = args.artifact_path
        key = output.lower()
        if not (
            key.startswith(("artifacts/", "findings/", "hardening/"))
            or key == "report_validation.md"
        ) or any(
            key == reserved or key.startswith(reserved + "/")
            for reserved in _RESERVED_ARTIFACT_PATHS
        ):
            raise SystemExit("Use the typed scan tools for canonical artifacts and checkpoints.")
        write_scan_local_bytes(scan_dir, output, sys.stdin.buffer.read())
    return {"scanId": scan_id, "path": str(scan_dir / output)}


def _read_staged_scan_draft(scan_dir: Path, draft_path: str) -> dict[str, Any]:
    try:
        relative = Path(draft_path).relative_to(scan_dir).as_posix()
    except ValueError as exc:
        raise SystemExit("Scan draft must be inside the registered scan drafts directory.") from exc
    if not re.fullmatch(r"drafts/[0-9a-fA-F-]+\.json", relative):
        raise SystemExit("Scan draft must be inside the registered scan drafts directory.")
    return _read_scan_local_json(scan_dir, relative, "Staged scan draft")


def _selected_publication_digest(prepared: Any, legacy_completeness: str | None = None) -> str:
    # Completion time is chosen at sealing, after publication. Everything else
    # must remain the host projection of the same accepted aggregate.
    manifest = copy.deepcopy(prepared[2])
    for field in ("completedAt", "sealedAt"):
        manifest["scan"].pop(field, None)
    coverage = prepared.coverage
    if legacy_completeness is not None:
        # Reconstruct the historical projection and its coverage artifact binding.
        coverage = {**coverage, "completeness": legacy_completeness}
        coverage_digest = hashlib.sha256(
            _contract_json_bytes("coverage.json", coverage)
        ).hexdigest()
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == manifest["scan"]["coverageRef"]:
                artifact["sha256"] = coverage_digest
    return _digest([manifest, prepared.findings, coverage])


def _require_selected_result(scan: Any, selection: dict[str, Any]) -> None:
    relative = selection["resultPath"]
    if relative is not None:
        _read_saved_result(
            Path(scan["scan_dir"]),
            relative,
            scan["id"],
            kind="dedup",
            accepted_source_digests={
                str(Path(scan["scan_dir"]) / relative): selection["resultSha256"]
            },
        )


def record_selected_publication(
    db: Any, connection: Any, scan: Any, prepared: PreparedScanFinalization
) -> None:
    run = db.deep_scan.require_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run)
    if selection is None:
        return
    _require_selected_result(scan, selection)
    selection["publicationSha256"] = _selected_publication_digest(prepared)
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan["id"]),
        )


def require_selected_publication(db: Any, connection: Any, scan: Any, prepared: Any) -> None:
    if scan["mode"] != "deep":
        return
    run = db.deep_scan.require_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run)
    if selection is None or "publicationSha256" not in selection:
        return
    try:
        _require_selected_result(scan, selection)
    except ContractError as exc:
        raise RecoverableContractError(str(exc)) from exc
    digest = selection.get("publicationSha256")
    if digest == _selected_publication_digest(prepared):
        return
    # Old receipts still bind every field, including on normalized seal replay.
    if "completeness" not in prepared.coverage and any(
        digest == _selected_publication_digest(prepared, completeness)
        for completeness in ("complete", "partial", "unknown")
    ):
        return
    raise RecoverableContractError(
        "The selected Deep Scan publication changed or is missing; "
        "republish its accepted result before completing the scan."
    )


def _require_current_deep_publication(
    db: Any, connection: Any, scan: Any, draft: dict[str, Any]
) -> bool:
    scan_id = scan["id"]
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    publication = draft.get("deepScanPublication")
    selection = db.deep_scan.deep_scan_finalization_input(run) if run is not None else None
    if (
        selection is None
        and publication is None
        and draft["manifest"]["scan"].get("complete") is False
        and (run is None or run["status"] == "running")
    ):
        return False
    if run is None:
        run = db.deep_scan.require_deep_scan_run(connection, scan_id)
    # Finished discovery-only runs hand remaining publication back to the parent.
    if (
        selection is None
        and publication is None
        and run["status"] != "running"
        and run["manifest_path"] != str(Path(scan["scan_dir"]) / "scan-manifest.json")
    ):
        return False
    db.deep_scan.require_current_coordinator(
        run,
        argparse.Namespace(
            coordinator_generation=publication.get("coordinatorGeneration") if publication else None
        ),
    )
    accepted_findings = False
    if selection is not None:
        if publication is None:
            raise SystemExit("Deep Scan publication requires its committed selection.")
        scan = db.require_scan(connection, scan_id)
        accepted_findings = has_verified_selected_result(db, connection, scan)
        if "publicationSha256" in selection:
            prepared = _prepare_scan_finalization(
                Path(scan["scan_dir"]),
                expected_coverage_mode=db.expected_coverage_mode(scan),
                completion_binding=db.workbench_completion_binding(scan, db.now()),
                draft_documents=(draft["manifest"], draft["findings"], draft["coverage"]),
                accepted_findings=accepted_findings,
            )
            require_selected_publication(db, connection, scan, prepared)
        selected_result = (
            str(Path(scan["scan_dir"]) / selection["resultPath"])
            if selection["resultPath"] is not None
            else None
        )
    else:
        # Generation-one runs predate host publication metadata. Keep their existing
        # draft path; adopted coordinators must carry their generation and selection.
        if publication is None:
            if run["status"] != "running" and run["manifest_path"] == str(
                Path(scan["scan_dir"]) / "scan-manifest.json"
            ):
                raise SystemExit("Deep Scan is terminal; drafts cannot replace its publication.")
            return False

        reducer = latest_publication_reducer(db, connection, scan_id)
        selected_result = reducer["result_manifest_path"] if reducer is not None else None
    if publication["resultPath"] != selected_result:
        raise SystemExit("Deep Scan aggregate belongs to a superseded publication selection.")
    if selection is None:
        accepted_findings = has_verified_selected_result(db, connection, scan, reducer=reducer)
    return accepted_findings


def write_scan_draft(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    with db.scan_completion_lock(scan_id):
        scan = db.require_scan(connection, scan_id)
        db.handoff.require_current_continuation(
            scan, args.claim_token, error_message="Scan draft is owned by another continuation."
        )
        if scan["status"] != "running" or scan["seal_manifest_digest"] is not None:
            raise SystemExit(
                "The scan stopped; its saved checkpoint was retained without replacing sealed results."
            )
        scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
        if (
            args.expected_draft_digest is not None
            and args.expected_draft_digest != _scan_draft_digest(scan_dir)
        ):
            raise SystemExit(
                "scan_draft_conflict: canonical scan results changed; reconcile the saved checkpoint again."
            )
        draft = _read_staged_scan_draft(scan_dir, args.draft_path)
        manifest, findings, coverage = draft["manifest"], draft["findings"], draft["coverage"]
        binding = db.workbench_completion_binding(scan, db.now())
        # Save scan IDs without sealing the draft.
        _populate_unsealed_manifest_envelope(manifest, manifest["scan"], binding)
        _populate_unsealed_artifact_envelope(manifest, findings, coverage, binding)
        _validate_completion_binding(manifest, findings, coverage, binding)
        checkpoint = manifest["scan"]
        checkpoint_contents = None
        if args.checkpoint_path is not None:
            try:
                checkpoint_relative = Path(args.checkpoint_path).relative_to(scan_dir).as_posix()
            except ValueError as exc:
                raise SystemExit(
                    "Scan checkpoint must be inside the registered scan drafts directory."
                ) from exc
            if not re.fullmatch(r"drafts/[0-9a-fA-F-]+\.checkpoint\.json", checkpoint_relative):
                raise SystemExit(
                    "Scan checkpoint must be inside the registered scan drafts directory."
                )
            checkpoint, checkpoint_contents = _read_scan_local_json_bytes(
                scan_dir, checkpoint_relative, "Staged scan checkpoint"
            )
            if checkpoint.get("scanId") != scan_id:
                raise SystemExit("Staged scan checkpoint belongs to another scan.")
        checkpoint_only = (
            scan["mode"] == "deep"
            and draft.get("deepScanPublication") is None
            and checkpoint.get("complete") is False
            and connection.execute(
                "SELECT 1 FROM deep_scan_runs WHERE scan_id = ? "
                "AND status = 'running' AND manifest_path = ?",
                (scan_id, str(scan_dir / "scan-manifest.json")),
            ).fetchone()
            is not None
        )
        run = None
        accepted_findings = False
        if scan["mode"] == "deep" and not checkpoint_only:
            accepted_findings = _require_current_deep_publication(db, connection, scan, draft)
            run = db.deep_scan.find_supported_deep_scan_run(connection, scan_id)
        if checkpoint_contents is not None:
            checkpoint_digest = hashlib.sha256(checkpoint_contents).hexdigest()
            write_scan_local_bytes(
                scan_dir,
                f"checkpoints/{checkpoint_digest}.json",
                checkpoint_contents,
            )
            if checkpoint_only:
                return {"scanId": scan_id, "status": "draft_written"}
        checkpoint = _parent_scan_draft(scan_id, manifest["scan"], findings, coverage)
        checkpoint_contents = _encoded(checkpoint)
        checkpoint_name = f"{hashlib.sha256(checkpoint_contents).hexdigest()}.json"
        checkpoint_relative = f"checkpoints/{checkpoint_name}"
        if not (scan_dir / checkpoint_relative).exists():
            write_scan_local_bytes(scan_dir, checkpoint_relative, checkpoint_contents)
        if checkpoint_only:
            return {"scanId": scan_id, "status": "draft_written"}
        write_scan_local_bytes(
            scan_dir, "checkpoint-head.json", _encoded({"checkpoint": checkpoint_name})
        )
        for filename, document in (
            ("findings.json", findings),
            ("coverage.json", coverage),
            ("scan-manifest.json", manifest),
        ):
            write_scan_local_bytes(
                scan_dir,
                filename,
                (json.dumps(document, allow_nan=False, indent=2) + "\n").encode(),
            )
        if scan["mode"] == "deep" and manifest["scan"].get("complete") is not False:
            # Select the accepted final publication before releasing the write lock.
            with connection:
                connection.execute(
                    "UPDATE deep_scan_runs SET manifest_path = ? "
                    "WHERE scan_id = ? AND status = 'running'",
                    (str(scan_dir / "scan-manifest.json"), scan_id),
                )
        model_warning = write_threat_model_projection_if_possible(scan_dir, manifest)
        if run is not None and db.deep_scan.deep_scan_finalization_input(run) is not None:
            prepared = _prepare_scan_finalization(
                scan_dir,
                expected_coverage_mode=db.expected_coverage_mode(scan),
                completion_binding=binding,
                draft_documents=(manifest, findings, coverage),
                accepted_findings=accepted_findings,
            )
            record_selected_publication(db, connection, scan, prepared)
        # Accepted Standard drafts are evidence of review or report assembly,
        # even when the parent omitted its explicit progress call.
        model_only_checkpoint = (
            manifest["scan"].get("complete") is False
            and isinstance(manifest["scan"].get("threatModel"), dict)
            and not findings.get("findings")
            and not coverage.get("surfaces")
            and not coverage.get("deferred")
        )
        if scan["mode"] == "standard" and not model_only_checkpoint:
            phase = "discovery" if manifest["scan"].get("complete") is False else "reporting"
            earlier = PHASES[: PHASES.index(phase)]
            placeholders = ",".join("?" for _ in earlier)
            timestamp = db.now()
            try:
                with connection:
                    changed = connection.execute(
                        "UPDATE scans SET phase = ?, updated_at = ? "
                        f"WHERE id = ? AND status = 'running' AND phase IN ({placeholders})",
                        (phase, timestamp, scan_id, *earlier),
                    )
                    if changed.rowcount:
                        connection.execute(
                            "UPDATE scan_progress SET phase_items_total = 0, "
                            "phase_items_completed = 0, phase_progress_unit = NULL, updated_at = ? "
                            "WHERE scan_id = ?",
                            (timestamp, scan_id),
                        )
            except sqlite3.Error as exc:
                print(f"Could not save scan progress: {exc}", file=sys.stderr)
    return {
        "scanId": scan_id,
        "status": "draft_written",
        **({"warnings": [model_warning]} if model_warning else {}),
    }


def _scan_draft_digest(scan_dir: Path) -> str:
    digest = hashlib.sha256()
    for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
        digest.update(filename.encode())
        digest.update(b"\0")
        try:
            (scan_dir / filename).lstat()
        except FileNotFoundError:
            digest.update(b"missing\0")
            continue
        digest.update(b"present\0")
        descriptor = open_scan_local_file_descriptor(scan_dir, filename, filename)
        with os.fdopen(descriptor, "rb") as handle:
            digest.update(handle.read())
        digest.update(b"\0")
    return digest.hexdigest()


def fail_scan(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    with db.scan_completion_lock(db.require_uuid(args.scan_id, "scan-id")):
        return fail_scan_locked(db, connection, args)


def fail_scan_locked(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    cost_json = db.parse_scan_cost(args.cost_json)
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = db.now()
        scan = db.require_scan(connection, scan_id)
        if scan["status"] == "failed":
            connection.commit()
            return db.scan_context(connection, scan["id"])
        if scan["status"] == "complete":
            raise SystemExit("A completed scan cannot be marked failed.")
        db.handoff.require_current_continuation(
            scan,
            args.claim_token,
            error_message="Scan failure is owned by another continuation.",
        )
        message = db.optional_text(args.message, maximum=2400)
        updated = connection.execute(
            """
            UPDATE scans
            SET status = 'failed', failure_message = ?, completed_at = ?, updated_at = ?,
                cost_json = ?
            WHERE id = ? AND status = 'running'
            """,
            (message, timestamp, timestamp, cost_json, scan["id"]),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can be marked failed.")
        db.deep_scan.fail_from_parent_scan(connection, scan["id"], message, timestamp)
        progress_updated = connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan["id"]),
        )
        if progress_updated.rowcount != 1:
            raise SystemExit("Codex Security scan progress not found.")
    preserve_stopped_results_after_transition(db, connection, scan["id"])
    return db.scan_context(connection, scan["id"])


def cancel_scan(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    with db.scan_completion_lock(db.require_uuid(args.scan_id, "scan-id")):
        return cancel_scan_locked(db, connection, args)


def cancel_scan_locked(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    thread_id = db.optional_text(args.thread_id, maximum=512)
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = db.now()
        scan = db.require_scan(connection, scan_id)
        workspace = db.require_workspace(connection, scan["workspace_id"])
        owning_thread_id = scan["continuation_thread_id"] or workspace["thread_id"]
        if thread_id is not None and owning_thread_id != thread_id:
            raise SystemExit("A scan can only be canceled from its owning Codex thread.")
        if scan["canceled_at"] is not None:
            connection.commit()
            return db.workspace_state(connection, scan["workspace_id"])
        if scan["status"] != "running":
            raise SystemExit("Only a running scan can be canceled.")
        updated = connection.execute(
            """
            UPDATE scans
            SET status = 'failed', canceled_at = ?, completed_at = ?, updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (timestamp, timestamp, timestamp, scan["id"]),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can be canceled.")
        db.deep_scan.cancel_from_parent_scan(connection, scan["id"], timestamp)
        progress_updated = connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan["id"]),
        )
        if progress_updated.rowcount != 1:
            raise SystemExit("Codex Security scan progress not found.")
    preserve_stopped_results_after_transition(db, connection, scan["id"])
    return db.workspace_state(connection, scan["workspace_id"])


def preserve_stopped_results_after_transition(db: Any, connection: Any, scan_id: str) -> None:
    try:
        published = preserve_scan_results_locked(db, connection, scan_id)
    except (ContractError, OSError, SystemExit, ValueError) as exc:
        scan = db.require_scan(connection, scan_id)
        warnings = json.loads(scan["completion_warnings_json"])
        warning = f"Saved scan evidence remains on disk; result publication needs follow-up: {exc}"
        with connection:
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                (json.dumps(list(dict.fromkeys([*warnings, warning]))), scan_id),
            )
        return
    if published:
        db.deep_scan.clear_deep_scan_publication_failure(connection, scan_id)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
