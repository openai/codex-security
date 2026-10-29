"""Retain semantic scan drafts without rerunning analysis or changing run state."""

from __future__ import annotations

import copy
import hashlib
import os
from collections import Counter, deque
from functools import partial
from pathlib import Path, PurePosixPath
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _finding_strength,
    _read_json,
    _recover_unsealed_findings,
    _require_safe_json_value,
    _validate_schema_node,
    finding_candidate_id,
    write_scan_local_bytes,
)
from review_state import uses_legacy_review
from workbench.retained_records import (
    _append_previous_finding,
    _competing_rejection_receipts,
    _conflicting_outcome_receipts,
    _ensure_finding_identities,
    _ensure_finding_identity,
    _finding_content,
    _finding_identity,
    _finding_key,
    _identity_candidate,
    _recover_preserved_worker_coverage,
    _recover_preserved_worker_source,
    _retained_findings,
    _saved_candidate_outcomes,
    _semantic_identity_key,
    _worker_candidate_key,
    contains_raw_value,
    distinct_reports,
    identifiers,
    raw_owner,
    raw_scope,
    same_raw_content,
    same_raw_finding,
    same_raw_value,
)
from workbench.saved_coverage import (
    _coverage_rows,
    _has_candidate_metadata,
    _inherit_coverage_sources,
    _merge_tied_parent_observations,
    _parent_observation_content,
    _project_worker_closure,
    _projected_worker_closure_sources,
    _resolved_deferred_rows,
    prepare_saved_coverage_projection,
)
from workbench.saved_sources import (
    _capture_parent_observation,
    _capture_saved_source,
    _checkpoint_head_directory,
    _checkpoint_paths,
    _CheckpointSnapshotError,
    _digest,
    _encoded,
    _freeze_source_times,
    _frozen_checkpoint_heads,
    _frozen_source_times,
    _is_source_order_snapshot,
    _latest_iteration,
    _model_capture,
    _parent_publication_ancestors,
    _read_saved_parent_result,
    _read_saved_result,
    _unselected_root_order,
    _worker_outputs,
)
from workbench_coverage_receipts import (
    _deferred_candidate_id,
    _generic_surface_updates,
    receipt_checkpoints,
    resolve_coverage_receipts,
    retain_recorded_receipt_ownership,
)
from workbench_target import committed_diff_snapshot_digest
from workbench_validation import javascript_utf8, path_within_scope


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
    checkpoint_heads: dict[str, str | None] | None = None,
    allow_frozen_legacy_parent: bool = False,
    parent_already_captured: bool = False,
    frozen_model_source: str | None = None,
    selected_model_source: list[str] | None = None,
    canonical_model: dict[str, Any] | None = None,
    canonical_model_source: str | None = None,
    canonical_sources: dict[str, str] | None = None,
    finding_scope: list[tuple[str, bool]] | None = None,
    preserve_canonical_parent: bool = False,
    project_worker_coverage: bool = False,
    created_paths: set[str] | None = None,
    current_contract: bool = False,
    recovery_snapshot_error: _CheckpointSnapshotError | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Read only bound parent/worker files; return an unsealed loss-preserving union."""
    initial_warnings = set(warnings)
    if frozen_source_digests is None:
        checkpoint_heads = {}
    snapshot_error = recovery_snapshot_error
    captured_records = dict(snapshot_error.records) if snapshot_error is not None else {}

    def capture_head(relative: str, canonical: Path | None = None) -> dict[str, tuple[str, int]]:
        nonlocal snapshot_error
        try:
            if canonical is not None:
                return _capture_parent_observation(
                    scan_dir,
                    scan_id,
                    canonical.name,
                    max(parent_modified, canonical.lstat().st_mtime_ns),
                    allow_frozen_legacy_parent,
                    created_paths=created_paths,
                )
            return _capture_saved_source(
                scan_dir,
                relative,
                scan_id,
                checkpoint_heads=checkpoint_heads,
                created_paths=created_paths,
            )
        except _CheckpointSnapshotError as exc:
            if "status" not in binding:
                # A running coordinator can continue from its remaining evidence.
                if checkpoint_heads is not None:
                    checkpoint_heads.pop(Path(relative).parent.as_posix(), None)
                raise
            # Finish selection from captured bytes before freezing an I/O failure.
            snapshot_error = snapshot_error or exc
            captured_records.update(exc.records)
            return exc.captured

    parent_context = dict(recovery_snapshot_error.parent_context) if recovery_snapshot_error else {}
    try:
        source_times = _frozen_source_times(
            scan_dir, scan_id, frozen_source_digests or {}, parent_context
        )
        if snapshot_error is not None:
            source_times.update({path: item[1] for path, item in snapshot_error.captured.items()})
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
    parent: dict[str, Any] | None = None
    frozen_parent_path: str | None = None
    parent_manifest: dict[str, Any] | None = None
    parent_is_canonical = False
    parent_modified = 0
    parent_model_source: str | None = None
    canonical_model_order: tuple[int, int] | None = None
    canonical_model_digest: str | None = None
    if frozen_source_digests is None or (
        allow_frozen_legacy_parent and not parent_already_captured
    ):
        try:
            parent_manifest, parent = _read_saved_parent_result(scan_dir, scan_id)
            # Without an accepted head, a file-authored draft is a full replacement.
            parent_file = (
                "coverage.json"
                if uses_legacy_review(parent_manifest["scan"])
                else "scan-manifest.json"
            )
            parent_modified = (scan_dir / parent_file).lstat().st_mtime_ns
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
                    for name in (
                        "findings.json",
                        "scan-manifest.json",
                        *(["coverage.json"] if uses_legacy_review(parent_scan) else []),
                    )
                )
            if not parent_scan.get("sealedAt") or allow_frozen_legacy_parent:
                payload = _encoded(parent)
                parent_digest = hashlib.sha256(payload).hexdigest()
                parent_checkpoint = f"checkpoints/{parent_digest}.json"
                if isinstance(parent.get("threatModel"), dict):
                    canonical_model_source = parent_checkpoint
                    parent_model_source = parent_checkpoint
                    canonical_model_order = (0, parent_modified)
                    canonical_model_digest = parent_digest
                parent_context["canonical"] = parent_checkpoint
                parent_context["canonicalObservedAtNs"] = str(parent_modified)
                checkpoint_path = scan_dir / parent_checkpoint
                if not checkpoint_path.exists():
                    if created_paths is not None and not os.path.lexists(checkpoint_path):
                        created_paths.add(parent_checkpoint)
                    write_scan_local_bytes(scan_dir, parent_checkpoint, payload)
                    # A recovery copy must not appear newer than the review it copies.
                    os.utime(checkpoint_path, ns=(parent_modified, parent_modified))
                captured = capture_head(
                    "checkpoint-head.json", checkpoint_path if head_modified is None else None
                )
                if captured and (head_modified is not None or allow_frozen_legacy_parent):
                    if checkpoint_heads is not None:
                        checkpoint_heads["."] = next(iter(captured))
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
    reducer = _latest_iteration(workers)
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
                captured = capture_head(relative)
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
    pending = deque(paths.items())
    while pending:
        relative, worker_id = pending.popleft()
        try:
            draft, digest, observed = captured_records.get(relative) or _read_saved_result(
                scan_dir, relative, scan_id, kind="dedup" if relative in reducer_paths else None
            )
            if frozen_source_digests is not None and frozen_source_digests[relative] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            source_digests[relative] = digest
            source_times.setdefault(relative, observed)
            source_order[relative] = (0, source_times[relative])
            directory = Path(relative).parent
            if directory.name in {"checkpoints", "checkpoint-heads"}:
                directory = directory.parent
            if _checkpoint_head_directory(relative) is not None:
                saved_heads[relative] = draft["checkpoint"]
                if isinstance(draft.get("inputCheckpoint"), str):
                    saved_inputs[relative] = draft["inputCheckpoint"]
                continue
            if (
                checkpoint_heads is not None
                and checkpoint_heads.get(directory.as_posix(), relative) is None
            ):
                continue
            if preserve_canonical_parent and worker_id is not None:
                discarded = _recover_preserved_worker_source(
                    scan_dir,
                    relative,
                    scan_id,
                    binding,
                    worker_id,
                    next(worker for worker in workers if worker["id"] == worker_id),
                    draft,
                    warnings,
                )
                if discarded:
                    discarded_by_source[relative] = discarded
            # Recovery expects coverage, but reducer results only contain findings
            # and context. Add an empty value after hashing the original result.
            sources.append((relative, {"reviewState": {}, **draft}, worker_id))
            if frozen_source_digests is None:
                pending.extend(
                    receipt_checkpoints(
                        relative, worker_id, paths, partial(_checkpoint_paths, scan_dir)
                    ).items()
                )
        except (ContractError, OSError, ValueError) as exc:
            if (scan_dir / relative).exists():
                warnings.append(f"Preserved unreadable checkpoint {relative}: {exc}")
    if frozen_source_digests is not None:
        if frozen_source_digests.keys() - source_digests.keys():
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.")

    if checkpoint_heads is None:
        checkpoint_heads = _frozen_checkpoint_heads(scan_dir, scan_id, source_digests)
    heads_snapshotted = False
    if frozen_source_digests is not None and snapshot_error is None:
        # Raw heads are a temporary fallback, not permanent publication sources.
        for relative in list(saved_heads):
            if Path(relative).name != "checkpoint-head.json":
                continue
            captured = _capture_saved_source(
                scan_dir,
                relative,
                scan_id,
                expected_digest=source_digests[relative],
                created_paths=created_paths,
            )
            for path, (digest, observed) in captured.items():
                if path in source_digests and source_digests[path] != digest:
                    raise ContractError("checkpoint changed after the scan stopped")
                source_digests[path] = digest
                source_times.setdefault(path, observed)
                if _checkpoint_head_directory(path) is not None:
                    saved_heads[path] = saved_heads[relative]
                    if relative in saved_inputs:
                        saved_inputs[path] = saved_inputs[relative]
                    if parent_context.get("head") == relative:
                        parent_context["head"] = path
                    source_order[path] = (0, observed)
                    key = Path(relative).parent.as_posix()
                    if checkpoint_heads.get(key) == relative:
                        checkpoint_heads[key] = path
            saved_inputs.pop(relative, None)
            del saved_heads[relative], source_digests[relative]
            heads_snapshotted = True
        if heads_snapshotted:
            source_digests = {
                path: digest
                for path, digest in source_digests.items()
                if not _is_source_order_snapshot(path)
            }
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
    authoritative_heads: set[str] = set()
    authoritative_observations: dict[str, tuple[int, int]] = {}
    parent_heads: list[tuple[int, str]] = []
    for head, checkpoint in saved_heads.items():
        directory = _checkpoint_head_directory(head)
        selected = (directory / "checkpoints" / checkpoint).as_posix()
        if selected not in source_order:
            raise ContractError("Checkpoint head is outside the saved source set.")
        key = directory.as_posix()
        if key in checkpoint_heads and checkpoint_heads[key] is None:
            continue
        observed = source_order[head][1]
        attempt = 0 if directory == Path(".") else worker_attempts[key][1]
        order = (attempt, observed)
        if key not in checkpoint_heads or checkpoint_heads[key] in (head, selected):
            authoritative_heads.add(selected)
            if checkpoint_heads.get(key) == head:
                authoritative_observations[selected] = order
            if directory == Path("."):
                parent_heads.append((observed, selected))
        selected_observations[selected] = max(selected_observations.get(selected, order), order)
    # A registered result independently retains its latest accepted observation.
    # Restoring the head does not withdraw that result's publication authority.
    registered_result_orders = {
        path: order for path, order in selected_observations.items() if path in current_results
    }
    # A restored head selects one observation, not the newest time for its payload.
    selected_observations.update(authoritative_observations)
    source_order.update(selected_observations)
    source_order.update(registered_result_orders)

    # Keep frozen source digests over the original data, before discarding markers
    # that never passed through the worker draft writer.
    retain_recorded_receipt_ownership(
        sources, _digest, binding["scope"]["includePaths"], finding_scope
    )
    drafts_by_path = {relative: draft for relative, draft, _ in sources}
    # A frozen model capture supplies context without replacing earlier findings.
    model_path = frozen_model_source or canonical_model_source
    model_draft = drafts_by_path.get(model_path)
    if (
        model_draft is not None
        and model_path not in selected_observations
        and model_path != parent_context.get("canonical")
        and isinstance(model := model_draft.get("threatModel"), dict)
        and model_draft == _model_capture(scan_id, model)
    ):
        model_draft["complete"] = False
    if frozen_source_digests is not None and "canonical" in parent_context:
        canonical = parent_context["canonical"]
        parent = drafts_by_path[canonical]
        parent_model_source = canonical
        parent_modified = int(
            parent_context.get("canonicalObservedAtNs", source_order[canonical][1])
        )
        parent_is_canonical = True
    if "head" in parent_context:
        head = parent_context["head"]
        parent_heads = [(source_order[head][1], f"checkpoints/{saved_heads[head]}")]

    if parent is None and frozen_source_digests is not None and "canonical" not in parent_context:
        # Older host snapshots remain evidence; only the newest is the current parent.
        saved_parents = {
            relative: draft
            for relative, draft, _ in sources
            if relative.startswith("checkpoints/")
            and isinstance(draft.get("previousParentCheckpoints"), list)
        }
        previous_parents = {
            relative
            for draft in saved_parents.values()
            for relative in draft["previousParentCheckpoints"]
            if isinstance(relative, str)
        }
        for relative, draft in saved_parents.items():
            if relative not in previous_parents:
                frozen_parent_path, parent = relative, draft
                parent_model_source = relative
                parent_is_canonical = draft.get("canonicalParent") is True
                break
    projected_coverage = parent["reviewState"] if parent else {}
    # V1 persists the review projection in the parent, without reducer sourceCoverage.

    coverage_receipts = partial(resolve_coverage_receipts, scan_dir)

    def canonical_coverage_record(field: str, item: dict[str, Any]) -> dict[str, Any]:
        refs = item.get("receiptRefs", [])
        if field != "surfaces" or not isinstance(refs, list):
            return item
        origin = projection_origins.get(id(item))
        if origin is not None and (worker := workers_by_id.get(origin[0])) is not None:
            refs = coverage_receipts(item, worker, origin[1])
        result = {
            **item,
            "receiptRefs": [Path(ref).as_posix() if isinstance(ref, str) else ref for ref in refs],
        }
        if isinstance(provenance := result.get("provenance"), dict):
            result["provenance"] = {
                key: value for key, value in provenance.items() if key != "scanReceiptRefs"
            }
        return result

    def retained_coverage_record(field: str, item: dict[str, Any]) -> dict[str, Any] | None:
        return projection.retained_record(coverage, field, item, canonical_coverage_record)

    reconciled_surface_ids: dict[tuple[str | None, str], str] = {}

    def project_missing_record(
        field: str,
        item: dict[str, Any],
        index: int,
        worker: Any,
        source: dict[str, Any],
        *,
        receipts_resolved: bool = False,
    ) -> dict[str, Any]:
        # Retain projectDiscoveryCoverage worker ownership.
        prefix = f"{worker['id']}-attempt-{worker['attempt']}"

        def accepted_positions(surface: dict[str, Any]) -> list[int]:
            return [
                position
                for position, accepted in accepted_surfaces.get((worker["id"], surface["id"]), [])
                if canonical_coverage_record("surfaces", accepted)
                == canonical_coverage_record("surfaces", surface)
            ]

        def surface_id(surface: dict[str, Any], offset: int) -> str:
            source_id = surface.get("id")
            if id(source) not in accepted_coverage_sources and isinstance(source_id, str):
                positions = accepted_positions(surface)
                if len(positions) == 1:
                    offset = positions[0]
                elif not positions:
                    return f"{prefix}-surface-{offset}-{_digest(surface)[:16]}"
            return f"{prefix}-surface-{offset}"

        result = copy.deepcopy(item)
        provenance = result.get("provenance")
        if not isinstance(provenance, dict):
            provenance = {}
        for key in ("workerId", "attempt", "sourceId", "candidateId"):
            provenance.pop(key, None)
        provenance.update(workerId=worker["id"], attempt=worker["attempt"])
        result["provenance"] = provenance
        source_rows = source.get(field, [])
        inferred_id = (
            isinstance(source_rows, list)
            and index <= len(source_rows)
            and id(source_rows[index - 1]) in inferred_coverage_ids
        )
        for key, name in (("id", "sourceId"), ("candidateId", "candidateId")):
            if key == "id" and inferred_id:
                continue
            if key in item:
                result["provenance"][name] = item[key]
        if isinstance(item.get("candidateId"), str):
            candidate_digest = hashlib.sha256(javascript_utf8(item["candidateId"])).hexdigest()
            result["candidateId"] = f"{prefix}-candidate-{candidate_digest}"
        if field == "surfaces":
            original = source_rows[index - 1] if isinstance(source_rows, list) else item
            result["id"] = surface_id(original, index)
            if not receipts_resolved and (origin := projection_origins.get(id(original))):
                result["receiptRefs"] = coverage_receipts(result, worker, origin[1])
            previous = retained_coverage_record("surfaces", result)
            if previous is not None and isinstance(previous.get("id"), str):
                result["id"] = previous["id"]
            else:
                surfaces = coverage.get("surfaces", [])
                if any(
                    isinstance(row, dict) and row.get("id") == result["id"]
                    for row in (surfaces if isinstance(surfaces, list) else [])
                ):
                    result["id"] = f"{result['id']}-{_digest(result)[:16]}"
        elif field == "deferred":
            result["id"] = f"{prefix}-deferred-{index}"
            if isinstance(item.get("surfaceIds"), list):
                surface_ids: dict[str, str] = {}
                surfaces = projected_coverage.get("surfaces", [])
                for surface in surfaces if isinstance(surfaces, list) else []:
                    if not isinstance(surface, dict) or not isinstance(surface.get("id"), str):
                        continue
                    provenance = surface.get("provenance", {})
                    if (
                        isinstance(provenance, dict)
                        and provenance.get("workerId") == worker["id"]
                        and provenance.get("attempt") == worker["attempt"]
                        and isinstance(provenance.get("sourceId"), str)
                    ):
                        surface_ids.setdefault(provenance["sourceId"], surface["id"])
                surfaces = source.get("surfaces", [])
                source_surface_ids: dict[str, tuple[int, dict[str, Any]]] = {}
                for offset, surface in enumerate(surfaces if isinstance(surfaces, list) else [], 1):
                    if isinstance(surface, dict) and isinstance(surface.get("id"), str):
                        source_surface_ids.setdefault(surface["id"], (offset, surface))
                for (owner, source_id), accepted in accepted_surfaces.items():
                    if owner == worker["id"] and accepted:
                        source_surface_ids.setdefault(source_id, accepted[0])
                for source_id, (offset, surface) in source_surface_ids.items():
                    if source_id not in item["surfaceIds"]:
                        continue
                    if (worker["id"], source_id) in reconciled_surface_ids:
                        surface_ids[source_id] = reconciled_surface_ids[(worker["id"], source_id)]
                        continue
                    projected_id = surface_id(surface, offset)
                    if id(source) in accepted_coverage_sources or accepted_positions(surface):
                        origin = projection_origins.get(id(surface))
                        projected = project_missing_record(
                            "surfaces", surface, offset, worker, origin[4] if origin else source
                        )
                        if origin := projection_origins.get(id(surface)):
                            projected["receiptRefs"] = coverage_receipts(
                                projected, worker, origin[1]
                            )
                        projected_id = projected["id"]
                        previous = retained_coverage_record("surfaces", projected)
                        if previous is not None and isinstance(previous.get("id"), str):
                            projected_id = previous["id"]
                    surface_ids[source_id] = projected_id
                result["surfaceIds"] = [
                    surface_ids.get(value, value) if isinstance(value, str) else value
                    for value in item["surfaceIds"]
                ]
        return result

    workers_by_id = {worker["id"]: worker for worker in workers}
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
                # Only a replacement head can replay without the canonical draft.
                if parent_context.get("canonical") not in source_digests:
                    parent_context.pop("canonical", None)
                    parent_context.pop("canonicalObservedAtNs", None)
                parent = draft
                parent_model_source = parent_path
                frozen_parent_path = (
                    parent_path
                    if isinstance(draft.get("previousParentCheckpoints"), list)
                    else None
                )
                parent_modified = modified
                parent_is_canonical = draft.get("canonicalParent") is True
            elif modified == parent_modified and _parent_observation_content(
                draft
            ) != _parent_observation_content(parent):
                parent = _merge_tied_parent_observations(parent, draft)
                parent_is_canonical = False
    # A reducer supplies findings but cannot supersede saved parent coverage.
    saved_parent = parent
    parent_is_root = parent is not None
    if parent is None and latest_reducer is not None:
        parent = drafts_by_path[latest_reducer]
        parent_model_source = latest_reducer

    projected_coverage = saved_parent["reviewState"] if saved_parent else {}
    reviews = projected_coverage.get("reviews")
    reviewed_attempts = {
        (review.get("workerId"), review.get("attempt"))
        for review in (reviews if isinstance(reviews, list) else [])
        if isinstance(review, dict)
        and isinstance(review.get("workerId"), str)
        and isinstance(review.get("attempt"), int)
    }
    # Reconcile raw source IDs and timestamps before projecting accepted outputs.
    accepted_sources = {
        relative
        for relative, draft, worker_id in sources
        if (worker := workers_by_id.get(worker_id)) is not None
        and worker["status"] == "succeeded"
        and worker["result_manifest_path"] == str(scan_dir / relative)
        and draft.get("complete") is not False
    }
    reviewed_attempts.update(
        (worker_id, workers_by_id[worker_id]["attempt"])
        for relative, _, worker_id in sources
        if relative in accepted_sources
    )
    projection = prepare_saved_coverage_projection(
        sources,
        parent,
        source_order,
        project_worker_coverage=project_worker_coverage,
        preserve_canonical_parent=preserve_canonical_parent,
        receipt_resolver=lambda relative, row, owner: resolve_coverage_receipts(
            scan_dir, row, workers_by_id[owner], relative
        ),
    )
    project_worker_coverage = projection.project_worker_coverage

    def retain_coverage_row(output, item, owner, field, original=None, qualified=False):
        retained = projection.retain_coverage_row(output, item, owner, field, original, qualified)
        source = item if original is None else original
        _inherit_coverage_sources(retained, [item, source], coverage_sources)
        if preserve_canonical_parent and (
            id(item) in canonical_rows or id(source) in canonical_rows
        ):
            canonical_rows.add(id(retained))
        if field == "surfaces":
            retained_surface_rows.add(id(source))
        return retained

    accepted_coverage_sources = {
        id(draft["reviewState"]) for relative, draft, _ in sources if relative in accepted_sources
    }
    accepted_surfaces: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    for relative, draft, worker_id in sources:
        if relative not in accepted_sources:
            continue
        surfaces = draft["reviewState"].get("surfaces", [])
        for index, surface in enumerate(surfaces if isinstance(surfaces, list) else [], 1):
            if isinstance(surface, dict) and isinstance(surface.get("id"), str):
                accepted_surfaces.setdefault((worker_id, surface["id"]), []).append(
                    (index, surface)
                )

    for _, draft, _ in sources:
        questions = draft["reviewState"].get("openQuestions")
        if isinstance(questions, list):
            draft["reviewState"]["openQuestions"] = [
                {"question": item.strip()} if isinstance(item, str) else item for item in questions
            ]
    projection_origins = {
        id(item): (worker_id, relative, field, index, draft["reviewState"])
        for relative, draft, worker_id in sources
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions")
        for index, item in enumerate(
            draft["reviewState"].get(field, [])
            if isinstance(draft["reviewState"].get(field, []), list)
            else [],
            1,
        )
        if isinstance(item, dict)
    }

    def project_record(
        field: str,
        item: dict[str, Any],
        source_item: dict[str, Any] | None = None,
        *,
        receipts_resolved: bool = False,
    ) -> dict[str, Any]:
        original = item if source_item is None else source_item
        origin = projection_origins.get(id(original))
        if origin is None:
            return item
        worker_id, relative, _, index, source = origin
        if relative not in accepted_sources:
            directory = Path(relative).parent
            if directory.name == "checkpoints":
                directory = directory.parent
            worker = workers_by_id.get(worker_id)
            if worker is None or worker_attempts.get(directory.as_posix(), (None, None)) != (
                worker_id,
                worker["attempt"],
            ):
                return item
            # Reproduced outputs and links from omitted checkpoints use the
            # accepted worker's surface namespace.
            accepted = next(
                (
                    (path, draft["reviewState"])
                    for path, draft, owner in sources
                    if owner == worker_id and path in accepted_sources
                ),
                None,
            )
            if accepted is not None and source == accepted[1]:
                relative, source = accepted
            elif relative not in selected_observations or accepted is None:
                if field == "deferred" and accepted is not None and "surfaceIds" in item:
                    return {
                        **item,
                        "surfaceIds": project_missing_record(
                            field, item, index, worker, accepted[1]
                        )["surfaceIds"],
                    }
                return item
        worker = workers_by_id[worker_id]
        result = project_missing_record(
            field, item, index, worker, source, receipts_resolved=receipts_resolved
        )
        if field == "surfaces" and not receipts_resolved:
            result["receiptRefs"] = coverage_receipts(result, worker, relative)
        return result

    all_sources = ([("parent", parent, None)] if parent else []) + sources
    source_owners = {relative: owner for relative, _, owner in all_sources}
    inferred_coverage_ids: set[int] = set()
    # Older checkpoints can omit IDs already assigned in their published output.
    for field in ("deferred", "surfaces"):
        named_rows: dict[str | None, list[dict[str, Any]]] = {}
        for _, draft, owner in all_sources:
            named_rows.setdefault(owner, []).extend(
                row
                for row in _coverage_rows(draft["reviewState"], field)
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            )
        for _, draft, owner in all_sources:
            rows = _coverage_rows(draft["reviewState"], field)
            reserved = {
                row["id"]
                for row in rows
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            }
            for row in rows:
                if not isinstance(row, dict) or "id" in row:
                    continue
                if field == "deferred" and _has_candidate_metadata(row):
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
                    inferred_coverage_ids.add(id(row))
                    row["id"] = identity
                    reserved.add(identity)

    # A discarded local surface must not fall back to another source's reused ID.
    surface_ids_by_source: dict[tuple[str, str], list[str]] = {
        (relative, row["id"]): []
        for relative, draft, _ in all_sources
        for row in (
            draft["reviewState"].get("surfaces", [])
            if isinstance(draft["reviewState"].get("surfaces"), list)
            else []
        )
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    discarded_coverage_sources: set[str] = set()
    if preserve_canonical_parent:
        for relative, draft, worker_id in sources:
            if worker_id is None:
                continue
            if _recover_preserved_worker_coverage(
                scan_dir,
                relative,
                worker_id,
                draft,
                discarded_by_source.get(relative, []),
                warnings,
            ):
                discarded_coverage_sources.add(relative)

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
    if allow_frozen_legacy_parent:
        manifest["scan"]["target"] = target
    for key in ("sealedAt", "artifacts", "coverageRef"):
        manifest["scan"].pop(key, None)
    manifest["scan"]["preservedSources"] = source_digests
    manifest["scan"]["preservedCheckpointHeads"] = checkpoint_heads
    # Completion follows the selected parent, including legacy terminal drafts
    # that omit the optional marker, rather than an older canonical manifest.
    if parent is not None:
        manifest["scan"].pop("complete", None)
        if "complete" in parent:
            manifest["scan"]["complete"] = parent["complete"]
        if isinstance(parent.get("scope"), dict):
            manifest["scan"]["scope"] = copy.deepcopy(parent["scope"])
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

    parent_model = (
        recovered_model(parent_model_source or "parent", parent, None)
        if parent is not None and "threatModel" in parent
        else None
    )
    canonical_model = manifest["scan"].pop("threatModel", canonical_model)
    if parent_model is not None:
        manifest["scan"]["threatModel"] = parent_model
        if (
            selected_model_source is not None
            and parent_model_source in drafts_by_path
            and (
                parent_model_source != canonical_model_source
                or canonical_model_digest is None
                or source_digests[parent_model_source] == canonical_model_digest
            )
        ):
            selected_model_source[:] = [parent_model_source]
    elif frozen_model_source is None:
        # Model fallback is independent of whether older findings are superseded.
        if canonical_model is not None:
            canonical_model = recovered_model("canonical", {"threatModel": canonical_model}, None)
        if (
            canonical_model_source is not None
            and Path(canonical_model_source).parent != Path("checkpoints")
        ) or (
            canonical_model_source is None
            and isinstance(canonical_model, dict)
            and canonical_model.get("origin") == "recovered"
        ):
            # Worker models follow their own selected head and independent result.
            canonical_model = None
            canonical_model_source = None
        if (
            canonical_model_source in drafts_by_path
            and recovered_model(
                canonical_model_source, drafts_by_path[canonical_model_source], None
            )
            is not None
            and (
                canonical_model_digest is None
                or source_digests[canonical_model_source] == canonical_model_digest
            )
        ):
            canonical_model = drafts_by_path[canonical_model_source].get("threatModel")
            canonical_model_order = max(
                canonical_model_order or source_order[canonical_model_source],
                source_order[canonical_model_source],
            )
        else:
            # A skipped checkpoint cannot supply provenance for valid canonical data.
            canonical_model_source = None
        root_models = [
            path
            for path in drafts_by_path
            if path in selected_observations
            and Path(path).parent == Path("checkpoints")
            and isinstance(drafts_by_path[path].get("threatModel"), dict)
            and recovered_model(path, drafts_by_path[path], None) is not None
        ]
        selected_root_models = [path for path in root_models if path in authoritative_heads]
        if isinstance(canonical_model, dict) and canonical_model_order is None:
            # Legacy publications have no model-source identity. Only newly admitted
            # observations can supersede that fallback without an explicit selection.
            new_models = {
                f"checkpoints/{checkpoint}"
                for head, checkpoint in saved_heads.items()
                if _checkpoint_head_directory(head) == Path(".")
                and head not in (canonical_sources or {})
            }
            root_models = [path for path in root_models if path in new_models]
        model_source = max(
            selected_root_models or root_models,
            key=lambda path: source_order[path],
            default=None,
        )
        if model_source is not None and (
            selected_root_models
            or not isinstance(canonical_model, dict)
            or canonical_model_order is None
            or source_order[model_source] > canonical_model_order
        ):
            manifest["scan"]["threatModel"] = copy.deepcopy(
                drafts_by_path[model_source]["threatModel"]
            )
            if selected_model_source is not None:
                selected_model_source[:] = [model_source]
        elif isinstance(canonical_model, dict):
            manifest["scan"]["threatModel"] = copy.deepcopy(canonical_model)
            if stopped and frozen_source_digests is None and canonical_model_source is None:
                # An unreadable canonical checkpoint must not leave a valid
                # inherited model dependent on live files after the first stop.
                model_draft = _model_capture(scan_id, canonical_model)
                digest = _digest(model_draft)
                canonical_model_source = f"checkpoints/{digest}.json"
                observed = (canonical_model_order or (0, parent_modified))[1]
                source_digests[canonical_model_source] = digest
                source_times[canonical_model_source] = observed
                try:
                    if not (scan_dir / canonical_model_source).exists():
                        if created_paths is not None and not os.path.lexists(
                            scan_dir / canonical_model_source
                        ):
                            created_paths.add(canonical_model_source)
                        write_scan_local_bytes(
                            scan_dir, canonical_model_source, _encoded(model_draft)
                        )
                        os.utime(scan_dir / canonical_model_source, ns=(observed, observed))
                    _, actual, _ = _read_saved_result(scan_dir, canonical_model_source, scan_id)
                    if actual != digest:
                        raise ContractError("Saved inherited model checkpoint changed.")
                except (ContractError, OSError) as exc:
                    snapshot_error = snapshot_error or exc
            if selected_model_source is not None and canonical_model_source is not None:
                selected_model_source[:] = [canonical_model_source]

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
        copy.deepcopy(parent["reviewState"])
        if parent and parent["reviewState"]
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
                (coverage, parent["reviewState"]) if preserve_canonical_parent else (coverage,)
            )
            for field in ("surfaces", "explicitExclusions", "deferred")
            for item in _coverage_rows(parent_coverage, field)
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
            rows = draft["reviewState"].get(field)
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    paths_for_row = coverage_sources.setdefault(id(row), (row, []))[1]
                    if relative not in paths_for_row:
                        paths_for_row.append(relative)
    if parent:
        for field in ("surfaces", "deferred"):
            rows, originals = coverage.get(field), parent["reviewState"].get(field)
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

    def projection_key(field: str, item: dict[str, Any]) -> tuple[str, str]:
        # Publication may rename canonical IDs and add retained finding history.
        ignored = {"id", "previousFindings"} if field == "surfaces" else {"id"}
        content = {
            key: value
            for key, value in canonical_coverage_record(field, item).items()
            if key not in ignored
        }
        return field, _digest(content)

    projected_sources: dict[tuple[str, str], tuple[str, dict[str, Any], tuple[int, int]]] = {}
    accepted_pending_candidates: set[tuple[str, int, str]] = set()
    selected_reported_candidates: dict[tuple[str, str], tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if relative not in selected_observations:
            continue
        for finding in draft["findings"]:
            if isinstance(finding, dict) and valid_finding(finding):
                candidate_id = finding_candidate_id(finding)
                if candidate_id:
                    key = (worker_id, candidate_id)
                    selected_reported_candidates[key] = max(
                        selected_reported_candidates.get(key, source_order[relative]),
                        source_order[relative],
                    )
    for relative, draft, worker_id in sources:
        if relative not in accepted_sources:
            continue
        worker = workers_by_id[worker_id]
        reported = {
            finding_candidate_id(finding)
            for finding in draft["findings"]
            if isinstance(finding, dict) and valid_finding(finding)
        }
        for field in ("surfaces", "deferred", "explicitExclusions"):
            rows = draft["reviewState"].get(field, [])
            for index, row in enumerate(rows if isinstance(rows, list) else [], 1):
                if not isinstance(row, dict):
                    continue
                if (
                    field == "deferred"
                    and isinstance(candidate_id := row.get("candidateId"), str)
                    and candidate_id not in reported
                    and selected_reported_candidates.get((worker_id, candidate_id), (-1, -1))
                    < source_order[relative]
                ):
                    accepted_pending_candidates.add((worker_id, worker["attempt"], candidate_id))
                projected = project_missing_record(field, row, index, worker, draft["reviewState"])
                if field == "surfaces":
                    projected["receiptRefs"] = coverage_receipts(projected, worker, relative)
                key = projection_key(field, projected)
                projected_sources[key] = (worker_id, row, source_order[relative])

    def record_source(
        field: str, owner: str | None, item: dict[str, Any]
    ) -> tuple[str | None, dict[str, Any]]:
        # Parent-authored provenance is data, not authority over another worker.
        if (source := projected_sources.get(projection_key(field, item))) and (
            owner is None or owner == source[0]
        ):
            return source[0], source[1]
        return owner, item

    def record_key(field: str, owner: str | None, item: dict[str, Any]) -> tuple[str | None, Any]:
        source_owner, original = record_source(field, owner, item)
        identity = original.get("id")
        return source_owner, identity if isinstance(identity, str) else None

    def coverage_candidate(
        owner: str | None, item: dict[str, Any]
    ) -> tuple[str | None, str] | None:
        for field in ("surfaces", "deferred", "explicitExclusions"):
            source_owner, original = record_source(field, owner, item)
            if original is not item:
                owner, item = source_owner, original
                break
        else:
            # A later parent can complete a known worker proof gap, but its
            # claimed provenance cannot overturn an accepted worker finding.
            provenance = item.get("provenance")
            if owner is None and isinstance(provenance, dict):
                source_owner = provenance.get("workerId")
                attempt = provenance.get("attempt")
                candidate_id = provenance.get("candidateId")
                if (
                    isinstance(source_owner, str)
                    and isinstance(attempt, int)
                    and isinstance(candidate_id, str)
                    and (source_owner, attempt, candidate_id) in accepted_pending_candidates
                ):
                    return source_owner, candidate_id
        candidate_id = (
            _deferred_candidate_id(item, owner, ambiguous_deferred)
            if any(key in item for key in ("candidate", "finding"))
            else item.get("candidateId")
        )
        return (owner, candidate_id) if isinstance(candidate_id, str) else None

    def candidate_order(
        relative: str, owner: str | None, item: dict[str, Any] | None = None
    ) -> tuple[int, int]:
        order = source_order[relative]
        if source_owners[relative] is None and owner is not None:
            if item is not None:
                for field in ("surfaces", "deferred", "explicitExclusions"):
                    key = projection_key(field, item)
                    if (source := projected_sources.get(key)) and source[0] == owner:
                        return source[2]
            attempt = int(workers_by_id[owner]["attempt"] or 0) if owner in headed_workers else 0
            return attempt, order[1]
        return order

    deferred_rows = {
        relative: _coverage_rows(draft["reviewState"], "deferred")
        for relative, draft, _ in all_sources
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
        by_id: dict[tuple[str | None, Any], dict[str, Any]] = {}
        candidate_aliases = {
            (source_owner, identity)
            for row in deferred_rows[relative]
            if isinstance(row, dict) and _has_candidate_metadata(row)
            for source_owner, original in [record_source("deferred", owner, row)]
            for identity in (original.get("id"), original.get("candidateId"))
            if isinstance(identity, str)
        }
        for row in deferred_rows[relative]:
            if not isinstance(row, dict) or not isinstance(identity := row.get("id"), str):
                continue
            if _has_candidate_metadata(row):
                continue
            key = record_key("deferred", owner, row)
            if key in candidate_aliases or (key in by_id and row != by_id[key]):
                ambiguous_deferred.add(key)
            by_id[key] = row
    current_drafts = ([("parent", parent, None)] if parent else []) + [
        source for source in sources if source[0] in current_results | selected_observations.keys()
    ]

    pending_surface_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    for relative, draft, owner in all_sources:
        surfaces = draft["reviewState"].get("surfaces", [])
        for surface in surfaces if isinstance(surfaces, list) else []:
            if (
                isinstance(surface, dict)
                and surface.get("disposition") == "needs_follow_up"
                and (candidate := coverage_candidate(owner, surface)) is not None
            ):
                order = candidate_order(relative, candidate[0], surface)
                pending_surface_orders[candidate] = max(
                    pending_surface_orders.get(candidate, order), order
                )
    # Generic closures belong to one logical scan or worker, just like candidates.
    # Keep them when recovering a terminal checkpoint without its canonical write.
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}

    candidate_ids: set[tuple[str | None, str]] = set()
    accepted_deferred_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}
    coverage_schema = _read_json(
        Path(__file__).resolve().parents[2] / "schemas" / "coverage.schema.json"
    )["properties"]

    projected_closure_sources = _projected_worker_closure_sources(
        sources, source_order, worker_attempts, coverage_schema["resolvedDeferred"]
    )

    for relative, draft, owner in all_sources:
        for item in deferred_rows[relative]:
            if not isinstance(item, dict):
                continue
            source_owner, original = record_source("deferred", owner, item)
            order = candidate_order(relative, source_owner, item)
            if isinstance(item.get("candidateId"), str) or "candidate" in item or "finding" in item:
                candidate_ids.update(
                    (source_owner, identity)
                    for identity in (original.get("id"), original.get("candidateId"))
                    if isinstance(identity, str)
                )
            identity = original.get("id") or original.get("candidateId")
            if isinstance(identity, str):
                key = (source_owner, identity)
                previous = active_deferred.get(key)
                if previous is None or order > previous[0]:
                    active_deferred[key] = (order, original, relative)
                if (
                    relative == "parent"
                    or relative in current_results
                    or relative in selected_observations
                ):
                    try:
                        # A malformed update cannot discard valid saved evidence.
                        _validate_schema_node(
                            {"id": identity, **item},
                            coverage_schema["deferred"]["items"],
                            "coverage.deferred",
                        )
                    except ContractError:
                        continue
                    accepted_deferred_orders[key] = max(
                        accepted_deferred_orders.get(key, order), order
                    )
        for closure in _resolved_deferred_rows(draft, coverage_schema["resolvedDeferred"]):
            closure_owner, closure_relative = owner, relative
            if owner is None and (
                source := projected_closure_sources.get((closure["id"], closure["reason"]))
            ):
                # A copied parent closeout keeps its worker's identity and observation
                # time, so a later parent write cannot hide reopened worker work.
                closure_owner, closure, closure_relative = source
            key = (closure_owner, closure["id"])
            order = candidate_order(closure_relative, closure_owner)
            previous = closed_deferred.get(key)
            if previous is None or order > previous[0]:
                # The parent comes first, preserving its reason on equal timestamps.
                closed_deferred[key] = (order, closure, closure_relative)
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
                and record_key("deferred", owner, row) in ambiguous_deferred
                and not _has_candidate_metadata(row)
                and (owner, row) not in reopened_rows
            ):
                reopened_rows.append((owner, row))
    retained_closures = [
        closure
        if owner is None
        else _project_worker_closure(relative, owner, closure, worker_attempts, source_order)
        for (owner, _), (_, closure, relative) in closed_deferred.items()
    ]
    coverage.pop("resolvedDeferred", None)
    if retained_closures:
        coverage["resolvedDeferred"] = copy.deepcopy(retained_closures)
        if parent:
            coverage["deferred"] = [
                row
                for row in deferred_rows["parent"]
                if not isinstance(row, dict)
                or not isinstance(row.get("id"), str)
                or (None, row["id"]) not in closed_deferred
            ]

    ordered_candidates = {
        (owner, identity)
        for owner, row in reopened_rows
        if (identity := _deferred_candidate_id(row, owner, ambiguous_deferred)) is not None
        and (owner, identity) in candidate_ids
    }

    outcomes, pending_candidate_orders = _saved_candidate_outcomes(
        scan_dir,
        current_drafts,
        valid_finding,
        coverage_candidate,
        candidate_order,
        workers_by_id,
        coverage_schema,
    )
    ordered_candidates.update(pending_candidate_orders)

    def select_outcomes(unusable_receipts):
        permitted = [entry for entry in outcomes if not unusable_receipts.intersection(entry[-1])]
        resolved, ordered_outcomes = {}, {}
        candidates = ordered_candidates.union(
            (owner, candidate_id)
            for relative, owner, candidate_id, _, _, _ in permitted
            if relative in selected_observations
        )
        selected_head_candidates = {
            (Path(relative).parent, owner, candidate_id)
            for relative, owner, candidate_id, _, _, _ in permitted
            if relative in authoritative_heads
        }
        other_root_order = _unselected_root_order(saved_heads, checkpoint_heads, source_order)
        for relative, owner, candidate_id, disposition, order, _ in permitted:
            if (
                relative in selected_observations
                and relative not in authoritative_heads
                and relative not in current_results
                and (Path(relative).parent, owner, candidate_id) in selected_head_candidates
            ):
                continue
            key = (owner, candidate_id)
            if pending_surface_orders.get(key, (-1, -1)) >= order:
                continue
            if key not in candidates:
                if relative == "parent" or relative in current_results:
                    resolved.setdefault(key, disposition)
                continue
            root_terminal = (
                owner is None
                and (relative == "parent" or relative in authoritative_heads)
                and (parent if relative == "parent" else drafts_by_path[relative]).get("complete")
                is not False
                and other_root_order < order
            )
            pending_order = pending_candidate_orders.get(key, (-1, -1))
            if (pending_order > order or (pending_order == order and not root_terminal)) or any(
                (
                    coverage_candidate(saved_owner, row)
                    or (saved_owner, _deferred_candidate_id(row, saved_owner, ambiguous_deferred))
                )
                == key
                and (
                    saved_order > order
                    or saved_order == order
                    and (
                        not root_terminal
                        or accepted_deferred_orders.get((saved_owner, identity)) == saved_order
                    )
                )
                for (saved_owner, identity), (saved_order, row, _) in active_deferred.items()
            ):
                continue
            previous = ordered_outcomes.get(key)
            if (
                previous is None
                or order > previous[0]
                or (
                    order == previous[0]
                    and previous[1] != relative
                    and previous[1] in current_results
                    and (
                        relative in checkpoint_heads.values()
                        or relative in authoritative_observations
                    )
                )
            ):
                resolved[key] = disposition
                ordered_outcomes[key] = (order, relative)
        return resolved, ordered_outcomes

    resolved, ordered_outcomes = select_outcomes(set())
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
    selected_terminal_orders: dict[str | None, tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if (
            relative in authoritative_heads
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
            if relative not in reducer_paths and relative not in discarded_coverage_sources:
                terminal_coverage_orders[worker_id] = max(
                    terminal_coverage_orders.get(worker_id, order), order
                )
    prior_terminal_orders: dict[str | None, tuple[int, int]] = {}
    partial_head_orders = {
        Path(path).parent: selected_observations[path]
        for path in authoritative_heads
        if drafts_by_path[path].get("complete") is False
    }
    for head, checkpoint in saved_heads.items():
        directory = _checkpoint_head_directory(head)
        relative = (directory / "checkpoints" / checkpoint).as_posix()
        partial_order = partial_head_orders.get(Path(relative).parent)
        if partial_order is None:
            continue
        order = (partial_order[0], source_order[head][1])
        if (
            drafts_by_path[relative].get("complete") is not False
            and relative not in discarded_by_source
            and relative not in discarded_coverage_sources
            and order <= partial_order
        ):
            # A partial head adds coverage after the preceding terminal replacement.
            worker_id = paths[relative]
            prior_terminal_orders[worker_id] = max(
                prior_terminal_orders.get(worker_id, order), order
            )

    # Reconcile raw records before generating context-dependent publication IDs.
    logical_rows: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
    row_groups: dict[tuple[str, int], dict[str, Any]] = {}
    published_groups: list[dict[str, Any]] = []

    def same_owner(left: str | None, right: str | None) -> bool:
        # Canonical recovery needs identity or recorded lineage to absorb worker evidence.
        return left == right or (not preserve_canonical_parent and (left is None or right is None))

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
            or draft["reviewState"].get("mode") == binding["coverageMode"]
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
        selected_terminal_order = selected_terminal_orders.get(worker_id)
        terminal_coverage_order = max(
            (
                order
                for order in (
                    terminal_coverage_orders.get(worker_id),
                    selected_terminal_order,
                    prior_terminal_orders.get(worker_id),
                )
                if order is not None
            ),
            default=None,
        )
        selected_coverage_superseded = (
            terminal_coverage_order is not None and source_order[relative] < terminal_coverage_order
        ) or (
            selected_terminal_order is not None
            and source_order[relative][0] == selected_terminal_order[0]
            and (
                relative in selected_observations
                and relative not in authoritative_heads
                and relative not in current_results
                or (
                    relative in current_results
                    and relative not in authoritative_heads
                    and source_order[relative] <= selected_terminal_order
                )
            )
        )
        selected_candidates = {
            candidate_id
            for (owner, candidate_id), (_, source) in ordered_outcomes.items()
            if owner == worker_id and source == relative
        }
        superseded = (
            worker_id is None
            and saved_parent is not None
            and saved_parent.get("complete") is not False
            and relative != "parent"
            and source_order[relative] <= (0, parent_modified)
            and (not stopped_parent_seal or relative in parent_preserved_sources)
            and (
                # Explicit recovery can admit checkpoints written after this parent.
                frozen_parent_path is None
                or relative == frozen_parent_path
                or relative in saved_parent.get("previousParentCheckpoints", [])
            )
        ) or (
            worker_id is not None
            and relative not in current_results
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
            and not (isinstance(item, dict) and _has_candidate_metadata(item))
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
            and (coverage_candidate(worker_id, item) or (worker_id, identity)) in resolved
            and (field == "deferred" or item.get("disposition") == "needs_follow_up")
        ):
            return False
        return True

    def source_surface_receipts(relative: str, row: dict[str, Any]) -> Any:
        worker = workers_by_id.get(source_owners.get(relative))
        return coverage_receipts(row, worker, relative) if worker else row.get("receiptRefs", [])

    replaced_deferred = {
        id(row)
        for relative, _, owner in all_sources
        for row in deferred_rows[relative]
        if isinstance(row, dict)
        and isinstance(row.get("id"), str)
        and (key := record_key("deferred", owner, row)) not in candidate_ids
        and key not in ambiguous_deferred
        and (updated := accepted_deferred_orders.get(key)) is not None
        and updated > candidate_order(relative, key[0], row)
    }
    ambiguous_surface_ids = {
        (owner, identity)
        for owner, row in reopened_rows
        if isinstance(row.get("id"), str)
        and (owner, row["id"]) in ambiguous_deferred
        and not _has_candidate_metadata(row)
        for identity in [
            row["id"],
            *(row.get("surfaceIds", []) if isinstance(row.get("surfaceIds", []), list) else []),
        ]
        if isinstance(identity, str)
    }
    for _, draft, owner in all_sources:
        by_id: dict[str, dict[str, Any]] = {}
        for surface in _coverage_rows(draft["reviewState"], "surfaces"):
            if not isinstance(surface, dict) or not isinstance(identity := surface.get("id"), str):
                continue
            if identity in by_id and surface != by_id[identity]:
                ambiguous_surface_ids.add((owner, identity))
            by_id[identity] = surface

    def ambiguous_pending_surface(row: dict[str, Any], owner: str | None) -> bool:
        return (
            isinstance(row.get("id"), str)
            and (owner, row["id"]) in ambiguous_surface_ids
            and row.get("disposition") == "needs_follow_up"
            and not _has_candidate_metadata(row)
        )

    def retain_findings(relative, draft, worker_id, selected_candidates, skip_superseded_findings):
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
                for item in _coverage_rows(coverage, "surfaces"):
                    if isinstance(item, dict) and (
                        coverage_candidate(None, item) == (worker_id, candidate_id)
                        or (
                            preserve_canonical_parent
                            and item.get("candidateId") == candidate_id
                            and any(
                                source_owners[source] == worker_id
                                for source in coverage_sources.get(id(item), (item, []))[1]
                            )
                        )
                        or (
                            not preserve_canonical_parent
                            and coverage_candidate(None, item) == (None, candidate_id)
                        )
                    ):
                        _append_previous_finding(item, finding)
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

    competing_receipts = _competing_rejection_receipts(
        outcomes, all_sources, source_surface_receipts
    )
    check_outcome_receipts = bool(competing_receipts)
    dry_run = check_outcome_receipts
    unavailable = set()
    if dry_run:
        initial_coverage = coverage
        initial_canonical_rows = canonical_rows
        initial_sources = coverage_sources
        initial_surface_rows = retained_surface_rows
        initial_ids = surface_ids_by_source
        initial_projection = projection
        output_warnings = warnings

    def retain_surface_links(owner, row):
        if isinstance(row, dict):
            links = row.get("surfaceIds", [])
            for identity in [row.get("id"), *(links if isinstance(links, list) else [])]:
                if isinstance(identity, str):
                    pending_surface_ids.add((owner, identity))

    def surface_is_retained(relative: str, owner: str | None, row: Any) -> bool:
        selection = source_coverage_selection(relative, owner)
        if (
            isinstance(row, dict)
            and isinstance(row.get("id"), str)
            and (owner, row["id"]) in pending_surface_ids
        ):
            selection = (False, *selection[1:])
        return coverage_row_is_retained("surfaces", row, owner, selection)

    while True:
        if check_outcome_receipts:
            warnings = [] if dry_run else output_warnings
            coverage = copy.deepcopy(initial_coverage)
            canonical_rows = initial_canonical_rows.copy()
            coverage_sources = {
                identity: (row, paths.copy()) for identity, (row, paths) in initial_sources.items()
            }
            for field in ("surfaces", "deferred", "explicitExclusions"):
                for initial, current in zip(
                    _coverage_rows(initial_coverage, field),
                    _coverage_rows(coverage, field),
                    strict=True,
                ):
                    if id(initial) in initial_canonical_rows:
                        canonical_rows.add(id(current))
                    _inherit_coverage_sources(current, [initial], coverage_sources)
            retained_surface_rows = initial_surface_rows.copy()
            surface_ids_by_source = {key: ids.copy() for key, ids in initial_ids.items()}
            reconciled_surface_ids.clear()
            projection = type(initial_projection)(
                initial_projection.project_worker_coverage,
                initial_projection.legacy_surface_links,
                sources,
            )
        # Apply reconciled outcomes to coverage already copied from the parent too.
        for field in ("surfaces", "deferred"):
            rows = coverage.get(field)
            if isinstance(rows, list):
                coverage[field] = [
                    row
                    for row in rows
                    if not (
                        isinstance(row, dict)
                        and (
                            (
                                field == "deferred"
                                and record_key(field, None, row) in closed_deferred
                            )
                            or (
                                coverage_candidate(None, row) in resolved
                                and (
                                    field == "deferred"
                                    or row.get("disposition") == "needs_follow_up"
                                )
                            )
                        )
                    )
                ]

        # Reserve receipts for supporting surfaces before repairing historical refs.
        prospective_tasks = []
        for relative, _, owner in all_sources:
            selection = source_coverage_selection(relative, owner)
            for row in deferred_rows[relative]:
                if (
                    coverage_row_is_retained("deferred", row, owner, selection)
                    and id(row) not in replaced_deferred
                    and not (
                        isinstance(row, dict)
                        and isinstance(row.get("id"), str)
                        and record_key("deferred", owner, row) in closed_deferred
                    )
                ):
                    prospective_tasks.append((owner, row))
        prospective_tasks.extend(
            (owner, row)
            for owner, row in reopened_rows
            if (owner, _deferred_candidate_id(row, owner, ambiguous_deferred)) not in resolved
        )
        pending_surface_ids = set()

        for owner, row in prospective_tasks:
            retain_surface_links(owner, row)
        if parent and isinstance(coverage.get("deferred"), list):
            previous = parent["reviewState"].get("deferred", [])
            removed_parent = (
                [row for row in previous if id(row) in replaced_deferred]
                if isinstance(previous, list)
                else []
            )
            for row in coverage["deferred"]:
                if row not in removed_parent:
                    retain_surface_links(None, row)

        fallback_surfaces = projection.fallback_surfaces(
            coverage,
            all_sources,
            prospective_tasks,
            surface_is_retained=surface_is_retained,
            ambiguous_surface_ids=ambiguous_surface_ids,
        )

        replaced_surfaces, surface_updates = _generic_surface_updates(
            all_sources,
            closed_deferred,
            active_deferred,
            resolved,
            reopened_generic,
            coverage_schema["surfaces"]["items"],
            deferred_rows,
            ambiguous_deferred,
            record_source,
            candidate_order,
            source_surface_receipts,
            canonical_rows=canonical_rows,
            coverage_sources=coverage_sources,
            receipt_root=scan_dir if project_worker_coverage else None,
            receipt_warnings=warnings,
            fallback_surfaces=fallback_surfaces,
            surface_is_retained=surface_is_retained,
            eligible_receipt_sources={
                relative
                for relative, draft, _ in all_sources
                if draft.get("complete") is not False or relative in selected_observations
            },
        )
        replaced_rows = {
            "surfaces": replaced_surfaces,
            "deferred": {
                id(row)
                for relative, _, owner in all_sources
                for row in deferred_rows[relative]
                if isinstance(row, dict)
                and isinstance(identity := row.get("id"), str)
                and (key := record_key("deferred", owner, row)) not in candidate_ids
                and key not in ambiguous_deferred
                and (updated := accepted_deferred_orders.get(key)) is not None
                and updated > candidate_order(relative, key[0], row)
            },
        }
        for field, replaced in replaced_rows.items():
            if parent and isinstance(coverage.get(field), list):
                previous = parent["reviewState"].get(field, [])
                if isinstance(previous, list):
                    removed_parent = [row for row in previous if id(row) in replaced]
                    coverage[field] = [row for row in coverage[field] if row not in removed_parent]
        if isinstance(coverage.get("surfaces"), list):
            for relative, owner, source_surface, surface in surface_updates:
                original_surface = surface
                # Generic updates already resolve each receipt at its saved source.
                surface = projection.repair_reviewed_surface(
                    coverage,
                    projected_coverage if parent_is_canonical else {},
                    workers_by_id.get(owner),
                    source_surface,
                    surface,
                ) or project_record("surfaces", surface, source_surface, receipts_resolved=True)
                reconciled_surface_ids[record_key("surfaces", owner, source_surface)] = surface[
                    "id"
                ]
                if surface not in coverage["surfaces"] and (
                    surface is original_surface
                    or retained_coverage_record("surfaces", surface) is None
                ):
                    retain_coverage_row(
                        coverage["surfaces"],
                        surface,
                        owner,
                        "surfaces",
                        source_surface,
                        surface is not original_surface or relative == "parent",
                    )
            for surface in coverage["surfaces"]:
                if isinstance(surface, dict):
                    surface.setdefault("receiptRefs", [])

        # Reopened work survives a superseded checkpoint, but current candidate
        # outcomes still apply. Parent closures cannot remove another worker's row.
        for owner, item in reopened_rows:
            source_owner, original = record_source("deferred", owner, item)
            if (
                identity := _deferred_candidate_id(original, source_owner, ambiguous_deferred)
            ) is not None and (
                source_owner,
                identity,
            ) in resolved:
                continue
            original_item = item
            item = project_record("deferred", item)
            pending = coverage.setdefault("deferred", [])
            if (
                isinstance(pending, list)
                and item not in pending
                and (item is original_item or retained_coverage_record("deferred", item) is None)
            ):
                retain_coverage_row(
                    pending, item, owner, "deferred", original_item, item is not original_item
                )
        for _, draft, owner in all_sources:
            for surface in _coverage_rows(draft["reviewState"], "surfaces"):
                if (
                    isinstance(surface, dict)
                    and ambiguous_pending_surface(surface, owner)
                    and isinstance(coverage.get("surfaces"), list)
                ):
                    original_surface = {**surface, "receiptRefs": surface.get("receiptRefs", [])}
                    retained_surface = project_record("surfaces", original_surface, surface)
                    if retained_surface not in coverage["surfaces"] and (
                        retained_surface is original_surface
                        or retained_coverage_record("surfaces", retained_surface) is None
                    ):
                        retain_coverage_row(
                            coverage["surfaces"],
                            retained_surface,
                            owner,
                            "surfaces",
                            surface,
                            retained_surface is not original_surface,
                        )
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
                and all(
                    valid_finding(finding) for finding in (parent["findings"] if parent else [])
                )
            )
            if (
                skip_superseded_findings
                and coverage_superseded
                and not selected_candidates
                and not retain_pending
            ):
                continue
            if (
                not dry_run
                and not skip_superseded_findings
                and "threatModel" not in manifest["scan"]
                and isinstance(draft.get("threatModel"), dict)
            ):
                model = recovered_model(relative, draft, worker_id)
                model_path = relative
                checkpoint_dir = Path(relative).parent
                root_checkpoint = checkpoint_dir == Path("checkpoints")
                prefer_checkpoint_head = root_checkpoint or (
                    worker_id is not None
                    and (checkpoint_dir.name == "checkpoints" or draft.get("complete") is False)
                )
                if worker_id is not None or root_checkpoint:
                    if checkpoint_dir.name != "checkpoints":
                        checkpoint_dir /= "checkpoints"
                    selected_models = [
                        path
                        for path in drafts_by_path
                        if (
                            path in selected_observations
                            or (
                                path in current_results
                                and drafts_by_path[path].get("complete") is not False
                            )
                        )
                        and (
                            Path(path).parent == checkpoint_dir
                            or (
                                path in current_results
                                and Path(path).parent / "checkpoints" == checkpoint_dir
                            )
                        )
                        and isinstance(drafts_by_path[path].get("threatModel"), dict)
                        and recovered_model(path, drafts_by_path[path], worker_id) is not None
                    ]
                    if selected_models:
                        authoritative_models = [
                            path
                            for path in selected_models
                            if path in authoritative_heads or path in current_results
                        ]
                        if not any(path in authoritative_heads for path in selected_models):
                            authoritative_models = selected_models
                        head_path = max(
                            authoritative_models or selected_models,
                            key=lambda path: (source_order[path], path in authoritative_heads),
                        )
                        current = drafts_by_path[head_path]
                        # A terminal checkpoint is committed before result.json is replaced.
                        # Use the admitted observation, including its frozen ordering on retries.
                        if not prefer_checkpoint_head and current.get("complete") is not False:
                            prefer_checkpoint_head = (
                                source_order[head_path] >= source_order[relative]
                            )
                        if prefer_checkpoint_head:
                            model = recovered_model(head_path, current, worker_id)
                            model_path = head_path
                if model is not None:
                    manifest["scan"]["threatModel"] = model
                    if selected_model_source is not None and model_path in source_digests:
                        selected_model_source[:] = [model_path]
            if not dry_run:
                retain_findings(
                    relative, draft, worker_id, selected_candidates, skip_superseded_findings
                )
            worker = workers_by_id.get(worker_id)
            # Only the accepted current output belongs to this worker attempt. An
            # unsuperseded archive can remain evidence after that output is lost.
            project_coverage = (
                worker is not None
                and worker["status"] == "succeeded"
                and worker["result_manifest_path"] == str(scan_dir / relative)
                and draft.get("complete") is not False
            )
            if coverage_superseded and not selected_candidates and not retain_pending:
                continue
            if project_coverage:
                reviewed_attempts.add((worker_id, worker["attempt"]))
                reviews = coverage.setdefault("reviews", [])
                if isinstance(reviews, list) and not any(
                    isinstance(review, dict)
                    and review.get("workerId") == worker_id
                    and review.get("attempt") == worker["attempt"]
                    for review in reviews
                ):
                    reviews.append(
                        {
                            "workerId": worker_id,
                            "attempt": worker["attempt"],
                            "completeness": draft["reviewState"].get("completeness", "partial"),
                        }
                    )
            for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions", "reviews"):
                if field == "reviews" and (
                    worker_id is not None or field not in draft["reviewState"]
                ):
                    continue
                if coverage_superseded and field not in {
                    "surfaces",
                    "explicitExclusions",
                    "deferred",
                }:
                    continue
                items = draft["reviewState"].get(field, [])
                if field == "deferred":
                    items = deferred_rows[relative]
                if not isinstance(items, list):
                    continue
                output = coverage.setdefault(field, [])
                if not isinstance(output, list):
                    # Keep malformed canonical collections for the existing finalizer's
                    # recovery and warnings rather than silently changing its contract.
                    continue
                for index, item in enumerate(items, 1):
                    source_item = item
                    if not (
                        surface_is_retained(relative, worker_id, item)
                        if field == "surfaces"
                        else coverage_row_is_retained(field, item, worker_id, selection)
                    ):
                        continue
                    if id(item) in replaced_rows.get(field, ()):
                        continue
                    if (
                        field == "deferred"
                        and isinstance(item, dict)
                        and isinstance(item.get("id"), str)
                        and record_key("deferred", worker_id, item) in closed_deferred
                    ):
                        continue
                    if field == "openQuestions" and isinstance(item, str):
                        item = {"question": item.strip()}
                    if (
                        field == "surfaces"
                        and isinstance(item, dict)
                        and item.get("disposition") in ("rejected", "not_applicable")
                        and isinstance(item.get("candidateId"), str)
                        and (
                            history_findings := rejected_history.get(
                                (worker_id, item["candidateId"])
                            )
                        )
                    ):
                        item = copy.deepcopy(item)
                        for finding in history_findings:
                            _append_previous_finding(item, finding, clone=True)
                    projected_row = False
                    if isinstance(item, dict):
                        original_item = item
                        item = (
                            project_missing_record(field, item, index, worker, draft["reviewState"])
                            if project_coverage
                            else project_record(field, item, source_item)
                        )
                        projected_row = item is not original_item
                    if field == "surfaces" and isinstance(item, dict):
                        item = {**item, "receiptRefs": item.get("receiptRefs", [])}
                    if (
                        field == "surfaces"
                        and worker is not None
                        and isinstance(item, dict)
                        and (project_coverage or not projected_row)
                    ):
                        item = copy.deepcopy(item)
                        item["receiptRefs"] = coverage_receipts(item, worker, relative)
                    if (
                        projected_row
                        and isinstance(item, dict)
                        and retained_coverage_record(field, item) is not None
                    ):
                        continue
                    if isinstance(item, dict) and "id" not in item:
                        semantic_item = dict(item)
                        existing = next(
                            (
                                existing
                                for existing in output
                                if isinstance(existing, dict)
                                and {key: value for key, value in existing.items() if key != "id"}
                                == semantic_item
                            ),
                            None,
                        )
                        if existing is not None:
                            _inherit_coverage_sources(existing, [source_item], coverage_sources)
                            if field == "surfaces":
                                retained_surface_rows.add(id(source_item))
                            continue
                    retain_coverage_row(
                        output,
                        item,
                        worker_id,
                        field,
                        source_item,
                        projected_row or project_coverage,
                    )

        projection.finalize(
            coverage,
            canonical_rows,
            _digest,
            preserve_canonical_parent=preserve_canonical_parent,
            all_sources=all_sources,
            source_order=source_order,
            coverage_sources=coverage_sources,
            surface_ids_by_source=surface_ids_by_source,
            retained_surface_rows=retained_surface_rows,
            resolved=resolved,
        )
        if not dry_run:
            break
        invalid = _conflicting_outcome_receipts(
            coverage,
            scan_dir,
            competing_receipts - unavailable,
        )
        if invalid:
            unavailable.update(invalid)
            resolved, ordered_outcomes = select_outcomes(unavailable)
        else:
            dry_run = False

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
    coverage.pop("completeness", None)
    if stopped:
        if not isinstance(coverage.get("deferred"), list):
            coverage["deferred"] = []
        item = {"id": "scan-stopped", "reason": reason}
        if item not in coverage["deferred"]:
            coverage["deferred"].append(item)
    surfaces = coverage.get("surfaces", [])
    for surface in surfaces if isinstance(surfaces, list) else []:
        if isinstance(surface, dict) and isinstance(surface.get("provenance"), dict):
            surface["provenance"].pop("scanReceiptRefs", None)
    if (
        frozen_source_digests is None
        or heads_snapshotted
        or snapshot_error is not None
        or any(_is_source_order_snapshot(path) for path in source_digests)
        or allow_frozen_legacy_parent
    ):
        try:
            if snapshot_error is not None:
                raise snapshot_error
            _freeze_source_times(
                scan_dir,
                scan_id,
                source_digests,
                source_times,
                parent_context,
                created_paths=created_paths,
            )
        except (ContractError, OSError) as exc:
            failure = _CheckpointSnapshotError(
                str(exc),
                {
                    path: (digest, source_times[path])
                    for path, digest in source_digests.items()
                    if not _is_source_order_snapshot(path)
                },
            )
            failure.parent_context = parent_context
            failure.heads = checkpoint_heads
            failure.documents = (manifest, {"findings": findings}, coverage)
            if isinstance(manifest["scan"].get("threatModel"), dict):
                failure.model_source = list(selected_model_source or [])
            raise failure from exc

    return manifest, {"findings": findings}, coverage
