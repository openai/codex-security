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
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    ScanLocalIOError,
    _finding_strength,
    _has_identity_text,
    _populate_unsealed_artifact_envelope,
    _populate_unsealed_manifest_envelope,
    _prepare_scan_finalization,
    _read_json,
    _read_saved_threat_model,
    _read_scan_local_json,
    _read_scan_local_json_bytes,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _remove_scan_local_file_if_exists,
    _require_safe_json_value,
    _validate_completion_binding,
    _validate_schema_node,
    _write_prepared_scan_finalization,
    finalize_scan,
    finding_candidate_id,
    manifest_is_sealed,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
    write_threat_model_projection_if_possible,
)
from workbench.saved_coverage import (
    _prepare_worker_coverage_recovery,
    _project_worker_coverage_row,
    _saved_coverage_id,
)
from workbench.saved_reconciliation import (
    _deferred_candidate_id as _deferred_candidate_id,
)
from workbench.saved_reconciliation import (
    _deferred_rows as _deferred_rows,
)
from workbench.saved_reconciliation import (
    _ensure_finding_identities as _ensure_finding_identities,
)
from workbench.saved_reconciliation import (
    _ensure_finding_identity as _ensure_finding_identity,
)
from workbench.saved_reconciliation import (
    _finding_content as _finding_content,
)
from workbench.saved_reconciliation import (
    _finding_identity as _finding_identity,
)
from workbench.saved_reconciliation import (
    _finding_key as _finding_key,
)
from workbench.saved_reconciliation import (
    _generic_surface_updates as _generic_surface_updates,
)
from workbench.saved_reconciliation import (
    _identity_candidate as _identity_candidate,
)
from workbench.saved_reconciliation import (
    _merge_tied_parent_observations as _merge_tied_parent_observations,
)
from workbench.saved_reconciliation import (
    _resolved_deferred_rows as _resolved_deferred_rows,
)
from workbench.saved_reconciliation import (
    _retained_findings as _retained_findings,
)
from workbench.saved_reconciliation import (
    _semantic_identity_key as _semantic_identity_key,
)
from workbench.saved_reconciliation import (
    _worker_candidate_key as _worker_candidate_key,
)
from workbench_constants import PHASES
from workbench_saved_sources import (
    _admit_parent_checkpoint,
    _capture_parent_observation,
    _capture_saved_source,
    _checkpoint_head_directory,
    _checkpoint_paths,
    _digest,
    _encode_retained_sources,
    _encoded,
    _freeze_source_times,
    _frozen_source_times,
    _is_source_order_snapshot,
    _latest_successful_reducer,
    _parent_publication_ancestors,
    _parent_scan_draft,
    _read_saved_parent_result,
    _read_saved_result,
    _require_current_deep_publication,
    _retained_source_state,
    _saved_result_paths,
    _source_digests,
    _worker_outputs,
)
from workbench_target import committed_diff_snapshot_digest
from workbench_validation import path_within_scope

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
) -> dict[str, Any]:
    warnings = json.loads(scan["completion_warnings_json"])
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    db.require_recorded_manifest_digest(scan, scan_dir)
    db.verify_manifest_binding(scan, db.read_json_object(scan_dir / db.ARTIFACTS["manifest"]))
    try:
        manifest, _, _ = finalize_scan(
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
    return db.scan_context(connection, scan["id"])


def _saved_results_changed(db: Any, connection: Any, scan: Any) -> bool:
    try:
        scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
        manifest_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
        workers = connection.execute(
            "SELECT id, kind, status, completed_at, artifact_dir, result_manifest_path "
            "FROM deep_scan_workers WHERE scan_id = ?",
            (scan["id"],),
        ).fetchall()
        paths = dict(_saved_result_paths(scan_dir, workers))
        frozen_sources = scan["retained_source_digests_json"]

        def has_saved_source() -> bool:
            for path in paths:
                try:
                    _read_saved_result(scan_dir, path, scan["id"], kind=paths[path])
                    return True
                except (ContractError, OSError, ValueError):
                    continue
            return False

        if manifest_path is None:
            if frozen_sources is not None:
                return bool(_retained_source_state(json.loads(frozen_sources))[0])
            return has_saved_source()
        if scan["seal_manifest_digest"] is None:
            try:
                _read_saved_parent_result(scan_dir, scan["id"])
                return True
            except (ContractError, OSError, ValueError):
                pass
            return has_saved_source()
        manifest = _read_scan_local_json(
            scan_dir,
            manifest_path.relative_to(scan_dir).as_posix(),
            "Saved scan manifest",
        )
        manifest_scan = manifest.get("scan")
        if not isinstance(manifest_scan, dict):
            return True
        published_sources = _source_digests(
            manifest_scan.get("preservedSources", {}),
            "Published scan source digests are malformed.",
        )
        current_sources = dict(published_sources)
        paths.update({path: None for path in published_sources if _is_source_order_snapshot(path)})
        for path in paths:
            try:
                captured = _capture_saved_source(
                    scan_dir,
                    path,
                    scan["id"],
                    kind=paths[path],
                    snapshot_head=path not in published_sources,
                    write=False,
                )
                current_sources.update({path: value[0] for path, value in captured.items()})
            except (ContractError, OSError, ValueError):
                continue
        return current_sources != published_sources
    except (ContractError, OSError, SystemExit, ValueError):
        return False


def _recovery_source_digests(db: Any, connection: Any, scan: Any) -> tuple[dict[str, str], bool]:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    frozen_sources: dict[str, str] | None = None
    include_parent = True
    raw_frozen_sources = scan["retained_source_digests_json"]
    if raw_frozen_sources is not None:
        frozen_sources, _ = _retained_source_state(json.loads(raw_frozen_sources))
        include_parent = False

    manifest_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
    if manifest_path is not None:
        manifest = _read_scan_local_json(
            scan_dir,
            manifest_path.relative_to(scan_dir).as_posix(),
            "Saved scan manifest",
        )
        manifest_scan = manifest.get("scan")
        if not isinstance(manifest_scan, dict):
            raise ContractError("Saved scan manifest has no scan object")
        if scan["seal_manifest_digest"] is not None or manifest_is_sealed(manifest_scan):
            if "preservedSources" in manifest_scan:
                published_sources = _source_digests(
                    manifest_scan["preservedSources"],
                    "Published scan source digests are malformed.",
                )
                include_parent = not published_sources
                if published_sources:
                    if frozen_sources is not None and frozen_sources != published_sources:
                        raise ContractError(
                            "Stopped scan sources changed after terminal publication."
                        )
                    frozen_sources = published_sources
                elif frozen_sources is None:
                    frozen_sources = {}
            else:
                include_parent = True

    workers = connection.execute(
        "SELECT id, kind, status, completed_at, artifact_dir, result_manifest_path "
        "FROM deep_scan_workers WHERE scan_id = ?",
        (scan["id"],),
    ).fetchall()
    paths = dict(_saved_result_paths(scan_dir, workers))
    recovery_sources = dict(frozen_sources or {})
    parent_context: dict[str, str] = {}
    source_times = _frozen_source_times(scan_dir, scan["id"], recovery_sources, parent_context)
    for relative, expected_digest in recovery_sources.items():
        try:
            _, digest, observed = _read_saved_result(
                scan_dir, relative, scan["id"], kind=paths.get(relative)
            )
        except (ContractError, OSError, ValueError) as exc:
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")
        if not _is_source_order_snapshot(relative):
            source_times.setdefault(relative, observed)

    for relative in paths.keys() - recovery_sources.keys():
        try:
            captured = _capture_saved_source(scan_dir, relative, scan["id"], kind=paths[relative])
        except (ContractError, OSError, ValueError):
            continue
        if relative == "checkpoint-head.json":
            parent_context["head"] = next(iter(captured))
        for path, (digest, observed) in captured.items():
            if path in recovery_sources and recovery_sources[path] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            recovery_sources[path] = digest
            source_times.setdefault(path, observed)
    _freeze_source_times(scan_dir, scan["id"], recovery_sources, source_times, parent_context)
    return recovery_sources, include_parent


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
    scan_mode: str | None = None,
    frozen_source_digests: dict[str, str] | None = None,
    allow_frozen_legacy_parent: bool = False,
    frozen_model_source: str | None = None,
    selected_model_source: list[str] | None = None,
    finding_scope: list[tuple[str, bool]] | None = None,
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
        if parent_manifest is not None and parent is not None:
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
                Path(__file__).resolve().parent.parent / "schemas/scan-manifest.schema.json"
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
    finding_positions: dict[str, tuple[int, dict[str, Any] | None]] = {}
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
            Path(__file__).resolve().parent.parent / "schemas",
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
        return left is None or right is None or left == right

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
        if superseded and not (
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
                    if not represented_by_parent and (
                        value is group["latest"]
                        if group is not None and group is retained_group
                        else _finding_strength(finding) > _finding_strength(retained)
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
        if superseded and not selected_candidates and not retain_pending:
            continue
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
            if superseded and field not in {"surfaces", "explicitExclusions", "deferred"}:
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
                        continue
                retained = append_coverage_row(output, item, worker_id, field)
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


def _snapshot_published_outputs(
    scan_dir: Path, relative_paths: tuple[str, ...] = _PUBLISHED_OUTPUTS
) -> dict[str, tuple[bytes, os.stat_result] | None]:
    snapshots: dict[str, tuple[bytes, os.stat_result] | None] = {}
    for relative in relative_paths:
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
    scan_dir: Path,
    snapshots: dict[str, tuple[bytes, os.stat_result] | None],
    created_paths: set[str] | None = None,
) -> None:
    for relative, snapshot in snapshots.items():
        if snapshot is None:
            path = scan_dir / relative
            if path.exists() or path.is_symlink():
                _remove_scan_local_file_if_exists(scan_dir, relative)
        else:
            contents, metadata = snapshot
            write_scan_local_bytes(scan_dir, relative, contents)
            os.utime(scan_dir / relative, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    for relative in sorted(created_paths or ()):
        # A journaled write can fail before creating its parent directory.
        path = scan_dir / relative
        if path.exists() or path.is_symlink():
            _remove_scan_local_file_if_exists(scan_dir, relative)


def preserve_deep_deadline_draft(
    db: Any, connection: Any, scan: Any, *, allow_empty: bool = False
) -> tuple[Path, dict[str, tuple[bytes, os.stat_result] | None], set[str]] | None:
    """Recover a settled, zero-accepted Deep deadline without sealing the parent."""
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    snapshots = _snapshot_published_outputs(
        scan_dir, ("findings.json", "coverage.json", "scan-manifest.json", "checkpoint-head.json")
    )
    warnings = json.loads(scan["completion_warnings_json"])
    binding = db.workbench_completion_binding(scan, db.now())
    created_paths: set[str] = set()
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
            project_worker_coverage=True,
            scan_mode="deep",
            finding_scope=db.requested_finding_scope(scan),
            created_paths=created_paths,
            current_contract=True,
            reason=(
                "The configured discovery time limit elapsed before any source review completed. "
                "Saved findings and pending review were preserved without a completed reduction."
            ),
        )
        if documents is None:
            if not allow_empty:
                raise ContractError("Deep Scan deadline has no saved parent draft.")
            _restore_published_outputs(scan_dir, snapshots, created_paths)
            connection.execute(
                "UPDATE scans SET completion_warnings_json = ? WHERE id = ?",
                (json.dumps(list(dict.fromkeys(warnings))), scan["id"]),
            )
            return None
        documents[0]["scan"].pop("complete", None)
        # A capped deadline can retain interrupted records even though its
        # completion binding requires strict validation of completed findings.
        expected_coverage_mode = db.expected_coverage_mode(scan)
        _populate_unsealed_manifest_envelope(documents[0], documents[0]["scan"], binding)
        _populate_unsealed_artifact_envelope(*documents, binding)
        if expected_coverage_mode == "deep_repository":
            documents[2]["inventoryStrategy"] = "repository"
        elif expected_coverage_mode == "scoped_path":
            documents[2]["inventoryStrategy"] = "scoped_path"
        schema_dir = Path(__file__).resolve().parent.parent / "schemas"
        discarded_findings = _recover_unsealed_findings(
            documents[0], documents[1], schema_dir, scan_dir, warnings, current_contract=True
        )
        _recover_unsealed_coverage(documents[2], schema_dir, scan_dir, warnings, discarded_findings)
        # Reuse stopped-result recovery's per-record validation, scope checks,
        # source lineage, and receipt validation before admitting this draft.
        prepared = _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=expected_coverage_mode,
            completion_binding=binding,
            recover_unsealed=True,
            draft_documents=documents,
            finding_scope=db.requested_finding_scope(scan),
        )
        warnings.extend(prepared.warnings)
        manifest, findings, coverage = prepared.manifest, prepared.findings, prepared.coverage
        manifest["scan"].pop("sealedAt", None)
        manifest["scan"].pop("artifacts", None)
        checkpoint = _parent_scan_draft(scan["id"], manifest["scan"], findings, coverage)
        contents = _encoded(checkpoint)
        name = f"{hashlib.sha256(contents).hexdigest()}.json"
        checkpoint_path = f"checkpoints/{name}"
        # This draft is recoverable parent evidence too. Restore its prior state
        # on local publication failure or a later caller transaction rollback.
        snapshots.update(_snapshot_published_outputs(scan_dir, (checkpoint_path,)))
        write_scan_local_bytes(scan_dir, checkpoint_path, contents)
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
    except BaseException:
        _restore_published_outputs(scan_dir, snapshots, created_paths)
        raise
    return scan_dir, snapshots, created_paths


def preserve_scan_results_locked(
    db: Any,
    connection: Any,
    scan_id: str,
    *,
    recovery_source_digests: dict[str, str] | None = None,
    include_parent_with_recovery: bool = False,
) -> bool:
    """Publish or verify retained terminal results through the workbench host."""
    scan = db.require_scan(connection, scan_id)
    if scan["status"] != "failed":
        return False
    frozen_source_digests: dict[str, str] | None = None
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
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    deep_run = connection.execute(
        "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
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
                "completion_warnings_json = ?, "
                "updated_at = ? WHERE id = ? AND status = 'failed'",
                (
                    digest,
                    _encode_retained_sources(retained_sources, model_source),
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
        isinstance(existing_scan, dict) and manifest_is_sealed(existing_scan)
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
            if frozen_source_digests is None:
                frozen_source_digests = _source_digests(
                    existing_sources, "Stopped scan source digests could not be frozen."
                )
            if existing_sources == frozen_source_digests:
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
        connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
            (scan_id,),
        ).fetchall(),
        warnings,
        stopped=True,
        scan_mode=scan["mode"],
        finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
        reason=(
            f"Scan {outcome}; saved findings and pending review were preserved. "
            f"{scan['failure_message'] or ''}"
        ).strip(),
        frozen_source_digests=frozen_source_digests,
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
        recovery_source_digests is None
        and model_source != ([saved_model_source] if saved_model_source is not None else [])
    ):
        retained_sources = _source_digests(
            documents[0].get("scan", {}).get("preservedSources"),
            "Stopped scan source digests could not be frozen.",
        )
        with connection:
            connection.execute(
                "UPDATE scans SET retained_source_digests_json = ? "
                "WHERE id = ? AND retained_source_digests_json IS ?",
                (
                    _encode_retained_sources(retained_sources, model_source),
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
        recovery_source_digests, include_parent = _recovery_source_digests(db, connection, scan)
        if not preserve_scan_results_locked(
            db,
            connection,
            scan_id,
            recovery_source_digests=recovery_source_digests,
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
            if manifest_is_sealed(manifest):
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
        try:
            relative = Path(args.draft_path).relative_to(scan_dir).as_posix()
        except ValueError as exc:
            raise SystemExit(
                "Scan draft must be inside the registered scan drafts directory."
            ) from exc
        if not re.fullmatch(r"drafts/[0-9a-fA-F-]+\.json", relative):
            raise SystemExit("Scan draft must be inside the registered scan drafts directory.")
        draft = _read_scan_local_json(scan_dir, relative, "Staged scan draft")
        accepted_input = copy.deepcopy(draft)
        accepted_checkpoint = None
        manifest, findings, coverage = draft["manifest"], draft["findings"], draft["coverage"]
        binding = db.workbench_completion_binding(scan, db.now())
        # Save scan IDs without sealing the draft.
        _populate_unsealed_manifest_envelope(manifest, manifest["scan"], binding)
        _populate_unsealed_artifact_envelope(manifest, findings, coverage, binding)
        _validate_completion_binding(manifest, findings, coverage, binding)
        projected = _parent_scan_draft(scan_id, manifest["scan"], findings, coverage)
        admitted_input = None
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
            accepted_checkpoint = checkpoint
            if checkpoint.get("scanId") != scan_id:
                raise SystemExit("Staged scan checkpoint belongs to another scan.")
            if scan["mode"] == "deep":
                checkpoint_contents = _admit_parent_checkpoint(
                    scan_dir, scan_id, checkpoint, projected
                )
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
        if scan["mode"] == "deep" and not checkpoint_only:
            _require_current_deep_publication(db, connection, scan, draft)
        acceptance_input = {**accepted_input, "checkpoint": accepted_checkpoint}
        acceptance_relative = Path(relative).with_suffix(".accepted.json").as_posix()
        acknowledge = (
            scan["mode"] == "deep"
            and draft.get("deepScanPublication") is not None
            and db.deep_scan.require_deep_scan_run(connection, scan_id)["workflow_version"]
            in {"deep-scan-mcp/v1", "deep-security-scan/v1"}
        )
        if acknowledge and (scan_dir / acceptance_relative).exists():
            accepted = _read_scan_local_json(scan_dir, acceptance_relative, "Accepted scan draft")
            if (
                accepted.get("status") == "draft_written"
                and accepted.get("input") == acceptance_input
            ):
                if accepted.get("draftDigest") != _scan_draft_digest(scan_dir):
                    raise SystemExit(
                        "scan_draft_conflict: canonical scan results changed after publication."
                    )
                return {
                    "scanId": scan_id,
                    "status": "draft_written",
                    **({"warnings": accepted["warnings"]} if accepted.get("warnings") else {}),
                }
        if (
            args.expected_draft_digest is not None
            and args.expected_draft_digest != _scan_draft_digest(scan_dir)
        ):
            raise SystemExit(
                "scan_draft_conflict: canonical scan results changed; reconcile the saved checkpoint again."
            )
        if checkpoint_contents is not None:
            checkpoint_digest = hashlib.sha256(checkpoint_contents).hexdigest()
            if scan["mode"] == "deep":
                admitted_input = f"{checkpoint_digest}.json"
            write_scan_local_bytes(
                scan_dir,
                f"checkpoints/{checkpoint_digest}.json",
                checkpoint_contents,
            )
            if checkpoint_only:
                return {"scanId": scan_id, "status": "draft_written"}
        projected_contents = _encoded(projected)
        checkpoint_name = f"{hashlib.sha256(projected_contents).hexdigest()}.json"
        checkpoint_relative = f"checkpoints/{checkpoint_name}"
        if not (scan_dir / checkpoint_relative).exists():
            write_scan_local_bytes(scan_dir, checkpoint_relative, projected_contents)
        if checkpoint_only:
            return {"scanId": scan_id, "status": "draft_written"}
        head = {"checkpoint": checkpoint_name}
        if admitted_input is not None:
            head["inputCheckpoint"] = admitted_input
        write_scan_local_bytes(scan_dir, "checkpoint-head.json", _encoded(head))
        documents = {
            filename: (json.dumps(document, allow_nan=False, indent=2) + "\n").encode()
            for filename, document in (
                ("findings.json", findings),
                ("coverage.json", coverage),
                ("scan-manifest.json", manifest),
            )
        }
        for filename, contents in documents.items():
            write_scan_local_bytes(scan_dir, filename, contents)
        if scan["mode"] == "deep" and manifest["scan"].get("complete") is not False:
            # Select the accepted final publication before releasing the write lock.
            with connection:
                connection.execute(
                    "UPDATE deep_scan_runs SET manifest_path = ? "
                    "WHERE scan_id = ? AND status = 'running'",
                    (str(scan_dir / "scan-manifest.json"), scan_id),
                )
        model_warning = write_threat_model_projection_if_possible(scan_dir, manifest)
        if acknowledge:
            # Optional recovery evidence is written only after the publication succeeds.
            try:
                acceptance = {
                    "status": "draft_written",
                    "input": acceptance_input,
                    "draftDigest": _scan_draft_contents_digest(documents),
                    **({"warnings": [model_warning]} if model_warning else {}),
                }
                write_scan_local_bytes(scan_dir, acceptance_relative, _encoded(acceptance))
            except (OSError, ScanLocalIOError):
                # A missing receipt prevents recovery but does not undo accepted results.
                pass
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
    documents: dict[str, bytes | None] = {}
    for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
        try:
            (scan_dir / filename).lstat()
        except FileNotFoundError:
            documents[filename] = None
            continue
        descriptor = open_scan_local_file_descriptor(scan_dir, filename, filename)
        with os.fdopen(descriptor, "rb") as handle:
            documents[filename] = handle.read()
    return _scan_draft_contents_digest(documents)


def _scan_draft_contents_digest(documents: dict[str, bytes | None]) -> str:
    digest = hashlib.sha256()
    for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
        digest.update(filename.encode())
        digest.update(b"\0")
        contents = documents[filename]
        if contents is None:
            digest.update(b"missing\0")
        else:
            digest.update(b"present\0")
            digest.update(contents)
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
        message = db.optional_text(args.message)
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
