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
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    _finding_strength,
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
    _validate_completion_binding,
    _validate_schema_node,
    _write_prepared_scan_finalization,
    finalize_scan,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
    write_threat_model_projection_if_possible,
)
from workbench.saved_coverage import (
    _prepare_worker_coverage_recovery,
    _project_worker_coverage_row,
    _saved_coverage_id,
)
from workbench.saved_sources import (
    _checkpoint_head_directory,
    _checkpoint_paths,
    _deferred_candidate_id,
    _deferred_rows,
    _digest,
    _encode_retained_sources,
    _encoded,
    _ensure_finding_identity,
    _finding_content,
    _finding_key,
    _frozen_checkpoint_heads,
    _frozen_source_times,
    _generic_surface_updates,
    _is_source_order_snapshot,
    _latest_successful_reducer,
    _legacy_checkpoint_observed_at,
    _merge_tied_parent_observations,
    _parent_scan_draft,
    _read_saved_parent_result,
    _read_saved_result,
    _resolved_deferred_rows,
    _restore_checkpoint_head,
    _retained_checkpoint_state,
    _retained_findings,
    _retained_source_state,
    _saved_result_paths,
    _source_digests,
    _unselected_root_order,
    _worker_candidate_key,
    _worker_outputs,
)
from workbench.saved_sources import _children as _children
from workbench_constants import PHASES
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


class _CheckpointSnapshotError(ContractError):
    """A captured source observation could not be persisted for publication replay."""

    def __init__(self, message: str, captured: dict[str, tuple[str, int]]) -> None:
        super().__init__(message)
        self.captured = captured
        self.records: dict[str, tuple[dict[str, Any], str, int]] = {}
        self.heads: dict[str, str | None] = {}
        self.model_source: list[str] = []
        self.include_parent = False
        self.documents: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None


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


def _capture_saved_source(
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    snapshot_head: bool = True,
    write: bool = True,
    checkpoint_heads: dict[str, str | None] | None = None,
    expected_digest: str | None = None,
) -> dict[str, tuple[str, int]]:
    if not snapshot_head or Path(relative).name != "checkpoint-head.json":
        _, digest, observed = _read_saved_result(scan_dir, relative, scan_id, kind=kind)
        return {relative: (digest, observed)}
    directory = Path(relative).parent
    head, head_digest, observed = _read_saved_result(scan_dir, relative, scan_id)
    if expected_digest is not None and head_digest != expected_digest:
        raise ContractError("checkpoint changed after the scan stopped")
    observation = {"checkpoint": head["checkpoint"], "observedAtNs": str(observed)}
    selected = (directory / "checkpoints" / observation["checkpoint"]).as_posix()
    selected_draft, selected_digest, selected_time = _read_saved_result(scan_dir, selected, scan_id)
    digest = _digest(observation)
    snapshot = (directory / "checkpoint-heads" / f"{digest}.json").as_posix()
    # Capture the selected file even if it was created after directory enumeration.
    if checkpoint_heads is not None:
        checkpoint_heads[directory.as_posix()] = snapshot
    if write and not (scan_dir / snapshot).exists():
        try:
            write_scan_local_bytes(scan_dir, snapshot, _encoded(observation))
        except (ContractError, OSError) as exc:
            if checkpoint_heads is not None:
                checkpoint_heads[directory.as_posix()] = relative
            failure = _CheckpointSnapshotError(
                str(exc),
                {relative: (head_digest, observed), selected: (selected_digest, selected_time)},
            )
            failure.records = {
                relative: (head, head_digest, observed),
                selected: (selected_draft, selected_digest, selected_time),
            }
            raise failure from exc
    return {
        snapshot: (digest, int(observation["observedAtNs"])),
        selected: (selected_digest, selected_time),
    }


def _freeze_source_times(
    scan_dir: Path, scan_id: str, sources: dict[str, str], times: dict[str, int]
) -> None:
    # Identical result rewrites must not change the order of frozen review evidence.
    observations = {
        path: {"digest": digest, "observedAtNs": str(times[path])}
        for path, digest in sources.items()
        if not _is_source_order_snapshot(path)
    }
    if not observations:
        return
    record = {"scanId": scan_id, "sources": observations}
    digest = _digest(record)
    path = f"source-order/{digest}.json"
    if not (scan_dir / path).exists():
        write_scan_local_bytes(scan_dir, path, _encoded(record))
    if _read_saved_result(scan_dir, path, scan_id)[1] != digest:
        raise ContractError("saved source ordering does not match its digest")
    sources[path] = digest


def _restore_frozen_model_capture(
    scan_dir: Path,
    scan_id: str,
    sources: dict[str, str],
    times: dict[str, int] | None,
    model_source: str | None,
) -> None:
    if model_source not in (times or {}) or (scan_dir / model_source).exists():
        return
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "Saved scan manifest")
    scan = manifest.get("scan")
    if not isinstance(scan, dict) or not isinstance(scan.get("threatModel"), dict):
        return
    draft = _parent_scan_draft(scan_id, {"threatModel": scan["threatModel"]}, {"findings": []}, {})
    digest = _digest(draft)
    if model_source != f"checkpoints/{digest}.json" or sources.get(model_source) != digest:
        return
    # A failed first capture can retry only the model and time bound by that stop.
    write_scan_local_bytes(scan_dir, model_source, _encoded(draft))
    observed = times[model_source]
    os.utime(scan_dir / model_source, ns=(observed, observed))


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
        _, pending_recovery = _retained_checkpoint_state(scan)
        if pending_recovery:
            return True
        published_heads = manifest_scan.get("preservedCheckpointHeads")
        if published_heads is None:
            published_heads = _frozen_checkpoint_heads(
                scan_dir, scan["id"], published_sources, skip_unreadable=True
            )
        elif "." not in published_heads:
            # Older publications recorded root observations without selecting a root head.
            legacy_heads = _frozen_checkpoint_heads(
                scan_dir, scan["id"], published_sources, skip_unreadable=True
            )
            if "." in legacy_heads:
                published_heads = {**published_heads, ".": legacy_heads["."]}
        checkpoint_heads = dict(published_heads)
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
                    checkpoint_heads=checkpoint_heads,
                )
                current_sources.update({path: value[0] for path, value in captured.items()})
                directory = Path(path).parent.as_posix()
                previous_head = published_heads.get(directory)
                if previous_head in captured and Path(previous_head).parent.name == "checkpoints":
                    observed = captured[checkpoint_heads[directory]][1]
                    if observed == _legacy_checkpoint_observed_at(
                        scan_dir, scan["id"], published_sources, previous_head
                    ):
                        checkpoint_heads[directory] = previous_head
            except (ContractError, OSError, ValueError):
                _restore_checkpoint_head(checkpoint_heads, published_heads, published_sources, path)
        return current_sources != published_sources or checkpoint_heads != published_heads
    except (ContractError, OSError, SystemExit, ValueError):
        return False


def _recovery_source_digests(
    db: Any, connection: Any, scan: Any
) -> tuple[dict[str, str], bool, dict[str, str | None]]:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    frozen_sources: dict[str, str] | None = None
    include_parent = True
    raw_frozen_sources = scan["retained_source_digests_json"]
    if raw_frozen_sources is not None:
        retained = json.loads(raw_frozen_sources)
        frozen_sources, model_source = _retained_source_state(retained)
        if isinstance(retained.get("sources"), dict) and retained.get("sourceTimes") is not None:
            _restore_frozen_model_capture(
                scan_dir, scan["id"], frozen_sources, retained["sourceTimes"], model_source
            )
            _freeze_source_times(scan_dir, scan["id"], frozen_sources, retained["sourceTimes"])
        include_parent = False
    checkpoint_heads, pending_recovery = _retained_checkpoint_state(scan)
    if pending_recovery:
        return frozen_sources, False, checkpoint_heads

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
        if scan["seal_manifest_digest"] is not None or (
            manifest_scan.get("sealedAt") is not None or manifest_scan.get("artifacts") is not None
        ):
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
    previous_heads = checkpoint_heads
    if previous_heads is None:
        previous_heads = _frozen_checkpoint_heads(scan_dir, scan["id"], frozen_sources or {})
    checkpoint_heads = dict(previous_heads)
    paths = dict(_saved_result_paths(scan_dir, workers))
    recovery_sources = dict(frozen_sources or {})
    source_times = _frozen_source_times(scan_dir, scan["id"], recovery_sources)
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

    snapshot_error = None
    captured_records = {}
    for relative in paths.keys() - recovery_sources.keys():
        try:
            captured = _capture_saved_source(
                scan_dir,
                relative,
                scan["id"],
                kind=paths[relative],
                checkpoint_heads=checkpoint_heads,
            )
        except _CheckpointSnapshotError as exc:
            snapshot_error = snapshot_error or exc
            captured = exc.captured
            captured_records.update(exc.records)
        except (ContractError, OSError, ValueError):
            _restore_checkpoint_head(
                checkpoint_heads, previous_heads, frozen_sources or {}, relative
            )
            continue
        for path, (digest, observed) in captured.items():
            if path in recovery_sources and recovery_sources[path] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            recovery_sources[path] = digest
            source_times.setdefault(path, observed)
    try:
        if snapshot_error is not None:
            raise snapshot_error
        _freeze_source_times(scan_dir, scan["id"], recovery_sources, source_times)
    except (ContractError, OSError) as exc:
        failure = _CheckpointSnapshotError(
            str(exc),
            {
                path: (digest, source_times[path])
                for path, digest in recovery_sources.items()
                if not _is_source_order_snapshot(path)
            },
        )
        failure.records = captured_records
        failure.heads = checkpoint_heads
        failure.include_parent = include_parent
        raise failure from exc
    return recovery_sources, include_parent, checkpoint_heads


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
    frozen_source_digests: dict[str, str] | None = None,
    checkpoint_heads: dict[str, str | None] | None = None,
    allow_frozen_legacy_parent: bool = False,
    frozen_model_source: str | None = None,
    selected_model_source: list[str] | None = None,
    canonical_model: dict[str, Any] | None = None,
    canonical_model_source: str | None = None,
    canonical_sources: dict[str, str] | None = None,
    project_worker_coverage: bool = False,
    recovery_snapshot_error: _CheckpointSnapshotError | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Read only bound parent/worker files; return an unsealed loss-preserving union."""
    initial_warnings = set(warnings)
    if frozen_source_digests is None:
        checkpoint_heads = {}
    snapshot_error = recovery_snapshot_error
    captured_records = dict(snapshot_error.records) if snapshot_error is not None else {}

    def capture_head(relative: str) -> dict[str, tuple[str, int]]:
        nonlocal snapshot_error
        try:
            return _capture_saved_source(
                scan_dir, relative, scan_id, checkpoint_heads=checkpoint_heads
            )
        except _CheckpointSnapshotError as exc:
            # Finish selection from captured bytes before freezing an I/O failure.
            snapshot_error = snapshot_error or exc
            captured_records.update(exc.records)
            return exc.captured

    try:
        source_times = (
            {path: observation[1] for path, observation in snapshot_error.captured.items()}
            if snapshot_error is not None
            else _frozen_source_times(scan_dir, scan_id, frozen_source_digests or {})
        )
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
    parent: dict[str, Any] | None = None
    parent_manifest: dict[str, Any] | None = None
    parent_is_canonical = False
    parent_modified = 0
    parent_model_source: str | None = None
    canonical_model_order: tuple[int, int] | None = None
    canonical_model_digest: str | None = None
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
                if isinstance(parent.get("threatModel"), dict):
                    canonical_model_source = parent_checkpoint
                    parent_model_source = parent_checkpoint
                    canonical_model_order = (0, parent_modified)
                    canonical_model_digest = parent_digest
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
                    observed = max(parent_modified, checkpoint_path.lstat().st_mtime_ns)
                    os.utime(head_path, ns=(observed, observed))
                if frozen_source_digests is not None:
                    captured = capture_head("checkpoint-head.json")
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
                captured = capture_head(relative)
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
                continue
            if checkpoint_heads is not None and directory.as_posix() in checkpoint_heads:
                if checkpoint_heads[directory.as_posix()] is None:
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

    if checkpoint_heads is None:
        checkpoint_heads = _frozen_checkpoint_heads(scan_dir, scan_id, source_digests)
    heads_snapshotted = False
    if frozen_source_digests is not None and snapshot_error is None:
        # Raw heads are a temporary fallback, not permanent publication sources.
        for relative in list(saved_heads):
            if Path(relative).name != "checkpoint-head.json":
                continue
            captured = _capture_saved_source(
                scan_dir, relative, scan_id, expected_digest=source_digests[relative]
            )
            for path, (digest, observed) in captured.items():
                if path in source_digests and source_digests[path] != digest:
                    raise ContractError("checkpoint changed after the scan stopped")
                source_digests[path] = digest
                source_times.setdefault(path, observed)
                if _checkpoint_head_directory(path) is not None:
                    saved_heads[path] = saved_heads[relative]
                    source_order[path] = (0, observed)
                    key = Path(relative).parent.as_posix()
                    if checkpoint_heads.get(key) == relative:
                        checkpoint_heads[key] = path
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

    drafts_by_path = {relative: draft for relative, draft, _ in sources}
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
                parent_model_source = parent_path
                parent_modified = modified
                parent_is_canonical = False
            elif modified == parent_modified and draft != parent:
                parent = _merge_tied_parent_observations(parent, draft)
                parent_is_canonical = False
    if parent is None and latest_reducer is not None:
        parent = drafts_by_path[latest_reducer]
        parent_model_source = latest_reducer

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

    pending_surface_ids: set[tuple[str | None, str]] = set()

    def retain_surface_links(owner: str | None, row: Any) -> None:
        if not isinstance(row, dict):
            return
        links = row.get("surfaceIds", [])
        for identity in [row.get("id"), *(links if isinstance(links, list) else [])]:
            if isinstance(identity, str):
                pending_surface_ids.add((owner, identity))

    def append_coverage_row(output: list[Any], item: Any, owner: str | None, field: str) -> Any:
        if field == "deferred":
            retain_surface_links(owner, item)
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
    model_schema = _read_json(
        Path(__file__).resolve().parent.parent / "schemas" / "scan-manifest.schema.json"
    )

    def valid_model(model: Any) -> bool:
        if not isinstance(model, dict):
            return False
        try:
            _validate_schema_node(
                model,
                model_schema["properties"]["scan"]["properties"]["threatModel"],
                "manifest.scan.threatModel",
                model_schema,
            )
        except ContractError:
            return False
        return True

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
        if (
            selected_model_source is not None
            and isinstance(parent.get("threatModel"), dict)
            and parent_model_source in drafts_by_path
            and (
                parent_model_source != canonical_model_source
                or canonical_model_digest is None
                or source_digests[parent_model_source] == canonical_model_digest
            )
        ):
            selected_model_source[:] = [parent_model_source]
        if isinstance(manifest["scan"].get("scope"), dict):
            manifest["scan"]["scope"].update(copy.deepcopy(binding["scope"]))
    if frozen_model_source is None and not isinstance((parent or {}).get("threatModel"), dict):
        # Model fallback is independent of whether older findings are superseded.
        canonical_model = manifest["scan"].get("threatModel", canonical_model)
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
            and valid_model(drafts_by_path[canonical_model_source].get("threatModel"))
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
            and valid_model(drafts_by_path[path].get("threatModel"))
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
            if (
                stopped
                and frozen_source_digests is None
                and canonical_model_source is None
                and valid_model(canonical_model)
            ):
                # An unreadable canonical checkpoint must not leave a valid
                # inherited model dependent on live files after the first stop.
                model_draft = _parent_scan_draft(
                    scan_id, {"threatModel": canonical_model}, {"findings": []}, {}
                )
                digest = _digest(model_draft)
                canonical_model_source = f"checkpoints/{digest}.json"
                observed = (canonical_model_order or (0, parent_modified))[1]
                source_digests[canonical_model_source] = digest
                source_times[canonical_model_source] = observed
                try:
                    if not (scan_dir / canonical_model_source).exists():
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
                        # Keep valid evidence.
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

    outcomes: list[tuple[str, dict[str, Any], str | None, str, str]] = []
    for relative, draft, owner in current_drafts:
        for finding in draft["findings"]:
            if (
                isinstance(finding, dict)
                and valid_finding(finding)
                and (candidate_id := finding_candidate_id(finding))
            ):
                outcomes.append((relative, draft, owner, candidate_id, "reported"))
        for field in ("surfaces", "explicitExclusions"):
            items = draft["coverage"].get(field, [])
            for item in items if isinstance(items, list) else []:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                    and item.get("disposition") in {"rejected", "not_applicable"}
                ):
                    normalized = dict(item)
                    if field == "surfaces":
                        normalized.setdefault("id", _saved_coverage_id(item))
                        normalized.setdefault("receiptRefs", [])
                    if field == "surfaces":
                        verified = {
                            "completeness": "partial",
                            "surfaces": [normalized],
                            "explicitExclusions": [],
                            "deferred": [],
                        }
                        _recover_unsealed_coverage(
                            verified,
                            Path(__file__).resolve().parent.parent / "schemas",
                            scan_dir,
                            [],
                            [],
                        )
                        if (
                            not verified["surfaces"]
                            or verified["surfaces"][0]["disposition"] != item["disposition"]
                        ):
                            continue
                        normalized = verified["surfaces"][0]
                    try:
                        _validate_schema_node(
                            normalized, coverage_schema[field]["items"], f"coverage.{field}"
                        )
                    except ContractError:
                        continue
                    outcomes.append(
                        (relative, draft, owner, item["candidateId"], item["disposition"])
                    )
    ordered_candidates.update(
        (owner, candidate_id)
        for relative, _, owner, candidate_id, _ in outcomes
        if relative in selected_observations
    )
    selected_head_candidates = {
        (Path(relative).parent, candidate_id)
        for relative, _, _, candidate_id, _ in outcomes
        if relative in authoritative_heads
    }
    other_root_order = _unselected_root_order(saved_heads, checkpoint_heads, source_order)
    # A selected partial draft can leave independent historical outcomes intact.
    for relative, draft, owner, candidate_id, disposition in outcomes:
        if (
            relative in selected_observations
            and relative not in authoritative_heads
            and relative not in current_results
            and (Path(relative).parent, candidate_id) in selected_head_candidates
        ):
            continue
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
            and (
                modified > order
                or owner is not None
                or accepted_deferred_orders.get((saved_owner, identity)) == modified
                or draft.get("complete") is False
                or (relative != "parent" and relative not in authoritative_heads)
                or other_root_order >= order
            )
            for (saved_owner, identity), (modified, row, _) in active_deferred.items()
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
                    relative in checkpoint_heads.values() or relative in authoritative_observations
                )
            )
        ):
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
    selected_terminal_orders: dict[str | None, tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if relative in authoritative_heads and draft.get("complete") is not False:
            order = source_order[relative]
            selected_terminal_orders[worker_id] = max(
                selected_terminal_orders.get(worker_id, order), order
            )
    terminal_worker_orders: dict[str | None, tuple[int, int]] = {}
    prior_terminal_orders: dict[str | None, tuple[int, int]] = {}
    partial_head_orders = {
        Path(path).parent: selected_observations[path]
        for path in authoritative_heads
        if drafts_by_path[path].get("complete") is False
    }
    for relative, draft, worker_id in sources:
        if relative in current_results and draft.get("complete") is not False:
            order = source_order[relative]
            terminal_worker_orders[worker_id] = max(
                terminal_worker_orders.get(worker_id, order), order
            )
    for head, checkpoint in saved_heads.items():
        directory = _checkpoint_head_directory(head)
        relative = (directory / "checkpoints" / checkpoint).as_posix()
        partial_order = partial_head_orders.get(Path(relative).parent)
        if partial_order is None:
            continue
        order = (partial_order[0], source_order[head][1])
        if drafts_by_path[relative].get("complete") is not False and order <= partial_order:
            # A partial head adds coverage after the preceding terminal replacement.
            worker_id = paths[relative]
            prior_terminal_orders[worker_id] = max(
                prior_terminal_orders.get(worker_id, order), order
            )

    def source_coverage_selection(
        relative: str,
        worker_id: str | None,
    ) -> tuple[bool, set[str], bool, bool]:
        worker_result_order = terminal_worker_orders.get(worker_id)
        selected_terminal_order = selected_terminal_orders.get(worker_id)
        terminal_coverage_order = max(
            (
                order
                for order in (
                    worker_result_order,
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
                    and (owner, row["id"]) in closed_deferred
                )
            ):
                prospective_tasks.append((owner, row))
    prospective_tasks.extend(
        (owner, row)
        for owner, row in reopened_rows
        if (owner, _deferred_candidate_id(row, owner, ambiguous_deferred)) not in resolved
    )
    for owner, row in prospective_tasks:
        retain_surface_links(owner, row)
    if parent and isinstance(coverage.get("deferred"), list):
        previous = parent["coverage"].get("deferred", [])
        removed_parent = (
            [row for row in previous if id(row) in replaced_deferred]
            if isinstance(previous, list)
            else []
        )
        for row in coverage["deferred"]:
            if row not in removed_parent:
                retain_surface_links(None, row)

    def surface_is_retained(relative: str, owner: str | None, row: Any) -> bool:
        selection = source_coverage_selection(relative, owner)
        if (
            isinstance(row, dict)
            and isinstance(row.get("id"), str)
            and (owner, row["id"]) in pending_surface_ids
        ):
            selection = (False, *selection[1:])
        return coverage_row_is_retained("surfaces", row, owner, selection)

    fallback_surfaces = []
    if surface_links and isinstance(coverage.get("surfaces"), list):
        # Plan the surviving associations before historical receipts can claim
        # a spelling needed by a surface that must be restored for its task.
        prospective_tasks = [
            (owner, _project_worker_coverage_row(row, owner, "deferred"))
            for owner, row in prospective_tasks
        ]
        prospective_surfaces = {}
        prospective_named = {}
        for relative, draft, owner in all_sources:
            rows = draft["coverage"].get("surfaces", [])
            for row in rows if isinstance(rows, list) else []:
                if owner is None or not isinstance(row, dict):
                    continue
                emitted = surface_is_retained(relative, owner, row)
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
        surface_is_retained=surface_is_retained,
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
    suppressed_surfaces: list[tuple[str | None, dict[str, Any]]] = []
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
            and (
                relative in authoritative_heads
                or relative in current_results
                or valid_model(draft.get("threatModel"))
            )
        ):
            model = draft["threatModel"]
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
                    and (
                        path in authoritative_heads
                        or path in current_results
                        or valid_model(drafts_by_path[path].get("threatModel"))
                    )
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
                        prefer_checkpoint_head = source_order[head_path] >= source_order[relative]
                    if prefer_checkpoint_head:
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
                suppress_coverage = (
                    selected_coverage_superseded
                    and field == "surfaces"
                    and isinstance(item, dict)
                    and not any(key in item for key in ("candidateId", "candidate", "finding"))
                )
                row_selection = (
                    (False, selected_candidates, superseded, retain_pending)
                    if suppress_coverage
                    else selection
                )
                if not coverage_row_is_retained(field, item, worker_id, row_selection):
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
                    if suppress_coverage:
                        suppressed_surfaces.append((worker_id, item))
                        continue
                if field == "deferred":
                    retain_surface_links(worker_id, item)
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

    # Deferred work retains its supporting surface even when ordinary coverage
    # from that checkpoint was replaced by a selected terminal observation.
    for owner, surface in suppressed_surfaces:
        if (
            isinstance(surface.get("id"), str)
            and (owner, surface["id"]) in pending_surface_ids
            and surface not in coverage["surfaces"]
        ):
            append_coverage_row(coverage["surfaces"], surface, owner, "surfaces")

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
            _freeze_source_times(scan_dir, scan_id, source_digests, source_times)
        except (ContractError, OSError) as exc:
            failure = _CheckpointSnapshotError(
                str(exc),
                {
                    path: (digest, source_times[path])
                    for path, digest in source_digests.items()
                    if not _is_source_order_snapshot(path)
                },
            )
            failure.heads = checkpoint_heads
            failure.documents = (manifest, {"findings": findings}, coverage)
            if valid_model(manifest["scan"].get("threatModel")):
                failure.model_source = list(selected_model_source or [])
            raise failure from exc

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
    recovery_checkpoint_heads: dict[str, str | None] | None = None,
    include_parent_with_recovery: bool = False,
    recovery_snapshot_error: _CheckpointSnapshotError | None = None,
) -> bool:
    """Publish or verify retained terminal results through the workbench host."""
    scan = db.require_scan(connection, scan_id)
    if scan["status"] != "failed":
        return False
    frozen_source_digests: dict[str, str] | None = None
    checkpoint_heads, pending_recovery = _retained_checkpoint_state(scan)
    model_source: list[str] = []
    saved_model_source: str | None = None
    raw_frozen_sources = scan["retained_source_digests_json"]
    frozen_source_times = None
    if raw_frozen_sources is not None:
        retained = json.loads(raw_frozen_sources)
        frozen_source_digests, saved_model_source = _retained_source_state(retained)
        if isinstance(retained.get("sources"), dict):
            frozen_source_times = retained.get("sourceTimes")
        if saved_model_source is not None:
            model_source.append(saved_model_source)
    canonical_sources = frozen_source_digests
    if recovery_source_digests is not None:
        frozen_source_digests = recovery_source_digests
        checkpoint_heads = recovery_checkpoint_heads
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    if frozen_source_digests is not None:
        _restore_frozen_model_capture(
            scan_dir, scan_id, frozen_source_digests, frozen_source_times, saved_model_source
        )
    if frozen_source_times is not None and recovery_source_digests is None:
        _freeze_source_times(scan_dir, scan_id, frozen_source_digests, frozen_source_times)
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
            existing_heads = existing_scan.get("preservedCheckpointHeads")
            if frozen_source_digests is None:
                frozen_source_digests = _source_digests(
                    existing_sources, "Stopped scan source digests could not be frozen."
                )
                checkpoint_heads = existing_heads
            unchanged = existing_sources == frozen_source_digests and (
                existing_heads == checkpoint_heads
                or (
                    "preservedCheckpointHeads" not in existing_scan
                    and recovery_source_digests is None
                    and not pending_recovery
                )
            )
            if unchanged and not any(
                Path(path).name == "checkpoint-head.json" for path in frozen_source_digests
            ):
                if (
                    raw_frozen_sources is not None
                    and scan["seal_manifest_digest"] is not None
                    and not publication_follow_up_warnings
                    and warnings == stored_warnings
                ):
                    return True
                record_publication(existing, existing_findings)
                return True
            if not unchanged and recovery_source_digests is None and not pending_recovery:
                raise ContractError("Stopped scan sources changed after terminal publication.")
    binding = {
        **db.workbench_completion_binding(scan, scan["completed_at"], existing),
        "status": outcome,
    }
    canonical_model_source = saved_model_source
    canonical_model = existing_scan.get("threatModel") if isinstance(existing_scan, dict) else None
    if existing is None and frozen_source_digests is not None:
        # An unsealed live draft is a fallback only when its complete identity
        # belongs to the frozen set. Otherwise recover from the captured sources.
        canonical_model = None
        try:
            _, canonical_draft = _read_saved_parent_result(scan_dir, scan_id)
            digest = _digest(canonical_draft)
            path = f"checkpoints/{digest}.json"
            if frozen_source_digests.get(path) == digest:
                canonical_model_source = path
                canonical_model = canonical_draft.get("threatModel")
        except (ContractError, OSError, ValueError):
            # This live fallback is optional.
            pass
    if recovery_source_digests is not None and not pending_recovery:
        model_source.clear()
    try:
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
            reason=(
                f"Scan {outcome}; saved findings and pending review were preserved. "
                f"{scan['failure_message'] or ''}"
            ).strip(),
            frozen_source_digests=frozen_source_digests,
            checkpoint_heads=checkpoint_heads,
            frozen_model_source=model_source[0] if model_source else None,
            selected_model_source=model_source,
            project_worker_coverage=scan["mode"] == "deep",
            canonical_model=canonical_model,
            canonical_model_source=canonical_model_source,
            canonical_sources=canonical_sources,
            recovery_snapshot_error=recovery_snapshot_error,
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
    except _CheckpointSnapshotError as exc:
        if frozen_source_digests is None or recovery_snapshot_error is not None:
            # The stop has already committed. Keep the source set and times in
            # the database even when auxiliary snapshot files cannot be written.
            # Changed raw heads remain rejected on retry.
            captured = exc.captured
            retained_sources = {path: value[0] for path, value in captured.items()}
            source_times = {path: value[1] for path, value in captured.items()}
            retained_heads = exc.heads
            if recovery_snapshot_error is not None:
                _prepare_scan_finalization(
                    scan_dir,
                    expected_coverage_mode=db.expected_coverage_mode(scan),
                    completion_binding=binding,
                    recover_unsealed=True,
                    draft_documents=exc.documents,
                    finding_scope=db.requested_finding_scope(scan)
                    if scan["mode"] == "deep"
                    else None,
                )
                retained_heads = {
                    "heads": retained_heads,
                    "recoveryBaseDigest": scan["seal_manifest_digest"],
                }
            with connection:
                connection.execute(
                    "UPDATE scans SET retained_source_digests_json = ?, "
                    "retained_checkpoint_heads_json = ?, completion_warnings_json = ? "
                    "WHERE id = ? AND retained_source_digests_json IS ?",
                    (
                        _encode_retained_sources(retained_sources, exc.model_source, source_times),
                        json.dumps(retained_heads, sort_keys=True),
                        json.dumps(list(dict.fromkeys(warnings))),
                        scan_id,
                        raw_frozen_sources,
                    ),
                )
        raise
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
    retained_state = None
    if (
        frozen_source_digests is None
        or scan["retained_checkpoint_heads_json"] is None
        or recovery_source_digests is not None
        or documents[0]["scan"]["preservedSources"] != frozen_source_digests
        or (saved_model_source is None and model_source)
    ):
        retained_sources = _source_digests(
            documents[0].get("scan", {}).get("preservedSources"),
            "Stopped scan source digests could not be frozen.",
        )
        retained_heads = documents[0]["scan"]["preservedCheckpointHeads"]
        if (
            recovery_source_digests is not None
            or pending_recovery
            or (existing is not None and existing_scan.get("status") == outcome)
        ):
            retained_heads = {
                "heads": retained_heads,
                "recoveryBaseDigest": scan["seal_manifest_digest"],
            }
        retained_state = (
            _encode_retained_sources(retained_sources, model_source),
            json.dumps(retained_heads, sort_keys=True),
            json.dumps(list(dict.fromkeys(warnings))),
            scan_id,
            raw_frozen_sources,
        )

    def retain_sources() -> None:
        if retained_state is not None:
            with connection:
                connection.execute(
                    "UPDATE scans SET retained_source_digests_json = ?, "
                    "retained_checkpoint_heads_json = ?, completion_warnings_json = ? "
                    "WHERE id = ? AND retained_source_digests_json IS ?",
                    retained_state,
                )

    first_preservation = recovery_source_digests is None and not pending_recovery
    if first_preservation:
        retain_sources()
    prepared = _prepare_scan_finalization(
        scan_dir,
        expected_coverage_mode=db.expected_coverage_mode(scan),
        completion_binding=binding,
        recover_unsealed=True,
        draft_documents=documents,
        finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
    )
    if not first_preservation:
        retain_sources()
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
        recovery_snapshot_error = None
        try:
            recovery_source_digests, include_parent, checkpoint_heads = _recovery_source_digests(
                db, connection, scan
            )
        except _CheckpointSnapshotError as exc:
            recovery_snapshot_error = exc
            recovery_source_digests = {path: value[0] for path, value in exc.captured.items()}
            include_parent = exc.include_parent
            checkpoint_heads = exc.heads
        if not preserve_scan_results_locked(
            db,
            connection,
            scan_id,
            recovery_source_digests=recovery_source_digests,
            recovery_checkpoint_heads=checkpoint_heads,
            include_parent_with_recovery=include_parent,
            recovery_snapshot_error=recovery_snapshot_error,
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


def _require_current_deep_publication(
    db: Any, connection: Any, scan: Any, draft: dict[str, Any]
) -> None:
    scan_id = scan["id"]
    run = connection.execute(
        "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    publication = draft.get("deepScanPublication")
    if (
        publication is None
        and draft["manifest"]["scan"].get("complete") is False
        and (run is None or run["status"] == "running")
    ):
        return
    if run is None:
        run = db.deep_scan.require_deep_scan_run(connection, scan_id)
    # Finished discovery-only runs hand remaining publication back to the parent.
    if (
        publication is None
        and run["status"] != "running"
        and run["manifest_path"] != str(Path(scan["scan_dir"]) / "scan-manifest.json")
    ):
        return
    db.deep_scan.require_current_coordinator(
        run,
        argparse.Namespace(
            coordinator_generation=publication.get("coordinatorGeneration") if publication else None
        ),
    )
    # Once finish selects the canonical parent, only completion may replay it.
    if publication is None:
        if run["status"] != "running" and run["manifest_path"] == str(
            Path(scan["scan_dir"]) / "scan-manifest.json"
        ):
            raise SystemExit("Deep Scan is terminal; drafts cannot replace its publication.")
        return

    # Match the durable reducer sequence used by coordinator recovery.
    def reducer_order(worker: Any) -> tuple[int, str]:
        match = re.fullmatch(r"dedup-([0-9]+)", Path(worker["prompt_path"]).parent.name)
        return (int(match[1]) if match else 0, worker["id"])

    reducer = max(
        (
            worker
            for worker in connection.execute(
                "SELECT * FROM deep_scan_workers WHERE scan_id = ?", (scan_id,)
            )
            if worker["kind"] == "dedup"
            and worker["status"] == "succeeded"
            and worker["result_manifest_path"]
        ),
        key=reducer_order,
        default=None,
    )
    selected_result = reducer["result_manifest_path"] if reducer is not None else None
    if publication["resultPath"] != selected_result:
        raise SystemExit("Deep Scan aggregate belongs to a superseded publication selection.")


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
        try:
            relative = Path(args.draft_path).relative_to(scan_dir).as_posix()
        except ValueError as exc:
            raise SystemExit(
                "Scan draft must be inside the registered scan drafts directory."
            ) from exc
        if not re.fullmatch(r"drafts/[0-9a-fA-F-]+\.json", relative):
            raise SystemExit("Scan draft must be inside the registered scan drafts directory.")
        draft = _read_scan_local_json(scan_dir, relative, "Staged scan draft")
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
        if scan["mode"] == "deep" and not checkpoint_only:
            _require_current_deep_publication(db, connection, scan, draft)
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
