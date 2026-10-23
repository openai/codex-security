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
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    ScanLocalIOError,
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
    _require_safe_json_value,
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
    _deferred_rows,
    _merge_tied_parent_observations,
    _parent_observation_content,
    _project_worker_closure,
    _projected_worker_closure_sources,
    _resolved_deferred_rows,
    prepare_saved_coverage_projection,
)
from workbench.saved_coverage import (
    _saved_coverage_id as _saved_coverage_id,
)
from workbench_constants import PHASES
from workbench_coverage_receipts import (
    _deferred_candidate_id,
    _generic_surface_updates,
    receipt_checkpoints,
    resolve_coverage_receipts,
    retain_recorded_receipt_ownership,
)
from workbench_target import committed_diff_snapshot_digest
from workbench_validation import javascript_utf8, path_within_scope

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


from workbench.retained_coverage import (
    _digest as _digest,
)
from workbench.retained_coverage import (
    _encoded as _encoded,
)
from workbench.retained_coverage import (
    _ensure_finding_identity as _ensure_finding_identity,
)
from workbench.retained_coverage import (
    _finding_content as _finding_content,
)
from workbench.retained_coverage import (
    _finding_key as _finding_key,
)
from workbench.retained_coverage import (
    _inherit_coverage_sources as _inherit_coverage_sources,
)
from workbench.retained_coverage import (
    _recover_preserved_worker_coverage,
    _recover_preserved_worker_source,
)
from workbench.retained_coverage import (
    _retained_findings as _retained_findings,
)
from workbench.retained_coverage import (
    _worker_candidate_key as _worker_candidate_key,
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
    _children as _children,
)
from workbench.saved_sources import (
    _encode_retained_sources as _encode_retained_sources,
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
    _read_saved_result as _read_saved_result,
)
from workbench.saved_sources import (
    _retained_source_state as _retained_source_state,
)
from workbench.saved_sources import (
    _source_digests as _source_digests,
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


def _latest_successful_reducer(workers: list[Any]) -> Any | None:
    return max(
        (
            worker
            for worker in workers
            if worker["kind"] == "dedup"
            and worker["status"] == "succeeded"
            and worker["result_manifest_path"]
        ),
        key=lambda worker: (worker["completed_at"] or "", worker["id"]),
        default=None,
    )


def _worker_outputs(scan_dir: Path, worker: Any) -> list[tuple[str, int]]:
    output = Path(worker["artifact_dir"]).relative_to(scan_dir)
    attempts = (output.parent if output.name == "output" else output) / "attempts"
    archived = [
        ((attempts / name).as_posix(), int(name.split("-")[1]))
        for name in _children(scan_dir, attempts.as_posix())
        if re.fullmatch(r"attempt-\d+", name)
    ]
    attempt = int(worker["attempt"] or 0) if "attempt" in worker.keys() else 0
    if worker["kind"] == "discovery" and not attempt:
        attempt = max((attempt for _, attempt in archived), default=0) + 1
    return [(output.as_posix(), attempt), *archived]


def _saved_result_paths(scan_dir: Path, workers: list[Any]) -> Iterator[tuple[str, str | None]]:
    latest_reducer = _latest_successful_reducer(workers)
    yield "checkpoint-head.json", None
    for directory in ("checkpoint-heads", "checkpoints"):
        yield from ((path, None) for path in _checkpoint_paths(scan_dir, directory))
    for worker in workers:
        if worker["kind"] not in {"dedup", "discovery"}:
            continue
        try:
            outputs = _worker_outputs(scan_dir, worker)
        except (TypeError, ValueError):
            continue
        for directory, _ in outputs:
            if worker["kind"] == "discovery":
                yield f"{directory}/checkpoint-head.json", worker["kind"]
                yield from (
                    (path, worker["kind"])
                    for path in _checkpoint_paths(scan_dir, f"{directory}/checkpoint-heads")
                )
            checkpoint_paths = _checkpoint_paths(scan_dir, f"{directory}/checkpoints")
            if worker["kind"] == "discovery" or checkpoint_paths:
                yield f"{directory}/result.json", worker["kind"]
                yield from ((path, worker["kind"]) for path in checkpoint_paths)
        if worker["result_manifest_path"] and (
            worker["kind"] == "discovery"
            or (latest_reducer is not None and worker["id"] == latest_reducer["id"])
        ):
            try:
                yield (
                    Path(worker["result_manifest_path"]).relative_to(scan_dir).as_posix(),
                    worker["kind"],
                )
            except ValueError:
                continue


def _parent_scan_draft(
    scan_id: str,
    parent_scan: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
) -> dict[str, Any]:
    parent = {
        "scanId": scan_id,
        "findings": findings.get("findings"),
        "coverage": coverage,
        **{
            key: parent_scan[key]
            for key in ("scope", "threatModel", "complete")
            if key in parent_scan
        },
    }
    if not isinstance(parent["findings"], list):
        raise ContractError("Saved parent draft has no findings array")
    return parent


def _read_saved_parent_result(
    scan_dir: Path, scan_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "Saved parent manifest")
    findings = _read_scan_local_json(scan_dir, "findings.json", "Saved parent findings")
    coverage = _read_scan_local_json(scan_dir, "coverage.json", "Saved parent coverage")
    parent_scan = manifest.get("scan")
    if not isinstance(parent_scan, dict):
        raise ContractError("Saved parent manifest has no scan object")
    if (parent_scan.get("sealedAt") or parent_scan.get("artifacts")) and (
        parent_scan.get("id", scan_id) != scan_id
        or findings.get("scanId", scan_id) != scan_id
        or coverage.get("scanId", scan_id) != scan_id
    ):
        raise ContractError("Saved parent documents belong to a different scan")
    return manifest, _parent_scan_draft(scan_id, parent_scan, findings, coverage)


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

    for relative in paths.keys() - recovery_sources.keys():
        try:
            captured = _capture_saved_source(scan_dir, relative, scan["id"], kind=paths[relative])
        except (ContractError, OSError, ValueError):
            continue
        for path, (digest, observed) in captured.items():
            if path in recovery_sources and recovery_sources[path] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            recovery_sources[path] = digest
            source_times.setdefault(path, observed)
    _freeze_source_times(scan_dir, scan["id"], recovery_sources, source_times)
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
    try:
        source_times = _frozen_source_times(scan_dir, scan_id, frozen_source_digests or {})
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
    parent: dict[str, Any] | None = None
    frozen_parent_path: str | None = None
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
                    if _parent_observation_content(previous_parent) != _parent_observation_content(
                        parent
                    ):
                        # Tied observations cannot decide which pending work came last.
                        parent = _merge_tied_parent_observations(parent, previous_parent)
                        parent_is_canonical = False
                        tied_observations = True
                snapshot = parent
                if stopped:
                    # Bind the frozen parent even if canonical outputs are lost.
                    snapshot = {
                        **parent,
                        "canonicalParent": parent_is_canonical,
                        "previousParentCheckpoints": [
                            f"checkpoints/{name}"
                            for name in _children(scan_dir, "checkpoints")
                            if re.fullmatch(r"[0-9a-f]{64}\.json", name)
                        ],
                    }
                payload = _encoded(snapshot)
                parent_digest = hashlib.sha256(payload).hexdigest()
                parent_checkpoint = f"checkpoints/{parent_digest}.json"
                checkpoint_path = scan_dir / parent_checkpoint
                if not checkpoint_path.exists():
                    if created_paths is not None and not os.path.lexists(checkpoint_path):
                        created_paths.add(parent_checkpoint)
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
                    captured = _capture_saved_source(
                        scan_dir, "checkpoint-head.json", scan_id, created_paths=created_paths
                    )
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

    discarded_by_source: dict[str, list[str]] = {}
    pending = deque(paths.items())
    while pending:
        relative, worker_id = pending.popleft()
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
            sources.append((relative, {"coverage": {}, **draft}, worker_id))
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

    # Frozen observations keep checkpoint selection after a worker moves its head.
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

    # Keep frozen source digests over the original data, before discarding markers
    # that never passed through the worker draft writer.
    retain_recorded_receipt_ownership(
        sources, _digest, binding["scope"]["includePaths"], finding_scope
    )
    drafts_by_path = {relative: draft for relative, draft, _ in sources}
    if parent is None and frozen_source_digests is not None:
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
                parent_is_canonical = draft.get("canonicalParent") is True
                break
    projected_coverage = parent["coverage"] if parent else {}
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
                parent = draft
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
    if parent is None and latest_reducer is not None:
        parent = drafts_by_path[latest_reducer]

    projected_coverage = saved_parent["coverage"] if saved_parent else {}
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
        id(draft["coverage"]) for relative, draft, _ in sources if relative in accepted_sources
    }
    accepted_surfaces: dict[tuple[str, str], list[tuple[int, dict[str, Any]]]] = {}
    for relative, draft, worker_id in sources:
        if relative not in accepted_sources:
            continue
        surfaces = draft["coverage"].get("surfaces", [])
        for index, surface in enumerate(surfaces if isinstance(surfaces, list) else [], 1):
            if isinstance(surface, dict) and isinstance(surface.get("id"), str):
                accepted_surfaces.setdefault((worker_id, surface["id"]), []).append(
                    (index, surface)
                )

    for _, draft, _ in sources:
        questions = draft["coverage"].get("openQuestions")
        if isinstance(questions, list):
            draft["coverage"]["openQuestions"] = [
                {"question": item.strip()} if isinstance(item, str) else item for item in questions
            ]
    projection_origins = {
        id(item): (worker_id, relative, field, index, draft["coverage"])
        for relative, draft, worker_id in sources
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions")
        for index, item in enumerate(
            draft["coverage"].get(field, [])
            if isinstance(draft["coverage"].get(field, []), list)
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
                    (path, draft["coverage"])
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
                    inferred_coverage_ids.add(id(row))
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
        and all(warning in initial_warnings for warning in warnings)
    ):
        return None

    if (
        frozen_source_digests is None
        or any(_is_source_order_snapshot(path) for path in source_digests)
        or allow_frozen_legacy_parent
    ):
        _freeze_source_times(
            scan_dir, scan_id, source_digests, source_times, created_paths=created_paths
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
    finding_positions: dict[str, int] = {}
    canonical_finding_keys: set[str] = set()
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
            current_contract=current_contract,
        )
        return bool(document["findings"])

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
            rows = draft["coverage"].get(field, [])
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
                projected = project_missing_record(field, row, index, worker, draft["coverage"])
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
        by_id: dict[tuple[str | None, Any], dict[str, Any]] = {}
        candidate_aliases = {
            (source_owner, identity)
            for row in deferred_rows[relative]
            if isinstance(row, dict)
            and any(key in row for key in ("candidateId", "candidate", "finding"))
            for source_owner, original in [record_source("deferred", owner, row)]
            for identity in (original.get("id"), original.get("candidateId"))
            if isinstance(identity, str)
        }
        for row in deferred_rows[relative]:
            if not isinstance(row, dict) or not isinstance(identity := row.get("id"), str):
                continue
            if any(key in row for key in ("candidateId", "candidate", "finding")):
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
        surfaces = draft["coverage"].get("surfaces", [])
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
        Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
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
                            item, coverage_schema["deferred"]["items"], "coverage.deferred"
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
                and not any(key in row for key in ("candidateId", "candidate", "finding"))
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
    resolved: dict[tuple[str | None, str], str] = {}

    ordered_candidates = {
        (owner, identity)
        for owner, row in reopened_rows
        if (identity := _deferred_candidate_id(row, owner, ambiguous_deferred)) is not None
        and (owner, identity) in candidate_ids
    }
    ordered_outcomes: dict[tuple[str | None, str], tuple[tuple[int, int], str]] = {}

    pending_candidate_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    outcomes: list[tuple[str, str | None, str, str, tuple[int, int]]] = []
    for relative, draft, owner in current_drafts:
        reported_candidates = {
            finding_candidate_id(finding)
            for finding in draft["findings"]
            if isinstance(finding, dict) and valid_finding(finding)
        }
        pending_candidates = set()
        for field in ("deferred", "surfaces"):
            items = draft["coverage"].get(field, [])
            for item in items if isinstance(items, list) else []:
                if isinstance(item, dict) and (
                    field == "deferred" or item.get("disposition") == "needs_follow_up"
                ):
                    if (pending := coverage_candidate(owner, item)) is not None:
                        if (
                            owner is not None
                            and pending[0] == owner
                            and pending[1] in reported_candidates
                        ):
                            continue
                        pending_candidates.add(pending)
                        order = candidate_order(relative, pending[0], item)
                        pending_candidate_orders[pending] = max(
                            pending_candidate_orders.get(pending, order), order
                        )
        for finding in draft["findings"]:
            if (
                isinstance(finding, dict)
                and valid_finding(finding)
                and (candidate_id := finding_candidate_id(finding))
            ):
                outcomes.append(
                    (relative, owner, candidate_id, "reported", candidate_order(relative, owner))
                )
        for field in ("surfaces", "explicitExclusions"):
            items = draft["coverage"].get(field, [])
            for item in items if isinstance(items, list) else []:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                    and item.get("disposition") in {"reported", "rejected", "not_applicable"}
                    and (candidate := coverage_candidate(owner, item)) is not None
                    and (item["disposition"] != "reported" or candidate[1] in reported_candidates)
                    and (candidate not in pending_candidates or item["disposition"] == "reported")
                ):
                    outcomes.append(
                        (
                            relative,
                            candidate[0],
                            candidate[1],
                            item["disposition"],
                            candidate_order(relative, candidate[0], item),
                        )
                    )
    ordered_candidates.update(pending_candidate_orders)
    ordered_candidates.update(
        (owner, candidate_id)
        for relative, owner, candidate_id, _, _ in outcomes
        if owner is not None and relative in selected_observations
    )
    # Reopened work and selected checkpoint outcomes follow the saved source order.
    for relative, owner, candidate_id, disposition, order in outcomes:
        key = (owner, candidate_id)
        if pending_surface_orders.get(key, (-1, -1)) >= order:
            continue
        if key not in ordered_candidates:
            if relative == "parent" or relative in current_results:
                resolved.setdefault(key, disposition)
            continue
        if pending_candidate_orders.get(key, (-1, -1)) >= order or any(
            (
                coverage_candidate(saved_owner, row)
                or (saved_owner, _deferred_candidate_id(row, saved_owner, ambiguous_deferred))
            )
            == key
            and saved_order >= order
            for (saved_owner, _), (saved_order, row, _) in active_deferred.items()
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
                        (field == "deferred" and record_key(field, None, row) in closed_deferred)
                        or (
                            coverage_candidate(None, row) in resolved
                            and (field == "deferred" or row.get("disposition") == "needs_follow_up")
                        )
                    )
                )
            ]

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
    fallback_surfaces = projection.fallback_surfaces(
        coverage,
        all_sources,
        deferred_rows,
        reopened_rows,
        selection_for_source=source_coverage_selection,
        row_is_retained=coverage_row_is_retained,
        replaced_deferred=replaced_deferred,
        closed_deferred=closed_deferred,
        ambiguous_surface_ids=ambiguous_surface_ids,
        deferred_is_resolved=lambda owner, row: (
            (owner, _deferred_candidate_id(row, owner, ambiguous_deferred)) in resolved
        ),
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
            previous = parent["coverage"].get(field, [])
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
            reconciled_surface_ids[record_key("surfaces", owner, source_surface)] = surface["id"]
            if surface not in coverage["surfaces"] and (
                surface is original_surface or retained_coverage_record("surfaces", surface) is None
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
                    if preserve_canonical_parent:
                        canonical_finding_keys.add(_finding_key(finding))
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
                if preserve_canonical_parent:
                    rejected_history.setdefault((worker_id, candidate_id), []).append(finding)
                surfaces = coverage.get("surfaces")
                for item in surfaces if isinstance(surfaces, list) else []:
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
                    if (
                        key not in canonical_finding_keys
                        and not represented_by_parent
                        and _finding_strength(finding) > _finding_strength(retained)
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
                        "completeness": draft["coverage"].get("completeness", "partial"),
                    }
                )
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions", "reviews"):
            if field == "reviews" and (worker_id is not None or field not in draft["coverage"]):
                continue
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
            for index, item in enumerate(items, 1):
                source_item = item
                if not coverage_row_is_retained(field, item, worker_id, selection):
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
                projected_row = False
                if isinstance(item, dict):
                    original_item = item
                    item = (
                        project_missing_record(field, item, index, worker, draft["coverage"])
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
                    output, item, worker_id, field, source_item, projected_row or project_coverage
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
    db: Any,
    connection: Any,
    scan: Any,
    *,
    preserve_reduction: bool = False,
    allow_empty: bool = False,
) -> tuple[Path, dict[str, tuple[bytes, os.stat_result] | None], set[str]] | None:
    """Recover unfinished reviews at a settled Deep deadline without sealing the parent."""
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    warnings = json.loads(scan["completion_warnings_json"])
    binding = db.workbench_completion_binding(scan, db.now())
    workers = connection.execute(
        "SELECT * FROM deep_scan_workers WHERE scan_id = ? ORDER BY created_at, id",
        (scan["id"],),
    ).fetchall()
    if preserve_reduction:
        # Completed reviews already went through reduction. Only add evidence
        # from unfinished reviews; raw accepted drafts must not undo that result.
        workers = [
            worker
            for worker in workers
            if worker["kind"] == "discovery" and worker["status"] == "canceled"
        ]
        if not workers:
            return None
        _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            completion_binding=binding,
            allow_missing_writeups=True,
        )
    snapshots = _snapshot_published_outputs(
        scan_dir, ("findings.json", "coverage.json", "scan-manifest.json", "checkpoint-head.json")
    )
    created_paths: set[str] = set()
    try:
        documents = merge_saved_results(
            scan_dir,
            scan["id"],
            binding,
            workers,
            warnings,
            stopped=not preserve_reduction,
            preserve_canonical_parent=preserve_reduction,
            project_worker_coverage=True,
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
        if preserve_reduction:
            marker = {
                "id": "scan-deadline",
                "reason": (
                    "The configured discovery time limit elapsed. Saved findings and "
                    "pending work from unfinished source reviews were preserved."
                ),
            }
            if not any(
                marker["id"] in (row.get("id"), row.get("candidateId"))
                for key in ("deferred", "resolvedDeferred")
                for row in documents[2].get(key, [])
            ):
                documents[2]["deferred"].append(marker)
        documents[0]["scan"].pop("complete", None)
        expected_coverage_mode = db.expected_coverage_mode(scan)
        if not preserve_reduction:
            # A capped deadline can retain interrupted records even though its
            # completion binding requires strict validation of completed findings.
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
            _recover_unsealed_coverage(
                documents[2], schema_dir, scan_dir, warnings, discarded_findings
            )
        # Reuse stopped-result recovery's per-record validation, scope checks,
        # source lineage, and receipt validation before admitting this draft.
        prepared = _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=expected_coverage_mode,
            completion_binding=binding,
            recover_unsealed=not preserve_reduction,
            allow_missing_writeups=preserve_reduction,
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
        reason=(
            f"Scan {outcome}; saved findings and pending review were preserved. "
            f"{scan['failure_message'] or ''}"
        ).strip(),
        frozen_source_digests=frozen_source_digests,
        frozen_model_source=model_source[0] if model_source else None,
        selected_model_source=model_source,
        finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
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
