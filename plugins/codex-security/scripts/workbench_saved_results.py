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
    _populate_unsealed_artifact_envelope,
    _populate_unsealed_manifest_envelope,
    _prepare_scan_finalization,
    _read_saved_threat_model,
    _read_scan_local_json,
    _read_scan_local_json_bytes,
    _remove_scan_local_file_if_exists,
    _validate_completion_binding,
    _write_prepared_scan_finalization,
    finalize_scan,
    manifest_is_sealed,
    open_scan_local_file_descriptor,
    parse_timestamp,
    write_scan_local_bytes,
    write_threat_model_projection_if_possible,
)
from finalize_scan_contract import finding_candidate_id as finding_candidate_id
from project_scan_artifacts import child_review_state, merge_coverage, project_scan_artifacts
from report_projection import retained_findings
from review_state import checkpoint_review_state, review_summary
from workbench.retained_coverage import merge_saved_results as merge_saved_results
from workbench.saved_coverage import (
    _saved_coverage_id as _saved_coverage_id,
)
from workbench.saved_outputs import _restore_published_outputs, _snapshot_published_outputs
from workbench.saved_sources import (
    _capture_saved_source,
    _checkpoint_paths,
    _CheckpointSnapshotError,
    _encode_retained_sources,
    _encoded,
    _freeze_source_times,
    _frozen_checkpoint_heads,
    _frozen_source_times,
    _is_source_order_snapshot,
    _legacy_checkpoint_observed_at,
    _parent_scan_draft,
    _read_saved_parent_result,
    _read_saved_result,
    _restore_checkpoint_head,
    _restore_frozen_model_capture,
    _retained_checkpoint_state,
    _retained_source_state,
    _saved_result_paths,
    _source_digests,
)
from workbench.saved_sources import (
    _digest as _digest,
)
from workbench.storage import saved_deep_workers
from workbench_composition import COMPOSITION_CHECKPOINT, CompositionView, load_composition
from workbench_constants import PHASES
from workbench_coverage_receipts import (
    _generic_surface_updates as _generic_surface_updates,
)
from workbench_scan_start import require_deep_pass_target, stored_scan_target_identity
from workbench_scan_usage import merge_scan_cost

_PUBLICATION_FOLLOW_UP_WARNING = (
    "Saved scan evidence remains on disk; result publication needs follow-up:"
)
_RESERVED_ARTIFACT_PATHS = json.loads(
    Path(__file__).with_name("reserved_artifact_paths.json").read_text(encoding="utf-8")
)


def threat_model_fields(db: Any, scan: sqlite3.Row) -> dict[str, Any]:
    """Return availability and provenance for a saved threat model, reporting it as unavailable when verification fails."""
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
        workers = saved_deep_workers(connection, scan)
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
                if (
                    Path(path).name == "checkpoint-head.json"
                    and previous_head in captured
                    and Path(previous_head).parent.name == "checkpoints"
                ):
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
            _freeze_source_times(
                scan_dir,
                scan["id"],
                frozen_sources,
                retained["sourceTimes"],
                retained.get("parentContext"),
            )
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

    if frozen_sources is None:
        save_composed_checkpoint(db, connection, scan, scan_dir, load_composition(connection, scan))

    workers = saved_deep_workers(connection, scan)
    previous_heads = checkpoint_heads
    if previous_heads is None:
        previous_heads = _frozen_checkpoint_heads(scan_dir, scan["id"], frozen_sources or {})
    checkpoint_heads = dict(previous_heads)
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
        if relative == "checkpoint-head.json":
            parent_context["head"] = next(iter(captured))
        for path, (digest, observed) in captured.items():
            if path in recovery_sources and recovery_sources[path] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            recovery_sources[path] = digest
            source_times.setdefault(path, observed)
    try:
        if snapshot_error is not None:
            raise snapshot_error
        _freeze_source_times(scan_dir, scan["id"], recovery_sources, source_times, parent_context)
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
        failure.parent_context = parent_context
        raise failure from exc
    return recovery_sources, include_parent, checkpoint_heads


def scan_results_recovery_needed(db: Any, connection: Any, scan: Any) -> bool:
    """Return whether a failed, uncanceled scan has a publication error or saved evidence to recover."""
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


def coverage_for_comparison(db: Any, scan: Any) -> dict[str, Any]:
    """Return coverage from the verified, sealed scan or raise SystemExit if the stored scan cannot be matched."""
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


def _stopped_child_draft(
    db: Any, connection: Any, child: Any, scan_dir: Path
) -> dict[str, Any] | None:
    """Read one ordinary saved scan through its normal validation and recovery path."""
    child_dir = db.require_canonical_scan_directory(Path(child["scan_dir"]))
    manifest_path = db.artifact_path(child_dir, "scan-manifest.json", required=False)
    manifest_scan = db.read_json_object(manifest_path).get("scan", {}) if manifest_path else {}
    if child["seal_manifest_digest"] is not None or (
        manifest_scan.get("sealedAt") is not None or manifest_scan.get("artifacts") is not None
    ):
        db.require_recorded_manifest_digest(child, child_dir)
        prepared = _prepare_scan_finalization(child_dir)
    else:
        binding = {**db.workbench_completion_binding(child, db.now()), "status": "interrupted"}
        warnings: list[str] = []
        documents = merge_saved_results(
            child_dir,
            child["id"],
            binding,
            [],
            warnings,
            stopped=True,
            scan_mode=child["mode"],
            reason="Independent scan stopped before aggregation.",
            finding_scope=db.requested_finding_scope(child) if child["mode"] == "deep" else None,
        )
        if documents is None:
            return None
        prepared = _prepare_scan_finalization(
            child_dir,
            completion_binding=binding,
            recover_unsealed=True,
            draft_documents=documents,
            finding_scope=db.requested_finding_scope(child) if child["mode"] == "deep" else None,
        )
    manifest, findings, coverage = prepared.manifest, prepared.findings, prepared.coverage
    db.verify_manifest_binding(child, manifest)
    coverage = child_review_state(db, connection, child, prepared)
    projected = project_scan_artifacts(
        child["parent_scan_id"], child["id"], child_dir, scan_dir, manifest, findings, coverage
    )
    draft = projected["draft"]
    for index, finding in enumerate(draft["findings"]):
        # No semantic merge has accepted these independent observations yet.
        identity = finding["identity"]
        identity["instance"] = f"{child['id']}-{identity.get('instance', 'saved')}"
        provenance = finding["provenance"]
        provenance.pop("preservedIdentity", None)
        provenance["sourceFindings"] = [
            {"id": f"{child['id']}:{index}", "finding": projected["sourceFindings"][index]}
        ]
    return draft


def save_composed_checkpoint(
    db: Any, connection: Any, scan: Any, scan_dir: Path, composition: CompositionView
) -> dict[str, Any] | None:
    """Retain accepted progress and unmerged ordinary child observations."""
    checkpoint = composition.checkpoint
    children = {child["scan_dir"]: child for child in composition.children}
    if checkpoint is None and not children:
        return None
    merged_ids = set(checkpoint["mergedScanIds"]) if checkpoint is not None else set()
    aggregate = copy.deepcopy(checkpoint["aggregate"]) if checkpoint is not None else None
    if not isinstance(aggregate, dict):
        aggregate = {"findings": [], "reviewState": {}}
    elif "coverage" in aggregate and "reviewState" not in aggregate:
        aggregate["reviewState"] = aggregate.pop("coverage")
    represented = set()
    for finding in aggregate["findings"]:
        for _, retained in retained_findings(finding):
            provenance = retained.get("provenance", {})
            represented.update(provenance.get("sourceFindingIds", []))
            represented.update(source["id"] for source in provenance.get("sourceFindings", []))
    recovery_errors = {}
    for child in children.values():
        try:
            require_deep_pass_target(scan, stored_scan_target_identity(child))
            child = db.require_scan(connection, child["id"])
            draft = _stopped_child_draft(db, connection, child, scan_dir)
        except (ContractError, OSError, SystemExit, ValueError) as exc:
            recovery_errors[child["id"]] = str(exc)
            continue
        if draft is None:
            continue
        closures = draft["reviewState"].get("resolvedDeferred")
        if (
            closures
            and child["status"] == "complete"
            and child["seal_manifest_digest"] is not None
            and draft.get("complete") is not False
        ):
            # Preserve the child's original observation time so a later parent
            # checkpoint can reopen its work. This does not select a parent head.
            completed = parse_timestamp(child["completed_at"])
            observed_ns = int(completed.timestamp()) * 1_000_000_000 + completed.microsecond * 1000
            name = save_pending_checkpoint(
                scan_dir,
                _encoded(
                    {
                        "scanId": scan["id"],
                        "findings": [],
                        "reviewState": {"resolvedDeferred": closures},
                    }
                ),
            )
            os.utime(scan_dir / "checkpoints" / name, ns=(observed_ns, observed_ns))
        if child["id"] in merged_ids:
            continue
        aggregate["findings"].extend(
            finding
            for finding in draft["findings"]
            if not represented.intersection(finding["provenance"]["sourceFindingIds"])
        )
        merge_coverage(aggregate.setdefault("reviewState", {}), draft["reviewState"])
        if draft.get("scope") or draft.get("threatModel"):
            scope = aggregate.setdefault("scope", {})
            for key, value in draft.get("scope", {}).items():
                if key != "sourceScans":
                    scope.setdefault(key, copy.deepcopy(value))
            context = {
                "scanId": child["id"],
                **{
                    key: copy.deepcopy(draft[key])
                    for key in ("scope", "threatModel")
                    if key in draft
                },
            }
            source_scans = scope.setdefault("sourceScans", [])
            if isinstance(source_scans, list) and context not in source_scans:
                source_scans.append(context)
        if "threatModel" in draft:
            aggregate.setdefault("threatModel", copy.deepcopy(draft["threatModel"]))
    aggregate["scanId"] = scan["id"]
    aggregate["complete"] = False
    coverage = aggregate.setdefault("reviewState", {})
    coverage.pop("completeness", None)
    deferred = coverage.setdefault("deferred", [])
    directories = (
        dict.fromkeys(Path(scan["scan_dir"]) / item["directory"] for item in checkpoint["passes"])
        if checkpoint is not None
        else {}
    )
    directories.update((Path(directory), None) for directory in children)
    for directory in directories:
        child = children.get(str(directory))
        if child is not None and child["id"] in merged_ids:
            continue
        relative = directory.relative_to(scan_dir).as_posix()
        note = {
            "id": f"unmerged-{child['id']}"
            if child is not None
            else f"unmerged-{_digest(relative)[:16]}",
            "reason": f"Independent scan did not complete and merge. Saved work: {relative}.",
        }
        if child is not None and child["id"] in recovery_errors:
            note["reason"] += f" Recovery failed: {recovery_errors[child['id']]}"
        if note not in deferred:
            deferred.append(note)
    payload = _encoded(aggregate)
    save_pending_checkpoint(scan_dir, payload)
    return aggregate


def clear_legacy_publication_error(connection: Any, scan_id: str) -> None:
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET publication_error_message = NULL WHERE scan_id = ?",
            (scan_id,),
        )


def stop_composition_children(db: Any, connection: Any, composition: CompositionView) -> None:
    merged = set(composition.checkpoint["mergedScanIds"]) if composition.checkpoint else set()
    for child in composition.children:
        if child["id"] not in merged and child["status"] == "running":
            fail_scan(
                db,
                connection,
                argparse.Namespace(
                    scan_id=child["id"],
                    claim_token=child["handoff_claim_token"],
                    cost_json=None,
                    message="Parent Deep Scan stopped.",
                ),
            )


def save_pending_checkpoint(scan_dir: Path, payload: bytes, staged_path: str = "") -> str:
    name = f"{hashlib.sha256(payload).hexdigest()}.json"
    # Publish the index first so every saved checkpoint remains discoverable.
    write_scan_local_bytes(scan_dir, f"checkpoints/pending/{name}", staged_path.encode("utf-8"))
    write_scan_local_bytes(scan_dir, f"checkpoints/{name}", payload)
    return name


def advance_scan_phase(db: Any, connection: Any, scan_id: str, phase: str) -> None:
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


def preserve_scan_results_locked(
    db: Any,
    connection: Any,
    scan_id: str,
    *,
    recovery_source_digests: dict[str, str] | None = None,
    recovery_checkpoint_heads: dict[str, str | None] | None = None,
    include_parent_with_recovery: bool = False,
    recovery_snapshot_error: _CheckpointSnapshotError | None = None,
    composition: CompositionView | None = None,
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
        _freeze_source_times(
            scan_dir,
            scan_id,
            frozen_source_digests,
            frozen_source_times,
            retained.get("parentContext"),
        )
    if frozen_source_digests is None:
        composition = composition or load_composition(connection, scan)
        save_composed_checkpoint(db, connection, scan, scan_dir, composition)
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
    # Older pending recoveries retained the parent union without recording the mode.
    legacy_parent = (
        include_parent_with_recovery
        or (pending_recovery is not None and pending_recovery.get("legacyParent", True) is True)
        or (
            composition is not None
            and composition.checkpoint is not None
            and existing is not None
            and existing_scan.get("status") == "completed"
            and "coverageRef" in existing_scan
            and frozen_source_digests is None
        )
        or (
            recovery_source_digests is None
            and frozen_source_digests == {}
            and isinstance(existing_scan, dict)
            and existing_scan.get("sealedAt") is not None
            and "preservedSources" not in existing_scan
        )
    )

    def pending_selection(heads: dict[str, str | None]) -> dict[str, Any]:
        return {
            "heads": heads,
            "recoveryBaseDigest": scan["seal_manifest_digest"],
            "legacyParent": legacy_parent,
        }

    try:
        documents = merge_saved_results(
            scan_dir,
            scan_id,
            binding,
            saved_deep_workers(connection, scan),
            warnings,
            stopped=True,
            scan_mode=scan["mode"],
            finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
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
            allow_frozen_legacy_parent=legacy_parent,
            parent_already_captured=pending_recovery is not None,
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
                retained_heads = pending_selection(retained_heads)
            with connection:
                connection.execute(
                    "UPDATE scans SET retained_source_digests_json = ?, "
                    "retained_checkpoint_heads_json = ?, completion_warnings_json = ? "
                    "WHERE id = ? AND retained_source_digests_json IS ?",
                    (
                        _encode_retained_sources(
                            retained_sources, exc.model_source, source_times, exc.parent_context
                        ),
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
        or model_source != ([saved_model_source] if saved_model_source is not None else [])
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
            retained_heads = pending_selection(retained_heads)
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
    """Recover terminal results from saved checkpoints under the completion lock for a failed, uncanceled scan."""
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
        clear_legacy_publication_error(connection, scan_id)
    return db.scan_context(connection, scan_id)


def preserve_scan_results(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    """Publish results for a stopped scan under its completion lock and return the updated scan context."""
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    cost_json = db.parse_scan_cost(getattr(args, "cost_json", None))
    with db.scan_completion_lock(scan_id):
        scan = db.require_scan(connection, scan_id)
        if scan["status"] == "complete":
            raise SystemExit("A completed scan cannot preserve new results.")
        workspace = db.require_workspace(connection, scan["workspace_id"])
        owner = db.handoff.owning_thread(scan, workspace)
        if args.thread_id is not None and args.thread_id != owner:
            raise SystemExit("Saved results can only be published from the owning Codex thread.")
        # The app can cancel before a continuation has claimed the scan.
        if not (
            getattr(args, "after_stop", False)
            and scan["canceled_at"] is not None
            and scan["handoff_claim_token"] is None
            and args.claim_token is None
        ):
            db.handoff.require_current_continuation(
                scan,
                args.claim_token,
                error_message="Saved results are owned by another continuation.",
            )
        if cost_json is not None:
            cost_json = merge_scan_cost(scan["cost_json"], cost_json)
            with connection:
                connection.execute(
                    "UPDATE scans SET cost_json = ? WHERE id = ?", (cost_json, scan_id)
                )
        if scan["status"] == "running":
            return db.scan_context(connection, scan_id)
        if getattr(args, "after_stop", False):
            preserve_stopped_results_after_transition(db, connection, scan_id, stop_children=True)
            return db.scan_context(connection, scan_id)
        published = preserve_scan_results_locked(db, connection, scan_id)
        if not published and scan["canceled_at"] is not None:
            raise SystemExit("Saved scan results could not be published or verified.")
        if published:
            clear_legacy_publication_error(connection, scan_id)
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
        if scan["mode"] == "deep" and output == COMPOSITION_CHECKPOINT:
            advance_scan_phase(db, connection, scan_id, "discovery")
    return {"scanId": scan_id, "path": str(scan_dir / output)}


def write_scan_draft(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    """Publish a staged draft for the current continuation of a running, unsealed scan.

    Read the draft from its registered scan directory and bind it to the scan
    before publishing it under the completion lock. Return the scan ID, the
    draft_written status, and any warning about the optional threat model.
    """
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
        acknowledged = set()
        staged_checkpoint_relative = None
        if args.checkpoint_path is not None:
            try:
                staged_checkpoint_relative = (
                    Path(args.checkpoint_path).relative_to(scan_dir).as_posix()
                )
            except ValueError as exc:
                raise SystemExit(
                    "Scan checkpoint must be inside the registered scan drafts directory."
                ) from exc
            if not re.fullmatch(
                r"drafts/[0-9a-fA-F-]+\.checkpoint\.json", staged_checkpoint_relative
            ):
                raise SystemExit(
                    "Scan checkpoint must be inside the registered scan drafts directory."
                )
            checkpoint, checkpoint_contents = _read_scan_local_json_bytes(
                scan_dir, staged_checkpoint_relative, "Staged scan checkpoint"
            )
            if checkpoint.get("scanId") != scan_id:
                raise SystemExit("Staged scan checkpoint belongs to another scan.")
            # Keep the staged observation discoverable on a publication conflict,
            # without archiving a new checkpoint before the draft is accepted.
            checkpoint_name = f"{hashlib.sha256(checkpoint_contents).hexdigest()}.json"
            acknowledged.add(checkpoint_name)
            write_scan_local_bytes(
                scan_dir,
                f"checkpoints/pending/{checkpoint_name}",
                staged_checkpoint_relative.encode("utf-8"),
            )
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
        reconciled = draft.get("reconciledCheckpointIds", [])
        if not isinstance(reconciled, list) or any(
            not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", name)
            for name in reconciled
        ):
            raise SystemExit("Reconciled checkpoint IDs must be saved checkpoint filenames.")
        acknowledged.update(reconciled)
        manifest, findings = draft["manifest"], draft["findings"]
        coverage = draft["reviewState"] if "reviewState" in draft else draft["coverage"]
        binding = db.workbench_completion_binding(scan, db.now())
        # Save scan IDs without sealing the draft.
        _populate_unsealed_manifest_envelope(manifest, manifest["scan"], binding)
        _populate_unsealed_artifact_envelope(manifest, findings, coverage, binding)
        _validate_completion_binding(manifest, findings, coverage, binding)
        manifest["scan"]["mode"] = coverage["mode"]
        manifest["scan"]["review"] = review_summary(coverage)
        manifest["scan"]["reviewState"] = checkpoint_review_state(coverage)
        manifest["scan"].pop("coverageRef", None)
        admitted_input = None
        if staged_checkpoint_relative is not None:
            if scan["mode"] == "deep" and checkpoint.get("complete") is not False:
                previous = {}
                if (scan_dir / "checkpoint-head.json").exists():
                    previous, _, _ = _read_saved_result(scan_dir, "checkpoint-head.json", scan_id)
                checkpoint["publication"] = {
                    "previousCheckpoint": previous.get("checkpoint"),
                    "previousInputCheckpoint": previous.get("inputCheckpoint"),
                }
                checkpoint_contents = _encoded(checkpoint)
            raw_name = f"{hashlib.sha256(checkpoint_contents).hexdigest()}.json"
            write_scan_local_bytes(scan_dir, f"checkpoints/{raw_name}", checkpoint_contents)
            if scan["mode"] == "deep":
                admitted_input = raw_name
        checkpoint = _parent_scan_draft(scan_id, manifest["scan"], findings, coverage)
        checkpoint_contents = _encoded(checkpoint)
        checkpoint_name = f"{hashlib.sha256(checkpoint_contents).hexdigest()}.json"
        checkpoint_relative = f"checkpoints/{checkpoint_name}"
        if not (scan_dir / checkpoint_relative).exists():
            write_scan_local_bytes(scan_dir, checkpoint_relative, checkpoint_contents)
        head = {"checkpoint": checkpoint_name}
        if admitted_input is not None:
            head["inputCheckpoint"] = admitted_input
        write_scan_local_bytes(scan_dir, "checkpoint-head.json", _encoded(head))
        for filename, document in (
            ("findings.json", findings),
            ("scan-manifest.json", manifest),
        ):
            write_scan_local_bytes(
                scan_dir,
                filename,
                (json.dumps(document, allow_nan=False, indent=2) + "\n").encode(),
            )
        _remove_scan_local_file_if_exists(scan_dir, "coverage.json")
        for name in acknowledged:
            _remove_scan_local_file_if_exists(scan_dir, f"checkpoints/pending/{name}")
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
            advance_scan_phase(db, connection, scan_id, phase)
        # Failed publication leaves its inputs available for retry/recovery. Only
        # this acknowledged write can remove its own per-attempt stage paths.
        for staged in (relative, staged_checkpoint_relative):
            if staged is not None:
                try:
                    _remove_scan_local_file_if_exists(scan_dir, staged)
                except (ContractError, OSError):
                    pass  # Optional cleanup must not change publication's outcome.
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
        contents = documents.get(filename)
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
        if scan["status"] == "complete":
            raise SystemExit("A completed scan cannot be marked failed.")
        if (
            scan["status"] != "failed"
            or getattr(args, "defer_publication", False)
            or cost_json is not None
        ):
            db.handoff.require_current_continuation(
                scan,
                args.claim_token,
                error_message="Scan failure is owned by another continuation.",
            )
        if scan["status"] == "failed":
            connection.commit()
            record_stopped_scan_usage(db, connection, scan_id, cost_json)
            return db.scan_context(connection, scan["id"])
        message = db.optional_text(args.message)
        updated = connection.execute(
            """
            UPDATE scans
            SET status = 'failed', failure_message = ?, completed_at = ?, updated_at = ?
            WHERE id = ? AND status = 'running'
            """,
            (message, timestamp, timestamp, scan["id"]),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can be marked failed.")
        progress_updated = connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan["id"]),
        )
        if progress_updated.rowcount != 1:
            raise SystemExit("Codex Security scan progress not found.")
    record_stopped_scan_usage(db, connection, scan_id, cost_json)
    if not getattr(args, "defer_publication", False):
        preserve_stopped_results_after_transition(db, connection, scan["id"])
    return db.scan_context(connection, scan["id"])


def cancel_scan(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    with db.scan_completion_lock(db.require_uuid(args.scan_id, "scan-id")):
        return cancel_scan_locked(db, connection, args)


def cancel_scan_locked(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    thread_id = db.optional_text(args.thread_id, maximum=512)
    cost_json = db.parse_scan_cost(getattr(args, "cost_json", None))
    connection.execute("BEGIN IMMEDIATE")
    with connection:
        timestamp = db.now()
        scan = db.require_scan(connection, scan_id)
        workspace = db.require_workspace(connection, scan["workspace_id"])
        owning_thread_id = db.handoff.owning_thread(scan, workspace)
        if thread_id is not None and owning_thread_id != thread_id:
            raise SystemExit("A scan can only be canceled from its owning Codex thread.")
        if scan["canceled_at"] is not None:
            connection.commit()
            record_stopped_scan_usage(db, connection, scan_id, cost_json)
            return {
                **db.workspace_state(connection, scan["workspace_id"]),
                "canceledScanId": scan["id"],
            }
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
        progress_updated = connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan["id"]),
        )
        if progress_updated.rowcount != 1:
            raise SystemExit("Codex Security scan progress not found.")
    record_stopped_scan_usage(db, connection, scan_id, cost_json)
    if not getattr(args, "defer_publication", False):
        preserve_stopped_results_after_transition(db, connection, scan["id"])
    return {**db.workspace_state(connection, scan["workspace_id"]), "canceledScanId": scan["id"]}


def record_stopped_scan_usage(
    db: Any, connection: Any, scan_id: str, cost_json: str | None = None
) -> None:
    """Keep optional accounting independent of the already-persisted scan outcome."""

    try:
        scan = db.require_scan(connection, scan_id)
        fields = db.scan_usage.merge_scan_usage_fields(
            db.scan_usage.stored_scan_cost_fields(scan["cost_json"]),
            db.scan_usage.stored_scan_cost_fields(cost_json),
        )
        fields = db.scan_usage.merge_scan_usage_fields(
            fields,
            {"usage": db.scan_usage.collect_scan_usage_safely(connection, scan)},
        )
        if fields:
            encoded = db.parse_scan_cost(json.dumps(fields))
            with connection:
                connection.execute(
                    "UPDATE scans SET cost_json = ? WHERE id = ? AND status = 'failed'",
                    (encoded, scan_id),
                )
    except (Exception, SystemExit) as exc:
        try:
            print(f"Could not save stopped scan token usage: {exc}", file=sys.stderr)
        except OSError:
            # A closed diagnostic stream must not alter the persisted scan outcome.
            pass


def preserve_stopped_results_after_transition(
    db: Any, connection: Any, scan_id: str, *, stop_children: bool = False
) -> None:
    try:
        scan = db.require_scan(connection, scan_id)
        composition = load_composition(connection, scan)
        if stop_children:
            stop_composition_children(db, connection, composition)
        if preserve_scan_results_locked(db, connection, scan_id, composition=composition):
            clear_legacy_publication_error(connection, scan_id)
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


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
