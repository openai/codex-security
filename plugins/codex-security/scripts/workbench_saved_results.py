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
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    RecoverableContractError,
    ScanLocalIOError,
    _populate_unsealed_artifact_envelope,
    _populate_unsealed_manifest_envelope,
    _prepare_scan_finalization,
    _read_saved_threat_model,
    _read_scan_local_json,
    _read_scan_local_json_bytes,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _remove_scan_local_file_if_exists,
    _seal_warnings,
    _validate_completion_binding,
    _write_prepared_scan_finalization,
    finalize_scan,
    manifest_is_sealed,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
    write_threat_model_projection_if_possible,
)
from finalize_scan_contract import finding_candidate_id as finding_candidate_id
from workbench.retained_coverage import (
    _append_previous_finding as _append_previous_finding,
)
from workbench.retained_coverage import (
    _coverage_rows as _coverage_rows,
)
from workbench.retained_coverage import (
    _ensure_finding_identities as _ensure_finding_identities,
)
from workbench.retained_coverage import (
    _ensure_finding_identity as _ensure_finding_identity,
)
from workbench.retained_coverage import (
    _finding_content as _finding_content,
)
from workbench.retained_coverage import (
    _finding_identity as _finding_identity,
)
from workbench.retained_coverage import (
    _finding_key as _finding_key,
)
from workbench.retained_coverage import (
    _has_candidate_metadata as _has_candidate_metadata,
)
from workbench.retained_coverage import (
    _identity_candidate as _identity_candidate,
)
from workbench.retained_coverage import (
    _retained_findings as _retained_findings,
)
from workbench.retained_coverage import (
    _semantic_identity_key as _semantic_identity_key,
)
from workbench.retained_coverage import (
    _worker_candidate_key as _worker_candidate_key,
)
from workbench.retained_coverage import merge_saved_results as merge_saved_results
from workbench.saved_coverage import (
    _deferred_rows as _deferred_rows,
)
from workbench.saved_coverage import (
    _inherit_coverage_sources as _inherit_coverage_sources,
)
from workbench.saved_coverage import (
    _merge_tied_parent_observations as _merge_tied_parent_observations,
)
from workbench.saved_coverage import (
    _resolved_deferred_rows as _resolved_deferred_rows,
)
from workbench.saved_coverage import (
    _saved_coverage_id as _saved_coverage_id,
)
from workbench.saved_outputs import _restore_published_outputs, _snapshot_published_outputs
from workbench.saved_sources import (
    _accepted_source_digests,
    _admit_parent_checkpoint,
    _capture_saved_source,
    _checkpoint_paths,
    _encode_retained_sources,
    _encoded,
    _freeze_source_times,
    _frozen_source_times,
    _is_source_order_snapshot,
    _parent_scan_draft,
    _read_saved_parent_result,
    _read_saved_result,
    _retained_source_state,
    _saved_result_paths,
    _saved_workers,
    _source_digests,
    _worker_checkpoint_head,
    _worker_checkpoint_heads,
)
from workbench.saved_sources import (
    _capture_parent_observation as _capture_parent_observation,
)
from workbench.saved_sources import (
    _checkpoint_head_directory as _checkpoint_head_directory,
)
from workbench.saved_sources import (
    _digest as _digest,
)
from workbench.saved_sources import (
    _latest_successful_reducer as _latest_successful_reducer,
)
from workbench.saved_sources import (
    _parent_publication_ancestors as _parent_publication_ancestors,
)
from workbench.saved_sources import (
    _worker_outputs as _worker_outputs,
)
from workbench_constants import PHASES
from workbench_coverage_receipts import (
    _deferred_candidate_id as _deferred_candidate_id,
)
from workbench_coverage_receipts import (
    _generic_surface_updates as _generic_surface_updates,
)
from workbench_coverage_receipts import (
    matches_worker_checkpoint,
    resolve_coverage_receipts,
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


def validate_sealed_budget_draft(
    db: Any, scan: sqlite3.Row, scan_dir: Path, manifest: dict[str, Any]
) -> None:
    # The seal can reach disk before parent completion commits. Validate
    # it without changing bytes; the existing finalizer commits replay.
    try:
        prepared = _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            completion_binding=db.workbench_completion_binding(scan, scan["started_at"], manifest),
        )
        coverage = prepared.coverage
        if coverage.get("completeness") != "partial" and not any(
            item["reason"] == "Validation was deferred because the scan reached its cost limit."
            or item["reason"].startswith(
                "Validation was deferred because the scan reached its cost limit: "
            )
            for item in coverage["deferred"]
        ):
            raise ContractError("Budget-exhausted completion requires saved cost-limit coverage.")
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc


def _saved_results_changed(db: Any, connection: Any, scan: Any) -> bool:
    try:
        scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
        manifest_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
        workers = _saved_workers(connection, scan["id"])
        accepted_digests = _accepted_source_digests(connection, scan["id"])
        paths = dict(_saved_result_paths(scan_dir, workers))
        frozen_sources = scan["retained_source_digests_json"]

        def has_saved_source() -> bool:
            for path in paths:
                try:
                    _read_saved_result(
                        scan_dir,
                        path,
                        scan["id"],
                        kind=paths[path],
                        accepted_source_digests=accepted_digests,
                    )
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
        if (
            "preservedCheckpointHeads" in manifest_scan
            and _worker_checkpoint_heads(scan_dir, workers, scan["id"], accepted_digests)
            != manifest_scan["preservedCheckpointHeads"]
        ):
            return True
        current_sources = dict(published_sources)
        paths.update({path: None for path in published_sources if _is_source_order_snapshot(path)})
        for path in paths:
            try:
                captured = _capture_saved_source(
                    scan_dir,
                    path,
                    scan["id"],
                    kind=paths[path],
                    accepted_source_digests=accepted_digests,
                    snapshot_head=path not in published_sources,
                    write=False,
                )
                current_sources.update({path: value[0] for path, value in captured.items()})
            except (ContractError, OSError, ValueError):
                continue
        return current_sources != published_sources
    except (ContractError, OSError, SystemExit, ValueError):
        return False


def _recovery_source_digests(
    db: Any, connection: Any, scan: Any
) -> tuple[dict[str, str], bool, dict[str, str] | None]:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    frozen_sources: dict[str, str] | None = None
    include_parent = True
    raw_frozen_sources = scan["retained_source_digests_json"]
    raw_checkpoint_heads = scan["retained_checkpoint_heads_json"]
    checkpoint_heads = (
        json.loads(raw_checkpoint_heads) if raw_checkpoint_heads is not None else None
    )
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
            if checkpoint_heads is None:
                checkpoint_heads = manifest_scan.get("preservedCheckpointHeads")
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

    workers = _saved_workers(connection, scan["id"])
    accepted_digests = _accepted_source_digests(connection, scan["id"])
    paths = dict(_saved_result_paths(scan_dir, workers))
    recovery_sources = dict(frozen_sources or {})
    parent_context: dict[str, str] = {}
    source_times = _frozen_source_times(scan_dir, scan["id"], recovery_sources, parent_context)
    for relative, expected_digest in recovery_sources.items():
        try:
            _, digest, observed = _read_saved_result(
                scan_dir,
                relative,
                scan["id"],
                kind=paths.get(relative),
                accepted_source_digests=accepted_digests,
            )
        except (ContractError, OSError, ValueError) as exc:
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")
        if not _is_source_order_snapshot(relative):
            source_times.setdefault(relative, observed)

    for relative in paths.keys() - recovery_sources.keys():
        try:
            captured = _capture_saved_source(
                scan_dir,
                relative,
                scan["id"],
                kind=paths[relative],
                write=checkpoint_heads is None,
                accepted_source_digests=accepted_digests,
            )
        except (ContractError, OSError, ValueError):
            continue
        if relative == "checkpoint-head.json":
            parent_context["head"] = next(iter(captured))
        for path, (digest, observed) in captured.items():
            if path in recovery_sources and recovery_sources[path] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            recovery_sources[path] = digest
            source_times.setdefault(path, observed)
    if checkpoint_heads is not None and (
        recovery_sources != frozen_sources
        or _worker_checkpoint_heads(scan_dir, workers, scan["id"], accepted_digests)
        != checkpoint_heads
    ):
        raise SystemExit(
            "This stopped scan requires a newer version to select recovery checkpoints."
        )
    _freeze_source_times(scan_dir, scan["id"], recovery_sources, source_times, parent_context)
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
            # Without reduction, the coordinator's empty draft cannot replace worker evidence.
            scan_mode="deep" if preserve_reduction else None,
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
            json.loads(raw_checkpoint_heads) if raw_checkpoint_heads is not None else None
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
            existing_heads = existing_scan.get("preservedCheckpointHeads")
            if checkpoint_heads is None:
                checkpoint_heads = existing_heads
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
        scan_mode=scan["mode"],
        finding_scope=db.requested_finding_scope(scan) if scan["mode"] == "deep" else None,
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
        deep_run = connection.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if deep_run is not None:
            db.deep_scan.require_supported_deep_scan(deep_run)
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


def _selected_publication_digest(prepared: Any, *, warnings: list[str] | None = None) -> str:
    # Completion time is chosen at sealing, after publication. Everything else
    # must remain the host projection of the same accepted aggregate.
    manifest = copy.deepcopy(prepared.manifest)
    if warnings:
        manifest["scan"]["warnings"] = warnings
    for field in ("completedAt", "sealedAt"):
        manifest["scan"].pop(field, None)
    return _digest([manifest, prepared.findings, prepared.coverage])


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


def record_selected_publication(db: Any, connection: Any, scan: Any, documents: Any) -> None:
    run = db.deep_scan.require_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run)
    if selection is None:
        return
    _require_selected_result(scan, selection)
    prepared = _prepare_scan_finalization(
        Path(scan["scan_dir"]),
        expected_coverage_mode=db.expected_coverage_mode(scan),
        completion_binding=db.workbench_completion_binding(scan, db.now(), documents[0]),
        draft_documents=documents,
    )
    selection["publicationSha256"] = _selected_publication_digest(prepared)
    selection.pop("sealedPublicationSha256", None)
    _store_publication_selection(connection, scan["id"], selection)


def _store_publication_selection(connection: Any, scan_id: str, selection: dict[str, Any]) -> None:
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET finalization_input_json = ? WHERE scan_id = ?",
            (json.dumps(selection), scan_id),
        )


def retain_unmerged_budget_coverage(
    scan: Any,
    scan_dir: Path,
    coverage: dict[str, Any],
    worker: Any,
    scope: Sequence[tuple[str, bool]],
) -> None:
    """Keep each unmerged review's obligations; its findings remain evidence only."""
    accepted_digests = _source_digests(
        {worker["accepted_result_path"]: worker["accepted_result_sha256"]}, "Accepted budget"
    )
    relative = Path(worker["accepted_result_path"]).relative_to(scan_dir).as_posix()
    draft, _, _ = _read_saved_result(
        scan_dir,
        relative,
        scan["id"],
        accepted_source_digests=accepted_digests,
    )
    head = _worker_checkpoint_head(
        scan_dir, Path(worker["artifact_dir"]).relative_to(scan_dir).as_posix(), scan["id"]
    )
    if head is not None and not matches_worker_checkpoint(
        _read_saved_result(scan_dir, head, scan["id"])[0], draft, scope
    ):
        raise ContractError("The accepted discovery differs from its current checkpoint head.")
    # The old Workbench named direct snapshots after their raw file digest.
    # Typed worker checkpoints also recorded scan-owned receipts.
    direct_result = head is None and Path(relative).stem == worker["accepted_result_sha256"]
    source = draft["coverage"]
    if (
        direct_result
        and not any(path == "." for path, _ in scope)
        and any(
            isinstance(row, dict)
            and isinstance(row.get("provenance"), dict)
            and row["provenance"].get("scanReceiptRefs")
            for row in source.get("surfaces", [])
        )
    ):
        # Older hosts checkpointed all findings before filtering result.json.
        for sibling in _checkpoint_paths(scan_dir, Path(relative).parent.as_posix()):
            if sibling == relative:
                continue
            try:
                checkpoint, raw = _read_scan_local_json_bytes(
                    scan_dir, sibling, "Worker checkpoint"
                )
            except (ContractError, OSError):
                continue
            if (
                Path(sibling).stem != hashlib.sha256(raw).hexdigest()
                and isinstance(checkpoint.get("findings"), list)
                and matches_worker_checkpoint(checkpoint, draft, scope)
            ):
                direct_result = False
                break
    provenance = {"workerId": worker["id"], "attempt": worker["attempt"]}
    prefix = f"{worker['id']}-attempt-{worker['attempt']}"
    surfaces = {
        item.get("id"): f"{prefix}-surface-{index + 1}"
        for index, item in enumerate(source.get("surfaces", []))
    }

    def retain(field: str, item: dict[str, Any]) -> None:
        # A committed budget draft can be replayed before the scan is sealed.
        # These IDs and provenance identify the same immutable accepted review.
        items = coverage.setdefault(field, [])
        if "id" in item:
            matches = []
            for index, existing in enumerate(items):
                existing_provenance = (
                    existing.get("provenance") if isinstance(existing, dict) else None
                )
                if (
                    isinstance(existing_provenance, dict)
                    and existing.get("id") == item["id"]
                    and all(
                        existing_provenance.get(key) == value for key, value in provenance.items()
                    )
                ):
                    previous = copy.deepcopy(existing)
                    previous["provenance"] = {**item["provenance"], **existing_provenance}
                    if previous != item:
                        raise ContractError(
                            "Legacy budget coverage changed from its accepted review."
                        )
                    matches.append(index)
            if matches:
                # Refresh older projections from the same accepted bytes, even
                # if an interrupted writer saved more than one copy.
                items[matches[0]] = item
                for index in reversed(matches[1:]):
                    del items[index]
                return
        if item not in items:
            items.append(item)

    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        for index, original in enumerate(source.get(field, [])):
            item = copy.deepcopy(original if isinstance(original, dict) else {"question": original})
            source_provenance = item.get("provenance")
            if not isinstance(source_provenance, dict):
                source_provenance = {}
            # Keep source descriptions; the accepted owner supplies identity.
            for key in ("workerId", "attempt", "sourceId", "candidateId"):
                source_provenance.pop(key, None)
            item["provenance"] = {
                **source_provenance,
                **provenance,
                **({"sourceId": item["id"]} if "id" in item else {}),
                **({"candidateId": item["candidateId"]} if "candidateId" in item else {}),
            }
            item["id"] = f"{prefix}-{field}-{index + 1}"
            if field == "surfaces":
                item["id"] = f"{prefix}-surface-{index + 1}"
                receipt_source = {**item, "provenance": {}} if direct_result else item
                item["receiptRefs"] = resolve_coverage_receipts(
                    scan_dir, receipt_source, worker, relative
                )
            if field == "deferred" and "candidateId" in item:
                item["candidateId"] = f"{prefix}-candidate-{index + 1}"
            if "surfaceIds" in item:
                item["surfaceIds"] = [surfaces.get(value, value) for value in item["surfaceIds"]]
            retain(field, item)
    retain("reviews", {**provenance, "completeness": source["completeness"]})
    for index, limitation in enumerate(draft.get("scope", {}).get("limitations", [])):
        retain(
            "deferred",
            {
                "id": f"{prefix}-scope-{index + 1}",
                "reason": limitation,
                "provenance": provenance,
            },
        )
    retain(
        "deferred",
        {
            "id": f"{prefix}-unmerged",
            "provenance": provenance,
            "reason": "This accepted discovery was not merged before the scan reached its cost limit.",
        },
    )


def _require_budget_publication(db: Any, connection: Any, scan: Any, documents: Any) -> None:
    prepared = _prepare_scan_finalization(
        Path(scan["scan_dir"]),
        expected_coverage_mode=db.expected_coverage_mode(scan),
        completion_binding=db.workbench_completion_binding(scan, db.now(), documents[0]),
        draft_documents=documents,
    )
    manifest = copy.deepcopy(documents[0])
    manifest["scan"].setdefault("id", scan["id"])
    manifest["scan"]["scope"] = {**prepared.manifest["scan"]["scope"], **manifest["scan"]["scope"]}
    db.verify_manifest_binding(scan, manifest)
    require_selected_publication(db, connection, scan, prepared)


def _write_budget_documents(scan_dir: Path, documents: Any) -> None:
    for name, payload in (
        ("findings.json", documents[1]),
        ("coverage.json", documents[2]),
        ("scan-manifest.json", documents[0]),
    ):
        try:
            write_scan_local_bytes(
                scan_dir,
                name,
                (json.dumps(payload, allow_nan=False, indent=2, sort_keys=True) + "\n").encode(),
            )
        except (ContractError, OSError, TypeError, ValueError) as exc:
            raise SystemExit(f"Budget-exhausted scan draft could not be saved: {exc}") from exc


def prepare_budget_draft(db: Any, connection: Any, scan: Any, warning: str) -> None:
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    run = db.deep_scan.require_deep_scan_run(connection, scan["id"])
    selection = db.deep_scan.deep_scan_finalization_input(run)
    has_publication = selection is not None and "publicationSha256" in selection
    candidates = (
        []
        if run["manifest_path"] == str(scan_dir / "scan-manifest.json")
        else db.budget_exhausted_candidates(scan, scan_dir)
    )
    try:
        if has_publication:
            snapshot = f"drafts/{selection['publicationSha256']}.json"
            try:
                documents = tuple(
                    _read_scan_local_json(scan_dir, name, name)
                    for name in ("scan-manifest.json", "findings.json", "coverage.json")
                )
                _require_budget_publication(db, connection, scan, documents)
            except (ContractError, OSError):
                # Canonical files can outlive a failed digest commit. Replay only
                # the saved projection bound to the still-committed selection.
                saved = _read_scan_local_json(scan_dir, snapshot, "Saved budget publication")
                documents = (saved["manifest"], saved["findings"], saved["coverage"])
                _require_budget_publication(db, connection, scan, documents)
                _write_budget_documents(scan_dir, documents)
            write_scan_local_bytes(
                scan_dir,
                snapshot,
                _encoded(
                    {
                        "manifest": documents[0],
                        "findings": documents[1],
                        "coverage": documents[2],
                    }
                ),
            )
        documents = db.budget_exhausted_draft(scan, scan_dir, candidates, warning)
        if documents is None:
            return
        if selection is not None and not has_publication:
            _require_selected_result(scan, selection)
            unmerged = connection.execute(
                "SELECT workers.*, attempts.accepted_result_path, attempts.accepted_result_sha256 "
                "FROM deep_scan_workers AS workers JOIN deep_scan_attempts AS attempts "
                "ON attempts.worker_id = workers.id AND attempts.attempt = workers.attempt "
                "WHERE workers.scan_id = ? AND workers.kind = 'discovery' "
                "AND workers.status = 'succeeded' AND workers.merge_state IN ('buffered', 'merging') "
                "ORDER BY workers.completion_sequence, workers.id",
                (scan["id"],),
            ).fetchall()
            for worker in unmerged:
                retain_unmerged_budget_coverage(
                    scan, scan_dir, documents[2], worker, db.requested_finding_scope(scan)
                )
        prepared = _prepare_scan_finalization(
            scan_dir,
            expected_coverage_mode=db.expected_coverage_mode(scan),
            completion_binding=db.workbench_completion_binding(scan, db.now(), documents[0]),
            draft_documents=documents,
        )
        manifest = copy.deepcopy(documents[0])
        manifest["scan"].setdefault("id", scan["id"])
        manifest["scan"]["scope"] = {
            **prepared.manifest["scan"]["scope"],
            **manifest["scan"]["scope"],
        }
        db.verify_manifest_binding(scan, manifest)
        _write_budget_documents(scan_dir, documents)
        if has_publication:
            documents = tuple(
                _read_scan_local_json(scan_dir, name, name)
                for name in ("scan-manifest.json", "findings.json", "coverage.json")
            )
            record_selected_publication(db, connection, scan, documents)
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc


def require_selected_publication(
    db: Any,
    connection: Any,
    scan: Any,
    prepared: Any,
    *,
    projection_warnings: list[str] | None = None,
) -> None:
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
    expected = selection["publicationSha256"]
    if prepared.was_sealed and projection_warnings is not None:
        expected = selection.get("sealedPublicationSha256", expected)
    if _selected_publication_digest(prepared) != expected:
        raise RecoverableContractError(
            "The selected Deep Scan publication changed or is missing; "
            "republish its accepted result before completing the scan."
        )
    if not prepared.was_sealed and projection_warnings is not None:
        # Bind the host projection before a file write can interrupt completion.
        warnings = _seal_warnings(prepared, projection_warnings)
        previous = selection.pop("sealedPublicationSha256", None)
        if warnings != prepared.manifest["scan"].get("warnings", []):
            selection["sealedPublicationSha256"] = _selected_publication_digest(
                prepared, warnings=warnings
            )
        if selection.get("sealedPublicationSha256") != previous:
            _store_publication_selection(connection, scan["id"], selection)


def _require_current_deep_publication(
    db: Any, connection: Any, scan: Any, draft: dict[str, Any]
) -> None:
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
        return
    if run is None:
        run = db.deep_scan.require_deep_scan_run(connection, scan_id)
    # Finished discovery-only runs hand remaining publication back to the parent.
    if (
        selection is None
        and publication is None
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
    if selection is not None:
        if publication is None:
            raise SystemExit("Deep Scan publication requires its committed selection.")
        scan = db.require_scan(connection, scan_id)
        if "publicationSha256" in selection:
            prepared = _prepare_scan_finalization(
                Path(scan["scan_dir"]),
                expected_coverage_mode=db.expected_coverage_mode(scan),
                completion_binding=db.workbench_completion_binding(scan, db.now()),
                draft_documents=(draft["manifest"], draft["findings"], draft["coverage"]),
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
            return

        # Publication follows the coordinator's durable reducer sequence. Stopped
        # legacy recovery separately retains its completion-time source ordering.
        def reducer_order(worker: Any) -> tuple[int, str]:
            match = re.fullmatch(r"dedup-([0-9]+)", Path(worker["prompt_path"]).parent.name)
            return (int(match[1]) if match else 0, worker["id"])

        reducer = max(
            (
                worker
                for worker in _saved_workers(connection, scan_id)
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
        if scan["mode"] == "deep":
            run = connection.execute(
                "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if run is not None:
                db.deep_scan.require_supported_deep_scan(run)
            if not checkpoint_only:
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
