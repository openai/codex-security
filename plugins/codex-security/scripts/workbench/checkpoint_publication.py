"""Publish and recover accepted checkpoint heads from existing workbench scans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _prepare_scan_finalization,
    _read_scan_local_json,
    _write_prepared_scan_finalization,
    finalize_scan,
    manifest_is_sealed,
)
from workbench.retained_coverage import merge_saved_results as merge_saved_results
from workbench.saved_outputs import _restore_published_outputs, _snapshot_published_outputs
from workbench.saved_sources import (
    _capture_saved_source,
    _checkpoint_paths,
    _CheckpointSnapshotError,
    _encode_retained_sources,
    _freeze_source_times,
    _frozen_checkpoint_heads,
    _frozen_source_times,
    _is_source_order_snapshot,
    _legacy_checkpoint_observed_at,
    _read_saved_parent_result,
    _read_saved_result,
    _restore_checkpoint_head,
    _restore_frozen_model_capture,
    _retained_checkpoint_state,
    _retained_source_state,
    _saved_result_paths,
    _source_digests,
)
from workbench.saved_sources import _digest as _digest
from workbench.storage import saved_deep_workers

_PUBLICATION_FOLLOW_UP_WARNING = (
    "Saved scan evidence remains on disk; result publication needs follow-up:"
)


def uses_checkpoint_history(connection: Any, scan: Any, scan_dir: Path) -> bool:
    # The two writers use different commit records. Keep existing scans bound to
    # their accepted heads, including frozen scans with no live head left on disk.
    if (
        scan["parent_scan_role"] == "deep_pass"
        or (scan_dir / "artifacts/scan-draft.json").exists()
        or (scan_dir / "checkpoints/pending").exists()
        or (scan_dir / "artifacts/deep-scan/checkpoint.json").exists()
    ):
        return False
    if (
        scan["mode"] == "deep"
        and connection.execute(
            "SELECT 1 FROM scans WHERE parent_scan_id = ? AND parent_scan_role = 'deep_pass' LIMIT 1",
            (scan["id"],),
        ).fetchone()
    ):
        return False
    return (
        scan["retained_checkpoint_heads_json"] is not None
        or (scan_dir / "checkpoint-head.json").exists()
        or (scan_dir / "checkpoint-heads").is_dir()
        # A bare checkpoint can predate the first head. Once sources are frozen,
        # it can also be the current writer's own snapshot of an adopted parent.
        or (
            scan["retained_source_digests_json"] is None
            and bool(_checkpoint_paths(scan_dir, "checkpoints"))
        )
        or (
            scan["mode"] == "deep"
            and connection.execute(
                "SELECT 1 FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
            ).fetchone()
            is not None
        )
    )


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
        _freeze_source_times(
            scan_dir,
            scan_id,
            frozen_source_digests,
            frozen_source_times,
            retained.get("parentContext"),
        )
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


def recover_scan_results_locked(db: Any, connection: Any, scan: Any) -> dict[str, Any]:
    scan_id = scan["id"]
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
    with connection:
        connection.execute(
            "UPDATE deep_scan_runs SET publication_error_message = NULL, updated_at = ? "
            "WHERE scan_id = ? AND publication_error_message IS NOT NULL",
            (db.now(), scan_id),
        )
    return db.scan_context(connection, scan_id)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
