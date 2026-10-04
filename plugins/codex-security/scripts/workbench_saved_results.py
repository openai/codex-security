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
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    DISPOSITIONS,
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
    _sha256_scan_local_file,
    _validate_completion_binding,
    _validate_schema_node,
    _write_prepared_scan_finalization,
    finalize_scan,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
    write_threat_model_projection_if_possible,
)
from project_scan_artifacts import project_scan_artifacts
from report_projection import retained_findings
from workbench_composition import (
    COMPOSITION_CHECKPOINT,
    CompositionView,
    load_composition,
    read_composition_checkpoint,
)
from workbench_constants import PHASES
from workbench_result_merge import (
    _deferred_rows,
    _freeze_source_times,
    _frozen_source_times,
    _is_source_order_snapshot,
    _legacy_read_saved_result,
    _legacy_source_digests,
    _parent_scan_draft,
    _reconcile_child_coverage,
    _reconcile_child_withdrawals,
    _resolved_deferred_rows,
    _retire_previous_child_coverage,
    _terminal_parent_finding_keys,
)
from workbench_scan_usage import merge_scan_cost
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


_CHILD_RECOVERY_WARNING = f"{_PUBLICATION_FOLLOW_UP_WARNING} Independent scan recovery failed:"

_RESERVED_ARTIFACT_PATHS = json.loads(
    Path(__file__).with_name("reserved_artifact_paths.json").read_text(encoding="utf-8")
)


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def _children(scan_dir: Path, relative: str) -> list[str]:
    cursor = scan_dir
    for part in Path(relative).parts:
        if part in {"..", "."}:
            return []
        cursor = cursor / part
        try:
            if not stat.S_ISDIR(cursor.lstat().st_mode):
                return []
        except FileNotFoundError:
            return []
    return sorted(child.name for child in cursor.iterdir())


def _saved_result_paths(scan_dir: Path, scan_id: str) -> list[str]:
    if (scan_dir / "artifacts/scan-draft.json").exists() and (
        scan_dir / "checkpoints/pending"
    ).exists():
        try:
            _read_saved_parent_result(scan_dir, scan_id)
            return _pending_result_paths(scan_dir)
        except (ContractError, OSError, ValueError):
            pass  # A damaged reconciliation head cannot discard immutable history.
    return [
        f"checkpoints/{name}"
        for name in dict.fromkeys(
            _children(scan_dir, "checkpoints") + _children(scan_dir, "checkpoints/pending")
        )
        if re.fullmatch(r"[0-9a-f]{64}\.json", name)
    ]


def _checkpoint_ids(value: Any) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(name, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", name) for name in value
    ):
        raise ContractError("Reconciled checkpoint IDs must be saved checkpoint filenames.")
    return value


def _committed_checkpoint_ids(scan_dir: Path) -> list[str]:
    if not (scan_dir / "artifacts/scan-draft.json").exists():
        return []
    draft = _read_scan_local_json(scan_dir, "artifacts/scan-draft.json", "Committed scan draft")
    return _checkpoint_ids(draft.get("reconciledCheckpointIds", []))


def _pending_result_paths(scan_dir: Path) -> list[str]:
    acknowledged = set(_committed_checkpoint_ids(scan_dir))
    return [
        f"checkpoints/{name}"
        for name in _children(scan_dir, "checkpoints/pending")
        if re.fullmatch(r"[0-9a-f]{64}\.json", name) and name not in acknowledged
    ]


def _retire_checkpoints(scan_dir: Path, names: list[str]) -> None:
    for name in names:
        relative = f"checkpoints/{name}"
        pending = scan_dir / f"checkpoints/pending/{name}"
        if pending.exists() and not (scan_dir / relative).exists():
            _, contents = _read_checkpoint_bytes(scan_dir, relative)
            observed = pending.stat().st_mtime_ns
            write_scan_local_bytes(scan_dir, relative, contents)
            os.utime(scan_dir / relative, ns=(observed, observed))
        _remove_scan_local_file_if_exists(scan_dir, f"checkpoints/pending/{name}")


def _read_checkpoint_bytes(scan_dir: Path, relative: str) -> tuple[dict[str, Any], bytes]:
    try:
        return _read_scan_local_json_bytes(scan_dir, relative, "Saved scan checkpoint")
    except ContractError as error:
        if not isinstance(error.__cause__, FileNotFoundError):
            raise
        if not re.fullmatch(r"checkpoints/[0-9a-f]{64}\.json", relative):
            raise ContractError("saved checkpoint is missing") from None
        name = Path(relative).name
        pending = f"checkpoints/pending/{name}"
        with os.fdopen(
            open_scan_local_file_descriptor(scan_dir, pending, "Pending checkpoint"), "rb"
        ) as handle:
            contents = handle.read()
        if contents.startswith(b"drafts/"):
            staged = contents.decode("utf-8")
            if not re.fullmatch(r"drafts/[0-9a-fA-F-]+\.checkpoint\.json", staged):
                raise ContractError("pending checkpoint has no valid staged source") from None
            draft, contents = _read_scan_local_json_bytes(
                scan_dir, staged, "Staged scan checkpoint"
            )
            if hashlib.sha256(contents).hexdigest() != name.removesuffix(".json"):
                raise ContractError("staged checkpoint changed after publication failed") from None
            return draft, contents
        return _read_scan_local_json_bytes(scan_dir, pending, "Saved scan checkpoint")


def _read_saved_result(scan_dir: Path, relative: str, scan_id: str) -> tuple[dict[str, Any], str]:
    if _is_source_order_snapshot(relative):
        draft, digest, _ = _legacy_read_saved_result(scan_dir, relative, scan_id)
        return draft, digest
    draft, _ = _read_checkpoint_bytes(scan_dir, relative)
    if draft.get("scanId") != scan_id:
        raise ContractError("checkpoint belongs to a different scan")
    if not isinstance(draft.get("findings"), list) or not isinstance(draft.get("coverage"), dict):
        raise ContractError("checkpoint has no semantic findings or coverage")
    return draft, _digest(draft)


def _read_saved_parent_result(
    scan_dir: Path, scan_id: str, *, canonical: bool = False
) -> tuple[dict[str, Any], dict[str, Any]]:
    committed = scan_dir / "artifacts/scan-draft.json"
    sealed = False
    try:
        canonical_manifest = _read_scan_local_json(
            scan_dir, "scan-manifest.json", "Saved parent manifest"
        )
        canonical_scan = canonical_manifest.get("scan")
        sealed = isinstance(canonical_scan, dict) and bool(canonical_scan.get("sealedAt"))
    except (ContractError, OSError, ValueError):
        pass
    if not canonical and committed.exists() and not sealed:
        documents = _read_scan_local_json(
            scan_dir, "artifacts/scan-draft.json", "Committed scan draft"
        )
        for name in ("manifest", "findings", "coverage"):
            if not isinstance(documents.get(name), dict):
                raise ContractError(f"Committed scan draft has no {name} object")
        manifest, findings, coverage = (
            documents["manifest"],
            documents["findings"],
            documents["coverage"],
        )
    else:
        manifest = _read_scan_local_json(scan_dir, "scan-manifest.json", "Saved parent manifest")
        findings = _read_scan_local_json(scan_dir, "findings.json", "Saved parent findings")
        coverage = _read_scan_local_json(scan_dir, "coverage.json", "Saved parent coverage")
    return _saved_parent_result(scan_id, manifest, findings, coverage)


def _saved_parent_result(
    scan_id: str, manifest: dict[str, Any], findings: dict[str, Any], coverage: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    parent_scan = manifest.get("scan")
    if not isinstance(parent_scan, dict):
        raise ContractError("Saved parent manifest has no scan object")
    if (parent_scan.get("sealedAt") or parent_scan.get("artifacts")) and (
        parent_scan.get("id", scan_id) != scan_id
        or findings.get("scanId", scan_id) != scan_id
        or coverage.get("scanId", scan_id) != scan_id
    ):
        raise ContractError("Saved parent documents belong to a different scan")
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
    return manifest, parent


def _source_digests(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(relative, str) and isinstance(digest, str) for relative, digest in value.items()
    ):
        raise ContractError(f"{label} source digests are malformed.")
    return value


def _unpublished_committed_draft(
    scan_dir: Path, scan_id: str, frozen_sources: dict[str, str]
) -> dict[str, Any] | None:
    """Read later accepted corrections without replacing a sealed publication."""
    try:
        documents = _read_scan_local_json(
            scan_dir, "artifacts/scan-draft.json", "Committed scan draft"
        )
        _, draft = _saved_parent_result(
            scan_id, documents["manifest"], documents["findings"], documents["coverage"]
        )
    except (ContractError, OSError, ValueError, KeyError, TypeError):
        return None
    digest = _digest(draft)
    for relative in frozen_sources:
        if _is_source_order_snapshot(relative):
            record, record_digest = _read_saved_result(scan_dir, relative, scan_id)
            if record_digest != frozen_sources[relative]:
                raise ContractError("saved source ordering changed after the scan stopped")
            if isinstance(record.get("committedDraftDigest"), str):
                return draft if record["committedDraftDigest"] != digest else None
    return draft if digest not in frozen_sources.values() else None


def _saved_results_changed(db: Any, connection: Any, scan: Any) -> bool:
    try:
        scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
        manifest_path = db.artifact_path(scan_dir, db.ARTIFACTS["manifest"], required=False)
        paths = _saved_result_paths(scan_dir, scan["id"])
        frozen_sources = scan["retained_source_digests_json"]

        def has_saved_source() -> bool:
            for path in paths:
                try:
                    _read_saved_result(scan_dir, path, scan["id"])
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
            manifest_scan.get("preservedSources", {}), "Published scan"
        )
        current_sources = dict(published_sources)
        for path in paths:
            try:
                _, current_sources[path] = _read_saved_result(scan_dir, path, scan["id"])
            except (ContractError, OSError, ValueError):
                continue
        return (
            current_sources != published_sources
            or _unpublished_committed_draft(scan_dir, scan["id"], published_sources) is not None
            or save_composed_checkpoint(
                db,
                connection,
                scan,
                scan_dir,
                load_composition(connection, scan),
                retained_draft=_retained_composed_draft(db, scan, scan_dir),
                write=False,
            )
            is not None
        )
    except (ContractError, OSError, SystemExit, ValueError):
        return False


def _recovery_source_digests(
    db: Any,
    connection: Any,
    scan: Any,
    composition: CompositionView,
    recovery_warnings: list[str],
) -> tuple[dict[str, str], bool, str | None]:
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
                    manifest_scan["preservedSources"], "Published scan"
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

    retained = _retained_composed_draft(db, scan, scan_dir)
    selected_committed = None
    committed_digest = None
    if frozen_sources is not None:
        committed = _unpublished_committed_draft(scan_dir, scan["id"], frozen_sources)
        if committed is not None:
            committed_digest = _digest(committed)
            retained = committed
            selected_committed = f"checkpoints/{_digest(committed)}.json"
            if not (scan_dir / selected_committed).exists():
                write_scan_local_bytes(scan_dir, selected_committed, _encoded(committed))
                observed = (scan_dir / "artifacts/scan-draft.json").stat().st_mtime_ns
                os.utime(scan_dir / selected_committed, ns=(observed, observed))
    # Explicit recovery includes later child corrections in the retained parent.
    aggregate = save_composed_checkpoint(
        db,
        connection,
        scan,
        scan_dir,
        composition,
        recovery_warnings,
        retained_draft=retained,
    )
    paths = set(_saved_result_paths(scan_dir, scan["id"]))
    if selected_committed is not None:
        paths.add(selected_committed)
    recovery_sources = dict(frozen_sources or {})
    source_times = _frozen_source_times(scan_dir, scan["id"], recovery_sources)
    for relative, expected_digest in recovery_sources.items():
        try:
            _, digest = _read_saved_result(scan_dir, relative, scan["id"])
        except (ContractError, OSError, ValueError) as exc:
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")

    for relative in paths - recovery_sources.keys():
        try:
            _, recovery_sources[relative] = _read_saved_result(scan_dir, relative, scan["id"])
        except (ContractError, OSError, ValueError):
            continue
    for relative in recovery_sources:
        if relative not in source_times and not _is_source_order_snapshot(relative):
            path = scan_dir / relative
            if not path.exists():
                path = scan_dir / "checkpoints/pending" / Path(relative).name
            source_times[relative] = path.stat().st_mtime_ns
    selected = (
        f"checkpoints/{_digest(aggregate)}.json" if aggregate is not None else selected_committed
    )
    _freeze_source_times(
        scan_dir,
        scan["id"],
        recovery_sources,
        source_times,
        selected_parent_checkpoint=selected,
        committed_draft_digest=committed_digest,
        selected_parent_observed_at=(
            (scan_dir / "artifacts/scan-draft.json").stat().st_mtime_ns
            if selected_committed is not None and aggregate is None
            else (scan_dir / selected).stat().st_mtime_ns
            if selected is not None
            else None
        ),
    )
    return (
        recovery_sources,
        include_parent,
        selected,
    )


def scan_results_recovery_needed(db: Any, connection: Any, scan: Any) -> bool:
    if scan["status"] != "failed" or scan["canceled_at"] is not None:
        return False
    warnings = json.loads(scan["completion_warnings_json"])
    if any(
        isinstance(warning, str) and warning.startswith(_PUBLICATION_FOLLOW_UP_WARNING)
        for warning in warnings
    ):
        return True
    return _saved_results_changed(db, connection, scan)


def _finding_key(finding: dict[str, Any]) -> str:
    # Wording and evidence may improve between checkpoints; distinct source locations
    # must not collide merely because two checkpoints use the same semantic identity.
    provenance = finding.get("provenance")
    identity = (
        provenance.get("preservedIdentity", finding.get("identity"))
        if isinstance(provenance, dict)
        else finding.get("identity")
    )
    if not isinstance(identity, dict):
        extensions = finding.get("extensions")
        source = str(
            (extensions.get("candidateId") if isinstance(extensions, dict) else None)
            or finding.get("title")
            or "finding"
        )
        identity = {
            "anchor": re.sub(r"[^a-z0-9._/-]+", "-", source.lower()).strip("._/-") or "finding"
        }
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


def merge_saved_results(
    scan_dir: Path,
    scan_id: str,
    binding: dict[str, Any],
    warnings: list[str],
    *,
    stopped: bool,
    reason: str,
    frozen_source_digests: dict[str, str] | None = None,
    allow_frozen_legacy_parent: bool = False,
    parent_documents: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None = None,
    frozen_model_source: str | None = None,
    selected_parent_checkpoint: str | None = None,
    write_snapshots: bool = True,
    composed_child_ids: tuple[str, ...] = (),
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Read only bound current parent/checkpoint files; return an unsealed loss-preserving union."""
    initial_warnings = set(warnings)
    source_times = _frozen_source_times(scan_dir, scan_id, frozen_source_digests or {})
    if selected_parent_checkpoint is None and frozen_source_digests:
        for relative in frozen_source_digests:
            if _is_source_order_snapshot(relative):
                record, _ = _read_saved_result(scan_dir, relative, scan_id)
                selected = record.get("selectedParentCheckpoint")
                if isinstance(selected, str) and selected in frozen_source_digests:
                    selected_parent_checkpoint = selected
    parent_observed = 0
    committed_digest = None
    parent: dict[str, Any] | None = None
    parent_manifest: dict[str, Any] | None = None
    parent_checkpoint = None
    if frozen_source_digests is None or allow_frozen_legacy_parent:
        try:
            parent_manifest, parent = (
                _saved_parent_result(scan_id, *parent_documents)
                if parent_documents is not None
                else _read_saved_parent_result(scan_dir, scan_id)
            )
        except (ContractError, OSError, ValueError) as exc:
            if not stopped:
                raise
            if (scan_dir / "scan-manifest.json").exists():
                warnings.append(f"Could not read the saved parent draft: {exc}")
            parent_manifest = None
            parent = None
        if parent_manifest is not None and parent is not None:
            head_path = scan_dir / "artifacts/scan-draft.json"
            if not head_path.exists():
                head_path = scan_dir / "coverage.json"
            parent_observed = head_path.stat().st_mtime_ns
            if head_path.name == "scan-draft.json" and not parent_manifest["scan"].get("sealedAt"):
                committed_digest = _digest(parent)
            parent_scan = parent_manifest["scan"]
            if not parent_scan.get("sealedAt") or allow_frozen_legacy_parent:
                payload = _encoded(parent)
                parent_digest = hashlib.sha256(payload).hexdigest()
                parent_checkpoint = f"checkpoints/{parent_digest}.json"
                if write_snapshots and not (scan_dir / parent_checkpoint).exists():
                    write_scan_local_bytes(scan_dir, parent_checkpoint, payload)
                    os.utime(scan_dir / parent_checkpoint, ns=(parent_observed, parent_observed))
                source_times.setdefault(parent_checkpoint, parent_observed)
                if frozen_source_digests is not None:
                    frozen_source_digests = {
                        **frozen_source_digests,
                        parent_checkpoint: parent_digest,
                    }

    current_checkpoint = None
    current_coverage = None
    if (
        stopped
        and frozen_source_digests is None
        and (scan_dir / "artifacts/scan-draft.json").exists()
    ):
        # SDK turns can write newer canonical files after their last MCP snapshot.
        # Retain those observations without replacing the committed reconciliation head.
        try:
            current_manifest, current = _read_saved_parent_result(scan_dir, scan_id, canonical=True)
            # The manifest is exported last. Only a matching envelope admits
            # later file-authored edits; older exports cannot reopen accepted history.
            if (
                not current_manifest["scan"].get("sealedAt")
                and parent_manifest
                and current_manifest["scan"].get("completedAt") is not None
                and current_manifest["scan"]["completedAt"]
                == parent_manifest["scan"].get("completedAt")
            ):
                payload = _encoded(current)
                current_checkpoint = f"checkpoints/{_digest(current)}.json"
                if write_snapshots:
                    write_scan_local_bytes(scan_dir, current_checkpoint, payload)
                current_coverage = copy.deepcopy(current["coverage"])
                _recover_unsealed_coverage(
                    current_coverage,
                    Path(__file__).resolve().parent.parent / "schemas",
                    scan_dir,
                    [],
                    [],
                )
        except (ContractError, OSError, ValueError) as exc:
            if (scan_dir / "findings.json").exists():
                warnings.append(f"Could not retain current file-authored results: {exc}")

    sources: list[tuple[str, dict[str, Any]]] = []
    parent_preserved_sources: dict[str, str] = {}
    source_digests: dict[str, str] = {}
    if parent_manifest:
        recorded = parent_manifest["scan"].get("preservedSources", {})
        if isinstance(recorded, dict):
            parent_preserved_sources = recorded
            source_digests.update(parent_preserved_sources)
            if frozen_source_digests is None:
                source_times.update(
                    _frozen_source_times(scan_dir, scan_id, parent_preserved_sources)
                )
    pending_paths = set(_pending_result_paths(scan_dir)) if parent is not None else set()
    paths = (
        list(frozen_source_digests)
        if frozen_source_digests is not None
        else (
            sorted(pending_paths)
            if (
                not stopped
                and parent is not None
                and parent.get("complete") is not False
                and (scan_dir / "artifacts/scan-draft.json").exists()
            )
            else _saved_result_paths(scan_dir, scan_id)
        )
    )
    if frozen_source_digests is None:
        paths = list(
            dict.fromkeys([*paths, *filter(None, (parent_checkpoint, current_checkpoint))])
        )

    for relative in paths:
        try:
            draft, digest = _read_saved_result(scan_dir, relative, scan_id)
            if frozen_source_digests is not None and frozen_source_digests[relative] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            source_digests[relative] = digest
            if _is_source_order_snapshot(relative):
                continue
            source_path = scan_dir / relative
            if not source_path.exists():
                source_path = scan_dir / "checkpoints/pending" / Path(relative).name
            source_times.setdefault(relative, source_path.stat().st_mtime_ns)
            if write_snapshots and not (scan_dir / relative).exists():
                _, contents = _read_checkpoint_bytes(scan_dir, relative)
                write_scan_local_bytes(scan_dir, relative, contents)
                observed = source_times[relative]
                os.utime(scan_dir / relative, ns=(observed, observed))
            sources.append((relative, draft))
        except (ContractError, OSError, ValueError) as exc:
            if (scan_dir / relative).exists():
                warnings.append(f"Preserved unreadable checkpoint {relative}: {exc}")
    if frozen_source_digests is not None:
        if frozen_source_digests.keys() - source_digests.keys():
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.")

    if selected_parent_checkpoint is not None:
        selected = next(
            (draft for relative, draft in sources if relative == selected_parent_checkpoint), None
        )
        if selected is not None:
            parent = copy.deepcopy(selected)
            parent_manifest = parent_manifest or {"scan": {}}
            parent_observed = source_times[selected_parent_checkpoint]
            for relative in frozen_source_digests or {}:
                if _is_source_order_snapshot(relative):
                    record, _ = _read_saved_result(scan_dir, relative, scan_id)
                    observed = record.get("selectedParentObservedAtNs")
                    if (
                        record.get("selectedParentCheckpoint") == selected_parent_checkpoint
                        and isinstance(observed, str)
                        and re.fullmatch(r"-?[0-9]+", observed)
                    ):
                        parent_observed = int(observed)
            parent_manifest["scan"].update(
                (key, copy.deepcopy(selected[key]))
                for key in ("scope", "threatModel", "complete")
                if key in selected
            )

    if parent is None and not sources:
        if not stopped or frozen_source_digests is not None:
            return None
        if (scan_dir / "scan-manifest.json").exists():
            try:
                manifest = _read_scan_local_json(
                    scan_dir, "scan-manifest.json", "Saved scan manifest"
                )
            except (ContractError, OSError, ValueError):
                return None
            if not isinstance(manifest.get("scan"), dict):
                # Loose coverage cannot replace an unreadable draft. Keep it
                # intact until a valid committed draft or checkpoint is available.
                return None
        try:
            coverage = _read_scan_local_json(scan_dir, "coverage.json", "Saved scan coverage")
        except (ContractError, OSError, ValueError):
            return None
        if coverage.get("scanId", scan_id) != scan_id:
            return None
        parent = {"scanId": scan_id, "findings": [], "coverage": coverage, "complete": False}
        payload = _encoded(parent)
        digest = hashlib.sha256(payload).hexdigest()
        relative = f"checkpoints/{digest}.json"
        if write_snapshots:
            write_scan_local_bytes(scan_dir, relative, payload)
        source_digests[relative] = digest
        source_times[relative] = (scan_dir / "coverage.json").stat().st_mtime_ns
    if (
        parent_manifest
        and parent_manifest["scan"].get("sealedAt")
        and parent_manifest["scan"].get("status") == binding["status"]
        and parent_manifest["scan"].get("preservedSources") == source_digests
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
    for key in ("sealedAt", "artifacts"):
        manifest["scan"].pop(key, None)
    manifest["scan"].setdefault("target", target)
    manifest["scan"]["scope"] = {
        **manifest["scan"].get("scope", {}),
        **binding["scope"],
    }
    manifest["scan"]["preservedSources"] = source_digests
    all_sources = ([("parent", parent)] if parent else []) + sources
    source_times["parent"] = parent_observed
    _retire_previous_child_coverage(
        [(relative, draft, None) for relative, draft in all_sources],
        {relative: (0, source_times.get(relative, 0)) for relative, _ in all_sources},
        composed_child_ids,
    )
    coverage = (
        copy.deepcopy(parent["coverage"])
        if parent and parent["coverage"]
        else {
            "completeness": "partial",
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

    def plain_row(item: Any) -> bool:
        return isinstance(item, dict) and not any(
            key in item for key in ("candidateId", "candidate", "finding")
        )

    def valid_coverage_row(item: Any, schema: dict[str, Any]) -> bool:
        try:
            _validate_schema_node(item, schema, "coverage.deferred")
        except ContractError:
            return False
        return True

    surfaces = coverage.get("surfaces", [])
    surface_rows = {
        item["id"]: item
        for item in (surfaces if isinstance(surfaces, list) else [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    if current_coverage is not None and isinstance(surfaces, list):
        current_surfaces = current_coverage.get("surfaces", [])
        for item in current_surfaces if isinstance(current_surfaces, list) else []:
            if (
                not plain_row(item)
                or not isinstance(item.get("id"), str)
                or item.get("disposition") not in DISPOSITIONS
            ):
                continue
            previous = surface_rows.get(item["id"])
            if previous is None:
                previous = copy.deepcopy(item)
                surfaces.append(previous)
                surface_rows[item["id"]] = previous
            elif plain_row(previous):
                previous.clear()
                previous.update(copy.deepcopy(item))
    canonical_rows = (
        {
            id(item)
            for field in ("surfaces", "explicitExclusions", "deferred")
            for item in (coverage.get(field) if isinstance(coverage.get(field), list) else [])
        }
        if parent_manifest
        else set()
    )
    findings: list[dict[str, Any]] = []
    finding_positions: dict[str, int] = {}
    represented: dict[str, str | None] = {}
    represented_history: dict[str, set[str]] = {}
    stopped_parent_seal = bool(
        stopped and parent_manifest and parent_manifest["scan"].get("sealedAt")
    )

    finding_schema = _read_json(
        Path(__file__).resolve().parent.parent / "schemas" / "findings.schema.json"
    )
    finding_validity: dict[str, bool] = {}

    def finding_in_scope(finding: dict[str, Any]) -> bool:
        locations = finding.get("locations", [])
        return isinstance(locations, list) and any(
            isinstance(location, dict)
            and isinstance(location.get("path"), str)
            and any(
                path_within_scope(location["path"], path)
                for path in binding["scope"]["includePaths"]
            )
            for location in locations
        )

    def valid_finding(value: Any) -> bool:
        # Use the finalizer's own per-record recovery before a draft can suppress
        # an earlier checkpoint. Invalid latest records must not hide valid history.
        key = _digest(value)
        if key in finding_validity:
            return finding_validity[key]
        document = {"scanId": scan_id, "findings": [copy.deepcopy(value)]}
        _ensure_finding_identity(document["findings"][0], candidate_only=True)
        _recover_unsealed_findings(
            {"scan": {"id": scan_id, "target": binding["target"]}},
            document,
            finding_schema,
            scan_dir,
            [],
        )
        finding_validity[key] = bool(document["findings"])
        return finding_validity[key]

    all_sources = ([("parent", parent)] if parent else []) + sources
    source_times["parent"] = parent_observed
    coverage_schema = _read_json(
        Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
    )["properties"]
    closed_deferred: dict[str, tuple[int, dict[str, Any]]] = {}
    active_deferred: dict[str, int] = {}
    ambiguous_deferred: set[str] = set()
    latest_generic: dict[str, tuple[int, dict[str, Any]]] = {}
    for relative, draft in all_sources:
        observed = source_times.get(relative, 0)
        seen: dict[str, Any] = {}
        items = draft["coverage"].get("deferred", [])
        items = items if isinstance(items, list) else []
        candidate_aliases = {
            identity
            for item in items
            if isinstance(item, dict) and not plain_row(item)
            for identity in (item.get("id"), item.get("candidateId"))
            if isinstance(identity, str)
        }
        for item in items:
            if not isinstance(item, dict):
                continue
            identity = item.get("id") or item.get("candidateId")
            if not isinstance(identity, str):
                continue
            if (identity in seen and item != seen[identity]) or identity in candidate_aliases:
                ambiguous_deferred.add(identity)
            seen[identity] = item
            active_deferred[identity] = max(active_deferred.get(identity, observed), observed)
            if plain_row(item) and valid_coverage_row(item, coverage_schema["deferred"]["items"]):
                previous = latest_generic.get(identity)
                if previous is None or observed > previous[0]:
                    latest_generic[identity] = (observed, item)
        for closure in _resolved_deferred_rows(
            draft,
            coverage_schema["resolvedDeferred"],
            accepted=relative in {"parent", selected_parent_checkpoint},
        ):
            previous = closed_deferred.get(closure["id"])
            if previous is None or observed > previous[0]:
                closed_deferred[closure["id"]] = (observed, closure)
    closed_deferred = {
        identity: value
        for identity, value in closed_deferred.items()
        if identity not in ambiguous_deferred and active_deferred.get(identity, -1) < value[0]
    }
    coverage.pop("resolvedDeferred", None)
    if closed_deferred:
        coverage["resolvedDeferred"] = [
            copy.deepcopy(value[1]) for value in closed_deferred.values()
        ]
    # Ambiguous legacy task IDs cannot identify an implicit replacement or closure.
    # Keep each distinct task even when a current draft resolves the matching candidate.
    deferred_output = coverage.setdefault("deferred", [])
    if isinstance(deferred_output, list):
        for _, draft in all_sources:
            items = draft["coverage"].get("deferred", [])
            for item in items if isinstance(items, list) else []:
                if (
                    plain_row(item)
                    and isinstance(item.get("id"), str)
                    and item["id"] in ambiguous_deferred
                    and item not in deferred_output
                ):
                    deferred_output.append(copy.deepcopy(item))
    ambiguous_surfaces = {
        surface_id
        for _, draft in all_sources
        for item in _deferred_rows(draft["coverage"])
        if plain_row(item) and isinstance(item.get("id"), str) and item["id"] in ambiguous_deferred
        for surface_id in item.get("surfaceIds", [])
        if isinstance(surface_id, str)
    }
    surface_output = coverage.setdefault("surfaces", [])
    if isinstance(surface_output, list):
        for _, draft in all_sources:
            items = draft["coverage"].get("surfaces", [])
            for item in items if isinstance(items, list) else []:
                if (
                    plain_row(item)
                    and isinstance(item.get("id"), str)
                    and item["id"] in ambiguous_surfaces
                    and item.get("disposition") == "needs_follow_up"
                    and item not in surface_output
                ):
                    surface_output.append(copy.deepcopy(item))
    terminal_drafts = (
        [parent]
        if parent and parent.get("complete") is not False
        else [
            draft
            for relative, draft in sources
            if draft.get("complete") is not False
            and (frozen_source_digests is None or source_times.get(relative, 0) <= parent_observed)
        ]
    )
    terminal_parent_keys = _terminal_parent_finding_keys(parent, terminal_drafts, None)
    if write_snapshots and source_digests:
        _freeze_source_times(
            scan_dir,
            scan_id,
            source_digests,
            source_times,
            selected_parent_checkpoint=selected_parent_checkpoint or parent_checkpoint,
            committed_draft_digest=committed_digest,
            selected_parent_observed_at=parent_observed if parent is not None else None,
        )
    resolved: dict[str, str] = {}
    resolved_surfaces: set[str] = set()
    pending_surfaces: set[str] = set()
    pending_work: set[bytes] = set()
    parent_findings_valid = True
    # Only the unchanged current parent can supersede earlier checkpoints.
    if parent:
        for finding in parent["findings"]:
            if not valid_finding(finding):
                parent_findings_valid = False
                continue
            if candidate_id := finding_candidate_id(finding):
                resolved.setdefault(candidate_id, "reported")
            canonical_key = _finding_key(finding)
            for _, retained in retained_findings(finding):
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
        for field in ("surfaces", "explicitExclusions"):
            items = coverage.get(field, [])
            for item in items if isinstance(items, list) else []:
                if (
                    field == "surfaces"
                    and isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                    and item.get("disposition")
                    in {"reported", "no_issue_found", "rejected", "not_applicable"}
                ):
                    resolved_surfaces.add(item["id"])
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                    and item.get("disposition") in {"reported", "rejected", "not_applicable"}
                ):
                    resolved.setdefault(item["candidateId"], item["disposition"])
        deferred = (current_coverage if current_coverage is not None else coverage).get(
            "deferred", []
        )
        for item in deferred if isinstance(deferred, list) else []:
            if isinstance(item, dict) and isinstance(item.get("surfaceIds"), list):
                pending_surfaces.update(
                    value for value in item["surfaceIds"] if isinstance(value, str)
                )

    if current_coverage is not None and isinstance(surfaces, list):
        current_candidates = {
            finding_candidate_id(finding)
            for finding in current["findings"]
            if isinstance(finding, dict) and valid_finding(finding) and finding_in_scope(finding)
        }
        for item in current_coverage["surfaces"]:
            candidate_id = item.get("candidateId")
            if isinstance(candidate_id, str) and (
                item["disposition"] in {"rejected", "not_applicable"}
                or (item["disposition"] == "reported" and candidate_id in current_candidates)
            ):
                resolved[candidate_id] = item["disposition"]
                current_surface = surface_rows.get(item["id"])
                if current_surface != item:
                    current_surface = copy.deepcopy(item)
                    surfaces.append(current_surface)
                surface_rows[item["id"]] = current_surface
                resolved_surfaces.add(item["id"])

    for relative, draft in all_sources:
        superseded = (
            parent is not None
            and parent.get("complete") is not False
            and relative not in {"parent", current_checkpoint, selected_parent_checkpoint}
            and relative not in pending_paths
            and source_times.get(relative, 0) <= parent_observed
            and (not stopped_parent_seal or relative in parent_preserved_sources)
        )
        if (
            (relative != "parent" or not parent_manifest)
            and not superseded
            and (
                draft.get("complete") is False
                or draft["coverage"].get("completeness") != "complete"
            )
            and coverage.get("completeness") in {"complete", "unknown"}
        ):
            coverage["completeness"] = "partial"
        if superseded and not stopped and parent_findings_valid:
            continue
        if relative in pending_paths:
            pending_work.update(_encoded(item) for item in draft["coverage"].get("deferred", []))
        if isinstance(draft.get("threatModel"), dict) and (
            relative == frozen_model_source or "threatModel" not in manifest["scan"]
        ):
            manifest["scan"]["threatModel"] = copy.deepcopy(draft["threatModel"])
        for value in draft["findings"]:
            if (
                relative == "parent"
                and parent_manifest
                and (
                    not isinstance(value, dict)
                    or resolved.get(finding_candidate_id(value))
                    not in {"rejected", "not_applicable"}
                    or not valid_finding(value)
                )
            ):
                finding = copy.deepcopy(value)
                _ensure_finding_identity(finding, candidate_only=True)
                if valid_finding(value):
                    finding_positions.setdefault(_finding_key(finding), len(findings))
                findings.append(finding)
                continue
            if relative != "parent" and parent and value in parent["findings"]:
                continue
            if not isinstance(value, dict):
                warnings.append(f"Retained malformed finding evidence in {relative}.")
                continue
            source_value = copy.deepcopy(value)
            finding = copy.deepcopy(value)
            candidate_id = finding_candidate_id(finding)
            if resolved.get(candidate_id) in {
                "rejected",
                "not_applicable",
            }:
                surfaces = coverage.get("surfaces")
                for item in surfaces if isinstance(surfaces, list) else []:
                    if (
                        isinstance(item, dict)
                        and item.get("candidateId") == candidate_id
                        and item.get("disposition") == resolved[candidate_id]
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
            if not finding_in_scope(finding):
                warnings.append(f"Skipped out-of-scope finding from {relative}.")
                coverage["completeness"] = "partial"
                continue
            provenance = finding.setdefault("provenance", {"source": "local_plugin"})
            if not isinstance(provenance, dict):
                findings.append(finding)
                continue
            _ensure_finding_identity(finding)
            if not valid_finding(finding):
                findings.append(finding)
                continue
            if relative == current_checkpoint and current_coverage is not None and candidate_id:
                resolved.setdefault(candidate_id, "reported")
            key = _finding_key(finding)
            represented_by_parent = False
            if relative != "parent":
                if key in represented:
                    mapped_key = represented[key]
                    historical_contents = represented_history.get(key, set())
                else:
                    mapped_key = None
                    historical_contents = set()
                if mapped_key is not None:
                    key = mapped_key
                    represented_by_parent = (
                        _digest(_finding_content(source_value)) in historical_contents
                    )
            if key in finding_positions:
                retained = findings[finding_positions[key]]
                if finding != retained:
                    if represented_by_parent:
                        previous = copy.deepcopy(source_value)
                        previous_history = previous.get("provenance", {}).pop(
                            "previousFindings", []
                        )
                    elif key not in terminal_parent_keys and _finding_strength(
                        finding
                    ) > _finding_strength(retained):
                        previous = copy.deepcopy(retained)
                        previous_history = previous["provenance"].pop("previousFindings", [])
                        retained = finding
                        findings[finding_positions[key]] = retained
                    else:
                        previous = copy.deepcopy(source_value)
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
                            for _, historical in retained_findings(retained)
                        )
                        if (
                            not already_retained
                            and original not in history
                            and original != retained
                        ):
                            history.append(original)
                    if history or isinstance(retained_history, list):
                        retained_provenance["previousFindings"] = history
                continue
            finding_positions[key] = len(findings)
            findings.append(finding)
        if superseded:
            continue
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
            items = draft["coverage"].get(field, [])
            if not isinstance(items, list):
                continue
            output = coverage.setdefault(field, [])
            if not isinstance(output, list):
                # Keep malformed canonical collections for the existing finalizer's
                # recovery and warnings rather than silently changing its contract.
                continue
            for item in items:
                if field == "openQuestions" and isinstance(item, str):
                    item = {"question": item.strip()}
                if isinstance(item, dict) and "id" not in item:
                    semantic_item = dict(item)
                    if field == "surfaces":
                        semantic_item.setdefault("receiptRefs", [])
                    if any(
                        isinstance(existing, dict)
                        and {key: value for key, value in existing.items() if key != "id"}
                        == semantic_item
                        for existing in output
                    ):
                        continue
                if item not in output:
                    output.append(copy.deepcopy(item))

    identities: dict[str, str] = {}
    resolved_rows: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if not valid_finding(finding):
            continue
        if candidate_id := finding_candidate_id(finding):
            resolved_rows.setdefault(candidate_id, finding)
        identity = finding.get("identity")
        if not isinstance(identity, dict):
            continue
        key = _encoded([finding.get("ruleId"), identity]).decode()
        variant = _finding_key(finding)
        if key in identities and identities[key] != variant:
            finding.setdefault("provenance", {})["preservedIdentity"] = copy.deepcopy(identity)
            identity["instance"] = f"{identity.get('instance', 'saved')}-{variant[:16]}"
        identities[key] = variant
    for field in ("surfaces", "explicitExclusions"):
        rows = coverage.get(field, [])
        for item in rows if isinstance(rows, list) else []:
            if (
                isinstance(item, dict)
                and isinstance(item.get("candidateId"), str)
                and item.get("disposition") in {"rejected", "not_applicable"}
                and item["disposition"] == resolved.get(item["candidateId"])
                and (field != "surfaces" or surface_rows.get(item.get("id")) is item)
            ):
                resolved_rows.setdefault(item["candidateId"], item)

    def superseded_work(field: str, item: Any) -> bool:
        if (
            field == "surfaces"
            and plain_row(item)
            and isinstance(item.get("id"), str)
            and item["id"] in ambiguous_surfaces
            and item.get("disposition") == "needs_follow_up"
        ):
            return False
        if (
            field == "deferred"
            and isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and item["id"] in closed_deferred
        ):
            return True
        if (
            field == "deferred"
            and plain_row(item)
            and isinstance(item.get("id"), str)
            and item["id"] not in ambiguous_deferred
            and item["id"] in latest_generic
            and item != latest_generic[item["id"]][1]
        ):
            return True
        superseded_surface = (
            field == "surfaces"
            and isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and item["id"] in surface_rows
            and item != surface_rows[item["id"]]
        )
        if (
            isinstance(item, dict)
            and item.get("candidateId") in resolved
            and (
                field == "deferred"
                or item.get("disposition") == "needs_follow_up"
                or superseded_surface
                or (
                    field == "surfaces"
                    and item.get("disposition") in DISPOSITIONS
                    and item["disposition"] != resolved[item["candidateId"]]
                )
            )
        ):
            current_row = resolved_rows.get(item["candidateId"])
            if current_row is not None:
                for source, destination in (
                    ("candidate", "originalCandidates"),
                    ("finding", "previousFindings"),
                ):
                    if source not in item:
                        continue
                    if resolved[item["candidateId"]] == "reported":
                        provenance = current_row["provenance"]
                        history = provenance.get(destination)
                        if not isinstance(history, list):
                            history = provenance[destination] = []
                        if item[source] not in history and item[source] != current_row:
                            history.append(copy.deepcopy(item[source]))
                    else:
                        current_row.setdefault(source, copy.deepcopy(item[source]))
            return True
        if not plain_row(item):
            return False
        if field == "surfaces":
            return superseded_surface
        return (
            field == "deferred"
            and _encoded(item) not in pending_work
            and isinstance(item.get("surfaceIds"), list)
            and bool(item["surfaceIds"])
            and all(
                isinstance(value, str)
                and value in resolved_surfaces
                and value not in pending_surfaces
                for value in item["surfaceIds"]
            )
        )

    for field in ("surfaces", "explicitExclusions", "deferred"):
        used: set[str] = set()
        items = coverage.setdefault(field, [])
        if isinstance(items, list):
            items[:] = [item for item in items if not superseded_work(field, item)]
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            if field == "surfaces":
                item.setdefault("receiptRefs", [])
            if id(item) in canonical_rows:
                if isinstance(item.get("id"), str):
                    used.add(item["id"])
                continue
            item.setdefault("id", item.get("candidateId") or f"saved-{_digest(item)[:16]}")
            if item["id"] in used:
                item["id"] = f"{item['id']}-{_digest(item)[:16]}"
            used.add(item["id"])
    if stopped or any(warning not in initial_warnings for warning in warnings):
        coverage["completeness"] = "partial"
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
        _, _, manifest, _, coverage, was_sealed, _ = _prepare_scan_finalization(scan_dir)
    except ContractError as exc:
        raise SystemExit(str(exc)) from exc
    if not was_sealed or manifest["scan"]["id"] != scan["id"]:
        raise SystemExit("Only sealed scans can be compared.")
    return coverage


@contextmanager
def preserve_prepared_sources_on_error(scan_dir: Path) -> Iterator[None]:
    """Rejected completion attempts must not become accepted observations."""
    directories = ("checkpoints", "checkpoints/pending", "source-order")

    def files() -> set[str]:
        return {
            f"{directory}/{name}"
            for directory in directories
            for name in _children(scan_dir, directory)
            if re.fullmatch(r"[0-9a-f]{64}\.json", name)
        }

    previous = files()
    try:
        yield
    except ContractError:
        for relative in files() - previous:
            _remove_scan_local_file_if_exists(scan_dir, relative)
        raise


def _snapshot_published_outputs(scan_dir: Path) -> dict[str, bytes | None]:
    snapshots: dict[str, bytes | None] = {}
    for relative in _PUBLISHED_OUTPUTS:
        descriptor = -1
        try:
            descriptor = open_scan_local_file_descriptor(
                scan_dir, relative, "Published scan output"
            )
            with os.fdopen(descriptor, "rb") as handle:
                descriptor = -1
                snapshots[relative] = handle.read()
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


def _restore_published_outputs(scan_dir: Path, snapshots: dict[str, bytes | None]) -> None:
    for relative, contents in snapshots.items():
        if contents is None:
            path = scan_dir / relative
            if path.exists() or path.is_symlink():
                _remove_scan_local_file_if_exists(scan_dir, relative)
        else:
            write_scan_local_bytes(scan_dir, relative, contents)


def require_current_deep_scan(db: Any, connection: Any, scan: Any) -> None:
    """Historical sealed results stay readable; retired executions do not resume."""
    if scan["mode"] != "deep" or scan["seal_manifest_digest"] is not None:
        return
    checkpoint = read_composition_checkpoint(scan, load_aggregate=False)
    if (checkpoint is not None and checkpoint["version"] != 3) or connection.execute(
        "SELECT 1 FROM deep_scan_runs WHERE scan_id = ?", (scan["id"],)
    ).fetchone() is not None:
        if db.sealed_scan_producer_version(scan) is not None:
            return
        raise SystemExit(
            "This Deep Scan used a retired execution engine or checkpoint format. Recover unfinished work with "
            "its original version, or start a new scan. Saved files have not been changed."
        )


def _stopped_child_draft(
    db: Any, child: Any, scan_dir: Path, *, write_snapshots: bool = True
) -> dict[str, Any] | None:
    """Read one ordinary saved scan through its normal validation and recovery path."""
    child_dir = db.require_canonical_scan_directory(Path(child["scan_dir"]))
    manifest_path = db.artifact_path(child_dir, "scan-manifest.json", required=False)
    manifest_scan = db.read_json_object(manifest_path).get("scan", {}) if manifest_path else {}
    if child["seal_manifest_digest"] is not None or (
        isinstance(manifest_scan, dict)
        and (
            manifest_scan.get("sealedAt") is not None or manifest_scan.get("artifacts") is not None
        )
    ):
        db.require_recorded_manifest_digest(child, child_dir)
        _, _, manifest, findings, coverage, _, _ = _prepare_scan_finalization(child_dir)
    else:
        binding = {**db.workbench_completion_binding(child, db.now()), "status": "interrupted"}
        warnings: list[str] = []
        frozen_sources, frozen_model = None, None
        if child["retained_source_digests_json"] is not None:
            frozen_sources, frozen_model = _retained_source_state(
                json.loads(child["retained_source_digests_json"])
            )
        documents = merge_saved_results(
            child_dir,
            child["id"],
            binding,
            warnings,
            stopped=True,
            reason="Independent scan stopped before aggregation.",
            frozen_source_digests=frozen_sources,
            frozen_model_source=frozen_model,
            write_snapshots=write_snapshots,
        )
        if documents is None:
            return None
        _, _, manifest, findings, coverage, _, _ = _prepare_scan_finalization(
            child_dir,
            completion_binding=binding,
            completion_warnings=warnings,
            draft_documents=documents,
        )
    db.verify_manifest_binding(child, manifest)
    projected = project_scan_artifacts(
        child["parent_scan_id"], child["id"], child_dir, scan_dir, manifest, findings, coverage
    )
    draft = projected["draft"]
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        for row in draft["coverage"].get(field, []):
            if not isinstance(row.get("id"), str):
                row["id"] = f"{child['id']}/{field}-{_digest(row)}"
    for index, finding in enumerate(draft["findings"]):
        # No semantic merge has accepted these independent observations yet.
        identity = finding["identity"]
        identity["instance"] = f"{child['id']}-{_encoded(identity.get('instance')).hex()}"
        provenance = finding["provenance"]
        provenance.pop("preservedIdentity", None)
        provenance["sourceFindings"] = [
            {"id": f"{child['id']}:{index}", "finding": projected["sourceFindings"][index]}
        ]
    return draft


def materialize_sources(draft: dict[str, Any]) -> dict[str, Any]:
    """Expand current flat provenance for the existing public report format."""
    result = copy.deepcopy(draft)
    sources = result.pop("sourceFindings", {})
    revisions = result.pop("revisions", {})
    for finding in result["findings"]:
        provenance = finding.get("provenance", {})
        revision_ids = provenance.pop("revisionIds", [])
        if revision_ids:
            provenance["previousFindings"] = [revisions[key] for key in revision_ids]
        source_ids = provenance.get("sourceFindingIds", [])
        if sources and source_ids:
            provenance["sourceFindings"] = [
                {"id": key, "finding": sources[key]} for key in source_ids
            ]
    return result


def union_coverage(target: dict[str, Any], source: dict[str, Any]) -> None:
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        rows = target.setdefault(field, [])
        seen = {_encoded(row) for row in rows}
        for row in source.get(field, []):
            key = _encoded(row)
            if key not in seen:
                seen.add(key)
                rows.append(copy.deepcopy(row))


def save_composed_checkpoint(
    db: Any,
    connection: Any,
    scan: Any,
    scan_dir: Path,
    composition: CompositionView,
    warnings: list[str] | None = None,
    *,
    retained_draft: dict[str, Any] | None = None,
    write: bool = True,
) -> dict[str, Any] | None:
    """Retain accepted progress and unmerged ordinary child observations."""
    checkpoint = read_composition_checkpoint(scan) if composition.checkpoint is not None else None
    children = {child["scan_dir"]: child for child in composition.children}
    if checkpoint is None and not children:
        return None
    merged_ids = set(checkpoint["mergedScanIds"]) if checkpoint is not None else set()
    aggregate = checkpoint["aggregate"] if checkpoint is not None else None
    aggregate = materialize_sources(aggregate) if isinstance(aggregate, dict) else None
    previous_aggregate = None
    if retained_draft is not None:
        aggregate = copy.deepcopy(retained_draft)
        aggregate["complete"] = False
        for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
            aggregate["coverage"].setdefault(field, [])
        previous_aggregate = copy.deepcopy(aggregate)
        unmerged_ids = {
            row.get("id") for row in aggregate["coverage"]["deferred"] if isinstance(row, dict)
        }
        merged_ids = {
            child["id"]
            for child in children.values()
            if f"unmerged-{child['id']}" not in unmerged_ids
        }
    if not isinstance(aggregate, dict):
        aggregate = {"findings": [], "coverage": {}}
    child_ids = {child["id"] for child in children.values()}

    def source_key(source: dict[str, Any]) -> bytes:
        identity = source.get("id")
        if isinstance(identity, str):
            owner, _, _ = identity.rpartition(":")
            if owner in child_ids:
                # Another finding's withdrawal can change this source's array position.
                return _encoded({**source, "id": owner})
        return _encoded(source)

    represented = set()
    for finding in aggregate["findings"]:
        for _, retained in retained_findings(finding):
            provenance = retained.get("provenance")
            if not isinstance(provenance, dict):
                continue
            sources = provenance.get("sourceFindings")
            if isinstance(sources, list):
                represented.update(
                    source_key(source) for source in sources if isinstance(source, dict)
                )
    recovery_errors = {}
    observed_children = set()
    for child in children.values():
        if child["id"] in merged_ids:
            continue
        try:
            child_scan = db.require_scan(connection, child["id"])
            draft = _stopped_child_draft(db, child_scan, scan_dir, write_snapshots=write)
        except (ContractError, OSError, SystemExit, ValueError) as exc:
            recovery_errors[child["id"]] = str(exc)
            if warnings is not None:
                warnings.append(f"{_CHILD_RECOVERY_WARNING} {exc}")
            if not write:
                return aggregate
            continue
        if draft is None:
            continue
        observed_children.add(child["id"])
        _reconcile_child_withdrawals(aggregate, draft)
        positions = {
            _finding_key(finding): index for index, finding in enumerate(aggregate["findings"])
        }
        child_occurrences = {}
        for index, previous in enumerate(aggregate["findings"]):
            previous_sources = previous.get("provenance", {}).get("sourceFindings")
            for source in previous_sources if isinstance(previous_sources, list) else []:
                if not isinstance(source, dict):
                    continue
                source_id, original = source.get("id"), source.get("finding")
                if (
                    isinstance(source_id, str)
                    and source_id.rpartition(":")[0] == child["id"]
                    and isinstance(original, dict)
                    and isinstance(occurrence := original.get("occurrenceId"), str)
                ):
                    child_occurrences[occurrence] = index
        for finding in draft["findings"]:
            sources = {source_key(source) for source in finding["provenance"]["sourceFindings"]}
            position = positions.get(_finding_key(finding))
            occurrence_match = position is None
            if position is None:
                # Location corrections keep the validated child's occurrence identity.
                original = finding["provenance"]["sourceFindings"][0]["finding"]
                position = child_occurrences.get(original["occurrenceId"])
            if position is None:
                if sources - represented:
                    aggregate["findings"].append(finding)
                continue
            previous = aggregate["findings"][position]
            previous_sources = {
                source_key(source)
                for source in previous.get("provenance", {}).get("sourceFindings", [])
            }
            content_changed = _finding_content(previous) != _finding_content(finding)
            if sources <= previous_sources and (not content_changed or occurrence_match):
                # Unchanged represented evidence does not replace a parent assessment.
                continue
            # The validated child has already selected its current finding. Preserve
            # its predecessor as history, not as a competing stronger observation.
            historical = copy.deepcopy(previous)
            previous_history = historical.get("provenance", {}).pop("previousFindings", [])
            if not isinstance(previous_history, list):
                previous_history = []
            history = finding["provenance"].get("previousFindings")
            history = list(history) if isinstance(history, list) else []
            for value in [*previous_history, *([historical] if content_changed else [])]:
                if value not in history:
                    history.append(value)
            if history:
                finding["provenance"]["previousFindings"] = history
            aggregate["findings"][position] = finding
        coverage = aggregate.setdefault("coverage", {})
        _reconcile_child_coverage(coverage, draft["coverage"], child["id"])
        union_coverage(coverage, draft["coverage"])
        if "threatModel" not in aggregate and isinstance(draft.get("threatModel"), dict):
            aggregate["threatModel"] = {
                **copy.deepcopy(draft["threatModel"]),
                "origin": "recovered",
            }
    aggregate["scanId"] = scan["id"]
    aggregate["complete"] = False
    coverage = aggregate.setdefault("coverage", {})
    coverage["completeness"] = "partial"
    deferred = coverage.setdefault("deferred", [])
    directories = (
        dict.fromkeys(Path(scan["scan_dir"]) / item["directory"] for item in checkpoint["passes"])
        if checkpoint is not None and retained_draft is None
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
        if child is not None and child["id"] in observed_children:
            note["coverageObserved"] = True
        if child is not None and child["id"] in recovery_errors:
            note["reason"] += f" Recovery failed: {recovery_errors[child['id']]}"
        if previous_aggregate is not None:
            previous = next(
                (index for index, row in enumerate(deferred) if row.get("id") == note["id"]),
                None,
            )
            if previous is not None:
                deferred[previous] = note
                continue
        if note not in deferred:
            deferred.append(note)
    if previous_aggregate is not None:
        resolved_candidates = {
            candidate
            for finding in aggregate["findings"]
            if (candidate := finding_candidate_id(finding)) is not None
        }
        resolved_candidates.update(
            row["candidateId"]
            for field in ("surfaces", "explicitExclusions")
            for row in coverage.get(field, [])
            if isinstance(row.get("candidateId"), str)
            and row.get("disposition") in {"reported", "rejected", "not_applicable"}
        )
        # Publication already retired these resolved review notes. Do not reopen
        # them merely because an unchanged child still carries the pending row.
        # Embedded observations must still reach publication's history merger.
        deferred[:] = [
            row
            for row in deferred
            if row.get("candidateId") not in resolved_candidates
            or row in previous_aggregate["coverage"]["deferred"]
            or "candidate" in row
            or "finding" in row
        ]
        if aggregate == previous_aggregate:
            return None
    if write:
        payload = _encoded(aggregate)
        name = hashlib.sha256(payload).hexdigest() + ".json"
        write_scan_local_bytes(scan_dir, f"checkpoints/pending/{name}", payload)
        write_scan_local_bytes(scan_dir, f"checkpoints/{name}", payload)
    return aggregate


def preserve_scan_results_locked(
    db: Any,
    connection: Any,
    scan_id: str,
    *,
    recovery_source_digests: dict[str, str] | None = None,
    include_parent_with_recovery: bool = False,
    selected_parent_checkpoint: str | None = None,
    composition: CompositionView | None = None,
    recovery_warnings: list[str] | None = None,
) -> bool:
    """Publish or verify retained terminal results through the workbench host."""
    scan = db.require_scan(connection, scan_id)
    if scan["status"] != "failed":
        return False
    composition = composition if composition is not None else load_composition(connection, scan)
    frozen_source_digests: dict[str, str] | None = None
    frozen_model_source: str | None = None
    raw_frozen_sources = scan["retained_source_digests_json"]
    if recovery_source_digests is not None:
        frozen_source_digests = recovery_source_digests
    elif raw_frozen_sources is not None:
        frozen_source_digests, frozen_model_source = _retained_source_state(
            json.loads(raw_frozen_sources)
        )
    scan_dir = db.require_canonical_scan_directory(Path(scan["scan_dir"]))
    require_current_deep_scan(db, connection, scan)
    outcome = "canceled" if scan["canceled_at"] else "failed"
    stored_warnings = json.loads(scan["completion_warnings_json"])
    publication_follow_up_warnings = [
        warning
        for warning in stored_warnings
        if isinstance(warning, str) and warning.startswith(_PUBLICATION_FOLLOW_UP_WARNING)
    ]
    warnings = [
        warning for warning in stored_warnings if warning not in publication_follow_up_warnings
    ]
    warnings.extend(recovery_warnings or [])

    if frozen_source_digests is None:
        save_composed_checkpoint(db, connection, scan, scan_dir, composition, warnings)
    elif recovery_source_digests is None:
        warnings.extend(
            warning
            for warning in publication_follow_up_warnings
            if warning.startswith(_CHILD_RECOVERY_WARNING)
        )

    def record_publication(manifest: dict[str, Any], findings: dict[str, Any]) -> None:
        retained_sources = manifest.get("scan", {}).get("preservedSources")
        if not isinstance(retained_sources, dict) or not all(
            isinstance(relative, str) and isinstance(source_digest, str)
            for relative, source_digest in retained_sources.items()
        ):
            raise ContractError("Stopped scan source digests could not be frozen.")
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
                    _encode_retained_sources(
                        retained_sources, [frozen_model_source] if frozen_model_source else []
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
    try:
        existing_scan = db.read_json_object(existing_path).get("scan", {}) if existing_path else {}
    except (ValueError, ContractError, SystemExit):
        if scan["seal_manifest_digest"] is not None:
            raise
        existing_scan = {}
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
                if not isinstance(existing_sources, dict) or not all(
                    isinstance(relative, str) and isinstance(digest, str)
                    for relative, digest in existing_sources.items()
                ):
                    raise ContractError("Stopped scan source digests could not be frozen.")
                frozen_source_digests = existing_sources
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
    documents = merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        warnings,
        stopped=True,
        reason=(
            f"Scan {outcome}; saved findings and pending review were preserved. "
            f"{scan['failure_message'] or ''}"
        ).strip(),
        frozen_source_digests=frozen_source_digests,
        frozen_model_source=frozen_model_source,
        composed_child_ids=tuple(child["id"] for child in composition.children),
        selected_parent_checkpoint=selected_parent_checkpoint,
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
    if frozen_source_digests is None:
        retained_sources = documents[0].get("scan", {}).get("preservedSources")
        if not isinstance(retained_sources, dict) or not all(
            isinstance(relative, str) and isinstance(digest, str)
            for relative, digest in retained_sources.items()
        ):
            raise ContractError("Stopped scan source digests could not be frozen.")
        with connection:
            connection.execute(
                "UPDATE scans SET retained_source_digests_json = ? "
                "WHERE id = ? AND retained_source_digests_json IS NULL",
                (json.dumps(retained_sources, sort_keys=True), scan_id),
            )
    prepared = _prepare_scan_finalization(
        scan_dir,
        expected_coverage_mode=db.expected_coverage_mode(scan),
        completion_binding=binding,
        completion_warnings=warnings,
        draft_documents=documents,
    )
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
        composition = load_composition(connection, scan)
        recovery_warnings: list[str] = []
        recovery_source_digests, include_parent, selected_parent = _recovery_source_digests(
            db, connection, scan, composition, recovery_warnings
        )
        if not preserve_scan_results_locked(
            db,
            connection,
            scan_id,
            recovery_source_digests=recovery_source_digests,
            include_parent_with_recovery=include_parent,
            selected_parent_checkpoint=selected_parent,
            composition=composition,
            recovery_warnings=recovery_warnings,
        ):
            raise SystemExit("No saved stopped-scan results were available to recover.")
    return db.scan_context(connection, scan_id)


def preserve_scan_results(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    cost_json = db.parse_scan_cost(args.cost_json)
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
        if scan["mode"] == "deep" and output == COMPOSITION_CHECKPOINT:
            advance_scan_phase(db, connection, scan_id, "discovery")
    return {"scanId": scan_id, "path": str(scan_dir / output)}


def stop_composition_children(db: Any, connection: Any, composition: CompositionView) -> None:
    merged = set(composition.checkpoint["mergedScanIds"]) if composition.checkpoint else set()
    for child in composition.children:
        if child["id"] not in merged and child["status"] == "running":
            with db.scan_completion_lock(child["id"]):
                current = db.require_scan(connection, child["id"])
                if current["status"] != "running":
                    continue
                fail_scan_locked(
                    db,
                    connection,
                    argparse.Namespace(
                        scan_id=child["id"],
                        claim_token=current["handoff_claim_token"],
                        cost_json=None,
                        message="Parent Deep Scan stopped.",
                    ),
                )


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
        # SDK callers publish both documents directly. File inputs remain available
        # for existing native callers and are read through verified scan-local handles.
        if args.draft_path is None:
            if args.checkpoint_path is not None:
                raise SystemExit("checkpoint-path requires draft-path.")
            incoming = json.load(sys.stdin)
            draft = incoming["documents"]
            checkpoint = incoming.get("checkpoint")
            reconciled = incoming.get("reconciledCheckpointIds", [])
            checkpoint_contents = _encoded(checkpoint) if checkpoint is not None else None
        else:

            def staged(path: str, suffix: str) -> tuple[dict[str, Any], bytes]:
                try:
                    relative = Path(path).relative_to(scan_dir).as_posix()
                except ValueError as exc:
                    raise SystemExit(
                        "Scan draft must be inside the registered scan drafts directory."
                    ) from exc
                if not re.fullmatch(r"drafts/[0-9a-fA-F-]+" + suffix + r"\.json", relative):
                    raise SystemExit(
                        "Scan draft must be inside the registered scan drafts directory."
                    )
                return _read_scan_local_json_bytes(scan_dir, relative, "Staged scan draft")

            draft, _ = staged(args.draft_path, "")
            reconciled = draft.get("reconciledCheckpointIds", [])
            checkpoint, checkpoint_contents = (
                staged(args.checkpoint_path, r"\.checkpoint")
                if args.checkpoint_path is not None
                else (None, None)
            )
        acknowledged = set(_checkpoint_ids(reconciled))
        pending_decision = checkpoint is not None and (
            checkpoint.get("complete") is not False
            or bool(checkpoint.get("coverage", {}).get("resolvedDeferred"))
            or any(
                row.get("disposition") in {"rejected", "not_applicable"}
                for row in checkpoint.get("coverage", {}).get("surfaces", [])
                if isinstance(row, dict)
            )
        )
        if (
            pending_decision
            and args.expected_draft_digest is not None
            and args.expected_draft_digest != _scan_draft_digest(scan_dir)
        ):
            raise SystemExit(
                "scan_draft_conflict: canonical scan results changed; reconcile the saved checkpoint again."
            )
        if pending_decision:
            preview = copy.deepcopy(draft)
            binding = db.workbench_completion_binding(scan, db.now())
            _populate_unsealed_manifest_envelope(
                preview["manifest"], preview["manifest"]["scan"], binding
            )
            _populate_unsealed_artifact_envelope(
                preview["manifest"], preview["findings"], preview["coverage"], binding
            )
            _validate_completion_binding(
                preview["manifest"], preview["findings"], preview["coverage"], binding
            )
        if checkpoint is not None:
            if checkpoint.get("scanId") != scan_id:
                raise SystemExit("Staged scan checkpoint belongs to another scan.")
            checkpoint_name = hashlib.sha256(checkpoint_contents).hexdigest() + ".json"
            # Index first: a failed committed-head write must leave discoverable evidence.
            write_scan_local_bytes(
                scan_dir, f"checkpoints/pending/{checkpoint_name}", checkpoint_contents
            )
            write_scan_local_bytes(scan_dir, f"checkpoints/{checkpoint_name}", checkpoint_contents)
            acknowledged.add(checkpoint_name)
        if (
            args.expected_draft_digest is not None
            and args.expected_draft_digest != _scan_draft_digest(scan_dir)
        ):
            raise SystemExit(
                "scan_draft_conflict: canonical scan results changed; reconcile the saved checkpoint again."
            )
        draft["reconciledCheckpointIds"] = sorted(acknowledged)
        write_draft_documents(db, scan, scan_dir, draft)
        model_warning = write_threat_model_projection_if_possible(scan_dir, draft["manifest"])
        # Accepted Standard drafts are evidence of review or report assembly,
        # even when the parent omitted its explicit progress call.
        model_only = (
            draft["manifest"]["scan"].get("complete") is False
            and isinstance(draft["manifest"]["scan"].get("threatModel"), dict)
            and not draft["findings"].get("findings")
            and not draft["coverage"].get("surfaces")
            and not draft["coverage"].get("deferred")
        )
        if scan["mode"] == "standard" and not model_only:
            phase = (
                "discovery" if draft["manifest"]["scan"].get("complete") is False else "reporting"
            )
            advance_scan_phase(db, connection, scan_id, phase)
        for path in (args.draft_path, args.checkpoint_path):
            if path is not None:
                try:
                    _remove_scan_local_file_if_exists(
                        scan_dir, Path(path).relative_to(scan_dir).as_posix()
                    )
                except (ContractError, OSError):
                    pass
    return {
        "scanId": scan_id,
        "status": "draft_written",
        **({"warnings": [model_warning]} if model_warning else {}),
    }


def write_draft_documents(db: Any, scan: Any, scan_dir: Path, draft: dict[str, Any]) -> None:
    manifest, findings, coverage = draft["manifest"], draft["findings"], draft["coverage"]
    binding = db.workbench_completion_binding(scan, db.now())
    # Save scan IDs without sealing the draft.
    _populate_unsealed_manifest_envelope(manifest, manifest["scan"], binding)
    _populate_unsealed_artifact_envelope(manifest, findings, coverage, binding)
    _validate_completion_binding(manifest, findings, coverage, binding)
    # Preserve the accepted stable IDs as immutable evidence before exporting
    # canonical files; the caller's raw checkpoint may not contain those IDs.
    _, normalized = _saved_parent_result(scan["id"], manifest, findings, coverage)
    normalized_contents = _encoded(normalized)
    normalized_name = hashlib.sha256(normalized_contents).hexdigest() + ".json"
    write_scan_local_bytes(scan_dir, f"checkpoints/{normalized_name}", normalized_contents)
    # Failed physical cleanup must not reopen accepted evidence on a later write.
    remaining = set(_committed_checkpoint_ids(scan_dir)) & set(
        _children(scan_dir, "checkpoints/pending")
    )
    draft["reconciledCheckpointIds"] = sorted(
        remaining | set(_checkpoint_ids(draft.get("reconciledCheckpointIds", [])))
    )
    canonical = {
        filename: (json.dumps(document, allow_nan=False, indent=2) + "\n").encode()
        for filename, document in (
            ("findings.json", findings),
            ("coverage.json", coverage),
            ("scan-manifest.json", manifest),
        )
    }
    previous = {}
    for filename in canonical:
        try:
            previous[filename] = _sha256_scan_local_file(scan_dir, filename, "Previous scan export")
        except (ContractError, OSError):
            previous[filename] = None
    # Recognize an interrupted export without assigning meaning to an authored
    # completion timestamp. These digests stay inside the committed snapshot.
    draft["canonicalExport"] = {
        "previous": previous,
        "current": {
            filename: hashlib.sha256(contents).hexdigest()
            for filename, contents in canonical.items()
        },
    }
    write_scan_local_bytes(scan_dir, "artifacts/scan-draft.json", _encoded(draft))
    try:
        _retire_checkpoints(scan_dir, draft["reconciledCheckpointIds"])
    except (ContractError, OSError):
        pass  # The committed acknowledgment already excludes these pending markers.
    for filename, contents in canonical.items():
        write_scan_local_bytes(scan_dir, filename, contents)


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


def _scan_draft_digest(scan_dir: Path) -> str:
    committed = scan_dir / "artifacts/scan-draft.json"
    try:
        committed.lstat()
    except FileNotFoundError:
        pass
    else:
        _, contents = _read_scan_local_json_bytes(
            scan_dir, "artifacts/scan-draft.json", "Committed scan draft"
        )
        return hashlib.sha256(contents).hexdigest()
    digest = hashlib.sha256()
    for filename in ("scan-manifest.json", "findings.json", "coverage.json"):
        digest.update(filename.encode())
        digest.update(b"\0")
        try:
            (scan_dir / filename).lstat()
        except FileNotFoundError:
            digest.update(b"missing\0")
            continue
        descriptor = open_scan_local_file_descriptor(scan_dir, filename, filename)
        with os.fdopen(descriptor, "rb") as source:
            contents = source.read()
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
    try:
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
            if cost_json is not None:
                cost_json = merge_scan_cost(scan["cost_json"], cost_json)
                connection.execute(
                    "UPDATE scans SET cost_json = ? WHERE id = ?", (cost_json, scan_id)
                )
            connection.commit()
            return db.scan_context(connection, scan["id"])
        message = db.optional_text(args.message, maximum=2400)
        updated = connection.execute(
            """
            UPDATE scans
            SET status = 'failed', failure_message = ?, completed_at = ?, updated_at = ?,
                cost_json = COALESCE(?, cost_json)
            WHERE id = ? AND status = 'running'
            """,
            (
                message,
                timestamp,
                timestamp,
                merge_scan_cost(scan["cost_json"], cost_json),
                scan["id"],
            ),
        )
        if updated.rowcount != 1:
            raise SystemExit("Only a running scan can be marked failed.")
        progress_updated = connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan["id"]),
        )
        if progress_updated.rowcount != 1:
            raise SystemExit("Codex Security scan progress not found.")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    if not getattr(args, "defer_publication", False):
        preserve_stopped_results_after_transition(db, connection, scan["id"], stop_children=True)
    return db.scan_context(connection, scan["id"])


def cancel_scan(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    with db.scan_completion_lock(db.require_uuid(args.scan_id, "scan-id")):
        return cancel_scan_locked(db, connection, args)


def cancel_scan_locked(db: Any, connection: Any, args: Any) -> dict[str, Any]:
    scan_id = db.require_uuid(args.scan_id, "scan-id")
    thread_id = db.optional_text(args.thread_id, maximum=512)
    connection.execute("BEGIN IMMEDIATE")
    try:
        timestamp = db.now()
        scan = db.require_scan(connection, scan_id)
        workspace = db.require_workspace(connection, scan["workspace_id"])
        owning_thread_id = db.handoff.owning_thread(scan, workspace)
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
        progress_updated = connection.execute(
            "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
            (timestamp, scan["id"]),
        )
        if progress_updated.rowcount != 1:
            raise SystemExit("Codex Security scan progress not found.")
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    if not getattr(args, "defer_publication", False):
        preserve_stopped_results_after_transition(db, connection, scan["id"], stop_children=True)
    return db.workspace_state(connection, scan["workspace_id"])


def preserve_stopped_results_after_transition(
    db: Any, connection: Any, scan_id: str, *, stop_children: bool = False
) -> None:
    try:
        scan = db.require_scan(connection, scan_id)
        composition = load_composition(connection, scan)
        if stop_children:
            stop_composition_children(db, connection, composition)
        preserve_scan_results_locked(db, connection, scan_id, composition=composition)
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


def _retained_source_state(value: Any) -> tuple[dict[str, str], str | None]:
    if isinstance(value, dict) and isinstance(value.get("sources"), dict):
        sources = _legacy_source_digests(
            value["sources"], "Saved stopped-scan source digests are malformed."
        )
        model_source = value.get("threatModelSource")
        if not isinstance(model_source, str) or model_source not in sources:
            raise ContractError("Saved stopped-scan model source is outside its checkpoint set.")
        return sources, model_source
    return _legacy_source_digests(value, "Saved stopped-scan source digests are malformed."), None


def _encode_retained_sources(sources: dict[str, str], model_source: list[str]) -> str:
    state = {"sources": sources, "threatModelSource": model_source[0]} if model_source else sources
    return json.dumps(state, sort_keys=True)


def _retained_composed_draft(db: Any, scan: Any, scan_dir: Path) -> dict[str, Any] | None:
    retained_draft: dict[str, Any] | None = None
    frozen_sources: dict[str, str] | None = None
    raw_frozen_sources = scan["retained_source_digests_json"]
    if raw_frozen_sources is not None:
        frozen_sources, _ = _retained_source_state(json.loads(raw_frozen_sources))

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
                    manifest_scan["preservedSources"], "Published scan"
                )
                if published_sources:
                    if frozen_sources is not None and frozen_sources != published_sources:
                        raise ContractError(
                            "Stopped scan sources changed after terminal publication."
                        )
                    frozen_sources = published_sources
                elif frozen_sources is None:
                    frozen_sources = {}
            db.require_recorded_manifest_digest(scan, scan_dir)
            _, _, manifest, findings, coverage, _, _ = _prepare_scan_finalization(scan_dir)
            db.verify_manifest_binding(scan, manifest)
            retained_draft = _parent_scan_draft(scan["id"], manifest["scan"], findings, coverage)
    return retained_draft


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
