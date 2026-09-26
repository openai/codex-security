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
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    _finding_strength,
    _populate_unsealed_artifact_envelope,
    _populate_unsealed_manifest_envelope,
    _prepare_scan_finalization,
    _read_json,
    _read_scan_local_json,
    _read_scan_local_json_bytes,
    _read_scan_local_json_with_metadata,
    _recover_unsealed_findings,
    _remove_scan_local_file_if_exists,
    _validate_completion_binding,
    _validate_resolved_deferred,
    _validate_schema_node,
    _write_prepared_scan_finalization,
    finalize_scan,
    finding_candidate_id,
    open_scan_local_file_descriptor,
    write_scan_local_bytes,
)
from workbench_constants import PHASES
from workbench_target import committed_diff_snapshot_digest
from workbench_validation import path_within_scope

_PUBLISHED_OUTPUTS = (
    "findings.json",
    "coverage.json",
    "scan-manifest.json",
    "report.md",
    "report.html",
    "exports/results.sarif",
)
_PUBLICATION_FOLLOW_UP_WARNING = (
    "Saved scan evidence remains on disk; result publication needs follow-up:"
)
_RESERVED_ARTIFACT_PATHS = json.loads(
    Path(__file__).with_name("reserved_artifact_paths.json").read_text(encoding="utf-8")
)


@dataclass(frozen=True)
class WorkbenchDbContext:
    ARTIFACTS: dict[str, str]
    artifact_path: Callable[..., Path | None]
    deep_scan: ModuleType
    expected_coverage_mode: Callable[..., str]
    handoff: ModuleType
    index_findings: Callable[..., None]
    now: Callable[[], str]
    optional_text: Callable[..., str | None]
    parse_scan_cost: Callable[..., dict[str, Any] | None]
    published_manifest_digest: Callable[..., str]
    read_json_object: Callable[[Path], dict[str, Any]]
    require_canonical_scan_directory: Callable[[Path], Path]
    require_recorded_manifest_digest: Callable[..., None]
    require_scan: Callable[..., Any]
    require_uuid: Callable[[str, str], str]
    require_workspace: Callable[..., Any]
    scan_completion_lock: Callable[..., Any]
    scan_context: Callable[..., dict[str, Any]]
    verify_manifest_binding: Callable[..., None]
    workbench_completion_binding: Callable[..., dict[str, Any]]
    workspace_state: Callable[..., dict[str, Any]]


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


def _checkpoint_paths(scan_dir: Path, directory: str) -> list[str]:
    return [
        f"{directory}/{name}"
        for name in _children(scan_dir, directory)
        if re.fullmatch(r"[0-9a-f]{64}\.json", name)
    ]


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


def _checkpoint_head_directory(relative: str) -> Path | None:
    path = Path(relative)
    if path.name == "checkpoint-head.json":
        return path.parent
    if path.parent.name == "checkpoint-heads":
        return path.parent.parent
    return None


def _validate_checkpoint_head(
    scan_dir: Path, directory: Path, scan_id: str, head: dict[str, Any]
) -> None:
    checkpoint = head.get("checkpoint")
    if not isinstance(checkpoint, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", checkpoint):
        raise ContractError("checkpoint head does not name a saved checkpoint")
    _read_saved_result(scan_dir, (directory / "checkpoints" / checkpoint).as_posix(), scan_id)


def _checkpoint_head_observation(scan_dir: Path, relative: str, scan_id: str) -> dict[str, Any]:
    head, _, metadata = _read_scan_local_json_with_metadata(
        scan_dir, relative, "Saved checkpoint head"
    )
    directory = Path(relative).parent
    _validate_checkpoint_head(scan_dir, directory, scan_id, head)
    return {"checkpoint": head["checkpoint"], "observedAtNs": str(metadata.st_mtime_ns)}


def _capture_saved_source(
    scan_dir: Path,
    relative: str,
    scan_id: str,
    *,
    kind: str | None = None,
    snapshot_head: bool = True,
    write: bool = True,
) -> dict[str, tuple[str, int]]:
    if not snapshot_head or Path(relative).name != "checkpoint-head.json":
        _, digest, observed = _read_saved_result_observation(scan_dir, relative, scan_id, kind=kind)
        return {relative: (digest, observed)}
    observation = _checkpoint_head_observation(scan_dir, relative, scan_id)
    directory = Path(relative).parent
    selected = (directory / "checkpoints" / observation["checkpoint"]).as_posix()
    _, selected_digest, selected_time = _read_saved_result_observation(scan_dir, selected, scan_id)
    digest = _digest(observation)
    snapshot = (directory / "checkpoint-heads" / f"{digest}.json").as_posix()
    # Capture the selected file even if the worker created it after directory enumeration.
    if write and not (scan_dir / snapshot).exists():
        write_scan_local_bytes(scan_dir, snapshot, _encoded(observation))
    return {
        snapshot: (digest, int(observation["observedAtNs"])),
        selected: (selected_digest, selected_time),
    }


def _is_source_order_snapshot(relative: str) -> bool:
    path = Path(relative)
    return path.parent == Path("source-order") and bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
    )


def _read_saved_result_observation(
    scan_dir: Path, relative: str, scan_id: str, *, kind: str | None = None
) -> tuple[dict[str, Any], str, int]:
    draft, _, metadata = _read_scan_local_json_with_metadata(
        scan_dir, relative, "Saved scan checkpoint"
    )
    directory = _checkpoint_head_directory(relative)
    if directory is not None:
        _validate_checkpoint_head(scan_dir, directory, scan_id, draft)
        if Path(relative).name == "checkpoint-head.json":
            return draft, _digest([draft, metadata.st_mtime_ns]), metadata.st_mtime_ns
        observed = draft.get("observedAtNs")
        if not isinstance(observed, str) or not re.fullmatch(r"-?[0-9]+", observed):
            raise ContractError("checkpoint head has no observation time")
        return draft, _digest(draft), int(observed)
    if draft.get("scanId") != scan_id:
        raise ContractError("checkpoint belongs to a different scan")
    if not _is_source_order_snapshot(relative) and (
        not isinstance(draft.get("findings"), list)
        or not isinstance(draft.get("coverage", {} if kind == "dedup" else None), dict)
    ):
        raise ContractError("checkpoint has no semantic findings or coverage")
    return draft, _digest(draft), metadata.st_mtime_ns


def _read_saved_result(
    scan_dir: Path, relative: str, scan_id: str, *, kind: str | None = None
) -> tuple[dict[str, Any], str]:
    draft, digest, _ = _read_saved_result_observation(scan_dir, relative, scan_id, kind=kind)
    return draft, digest


def _frozen_source_times(scan_dir: Path, scan_id: str, sources: dict[str, str]) -> dict[str, int]:
    times: dict[str, int] = {}
    snapshots = [path for path in sources if _is_source_order_snapshot(path)]
    for path in snapshots:
        record, digest = _read_saved_result(scan_dir, path, scan_id)
        if digest != sources[path] or not isinstance(record.get("sources"), dict):
            raise ContractError("saved source ordering changed after the scan stopped")
        for relative, observation in record["sources"].items():
            if (
                not isinstance(observation, dict)
                or relative not in sources
                or observation.get("digest") != sources[relative]
                or not isinstance(observation.get("observedAtNs"), str)
                or not re.fullmatch(r"-?[0-9]+", observation["observedAtNs"])
            ):
                raise ContractError("saved source ordering does not match its frozen sources")
            observed = int(observation["observedAtNs"])
            if relative in times and times[relative] != observed:
                raise ContractError("saved source ordering has conflicting observations")
            times[relative] = observed
    if snapshots and sources.keys() - set(snapshots) - times.keys():
        raise ContractError("saved source ordering is incomplete")
    return times


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


def _source_digests(value: Any, error: str) -> dict[str, str]:
    if not isinstance(value, dict) or not all(
        isinstance(relative, str) and isinstance(digest, str) for relative, digest in value.items()
    ):
        raise ContractError(error)
    return value


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
                return bool(
                    _source_digests(
                        json.loads(frozen_sources),
                        "Frozen stopped-scan source digests are malformed.",
                    )
                )
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
        frozen_sources = _source_digests(
            json.loads(raw_frozen_sources), "Saved stopped-scan source digests are malformed."
        )
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
            _, digest, observed = _read_saved_result_observation(
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
        rows = observed["coverage"].get("resolvedDeferred", [])
        if observed.get("complete") is False:
            continue
        try:
            _validate_schema_node(rows, closure_schema, "coverage.resolvedDeferred")
            _validate_resolved_deferred(
                {
                    **observed["coverage"],
                    "deferred": _deferred_rows(observed["coverage"]),
                }
            )
        except ContractError:
            continue
        for row in rows:
            if (
                isinstance(row, dict)
                and isinstance(row.get("id"), str)
                and row["id"] not in pending_ids
            ):
                closures.setdefault(row["id"], copy.deepcopy(row))
    coverage.pop("resolvedDeferred", None)
    if closures:
        coverage["resolvedDeferred"] = list(closures.values())
    if current.get("complete") is False or previous.get("complete") is False:
        merged["complete"] = False
    if (
        coverage.get("deferred")
        or merged.get("complete") is False
        or (
            isinstance(coverage.get("surfaces"), list)
            and any(
                isinstance(row, dict) and row.get("disposition") == "needs_follow_up"
                for row in coverage["surfaces"]
            )
        )
        or previous["coverage"].get("completeness") == "partial"
    ):
        coverage["completeness"] = "partial"
    return merged


def _saved_coverage_id(item: dict[str, Any]) -> str:
    return item.get("candidateId") or f"saved-{_digest(item)[:16]}"


def _generic_surface_updates(
    sources: list[tuple[str, dict[str, Any], str | None]],
    source_order: dict[str, tuple[int, int]],
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    resolved_candidates: dict[tuple[str | None, str], str],
    reopened_generic: set[tuple[str | None, str]],
    surface_schema: dict[str, Any],
    deferred_rows: dict[str, list[Any]],
) -> tuple[set[int], list[dict[str, Any]]]:
    def linked(row: dict[str, Any], identity: str | None) -> bool:
        surface_ids = row.get("surfaceIds", [])
        return identity is not None and (
            row.get("id") == identity or (isinstance(surface_ids, list) and identity in surface_ids)
        )

    replaced: set[int] = set()
    updates: list[dict[str, Any]] = []
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
        if not closed_ids and not reopened_ids:
            continue
        current = draft["coverage"].get("surfaces", [])
        for surface in current if isinstance(current, list) else []:
            if not isinstance(surface, dict):
                continue
            reopening = surface.get("disposition") == "needs_follow_up"
            work_ids = reopened_ids if reopening else closed_ids
            if not work_ids:
                continue
            identity = surface.get("id")
            if not isinstance(identity, str):
                continue
            matches = [
                (saved_path, saved, row)
                for saved_path, saved, saved_owner in sources
                if saved_owner == owner
                for row in (
                    saved["coverage"]["surfaces"]
                    if isinstance(saved["coverage"].get("surfaces"), list)
                    else []
                )
                if isinstance(row, dict) and row.get("id") == identity
            ]
            if any(
                "candidateId" in row or "candidate" in row or "finding" in row
                for _, _, row in matches
            ):
                continue
            if any(
                row is not surface
                and source_order[saved_path] >= source_order[relative]
                and row.get("disposition") != surface.get("disposition")
                for saved_path, _, row in matches
            ):
                continue

            if not reopening and any(
                saved_owner == owner
                and not isinstance(row.get("id") or row.get("candidateId"), str)
                and linked(row, identity)
                for saved_path, _, saved_owner in sources
                for row in deferred_rows[saved_path]
                if isinstance(row, dict)
            ):
                continue
            if not reopening and any(
                saved_owner == owner
                and (owner, deferred_id) not in closed_deferred
                and (owner, row.get("candidateId") or deferred_id) not in resolved_candidates
                and linked(row, identity)
                for (saved_owner, deferred_id), (_, row, _) in active_deferred.items()
            ):
                continue
            linked_work = False
            for saved_path, _, _ in matches:
                deferred = deferred_rows[saved_path]
                rows = [row for row in deferred if isinstance(row, dict)]
                if any(row.get("id") in work_ids and linked(row, identity) for row in rows):
                    linked_work = True
                    break
            if not linked_work:
                continue
            latest_surface = max(matches, key=lambda match: source_order[match[0]])[2]
            update = copy.deepcopy(latest_surface)
            refs = update.setdefault("receiptRefs", [])
            if isinstance(refs, list):
                for _, _, row in matches:
                    previous_refs = row.get("receiptRefs", [])
                    for ref in previous_refs if isinstance(previous_refs, list) else []:
                        if ref not in refs:
                            refs.append(ref)
            try:
                _validate_schema_node(update, surface_schema, "coverage.surfaces")
            except ContractError:
                continue
            replaced.add(id(surface))
            replaced.update(
                id(row)
                for _, _, row in matches
                if reopening
                or row.get("disposition") in {"needs_follow_up", surface.get("disposition")}
            )
            if update not in updates:
                updates.append(update)
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
    frozen_source_digests: dict[str, str] | None = None,
    allow_frozen_legacy_parent: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    """Read only bound parent/worker files; return an unsealed loss-preserving union."""
    initial_warnings = set(warnings)
    try:
        source_times = _frozen_source_times(scan_dir, scan_id, frozen_source_digests or {})
    except (ContractError, OSError, ValueError) as exc:
        raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
    parent: dict[str, Any] | None = None
    parent_manifest: dict[str, Any] | None = None
    parent_is_canonical = False
    parent_modified = 0
    if frozen_source_digests is None or allow_frozen_legacy_parent:
        try:
            parent_manifest, parent = _read_saved_parent_result(scan_dir, scan_id)
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
            if not parent_scan.get("sealedAt") or allow_frozen_legacy_parent:
                head_path = scan_dir / "checkpoint-head.json"
                try:
                    previous_head = _checkpoint_head_observation(
                        scan_dir, "checkpoint-head.json", scan_id
                    )
                    head_modified = int(previous_head["observedAtNs"])
                except (ContractError, OSError, ValueError):
                    head_modified = None
                tied_observations = False
                if head_modified == parent_modified:
                    previous_parent, _ = _read_saved_result(
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
            draft, digest, observed = _read_saved_result_observation(
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
        parent = next((draft for relative, draft, _ in sources if relative == latest_reducer), None)

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
    all_sources = ([("parent", parent, None)] if parent else []) + sources
    deferred_rows = {
        relative: _deferred_rows(draft["coverage"]) for relative, draft, _ in all_sources
    }
    current_drafts = ([("parent", parent, None)] if parent else []) + [
        source for source in sources if source[0] in current_results | selected_observations.keys()
    ]
    # Generic closures belong to one logical scan or worker, just like candidates.
    # Keep them when recovering a terminal checkpoint without its canonical write.
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}

    candidate_ids: set[tuple[str | None, str]] = set()
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]] = {}
    for relative, _, owner in all_sources:
        order = (0, parent_modified) if relative == "parent" else source_order[relative]
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
    coverage_schema = _read_json(
        Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
    )["properties"]
    closure_schema = coverage_schema["resolvedDeferred"]
    for relative, draft, owner in all_sources:
        if draft.get("complete") is False:
            continue
        closures = draft["coverage"].get("resolvedDeferred", [])
        try:
            # Invalid closure metadata cannot discard the evidence it names.
            _validate_schema_node(closures, closure_schema, "coverage.resolvedDeferred")
            _validate_resolved_deferred({**draft["coverage"], "deferred": deferred_rows[relative]})
        except ContractError:
            continue
        for closure in closures:
            key = (owner, closure["id"])
            order = (0, parent_modified) if relative == "parent" else source_order[relative]
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
        if key in candidate_ids or reopened:
            del closed_deferred[key]
        for _, item, _ in reopened:
            reopened_rows.append((key[0], item))
            if key not in candidate_ids:
                reopened_generic.add(key)
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
                if not isinstance(row, dict) or (None, row.get("id")) not in closed_deferred
            ]
    resolved: dict[tuple[str | None, str], str] = {}

    ordered_candidates = {
        (owner, row.get("candidateId") or row.get("id"))
        for owner, row in reopened_rows
        if (owner, row.get("candidateId") or row.get("id")) in candidate_ids
    }
    ordered_outcomes: dict[tuple[str | None, str], tuple[tuple[int, int], str]] = {}

    # Reopened work and selected checkpoint outcomes follow the saved source order.
    def record_candidate_outcome(
        relative: str, owner: str | None, candidate_id: str, disposition: str
    ) -> None:
        key = (owner, candidate_id)
        if key not in ordered_candidates:
            if relative == "parent" or relative in current_results:
                resolved.setdefault(key, disposition)
            return
        order = source_order[relative]
        if any(
            saved_owner == owner
            and (row.get("candidateId") or row.get("id")) == candidate_id
            and modified >= order
            for (saved_owner, _), (modified, row, _) in active_deferred.items()
        ):
            return
        if key not in ordered_outcomes or order > ordered_outcomes[key][0]:
            resolved[key] = disposition
            ordered_outcomes[key] = (order, relative)

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
                    and item.get("disposition") in {"reported", "rejected", "not_applicable"}
                ):
                    outcomes.append((relative, owner, item["candidateId"], item["disposition"]))
    ordered_candidates.update(
        (owner, candidate_id)
        for relative, owner, candidate_id, _ in outcomes
        if owner is not None and relative in selected_observations
    )
    for outcome in outcomes:
        record_candidate_outcome(*outcome)
    # Only the current parent may claim that another worker finding was absorbed.
    # A superseded checkpoint must not suppress a newer independent result.
    for draft in [parent] if parent else []:
        for finding in draft["findings"]:
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
                            resolved.setdefault(candidate_key, "reported")
    replaced_surfaces, surface_updates = _generic_surface_updates(
        all_sources,
        source_order,
        closed_deferred,
        active_deferred,
        resolved,
        reopened_generic,
        coverage_schema["surfaces"]["items"],
        deferred_rows,
    )
    if parent and isinstance(coverage.get("surfaces"), list):
        previous = parent["coverage"].get("surfaces", [])
        if isinstance(previous, list):
            removed_parent = [row for row in previous if id(row) in replaced_surfaces]
            coverage["surfaces"] = [
                row for row in coverage["surfaces"] if row not in removed_parent
            ]
    if isinstance(coverage.get("surfaces"), list):
        for surface in surface_updates:
            if surface not in coverage["surfaces"]:
                coverage["surfaces"].append(surface)

    # Reopened work survives a superseded checkpoint, but current candidate
    # outcomes still apply. Parent closures cannot remove another worker's row.
    for owner, item in reopened_rows:
        if (owner, item.get("candidateId") or item.get("id")) in resolved:
            continue
        pending = coverage.setdefault("deferred", [])
        if isinstance(pending, list) and item not in pending:
            pending.append(copy.deepcopy(item))
    terminal_worker_orders: dict[str | None, tuple[int, int]] = {}
    for relative, draft, worker_id in sources:
        if relative in current_results and draft.get("complete") is not False:
            order = source_order[relative]
            terminal_worker_orders[worker_id] = max(
                terminal_worker_orders.get(worker_id, order), order
            )
    for relative, draft, worker_id in all_sources:
        worker_result_order = terminal_worker_orders.get(worker_id)
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
        ) or (relative not in current_results and worker_result_order is not None)
        # A failed result write can leave pending work outside the accepted result.
        accepted_order = (
            (0, parent_modified)
            if worker_id is None and parent is not None
            else worker_result_order
        )
        selected_deferred = (
            {id(row) for row in deferred_rows[relative] if isinstance(row, dict)}
            if superseded
            and (worker_id in headed_workers or (worker_id is None and parent_heads))
            and accepted_order is not None
            and source_order[relative] >= accepted_order
            else set()
        )
        if (
            (relative != "parent" or not parent_is_canonical)
            and not superseded
            and (
                draft.get("complete") is False
                or draft["coverage"].get("completeness") != "complete"
            )
            and coverage.get("completeness") in {"complete", "unknown"}
        ):
            coverage["completeness"] = "partial"
        skip_superseded_findings = (
            superseded
            and not stopped
            and all(valid_finding(finding) for finding in (parent["findings"] if parent else []))
        )
        if skip_superseded_findings and not selected_candidates and not selected_deferred:
            continue
        if (
            not skip_superseded_findings
            and "threatModel" not in manifest["scan"]
            and isinstance(draft.get("threatModel"), dict)
        ):
            manifest["scan"]["threatModel"] = copy.deepcopy(draft["threatModel"])
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
            source_value = copy.deepcopy(value)
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
                coverage["completeness"] = "partial"
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
                    elif _finding_strength(finding) > _finding_strength(retained):
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
        if superseded and not selected_candidates and not selected_deferred:
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
                # A selected outcome must retain its evidence even if its result write failed.
                if superseded and not (
                    isinstance(item, dict)
                    and (
                        (field == "deferred" and id(item) in selected_deferred)
                        or (
                            isinstance(item.get("candidateId"), str)
                            and item["candidateId"] in selected_candidates
                            and item.get("disposition")
                            == resolved.get((worker_id, item["candidateId"]))
                        )
                    )
                ):
                    continue
                if field == "surfaces" and id(item) in replaced_surfaces:
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
                if (
                    isinstance(item, dict)
                    and (
                        worker_id,
                        item.get("candidateId")
                        or (item.get("id") if field == "deferred" else None),
                    )
                    in resolved
                    and (field == "deferred" or item.get("disposition") == "needs_follow_up")
                ):
                    continue
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
    for field in ("surfaces", "explicitExclusions", "deferred"):
        used: set[str] = set()
        items = coverage.setdefault(field, [])
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            if id(item) in canonical_rows:
                if isinstance(item.get("id"), str):
                    used.add(item["id"])
                continue
            item.setdefault("id", _saved_coverage_id(item))
            if item["id"] in used:
                item["id"] = f"{item['id']}-{_digest(item)[:16]}"
            used.add(item["id"])
            if field == "surfaces":
                item.setdefault("receiptRefs", [])
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
    raw_frozen_sources = scan["retained_source_digests_json"]
    if recovery_source_digests is not None:
        frozen_source_digests = recovery_source_digests
    elif raw_frozen_sources is not None:
        frozen_source_digests = _source_digests(
            json.loads(raw_frozen_sources), "Saved stopped-scan source digests are malformed."
        )
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
                    json.dumps(retained_sources, sort_keys=True),
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
            scan_dir, expected_coverage_mode=db.expected_coverage_mode(scan)
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
        retained_sources = _source_digests(
            documents[0].get("scan", {}).get("preservedSources"),
            "Stopped scan source digests could not be frozen.",
        )
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
        manifest, findings, _ = _write_prepared_scan_finalization(prepared)
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
            checkpoint_digest = hashlib.sha256(checkpoint_contents).hexdigest()
            write_scan_local_bytes(
                scan_dir,
                f"checkpoints/{checkpoint_digest}.json",
                checkpoint_contents,
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
        manifest, findings, coverage = draft["manifest"], draft["findings"], draft["coverage"]
        binding = db.workbench_completion_binding(scan, db.now())
        # Validate on copies: saved canonical documents remain ordinary unsealed drafts.
        copied_manifest = copy.deepcopy(manifest)
        copied_findings = copy.deepcopy(findings)
        copied_coverage = copy.deepcopy(coverage)
        _populate_unsealed_manifest_envelope(copied_manifest, copied_manifest["scan"], binding)
        _populate_unsealed_artifact_envelope(
            copied_manifest, copied_findings, copied_coverage, binding
        )
        _validate_completion_binding(copied_manifest, copied_findings, copied_coverage, binding)
        checkpoint = _parent_scan_draft(scan_id, manifest["scan"], findings, coverage)
        checkpoint_contents = _encoded(checkpoint)
        checkpoint_name = f"{hashlib.sha256(checkpoint_contents).hexdigest()}.json"
        checkpoint_relative = f"checkpoints/{checkpoint_name}"
        if not (scan_dir / checkpoint_relative).exists():
            write_scan_local_bytes(scan_dir, checkpoint_relative, checkpoint_contents)
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
        # Accepted Standard drafts are evidence of review or report assembly,
        # even when the parent omitted its explicit progress call.
        if scan["mode"] == "standard":
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
    return {"scanId": scan_id, "status": "draft_written"}


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
        _, contents = _read_scan_local_json_bytes(scan_dir, filename, filename)
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
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    preserve_stopped_results_after_transition(db, connection, scan["id"])
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
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
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
