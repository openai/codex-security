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
from candidate_identity import (
    candidate_key,
    candidate_owner,
    coverage_candidate_key,
    diff_candidate_disposition,
    finding_candidate_key,
    surface_reference_key,
    unresolved_candidates,
)
from finalize_scan_contract import (
    ContractError,
    _finding_strength,
    _populate_unsealed_artifact_envelope,
    _populate_unsealed_manifest_envelope,
    _prepare_scan_finalization,
    _read_scan_local_json,
    _read_scan_local_json_bytes,
    _recover_unsealed_findings,
    _remove_scan_local_file_if_exists,
    _validate_completion_binding,
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


def _saved_result_paths(scan_dir: Path, workers: list[Any]) -> Iterator[tuple[str, str | None]]:
    latest_reducer = _latest_successful_reducer(workers)

    def checkpoints(directory: str, kind: str | None = None) -> Iterator[tuple[str, str | None]]:
        for name in _children(scan_dir, directory):
            if re.fullmatch(r"[0-9a-f]{64}\.json", name):
                yield f"{directory}/{name}", kind

    yield from checkpoints("checkpoints")
    for worker in workers:
        if worker["kind"] not in {"dedup", "discovery"}:
            continue
        try:
            output = Path(worker["artifact_dir"]).relative_to(scan_dir).as_posix()
        except (TypeError, ValueError):
            continue
        attempts = (Path(output).parent if Path(output).name == "output" else Path(output)) / (
            "attempts"
        )
        directories = [output] + [
            (attempts / name).as_posix()
            for name in _children(scan_dir, attempts.as_posix())
            if re.fullmatch(r"attempt-\d+", name)
        ]
        for directory in directories:
            checkpoint_paths = list(checkpoints(f"{directory}/checkpoints", worker["kind"]))
            if worker["kind"] == "discovery" or checkpoint_paths:
                yield f"{directory}/result.json", worker["kind"]
                yield from checkpoint_paths
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


def _read_saved_result(
    scan_dir: Path, relative: str, scan_id: str, *, kind: str | None = None
) -> tuple[dict[str, Any], str]:
    draft = _read_scan_local_json(scan_dir, relative, "Saved scan checkpoint")
    if draft.get("scanId") != scan_id:
        raise ContractError("checkpoint belongs to a different scan")
    if not isinstance(draft.get("findings"), list) or not isinstance(
        draft.get("coverage", {} if kind == "dedup" else None), dict
    ):
        raise ContractError("checkpoint has no semantic findings or coverage")
    return draft, _digest(draft)


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
                return bool(_source_digests(json.loads(frozen_sources), "Frozen stopped-scan"))
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
                _, current_sources[path] = _read_saved_result(
                    scan_dir, path, scan["id"], kind=paths[path]
                )
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
        frozen_sources = _source_digests(json.loads(raw_frozen_sources), "Saved stopped-scan")
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

    workers = connection.execute(
        "SELECT id, kind, status, completed_at, artifact_dir, result_manifest_path "
        "FROM deep_scan_workers WHERE scan_id = ?",
        (scan["id"],),
    ).fetchall()
    paths = dict(_saved_result_paths(scan_dir, workers))
    recovery_sources = dict(frozen_sources or {})
    for relative, expected_digest in recovery_sources.items():
        try:
            _, digest = _read_saved_result(scan_dir, relative, scan["id"], kind=paths.get(relative))
        except (ContractError, OSError, ValueError) as exc:
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.") from exc
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")

    for relative in paths.keys() - recovery_sources.keys():
        try:
            _, recovery_sources[relative] = _read_saved_result(
                scan_dir, relative, scan["id"], kind=paths[relative]
            )
        except (ContractError, OSError, ValueError):
            continue
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


def recoverable_findings(
    scan_dir: Path, scan_id: str, target: dict[str, Any], values: list[Any]
) -> list[dict[str, Any]]:
    """Use finalizer recovery before findings can resolve saved candidate state."""
    document = {"scanId": scan_id, "findings": copy.deepcopy(values)}
    for finding in document["findings"]:
        if isinstance(finding, dict):
            _ensure_finding_identity(finding, candidate_only=True)
    _recover_unsealed_findings(
        {"scan": {"id": scan_id, "target": target}},
        document,
        Path(__file__).resolve().parent.parent / "schemas",
        scan_dir,
        [],
    )
    return document["findings"]


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


def _bind_finding_worker(
    finding: dict[str, Any], worker_id: str, original: dict[str, Any] | None = None
) -> None:
    provenance = finding["provenance"]
    if "sourceWorkerId" in provenance and provenance["sourceWorkerId"] != worker_id:
        # Imported ownership remains evidence; the bound source owns the candidate.
        previous = copy.deepcopy(original if original is not None else finding)
        if not isinstance(provenance.get("previousFindings"), list):
            provenance["previousFindings"] = []
        if previous not in provenance["previousFindings"]:
            provenance["previousFindings"].append(previous)
    provenance["sourceWorkerId"] = worker_id
    provenance.setdefault("workerId", worker_id)


def _bind_retained_source_owners(draft: dict[str, Any], worker_ids: set[str]) -> dict[str, Any]:
    result = copy.deepcopy(draft)
    for finding in result["findings"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("provenance"), dict):
            continue
        candidate_id = finding_candidate_id(finding)
        originals = finding["provenance"].get("sourceFindings")
        if candidate_id is None or not isinstance(originals, list):
            continue
        owners = {
            source["id"].rsplit(":", 1)[0]
            for source in originals
            if isinstance(source, dict)
            and isinstance(source.get("id"), str)
            and ":" in source["id"]
            and source["id"].rsplit(":", 1)[0] in worker_ids
            and isinstance(source.get("finding"), dict)
            and finding_candidate_id(source["finding"]) == candidate_id
        }
        if len(owners) == 1:
            _bind_finding_worker(finding, next(iter(owners)))
    return result


def _diff_candidate_phase_snapshot(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        phase: candidate[phase] for phase in ("validation", "attack_path") if phase in candidate
    }


def _diff_candidate_decision(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Project a terminal Diff ledger decision; either deferred phase remains unresolved."""
    validation = candidate.get("validation") or {}
    attack_path = candidate.get("attack_path") or {}
    if not isinstance(validation, dict) or not isinstance(attack_path, dict):
        raise ValueError("Diff candidate phase records must be objects.")
    disposition = diff_candidate_disposition(candidate)
    if disposition is None:
        return None
    summary = candidate.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("Diff candidate summary is missing.")
    return {
        "candidateId": candidate["candidate_id"],
        "label": summary,
        "disposition": disposition,
        "notes": next(
            value
            for value in (
                *(
                    [attack_path.get("counterevidence"), attack_path.get("severity_rationale")]
                    if attack_path.get("decision") == "ignore"
                    else []
                ),
                validation.get("counterevidence_or_proof_gap"),
                f"Candidate review concluded: {summary}",
            )
            if isinstance(value, str) and value.strip()
        ),
        "candidate": candidate,
    }


def _generated_diff_candidate_decision(item: dict[str, Any]) -> bool:
    candidate = item.get("candidate")
    if not isinstance(candidate, dict) or item.get("candidateId") != candidate.get("candidate_id"):
        return False
    try:
        decision = _diff_candidate_decision(candidate)
    except (KeyError, ValueError):
        return False
    return decision is not None and all(
        item.get(field) == decision[field] for field in ("label", "disposition", "notes")
    )


def _diff_candidate_reason(candidate: dict[str, Any]) -> str:
    validation = candidate.get("validation")
    validation = validation if isinstance(validation, dict) else {}
    attack_path = candidate.get("attack_path")
    attack_path = attack_path if isinstance(attack_path, dict) else {}
    if (
        validation.get("disposition") == "reportable"
        and attack_path.get("decision") == "reportable"
    ):
        return f"A reportable candidate has no saved finding: {candidate.get('summary')}"
    return next(
        value
        for value in (
            attack_path.get("proof_gap"),
            validation.get("counterevidence_or_proof_gap"),
            validation.get("remaining_uncertainty"),
            f"Candidate review is incomplete: {candidate.get('summary')}",
        )
        if isinstance(value, str) and value.strip()
    )


def _generated_budget_candidate_surface(item: dict[str, Any]) -> bool:
    candidate = item.get("candidate")
    return (
        isinstance(candidate, dict)
        and item.get("candidateId") == candidate.get("candidate_id")
        and item.get("disposition") == (diff_candidate_disposition(candidate) or "needs_follow_up")
        and item.get("label") == candidate.get("summary")
        and item.get("notes") == candidate.get("evidence")
    )


def preserve_budget_candidates(
    coverage: dict[str, Any], findings: list[dict[str, Any]], candidates: list[dict[str, Any]]
) -> None:
    """Reconcile ledger candidates with the saved cost-limit draft's decisions."""
    findings_by_candidate = {
        key
        for finding in findings
        if isinstance(finding, dict) and (key := finding_candidate_key(finding)) is not None
    }

    terminal_decisions = {
        coverage_candidate_key(item): item["disposition"]
        for field in ("surfaces", "explicitExclusions")
        for item in coverage[field]
        if isinstance(item, dict)
        and item.get("disposition") in ("rejected", "not_applicable")
        and (field != "surfaces" or not _generated_budget_candidate_surface(item))
    }
    dispositions = {
        (None, candidate["candidate_id"]): (
            "reported"
            if (None, candidate["candidate_id"]) in findings_by_candidate
            else terminal_decisions.get((None, candidate["candidate_id"]))
            or diff_candidate_disposition(candidate)
            or "needs_follow_up"
        )
        for candidate in candidates
    }
    deferred_by_candidate = {}
    surfaces_by_candidate = {}
    surfaces_by_id = {}
    for field, index in (
        ("deferred", deferred_by_candidate),
        ("surfaces", surfaces_by_candidate),
    ):
        for item in coverage[field]:
            if isinstance(item, dict) and (key := coverage_candidate_key(item)) is not None:
                index.setdefault(key, []).append(item)
    for surface in coverage["surfaces"]:
        if isinstance(surface, dict) and isinstance(surface.get("id"), str):
            surfaces_by_id.setdefault(surface["id"], []).append(surface)
    coverage["deferred"] = [
        item
        for item in coverage["deferred"]
        if not isinstance(item, dict)
        or dispositions.get(coverage_candidate_key(item), "needs_follow_up") == "needs_follow_up"
    ]
    # Only surviving references protect shared surfaces. Index by ID while retaining
    # owner-specific rows, so each reference need not scan every saved surface.
    referenced = {
        surface_reference_key(surface_id, item, surfaces_by_id.get(surface_id, []))
        for item in coverage["deferred"]
        if isinstance(item, dict)
        for surface_ids in [item.get("surfaceIds", [])]
        if isinstance(surface_ids, list)
        for surface_id in surface_ids
        if isinstance(surface_id, str)
    }
    used_ids = {
        field: {
            item["id"]
            for item in coverage[field]
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        for field in ("surfaces", "deferred")
    }

    def available_id(prefix: str, field: str) -> str:
        existing = used_ids[field]
        result, suffix = prefix, 1
        while result in existing:
            suffix += 1
            result = f"{prefix}-{suffix}"
        existing.add(result)
        return result

    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        key = (None, candidate_id)
        deferred = deferred_by_candidate.get(key, [])
        disposition = dispositions[key]
        # An interrupted budget completion can leave generated candidate rows.
        # Refresh them before retaining pending work, including shared surfaces.
        for surface in surfaces_by_candidate.get(key, []):
            if _generated_budget_candidate_surface(surface):
                surface.update(
                    label=candidate["summary"],
                    disposition=disposition,
                    notes=candidate["evidence"],
                    candidate={
                        **{
                            k: v
                            for k, v in surface["candidate"].items()
                            if k not in {"validation", "attack_path"}
                        },
                        **candidate,
                    },
                )
        if disposition == "needs_follow_up" and deferred:
            for item in deferred:
                item.setdefault("candidate", candidate)
            continue
        # A surface may also carry evidence for unfinished work from another
        # candidate or owner. Preserve those shared rows and add a dedicated decision.
        surfaces = [
            item
            for item in surfaces_by_candidate.get(key, [])
            if isinstance(item.get("id"), str)
            and item["id"].strip()
            and (item.get("disposition") != "reported" or disposition == "reported")
            and candidate_key(item["id"], item.get("sourceWorkerId")) not in referenced
        ]
        if not surfaces:
            surface = {
                "id": available_id(f"candidate-{candidate_id}", "surfaces"),
                "candidateId": candidate_id,
                "label": candidate["summary"],
                "disposition": disposition,
                "notes": candidate["evidence"],
                "receiptRefs": [],
            }
            coverage["surfaces"].append(surface)
            surfaces = [surface]
        retained_candidate = {}
        for item in [*deferred, *surfaces]:
            previous = item.get("candidate")
            if isinstance(previous, dict):
                retained_candidate.update(
                    {k: v for k, v in previous.items() if k not in {"validation", "attack_path"}}
                )
        previous_findings = [
            item["finding"] for item in deferred if isinstance(item.get("finding"), dict)
        ]
        for surface in surfaces:
            if disposition == "reported" or surface.get("disposition") not in (
                "rejected",
                "not_applicable",
            ):
                surface["disposition"] = disposition
            surface["candidate"] = {**retained_candidate, **candidate}
            if previous_findings:
                if not isinstance(surface.get("previousFindings"), list):
                    surface["previousFindings"] = []
                for finding in previous_findings:
                    if finding not in surface["previousFindings"]:
                        surface["previousFindings"].append(finding)
        if disposition != "needs_follow_up":
            continue
        paths = list(dict.fromkeys(location["path"] for location in candidate["locations"]))
        coverage["deferred"].append(
            {
                "id": available_id(candidate_id, "deferred"),
                "candidateId": candidate_id,
                "candidate": candidate,
                "reason": (
                    "Validation was deferred because the scan reached its cost limit: "
                    f"{candidate['summary']}. Evidence: {candidate['evidence']}"
                ),
                "paths": paths,
                "surfaceIds": [surface["id"] for surface in surfaces],
            }
        )


def _stopped_diff_candidate_decisions(
    scan_dir: Path,
    scan_id: str,
    drafts: list[dict[str, Any]],
    warnings: list[str],
    *,
    current_coverage: dict[str, Any],
    current_findings: list[dict[str, Any]],
    checkpoint_findings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Freeze current candidate state before historical evidence is recovered."""
    pending = {}
    current_pending_ids = {
        item["candidateId"]
        for item in unresolved_candidates(current_coverage, current_findings)
        if candidate_owner(item.get("sourceWorkerId")) is None
    }
    demoted_findings = {}
    # Count identities once, but inspect every current row and supported payload:
    # writers retain demoted findings on pending rows and later terminal surfaces.
    for field in ("deferred", "surfaces", "explicitExclusions"):
        items = current_coverage.get(field, [])
        for item in items if isinstance(items, list) else []:
            if (
                not isinstance(item, dict)
                or (key := coverage_candidate_key(item)) is None
                or key[0] is not None
            ):
                continue
            for payload in (item.get("finding"), item.get("candidate")):
                if isinstance(payload, dict):
                    for retained in _retained_findings(payload):
                        if finding_candidate_key(retained) == key:
                            demoted_findings.setdefault(key, []).append(retained)
    for draft in drafts:
        items = draft["coverage"].get("deferred", [])
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict) and (key := coverage_candidate_key(item)) and key[0] is None:
                pending.setdefault(key[1], copy.deepcopy(item))
    findings = [
        finding
        for finding in current_findings
        if (key := finding_candidate_key(finding)) is not None and key[0] is None
    ]
    authored = []
    generated = {}
    for field in ("surfaces", "explicitExclusions"):
        items = current_coverage.get(field, [])
        for item in items if isinstance(items, list) else []:
            if (
                isinstance(item, dict)
                and item.get("disposition") in {"rejected", "not_applicable"}
                and (key := coverage_candidate_key(item)) is not None
                and key[0] is None
            ):
                if field == "surfaces" and _generated_diff_candidate_decision(item):
                    generated[key[1]] = copy.deepcopy(item)
                else:
                    authored.append((field, copy.deepcopy(item)))
    authored_ids = {item["candidateId"] for _, item in authored}
    finding_ids = {finding_candidate_id(finding) for finding in findings}

    def was_demoted(finding: dict[str, Any]) -> bool:
        return any(
            isinstance(retained.get("provenance"), dict)
            and retained["provenance"].get("diffCandidateDecision")
            == finding["provenance"]["diffCandidateDecision"]
            and _finding_content(retained) == _finding_content(finding)
            for retained in demoted_findings.get(finding_candidate_key(finding), [])
        )

    # Publication can stop after checkpointing an explicit finding override but
    # before replacing the parent. Its phase snapshot still establishes ordering.
    # Current coverage retaining that finding records a later demotion.
    findings.extend(
        finding
        for finding in checkpoint_findings
        if (key := finding_candidate_key(finding)) is not None
        and key[0] is None
        and key[1] not in finding_ids | authored_ids
        and isinstance(finding.get("provenance", {}).get("diffCandidateDecision"), dict)
        and not was_demoted(finding)
        and (
            key[1] not in generated
            or finding["provenance"]["diffCandidateDecision"]
            == _diff_candidate_phase_snapshot(generated[key[1]]["candidate"])
        )
    )
    finding_ids = {finding_candidate_id(finding) for finding in findings}
    marked_ids = {
        finding_candidate_id(finding)
        for finding in findings
        if isinstance(finding.get("provenance", {}).get("diffCandidateDecision"), dict)
    }
    authoritative = finding_ids | authored_ids
    tracked = pending.keys() | generated.keys() | authoritative
    if not tracked:
        return None
    coverage = {
        "completeness": "partial",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        # Keep the existing checkpoint marker so frozen older scans remain readable.
        "stoppedDiffCandidateDecisions": True,
    }
    decisions = {
        candidate_id: item
        for candidate_id, item in generated.items()
        if candidate_id not in authoritative
    }
    pending = {
        candidate_id: item
        for candidate_id, item in pending.items()
        if candidate_id not in authoritative and candidate_id not in generated
    }
    relative = "artifacts/02_discovery/candidate_ledger.jsonl"
    try:
        if (tracked - authoritative or marked_ids) and (scan_dir / relative).exists():
            descriptor = open_scan_local_file_descriptor(
                scan_dir, relative, "Diff candidate ledger"
            )
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                candidates = [json.loads(line) for line in handle if line.strip()]
            for candidate in candidates:
                if (
                    not isinstance(candidate, dict)
                    or not isinstance(candidate.get("candidate_id"), str)
                    or (candidate_id := candidate["candidate_id"]) not in tracked
                    or (candidate_id in authoritative and candidate_id not in marked_ids)
                ):
                    continue
                decision = _diff_candidate_decision(candidate)
                if (
                    not isinstance(candidate.get("summary"), str)
                    or not candidate["summary"].strip()
                ):
                    raise ValueError("Diff candidate summary is missing.")
                phase_snapshot = _diff_candidate_phase_snapshot(candidate)
                # A current ledger snapshot can establish that a finding checkpoint
                # supersedes an older marked parent or generated terminal decision.
                for finding in checkpoint_findings:
                    if (
                        finding_candidate_key(finding) == (None, candidate_id)
                        and finding.get("provenance", {}).get("diffCandidateDecision")
                        == phase_snapshot
                        and finding not in findings
                        and candidate_id not in authored_ids
                        and not was_demoted(finding)
                    ):
                        findings.append(finding)
                        finding_ids.add(candidate_id)
                        authoritative.add(candidate_id)
                        decisions.pop(candidate_id, None)
                        pending.pop(candidate_id, None)
                if candidate_id in authoritative:
                    overrides = [
                        finding
                        for finding in findings
                        if finding_candidate_id(finding) == candidate_id
                    ]
                    current_overrides = [
                        finding
                        for finding in overrides
                        if not isinstance(
                            marker := finding["provenance"].get("diffCandidateDecision"), dict
                        )
                        or marker == phase_snapshot
                    ]
                    if candidate_id in authored_ids or current_overrides:
                        findings = [
                            finding
                            for finding in findings
                            if finding not in overrides or finding in current_overrides
                        ]
                        continue
                    # Only a recorded override supplies ordering evidence for a
                    # newer phase change. Legacy explicit findings keep precedence.
                    findings = [finding for finding in findings if finding not in overrides]
                    finding_ids.discard(candidate_id)
                    authoritative.discard(candidate_id)
                prior = pending.get(candidate_id, generated.get(candidate_id, {}))
                previous = prior.get("candidate")
                previous = previous if isinstance(previous, dict) else {}
                candidate = {
                    **{k: v for k, v in previous.items() if k not in {"attack_path", "validation"}},
                    **candidate,
                }
                if decision is not None:
                    decisions[candidate_id] = {
                        **generated.get(candidate_id, {}),
                        **decision,
                        "candidate": candidate,
                    }
                    pending.pop(candidate_id, None)
                    continue
                item = pending.setdefault(candidate_id, {"candidateId": candidate_id})
                current_pending_ids.add(candidate_id)
                item["candidate"] = candidate
                if "reason" not in item or item["reason"] == _diff_candidate_reason(previous):
                    item["reason"] = _diff_candidate_reason(candidate)
                old_decision = decisions.pop(candidate_id, None)
                if old_decision is not None:
                    coverage["surfaces"].append(
                        {
                            **old_decision,
                            "candidate": item["candidate"],
                            "label": candidate["summary"],
                            "disposition": "needs_follow_up",
                            "notes": item["reason"],
                        }
                    )
    except (ContractError, OSError, ValueError) as exc:
        warnings.append(f"Could not reconcile the saved Diff candidates: {exc}")
    for field, item in authored:
        if item["candidateId"] not in finding_ids:
            coverage[field].append(item)
    coverage["surfaces"].extend(decisions.values())
    coverage["deferred"].extend(
        item for candidate_id, item in pending.items() if candidate_id in current_pending_ids
    )
    return {
        "scanId": scan_id,
        "complete": False,
        "findings": copy.deepcopy(findings),
        "coverage": coverage,
    }


def _reconcile_stopped_diff_sources(
    parent: dict[str, Any] | None,
    sources: list[tuple[str, dict[str, Any], str | None]],
    decisions: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[tuple[str, dict[str, Any], str | None]]]:
    """Apply frozen candidate state to copies, retaining all original source digests."""
    states = {}
    for draft in decisions:
        for finding in draft["findings"]:
            states[finding_candidate_key(finding)] = ("reported", finding)
        for field in ("surfaces", "explicitExclusions"):
            for item in draft["coverage"][field]:
                if item.get("disposition") in {"rejected", "not_applicable"}:
                    states[coverage_candidate_key(item)] = (item["disposition"], item)
        for item in unresolved_candidates(draft["coverage"], draft["findings"]):
            states[coverage_candidate_key(item)] = ("deferred", item)

    def project(draft: dict[str, Any], owner: str | None) -> dict[str, Any]:
        if draft["coverage"].get("stoppedDiffCandidateDecisions") is True:
            return draft
        result = copy.deepcopy(draft)
        retained = []
        for finding in result["findings"]:
            state = (
                states.get(finding_candidate_key(finding, owner))
                if isinstance(finding, dict)
                else None
            )
            if state is None:
                retained.append(finding)
            elif state[0] == "reported":
                provenance = finding.get("provenance")
                marker = (
                    provenance.get("diffCandidateDecision")
                    if isinstance(provenance, dict)
                    else None
                )
                current_marker = state[1].get("provenance", {}).get("diffCandidateDecision")
                if (
                    isinstance(marker, dict)
                    and isinstance(current_marker, dict)
                    and marker != current_marker
                ):
                    if not isinstance(state[1]["provenance"].get("previousFindings"), list):
                        state[1]["provenance"]["previousFindings"] = []
                    history = state[1]["provenance"]["previousFindings"]
                    if finding not in history:
                        history.append(finding)
                else:
                    retained.append(finding)
            elif state[0] == "deferred":
                state[1].setdefault("finding", finding)
            else:
                history = state[1].setdefault("previousFindings", [])
                if finding not in history:
                    history.append(finding)
        result["findings"] = retained
        for field in ("surfaces", "explicitExclusions", "deferred"):
            items = result["coverage"].get(field)
            if isinstance(items, list):
                result["coverage"][field] = [
                    item
                    for item in items
                    if not isinstance(item, dict)
                    or coverage_candidate_key(item, owner) not in states
                    or (
                        field != "deferred"
                        and item.get("disposition") not in {"rejected", "not_applicable"}
                    )
                ]
        return result

    return (
        project(parent, None) if parent else None,
        [(relative, project(draft, owner), owner) for relative, draft, owner in sources],
    )


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
    """Merge bound results, persisting parent and stopped-decision checkpoints for replay."""
    initial_warnings = set(warnings)
    parent: dict[str, Any] | None = None
    parent_manifest: dict[str, Any] | None = None
    if frozen_source_digests is None or allow_frozen_legacy_parent:
        try:
            parent_manifest, parent = _read_saved_parent_result(scan_dir, scan_id)
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
                checkpoint = copy.deepcopy(parent)
                if (
                    stopped
                    and parent_scan.get("sealedAt")
                    and not parent_scan.get("preservedSources")
                ):
                    checkpoint["coverage"]["legacyUnscopedParentCandidates"] = True
                payload = _encoded(checkpoint)
                parent_digest = hashlib.sha256(payload).hexdigest()
                parent_checkpoint = f"checkpoints/{parent_digest}.json"
                write_scan_local_bytes(scan_dir, parent_checkpoint, payload)
                if frozen_source_digests is not None:
                    frozen_source_digests = {
                        **frozen_source_digests,
                        parent_checkpoint: parent_digest,
                    }

    sources: list[tuple[str, dict[str, Any], str | None]] = []
    parent_preserved_sources: dict[str, str] = {}
    source_digests: dict[str, str] = {}
    if parent_manifest:
        recorded = parent_manifest["scan"].get("preservedSources", {})
        if isinstance(recorded, dict):
            parent_preserved_sources = recorded
            source_digests.update(parent_preserved_sources)
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

    def checkpoints(directory: str, worker_id: str | None) -> None:
        for name in _children(scan_dir, directory):
            if re.fullmatch(r"[0-9a-f]{64}\.json", name):
                paths[f"{directory}/{name}"] = worker_id

    checkpoints("checkpoints", None)
    for worker in workers:
        try:
            output = Path(worker["artifact_dir"]).relative_to(scan_dir).as_posix()
        except (TypeError, ValueError):
            warnings.append("Skipped a worker checkpoint outside the scan directory.")
            continue
        if worker["kind"] == "dedup":

            def reducer_output(directory: str, attempt: int, reducer_worker: Any) -> None:
                result_path = f"{directory}/result.json"
                checkpoint_paths = [
                    f"{directory}/checkpoints/{name}"
                    for name in _children(scan_dir, f"{directory}/checkpoints")
                    if re.fullmatch(r"[0-9a-f]{64}\.json", name)
                ]
                if not checkpoint_paths:
                    return
                paths[result_path] = None
                for checkpoint_path in checkpoint_paths:
                    paths[checkpoint_path] = None
                reducer_paths.update([result_path, *checkpoint_paths])
                reducer_outputs.append((reducer_worker, result_path, checkpoint_paths, attempt))

            reducer_output(output, int(worker["attempt"] or 0), worker)
            attempts = (
                Path(output).parent if Path(output).name == "output" else Path(output)
            ) / "attempts"
            for name in _children(scan_dir, attempts.as_posix()):
                match = re.fullmatch(r"attempt-(\d+)", name)
                if match:
                    reducer_output((attempts / name).as_posix(), int(match.group(1)), worker)
            continue
        if worker["kind"] != "discovery":
            continue
        paths[f"{output}/result.json"] = worker["id"]
        current_results.add(f"{output}/result.json")
        checkpoints(f"{output}/checkpoints", worker["id"])
        attempts = (
            Path(output).parent if Path(output).name == "output" else Path(output)
        ) / "attempts"
        for name in _children(scan_dir, attempts.as_posix()):
            if re.fullmatch(r"attempt-\d+", name):
                archived = (attempts / name).as_posix()
                paths[f"{archived}/result.json"] = worker["id"]
                checkpoints(f"{archived}/checkpoints", worker["id"])
        if worker["result_manifest_path"]:
            try:
                current_path = Path(worker["result_manifest_path"]).relative_to(scan_dir).as_posix()
                paths[current_path] = worker["id"]
                current_results.add(current_path)
            except ValueError:
                warnings.append("Skipped a worker result outside the scan directory.")

    if frozen_source_digests is not None:
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
            draft, digest = _read_saved_result(
                scan_dir, relative, scan_id, kind="dedup" if relative in reducer_paths else None
            )
            if frozen_source_digests is not None and frozen_source_digests[relative] != digest:
                raise ContractError("checkpoint changed after the scan stopped")
            source_digests[relative] = digest
            # Reducer metadata retains pending candidates independently of findings.
            # Project it only after hashing the immutable original result.
            projected = {"coverage": {}, **draft}
            if relative in reducer_paths and draft.get("unresolvedCandidates"):
                projected["coverage"] = copy.deepcopy(projected["coverage"])
                projected["coverage"].setdefault("deferred", []).extend(
                    copy.deepcopy(draft["unresolvedCandidates"])
                )
                projected["coverage"]["completeness"] = "partial"
            sources.append((relative, projected, worker_id))
        except (ContractError, OSError, ValueError) as exc:
            if (scan_dir / relative).exists():
                warnings.append(f"Preserved unreadable checkpoint {relative}: {exc}")
    if frozen_source_digests is not None:
        if frozen_source_digests.keys() - source_digests.keys():
            raise ContractError("Frozen stopped-scan checkpoint set is incomplete.")

    worker_ids = {worker["id"] for worker in workers if worker["kind"] == "discovery"}
    if worker_ids:
        if parent is not None:
            parent = _bind_retained_source_owners(parent, worker_ids)
        sources = [
            (
                relative,
                _bind_retained_source_owners(draft, worker_ids) if owner is None else draft,
                owner,
            )
            for relative, draft, owner in sources
        ]

    def valid_finding(value: Any) -> bool:
        # Invalid latest records must not hide valid history.
        return bool(recoverable_findings(scan_dir, scan_id, binding["target"], [value]))

    decision_drafts = [
        draft
        for _, draft, _ in sources
        if draft["coverage"].get("stoppedDiffCandidateDecisions") is True
    ]
    if (
        stopped
        and binding["coverageMode"] in {"commit", "branch_diff", "working_tree"}
        and frozen_source_digests is None
        and not decision_drafts
    ):
        decision_draft = _stopped_diff_candidate_decisions(
            scan_dir,
            scan_id,
            ([parent] if parent else []) + [draft for _, draft, owner in sources if owner is None],
            warnings,
            current_coverage=parent["coverage"] if parent else {},
            current_findings=[finding for finding in parent["findings"] if valid_finding(finding)]
            if parent
            else [],
            checkpoint_findings=[
                finding
                for _, draft, owner in sources
                if owner is None
                for finding in draft["findings"]
                if valid_finding(finding)
            ],
        )
        if decision_draft is not None:
            digest = _digest(decision_draft)
            relative = f"checkpoints/{digest}.json"
            write_scan_local_bytes(scan_dir, relative, _encoded(decision_draft))
            source_digests[relative] = digest
            sources.append((relative, decision_draft, None))
            decision_drafts.append(decision_draft)
    diff_resolved = {
        (None, item["candidateId"])
        for draft in decision_drafts
        for field in ("surfaces", "explicitExclusions")
        for item in draft["coverage"][field]
        if item.get("disposition") in {"rejected", "not_applicable"}
    }
    resolved_surface_keys = {
        (key[0], surface_id)
        for _, draft, worker_id in ([("parent", parent, None)] if parent else []) + sources
        for items in [draft["coverage"].get("deferred", [])]
        if isinstance(items, list)
        for item in items
        if isinstance(item, dict)
        and (key := coverage_candidate_key(item, worker_id)) in diff_resolved
        for surface_ids in [item.get("surfaceIds", [])]
        if isinstance(surface_ids, list)
        for surface_id in surface_ids
        if isinstance(surface_id, str)
    }
    if decision_drafts:
        parent, sources = _reconcile_stopped_diff_sources(parent, sources, decision_drafts)

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
        reducer_order = (worker["completed_at"] or "", worker["id"], attempt)
        if latest_reducer_key is None or reducer_order > latest_reducer_key:
            latest_reducer_key = reducer_order
            latest_reducer = result_path

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
    coverage = {
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
        **(copy.deepcopy(parent["coverage"]) if parent else {}),
    }
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
        if parent_manifest
        else set()
    )
    findings: list[dict[str, Any]] = []
    finding_positions: dict[str, int] = {}
    represented: dict[str, str | None] = {}
    represented_candidates: dict[tuple[str, str, Any, Any, Any], str | None] = {}
    represented_history: dict[str, set[str]] = {}
    represented_candidate_history: dict[tuple[str, str, Any, Any, Any], set[str]] = {}
    rejected_history: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
    stopped_parent_seal = bool(
        stopped and parent_manifest and parent_manifest["scan"].get("sealedAt")
    )

    legacy_candidate_rows = {
        field: [
            item
            for draft in (
                ([parent] if stopped_parent_seal and not parent_preserved_sources else [])
                + [
                    source
                    for _, source, _ in sources
                    if source["coverage"].get("legacyUnscopedParentCandidates") is True
                ]
            )
            for items in [draft["coverage"].get(field, [])]
            if isinstance(items, list)
            for item in items
            if isinstance(item, dict)
            and isinstance(item.get("candidateId"), str)
            and candidate_owner(item.get("sourceWorkerId")) is None
        ]
        for field in ("surfaces", "explicitExclusions", "deferred")
    }

    all_sources = ([("parent", parent, None)] if parent else []) + sources
    current_drafts = [
        (worker_id, draft) for relative, draft, worker_id in sources if relative in current_results
    ]
    if parent:
        if stopped_parent_seal and not parent_preserved_sources:
            # A legacy stopped parent predates newly recovered worker decisions.
            current_drafts.append((None, parent))
        else:
            current_drafts.insert(0, (None, parent))
    resolved: dict[tuple[str | None, str], str] = {}
    for owner, draft in [(None, draft) for draft in decision_drafts] + current_drafts:
        for finding in draft["findings"]:
            if (
                isinstance(finding, dict)
                and valid_finding(finding)
                and (key := finding_candidate_key(finding, owner)) is not None
            ):
                resolved.setdefault(key, "reported")
        for field in ("surfaces", "explicitExclusions"):
            items = draft["coverage"].get(field, [])
            for item in items if isinstance(items, list) else []:
                if (
                    isinstance(item, dict)
                    and item.get("disposition") in {"rejected", "not_applicable"}
                    and (key := coverage_candidate_key(item, owner)) is not None
                ):
                    resolved.setdefault(key, item["disposition"])
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
                            worker_candidate = _worker_candidate_key(
                                source_id.rsplit(":", 1)[0],
                                candidate_id,
                                original["finding"],
                            )
                            previous_key = represented_candidates.get(worker_candidate)
                            if worker_candidate not in represented_candidates:
                                represented_candidates[worker_candidate] = canonical_key
                            elif previous_key != canonical_key:
                                # Candidate ids are only authoritative within one
                                # logical worker. Multiple canonical owners make
                                # that worker-local identity ambiguous.
                                represented_candidates[worker_candidate] = None
                            represented_candidate_history.setdefault(worker_candidate, set()).add(
                                _digest(_finding_content(original["finding"]))
                            )
                            resolved.setdefault(worker_candidate[:2], "reported")
    pending_resolved = resolved.keys() | diff_resolved

    for relative, draft, worker_id in all_sources:
        superseded = (
            worker_id is None
            and parent is not None
            and parent.get("complete") is not False
            and relative != "parent"
            and (not stopped_parent_seal or relative in parent_preserved_sources)
        ) or (
            relative not in current_results
            and any(
                saved_worker == worker_id
                and saved_path in current_results
                and current.get("complete") is not False
                for saved_path, current, saved_worker in sources
            )
        )
        if draft["coverage"].get("stoppedDiffCandidateDecisions") is True:
            superseded = False
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
        if (
            superseded
            and not stopped
            and all(valid_finding(finding) for finding in (parent["findings"] if parent else []))
        ):
            continue
        if "threatModel" not in manifest["scan"] and isinstance(draft.get("threatModel"), dict):
            manifest["scan"]["threatModel"] = copy.deepcopy(draft["threatModel"])
        for value in draft["findings"]:
            if relative == "parent" and parent_manifest:
                finding = copy.deepcopy(value)
                _ensure_finding_identity(finding, candidate_only=True)
                candidate = finding_candidate_key(finding) if isinstance(finding, dict) else None
                if (
                    stopped_parent_seal
                    and candidate is not None
                    and candidate[0] is not None
                    and resolved.get(candidate) in {"rejected", "not_applicable"}
                ):
                    rejected_history.setdefault(candidate, []).append(finding)
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
            candidate = finding_candidate_key(finding, worker_id)
            if relative != "parent" and resolved.get(candidate) in {"rejected", "not_applicable"}:
                rejected_history.setdefault(candidate, []).append(copy.deepcopy(finding))
                surfaces = coverage.get("surfaces")
                for item in surfaces if isinstance(surfaces, list) else []:
                    if isinstance(item, dict) and coverage_candidate_key(item) == candidate:
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
                _bind_finding_worker(finding, worker_id, source_value)
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
                    worker_candidate = _worker_candidate_key(worker_id, candidate_id, finding)
                    if worker_candidate not in represented_candidates:
                        represented_candidates[worker_candidate] = key
                    mapped_key = represented_candidates[worker_candidate]
                    historical_contents = represented_candidate_history.get(worker_candidate, set())
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
                if (
                    worker_id is not None
                    and isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                ):
                    # Legacy parents copied worker rows without ownership. Preserve
                    # the existing exact/semantic dedupe before adding that owner.
                    semantic_item = dict(item)
                    if field == "surfaces":
                        semantic_item.setdefault("receiptRefs", [])
                    for existing in output:
                        if (
                            isinstance(existing, dict)
                            and candidate_owner(existing.get("sourceWorkerId")) is None
                            and existing in legacy_candidate_rows.get(field, [])
                            and (
                                existing == item
                                or (
                                    "id" not in item
                                    and {
                                        key: value for key, value in existing.items() if key != "id"
                                    }
                                    == semantic_item
                                )
                            )
                        ):
                            existing["sourceWorkerId"] = worker_id
                            break
                    item = {**item, "sourceWorkerId": worker_id}
                if (
                    field == "surfaces"
                    and isinstance(item, dict)
                    and item.get("disposition") in {"rejected", "not_applicable"}
                    and isinstance(item.get("candidateId"), str)
                    and (
                        history_findings := rejected_history.get(
                            coverage_candidate_key(item, worker_id)
                        )
                    )
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
                    and coverage_candidate_key(item) in pending_resolved
                    and (
                        field == "deferred"
                        or (
                            item.get("disposition") == "needs_follow_up"
                            and coverage_candidate_key(item) not in diff_resolved
                        )
                    )
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

    if isinstance(coverage.get("deferred"), list):
        coverage["deferred"] = [
            item
            for item in coverage["deferred"]
            if not isinstance(item, dict) or coverage_candidate_key(item) not in pending_resolved
        ]

    if diff_resolved and isinstance(coverage.get("surfaces"), list):
        # Shared evidence belongs to surviving candidates and explicit references.
        deferred = coverage.get("deferred", [])
        surfaces = [item for item in coverage["surfaces"] if isinstance(item, dict)]
        pending_candidate_keys = {
            key
            for item in (deferred if isinstance(deferred, list) else [])
            if isinstance(item, dict) and (key := coverage_candidate_key(item)) is not None
        }
        pending_surface_keys = {
            surface_reference_key(surface_id, item, surfaces)
            for item in (deferred if isinstance(deferred, list) else [])
            if isinstance(item, dict)
            for surface_ids in [item.get("surfaceIds", [])]
            if isinstance(surface_ids, list)
            for surface_id in surface_ids
            if isinstance(surface_id, str)
        }
        coverage["surfaces"] = [
            item
            for item in coverage["surfaces"]
            if not isinstance(item, dict)
            or item.get("disposition") != "needs_follow_up"
            or (
                coverage_candidate_key(item) not in diff_resolved
                and candidate_key(item.get("id"), item.get("sourceWorkerId"))
                not in resolved_surface_keys
            )
            or coverage_candidate_key(item) in pending_candidate_keys
            or candidate_key(item.get("id"), item.get("sourceWorkerId")) in pending_surface_keys
        ]

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
    surfaces = coverage.get("surfaces", [])
    surfaces = (
        [item for item in surfaces if isinstance(item, dict)] if isinstance(surfaces, list) else []
    )
    original_surfaces = [dict(item) for item in surfaces]
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
            item.setdefault("id", item.get("candidateId") or f"saved-{_digest(item)[:16]}")
            if item["id"] in used:
                item["id"] = f"{item['id']}-{_digest(item)[:16]}"
            used.add(item["id"])
            if field == "surfaces":
                item.setdefault("receiptRefs", [])
    renamed_surfaces = {}
    for original, surface in zip(original_surfaces, surfaces):
        if (key := candidate_key(original.get("id"), original.get("sourceWorkerId"))) is not None:
            renamed_surfaces.setdefault(key, surface["id"])
    deferred = coverage.get("deferred", [])
    for item in deferred if isinstance(deferred, list) else []:
        if isinstance(item, dict) and isinstance(item.get("surfaceIds"), list):
            item["surfaceIds"] = [
                renamed_surfaces.get(surface_reference_key(value, item, original_surfaces), value)
                for value in item["surfaceIds"]
            ]
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
            json.loads(raw_frozen_sources), "Saved stopped-scan"
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
        # Save scan IDs without sealing the draft.
        _populate_unsealed_manifest_envelope(manifest, manifest["scan"], binding)
        _populate_unsealed_artifact_envelope(manifest, findings, coverage, binding)
        _validate_completion_binding(manifest, findings, coverage, binding)
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
