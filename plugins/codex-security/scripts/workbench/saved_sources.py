"""Encoding, path, and observation helpers for saved scan sources."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_json,
    _read_scan_local_json,
    _read_scan_local_json_with_metadata,
    _require_portable_relative_path,
    _require_str,
    _validate_resolved_deferred,
    _validate_schema_node,
    finding_candidate_id,
    open_scan_local_file_descriptor,
)
from workbench.saved_coverage import _project_worker_coverage_row, _saved_coverage_id


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def _encode_retained_sources(
    sources: dict[str, str],
    model_source: list[str],
    source_times: dict[str, int] | None = None,
) -> str:
    state: dict[str, Any] = sources
    if model_source or source_times is not None:
        state = {"sources": sources}
        if model_source:
            state["threatModelSource"] = model_source[0]
        if source_times is not None:
            state["sourceTimes"] = source_times
    return json.dumps(state, sort_keys=True)


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


def _checkpoint_head_directory(relative: str) -> Path | None:
    path = Path(relative)
    if path.name == "checkpoint-head.json":
        return path.parent
    if path.parent.name == "checkpoint-heads":
        return path.parent.parent
    return None


def _unselected_root_order(
    saved_heads: dict[str, str],
    checkpoint_heads: dict[str, str | None],
    source_order: dict[str, tuple[int, int]],
) -> tuple[int, int]:
    # One payload can have several accepted observations; retain their order.
    return max(
        (
            source_order[head]
            for head, checkpoint in saved_heads.items()
            if _checkpoint_head_directory(head) == Path(".")
            and checkpoint_heads.get(".") not in (None, head, f"checkpoints/{checkpoint}")
        ),
        default=(-1, 0),
    )


def _is_source_order_snapshot(relative: str) -> bool:
    path = Path(relative)
    return path.parent == Path("source-order") and bool(
        re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
    )


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
        normalized = dict(finding)
        normalized.pop("identity", None)
        _ensure_finding_identity(normalized)
        identity = normalized["identity"]
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


def _resolved_deferred_rows(draft: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, Any]]:
    if draft.get("complete") is False:
        return []
    coverage = draft["coverage"]
    rows = coverage.get("resolvedDeferred", [])
    try:
        # Invalid closure metadata cannot discard the evidence it names.
        _validate_schema_node(rows, schema, "coverage.resolvedDeferred")
        _validate_resolved_deferred({**coverage, "deferred": _deferred_rows(coverage)})
    except ContractError:
        return []
    return rows


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
        Path(__file__).resolve().parent.parent.parent / "schemas" / "coverage.schema.json"
    )["properties"]["resolvedDeferred"]
    closures = {}
    for observed in (current, previous):
        for row in _resolved_deferred_rows(observed, closure_schema):
            if row["id"] not in pending_ids:
                closures.setdefault(row["id"], copy.deepcopy(row))
    coverage.pop("resolvedDeferred", None)
    if closures:
        coverage["resolvedDeferred"] = list(closures.values())
    if current.get("complete") is False or previous.get("complete") is False:
        merged["complete"] = False
    coverage.pop("completeness", None)
    return merged


def _deferred_candidate_id(
    row: dict[str, Any],
    owner: str | None,
    ambiguous_deferred: set[tuple[str | None, str]],
) -> str | None:
    identity = row.get("candidateId") or row.get("id")
    if not isinstance(identity, str):
        return None
    if (owner, identity) in ambiguous_deferred and not any(
        key in row for key in ("candidateId", "candidate", "finding")
    ):
        return None
    return identity


def _generic_surface_updates(
    sources: list[tuple[str, dict[str, Any], str | None]],
    source_order: dict[str, tuple[int, int]],
    closed_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    active_deferred: dict[tuple[str | None, str], tuple[tuple[int, int], dict[str, Any], str]],
    resolved_candidates: dict[tuple[str | None, str], str],
    reopened_generic: set[tuple[str | None, str]],
    surface_schema: dict[str, Any],
    deferred_rows: dict[str, list[Any]],
    ambiguous_deferred: set[tuple[str | None, str]],
    *,
    surface_is_retained: Callable[[str, str | None, dict[str, Any]], bool],
    eligible_receipt_sources: set[str],
    receipt_root: Path | None = None,
    receipt_warnings: list[str] | None = None,
    fallback_surfaces: list[dict[str, Any]] | None = None,
) -> tuple[set[int], list[tuple[str | None, dict[str, Any], set[int]]]]:
    if not closed_deferred and not reopened_generic and receipt_root is None:
        return set(), []

    def receipt_error(ref: Any) -> ContractError | None:
        if receipt_root is None or not isinstance(ref, str):
            return ContractError("Saved coverage receipt is unavailable.")
        try:
            descriptor = open_scan_local_file_descriptor(
                receipt_root, ref, "Saved coverage receipt"
            )
            os.close(descriptor)
        except ContractError as exc:
            return exc
        return None

    def linked(row: dict[str, Any], identity: str | None) -> bool:
        surface_ids = row.get("surfaceIds", [])
        return identity is not None and (
            row.get("id") == identity or (isinstance(surface_ids, list) and identity in surface_ids)
        )

    saved_surfaces: dict[tuple[str | None, str], list[tuple[str, dict[str, Any]]]] = {}
    for relative, draft, owner in sources:
        rows = draft["coverage"].get("surfaces", [])
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and isinstance(row.get("id"), str):
                saved_surfaces.setdefault((owner, row["id"]), []).append((relative, row))
    replaced: set[int] = set()
    updates: list[tuple[str | None, dict[str, Any], set[int]]] = []
    # Current selections across all surfaces take precedence over historical refs.
    receipt_paths: dict[str, str] = {}
    retained_surfaces: dict[tuple[str | None, str], dict[str, Any]] = {}
    if receipt_root is not None:
        receipt_surfaces: list[tuple[str | None, dict[str, Any]]] = []
        for key, matches in saved_surfaces.items():
            retained = [
                match for match in matches if surface_is_retained(match[0], key[0], match[1])
            ]
            if not retained:
                continue
            latest_source, latest_surface = max(retained, key=lambda match: source_order[match[0]])
            retained_surfaces[key] = latest_surface
            receipt_surfaces.extend(
                (key[0], row)
                for relative, row in retained
                if source_order[relative] == source_order[latest_source]
            )
        for relative, draft, owner in sources:
            rows = draft["coverage"].get("surfaces", [])
            for row in rows if isinstance(rows, list) else []:
                if (
                    isinstance(row, dict)
                    and "id" not in row
                    and surface_is_retained(relative, owner, row)
                ):
                    receipt_surfaces.append((owner, row))
        receipt_surfaces.extend((None, row) for row in fallback_surfaces or [])
        for owner, latest_surface in receipt_surfaces:
            # Recovery repairs disposition and receipts before validating row
            # metadata. A row discarded there cannot reserve a receipt spelling.
            metadata = _project_worker_coverage_row(latest_surface, owner, "surfaces")
            metadata.setdefault("id", _saved_coverage_id(metadata))
            metadata.update(disposition="needs_follow_up", receiptRefs=[])
            try:
                _require_str(metadata, "id", "coverage.surfaces")
                _validate_schema_node(metadata, surface_schema, "coverage.surfaces")
            except ContractError:
                continue
            refs = latest_surface.get("receiptRefs", [])
            for ref in refs if isinstance(refs, list) else []:
                if receipt_error(ref) is None:
                    normalized = _require_portable_relative_path(ref, "Saved coverage receipt")
                    receipt_paths.setdefault(normalized.lower(), normalized)
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
        if not closed_ids and not reopened_ids and receipt_root is None:
            continue
        current = draft["coverage"].get("surfaces", [])
        for surface in current if isinstance(current, list) else []:
            if not isinstance(surface, dict):
                continue
            reopening = surface.get("disposition") == "needs_follow_up"
            work_ids = reopened_ids if reopening else closed_ids
            repair_only = not work_ids
            if repair_only and receipt_root is None:
                continue
            identity = surface.get("id")
            if not isinstance(identity, str):
                continue
            matches = saved_surfaces[(owner, identity)]
            # Receipt repair alone cannot close or reopen a saved surface.
            if repair_only and any(
                row.get("disposition") != surface.get("disposition") for _, row in matches
            ):
                continue
            # Older writers could assign one ID to distinct surfaces in a draft.
            # A closure cannot identify which of those observations it replaces.
            by_source = dict(matches)
            if any(row != by_source[saved_path] for saved_path, row in matches):
                continue
            if any(
                "candidateId" in row or "candidate" in row or "finding" in row for _, row in matches
            ):
                continue
            if any(
                row is not surface
                and source_order[saved_path] >= source_order[relative]
                and row.get("disposition") != surface.get("disposition")
                for saved_path, row in matches
            ):
                continue

            if not reopening and any(
                saved_owner == owner
                and (
                    not isinstance(row.get("id") or row.get("candidateId"), str)
                    or (
                        isinstance(row.get("id"), str)
                        and (owner, row["id"]) in ambiguous_deferred
                        and not any(key in row for key in ("candidateId", "candidate", "finding"))
                    )
                )
                and linked(row, identity)
                for saved_path, _, saved_owner in sources
                for row in deferred_rows[saved_path]
                if isinstance(row, dict)
            ):
                continue
            if not reopening and any(
                saved_owner == owner
                and (owner, deferred_id) not in closed_deferred
                and (
                    (candidate_id := _deferred_candidate_id(row, owner, ambiguous_deferred)) is None
                    or (owner, candidate_id) not in resolved_candidates
                )
                and linked(row, identity)
                for (saved_owner, deferred_id), (_, row, _) in active_deferred.items()
            ):
                continue
            # An accepted checkpoint can update a saved surface by ID without
            # optional surfaceIds links on its generic task.
            receipt_matches = [
                (saved_path, row)
                for saved_path, row in matches
                if receipt_root is None
                or saved_path in eligible_receipt_sources
                or surface_is_retained(saved_path, owner, row)
            ]
            if not receipt_matches:
                continue
            latest_surface = max(receipt_matches, key=lambda match: source_order[match[0]])[1]
            target = retained_surfaces.get((owner, identity)) if repair_only else latest_surface
            if target is None:
                continue
            update = copy.deepcopy(target)
            # Historical evidence can repair a retained row without promoting
            # an unselected observation's label, notes, or other metadata.
            refs = copy.deepcopy(latest_surface.get("receiptRefs", []))
            update["receiptRefs"] = refs
            replaced_receipt = False
            replacement_paths = dict(receipt_paths)
            if isinstance(refs, list):
                repaired = (
                    not reopening and bool(refs) and all(receipt_error(ref) is None for ref in refs)
                )
                if repaired:
                    for ref in refs:
                        normalized = _require_portable_relative_path(ref, "Saved coverage receipt")
                        key = normalized.lower()
                        if key in replacement_paths and replacement_paths[key] != normalized:
                            repaired = False
                            break
                        replacement_paths[key] = normalized
                for _, row in receipt_matches:
                    previous_refs = row.get("receiptRefs", [])
                    for ref in previous_refs if isinstance(previous_refs, list) else []:
                        if ref not in refs:
                            failure = receipt_error(ref) if repaired else None
                            replaceable = failure is not None and isinstance(
                                failure.__cause__, FileNotFoundError
                            )
                            if repaired and isinstance(ref, str):
                                try:
                                    normalized = _require_portable_relative_path(
                                        ref, "Saved coverage receipt"
                                    )
                                except ContractError as error:
                                    failure = error
                                    replaceable = True
                                else:
                                    key = normalized.lower()
                                    previous = replacement_paths.get(key)
                                    if previous is not None and previous != normalized:
                                        failure = ContractError(
                                            f"Saved coverage receipt: duplicate artifact path: {previous} and {normalized}"
                                        )
                                        replaceable = True
                                    elif not replaceable:
                                        replacement_paths[key] = normalized
                            if replaceable:
                                replaced_receipt = True
                                if receipt_warnings is not None:
                                    receipt_warnings.append(
                                        f"Replaced invalid saved coverage receipt {ref}: {failure}"
                                    )
                                continue
                            refs.append(ref)
            if repair_only and not replaced_receipt:
                continue
            try:
                _validate_schema_node(update, surface_schema, "coverage.surfaces")
            except ContractError:
                continue
            replaced_sources = {
                id(row)
                for _, row in matches
                if reopening
                or row.get("disposition") in {"needs_follow_up", surface.get("disposition")}
            }
            replaced.update(replaced_sources)
            existing = next(
                (entry for entry in updates if entry[0] == owner and entry[1] == update), None
            )
            if existing is None:
                receipt_paths.update(replacement_paths)
                updates.append((owner, update, replaced_sources))
            else:
                existing[2].update(replaced_sources)
    return replaced, updates


def _read_saved_result(
    scan_dir: Path, relative: str, scan_id: str, *, kind: str | None = None
) -> tuple[dict[str, Any], str, int]:
    draft, _, metadata = _read_scan_local_json_with_metadata(
        scan_dir, relative, "Saved scan checkpoint"
    )
    directory = _checkpoint_head_directory(relative)
    if directory is not None:
        checkpoint = draft.get("checkpoint")
        if not isinstance(checkpoint, str) or not re.fullmatch(r"[0-9a-f]{64}\.json", checkpoint):
            raise ContractError("checkpoint head does not name a saved checkpoint")
        _read_saved_result(scan_dir, (directory / "checkpoints" / checkpoint).as_posix(), scan_id)
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


def _frozen_source_times(scan_dir: Path, scan_id: str, sources: dict[str, str]) -> dict[str, int]:
    times: dict[str, int] = {}
    snapshots = [path for path in sources if _is_source_order_snapshot(path)]
    for path in snapshots:
        record, digest, _ = _read_saved_result(scan_dir, path, scan_id)
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


def _retained_source_state(value: Any) -> tuple[dict[str, str], str | None]:
    if isinstance(value, dict) and isinstance(value.get("sources"), dict):
        sources = _source_digests(
            value["sources"], "Saved stopped-scan source digests are malformed."
        )
        model_source = value.get("threatModelSource")
        if "threatModelSource" in value and (
            not isinstance(model_source, str) or model_source not in sources
        ):
            raise ContractError("Saved stopped-scan model source is outside its checkpoint set.")
        return sources, model_source
    return _source_digests(value, "Saved stopped-scan source digests are malformed."), None


def _frozen_checkpoint_heads(
    scan_dir: Path, scan_id: str, sources: dict[str, str], *, skip_unreadable: bool = False
) -> dict[str, str]:
    try:
        times = _frozen_source_times(scan_dir, scan_id, sources)
    except (ContractError, OSError, ValueError):
        if not skip_unreadable:
            raise
        times = {}
    heads: dict[str, tuple[int, str]] = {}
    ambiguous: set[str] = set()
    for relative, expected_digest in sources.items():
        directory = _checkpoint_head_directory(relative)
        if directory is None:
            continue
        try:
            head, digest, observed = _read_saved_result(scan_dir, relative, scan_id)
            if digest != expected_digest:
                raise ContractError("checkpoint changed after the scan stopped")
        except (ContractError, OSError, ValueError):
            if skip_unreadable:
                continue
            raise
        selected = (directory / "checkpoints" / head["checkpoint"]).as_posix()
        observation = (times.get(relative, observed), selected)
        key = directory.as_posix()
        if key not in heads or observation[0] > heads[key][0]:
            heads[key] = observation
            ambiguous.discard(key)
        elif observation[0] == heads[key][0] and selected != heads[key][1]:
            ambiguous.add(key)
    # A legacy tie retains both observations until recovery selects a head.
    return {
        directory: selected
        for directory, (_, selected) in heads.items()
        if directory not in ambiguous
    }


def _retained_checkpoint_state(scan: Any) -> tuple[dict[str, str | None] | None, bool]:
    raw = scan["retained_checkpoint_heads_json"]
    if raw is None:
        return None, False
    saved = json.loads(raw)
    if not isinstance(saved.get("heads"), dict):
        return saved, False
    if saved["recoveryBaseDigest"] != scan["seal_manifest_digest"]:
        raise ContractError("Stopped scan recovery publication changed after selection.")
    return saved["heads"], True


def _restore_checkpoint_head(
    heads: dict[str, str | None],
    previous_heads: dict[str, str | None],
    sources: dict[str, str],
    relative: str,
) -> None:
    path = Path(relative)
    if path.name != "checkpoint-head.json":
        return
    directory = path.parent.as_posix()
    if directory in previous_heads:
        heads[directory] = previous_heads[directory]
        return
    directories = {path.parent, path.parent / "checkpoints", path.parent / "checkpoint-heads"}
    if any(Path(source).parent in directories for source in sources):
        # Legacy evidence can remain accepted without one selected head.
        heads.pop(directory, None)


def _legacy_checkpoint_observed_at(
    scan_dir: Path, scan_id: str, sources: dict[str, str], selected: str
) -> int | None:
    times = _frozen_source_times(scan_dir, scan_id, sources)
    checkpoint = Path(selected)
    observations = []
    for relative, expected_digest in sources.items():
        if _checkpoint_head_directory(relative) != checkpoint.parent.parent:
            continue
        head, digest, observed = _read_saved_result(scan_dir, relative, scan_id)
        if digest != expected_digest:
            raise ContractError("checkpoint changed after the scan stopped")
        if head["checkpoint"] == checkpoint.name:
            observations.append(times.get(relative, observed))
    # Payload-only selections used the newest retained observation for that payload.
    return max(observations, default=None)
