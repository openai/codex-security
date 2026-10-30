"""Identify and recover records retained from saved scan evidence."""

from __future__ import annotations

import copy
import hashlib
import re
import unicodedata
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _has_identity_text,
    _read_json,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _require_safe_json_value,
    _validate_current_findings,
    _validate_schema_node,
    finding_candidate_id,
)
from workbench.saved_coverage import _coverage_rows, _has_candidate_metadata, _saved_coverage_id
from workbench.saved_sources import _digest, _encoded
from workbench_coverage_receipts import _deferred_candidate_id, resolve_coverage_receipts
from workbench_validation import javascript_utf8

_FINDING_IDENTITY_SCHEMA = _read_json(
    Path(__file__).resolve().parents[2] / "schemas" / "findings.schema.json"
)["properties"]["findings"]["items"]["properties"]["identity"]


def _finding_identity(finding: dict[str, Any]) -> Any:
    provenance = finding.get("provenance")
    if isinstance(provenance, dict) and "preservedIdentity" in provenance:
        try:
            _validate_schema_node(
                provenance["preservedIdentity"], _FINDING_IDENTITY_SCHEMA, "finding.identity"
            )
        except ContractError:
            pass
        else:
            return provenance["preservedIdentity"]
    return finding.get("identity")


def _finding_key(finding: dict[str, Any], owner: str | None = None) -> str:
    # Wording and evidence may improve between checkpoints; distinct source locations
    # must not collide merely because two workers chose the same semantic identity.
    provenance = finding.get("provenance")
    identity = _finding_identity(finding)
    if not isinstance(identity, dict):
        normalized = dict(finding)
        normalized.pop("identity", None)
        _ensure_finding_identity(normalized)
        identity = normalized["identity"]
    owner = provenance.get("workerId", owner) if isinstance(provenance, dict) else owner
    parts = [finding.get("ruleId"), identity, _finding_locations(finding)]
    if owner is not None and finding_candidate_id(finding):
        parts.append(owner)
    return _digest(parts)


def _finding_locations(finding: dict[str, Any]) -> list[tuple[Any, Any, Any]]:
    locations = finding.get("locations", [])
    return sorted(
        (
            (
                location.get("path"),
                location.get("startLine"),
                location.get("endLine", location.get("startLine")),
            )
            for location in (locations if isinstance(locations, list) else [])
            if isinstance(location, dict)
        ),
        key=_encoded,
    )


def _worker_candidate_key(
    worker_id: str, candidate_id: str, finding: dict[str, Any]
) -> tuple[str, str, Any, Any, Any]:
    """Identify one worker-local candidate without merging unrelated locations."""
    identity = _finding_identity(finding)
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


def _identity_candidate(finding: dict[str, Any]) -> str | None:
    return next(
        (
            value
            for section in (finding.get("extensions"), finding.get("provenance"))
            if isinstance(section, dict) and _has_identity_text(value := section.get("candidateId"))
        ),
        None,
    )


def _ensure_finding_identity(finding: Any) -> None:
    _ensure_finding_identities([finding])


def _semantic_identifier(value: str, fallback: str) -> str:
    normalized = re.sub(r"[\u0300-\u036f]", "", unicodedata.normalize("NFKD", value))
    identifier = re.sub(r"[^a-z0-9._/-]+", "-", normalized.lower())
    return re.sub(r"^[^a-z0-9]+|-+$", "", identifier) or fallback


def _semantic_identity_key(finding: dict[str, Any], identity: Any = None) -> bytes:
    identity = finding.get("identity") if identity is None else identity
    if isinstance(identity, dict):
        identity = {key: identity.get(key) for key in ("anchor", "instance")}
    return _encoded([finding.get("ruleId"), identity])


def _ensure_finding_identities(findings: list[Any], *, deep: bool = False) -> None:
    """Use the same candidate, anchor and sibling rules as draft publication."""
    anchors: dict[int, Any] = {}
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        identity = finding.get("identity")
        if "identity" in finding:
            anchors[index] = identity.get("anchor") if isinstance(identity, dict) else None
            continue
        candidate = _identity_candidate(finding)
        anchors[index] = _semantic_identifier(
            candidate or str(finding.get("title") or "finding"), f"finding-{index + 1}"
        )
    counts = Counter(
        _digest([findings[index].get("ruleId"), anchor]) for index, anchor in anchors.items()
    )

    authored = {
        _semantic_identity_key(finding)
        for finding in findings
        if isinstance(finding, dict) and "identity" in finding
    }
    generated = []
    for index, anchor in anchors.items():
        finding = findings[index]
        if "identity" in finding:
            continue
        identity = {"anchor": anchor}
        extensions = finding.get("extensions")
        sibling = next(
            (
                value
                for field in ("reportId", "ledgerRowId")
                if isinstance(extensions, dict)
                and _has_identity_text(value := extensions.get(field))
            ),
            None,
        )
        if sibling or counts[_digest([finding.get("ruleId"), anchor])] > 1:
            identity["instance"] = _semantic_identifier(
                sibling or str(finding.get("title") or "finding"), f"finding-{index + 1}"
            )
        finding["identity"] = identity
        generated.append(finding)

    reserved = {
        _semantic_identity_key(finding) for finding in findings if isinstance(finding, dict)
    }
    used = set() if deep else authored.copy()
    generated_ids = {id(finding) for finding in generated}
    for finding in findings if deep else generated:
        key = _semantic_identity_key(finding)
        if key in used or (id(finding) in generated_ids and key in authored):
            identity = finding["identity"]
            if id(finding) not in generated_ids:
                finding.setdefault("provenance", {}).setdefault(
                    "preservedIdentity", copy.deepcopy(identity)
                )
            base_instance = identity.get("instance", "saved")
            suffix = 2
            while True:
                identity["instance"] = f"{base_instance}-{suffix}"
                key = _semantic_identity_key(finding)
                if key not in reserved:
                    reserved.add(key)
                    break
                suffix += 1
        used.add(key)


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


def _append_previous_finding(
    item: dict[str, Any], finding: dict[str, Any], *, clone: bool = False
) -> None:
    if not isinstance(item.get("previousFindings"), list):
        item["previousFindings"] = []
    history = item["previousFindings"]
    if not any(
        isinstance(previous, dict)
        and _finding_key(previous) == _finding_key(finding)
        and _finding_content(previous) == _finding_content(finding)
        for previous in history
    ):
        history.append(copy.deepcopy(finding) if clone else finding)


def _recover_preserved_worker_source(
    scan_dir, relative, scan_id, binding, worker_id, worker, draft, warnings
):
    discarded_findings = []
    # Recover imported records without relaxing canonical parent validation.
    if "complete" in draft and not isinstance(draft["complete"], bool):
        draft["complete"] = False
        warnings.append(f"{relative}: Invalid complete marker; retained as a progress checkpoint.")
    schema_dir = Path(__file__).resolve().parents[2] / "schemas"
    if "threatModel" in draft:
        try:
            model = draft["threatModel"]
            if isinstance(model, dict):
                model = {**model, "origin": "recovered"}
            schema = _read_json(schema_dir / "scan-manifest.schema.json")
            _validate_schema_node(
                model,
                schema["properties"]["scan"]["properties"]["threatModel"],
                "threatModel",
                schema,
            )
            _require_safe_json_value(model, "threatModel")
        except ContractError as exc:
            draft.pop("threatModel")
            warnings.append(f"{relative}: Skipped malformed threat model: {exc}.")
    directory = Path(relative).parent
    if directory.name == "checkpoints":
        directory = directory.parent
    recovered_findings = []
    for index, finding in enumerate(draft["findings"]):
        needs_identity = isinstance(finding, dict) and "identity" not in finding
        _ensure_finding_identity(finding)
        recovered = {"scanId": scan_id, "findings": [finding]}
        source_warnings: list[str] = []
        discarded = _recover_unsealed_findings(
            {"scan": {"id": scan_id, "target": binding["target"]}},
            recovered,
            schema_dir,
            scan_dir / directory,
            source_warnings,
        )
        if recovered["findings"]:
            try:
                _validate_current_findings(recovered, schema_dir)
            except ContractError as exc:
                warning = f"Skipped malformed finding: {exc}."
                source_warnings.append(warning)
                discarded.append(warning)
                recovered["findings"] = []
        if discarded:
            discarded_findings.extend(discarded)
        for recovered_finding in recovered["findings"]:
            if needs_identity:
                # Reconcile anonymous revisions before assigning sibling identities.
                recovered_finding.pop("identity", None)
            writeup = recovered_finding.pop("writeup", None)
            if writeup is not None:
                source_warnings.append(
                    "Retained worker writeup at "
                    f"{directory.as_posix()}/{writeup['reportPath']}; "
                    "the parent report renders this finding inline."
                )
        recovered_findings.extend(recovered["findings"])
        warnings.extend(f"{relative} finding {index + 1}: {warning}" for warning in source_warnings)
    draft["findings"] = recovered_findings
    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        rows = draft["reviewState"].get(field)
        if not isinstance(rows, list):
            continue
        for index, row in enumerate(rows):
            if field == "openQuestions" and isinstance(row, str):
                row = rows[index] = {"question": row}
            if not isinstance(row, dict):
                continue
            row["workerId"] = worker_id
            if field == "surfaces":
                row["receiptRefs"] = resolve_coverage_receipts(
                    scan_dir,
                    row,
                    worker,
                    relative,
                )
    return discarded_findings


def _recover_preserved_worker_coverage(
    scan_dir, relative, worker_id, draft, discarded_findings, warnings
):
    discarded_coverage = False
    for field in ("surfaces", "explicitExclusions", "deferred"):
        rows = draft["reviewState"].get(field)
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                row.setdefault("id", _saved_coverage_id(row))
                if field == "surfaces":
                    row.setdefault("receiptRefs", [])
    source_warnings = []
    discarded_fields = _recover_unsealed_coverage(
        draft["reviewState"],
        Path(__file__).resolve().parents[2] / "schemas",
        scan_dir,
        source_warnings,
        discarded_findings,
        # Reconcile local IDs and valid outcomes against worker history below.
        worker_draft=True,
    )
    if discarded_fields & {
        "surfaces",
        "explicitExclusions",
        "deferred",
        "resolvedDeferred",
    }:
        discarded_coverage = True
    for row in draft["reviewState"]["deferred"]:
        row["workerId"] = worker_id
    warnings.extend(f"{relative}: {warning}" for warning in source_warnings)
    return discarded_coverage


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
            for a, b in zip(identifiers(left["latest"]), identifiers(right["latest"]), strict=True)
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


def _saved_outcome_receipts(scan_dir, relative, worker, field, item, coverage_schema):
    normalized = dict(item)
    if field == "surfaces":
        normalized.setdefault("id", _saved_coverage_id(item))
        normalized.setdefault("receiptRefs", [])
        if worker is not None:
            normalized["receiptRefs"] = resolve_coverage_receipts(
                scan_dir, normalized, worker, relative
            )
        verified = {
            "completeness": "partial",
            "surfaces": [normalized],
            "explicitExclusions": [],
            "deferred": [],
        }
        _recover_unsealed_coverage(
            verified, Path(__file__).resolve().parents[2] / "schemas", scan_dir, [], []
        )
        if (
            not verified["surfaces"]
            or verified["surfaces"][0]["disposition"] != item["disposition"]
        ):
            return None
        normalized = verified["surfaces"][0]
    try:
        _validate_schema_node(normalized, coverage_schema[field]["items"], f"coverage.{field}")
    except ContractError:
        return None
    return tuple(normalized.get("receiptRefs", [])) if field == "surfaces" else ()


def _conflicting_outcome_receipts(coverage, scan_dir, receipts):
    # Only a recovered surface can reserve the spelling that invalidates a second row.
    surfaces = _coverage_rows(coverage, "surfaces")
    projected = {
        "surfaces": [dict(row) if isinstance(row, dict) else row for row in surfaces],
        "deferred": [],
        "explicitExclusions": [],
    }
    _recover_unsealed_coverage(
        projected, Path(__file__).resolve().parents[2] / "schemas", scan_dir, [], []
    )
    kept = {ref.lower(): ref for row in projected["surfaces"] for ref in row["receiptRefs"]}
    for row in surfaces:
        if not (
            isinstance(row, dict)
            and isinstance(row.get("candidateId"), str)
            and row.get("disposition") in ("rejected", "not_applicable")
            and isinstance(row.get("receiptRefs"), list)
        ):
            continue
        normalized = {Path(ref).as_posix() for ref in row["receiptRefs"] if isinstance(ref, str)}
        if losing := {ref for ref in normalized & receipts if kept.get(ref.lower(), ref) != ref}:
            return losing
    return set()


def _saved_candidate_outcomes(
    scan_dir,
    current_drafts,
    valid_finding,
    coverage_candidate,
    candidate_order,
    workers_by_id,
    coverage_schema,
):
    pending_candidate_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    outcomes = []
    for relative, draft, owner in current_drafts:
        reported_candidates = {
            finding_candidate_id(finding)
            for finding in draft["findings"]
            if isinstance(finding, dict) and valid_finding(finding)
        }
        pending_candidates = set()
        for field in ("deferred", "surfaces"):
            items = draft["reviewState"].get(field, [])
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
                    (
                        relative,
                        owner,
                        candidate_id,
                        "reported",
                        candidate_order(relative, owner),
                        (),
                    )
                )
        for field in ("surfaces", "explicitExclusions"):
            for item in _coverage_rows(draft["reviewState"], field):
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                    and item.get("disposition") in ("reported", "rejected", "not_applicable")
                    and (candidate := coverage_candidate(owner, item)) is not None
                    and (item["disposition"] != "reported" or candidate[1] in reported_candidates)
                    and (candidate not in pending_candidates or item["disposition"] == "reported")
                ):
                    receipts = ()
                    if item["disposition"] != "reported":
                        receipts = _saved_outcome_receipts(
                            scan_dir,
                            relative,
                            workers_by_id.get(owner),
                            field,
                            item,
                            coverage_schema,
                        )
                        if receipts is None:
                            continue
                    outcomes.append(
                        (
                            relative,
                            candidate[0],
                            candidate[1],
                            item["disposition"],
                            candidate_order(relative, candidate[0], item),
                            receipts,
                        )
                    )
    return outcomes, pending_candidate_orders


def _competing_rejection_receipts(outcomes, all_sources, source_surface_receipts):
    receipt_spellings: dict[str, set[str]] = {}
    for _, _, _, _, _, receipts in outcomes:
        for ref in receipts:
            receipt_spellings.setdefault(ref.lower(), set()).add(ref)
    if receipt_spellings and any(
        isinstance(ref, str)
        and (spellings := receipt_spellings.get(Path(ref).as_posix().lower())) is not None
        and spellings != {Path(ref).as_posix()}
        for relative, draft, owner in all_sources
        for row in _coverage_rows(draft["reviewState"], "surfaces")
        if isinstance(row, dict)
        for refs in (source_surface_receipts(relative, row),)
        if isinstance(refs, list)
        for ref in refs
    ):
        return {ref for spellings in receipt_spellings.values() for ref in spellings}
    return set()


def _project_missing_record(
    field: str,
    item: dict[str, Any],
    index: int,
    worker: Any,
    source: dict[str, Any],
    *,
    receipts_resolved: bool = False,
    inferred_coverage_ids,
    projection_origins,
    coverage_receipts,
    retained_coverage_record,
    coverage,
    projected_coverage,
    accepted_surfaces,
    reconciled_surface_ids,
    accepted_coverage_sources,
    project_missing_record,
    canonical_coverage_record,
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
                        projected["receiptRefs"] = coverage_receipts(projected, worker, origin[1])
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


def _coverage_row_is_retained(
    field: str,
    item: Any,
    worker_id: str | None,
    selection: tuple[bool, set[str], bool, bool, bool],
    *,
    resolved,
    ambiguous_deferred,
    coverage_candidate,
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
        and not (isinstance(item, dict) and _has_candidate_metadata(item))
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


def _recovered_model(
    relative: str,
    draft: dict[str, Any],
    owner: str | None,
    *,
    model_checks,
    warnings,
) -> dict[str, Any] | None:
    if relative not in model_checks:
        model = copy.deepcopy(draft.get("threatModel"))
        if isinstance(model, dict) and owner is not None:
            model["origin"] = "recovered"
        schema = _read_json(
            Path(__file__).resolve().parents[2] / "schemas/scan-manifest.schema.json"
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
