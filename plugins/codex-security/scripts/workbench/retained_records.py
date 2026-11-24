"""Identify and recover records retained from saved scan evidence."""

from __future__ import annotations

import copy
import hashlib
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _has_identity_text,
    _read_json,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _require_safe_json_value,
    _validate_schema_node,
    finding_candidate_id,
)
from finalize_scan_contract import _schema_values_equal as same_raw_value
from workbench.saved_coverage import _coverage_rows, _saved_coverage_id
from workbench.saved_sources import _digest, _encoded
from workbench_coverage_receipts import resolve_coverage_receipts
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
        sibling = next((value for value in _report_ids(finding) if value is not None), None)
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


def _recover_preserved_worker_source(
    scan_dir, relative, scan_id, binding, worker_id, worker, draft, warnings
):
    """Normalize findings and receipt references in the draft and return diagnostics for discarded findings."""
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
            current_contract=True,
        )
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
    """Repair coverage in the draft, append source warnings, and return whether coverage was discarded."""
    discarded_coverage = False
    for field in ("surfaces", "explicitExclusions", "deferred"):
        for row in _coverage_rows(draft["reviewState"], field):
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


def _report_ids(value: dict[str, Any]) -> tuple[Any, Any]:
    """Return the report ID and ledger row ID from extensions, using None for missing or blank IDs."""
    extensions = value.get("extensions")
    return tuple(
        identifier if _has_identity_text(identifier) else None
        for identifier in (
            extensions.get(field) if isinstance(extensions, dict) else None
            for field in ("reportId", "ledgerRowId")
        )
    )


def raw_owner(value: dict[str, Any], source_owner: str | None) -> str | None:
    """Return the source owner, falling back to the worker ID recorded in finding provenance."""
    if source_owner is not None:
        return source_owner
    provenance = value.get("provenance", {})
    owner = provenance.get("workerId")
    return owner if isinstance(owner, str) else source_owner


def raw_scope(value: dict[str, Any]) -> tuple[Any, ...]:
    """Return the rule, path, and line range of the first location used to match anonymous reports."""
    # Match scanFindingIdentity's primary location for anonymous reports.
    location = value["locations"][0]
    return (
        value.get("ruleId"),
        location["path"],
        location["startLine"],
        location.get("endLine"),
    )


def same_raw_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Compare substantive finding fields while ignoring identity, provenance, and report-tracking IDs."""

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
    """Check whether the current JSON value retains every part of the previous value.

    Match dictionary values by key and list elements by content, regardless of order.
    """
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
    """Return saved candidate outcomes with their evidence and the ordering of pending candidates by owner."""
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
            for item in _coverage_rows(draft["reviewState"], field):
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
            if any(
                isinstance(row, dict) and row.get("id") == result["id"]
                for row in _coverage_rows(coverage, "surfaces")
            ):
                result["id"] = f"{result['id']}-{_digest(result)[:16]}"
    elif field == "deferred":
        result["id"] = f"{prefix}-deferred-{index}"
        if isinstance(item.get("surfaceIds"), list):
            surface_ids: dict[str, str] = {}
            for surface in _coverage_rows(projected_coverage, "surfaces"):
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
            source_surface_ids: dict[str, tuple[int, dict[str, Any]]] = {}
            for offset, surface in enumerate(_coverage_rows(source, "surfaces"), 1):
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
