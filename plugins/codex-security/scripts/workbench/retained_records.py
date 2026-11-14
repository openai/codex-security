"""Identify and recover records retained from saved scan evidence."""

from __future__ import annotations

import copy
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

from candidate_identity import _has_identity_text, finding_candidate_key
from finalize_scan_contract import (
    ContractError,
    _finding_strength,
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
from workbench_budget_candidates import current_report, valid_exclusion
from workbench_budget_candidates import finding_content as _finding_content
from workbench_coverage_receipts import resolve_coverage_receipts

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


def identifiers(value: dict[str, Any]) -> tuple[Any, Any]:
    """Return the report ID and ledger row ID from extensions, using None for missing or blank IDs."""
    extensions = value.get("extensions")
    return tuple(
        identifier if _has_identity_text(identifier) else None
        for identifier in (
            extensions.get(field) if isinstance(extensions, dict) else None
            for field in ("reportId", "ledgerRowId")
        )
    )


def distinct_reports(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    """Check the latest observations for conflicting report IDs or ledger row IDs."""
    return (
        left is not None
        and right is not None
        and any(
            a is not None and b is not None and a != b
            for a, b in zip(identifiers(left["latest"]), identifiers(right["latest"]), strict=True)
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


def same_raw_finding(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Check whether semantic identities match or, in their absence, whether candidate and report IDs are compatible."""
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
    selected_observations,
    source_order,
):
    """Return saved candidate outcomes with their evidence and the ordering of pending candidates by owner."""
    pending_candidate_orders: dict[tuple[str | None, str], tuple[int, int]] = {}
    outcomes = []
    accepted_in_source = set()
    for relative, draft, owner in current_drafts:
        reported_candidates = {
            key
            for finding in draft["findings"]
            if isinstance(finding, dict)
            and valid_finding(finding)
            and (key := finding_candidate_key(finding, owner)) is not None
            and current_report(finding, draft, owner, relative in selected_observations)
        }
        terminal_candidates = {
            key
            for field in ("surfaces", "explicitExclusions")
            for row in _coverage_rows(draft["reviewState"], field)
            if (owner is None or draft.get("complete") is not False)
            and isinstance(row, dict)
            and row.get("disposition") in ("rejected", "not_applicable")
            and (
                valid_exclusion(row, coverage_schema[field]["items"])
                if field == "explicitExclusions"
                else isinstance(row.get("label"), str) and row["label"].strip()
            )
            and (key := coverage_candidate(owner, row)) is not None
        }
        accepted_in_source.update(
            (relative, key) for key in reported_candidates | terminal_candidates
        )
        pending_candidates = set()
        for field in ("deferred", "surfaces"):
            for item in _coverage_rows(draft["reviewState"], field):
                if isinstance(item, dict) and (
                    field == "deferred" or item.get("disposition") == "needs_follow_up"
                ):
                    if (pending := coverage_candidate(owner, item)) is not None:
                        if (relative, pending) in accepted_in_source:
                            continue
                        pending_candidates.add(pending)
                        order = candidate_order(relative, pending[0], item)
                        pending_candidate_orders[pending] = max(
                            pending_candidate_orders.get(pending, order), order
                        )
        for candidate in reported_candidates:
            outcomes.append((relative, *candidate, "reported", source_order[relative], ()))
        for field in ("surfaces", "explicitExclusions"):
            for item in _coverage_rows(draft["reviewState"], field):
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("candidateId"), str)
                    and item.get("disposition") in ("reported", "rejected", "not_applicable")
                    and (candidate := coverage_candidate(owner, item)) is not None
                    and (item["disposition"] != "reported" or candidate in reported_candidates)
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
    return outcomes, pending_candidate_orders, accepted_in_source


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


def after_custom_validation(parent, sources):
    scope = parent.get("scope") if parent else None
    if not isinstance(scope, dict) or scope.get("validationMode") != "custom":
        return sources

    def provisional(finding):
        extensions = finding.get("extensions") if isinstance(finding, dict) else None
        return isinstance(extensions, dict) and bool(extensions.get("customValidationSurfaceIds"))

    # The validator removes its provisional marker when it publishes a finding.
    # Earlier parent checkpoints can still carry those inputs and unrelated evidence.
    if any(provisional(finding) for finding in parent["findings"]):
        return sources
    return [
        (
            relative,
            {**draft, "findings": [row for row in draft["findings"] if not provisional(row)]},
            owner,
        )
        if owner is None and any(provisional(row) for row in draft["findings"])
        else (relative, draft, owner)
        for relative, draft, owner in sources
    ]


def group_saved_findings(
    all_sources,
    parent_is_canonical,
    precedes_terminal_parent,
    finding_source_order,
    replaced_parent_finding,
    valid_finding,
    finding_within_scope,
    same_owner,
    terminal_findings,
    represented,
    represented_history,
    represented_candidates,
    represented_candidate_history,
):
    """Reconcile equivalent saved findings and retain each distinct group and its history."""
    logical_rows: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = {}
    row_groups: dict[tuple[str, int], dict[str, Any]] = {}
    published_groups: list[dict[str, Any]] = []
    finding_sources = [
        source for source in all_sources if not precedes_terminal_parent(source[0], source[2])
    ]
    # Publication chronology spans workers; attempt numbers only order one worker's revisions.
    for source in sorted(finding_sources, key=lambda item: finding_source_order(item)[2:]):
        relative, draft, source_owner = source
        explicit_identity_counts = Counter(
            _semantic_identity_key(sibling, _finding_identity(sibling))
            for sibling in draft["findings"]
            if isinstance(sibling, dict)
            and isinstance(sibling.get("identity"), dict)
            and ((relative == "parent" and parent_is_canonical) or finding_within_scope(sibling))
        )
        pending = []
        for index, value in enumerate(draft["findings"]):
            if (
                not isinstance(value, dict)
                or replaced_parent_finding(relative, source_owner, value)
                or not valid_finding(value)
                or (
                    not (relative == "parent" and parent_is_canonical)
                    and not finding_within_scope(value)
                )
            ):
                continue
            owner = raw_owner(value, source_owner)
            scope = raw_scope(value)
            candidate = finding_candidate_id(value)
            scopes = [scope, (scope[0], candidate)] if candidate else [scope]
            publication_identity = (
                _finding_identity(
                    value if "identity" in value else terminal_findings[relative][index]
                )
                if relative in terminal_findings
                else None
            )
            matches = [
                group
                for group in {
                    key: group
                    for saved_scope in scopes
                    for key, group in logical_rows.get(saved_scope, {}).items()
                }.values()
                if same_owner(owner, group["owner"])
                and (
                    publication_identity is None
                    or group["identity"] is None
                    or _semantic_identity_key(value, group["identity"])
                    == _semantic_identity_key(value, publication_identity)
                )
                and (
                    (relative == "parent" and parent_is_canonical)
                    or group["identity"] is None
                    or "identity" not in value
                    or _semantic_identity_key(value, group["identity"])
                    == _semantic_identity_key(value, _finding_identity(value))
                )
                and all(same_raw_finding(value, previous) for previous in group["rows"])
            ]
            ranked = []
            for group in matches:
                latest = group["latest"]
                if (
                    isinstance(value.get("identity"), dict)
                    and explicit_identity_counts[
                        _semantic_identity_key(value, _finding_identity(value))
                    ]
                    == 1
                    and group["identity"] is not None
                    and _semantic_identity_key(value, _finding_identity(value))
                    == _semantic_identity_key(value, group["identity"])
                ):
                    rank = 4
                elif (
                    owner == group["owner"]
                    and same_raw_content(value, latest)
                    and _identity_candidate(value) == _identity_candidate(latest)
                    and identifiers(value) == identifiers(latest)
                ):
                    rank = 3
                elif any(same_raw_content(value, previous) for previous in group["rows"]):
                    rank = 2
                elif (
                    latest.get("title") == value.get("title")
                    and raw_scope(latest) == scope
                    and all(
                        previous is None or current == previous
                        for current, previous in zip(
                            identifiers(value), identifiers(latest), strict=True
                        )
                    )
                ):
                    rank = 1
                else:
                    rank = 0
                ranked.append((group, rank))
            pending.append((index, value, owner, scopes, ranked))
        assigned = {}
        claimed = set()
        for index, value, owner, _, matches in pending:
            for group, _ in matches:
                if (
                    group["key"] not in claimed
                    and owner == group["owner"]
                    and same_raw_value(value, group["latest"])
                ):
                    assigned[index] = group
                    claimed.add(group["key"])
                    break
        for rank in (4, 3, 2, 1, 0):
            identity_claims = {
                group["key"]
                for index, _, _, _, matches in pending
                for group, score in matches
                if score == 4 and assigned.get(index) is group
            }
            options = {
                index: [
                    group
                    for group, score in matches
                    if score >= rank
                    and (
                        group["key"] not in claimed
                        or (rank == 0 and group["key"] not in identity_claims)
                    )
                ]
                for index, _, _, _, matches in pending
                if index not in assigned
            }
            counts = {}
            for groups in options.values():
                for group in groups:
                    counts[group["key"]] = counts.get(group["key"], 0) + 1
            chosen = {
                index: groups[0]
                for index, groups in options.items()
                if len(groups) == 1
                and groups[0]["key"] not in claimed
                and counts[groups[0]["key"]] == 1
            }
            assigned.update(chosen)
            claimed.update(group["key"] for group in chosen.values())
        current_groups: list[tuple[int, dict[str, Any]]] = []
        for index, value, owner, scopes, _ in pending:
            match = assigned.get(index)
            if match is None:
                match = {
                    "owner": owner,
                    "rows": [],
                    "identity": None,
                    "key": f"raw:{len(row_groups)}",
                }
            for saved_scope in scopes:
                logical_rows.setdefault(saved_scope, {})[match["key"]] = match
            if match["owner"] is None:
                match["owner"] = owner
            if not any(same_raw_value(value, previous) for previous in match["rows"]):
                match["rows"].append(value)
            observations = match.setdefault("observations", {})
            previous = observations.get(source_owner)
            if previous is None or (
                finding_source_order(source, True),
                _finding_strength(value),
            ) > (
                finding_source_order(previous[0], True),
                _finding_strength(previous[1]),
            ):
                observations[source_owner] = (source, value)
                match["latest"] = max(
                    observations.values(),
                    key=lambda observation: (
                        finding_source_order(observation[0]),
                        _finding_strength(observation[1]),
                    ),
                )[1]
            if relative in terminal_findings:
                match["identity"] = copy.deepcopy(
                    _finding_identity(
                        value if "identity" in value else terminal_findings[relative][index]
                    )
                )
            elif "identity" in value and (match["identity"] is None or relative == "parent"):
                match["identity"] = copy.deepcopy(_finding_identity(value))
            row_groups[(relative, index)] = match
            current_groups.append((index, match))
        if source_owner is None:
            current_ordered = [
                group for _, group in sorted(current_groups, key=lambda item: item[0])
            ]
            ordered = current_ordered + [
                group for group in published_groups if group not in current_ordered
            ]
            normalized = []
            for group in ordered:
                value = copy.deepcopy(group["latest"])
                if group["identity"] is not None:
                    value["identity"] = copy.deepcopy(group["identity"])
                normalized.append(value)
            _ensure_finding_identities(normalized)
            for group, value in zip(ordered, normalized, strict=True):
                group["identity"] = value["identity"]
            published_groups = ordered

    # A later worker draft can collapse raw duplicates that it fully contains.
    # Keep established identities and any evidence absent from the newer report.
    contained_groups = set()
    for group in {group["key"]: group for group in row_groups.values()}.values():
        owner = group["owner"]
        previous = group["observations"].get(owner)
        if owner is None or group["identity"] is not None or previous is None:
            continue
        for current in logical_rows.get(raw_scope(group["latest"]), {}).values():
            observed = current["observations"].get(owner)
            if (
                current["owner"] == owner
                and observed is not None
                and finding_source_order(observed[0], True)
                > finding_source_order(previous[0], True)
                and all(contains_raw_value(current["latest"], row) for row in group["rows"])
            ):
                contained_groups.add(group["key"])
                break

    # An absorbed source represents every reconciled version of that worker report.
    for groups in logical_rows.values():
        for group in groups.values():
            destinations = set()
            for value in group["rows"]:
                history_key = _finding_key(value)
                if _digest(_finding_content(value)) in represented_history.get(history_key, set()):
                    destinations.add(represented.get(history_key))
                elif group["owner"] and (candidate_id := finding_candidate_id(value)):
                    candidate_key = _worker_candidate_key(group["owner"], candidate_id, value)
                    if _digest(_finding_content(value)) in represented_candidate_history.get(
                        candidate_key, set()
                    ):
                        destinations.add(represented_candidates[candidate_key])
            if len(destinations) == 1 and None not in destinations:
                group["parent_key"] = destinations.pop()

    return row_groups, contained_groups
