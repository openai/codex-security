"""Reconcile saved cost-limit coverage with Diff candidate ledger decisions."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from candidate_identity import (
    _deferred_owner,
    candidate_key,
    coverage_candidate_key,
    diff_candidate_disposition,
    finding_candidate_key,
    is_candidate_row,
    surface_reference_key,
)
from finalize_scan_contract import (
    ContractError,
    _read_json,
    _recover_unsealed_coverage,
    _require_portable_relative_path,
    _require_scan_local_file,
    _validate_resolved_deferred,
    _validate_schema_node,
)


def resolved_deferred_rows(draft: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, Any]]:
    if draft.get("complete") is False:
        return []
    coverage = draft["coverage"]
    rows = coverage.get("resolvedDeferred", [])
    deferred = coverage.get("deferred", [])
    try:
        # Invalid closure metadata cannot discard the evidence it names.
        _validate_schema_node(rows, schema, "coverage.resolvedDeferred")
        _validate_resolved_deferred(
            {**coverage, "deferred": deferred if isinstance(deferred, list) else []}
        )
    except ContractError:
        return []
    return rows


def recover_candidate_receipts(
    parent: dict[str, Any] | None,
    scan_dir: Path,
    warnings: list[str],
    source: str | None = None,
    *,
    owner: str | None = None,
    reopened: set[tuple[str | None, str]] | None = None,
) -> dict[str, Any] | None:
    if parent is None:
        return parent
    surfaces = parent["coverage"].get("surfaces")
    if not isinstance(surfaces, list) or not any(
        isinstance(row, dict)
        and row.get("disposition") in ("rejected", "not_applicable")
        and (
            not isinstance(row.get("label"), str)
            or not row["label"]
            or row.get("receiptRefs")
            or ("receiptRefs" in row and not isinstance(row["receiptRefs"], list))
        )
        for row in surfaces
    ):
        return parent
    # Receipt recovery must precede resolution of the candidate's saved proof gaps.
    if source is not None:
        directory = Path(source).parent
        if directory.name == "checkpoints":
            directory = directory.parent
        scan_dir = scan_dir / directory
    parent = copy.deepcopy(parent)
    if source is not None:
        coverage = parent["coverage"]
        closures = []
        if coverage.get("resolvedDeferred"):
            schema = _read_json(
                Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
            )["properties"]["resolvedDeferred"]
            closures = resolved_deferred_rows(parent, schema)
        if not isinstance(coverage.get("deferred"), list):
            coverage["deferred"] = []
        for index, row in enumerate(coverage["surfaces"]):
            if not isinstance(row, dict) or row.get("disposition") not in (
                "rejected",
                "not_applicable",
            ):
                continue
            refs = row.get("receiptRefs", [])
            invalid = not isinstance(row.get("label"), str) or not row["label"]
            recovered = []
            warning_start = len(warnings)
            if not isinstance(refs, list):
                warnings.append(
                    f"Skipped malformed receipt references for coverage surface {index + 1}: expected an array."
                )
                invalid = True
            for position, ref in enumerate(refs if isinstance(refs, list) else []):
                context = f"coverage.surfaces[{index}].receiptRefs[{position}]"
                try:
                    if not isinstance(ref, str):
                        raise ContractError(f"{context}: expected a string")
                    ref = _require_portable_relative_path(ref, context)
                    if not ref.startswith("artifacts/"):
                        raise ContractError(f"{context}: expected a file under artifacts/")
                    _require_scan_local_file(scan_dir, ref, context)
                except ContractError as exc:
                    warnings.append(
                        f"Skipped malformed coverage receipt {index + 1}.{position + 1}: {exc}."
                    )
                    invalid = True
                    continue
                # Publication validates and seals receipts relative to the parent scan.
                recovered.append((directory / ref).as_posix())
            row["receiptRefs"] = recovered
            if invalid:
                row["disposition"] = "needs_follow_up"
                coverage["completeness"] = "partial"
                if (key := coverage_candidate_key(row, owner)) is not None:
                    pending = next(
                        (
                            item
                            for item in coverage["deferred"]
                            if isinstance(item, dict) and coverage_candidate_key(item, owner) == key
                        ),
                        None,
                    )
                    if pending is None:
                        pending = {
                            "candidateId": row["candidateId"],
                            "reason": "\n".join(warnings[warning_start:]),
                            **({"surfaceIds": [row["id"]]} if "id" in row else {}),
                            **{
                                field: copy.deepcopy(row[field])
                                for field in ("sourceWorkerId", "candidate", "finding")
                                if field in row
                            },
                        }
                        coverage["deferred"].append(pending)
                    archive_candidate_payloads(pending, [row])
        if closures:
            # Reopened candidate work must not invalidate unrelated valid closures.
            active = {
                row["id"]
                for row in coverage["deferred"]
                if isinstance(row, dict) and isinstance(row.get("id"), str)
            }
            coverage["resolvedDeferred"] = [row for row in closures if row["id"] not in active]
        return parent
    terminal = {
        coverage_candidate_key(row)
        for row in surfaces
        if isinstance(row, dict) and row.get("disposition") in ("rejected", "not_applicable")
    }
    _recover_unsealed_coverage(
        parent["coverage"],
        Path(__file__).resolve().parent.parent / "schemas",
        scan_dir,
        warnings,
        [],
    )
    if reopened is not None:
        reopened.update(
            key
            for row in parent["coverage"]["surfaces"]
            if row.get("disposition") == "needs_follow_up"
            and (key := coverage_candidate_key(row)) is not None
            and key in terminal
        )
    return parent


def archive_candidate_payloads(destination: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    for row in rows:
        for field, archive in (
            ("candidate", "originalCandidates"),
            ("finding", "previousFindings"),
        ):
            values = (
                [row[field]]
                if field in row
                and (
                    field not in destination
                    or json.dumps(row[field], sort_keys=True)
                    != json.dumps(destination[field], sort_keys=True)
                )
                else []
            )
            if isinstance(row.get(archive), list):
                values.extend(row[archive])
            if not values:
                continue
            if not isinstance(destination.get(archive), list):
                destination[archive] = []
            archived = {json.dumps(value, sort_keys=True) for value in destination[archive]}
            for value in values:
                encoded = json.dumps(value, sort_keys=True)
                if encoded not in archived:
                    destination[archive].append(copy.deepcopy(value))
                    archived.add(encoded)


def project_resolved_candidate_rows(
    rows: list[Any],
    field: str,
    owner: str | None,
    states: dict[Any, tuple[str, dict[str, Any]]],
    *,
    pending: list[dict[str, Any]] | None = None,
) -> list[Any]:
    surfaces = [row for row in rows if isinstance(row, dict)] if field == "surfaces" else []
    referenced_surfaces = {
        surface_reference_key(surface_id, item, surfaces)
        for item in pending or []
        for refs in [item.get("surfaceIds", [])]
        if isinstance(refs, list)
        for surface_id in refs
        if isinstance(surface_id, str)
    }
    retained = []
    for row in rows:
        state = states.get(coverage_candidate_key(row, owner)) if isinstance(row, dict) else None
        if state is None or (
            field != "deferred" and row.get("disposition") not in ("rejected", "not_applicable")
        ):
            retained.append(row)
        else:
            destination = state[1]["provenance"] if state[0] == "reported" else state[1]
            archive_candidate_payloads(destination, [row])
            if (
                field == "surfaces"
                and referenced_surfaces
                and candidate_key(row.get("id"), row.get("sourceWorkerId")) in referenced_surfaces
            ):
                retained.append(
                    {
                        **row,
                        "disposition": "needs_follow_up" if state[0] == "deferred" else state[0],
                    }
                )
    return retained


def retained_source_candidate_key(
    source: dict[str, Any],
    registered: dict[tuple[str, str], str],
    workers: set[str],
) -> tuple[str | None, str] | None:
    finding, reference = source.get("finding"), source.get("id")
    if not isinstance(finding, dict) or not isinstance(reference, str):
        return None
    key = finding_candidate_key(finding)
    if key is None:
        return None
    owner = registered.get((reference, key[1]))
    if owner is not None:
        return owner, key[1]
    if key[0] is not None:
        return key
    # Older reducers emitted ownerless originals using their known worker:index codec.
    worker, separator, index = reference.rpartition(":")
    if separator and worker in workers and re.fullmatch(r"0|[1-9][0-9]*", index):
        return worker, key[1]
    return key


def archive_resolved_deferred_payloads(
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
    resolved: dict[Any, str],
    valid_finding: Callable[[dict[str, Any]], bool],
    source_owners: dict[tuple[str, str], str],
    worker_ids: set[str],
) -> None:
    states = {
        key: ("reported", finding)
        for finding in findings
        if isinstance(finding, dict)
        and valid_finding(finding)
        and (key := finding_candidate_key(finding)) is not None
        and resolved.get(key) == "reported"
    }
    for finding in findings:
        if not isinstance(finding, dict) or not valid_finding(finding):
            continue
        sources = finding["provenance"].get("sourceFindings", [])
        for source in sources if isinstance(sources, list) else []:
            if isinstance(source, dict):
                key = retained_source_candidate_key(source, source_owners, worker_ids)
                if key is not None and resolved.get(key) == "reported":
                    states.setdefault(key, ("reported", finding))
    for field in ("surfaces", "explicitExclusions"):
        rows = coverage.get(field)
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and (key := coverage_candidate_key(row)) is not None:
                if (
                    resolved.get(key) in ("rejected", "not_applicable")
                    and row.get("disposition") == resolved[key]
                ):
                    states[key] = (resolved[key], row)
    # Preserve the evidence before the caller removes resolved proof gaps.
    project_resolved_candidate_rows(coverage["deferred"], "deferred", None, states)


def archive_resolved_diff_payloads(
    coverage: dict[str, Any], findings: list[dict[str, Any]], submitted_coverage: dict[str, Any]
) -> None:
    submitted: dict[str, list[dict[str, Any]]] = {}
    rows = submitted_coverage.get("deferred")
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and (key := coverage_candidate_key(row)) and key[0] is None:
            submitted.setdefault(key[1], []).append(row)
    for item in coverage["surfaces"] + coverage["explicitExclusions"]:
        if (key := coverage_candidate_key(item)) is not None:
            archive_candidate_payloads(item, submitted.get(key[1], []))
    for finding in findings:
        if (key := finding_candidate_key(finding)) is not None:
            archive_candidate_payloads(finding["provenance"], submitted.get(key[1], []))


def _generated_budget_candidate_surface(item: dict[str, Any]) -> bool:
    candidate = item.get("candidate")
    return (
        isinstance(candidate, dict)
        and isinstance(candidate.get("locations"), list)
        and all(
            isinstance(location, dict) and isinstance(location.get("path"), str)
            for location in candidate["locations"]
        )
        and item.get("candidateId") == candidate.get("candidate_id")
        and item.get("disposition") == (diff_candidate_disposition(candidate) or "needs_follow_up")
        and item.get("label") == candidate.get("summary")
        and item.get("notes") == candidate.get("evidence")
    )


def _budget_candidate_deferred(candidate: dict[str, Any], surface_ids: list[str]) -> dict[str, Any]:
    return {
        "candidate": candidate,
        "reason": (
            "Validation was deferred because the scan reached its cost limit: "
            f"{candidate['summary']}. Evidence: {candidate['evidence']}"
        ),
        "paths": list(dict.fromkeys(location["path"] for location in candidate["locations"])),
        "surfaceIds": surface_ids,
    }


def valid_exclusion(item: dict[str, Any], schema: dict[str, Any]) -> bool:
    try:
        _validate_schema_node(item, schema, "coverage.explicitExclusions")
    except ContractError:
        return False
    return True


def preserve_budget_candidates(
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    *,
    receipt_reopened: set[tuple[str | None, str]] | None = None,
) -> set[tuple[str | None, str]]:
    """Reconcile ledger candidates with the saved cost-limit draft's decisions."""
    findings_by_candidate = {
        key
        for finding in findings
        if isinstance(finding, dict)
        and not (
            isinstance(provenance := finding.get("provenance"), dict)
            and provenance.get("candidateReopened") is True
        )
        and (key := finding_candidate_key(finding)) is not None
    }

    candidates_by_surface_id = {
        f"candidate-{candidate['candidate_id']}": candidate for candidate in candidates
    }
    legacy_generated = set()
    for surface in coverage["surfaces"]:
        if not isinstance(surface, dict):
            continue
        surface_id = surface.get("id")
        candidate = (
            candidates_by_surface_id.get(surface_id) if isinstance(surface_id, str) else None
        )
        if (
            candidate is not None
            and surface.get("candidateId") is None
            and surface.get("candidate") is None
            and surface.get("sourceWorkerId") is None
            and (
                (
                    surface.get("label") == candidate["summary"]
                    and surface.get("notes") == candidate["evidence"]
                )
                or any(
                    isinstance(row, dict)
                    and coverage_candidate_key(row) == (None, candidate["candidate_id"])
                    and row.get("surfaceIds") == [surface_id]
                    and row.get("reason")
                    == (
                        "Validation was deferred because the scan reached its cost limit: "
                        f"{surface.get('label')}. Evidence: {surface.get('notes')}"
                    )
                    for row in coverage["deferred"]
                )
            )
            and surface.get("disposition") in ("needs_follow_up", "rejected", "not_applicable")
        ):
            surface["candidateId"] = candidate["candidate_id"]
            legacy_generated.add(id(surface))

    def generated_surface(item: dict[str, Any]) -> bool:
        return id(item) in legacy_generated or _generated_budget_candidate_surface(item)

    terminal_decisions = {}
    coverage_schema = _read_json(
        Path(__file__).resolve().parent.parent / "schemas" / "coverage.schema.json"
    )["properties"]
    for field in ("surfaces", "explicitExclusions"):
        for item in coverage[field]:
            if (
                not isinstance(item, dict)
                or item.get("disposition") not in ("rejected", "not_applicable")
                or (field == "surfaces" and generated_surface(item))
            ):
                continue
            # Finalization still rejects malformed rows; they cannot close saved work first.
            if field == "explicitExclusions" and not valid_exclusion(
                item, coverage_schema[field]["items"]
            ):
                continue
            terminal_decisions[coverage_candidate_key(item)] = item["disposition"]
    # A retry can read the recovered draft after the invalid receipt was removed.
    # Keep that reopening tied to the ledger decision it invalidated; a new phase
    # or an independent saved terminal decision can still resolve the candidate.
    receipt_reopened = set(receipt_reopened or ())
    finding_keys = {finding_candidate_key(finding) for finding in findings}
    pending_decisions = set()
    candidates_by_key = {(None, candidate["candidate_id"]): candidate for candidate in candidates}
    for item in coverage["deferred"]:
        if not isinstance(item, dict):
            continue
        key = coverage_candidate_key(item)
        candidate = candidates_by_key.get(key)
        if candidate is None:
            continue
        phase = _diff_candidate_phase_snapshot(candidate)
        previous = item.get("candidate")
        # A saved proof gap authored against this phase is newer than its ledger decision.
        if (
            key not in finding_keys
            and isinstance(previous, dict)
            and _diff_candidate_phase_snapshot(previous) == phase
        ):
            pending_decisions.add(key)
        if key in receipt_reopened and diff_candidate_disposition(candidate) in (
            "rejected",
            "not_applicable",
        ):
            item["receiptReopenedDecision"] = copy.deepcopy(phase)
        elif item.get("receiptReopenedDecision") == phase:
            receipt_reopened.add(key)

    dispositions = {
        (None, candidate["candidate_id"]): (
            "reported"
            if (None, candidate["candidate_id"]) in findings_by_candidate
            else terminal_decisions.get((None, candidate["candidate_id"]))
            or (
                diff_candidate_disposition(candidate)
                if (None, candidate["candidate_id"]) not in receipt_reopened | pending_decisions
                else None
            )
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

    closures = coverage.get("resolvedDeferred")
    if isinstance(closures, list):
        used_ids["deferred"].update(
            row["id"]
            for row in closures
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        )

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
        generated_surfaces = [
            surface for surface in surfaces_by_candidate.get(key, []) if generated_surface(surface)
        ]
        legacy_deferred = {
            id(item)
            for surface in generated_surfaces
            if id(surface) in legacy_generated
            for item in deferred
            if item.get("candidate") is None
            and item.get("surfaceIds") == [surface.get("id")]
            and item.get("reason")
            == (
                "Validation was deferred because the scan reached its cost limit: "
                f"{surface.get('label')}. Evidence: {surface.get('notes')}"
            )
            and isinstance(item.get("paths"), list)
        }
        previous_candidates = [
            surface["candidate"]
            for surface in generated_surfaces
            if isinstance(surface.get("candidate"), dict)
        ]
        generated_surface_ids = [
            surface["id"] for surface in generated_surfaces if isinstance(surface.get("id"), str)
        ]
        for surface in generated_surfaces:
            previous = copy.deepcopy(surface.get("candidate"))
            surface.update(
                label=candidate["summary"],
                disposition=disposition,
                notes=candidate["evidence"],
                candidate={
                    **{
                        k: v
                        for k, v in (surface.get("candidate") or {}).items()
                        if k not in {"validation", "attack_path"}
                    },
                    **candidate,
                },
            )
            if isinstance(previous, dict):
                archive_candidate_payloads(surface, [{"candidate": previous}])
        if disposition == "needs_follow_up" and deferred:
            for item in deferred:
                previous = item.get("candidate")
                if isinstance(previous, dict) and previous in previous_candidates:
                    saved_ids = item.get("surfaceIds")
                    if not (
                        isinstance(saved_ids, list)
                        and saved_ids
                        and all(surface_id in generated_surface_ids for surface_id in saved_ids)
                    ):
                        continue
                    generated = _budget_candidate_deferred(previous, saved_ids)
                    if all(item.get(field) == value for field, value in generated.items()):
                        refreshed = {
                            **{
                                field: value
                                for field, value in previous.items()
                                if field not in {"validation", "attack_path"}
                            },
                            **candidate,
                        }
                        item.update(_budget_candidate_deferred(refreshed, saved_ids))
                elif id(item) in legacy_deferred:
                    refreshed = _budget_candidate_deferred(candidate, item["surfaceIds"])
                    # Legacy rows have no prior snapshot to distinguish authored paths.
                    refreshed["paths"] = list(dict.fromkeys([*item["paths"], *refreshed["paths"]]))
                    item.update(refreshed)
                else:
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
        for surface in surfaces:
            if disposition == "reported" or surface.get("disposition") not in (
                "rejected",
                "not_applicable",
            ):
                surface["disposition"] = disposition
            had_candidate = "candidate" in surface
            previous = surface.get("candidate")
            surface["candidate"] = {**retained_candidate, **candidate}
            if had_candidate:
                archive_candidate_payloads(surface, [{"candidate": previous}])
            archive_candidate_payloads(surface, deferred)
        if disposition != "needs_follow_up":
            continue
        coverage["deferred"].append(
            {
                "id": available_id(candidate_id, "deferred"),
                "candidateId": candidate_id,
                **_budget_candidate_deferred(candidate, [surface["id"] for surface in surfaces]),
            }
        )

    return {
        key
        for key, disposition in dispositions.items()
        if disposition in ("rejected", "not_applicable")
    }


def _diff_candidate_phase_snapshot(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        phase: candidate[phase] for phase in ("validation", "attack_path") if phase in candidate
    }


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


def _diff_candidate_decision(
    candidate: dict[str, Any], *, legacy_reason: bool = False
) -> dict[str, Any] | None:
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
                    if (legacy_reason or disposition == "rejected")
                    and attack_path.get("decision") == "ignore"
                    else []
                ),
                validation.get("counterevidence_or_proof_gap"),
                f"Candidate review concluded: {summary}",
            )
            if isinstance(value, str) and value.strip()
        ),
        "candidate": candidate,
    }


def finding_content(finding: dict[str, Any]) -> dict[str, Any]:
    """Return substantive finding content without generated identity or provenance."""
    return {
        key: value
        for key, value in finding.items()
        if key not in {"findingId", "occurrenceId", "fingerprints", "identity", "provenance"}
    }


def copied_report_has_later_pending(
    relative: str,
    owner: str,
    candidate_id: str,
    sources: list[tuple[str, dict[str, Any], str | None]],
    source_order: dict[str, tuple[int, int]],
    valid_finding: Callable[[Any], bool],
) -> bool:
    """Keep explicit pending input when a worker copies its older report forward."""

    def coverage_rows(draft: dict[str, Any], field: str) -> list[Any]:
        rows = draft["coverage"].get(field)
        return rows if isinstance(rows, list) else []

    key = (owner, candidate_id)
    attempt = source_order[relative][0]
    drafts = {
        path: draft
        for path, draft, worker in sources
        if worker == owner and source_order[path][0] == attempt
    }
    reports = [
        finding
        for finding in drafts[relative]["findings"]
        if valid_finding(finding) and finding_candidate_key(finding, owner) == key
    ]
    if not reports:
        return False
    pending_orders = [
        source_order[path]
        for path, draft in drafts.items()
        if any(
            isinstance(row, dict) and coverage_candidate_key(row, owner) == key
            for row in coverage_rows(draft, "deferred")
        )
        and not any(
            valid_finding(finding)
            and finding_candidate_key(finding, owner) == key
            and finding["provenance"].get("candidateReopened") is not True
            for finding in draft["findings"]
        )
        and not any(
            isinstance(row, dict)
            and coverage_candidate_key(row, owner) == key
            and row.get("disposition") in {"rejected", "not_applicable"}
            for field in ("surfaces", "explicitExclusions")
            for row in coverage_rows(draft, field)
        )
    ]
    return bool(pending_orders) and all(
        any(
            source_order[path] < pending_order
            for path, draft in drafts.items()
            if finding in draft["findings"]
            for pending_order in pending_orders
        )
        for finding in reports
    )


def current_report(
    finding: dict[str, Any], draft: dict[str, Any], owner: str | None, selected: bool
) -> bool:
    """A selected terminal worker input can accept a previously reopened report."""
    if finding["provenance"].get("candidateReopened") is not True:
        return True
    if not selected or owner is None or draft.get("complete") is False:
        return False
    key = finding_candidate_key(finding, owner)
    deferred = draft["coverage"].get("deferred")
    return not any(
        isinstance(row, dict) and coverage_candidate_key(row, owner) == key
        for row in (deferred if isinstance(deferred, list) else [])
    )


def reuse_candidate_task_ids(sources: list[tuple[str, dict[str, Any], str | None]]) -> None:
    """Reuse a unique saved ID for identical candidate evidence with an omitted task ID."""
    entries = [
        (draft["coverage"]["deferred"], owner)
        for _, draft, owner in sources
        if isinstance(draft["coverage"].get("deferred"), list)
    ]
    named: dict[Any, set[str]] = {}
    for rows, owner in entries:
        for row in rows:
            if (
                isinstance(row, dict)
                and isinstance(row.get("id"), str)
                and row["id"].strip()
                and (key := coverage_candidate_key(row, owner)) is not None
            ):
                content = json.dumps(
                    {field: value for field, value in row.items() if field != "id"}, sort_keys=True
                )
                named.setdefault((key, content), set()).add(row["id"])
    for rows, owner in entries:
        for index, row in enumerate(rows):
            if (
                isinstance(row, dict)
                and "id" not in row
                and (key := coverage_candidate_key(row, owner)) is not None
            ):
                identities = named.get((key, json.dumps(row, sort_keys=True)), set())
                if len(identities) == 1:
                    rows[index] = {**row, "id": next(iter(identities))}


def deferred_identity_collisions(
    sources: list[tuple[str, dict[str, Any], str | None]],
    deferred_rows: dict[str, list[Any]],
) -> tuple[set[tuple[str | None, str]], set[tuple[str | None, str]]]:
    """Keep generic task IDs distinct from candidate identities and ambiguous task IDs."""
    ambiguous: set[tuple[str | None, str]] = set()
    unclosable: set[tuple[str | None, str]] = set()
    for relative, draft, owner in sources:
        rows = deferred_rows[relative]
        candidates = [row for row in rows if isinstance(row, dict) and is_candidate_row(row)]
        aliases = {
            identity
            for row in candidates
            for identity in (row.get("id"), row.get("candidateId"))
            if isinstance(identity, str)
        }
        for row in candidates:
            if isinstance(identity := row.get("id") or row.get("candidateId"), str):
                unclosable.add((_deferred_owner(row, owner), identity))
        aliases.update(
            key[1]
            for finding in draft["findings"]
            if isinstance(finding, dict)
            and (key := finding_candidate_key(finding, owner)) is not None
            and key[0] == owner
        )
        for field in ("surfaces", "explicitExclusions"):
            items = draft["coverage"].get(field, [])
            aliases.update(
                key[1]
                for row in (items if isinstance(items, list) else [])
                if isinstance(row, dict)
                and (key := coverage_candidate_key(row, owner)) is not None
                and key[0] == owner
            )
        by_id: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(identity := row.get("id"), str):
                continue
            if is_candidate_row(row):
                continue
            key = (owner, identity)
            if identity in aliases:
                ambiguous.add(key)
            if identity in by_id and row != by_id[identity]:
                ambiguous.add(key)
                unclosable.add(key)
            by_id[identity] = row
    return ambiguous, unclosable


def _generated_diff_candidate_decision(item: dict[str, Any]) -> bool:
    candidate = item.get("candidate")
    if not isinstance(candidate, dict) or item.get("candidateId") != candidate.get("candidate_id"):
        return False
    try:
        decision = _diff_candidate_decision(candidate)
    except (KeyError, ValueError):
        return False
    return (
        decision is not None
        and all(item.get(field) == decision[field] for field in ("label", "disposition"))
        and item.get("notes")
        in (decision["notes"], _diff_candidate_decision(candidate, legacy_reason=True)["notes"])
    )
