"""Shared identity and resolution rules for saved scan candidates."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from typing import Any

CandidateKey = tuple[str | None, str]


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


def candidate_owner(*values: Any) -> str | None:
    return next((value for value in values if isinstance(value, str) and value.strip()), None)


def coverage_owner(item: dict[str, Any]) -> Any:
    """Read the accepted worker projection, or the owner in a legacy saved row."""
    provenance = item.get("provenance")
    if isinstance(provenance, dict) and candidate_owner(provenance.get("workerId")):
        return provenance["workerId"]
    owner = item.get("sourceWorkerId")
    if owner is not None and not isinstance(owner, str):
        return owner
    return candidate_owner(owner, item.get("workerId"))


def candidate_key(candidate_id: Any, owner: Any = None) -> CandidateKey | None:
    if not isinstance(candidate_id, str) or not candidate_id.strip():
        return None
    return candidate_owner(owner), candidate_id


def _has_identity_text(value: Any) -> bool:
    # Match JavaScript String.trim when selecting optional identity metadata.
    return isinstance(value, str) and bool(
        value.strip(
            "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680"
            "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
            "\u2028\u2029\u202f\u205f\u3000\ufeff"
        )
    )


def finding_candidate_id(finding: dict[str, Any]) -> str | None:
    provenance = finding.get("provenance")
    if isinstance(provenance, dict) and _has_identity_text(value := provenance.get("candidateId")):
        return value
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return None
    return next(
        (
            value
            for field in ("candidateId", "reportId", "ledgerRowId")
            if _has_identity_text(value := extensions.get(field))
        ),
        None,
    )


def finding_candidate_key(finding: dict[str, Any], owner: str | None = None) -> CandidateKey | None:
    provenance = finding.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    extensions = finding.get("extensions")
    extensions = extensions if isinstance(extensions, dict) else {}
    # A worker result's actual owner overrides imported finding metadata.
    owner = candidate_owner(
        owner,
        provenance.get("sourceWorkerId"),
        provenance.get("workerId"),
        extensions.get("sourceWorkerId"),
    )
    return candidate_key(finding_candidate_id(finding), owner)


def coverage_candidate_key(item: dict[str, Any], owner: str | None = None) -> CandidateKey | None:
    source_owner = candidate_owner(owner) or coverage_owner(item)
    # A malformed coverage owner cannot resolve valid candidates before draft recovery.
    if source_owner is not None and not isinstance(source_owner, str):
        return None
    candidate_id = item.get("candidateId")
    provenance = item.get("provenance")
    if (
        owner is None
        and isinstance(candidate_id, str)
        and isinstance(provenance, dict)
        and candidate_owner(provenance.get("workerId"))
        and provenance.get("candidateId") is not None
    ):
        candidate_id = provenance["candidateId"]
    return candidate_key(candidate_id, source_owner)


def is_candidate_row(row: dict[str, Any]) -> bool:
    """Distinguish candidate identity/evidence from generic extension metadata."""
    return isinstance(row.get("candidateId"), str) or "candidate" in row or "finding" in row


def _deferred_owner(row: dict[str, Any], owner: str | None) -> str | None:
    return candidate_owner(owner, coverage_owner(row)) if is_candidate_row(row) else owner


def _deferred_candidate_id(row: dict[str, Any]) -> str | None:
    if not is_candidate_row(row):
        return None
    identity = row.get("candidateId")
    if not isinstance(identity, str) or not identity:
        identity = row.get("id")
    return identity if isinstance(identity, str) else None


def surface_reference_key(
    surface_id: Any, source: dict[str, Any], surfaces: list[dict[str, Any]]
) -> CandidateKey | None:
    """Prefer the matching owner for duplicate IDs; unique references may be shared."""
    matches = [surface for surface in surfaces if surface.get("id") == surface_id]
    target = next(
        (
            surface
            for surface in matches
            if candidate_owner(coverage_owner(surface)) == candidate_owner(coverage_owner(source))
        ),
        matches[0] if len(matches) == 1 else source,
    )
    return candidate_key(surface_id, coverage_owner(target))


def reducer_coverage(coverage: dict[str, Any], candidates: list[Any]) -> dict[str, Any]:
    result = copy.deepcopy(coverage)
    deferred = result.get("deferred")
    result["deferred"] = (deferred if isinstance(deferred, list) else []) + copy.deepcopy(
        candidates
    )
    result.pop("completeness", None)
    return result


def _saved_row_key(value: Any) -> Any:
    # Preserve JSON object and numeric equality without conflating booleans.
    if isinstance(value, bool):
        return (bool, value)
    if isinstance(value, dict):
        return frozenset((key, _saved_row_key(child)) for key, child in value.items())
    if isinstance(value, list):
        return tuple(_saved_row_key(child) for child in value)
    return value


def unresolved_candidates(
    coverage: dict[str, Any], findings: list[dict[str, Any]] | None = None, *, sealed: bool = False
) -> list[dict[str, Any]]:
    """Select saved candidate identities without a finding or terminal disposition."""
    candidates: dict[CandidateKey, dict[str, Any]] = {}
    for item in unresolved_candidate_rows(coverage, findings, sealed=sealed):
        candidates.setdefault(coverage_candidate_key(item), item)
    return list(candidates.values())


def unresolved_candidate_rows(
    coverage: dict[str, Any], findings: list[dict[str, Any]] | None = None, *, sealed: bool = False
) -> list[dict[str, Any]]:
    """Keep each distinct saved proof gap while applying candidate resolutions."""

    def objects(value: Any) -> list[dict[str, Any]]:
        # Progress also reads incomplete, unsealed drafts before finalizer recovery.
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    resolved = {
        key
        for finding in objects(findings)
        if not (
            isinstance(provenance := finding.get("provenance"), dict)
            and provenance.get("candidateReopened") is True
        )
        and (key := finding_candidate_key(finding)) is not None
    }
    # Legacy sealed exclusions were opaque metadata; active drafts retain their decisions.
    for field in (
        ("surfaces",)
        if sealed and coverage.get("receiptSealVersion") != 1
        else ("surfaces", "explicitExclusions")
    ):
        resolved.update(
            key
            for item in objects(coverage.get(field))
            if item.get("disposition") in ("rejected", "not_applicable")
            and (key := coverage_candidate_key(item)) is not None
        )
    candidates = []
    seen = set()
    for item in objects(coverage.get("deferred")):
        key = coverage_candidate_key(item)
        if key is not None and key not in resolved:
            row_key = _saved_row_key(item)
            if row_key not in seen:
                seen.add(row_key)
                candidates.append(item)
    return candidates


def diff_candidate_disposition(candidate: dict[str, Any]) -> str | None:
    """Return the terminal coverage disposition, with deferred phases taking precedence."""
    validation = candidate.get("validation")
    disposition = validation.get("disposition") if isinstance(validation, dict) else None
    attack_path = candidate.get("attack_path")
    decision = attack_path.get("decision") if isinstance(attack_path, dict) else None
    if disposition == "deferred" or decision == "deferred":
        return None
    if disposition == "not_applicable":
        return "not_applicable"
    if disposition == "suppressed" or decision == "ignore":
        return "rejected"
    return None


def resolved_candidate_surface_keys(
    sources: list[tuple[str, dict[str, Any], str | None]], candidates: set[CandidateKey]
) -> set[CandidateKey | None]:
    """Resolve each dismissed candidate's references in its saved surface context."""
    return {
        surface_reference_key(
            surface_id,
            item,
            [
                surface
                for surfaces in [draft["coverage"].get("surfaces")]
                if isinstance(surfaces, list)
                for surface in surfaces
                if isinstance(surface, dict)
            ],
        )
        for _, draft, worker_id in sources
        for items in [draft["coverage"].get("deferred", [])]
        if isinstance(items, list)
        for item in items
        if isinstance(item, dict) and coverage_candidate_key(item, worker_id) in candidates
        for surface_ids in [item.get("surfaceIds", [])]
        if isinstance(surface_ids, list)
        for surface_id in surface_ids
        if isinstance(surface_id, str)
    }


def retain_recovered_candidate_gaps(
    coverage: dict[str, Any], recovered_candidates: list[tuple[dict[str, Any], str]]
) -> None:
    deferred_ids = {item["id"] for item in coverage["deferred"]}
    closures = coverage.get("resolvedDeferred")
    if isinstance(closures, list):
        deferred_ids.update(
            item["id"]
            for item in closures
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        )
    for surface, reason in recovered_candidates:
        key = coverage_candidate_key(surface)
        if key is not None and any(
            coverage_candidate_key(item) == key for item in coverage["deferred"]
        ):
            continue
        identity = surface["id"]
        suffix = 2
        while identity in deferred_ids:
            identity = f"{surface['id']}-{suffix}"
            suffix += 1
        deferred_ids.add(identity)
        coverage["deferred"].append(
            {
                "id": identity,
                "candidateId": surface["candidateId"],
                "reason": reason,
                "surfaceIds": [surface["id"]],
                **{
                    field: copy.deepcopy(surface[field])
                    for field in (
                        "sourceWorkerId",
                        "workerId",
                        "provenance",
                        "candidate",
                        "finding",
                    )
                    if field in surface
                    and (
                        field in ("sourceWorkerId", "workerId") or isinstance(surface[field], dict)
                    )
                },
            }
        )


def candidate_receipt_sections(
    coverage: dict[str, Any],
    sections: tuple[str, ...],
    owner: str | None,
) -> list[str]:
    return [
        field
        for field in sections
        if any(
            isinstance(row, dict)
            and (
                (field == "explicitExclusions" and coverage_candidate_key(row, owner) is not None)
                or row.get("disposition") in ("rejected", "not_applicable")
            )
            and (
                (
                    field == "surfaces"
                    and (not isinstance(row.get("label"), str) or not row["label"].strip())
                )
                or row.get("receiptRefs")
                or ("receiptRefs" in row and not isinstance(row["receiptRefs"], list))
            )
            for rows in [coverage.get(field)]
            for row in (rows if isinstance(rows, list) else [])
        )
    ]


def recover_candidate_receipt_rows(
    coverage: dict[str, Any],
    fields: list[str],
    closures: list[dict[str, Any]],
    warnings: list[str],
    reopened: set[CandidateKey],
    *,
    owner: str | None,
    worker: bool,
    validate_receipt: Callable[[Any, str], str],
    receipt_refs: Callable[[dict[str, Any]], Any],
) -> None:
    """Reopen failed candidate decisions while retaining each submitted proof gap."""
    if not isinstance(coverage.get("deferred"), list):
        coverage["deferred"] = []
    for field, index, row in (
        (section, index, row)
        for section in fields
        if worker or section == "explicitExclusions"
        for index, row in enumerate(coverage[section])
    ):
        if (
            not isinstance(row, dict)
            or (
                field == "surfaces" and row.get("disposition") not in ("rejected", "not_applicable")
            )
            or (field == "explicitExclusions" and coverage_candidate_key(row, owner) is None)
        ):
            continue
        refs = receipt_refs(row)
        invalid = field == "surfaces" and (
            not isinstance(row.get("label"), str) or not row["label"].strip()
        )
        recovered = []
        warning_start = len(warnings)
        if invalid:
            warnings.append(
                f"Skipped malformed coverage surface {index + 1}: expected a nonempty label."
            )
        if not isinstance(refs, list):
            warnings.append(
                f"Skipped malformed receipt references for coverage surface {index + 1}: expected an array."
            )
            invalid = True
        for position, ref in enumerate(refs if isinstance(refs, list) else []):
            context = f"coverage.{field}[{index}].receiptRefs[{position}]"
            try:
                ref = validate_receipt(ref, context)
            except ValueError as exc:
                warnings.append(
                    f"Skipped malformed coverage receipt {index + 1}.{position + 1}: {exc}."
                )
                invalid = True
                continue
            # Publication validates and seals receipts relative to the parent scan.
            recovered.append(ref)
        row["receiptRefs"] = recovered
        if invalid:
            row["disposition"] = "needs_follow_up"
            if (key := coverage_candidate_key(row, owner)) is not None:
                reopened.add(key)
                pending = next(
                    (
                        item
                        for item in coverage["deferred"]
                        if isinstance(item, dict) and coverage_candidate_key(item, owner) == key
                    ),
                    None,
                )
                if pending is None:
                    identity = row.get("id")
                    if not isinstance(identity, str) or not identity.strip():
                        identity = None
                    pending = {
                        "candidateId": row["candidateId"],
                        "reason": "\n".join(warnings[warning_start:]),
                        **(
                            {"surfaceIds": [identity]}
                            if field == "surfaces" and identity is not None
                            else {}
                        ),
                        **{
                            field: copy.deepcopy(row[field])
                            for field in (
                                "sourceWorkerId",
                                "workerId",
                                "provenance",
                                "candidate",
                                "finding",
                            )
                            if field in row
                        },
                    }
                    if not worker:
                        used_ids = {
                            item.get("id")
                            for item in [*coverage["deferred"], *closures]
                            if isinstance(item, dict) and isinstance(item.get("id"), str)
                        }
                        base = identity or row["candidateId"]
                        identity, suffix = base, 2
                        while identity in used_ids:
                            identity, suffix = f"{base}-{suffix}", suffix + 1
                        pending["id"] = identity
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
