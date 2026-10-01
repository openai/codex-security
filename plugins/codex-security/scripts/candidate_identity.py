"""Shared identity and resolution rules for saved scan candidates."""

from __future__ import annotations

from typing import Any

CandidateKey = tuple[str | None, str]


def candidate_owner(*values: Any) -> str | None:
    return next((value for value in values if isinstance(value, str) and value.strip()), None)


def candidate_key(candidate_id: Any, owner: Any = None) -> CandidateKey | None:
    if not isinstance(candidate_id, str) or not candidate_id.strip():
        return None
    return candidate_owner(owner), candidate_id


def finding_candidate_id(finding: dict[str, Any]) -> str | None:
    provenance = finding.get("provenance")
    if (
        isinstance(provenance, dict)
        and isinstance(value := provenance.get("candidateId"), str)
        and value.strip()
    ):
        return value
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return None
    return next(
        (
            value
            for field in ("candidateId", "reportId", "ledgerRowId")
            if isinstance(value := extensions.get(field), str) and value.strip()
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
    source_owner = candidate_owner(owner) or item.get("sourceWorkerId")
    # A malformed coverage owner cannot resolve valid candidates before draft recovery.
    if source_owner is not None and not isinstance(source_owner, str):
        return None
    return candidate_key(item.get("candidateId"), source_owner)


def surface_reference_key(
    surface_id: Any, source: dict[str, Any], surfaces: list[dict[str, Any]]
) -> CandidateKey | None:
    """Prefer the matching owner for duplicate IDs; unique references may be shared."""
    matches = [surface for surface in surfaces if surface.get("id") == surface_id]
    target = next(
        (
            surface
            for surface in matches
            if candidate_owner(surface.get("sourceWorkerId"))
            == candidate_owner(source.get("sourceWorkerId"))
        ),
        matches[0] if len(matches) == 1 else source,
    )
    return candidate_key(surface_id, target.get("sourceWorkerId"))


def unresolved_candidates(
    coverage: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Select saved candidate identities without a finding or terminal disposition."""

    def objects(value: Any) -> list[dict[str, Any]]:
        # Progress also reads incomplete, unsealed drafts before finalizer recovery.
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    resolved = {
        key for finding in objects(findings) if (key := finding_candidate_key(finding)) is not None
    }
    for field in ("surfaces", "explicitExclusions"):
        resolved.update(
            key
            for item in objects(coverage.get(field))
            if item.get("disposition") in ("rejected", "not_applicable")
            and (key := coverage_candidate_key(item)) is not None
        )
    candidates: dict[CandidateKey, dict[str, Any]] = {}
    for item in objects(coverage.get("deferred")):
        key = coverage_candidate_key(item)
        if key is not None and key not in resolved:
            candidates.setdefault(key, item)
    return list(candidates.values())


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
