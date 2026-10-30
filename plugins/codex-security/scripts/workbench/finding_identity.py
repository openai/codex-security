"""Allocate semantic finding identities from saved draft and publication observations."""

from __future__ import annotations

import copy
import re
import unicodedata
from collections import Counter
from collections.abc import Iterator
from typing import Any

from finalize_scan_contract import _finding_strength, _has_identity_text, finding_candidate_id
from workbench.retained_records import _ensure_finding_identity, _finding_identity, raw_scope
from workbench.saved_sources import _digest, _encoded


def _finding_content(finding: dict[str, Any]) -> dict[str, Any]:
    """Return substantive finding content without generated identity or provenance."""
    return {
        key: value
        for key, value in finding.items()
        if key not in {"findingId", "occurrenceId", "fingerprints", "identity", "provenance"}
    }


def _legacy_identity_key(finding: dict[str, Any], owner: str | None) -> str:
    content = _finding_content(finding)
    locations = content.get("locations")
    if isinstance(locations, list):
        content["locations"] = sorted(
            [
                {**row, "endLine": row.get("endLine", row.get("startLine"))}
                if isinstance(row, dict)
                else row
                for row in locations
            ],
            key=_encoded,
        )
    return _digest([owner, _identity_candidate(finding), content])


def _historical_content(finding: dict[str, Any]) -> str:
    # Candidate identity can be serialized in either extensions or provenance.
    content = _finding_content(finding)
    extensions = content.get("extensions")
    if isinstance(extensions, dict) and "candidateId" in extensions:
        content["extensions"] = {
            key: value for key, value in extensions.items() if key != "candidateId"
        }
        if not content["extensions"]:
            del content["extensions"]
    return _digest(content)


def _retained_findings(finding: dict[str, Any]) -> Iterator[dict[str, Any]]:
    return (row for row, _ in _retained_source_findings(finding, ()))


def _retained_source_findings(finding, workers):
    """Yield saved observations with the registered worker from their source reference."""
    pending = [(finding, None)]
    seen: set[int] = set()
    while pending:
        current, owner = pending.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        yield current, owner
        provenance = current.get("provenance")
        if not isinstance(provenance, dict):
            continue
        previous = provenance.get("previousFindings")
        if isinstance(previous, list):
            pending.extend((item, owner) for item in reversed(previous) if isinstance(item, dict))
        sources = provenance.get("sourceFindings")
        if isinstance(sources, list):
            for source in reversed(sources):
                if isinstance(source, dict) and isinstance(source.get("finding"), dict):
                    reference = source.get("id")
                    worker = reference.rpartition(":")[0] if isinstance(reference, str) else None
                    pending.append((source["finding"], worker if worker in workers else owner))


def _finding_locations(
    finding: dict[str, Any], *, include_role: bool = False
) -> list[tuple[Any, ...]]:
    locations = finding.get("locations", [])
    return sorted(
        (
            (
                location.get("path"),
                location.get("startLine"),
                location.get("endLine", location.get("startLine")),
                *((location.get("role"),) if include_role else ()),
            )
            for location in (locations if isinstance(locations, list) else [])
            if isinstance(location, dict)
        ),
        key=_encoded,
    )


def _identity_candidate(finding: dict[str, Any]) -> str | None:
    return next(
        (
            value
            for section in (finding.get("extensions"), finding.get("provenance"))
            if isinstance(section, dict) and _has_identity_text(value := section.get("candidateId"))
        ),
        None,
    )


def _semantic_identifier(value: str, fallback: str) -> str:
    normalized = re.sub(r"[\u0300-\u036f]", "", unicodedata.normalize("NFKD", value))
    identifier = re.sub(r"[^a-z0-9._/-]+", "-", normalized.lower())
    return re.sub(r"^[^a-z0-9]+|-+$", "", identifier) or fallback


def _semantic_identity_key(finding: dict[str, Any], identity: Any = None) -> bytes:
    identity = finding.get("identity") if identity is None else identity
    if isinstance(identity, dict):
        identity = {key: identity.get(key) for key in ("anchor", "instance")}
    return _encoded([finding.get("ruleId"), identity])


def _report_ids(value: dict[str, Any]) -> tuple[Any, Any]:
    extensions = value.get("extensions")
    return tuple(
        identifier if _has_identity_text(identifier) else None
        for identifier in (
            extensions.get(field) if isinstance(extensions, dict) else None
            for field in ("reportId", "ledgerRowId")
        )
    )


def _distinct_report_rows(first: dict[str, Any], second: dict[str, Any]) -> bool:
    return (
        isinstance(first.get("identity"), dict)
        and isinstance(second.get("identity"), dict)
        and _semantic_identity_key(first) != _semantic_identity_key(second)
    ) or any(
        a is not None and b is not None and a != b
        for a, b in zip(_report_ids(first), _report_ids(second), strict=True)
    )


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


def bind_saved_candidate_identities(
    findings: list[dict[str, Any]], observations: dict[int, tuple[str, dict[str, Any], str | None]]
) -> dict[int, str]:
    """Bind same-batch identities and return worker scopes for collision detection."""
    bound_owners: dict[int, str] = {}

    def observation_content(raw: dict[str, Any]) -> dict[str, Any]:
        title = _semantic_identifier(raw["title"], "finding")
        identity = raw.get("identity", {})
        return {
            **{
                key: value
                for key, value in _finding_content(raw).items()
                if key not in ("severity", "confidence")
            },
            "locations": _finding_locations(raw, include_role=True),
            "identity": [
                None if identity.get(key) == title else identity.get(key)
                for key in ("anchor", "instance")
            ],
        }

    def same_observation_content(left: dict[str, Any], right: dict[str, Any]) -> bool:
        return same_raw_value(observation_content(left), observation_content(right))

    exact = {}
    for source, raw, owner in observations.values():
        if isinstance(raw.get("identity"), dict):
            owner = owner or raw["provenance"].get("workerId")
            key = _encoded((source, owner, _identity_candidate(raw), _finding_content(raw)))
            exact.setdefault(key, set()).add(raw["identity"]["anchor"])

    scopes = {}
    for index, (source, raw, owner) in observations.items():
        extensions = raw.get("extensions", {})
        qualified = any(
            _has_identity_text(extensions.get(key))
            for key in ("reportId", "ledgerRowId", "candidateId")
        )
        candidate = _identity_candidate(raw)
        owner = owner or raw["provenance"].get("workerId")
        title_anchor = _semantic_identifier(raw["title"], "finding")
        anchor = raw.get("identity", {}).get("anchor")
        if anchor is None:
            key = _encoded((source, owner, candidate, _finding_content(raw)))
            authored = exact.get(key, set())
            anchor = next(iter(authored)) if len(authored) == 1 else title_anchor
        if candidate and anchor == _semantic_identifier(candidate, "finding"):
            anchor = title_anchor
        scope = source, raw["ruleId"], raw["title"], anchor, tuple(_finding_locations(raw))
        key = (owner if isinstance(owner, str) and owner else None, finding_candidate_id(raw))
        rows = scopes.setdefault(scope, {}).setdefault(key, [])
        if not qualified:
            rows.append((index, raw))

    for groups in scopes.values():
        for owner, candidate in list(groups):
            if owner is not None and candidate is not None:
                continue
            matches = [
                key
                for key in groups
                if key != (owner, candidate)
                and key[1] is not None
                and (owner is None or owner == key[0])
                and (candidate is None or candidate == key[1])
            ]
            if len(matches) != 1:
                continue
            rows = groups[(owner, candidate)]
            other = groups[matches[0]]
            if not rows or not other:
                continue
            if candidate is None and not any(
                all(same_observation_content(raw, known) for _, raw in rows) for _, known in other
            ):
                continue
            strengths = {_finding_strength(value) for _, value in (*rows, *other)}
            if len(strengths) > 1 or (
                candidate is None and any("identity" in value for _, value in rows)
            ):
                other.extend(groups.pop((owner, candidate)))
        for (owner, candidate), rows in groups.items():
            if len(rows) < 2:
                continue
            explicit = [(index, value) for index, value in rows if "identity" in value]
            if len({_semantic_identity_key(row) for _, row in explicit}) > 1:
                rows = [(index, value) for index, value in rows if "identity" not in value]
                if not candidate or len(rows) < 2:
                    continue
                explicit = []
                if any(not same_observation_content(raw, rows[0][1]) for _, raw in rows[1:]):
                    continue
            if not candidate and any(
                not same_observation_content(raw, rows[0][1]) for _, raw in rows[1:]
            ):
                continue
            known = [(index, raw) for index, raw in rows if _identity_candidate(raw) == candidate]
            first, _ = min(explicit or known or rows, key=lambda item: item[0])
            identity = findings[first]["identity"]
            for index, _ in rows:
                finding = findings[index]
                for field in ("anchor", "instance"):
                    if field in identity:
                        finding["identity"][field] = identity[field]
                    else:
                        finding["identity"].pop(field, None)
                provenance = finding["provenance"]
                if candidate is not None and _identity_candidate(finding) is None:
                    provenance["candidateId"] = candidate
                if owner is not None:
                    bound_owners[index] = owner
    return bound_owners


def _finding_key(
    finding: dict[str, Any], owner: str | None = None, *, include_candidate: bool = True
) -> str:
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
    parts = [
        finding.get("ruleId"),
        identity.get("anchor"),
        identity.get("instance"),
        _finding_locations(finding),
    ]
    if include_candidate and (candidate := _identity_candidate(finding)):
        parts.extend((candidate, owner))
    elif owner is not None and finding_candidate_id(finding):
        parts.append(owner)
    return _digest(parts)


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


def same_raw_finding(
    left: dict[str, Any], right: dict[str, Any], *, allow_relabel: bool = False
) -> bool:
    candidates = (_identity_candidate(left), _identity_candidate(right))
    if all(candidates) and candidates[0] != candidates[1]:
        # A later revision of one authored finding can replace its candidate label.
        return (
            allow_relabel
            and "identity" in left
            and "identity" in right
            and _semantic_identity_key(left) == _semantic_identity_key(right)
            and raw_scope(left) == raw_scope(right)
            and _report_ids(left) == _report_ids(right)
        )
    if isinstance(left.get("identity"), dict) and isinstance(right.get("identity"), dict):
        if all("preservedIdentity" in row["provenance"] for row in (left, right)):
            same_identity = _semantic_identity_key(left) == _semantic_identity_key(right)
        else:
            same_identity = _semantic_identity_key(
                left, _finding_identity(left)
            ) == _semantic_identity_key(right, _finding_identity(right))
        # At a different site the same anchor can describe a separate report.
        if not same_identity or raw_scope(left) == raw_scope(right):
            return same_identity
    pairs = list(zip(_report_ids(left), _report_ids(right), strict=True))
    if any(a is not None for a, _ in pairs) and any(b is not None for _, b in pairs):
        if not any(a is not None and b is not None for a, b in pairs) or any(
            a is not None and b is not None and a != b for a, b in pairs
        ):
            return False
    return True


def _same_published_finding(left: dict[str, Any], right: dict[str, Any], *, valid_finding) -> bool:
    if not valid_finding(left) or not valid_finding(right):
        return False
    return (
        same_raw_value(_finding_content(left), _finding_content(right))
        and (
            "identity" not in left
            or same_raw_value(_finding_identity(left), _finding_identity(right))
        )
        and same_raw_value(
            {
                key: value
                for key, value in left.get("provenance", {}).items()
                if key not in ("previousFindings", "preservedIdentity")
            },
            {
                key: value
                for key, value in right.get("provenance", {}).items()
                if key not in ("previousFindings", "preservedIdentity")
            },
        )
    )
