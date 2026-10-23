"""Finding identity and history helpers for saved scan recovery."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from finalize_scan_contract import finding_candidate_id


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
