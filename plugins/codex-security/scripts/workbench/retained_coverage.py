"""Reconcile retained coverage observations during saved-result recovery."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from finalize_scan_contract import (
    ContractError,
    _read_json,
    _recover_unsealed_coverage,
    _recover_unsealed_findings,
    _require_safe_json_value,
    _validate_current_findings,
    _validate_schema_node,
    finding_candidate_id,
)
from workbench.saved_coverage import _saved_coverage_id
from workbench_coverage_receipts import resolve_coverage_receipts


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


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


def _inherit_coverage_sources(
    row: Any,
    originals: list[Any],
    sources: dict[int, tuple[dict[str, Any], list[str]]],
) -> None:
    if not isinstance(row, dict):
        return
    for original in originals:
        saved = sources.get(id(original))
        if saved is None:
            continue
        # Retain the object as well as its ID while copies are reconciled.
        paths = sources.setdefault(id(row), (row, []))[1]
        for relative in saved[1]:
            if relative not in paths:
                paths.append(relative)


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
        rows = draft["coverage"].get(field)
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
        rows = draft["coverage"].get(field)
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                row.setdefault("id", _saved_coverage_id(row))
                if field == "surfaces":
                    row.setdefault("receiptRefs", [])
    source_warnings = []
    discarded_fields = _recover_unsealed_coverage(
        draft["coverage"],
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
    for row in draft["coverage"]["deferred"]:
        row["workerId"] = worker_id
    warnings.extend(f"{relative}: {warning}" for warning in source_warnings)
    return discarded_coverage
