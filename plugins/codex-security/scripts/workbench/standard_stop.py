"""Freeze acknowledged local Standard work at the stop transition."""

from __future__ import annotations

import json
import re
from pathlib import Path

from finalize_scan_contract import (
    ContractError,
    _read_scan_local_json,
    finding_candidate_id,
    write_scan_local_bytes,
)
from standard_validation import DECISIONS, QUEUE, read_optional

RETURNS = "artifacts/02_discovery/standard-returns"
STANDARD_STOP_SNAPSHOT = f"{RETURNS}/stopped.json"


def capture_standard_stop(scan_dir: Path, scan_id: str, warnings: list[str]) -> None:
    # reviewed replaces the queue atomically after writing the receipt. Read the
    # index once while committing the terminal transition. Orphans and later
    # acknowledgements never become recovery inputs.
    queue = read_optional(scan_dir, QUEUE)
    if not queue:
        return
    rows = []
    try:
        decisions = read_optional(scan_dir, DECISIONS)
    except (ContractError, OSError, ValueError) as exc:
        warnings.append(f"Could not read Standard claim decisions at stop: {exc}")
        decisions = {}
    offset = 0
    for ref in queue.get("returns", []):
        if not isinstance(ref, dict) or type(ref.get("count")) is not int or ref["count"] < 0:
            warnings.append(
                "Standard return count is invalid; remaining candidate IDs are unknown."
            )
            break
        start = offset + 1
        offset += ref["count"]
        try:
            relative = ref.get("file")
            if not isinstance(relative, str) or not re.fullmatch(
                rf"{RETURNS}/[0-9a-f]{{64}}\.json", relative
            ):
                raise ContractError("Invalid Standard return path.")
            receipt = _read_scan_local_json(scan_dir, relative, "Standard worker return")
            candidates = receipt.get("findings")
            if not isinstance(candidates, list) or len(candidates) != ref["count"]:
                raise ContractError(
                    "Standard return disagrees with the acknowledged candidate count."
                )
            if not all(
                isinstance(receipt.get(k), list) for k in ("reviewed_files", "resolved_questions")
            ):
                raise ContractError("Invalid Standard worker return evidence.")
        except (ContractError, OSError, ValueError) as exc:
            warnings.append(
                f"Could not retain Standard return starting at candidate {start}: {exc}"
            )
            continue
        for number, candidate in enumerate(candidates, start):
            key = f"standard-{number}"
            title = (
                candidate.get("title") or candidate.get("rule")
                if isinstance(candidate, dict)
                else None
            )
            parts = decisions.get(key)
            if not isinstance(parts, list) or not parts:
                parts = [None]
            for i, decision in enumerate(parts, 1):
                claim = f"{key}.{i}" if isinstance(decision, dict) else key
                duplicate = (
                    decision.get("duplicateOf")
                    if isinstance(decision, dict) and decision.get("disposition") == "duplicate"
                    else None
                )
                rows.append(
                    {
                        "id": claim,
                        "candidateId": claim,
                        "reason": f"Standard worker return awaits checkpointed validation: {title or key}.",
                        "workerReturn": relative,
                        "workerCandidate": candidate,
                        "counterevidence": receipt.get("resolved_questions", []),
                        "paths": receipt.get("reviewed_files", []),
                        **({"duplicateOf": duplicate} if isinstance(duplicate, str) else {}),
                    }
                )
    reviewed = set(queue.get("reviewed", []))
    unread = [path for batch in queue.get("batches", []) for path in batch if path not in reviewed]
    if unread:
        rows.append(
            {
                "id": "standard-unreviewed-files",
                "reason": "The scan stopped before the assigned files were reviewed.",
                "paths": unread,
            }
        )
    if rows:
        snapshot = {"scanId": scan_id, "findings": [], "reviewState": {"deferred": rows}}
        write_scan_local_bytes(scan_dir, STANDARD_STOP_SNAPSHOT, json.dumps(snapshot).encode())


def add_unfinished_standard_work(rows, coverage, findings):
    reported = set()
    for finding in findings:
        reported.add(finding_candidate_id(finding))
        aliases = finding.get("provenance", {}).get("duplicateCandidateIds", [])
        if isinstance(aliases, list):
            reported.update(alias for alias in aliases if isinstance(alias, str))
    reported.discard(None)
    represented = set(reported)
    for surface in coverage.get("surfaces", []):
        if (
            isinstance(surface, dict)
            and surface.get("disposition") in ("rejected", "not_applicable")
            and surface.get("notes")
            and isinstance(surface.get("candidateId"), str)
        ):
            represented.add(surface["candidateId"])
    represented.update(
        row[key]
        for row in coverage.get("resolvedDeferred", [])
        if isinstance(row, dict)
        for key in ("candidateId", "id")
        if isinstance(row.get(key), str)
    )
    pending = {
        row[key]: row
        for row in coverage["deferred"]
        if isinstance(row, dict)
        for key in ("candidateId", "id")
        if isinstance(row.get(key), str)
    }
    for row in rows:
        key = row["id"]
        if key in represented or row.get("duplicateOf") in reported:
            continue
        existing = pending.get(key)
        if existing is None:
            coverage["deferred"].append(row)
        elif key == "standard-unreviewed-files":
            # The stop-time queue records which assigned files are still unread.
            existing["paths"] = row["paths"]
        else:
            # A pending checkpoint owns its explanation. Add the acknowledged
            # worker evidence even when the parent has already deferred this ID.
            for field in ("candidateId", "workerReturn", "workerCandidate", "duplicateOf"):
                if field in row:
                    existing[field] = row[field]
            for field in ("paths", "counterevidence"):
                saved = existing.get(field, [])
                if not isinstance(saved, list):
                    saved = [saved]
                existing[field] = saved + [item for item in row[field] if item not in saved]
