"""Read small batches of Standard candidates and reconcile their decisions with the report."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from finalize_scan_contract import (
    ContractError,
    MissingScanLocalFileError,
    RecoverableContractError,
    _read_scan_local_json,
    finding_candidate_id,
    write_scan_local_bytes,
)

QUEUE = "artifacts/01_context/standard-queue.json"
DECISIONS = "artifacts/04_validation/standard-decisions.json"


def read_optional(scan_dir: Path, name: str) -> dict:
    try:
        return _read_scan_local_json(scan_dir, name, name)
    except MissingScanLocalFileError:
        return {}


def has_standard_review_state(scan_dir: Path) -> bool:
    return any(
        (scan_dir / marker).exists()
        for marker in (QUEUE, DECISIONS, "artifacts/02_discovery/standard-returns")
    )


def read_standard_queue(scan_dir: Path) -> dict:
    queue = read_optional(scan_dir, QUEUE)
    if not queue and has_standard_review_state(scan_dir):
        raise RecoverableContractError(
            "The Standard file queue is missing or incomplete. Restore the queue before "
            "publishing its results, or rebuild it if no worker returns were saved."
        )
    return queue


def returned_candidates(scan_dir: Path, queue: dict, after: int, wanted):
    offset = 0
    for ref in queue.get("returns", []):
        result = None
        for number in range(max(offset, after) + 1, offset + ref["count"] + 1):
            key = f"standard-{number}"
            if not wanted(key):
                continue
            if result is None:
                result = _read_scan_local_json(scan_dir, ref["file"], "Standard worker return")
            yield {
                "candidateId": key,
                "cursor": number,
                "candidate": result["findings"][number - offset - 1],
                "reviewed_files": result["reviewed_files"],
                "counterevidence": result["resolved_questions"],
            }
        offset += ref["count"]


def can_revisit(part: dict, outcomes: dict) -> bool:
    if part["disposition"] != "duplicate":
        return part["disposition"] == "deferred"
    target = part.get("duplicateOf")
    linked = outcomes.get(target) if isinstance(target, str) else None
    return not isinstance(linked, dict) or linked.get("disposition") != "reportable"


def pending_batch(scan_dir: Path, queue: dict, decisions: dict, after: int) -> list:
    outcomes = claim_outcomes(decisions)

    def wanted(key):
        return key not in decisions or any(can_revisit(part, outcomes) for part in decisions[key])

    rows = list(islice(returned_candidates(scan_dir, queue, after, wanted), 5))
    for row in rows:
        if row["candidateId"] in decisions:
            row["parts"] = decisions[row["candidateId"]]
    return rows


def candidate_ids(queue: dict):
    count = sum(ref["count"] for ref in queue.get("returns", []))
    return (f"standard-{number}" for number in range(1, count + 1))


def claim_outcomes(decisions: dict) -> dict:
    return {
        f"{key}.{index}": part
        for key, parts in decisions.items()
        for index, part in enumerate(parts, 1)
    }


def update_part(claim: str, part: dict, saved: dict | None, outcomes: dict) -> dict:
    # History belongs to the saved claim, including when a reviewer retries an earlier return.
    part = {k: v for k, v in part.items() if k != "previousDecisions"}
    if saved is None:
        return part
    original = {k: v for k, v in saved.items() if k != "previousDecisions"}
    if part == original:
        return saved
    if (
        not can_revisit(saved, outcomes)
        or saved["disposition"] == part["disposition"] == "deferred"
    ):
        raise ContractError(f"Standard claim {claim} already has a different decision.")
    return {**part, "previousDecisions": [*saved.get("previousDecisions", []), original]}


def record(scan_dir: Path, queue: dict, decisions: dict, rows: list) -> None:
    known = set(candidate_ids(queue))
    original = claim_outcomes(decisions)
    for row in rows:
        key, parts = row["candidateId"], row["parts"]
        if key not in known or not isinstance(parts, list) or not parts:
            raise ContractError(f"Expected a decision on a returned Standard candidate: {key}.")
        previous = decisions.get(key)
        if previous is not None and len(previous) != len(parts):
            raise ContractError(f"Standard candidate {key} must keep its recorded claim IDs.")
        updated_parts = []
        for index, part in enumerate(parts, 1):
            claim = f"{key}.{index}"
            disposition = part["disposition"]
            if disposition not in {
                "reportable",
                "duplicate",
                "rejected",
                "not_applicable",
                "deferred",
            }:
                raise ContractError(f"Unknown decision for {key}: {disposition}.")
            if not part.get("reason", "").strip():
                raise ContractError(f"Standard candidate {key} needs a source-backed reason.")
            saved = previous[index - 1] if previous is not None else None
            updated_parts.append(update_part(claim, part, saved, original))
        decisions[key] = updated_parts

    outcomes = claim_outcomes(decisions)
    for claim, part in outcomes.items():
        if part["disposition"] != "duplicate" or part == original.get(claim):
            continue
        target = part.get("duplicateOf")
        match = (
            re.fullmatch(r"(standard-[1-9][0-9]*)\.[1-9][0-9]*", target)
            if isinstance(target, str)
            else None
        )
        if not match or match[1] not in known or target == claim:
            raise ContractError(
                f"Standard claim {claim} needs a different returned claim as its duplicate target."
            )
        if match[1] in decisions and (
            target not in outcomes
            or (
                outcomes[target]["disposition"] != "reportable"
                and not can_revisit(outcomes[target], outcomes)
            )
        ):
            raise ContractError(f"Duplicate target {target} has no reportable decision.")
    write_scan_local_bytes(scan_dir, DECISIONS, json.dumps(decisions).encode())


def investigation_deadline_elapsed(recipe: dict) -> bool:
    minutes = recipe.get("maxTimeMinutes")
    start = recipe.get("timeBudgetStartedAt")
    if (
        isinstance(minutes, bool)
        or not isinstance(minutes, (int, float))
        or minutes <= 0
        or not isinstance(start, str)
    ):
        return False
    try:
        started_at = datetime.fromisoformat(start.replace("Z", "+00:00"))
        elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
        return math.isfinite(minutes) and elapsed / 60 >= minutes
    except (OverflowError, TypeError, ValueError):
        return False


def require_standard_decisions(
    scan, manifest: dict, findings: dict, coverage: dict, *, sealing=False
) -> bool:
    """Check the draft and return whether its unfinished work must accompany the seal."""
    if scan["mode"] != "standard":
        return False
    scan_dir = Path(scan["scan_dir"])
    queue = read_standard_queue(scan_dir)
    remaining = (
        {path for batch in queue["batches"] for path in batch} - set(queue["reviewed"])
        if queue
        else set()
    )
    recipe = json.loads(scan["recipe_json"] or "{}")
    elapsed = investigation_deadline_elapsed(recipe)
    deferred_rows = [
        row
        for row in coverage.get("deferred", [])
        if isinstance(row, dict) and isinstance(row.get("reason"), str) and row["reason"].strip()
    ]
    retain_deferred = elapsed and bool(deferred_rows)
    if remaining:
        if not elapsed:
            raise RecoverableContractError(
                f"{len(remaining)} Standard target files still need review."
            )
        declared = {
            path
            for row in deferred_rows
            if isinstance(row.get("paths"), list)
            for path in row["paths"]
            if isinstance(path, str)
        }
        if remaining - declared:
            raise RecoverableContractError(
                "The Standard investigation deadline elapsed. Name every unread target path "
                "in deferred work and explain why it remains unfinished."
            )
    if recipe.get("validationMode") == "custom":
        if (
            retain_deferred
            and sealing
            and manifest["scan"].get("scope", {}).get("validationMode") != "custom"
        ):
            raise RecoverableContractError(
                "The partial discovery draft is awaiting custom validation."
            )
        return retain_deferred
    if not queue:
        return retain_deferred

    decisions = read_optional(scan_dir, DECISIONS)
    deferred_candidates = {
        row["candidateId"]: row for row in deferred_rows if isinstance(row.get("candidateId"), str)
    }
    receipt_rows = {}
    for key in candidate_ids(queue):
        if key in decisions:
            continue
        if not elapsed or key not in deferred_candidates:
            raise RecoverableContractError(
                f"Standard candidate {key} has no decision. "
                "Resume with standard_validation.py pending."
            )
        receipt_rows[key] = [deferred_candidates[key]]

    outcomes = claim_outcomes(decisions)
    reported = set()
    for finding in findings.get("findings", []):
        root = finding_candidate_id(finding)
        aliases = finding.get("provenance", {}).get("duplicateCandidateIds", [])
        identities = {root} if root else set()
        if isinstance(aliases, list):
            identities.update(alias for alias in aliases if isinstance(alias, str))
        for identity in identities:
            if identity not in outcomes and re.fullmatch(r"standard-[0-9]+(?:\.[0-9]+)?", identity):
                raise RecoverableContractError(
                    f"Standard ID {identity} has no recorded claim decision."
                )
        if root in outcomes and outcomes[root]["disposition"] != "reportable":
            raise RecoverableContractError(
                f"Standard claim {root} is {outcomes[root]['disposition']} and cannot be a finding."
            )
        reported.update(identities)
    deferred = {row.get("candidateId") for row in coverage.get("deferred", [])}
    rejected = {
        (row.get("candidateId"), row["disposition"])
        for row in coverage.get("surfaces", [])
        if row.get("notes")
    }
    for claim, part in outcomes.items():
        disposition = part["disposition"]
        if disposition == "reportable":
            saved = claim in reported
        elif disposition == "duplicate":
            target = part["duplicateOf"]
            if can_revisit(part, outcomes):
                if elapsed and claim in deferred_candidates and claim not in reported:
                    row = deferred_candidates[claim]
                    row["decision"] = part
                    receipt_rows.setdefault(claim.rsplit(".", 1)[0], []).append(row)
                    continue
                raise RecoverableContractError(
                    f"Duplicate target {target} has no reportable decision."
                )
            saved = target in reported
        elif disposition == "deferred":
            saved = claim in deferred and claim not in reported
        else:
            saved = (claim, disposition) in rejected and claim not in reported
        if not saved:
            raise RecoverableContractError(
                f"Standard claim {claim} is {disposition}. The report does not match its decision."
            )
    if receipt_rows:
        for receipt in returned_candidates(scan_dir, queue, 0, receipt_rows.__contains__):
            # A deadline proof gap keeps the worker's original evidence and counterevidence.
            for row in receipt_rows[receipt["candidateId"]]:
                for field in ("candidate", "counterevidence", "reviewed_files"):
                    row[field] = receipt[field]
    return retain_deferred


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["pending", "record"])
    parser.add_argument("scan_dir", type=Path)
    parser.add_argument("after_cursor", type=int, nargs="?", default=0)
    args = parser.parse_args()
    queue = _read_scan_local_json(args.scan_dir, QUEUE, QUEUE)
    decisions = read_optional(args.scan_dir, DECISIONS)
    if args.action == "record":
        record(args.scan_dir, queue, decisions, json.load(sys.stdin))
    else:
        print(json.dumps(pending_batch(args.scan_dir, queue, decisions, args.after_cursor)))


if __name__ == "__main__":
    try:
        main()
    except (ContractError, KeyError, ValueError) as exc:
        sys.exit(str(exc))
