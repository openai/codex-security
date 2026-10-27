"""Read small batches of Standard candidates and reconcile their decisions with the report."""

from __future__ import annotations

import argparse
import json
import sys
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


def pending_batch(scan_dir: Path, queue: dict, decisions: dict, after: int) -> list:
    pending = []
    offset = 0
    for ref in queue.get("returns", []):
        result = None
        for number in range(max(offset, after) + 1, offset + ref["count"] + 1):
            key = f"standard-{number}"
            if key in decisions:
                continue
            if result is None:
                result = _read_scan_local_json(scan_dir, ref["file"], "Standard worker return")
            pending.append(
                {
                    "candidateId": key,
                    "cursor": number,
                    "candidate": result["findings"][number - offset - 1],
                    "reviewed_files": result["reviewed_files"],
                    "counterevidence": result["resolved_questions"],
                }
            )
            if len(pending) == 5:
                return pending
        offset += ref["count"]
    return pending


def candidate_ids(queue: dict):
    count = sum(ref["count"] for ref in queue.get("returns", []))
    return (f"standard-{number}" for number in range(1, count + 1))


def claim_outcomes(decisions: dict) -> dict:
    return {
        f"{key}.{index}": part
        for key, parts in decisions.items()
        for index, part in enumerate(parts, 1)
    }


def record(scan_dir: Path, queue: dict, decisions: dict, rows: list) -> None:
    known = set(candidate_ids(queue))
    for row in rows:
        key, parts = row["candidateId"], row["parts"]
        if key not in known or not isinstance(parts, list) or not parts:
            raise ContractError(f"Expected a decision on a returned Standard candidate: {key}.")
        if key in decisions and decisions[key] != parts:
            raise ContractError(f"Standard candidate {key} already has a different decision.")
        for part in parts:
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
            if disposition == "duplicate" and not part.get("duplicateOf"):
                raise ContractError(
                    f"Standard candidate {key} needs a reportable duplicate target."
                )
        decisions[key] = parts
    outcomes = claim_outcomes(decisions)
    for row in rows:
        for part in row["parts"]:
            if part["disposition"] == "duplicate" and (
                outcomes.get(part["duplicateOf"], {}).get("disposition") != "reportable"
            ):
                raise ContractError(
                    f"Duplicate target {part['duplicateOf']} has no reportable decision."
                )
    write_scan_local_bytes(scan_dir, DECISIONS, json.dumps(decisions).encode())


def require_standard_decisions(scan, findings: dict, coverage: dict) -> None:
    if scan["mode"] != "standard":
        return
    scan_dir = Path(scan["scan_dir"])
    queue = read_optional(scan_dir, QUEUE)
    if not queue:
        return
    remaining = {path for batch in queue["batches"] for path in batch} - set(queue["reviewed"])
    if remaining:
        raise RecoverableContractError(f"{len(remaining)} Standard target files still need review.")
    if json.loads(scan["recipe_json"] or "{}").get("validationMode") == "custom":
        return

    decisions = read_optional(scan_dir, DECISIONS)
    for key in candidate_ids(queue):
        if key not in decisions:
            raise RecoverableContractError(
                f"Standard candidate {key} has no decision. "
                "Resume with standard_validation.py pending."
            )

    outcomes = claim_outcomes(decisions)
    reported = set()
    for finding in findings.get("findings", []):
        if root := finding_candidate_id(finding):
            reported.add(root)
            if outcomes.get(root, {}).get("disposition") == "reportable":
                reported.update(finding.get("provenance", {}).get("duplicateCandidateIds", []))
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
            saved = part["duplicateOf"] in reported
        elif disposition == "deferred":
            saved = claim in deferred
        else:
            saved = (claim, disposition) in rejected
        if not saved:
            raise RecoverableContractError(
                f"Standard claim {claim} is {disposition}. Its decision is missing from the report."
            )


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
