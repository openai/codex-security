"""Project accepted worker coverage into a stopped scan's publication."""

from __future__ import annotations

import argparse
import copy
import sqlite3
from pathlib import Path
from typing import Any


def retain_unmerged_review_coverage(
    scan_dir: Path, coverage: dict[str, Any], worker: sqlite3.Row, draft: dict[str, Any]
) -> None:
    """Retain review provenance and obligations without promoting its findings."""
    source = draft["coverage"]
    provenance = {"workerId": worker["id"], "attempt": worker["attempt"]}
    prefix = f"{worker['id']}-attempt-{worker['attempt']}"
    artifact_prefix = Path(worker["artifact_dir"]).relative_to(scan_dir).as_posix()
    archive_prefix = f"{Path(artifact_prefix).parent.as_posix()}/attempts/"
    recorded = Path(worker["accepted_result_path"]).parent.name == "checkpoints"
    surfaces = {
        item.get("id"): f"{prefix}-surface-{index + 1}"
        for index, item in enumerate(source.get("surfaces", []))
    }

    def retain(field: str, item: dict[str, Any]) -> None:
        # A committed budget draft can be replayed before the scan is sealed.
        # These IDs and provenance identify the same immutable accepted review.
        items = coverage.setdefault(field, [])
        if "id" in item:
            matches = []
            for index, existing in enumerate(items):
                existing_provenance = (
                    existing.get("provenance") if isinstance(existing, dict) else None
                )
                if (
                    isinstance(existing_provenance, dict)
                    and existing.get("id") == item["id"]
                    and all(
                        existing_provenance.get(key) == value for key, value in provenance.items()
                    )
                ):
                    matches.append(index)
            if matches:
                # Refresh older projections from the same accepted bytes, even
                # if an interrupted writer saved more than one copy.
                items[matches[0]] = item
                for index in reversed(matches[1:]):
                    del items[index]
                return
        if item not in items:
            items.append(item)

    for field in ("surfaces", "explicitExclusions", "deferred", "openQuestions"):
        for index, original in enumerate(source.get(field, [])):
            item = copy.deepcopy(original if isinstance(original, dict) else {"question": original})
            source_provenance = item.get("provenance")
            if not isinstance(source_provenance, dict):
                source_provenance = {}
            scan_refs = source_provenance.pop("scanReceiptRefs", [])
            # Keep source descriptions; the accepted owner supplies identity.
            for key in ("workerId", "attempt", "sourceId", "candidateId"):
                source_provenance.pop(key, None)
            item["provenance"] = {
                **source_provenance,
                **provenance,
                **({"sourceId": item["id"]} if "id" in item else {}),
                **({"candidateId": item["candidateId"]} if "candidateId" in item else {}),
            }
            item["id"] = f"{prefix}-{field}-{index + 1}"
            if field == "surfaces":
                item["id"] = f"{prefix}-surface-{index + 1}"
                item["receiptRefs"] = [
                    ref
                    if ref.startswith((archive_prefix, f"{artifact_prefix}/"))
                    or (recorded and isinstance(scan_refs, list) and ref in scan_refs)
                    else f"{artifact_prefix}/{ref}"
                    for ref in item.get("receiptRefs", [])
                ]
            if field == "deferred" and "candidateId" in item:
                item["candidateId"] = f"{prefix}-candidate-{index + 1}"
            if "surfaceIds" in item:
                item["surfaceIds"] = [surfaces.get(value, value) for value in item["surfaceIds"]]
            retain(field, item)
    retain("reviews", provenance)
    for index, limitation in enumerate(draft.get("scope", {}).get("limitations", [])):
        retain(
            "deferred",
            {
                "id": f"{prefix}-scope-{index + 1}",
                "reason": limitation,
                "provenance": provenance,
            },
        )
    retain(
        "deferred",
        {
            "id": f"{prefix}-unmerged",
            "provenance": provenance,
            "reason": "This accepted discovery was not merged before the scan reached its cost limit.",
        },
    )


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
