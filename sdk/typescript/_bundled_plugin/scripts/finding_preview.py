"""Bound structured finding details for workbench list responses."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from workbench_constants import (
    FINDING_ATTACK_PATH_PREVIEW_BYTES,
    FINDING_CODE_EVIDENCE_LIMIT,
    FINDING_CODE_EVIDENCE_SNIPPET_BYTES,
    FINDING_DETAILS_PREVIEW_BYTES,
    FINDING_EVIDENCE_EXCERPT_BYTES,
    FINDING_ROOT_CAUSE_PREVIEW_BYTES,
    FINDING_VALIDATION_PREVIEW_BYTES,
)


def bounded_finding_details(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    prepared: dict[str, Any] = {}
    for aliases, maximum_bytes, priority_keys, reserved_fields in (
        (
            ("rootCause", "root_cause"),
            FINDING_ROOT_CAUSE_PREVIEW_BYTES,
            (
                "summary",
                "description",
                "detail",
                "cause",
                "rationale",
                "why",
                "explanation",
                "evidenceRefs",
                "evidence_refs",
            ),
            (
                (("summary", "description", "detail", "cause", "rationale", "why"), 1_000),
                (("evidenceRefs", "evidence_refs"), 400),
            ),
        ),
        (
            ("validation",),
            FINDING_VALIDATION_PREVIEW_BYTES,
            (
                "summary",
                "conclusion",
                "method",
                "status",
                "disposition",
                "result",
                "rationale",
                "evidenceRef",
                "evidence_ref",
                "evidenceRefs",
                "evidence_refs",
                "assertions",
                "evidence",
                "limitations",
            ),
            (
                (("summary", "conclusion", "rationale", "detail", "disposition"), 800),
                (("method",), 256),
                (("status",), 128),
                (("evidenceRefs", "evidence_refs"), 400),
                (("assertions",), 400),
                (("evidence",), 400),
                (("limitations",), 400),
            ),
        ),
        (
            ("attackPath",),
            FINDING_ATTACK_PATH_PREVIEW_BYTES,
            (
                "narrative",
                "summary",
                "description",
                "dataFlow",
                "data_flow",
                "dataflow",
                "path",
                "reachability",
                "steps",
                "authScope",
                "auth_scope",
                "vector",
                "preconditions",
                "assumptions",
                "impact",
                "likelihood",
                "evidenceRefs",
                "evidence_refs",
            ),
            (
                (("narrative", "summary", "description"), 600),
                (("dataFlow", "data_flow", "dataflow", "path"), 600),
                (("reachability",), 500),
                (("steps",), 500),
                (("authScope", "auth_scope"), 200),
                (("vector",), 200),
                (("preconditions",), 500),
                (("assumptions",), 300),
                (("evidenceRefs", "evidence_refs"), 300),
            ),
        ),
    ):
        key = next((alias for alias in aliases if alias in value), None)
        if key is not None:
            prepared[key] = bounded_finding_section(
                value[key],
                maximum_bytes,
                priority_keys,
                reserved_fields,
            )

    writeup = value.get("writeup")
    if isinstance(writeup, dict) and isinstance(writeup.get("reportPath"), str):
        prepared["writeup"] = {"reportPath": bounded_json_text(writeup["reportPath"], 512)[0]}

    evidence_key = next(
        (key for key in ("codeEvidence", "code_evidence") if key in value),
        None,
    )
    if evidence_key is not None:
        prepared[evidence_key] = bounded_code_evidence(value[evidence_key])

    for key in (
        "confidence",
        "detectedAt",
        "evidence",
        "evidenceExcerpt",
        "identity",
        "provenance",
        "ruleId",
        "severity",
        "status",
        "taxonomy",
    ):
        if key in value:
            prepared[key] = (
                bounded_json_text(value[key], FINDING_EVIDENCE_EXCERPT_BYTES)[0]
                if key == "evidenceExcerpt" and isinstance(value[key], str)
                else value[key]
            )

    budget = [FINDING_DETAILS_PREVIEW_BYTES]
    bounded = bounded_json_value(prepared, budget)
    return bounded if isinstance(bounded, dict) else {}


def bounded_finding_section(
    value: Any,
    maximum_bytes: int,
    priority_keys: tuple[str, ...],
    reserved_fields: tuple[tuple[tuple[str, ...], int], ...],
) -> Any:
    if not isinstance(value, dict):
        return bounded_json_value(value, [maximum_bytes])
    ordered: dict[str, Any] = {}
    for aliases, field_bytes in reserved_fields:
        key = next((alias for alias in aliases if alias in value), None)
        if key is not None:
            ordered[key] = bounded_json_value(value[key], [field_bytes])
    for key in (*priority_keys, *value):
        if key in value and key not in ordered:
            ordered[key] = value[key]
    evidence_key = next(
        (key for key in ("codeEvidence", "code_evidence") if key in ordered),
        None,
    )
    if evidence_key is not None:
        ordered[evidence_key] = bounded_code_evidence(ordered[evidence_key])
        ordered.pop("code_evidence" if evidence_key == "codeEvidence" else "codeEvidence", None)
    return bounded_json_value(ordered, [maximum_bytes])


def bounded_code_evidence(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    bounded = []
    for item in value[:FINDING_CODE_EVIDENCE_LIMIT]:
        if not isinstance(item, dict):
            bounded.append(item)
            continue
        evidence = dict(item)
        code = evidence.get("code")
        if isinstance(code, str):
            evidence["code"] = bounded_json_text(
                code,
                FINDING_CODE_EVIDENCE_SNIPPET_BYTES,
            )[0]
        bounded.append(evidence)
    return bounded


def bounded_json_value(value: Any, budget: list[int], *, depth: int = 0) -> Any:
    if budget[0] <= 0:
        return None
    if depth >= 4:
        consume_json_budget(budget, 4)
        return None
    if isinstance(value, str):
        bounded, size = bounded_json_text(value, budget[0])
        consume_json_budget(budget, size)
        return bounded
    if value is None or isinstance(value, (bool, int, float)):
        consume_json_budget(budget, len(json.dumps(value, separators=(",", ":")).encode("utf-8")))
        return value
    if isinstance(value, list):
        if not consume_json_budget(budget, 2):
            return []
        result = []
        for item in value[:20]:
            separator = 0 if not result else 1
            if not consume_json_budget(budget, separator):
                break
            result.append(bounded_json_value(item, budget, depth=depth + 1))
        return result
    if isinstance(value, dict):
        if not consume_json_budget(budget, 2):
            return {}
        result = {}
        for key, item in list(value.items())[:20]:
            if budget[0] <= 0 or not isinstance(key, str):
                break
            separator = 0 if not result else 1
            if not consume_json_budget(budget, separator):
                break
            bounded_key, key_size = bounded_json_text(key, min(budget[0], 512))
            if not consume_json_budget(budget, key_size + 1):
                break
            result[bounded_key] = bounded_json_value(item, budget, depth=depth + 1)
        return result
    consume_json_budget(budget, 4)
    return None


def consume_json_budget(budget: list[int], size: int) -> bool:
    if budget[0] < size:
        budget[0] = 0
        return False
    budget[0] -= size
    return True


def bounded_json_text(value: str, maximum_bytes: int) -> tuple[str, int]:
    low = 0
    high = len(value)
    selected = ""
    selected_size = 2
    while low <= high:
        midpoint = (low + high) // 2
        candidate = value[:midpoint]
        size = len(json.dumps(candidate, separators=(",", ":")).encode("utf-8"))
        if size <= maximum_bytes:
            selected = candidate
            selected_size = size
            low = midpoint + 1
        else:
            high = midpoint - 1
    return selected, selected_size


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
