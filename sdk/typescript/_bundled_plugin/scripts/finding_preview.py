"""Bound structured finding details for workbench list responses."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from report_projection import merged_root_cause
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
                "counterEvidence",
                "limitations",
            ),
            (
                (("summary", "conclusion", "rationale", "detail", "disposition"), 800),
                (("method",), 256),
                (("status",), 128),
                (("evidenceRefs", "evidence_refs"), 400),
                (("assertions",), 400),
                (("evidence",), 400),
                (("counterEvidence",), 400),
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
        if aliases == ("rootCause", "root_cause"):
            key, section = merged_root_cause(value)
        else:
            key = next((alias for alias in aliases if alias in value), None)
            section = value[key] if key is not None else None
        if key is not None:
            if key == "attackPath" and isinstance(section, dict):
                section = dict(section)
                for assessment in ("impact", "likelihood"):
                    if isinstance(section.get(assessment), str):
                        assessment_value = section[assessment]
                        assessment_key = (
                            "level"
                            if re.fullmatch(
                                r"critical|high|medium|low|informational|ignore|unknown",
                                assessment_value,
                                flags=re.IGNORECASE,
                            )
                            else "rationale"
                        )
                        section[assessment] = {assessment_key: assessment_value}
            prepared[key] = bounded_finding_section(
                section,
                maximum_bytes,
                priority_keys,
                reserved_fields,
            )

    writeup = value.get("writeup")
    if isinstance(writeup, dict) and isinstance(writeup.get("reportPath"), str):
        prepared["writeup"] = {"reportPath": bounded_json_text(writeup["reportPath"], 512)[0]}

    evidence_key, evidence = merged_code_evidence(value)
    if evidence_key is not None:
        prepared[evidence_key] = bounded_code_evidence(evidence)

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
        "preventiveControls",
        "remediationTests",
    ):
        if key in value:
            prepared[key] = (
                bounded_json_text(value[key], FINDING_EVIDENCE_EXCERPT_BYTES)[0]
                if key == "evidenceExcerpt" and isinstance(value[key], str)
                else value[key]
            )

    guidance = {
        key: prepared[key]
        for key in ("remediationTests", "preventiveControls")
        if key in prepared and isinstance(prepared[key], list)
    }
    diagnostics = (
        "rootCause",
        "root_cause",
        "validation",
        "attackPath",
        "codeEvidence",
        "code_evidence",
    )
    core_keys = (
        "writeup",
        *diagnostics,
        "confidence",
        "detectedAt",
        "identity",
        "provenance",
        "ruleId",
        "severity",
        "status",
        "taxonomy",
        "evidence",
        "evidenceExcerpt",
    )
    core = {key: prepared[key] for key in core_keys if key in prepared}
    extras = {
        key: item for key, item in prepared.items() if key not in core and key not in guidance
    }
    complete_guidance = {key: items[:1] for key, items in guidance.items()}
    minimum_guidance = {
        key: [items[0][:1]] if items and isinstance(items[0], str) else []
        for key, items in guidance.items()
    }
    projected_core = {}
    for selected_guidance in (complete_guidance, minimum_guidance):
        reserved = (
            len(json.dumps(selected_guidance, separators=(",", ":")).encode("utf-8")) - 1
            if selected_guidance
            else 0
        )
        if reserved >= FINDING_DETAILS_PREVIEW_BYTES:
            continue
        projected_core = bounded_json_value(
            core,
            [FINDING_DETAILS_PREVIEW_BYTES - reserved],
        )
        if all(key in projected_core for key in core):
            break
    ordered_guidance = dict(sorted(guidance.items(), key=lambda entry: bool(entry[1])))
    bounded = bounded_json_value(
        {**projected_core, **ordered_guidance, **extras},
        [FINDING_DETAILS_PREVIEW_BYTES],
    )
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
    evidence_key, evidence = merged_code_evidence(ordered)
    if evidence_key is not None:
        ordered[evidence_key] = bounded_code_evidence(evidence)
        ordered.pop("code_evidence" if evidence_key == "codeEvidence" else "codeEvidence", None)
    return bounded_json_value(ordered, [maximum_bytes])


def merged_code_evidence(value: dict[str, Any]) -> tuple[str | None, Any]:
    evidence_keys = [key for key in ("codeEvidence", "code_evidence") if key in value]
    if not evidence_keys:
        return None, None
    catalogs = [value[key] for key in evidence_keys if isinstance(value[key], list)]
    if catalogs:
        merged = []
        seen_ids: set[str] = set()
        for catalog in catalogs:
            for item in catalog:
                if not _is_valid_code_evidence(item):
                    continue
                evidence_id = item["id"]
                if evidence_id in seen_ids:
                    continue
                seen_ids.add(evidence_id)
                merged.append(item)
        return evidence_keys[0], merged
    return evidence_keys[0], value[evidence_keys[0]]


def _is_valid_code_evidence(item: Any) -> bool:
    return (
        isinstance(item, dict)
        and isinstance(item.get("id"), str)
        and bool(item["id"].strip())
        and isinstance(item.get("code"), str)
        and bool(item["code"].strip())
    )


def bounded_code_evidence(value: Any) -> Any:
    if not isinstance(value, list):
        return value
    bounded = []
    for item in value:
        if not _is_valid_code_evidence(item):
            continue
        if len(bounded) >= FINDING_CODE_EVIDENCE_LIMIT:
            break
        evidence = dict(item)
        for field in ("explanation", "label", "language", "path"):
            if field in evidence and not isinstance(evidence[field], str):
                evidence.pop(field)
        if (
            "role" in evidence
            and evidence["role"] is not None
            and not isinstance(evidence["role"], str)
        ):
            evidence.pop("role")
        start_line = evidence.get("startLine")
        if "startLine" in evidence and (
            not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1
        ):
            evidence.pop("startLine")
        end_line = evidence.get("endLine")
        if (
            "endLine" in evidence
            and end_line is not None
            and (not isinstance(end_line, int) or isinstance(end_line, bool) or end_line < 1)
        ):
            evidence.pop("endLine")
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
        for item in value:
            remaining = budget[0]
            separator = 0 if not result else 1
            if not consume_json_budget(budget, separator):
                break
            bounded_item = bounded_json_value(item, budget, depth=depth + 1)
            size = len(json.dumps(bounded_item, separators=(",", ":")).encode("utf-8"))
            if separator + size > remaining or (
                isinstance(item, str) and item and bounded_item == ""
            ):
                budget[0] = remaining
                break
            budget[0] = remaining - separator - size
            result.append(bounded_item)
        return result
    if isinstance(value, dict):
        if not consume_json_budget(budget, 2):
            return {}
        result = {}
        for key, item in list(value.items())[:20]:
            if budget[0] <= 0 or not isinstance(key, str):
                break
            remaining = budget[0]
            separator = 0 if not result else 1
            if not consume_json_budget(budget, separator):
                budget[0] = remaining
                break
            bounded_key, key_size = bounded_json_text(key, min(budget[0], 512))
            if not consume_json_budget(budget, key_size + 1):
                budget[0] = remaining
                break
            item_budget = budget
            if depth == 0 and key == "remediationTests":
                controls = value.get("preventiveControls")
                if (
                    isinstance(item, list)
                    and item
                    and isinstance(item[0], str)
                    and item[0]
                    and isinstance(controls, list)
                    and controls
                    and isinstance(controls[0], str)
                    and controls[0]
                ):
                    minimum_tests = len(
                        json.dumps([item[0][0]], separators=(",", ":")).encode("utf-8")
                    )
                    for control in (controls[0], controls[0][0]):
                        reserved = (
                            len(
                                json.dumps(
                                    {"preventiveControls": [control]},
                                    separators=(",", ":"),
                                ).encode("utf-8")
                            )
                            - 1
                        )
                        if budget[0] >= minimum_tests + reserved:
                            item_budget = [budget[0] - reserved]
                            break
            bounded_item = bounded_json_value(item, item_budget, depth=depth + 1)
            size = (
                separator
                + key_size
                + 1
                + len(json.dumps(bounded_item, separators=(",", ":")).encode("utf-8"))
            )
            if size > remaining or (isinstance(item, str) and item and bounded_item == ""):
                budget[0] = remaining
                break
            budget[0] = remaining - size
            result[bounded_key] = bounded_item
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
