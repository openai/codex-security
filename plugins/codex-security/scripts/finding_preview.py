"""Bound structured finding details for workbench list responses."""

from __future__ import annotations

import argparse
import json
import re
import sys
from bisect import bisect_right
from itertools import chain
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
    FINDING_LEVEL_BYTES,
    FINDING_ROOT_CAUSE_PREVIEW_BYTES,
    FINDING_SUMMARY_BYTES,
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

    evidence_key, evidence = merged_bounded_code_evidence(value)
    if evidence_key is not None:
        prepared[evidence_key] = evidence

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
    for key in ("severity", "confidence"):
        if key in prepared:
            prepared[key] = bounded_finding_section(
                prepared[key],
                FINDING_SUMMARY_BYTES,
                ("level",),
                ((("level",), FINDING_LEVEL_BYTES),),
            )
    if "taxonomy" in prepared:
        prepared["taxonomy"] = bounded_finding_section(
            prepared["taxonomy"], FINDING_SUMMARY_BYTES, ("cwe",), ()
        )
    metadata_keys = (
        "ruleId",
        "status",
        "detectedAt",
        "identity",
        "taxonomy",
        "severity",
        "confidence",
    )
    metadata = {
        key: bounded_json_value(prepared[key], [FINDING_SUMMARY_BYTES])
        for key in metadata_keys
        if key in prepared
    }
    metadata = dict(sorted(metadata.items(), key=lambda item: json_size(item[1])))
    metadata_budget = FINDING_SUMMARY_BYTES - 2 - sum(json_size(key) + 2 for key in metadata)
    for index, (key, item) in enumerate(metadata.items()):
        metadata[key] = bounded_json_value(item, [metadata_budget // (len(metadata) - index)])
        metadata_budget -= json_size(metadata[key])
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
        "provenance",
        "evidence",
        "evidenceExcerpt",
    )
    core = {key: prepared[key] for key in core_keys if key in prepared}
    extras = {
        key: item
        for key, item in prepared.items()
        if key not in core and key not in guidance and key not in metadata_keys
    }
    complete_guidance = {key: items[:1] for key, items in guidance.items()}
    minimum_guidance = {
        key: [items[0][:1]] if items and isinstance(items[0], str) else []
        for key, items in guidance.items()
    }
    projected_core = {}
    for selected_guidance in (complete_guidance, minimum_guidance):
        # Keep raw guidance inline to preserve its JSON-encoding recursion boundary.
        reserved = (
            len(json.dumps(selected_guidance, separators=(",", ":"))) - 1
            if selected_guidance
            else 0
        )
        if metadata:
            reserved += json_size(metadata) - 1
        if reserved >= FINDING_DETAILS_PREVIEW_BYTES:
            continue
        projected_core = bounded_json_value(
            core,
            [FINDING_DETAILS_PREVIEW_BYTES - reserved],
            max_depth=5,
        )
        if all(key in projected_core for key in core):
            break
    ordered_guidance = dict(sorted(guidance.items(), key=lambda entry: bool(entry[1])))
    bounded = bounded_json_value(
        {**metadata, **projected_core, **ordered_guidance, **extras},
        [FINDING_DETAILS_PREVIEW_BYTES],
        max_depth=5,
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
    evidence_key, evidence = merged_bounded_code_evidence(ordered)
    if evidence_key is not None:
        ordered[evidence_key] = evidence
        ordered.pop("code_evidence" if evidence_key == "codeEvidence" else "codeEvidence", None)
    return bounded_json_value(ordered, [maximum_bytes])


def merged_bounded_code_evidence(value: dict[str, Any]) -> tuple[str | None, Any]:
    evidence_keys = [key for key in ("codeEvidence", "code_evidence") if key in value]
    if not evidence_keys:
        return None, None
    catalogs = [value[key] for key in evidence_keys if isinstance(value[key], list)]
    if not catalogs:
        return evidence_keys[0], value[evidence_keys[0]]
    bounded = {}
    for item in chain.from_iterable(catalogs):
        if not (
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and bool(item["id"].strip())
            and isinstance(item.get("code"), str)
            and bool(item["code"].strip())
        ):
            continue
        if item["id"] in bounded:
            continue
        if len(bounded) >= FINDING_CODE_EVIDENCE_LIMIT:
            return evidence_keys[0], list(bounded.values())
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
        evidence["code"] = bounded_json_text(
            evidence["code"],
            FINDING_CODE_EVIDENCE_SNIPPET_BYTES,
        )[0]
        bounded[item["id"]] = evidence
    return evidence_keys[0], list(bounded.values())


def json_size(value: Any) -> int:
    # ASCII output gives byte length; strings can use the cached default encoder.
    return len(json.dumps(value, separators=None if isinstance(value, str) else (",", ":")))


def bounded_json_value(
    value: Any,
    budget: list[int],
    *,
    depth: int = 0,
    max_depth: int = 4,
) -> Any:
    if budget[0] <= 0:
        return None
    if depth >= max_depth:
        consume_json_budget(budget, 4)
        return None
    if isinstance(value, str):
        bounded, size = bounded_json_text(value, budget[0])
        consume_json_budget(budget, size)
        return bounded
    if value is None or isinstance(value, (bool, int, float)):
        consume_json_budget(budget, json_size(value))
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
            bounded_item = bounded_json_value(
                item,
                budget,
                depth=depth + 1,
                max_depth=max_depth,
            )
            size = json_size(bounded_item)
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
                    minimum_tests = json_size([item[0][0]])
                    for control in (controls[0], controls[0][0]):
                        reserved = json_size({"preventiveControls": [control]}) - 1
                        if budget[0] >= minimum_tests + reserved:
                            item_budget = [budget[0] - reserved]
                            break
            bounded_item = bounded_json_value(
                item,
                item_budget,
                depth=depth + 1,
                max_depth=max_depth,
            )
            size = separator + key_size + 1 + json_size(bounded_item)
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
    length = bisect_right(range(len(value) + 1), maximum_bytes, key=lambda n: json_size(value[:n]))
    selected = value[: max(0, length - 1)]
    return selected, json_size(selected)


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
