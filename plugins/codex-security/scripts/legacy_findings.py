"""Normalize legacy finding details for scan contract validation."""

from __future__ import annotations

import copy
from typing import Any

import report_projection


def _filter_unknown_legacy_evidence_refs(section: dict[str, Any], evidence_ids: set[str]) -> None:
    for refs_field in ("evidenceRefs", "evidence_refs"):
        refs = section.get(refs_field)
        if isinstance(refs, list):
            section[refs_field] = [
                ref for ref in refs if isinstance(ref, str) and ref.strip() and ref in evidence_ids
            ]


def _normalize_legacy_string_list_fields(section: dict[str, Any], fields: tuple[str, ...]) -> None:
    for field in fields:
        if field not in section:
            continue
        value = section[field]
        if isinstance(value, str):
            normalized = [value] if value.strip() else []
        elif isinstance(value, list):
            normalized = [item for item in value if isinstance(item, str) and item.strip()]
        else:
            normalized = []
        if normalized:
            section[field] = normalized
        else:
            section.pop(field)


def _remove_unsupported_legacy_scalar_fields(
    section: dict[str, Any], fields: tuple[str, ...]
) -> None:
    for field in fields:
        if field in section and (not isinstance(section[field], str) or section[field] == ""):
            section.pop(field)


def _legacy_sealed_findings_for_validation(findings: dict[str, Any]) -> dict[str, Any]:
    compatible = copy.deepcopy(findings)
    finding_items = compatible.get("findings")
    if not isinstance(finding_items, list):
        return compatible
    for finding in finding_items:
        if not isinstance(finding, dict):
            continue
        canonical_evidence = finding.get("codeEvidence")
        canonical_evidence = canonical_evidence if isinstance(canonical_evidence, list) else []
        evidence_ids = {
            evidence["id"]
            for evidence in canonical_evidence
            if isinstance(evidence, dict) and isinstance(evidence.get("id"), str) and evidence["id"]
        }
        legacy_evidence = finding.get("code_evidence")
        if isinstance(legacy_evidence, list):
            compatible_legacy_evidence = []
            for evidence in report_projection.code_evidence_rows(legacy_evidence):
                evidence_id = evidence.get("id")
                if not isinstance(evidence_id, str) or not evidence_id.strip():
                    continue
                if evidence_id in evidence_ids:
                    continue
                evidence_ids.add(evidence_id)
                compatible_legacy_evidence.append(evidence)
            finding["code_evidence"] = compatible_legacy_evidence
        elif "code_evidence" in finding:
            finding.pop("code_evidence")
        for section_name, list_fields in (
            ("rootCause", ("evidenceRefs", "evidence_refs")),
            ("root_cause", ("evidenceRefs", "evidence_refs")),
            (
                "validation",
                (
                    "assertions",
                    "counterEvidence",
                    "evidence",
                    "evidenceRefs",
                    "evidence_refs",
                    "limitations",
                ),
            ),
            (
                "attackPath",
                (
                    "assumptions",
                    "blindspots",
                    "controls",
                    "evidenceRefs",
                    "evidence_refs",
                    "limitations",
                    "preconditions",
                    "steps",
                ),
            ),
        ):
            section = finding.get(section_name)
            if not isinstance(section, dict):
                continue
            _normalize_legacy_string_list_fields(section, list_fields)
            _filter_unknown_legacy_evidence_refs(section, evidence_ids)
        legacy_root_cause = finding.get("root_cause")
        if isinstance(legacy_root_cause, dict):
            _remove_unsupported_legacy_scalar_fields(
                legacy_root_cause, ("summary", "code", "language")
            )
        elif (
            "root_cause" in finding
            and legacy_root_cause is not None
            and (not isinstance(legacy_root_cause, str) or legacy_root_cause == "")
        ):
            finding.pop("root_cause")
        validation = finding.get("validation")
        if isinstance(validation, dict):
            _remove_unsupported_legacy_scalar_fields(
                validation, ("method", "status", "summary", "disposition", "result")
            )
        attack_path = finding.get("attackPath")
        if not isinstance(attack_path, dict):
            continue
        _remove_unsupported_legacy_scalar_fields(attack_path, ("summary",))
        for field in ("dataFlow", "data_flow", "dataflow", "reachability"):
            detail = attack_path.get(field)
            if isinstance(detail, dict):
                detail_scalar_fields = ("summary", "source", "sink", "outcome")
                if field == "reachability":
                    detail_scalar_fields += ("attacker", "entrypoint")
                _remove_unsupported_legacy_scalar_fields(detail, detail_scalar_fields)
                _normalize_legacy_string_list_fields(
                    detail, ("evidenceRefs", "evidence_refs", "transformations")
                )
                _filter_unknown_legacy_evidence_refs(detail, evidence_ids)
                if field == "reachability":
                    _normalize_legacy_string_list_fields(detail, ("preconditions",))
            elif not isinstance(detail, str) or detail == "":
                attack_path.pop(field, None)
        for field in ("impact", "likelihood"):
            detail = attack_path.get(field)
            if isinstance(detail, dict):
                _remove_unsupported_legacy_scalar_fields(detail, ("level", "rationale", "why"))
            elif detail is not None and (not isinstance(detail, str) or detail == ""):
                attack_path.pop(field)
    return compatible
