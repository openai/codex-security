#!/usr/bin/env python3
"""Project canonical Codex Security scan JSON into the standard reports."""

from __future__ import annotations

import argparse
import re
from collections import Counter
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
REPORTABLE_SEVERITIES = {"critical", "high", "medium", "low"}
DISPOSITION_LABELS = {
    "reported": "Reported",
    "no_issue_found": "No issue found",
    "rejected": "Rejected",
    "not_applicable": "Not applicable",
    "needs_follow_up": "Needs follow-up",
}
WRITEUP_REPORT_PATH_RE = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")


class ReportProjectionError(ValueError):
    """Raised when a canonical scan cannot be projected into a valid report."""


def _text(value: Any, fallback: str) -> str:
    candidate = value if isinstance(value, str) and value.strip() else fallback
    normalized = " ".join(candidate.split())
    if not normalized:
        return ""
    if re.match(r"^(?:#{1,6}\s|[-*+]\s|>\s|```|\d+\.\s|\|)", normalized):
        normalized = f"Text: {normalized}"
    rendered: list[str] = []
    cursor = 0
    for match in re.finditer(r"(?<!`)`([^`\n]+)`(?!`)", normalized):
        rendered.append(_escape_markdown_text(normalized[cursor : match.start()]))
        rendered.append(f"`{match.group(1)}`")
        cursor = match.end()
    rendered.append(_escape_markdown_text(normalized[cursor:]))
    return "".join(rendered)


def _escape_markdown_text(value: str) -> str:
    return re.sub(r"([\\`*\[\]<>])", r"\\\1", value)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = _text(item, "")
        if text:
            normalized.append(text)
    return normalized


def _cell(value: Any) -> str:
    return _text(value, "none").replace("|", "\\|").replace("\n", "<br>")


def _link_label(value: Any, fallback: str) -> str:
    return _cell(value) or _cell(fallback)


def _deep_report_id(finding: dict[str, Any]) -> str:
    extensions = finding.get("extensions")
    if isinstance(extensions, dict):
        report_id = extensions.get("reportId")
        if isinstance(report_id, str) and report_id.strip():
            return report_id
        ledger_row_id = extensions.get("ledgerRowId")
        if isinstance(ledger_row_id, str) and ledger_row_id.strip():
            return ledger_row_id
    identity = finding.get("identity")
    if isinstance(identity, dict):
        instance = identity.get("instance")
        if isinstance(instance, str) and instance.strip():
            return instance
    occurrence_id = finding.get("occurrenceId")
    return (
        occurrence_id
        if isinstance(occurrence_id, str) and occurrence_id.strip()
        else "Unidentified report"
    )


def _deep_candidate_id(finding: dict[str, Any]) -> str:
    extensions = finding.get("extensions")
    if isinstance(extensions, dict):
        candidate_id = extensions.get("candidateId")
        if isinstance(candidate_id, str) and candidate_id.strip():
            return candidate_id
    return _deep_report_id(finding)


def _has_deep_child_metadata(finding: dict[str, Any]) -> bool:
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return False
    return any(
        isinstance(extensions.get(field), str) and extensions[field].strip()
        for field in ("candidateId", "reportId")
    )


def _uses_deep_presentation(coverage: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
    if coverage.get("mode") == "deep_repository":
        return True
    if coverage.get("mode") != "scoped_path":
        return False
    # Scoped deep scans can arrive as scoped_path artifacts. The child ids are
    # the stable deep-scan signal; ordinary scoped scans do not emit them.
    return any(_has_deep_child_metadata(finding) for finding in findings)


def _deep_title_parts(finding: dict[str, Any]) -> tuple[str, str | None]:
    title = finding.get("title")
    if not isinstance(title, str):
        return "Untitled finding", None
    normalized = " ".join(title.split())
    match = re.fullmatch(r"(.+?)\s+\[([^\[\]\n]+)\]", normalized)
    if match is None:
        return normalized, None
    annotation = match.group(2)
    extensions = finding.get("extensions")
    recognized_ids = [_deep_report_id(finding)]
    if isinstance(extensions, dict):
        ledger_row_id = extensions.get("ledgerRowId")
        if isinstance(ledger_row_id, str) and ledger_row_id.strip():
            recognized_ids.append(ledger_row_id)
    if any(
        annotation == report_id or annotation.startswith(f"{report_id};")
        for report_id in recognized_ids
    ):
        return match.group(1), annotation
    return normalized, None


def _deep_finding_title(finding: dict[str, Any]) -> str:
    return _deep_title_parts(finding)[0]


def _deep_finding_groups(
    findings: list[dict[str, Any]], writeup_paths: list[str | None]
) -> list[list[tuple[int, dict[str, Any], str | None]]]:
    groups: dict[str, list[tuple[int, dict[str, Any], str | None]]] = {}
    for number, (finding, report_path) in enumerate(zip(findings, writeup_paths, strict=True), 1):
        groups.setdefault(_deep_candidate_id(finding), []).append((number, finding, report_path))
    return list(groups.values())


def _deep_group_titles(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    titles: list[str] = []
    for _, finding, _ in group:
        title = _cell(_deep_finding_title(finding))
        if title not in titles:
            titles.append(title)
    return "<br>".join(titles)


def _deep_group_levels(
    group: list[tuple[int, dict[str, Any], str | None]],
    field: str,
    order: dict[str, int],
) -> str:
    levels = {finding[field]["level"] for _, finding, _ in group}
    return "<br>".join(sorted(levels, key=lambda level: order.get(level, len(order))))


def _deep_group_report_labels(
    group: list[tuple[int, dict[str, Any], str | None]],
) -> list[str]:
    report_ids = [_deep_report_id(finding) for _, finding, _ in group]
    report_id_counts = Counter(report_ids)
    labels = [
        (_deep_title_parts(finding)[1] if report_id_counts[report_id] > 1 else report_id)
        or report_id
        for report_id, (_, finding, _) in zip(report_ids, group, strict=True)
    ]
    label_counts = Counter(labels)
    return [
        (
            finding.get("identity", {}).get("instance")
            if label_counts[label] > 1 and isinstance(finding.get("identity"), dict)
            else label
        )
        or _deep_report_id(finding)
        for label, (_, finding, _) in zip(labels, group, strict=True)
    ]


def _deep_group_report_links(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    labels = _deep_group_report_labels(group)
    return "<br>".join(
        f"[{_link_label(label, 'Unidentified report')}](#finding-{number})"
        for label, (number, _, _) in zip(labels, group, strict=True)
    )


def _deep_group_writeup_links(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    labels = _deep_group_report_labels(group)
    links: list[str] = []
    for label, (_, _, report_path) in zip(labels, group, strict=True):
        report_id = _link_label(label, "Unidentified report")
        links.append(
            f"[Open {report_id}]({report_path})" if report_path else f"{report_id}: inline below"
        )
    return "<br>".join(links)


def _writeup_report_path(finding: dict[str, Any]) -> str | None:
    writeup = finding.get("writeup")
    if writeup is None:
        return None
    if not isinstance(writeup, dict):
        raise ReportProjectionError("finding writeup must be an object")
    report_path = writeup.get("reportPath")
    if not isinstance(report_path, str) or not WRITEUP_REPORT_PATH_RE.fullmatch(report_path):
        raise ReportProjectionError("finding writeup has an invalid reportPath")
    return report_path


def _hardening_portfolio_path(scan: dict[str, Any]) -> str | None:
    hardening = scan.get("hardening")
    if hardening is None:
        return None
    if not isinstance(hardening, dict):
        raise ReportProjectionError("scan hardening must be an object")
    portfolio_path = hardening.get("portfolioPath")
    if portfolio_path != "hardening/hardening.md":
        raise ReportProjectionError("scan hardening has an invalid portfolioPath")
    return portfolio_path


def _bullets(items: list[str], fallback: str) -> list[str]:
    return [f"- {item}" for item in (items or [fallback])]


def _code_evidence_catalog(finding: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog: dict[str, dict[str, Any]] = {}
    for key in ("codeEvidence", "code_evidence"):
        raw = finding.get(key, [])
        if not isinstance(raw, list):
            continue
        for item in raw:
            if (
                isinstance(item, dict)
                and isinstance(item.get("id"), str)
                and isinstance(item.get("code"), str)
                and item["code"].strip()
            ):
                catalog.setdefault(item["id"], item)
    return catalog


def _section_code_evidence(
    finding: dict[str, Any], *sections: dict[str, Any]
) -> list[dict[str, Any]]:
    catalog = _code_evidence_catalog(finding)
    resolved: list[dict[str, Any]] = []
    for section in sections:
        for key in ("evidenceRefs", "evidence_refs"):
            refs = section.get(key, [])
            if isinstance(refs, str):
                refs = [refs]
            if isinstance(refs, list):
                resolved.extend(
                    catalog[ref] for ref in refs if isinstance(ref, str) and ref in catalog
                )
        for key in ("codeEvidence", "code_evidence"):
            embedded = section.get(key, [])
            if isinstance(embedded, list):
                resolved.extend(
                    item
                    for item in embedded
                    if isinstance(item, dict)
                    and isinstance(item.get("code"), str)
                    and item["code"].strip()
                )
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in resolved:
        key = (str(item.get("id", "")), item["code"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def merged_root_cause(value: dict[str, Any]) -> tuple[str | None, Any]:
    keys = [key for key in ("rootCause", "root_cause") if key in value]
    if not keys:
        return None, None
    if len(keys) == 1:
        detail = value[keys[0]]
        return keys[0], detail if isinstance(detail, (str, dict)) else None
    details: list[dict[str, Any]] = []
    for key in keys:
        detail = value[key]
        if isinstance(detail, str):
            details.append({"summary": detail})
        elif isinstance(detail, dict):
            details.append(detail)
        elif detail is not None:
            continue
    if not details:
        return keys[0], None

    merged: dict[str, Any] = {}
    text_fields = {
        "cause",
        "code",
        "description",
        "detail",
        "explanation",
        "rationale",
        "summary",
        "why",
    }
    for detail in details:
        for field, item in detail.items():
            if field in (
                "evidenceRefs",
                "evidence_refs",
                "codeEvidence",
                "code_evidence",
                "language",
            ):
                continue
            if field in text_fields and (not isinstance(item, str) or not item.strip()):
                continue
            current = merged.get(field)
            if (
                field not in merged
                or current in (None, "", [], {})
                or (isinstance(current, str) and not current.strip())
            ):
                merged[field] = item

    evidence_values = [
        detail[field]
        for detail in details
        for field in ("evidenceRefs", "evidence_refs")
        if field in detail
    ]
    if evidence_values:
        merged["evidenceRefs"] = list(
            dict.fromkeys(
                item
                for evidence in evidence_values
                for item in (evidence if isinstance(evidence, list) else [evidence])
                if isinstance(item, str)
            )
        )

    embedded_evidence = [
        item
        for detail in details
        for field in ("codeEvidence", "code_evidence")
        for item in (detail.get(field, []) if isinstance(detail.get(field), list) else [])
    ]
    if embedded_evidence:
        merged["codeEvidence"] = embedded_evidence

    code = merged.get("code")
    matching_details = (
        details
        if not isinstance(code, str) or not code.strip()
        else [detail for detail in details if detail.get("code") == code]
    )
    language = next(
        (
            detail["language"]
            for detail in matching_details
            if isinstance(detail.get("language"), str) and detail["language"].strip()
        ),
        None,
    )
    if language is not None:
        merged["language"] = language
    return keys[0], merged


def _root_cause_code_evidence(
    finding: dict[str, Any], root_cause: dict[str, Any]
) -> list[dict[str, Any]]:
    evidence = _section_code_evidence(finding, root_cause)
    legacy_code = root_cause.get("code")
    if not isinstance(legacy_code, str) or not legacy_code.strip():
        return evidence
    if any(item["code"] == legacy_code for item in evidence):
        return evidence
    root_location = next(
        (
            location
            for location in finding.get("locations", [])
            if isinstance(location, dict) and location.get("role") == "root_control"
        ),
        {},
    )
    return [
        *evidence,
        {
            "code": legacy_code,
            "label": "Broken control",
            "language": root_cause.get("language", ""),
            "location": root_location,
        },
    ]


def _code_evidence_location(item: dict[str, Any]) -> str:
    location = item.get("location")
    if isinstance(location, str):
        return location
    if isinstance(location, dict):
        item = location
    path = item.get("path")
    start = item.get("startLine")
    end = item.get("endLine", start)
    if not isinstance(path, str) or not path:
        return ""
    if not isinstance(start, int):
        return path
    return f"{path}:{start}" if end == start else f"{path}:{start}-{end}"


def _code_fence(code: str) -> str:
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", code)), default=0)
    return "`" * max(3, longest_run + 1)


def _code_evidence_lines(evidence: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(evidence):
        label = _text(item.get("label"), f"Code evidence {index + 1}")
        location = _text(_code_evidence_location(item), "")
        explanation = _text(item.get("explanation"), "")
        language = item.get("language") if isinstance(item.get("language"), str) else ""
        language = language if re.fullmatch(r"[A-Za-z0-9_+.-]*", language) else ""
        code = item["code"]
        fence = _code_fence(code)
        heading = f"**{label}**"
        if location:
            heading += f" — `{location}`"
        lines.extend(["", heading])
        if explanation:
            lines.extend(["", explanation])
        lines.extend(["", f"{fence}{language}", code, fence])
    return lines


def _severity_mix(findings: list[dict[str, Any]]) -> str:
    counts = Counter(finding["severity"]["level"] for finding in findings)
    return (
        ", ".join(f"{level}: {counts[level]}" for level in SEVERITY_ORDER if counts[level])
        or "none"
    )


def _confidence_mix(findings: list[dict[str, Any]]) -> str:
    counts = Counter(finding["confidence"]["level"] for finding in findings)
    return (
        ", ".join(
            f"{level}: {counts[level]}" for level in ("high", "medium", "low") if counts[level]
        )
        or "none"
    )


def _locations(finding: dict[str, Any]) -> str:
    rendered = []
    for location in finding["locations"]:
        start = location["startLine"]
        end = location.get("endLine", start)
        suffix = f":{start}" if end == start else f":{start}-{end}"
        rendered.append(f"{location['path']}{suffix}")
    return ", ".join(rendered)


def _finding_sort_key(finding: dict[str, Any]) -> tuple[int, str, str]:
    return (
        SEVERITY_ORDER.get(finding["severity"]["level"], len(SEVERITY_ORDER)),
        finding.get("occurrenceId", ""),
        finding["title"],
    )


def _target_scope_lines(target: dict[str, Any]) -> list[str]:
    lines = [
        f"- Target kind: {_text(target.get('kind'), 'not recorded')}",
        f"- Target ID: {_text(target.get('targetId'), 'not recorded')}",
    ]
    base_revision = _text(target.get("baseRevision"), "")
    head_revision = _text(target.get("headRevision"), "")
    if base_revision or head_revision:
        lines.append(
            f"- Revision range: {base_revision or 'unknown'}...{head_revision or 'unknown'}"
        )
    revision = _text(target.get("revision"), "")
    if revision:
        lines.append(f"- Revision: {revision}")
    snapshot_digest = _text(target.get("snapshotDigest"), "")
    if snapshot_digest:
        lines.append(f"- Snapshot digest: {snapshot_digest}")
    return lines


def _surface_notes(surface: dict[str, Any]) -> str:
    notes = surface.get("notes", "No additional canonical notes were recorded.")
    receipt_refs = surface.get("receiptRefs", [])
    if not isinstance(receipt_refs, list) or not receipt_refs:
        return _cell(notes)
    evidence = ", ".join(item for item in receipt_refs if isinstance(item, str))
    if not evidence:
        return _cell(notes)
    return _cell(f"{notes} Evidence: {evidence}")


def _finding_section(number: int, finding: dict[str, Any]) -> list[str]:
    validation = finding.get("validation") if isinstance(finding.get("validation"), dict) else {}
    _, raw_root_cause = merged_root_cause(finding)
    root_cause = raw_root_cause if isinstance(raw_root_cause, dict) else {}
    attack_path = finding.get("attackPath") if isinstance(finding.get("attackPath"), dict) else {}
    dataflow_sections = [
        {"summary": value} if isinstance(value, str) else value
        for key in ("dataFlow", "dataflow", "data_flow")
        if isinstance((value := attack_path.get(key)), (str, dict))
    ]
    dataflow: dict[str, Any] = {}
    for key in ("summary", "source", "sink", "outcome"):
        value = next(
            (
                section[key]
                for section in dataflow_sections
                if key in section and isinstance(section[key], str) and section[key].strip()
            ),
            None,
        )
        if value is not None:
            dataflow[key] = value
    transformations = list(
        dict.fromkeys(
            transformation
            for section in dataflow_sections
            for transformation in (
                [section.get("transformations")]
                if isinstance(section.get("transformations"), str)
                else section.get("transformations")
                if isinstance(section.get("transformations"), list)
                else []
            )
            if isinstance(transformation, str) and transformation.strip()
        )
    )
    if transformations:
        dataflow["transformations"] = transformations
    raw_reachability = attack_path.get("reachability")
    reachability = (
        {"summary": raw_reachability}
        if isinstance(raw_reachability, str)
        else raw_reachability
        if isinstance(raw_reachability, dict)
        else {}
    )
    severity = finding["severity"]
    validation_outcomes = [
        (label, text)
        for label, key in (
            ("Status", "status"),
            ("Disposition", "disposition"),
            ("Result", "result"),
        )
        if (text := _text(validation.get(key), ""))
    ]
    validation_summary = _text(
        validation.get("summary"),
        "Validation outcomes are recorded below."
        if validation_outcomes
        else f"{finding['confidence']['rationale']} Validation details were not recorded separately.",
    )
    validation_evidence = _strings(validation.get("evidence"))
    validation_assertions = _strings(validation.get("assertions"))
    validation_counterevidence = _strings(validation.get("counterEvidence"))
    validation_limitations = _strings(validation.get("limitations"))
    root_cause_summary = _text(
        raw_root_cause if isinstance(raw_root_cause, str) else root_cause.get("summary"),
        "",
    )
    root_cause_code_evidence = _root_cause_code_evidence(finding, root_cause)
    validation_code_evidence = _section_code_evidence(finding, validation)
    dataflow_code_evidence = _section_code_evidence(finding, attack_path, *dataflow_sections)
    reachability_code_evidence = _section_code_evidence(finding, reachability)
    dataflow_summary = _text(
        dataflow.get("summary"),
        f"The canonical finding records the affected path at {_locations(finding)}, but no expanded source-to-sink narrative was recorded.",
    )
    reachability_summary = _text(
        reachability.get("summary"),
        _text(
            attack_path.get("summary"),
            "Reachability was not recorded beyond the canonical finding summary and affected locations.",
        ),
    )
    severity_rationale = _text(
        severity.get("rationale"),
        f"The scan assigned {severity['level']} severity; no separate canonical severity rationale was recorded.",
    )
    severity_change = _text(
        severity.get("changeConditions"),
        "Additional runtime or deployment evidence could raise or lower this severity.",
    )
    remediation_tests = _strings(finding.get("remediationTests"))
    preventive_controls = _strings(finding.get("preventiveControls"))
    attack_steps = _strings(attack_path.get("steps"))
    cwes = ", ".join(finding["taxonomy"]["cwe"]) or "none"
    title = _text(finding["title"], "Untitled finding")
    lines = [
        f'<a id="finding-{number}"></a>',
        "",
        f"### [{number}] {title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {_cell(severity['level'])} |",
        f"| Confidence | {_cell(finding['confidence']['level'])} |",
        f"| Confidence rationale | {_cell(finding['confidence']['rationale'])} |",
        f"| Category | {_cell(finding['taxonomy']['category'])} |",
        f"| CWE | {_cell(cwes)} |",
        f"| Affected lines | {_cell(_locations(finding))} |",
        "",
        "#### Summary",
        "",
        _text(finding["summary"], "No canonical finding summary was recorded."),
    ]
    if root_cause_summary or root_cause_code_evidence:
        lines.extend(["", "#### Root Cause", ""])
        if root_cause_summary:
            lines.append(root_cause_summary)
        lines.extend(_code_evidence_lines(root_cause_code_evidence))
    lines.extend(["", "#### Validation", "", validation_summary])
    if validation.get("method"):
        lines.extend(["", f"Validation method: {_text(validation['method'], 'not recorded')}"])
    if validation_outcomes:
        lines.extend(["", *(f"- **{label}:** {value}" for label, value in validation_outcomes)])
    lines.extend(_code_evidence_lines(validation_code_evidence))
    if validation_assertions:
        lines.extend(["", "Assertions:", *_bullets(validation_assertions, "None recorded.")])
    if validation_evidence:
        lines.extend(["", "Evidence:", *_bullets(validation_evidence, "No evidence recorded.")])
    if validation_counterevidence:
        lines.extend(
            [
                "",
                "Counterevidence and remaining uncertainty:",
                *_bullets(validation_counterevidence, "None recorded."),
            ]
        )
    if validation_limitations:
        lines.extend(["", "Limitations:", *_bullets(validation_limitations, "None recorded.")])
    lines.extend(["", "#### Dataflow", "", dataflow_summary])
    if attack_steps:
        lines.extend(["", "Attack steps:", *_bullets(attack_steps, "None recorded.")])
    for label, key in (("Source", "source"), ("Sink", "sink"), ("Outcome", "outcome")):
        if dataflow.get(key):
            lines.extend(["", f"- **{label}:** {_text(dataflow[key], 'not recorded')}"])
    transformations = _strings(dataflow.get("transformations"))
    if transformations:
        lines.extend(["", "Transformations:", *_bullets(transformations, "None recorded.")])
    lines.extend(_code_evidence_lines(dataflow_code_evidence))
    lines.extend(["", "#### Reachability", "", reachability_summary])
    for label, key in (
        ("Attacker", "attacker"),
        ("Entry point", "entrypoint"),
        ("Source", "source"),
        ("Sink", "sink"),
        ("Outcome", "outcome"),
    ):
        if reachability.get(key):
            lines.extend(["", f"- **{label}:** {_text(reachability[key], 'not recorded')}"])
    preconditions = list(
        dict.fromkeys(
            [
                *_strings(attack_path.get("preconditions")),
                *_strings(reachability.get("preconditions")),
            ]
        )
    )
    if preconditions:
        lines.extend(["", "Preconditions:", *_bullets(preconditions, "None recorded.")])
    for label, key in (
        ("Assumptions", "assumptions"),
        ("Existing controls", "controls"),
        ("Blind spots", "blindspots"),
        ("Limitations", "limitations"),
    ):
        values = _strings(attack_path.get(key))
        if values:
            lines.extend(["", f"{label}:", *_bullets(values, "None recorded.")])
    lines.extend(_code_evidence_lines(reachability_code_evidence))
    lines.extend(
        [
            "",
            "#### Severity",
            "",
            f"**{severity['level'].capitalize()}** — {severity_rationale}",
            "",
            severity_change,
        ]
    )
    for label, key in (("Impact", "impact"), ("Likelihood", "likelihood")):
        assessment = attack_path.get(key)
        if isinstance(assessment, str):
            rendered = _text(assessment, "")
            if rendered:
                lines.extend(["", f"**{label} assessment:** {rendered}"])
            continue
        if not isinstance(assessment, dict):
            continue
        details = [
            (detail_label, text)
            for detail_label, detail_key in (
                ("Level", "level"),
                ("Rationale", "rationale"),
                ("Why", "why"),
            )
            if (text := _text(assessment.get(detail_key), ""))
        ]
        if details:
            lines.extend(
                ["", f"{label} assessment:", *(f"- **{name}:** {value}" for name, value in details)]
            )
    lines.extend(
        [
            "",
            "#### Remediation",
            "",
            _text(finding["remediation"], "No canonical remediation was recorded."),
        ]
    )
    if remediation_tests:
        lines.extend(["", "Tests:", *_bullets(remediation_tests, "No tests recorded.")])
    if preventive_controls:
        lines.extend(["", "Preventive controls:", *_bullets(preventive_controls, "None recorded.")])
    return lines


def _linked_finding_section(number: int, finding: dict[str, Any], report_path: str) -> list[str]:
    cwes = ", ".join(finding["taxonomy"]["cwe"]) or "none"
    title = _text(finding["title"], "Untitled finding")
    link = f"[detailed technical write-up]({report_path})"
    lines = [
        f'<a id="finding-{number}"></a>',
        "",
        f"### [{number}] {title}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {_cell(finding['severity']['level'])} |",
        f"| Confidence | {_cell(finding['confidence']['level'])} |",
        f"| Confidence rationale | {_cell(finding['confidence']['rationale'])} |",
        f"| Category | {_cell(finding['taxonomy']['category'])} |",
        f"| CWE | {_cell(cwes)} |",
        f"| Affected lines | {_cell(_locations(finding))} |",
    ]
    for heading in ("Summary", "Validation", "Dataflow", "Reachability", "Severity", "Remediation"):
        lines.extend(["", f"#### {heading}", "", f"See the {link}."])
    return lines


def build_report_markdown(
    manifest: dict[str, Any], findings_document: dict[str, Any], coverage: dict[str, Any]
) -> str:
    scan = manifest["scan"]
    target = scan["target"]
    scope = scan["scope"]
    threat_model = scan.get("threatModel") if isinstance(scan.get("threatModel"), dict) else {}
    findings = sorted(
        (
            finding
            for finding in findings_document["findings"]
            if finding["severity"]["level"] in REPORTABLE_SEVERITIES
        ),
        key=_finding_sort_key,
    )
    writeup_paths = [_writeup_report_path(finding) for finding in findings]
    duplicate_writeup_paths = sorted(
        path
        for path, count in Counter(path for path in writeup_paths if path is not None).items()
        if count > 1
    )
    if duplicate_writeup_paths:
        raise ReportProjectionError(
            "reportable findings have duplicate writeup reportPath values: "
            + ", ".join(duplicate_writeup_paths)
        )
    deep_presentation = _uses_deep_presentation(coverage, findings)
    deep_finding_groups = _deep_finding_groups(findings, writeup_paths) if deep_presentation else []
    hardening_portfolio_path = _hardening_portfolio_path(scan)
    include_paths = _strings(coverage.get("includePaths", scope.get("includePaths", [])))
    exclude_paths = _strings(coverage.get("excludePaths", scope.get("excludePaths", [])))
    limitations = _strings(scope.get("limitations"))
    explicit_exclusions = coverage.get("explicitExclusions", [])
    lines = [
        f"# Security Review: {_text(target['displayName'], 'Unknown target')}",
        "",
        "## Scope",
        "",
        _text(
            scope.get("summary"),
            "The scan was configured for the include paths and exclusions listed below.",
        ),
        "",
        f"- Scan mode: {coverage['mode']}",
        *_target_scope_lines(target),
        f"- Inventory strategy: {coverage['inventoryStrategy']}",
        f"- Included paths: {', '.join(include_paths) or 'none'}",
        f"- Excluded paths: {', '.join(exclude_paths) or 'none'}",
        f"- Runtime or test status: {_text(scope.get('runtimeStatus'), 'not recorded')}",
    ]
    artifacts_reviewed = _strings(scope.get("artifactsReviewed"))
    if artifacts_reviewed:
        lines.extend(["- Artifacts reviewed: " + ", ".join(artifacts_reviewed)])
    context = _text(scope.get("context"), "")
    if context:
        lines.extend([f"- Scan context: {context}"])
    for exclusion in explicit_exclusions:
        if isinstance(exclusion, dict):
            limitations.append(
                f"Excluded {_text(exclusion.get('pattern'), 'unspecified')}: "
                f"{_text(exclusion.get('reason'), 'reason not recorded')}"
            )
    if limitations:
        lines.extend(["", "Limitations and exclusions:", *_bullets(limitations, "None recorded.")])
    summary_count_lines = (
        [
            f"| Reportable DSS findings | {len(deep_finding_groups)} |",
            f"| Report instances | {len(findings)} |",
            f"| Report severity mix | {_severity_mix(findings)} |",
            f"| Report confidence mix | {_confidence_mix(findings)} |",
        ]
        if deep_presentation
        else [
            f"| Reportable findings | {len(findings)} |",
            f"| Severity mix | {_severity_mix(findings)} |",
            f"| Confidence mix | {_confidence_mix(findings)} |",
        ]
    )
    lines.extend(
        [
            "",
            "### Scan Summary",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Scan outcome | {scan.get('status', 'completed')} |",
            *summary_count_lines,
            f"| Coverage | {coverage['completeness']} |",
            f"| Validation mode | {_cell(scope.get('validationMode', 'not recorded'))} |",
            "",
            "Canonical artifacts: `scan-manifest.json`, `findings.json`, and `coverage.json`. This report is a deterministic projection of those files.",
            "",
            "## Threat Model",
            "",
            _text(
                threat_model.get("summary"),
                "No explicit canonical threat-model summary was recorded.",
            ),
        ]
    )
    for heading, key, fallback in (
        ("Assets", "assets", "No assets were recorded."),
        ("Trust Boundaries", "trustBoundaries", "No trust boundaries were recorded."),
        (
            "Attacker Capabilities",
            "attackerCapabilities",
            "No attacker capabilities were recorded.",
        ),
        ("Security Objectives", "securityObjectives", "No security objectives were recorded."),
        ("Assumptions", "assumptions", "No assumptions were recorded."),
    ):
        values = _strings(threat_model.get(key))
        if values:
            lines.extend(["", f"### {heading}", "", *_bullets(values, fallback)])
    lines.extend(["", "## Findings", ""])
    if findings:
        if deep_presentation:
            lines.extend(
                [
                    "| Findings | Reports | Severity | Confidence | Detailed write-up |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for group in deep_finding_groups:
                lines.append(
                    f"| {_deep_group_titles(group)} | {_deep_group_report_links(group)} "
                    f"| {_deep_group_levels(group, 'severity', SEVERITY_ORDER)} "
                    f"| {_deep_group_levels(group, 'confidence', CONFIDENCE_ORDER)} "
                    f"| {_deep_group_writeup_links(group)} |"
                )
        else:
            lines.extend(
                [
                    "| Finding | Severity | Confidence | Detailed write-up |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for number, (finding, report_path) in enumerate(
                zip(findings, writeup_paths, strict=True), 1
            ):
                title = _link_label(finding["title"], "Untitled finding")
                finding_link = f"[{title}](#finding-{number})"
                writeup_link = f"[Open report]({report_path})" if report_path else "inline below"
                lines.append(
                    f"| {finding_link} | {finding['severity']['level']} "
                    f"| {finding['confidence']['level']} | {writeup_link} |"
                )
        lines.extend(
            [
                "",
                "### Confidence Scale",
                "",
                "| Label | Meaning |",
                "| --- | --- |",
                "| high | Direct evidence supports the finding with no material unresolved blocker. |",
                "| medium | Evidence supports a plausible issue, but material runtime or reachability proof remains. |",
                "| low | Evidence is incomplete and the item is retained only for explicit follow-up. |",
            ]
        )
        for number, (finding, report_path) in enumerate(
            zip(findings, writeup_paths, strict=True), 1
        ):
            if report_path is not None:
                lines.extend(["", *_linked_finding_section(number, finding, report_path)])
            else:
                lines.extend(["", *_finding_section(number, finding)])
    else:
        deferred = coverage.get("deferred", [])
        no_source_review = (
            coverage.get("completeness") == "partial"
            and isinstance(deferred, list)
            and any(
                isinstance(item, dict)
                and item.get("reason")
                == "The configured discovery time limit elapsed before any source review completed."
                for item in deferred
            )
        )
        budget_exhausted = (
            coverage.get("completeness") == "partial"
            and isinstance(deferred, list)
            and any(
                isinstance(item, dict)
                and isinstance(item.get("reason"), str)
                and (
                    item["reason"]
                    == "Validation was deferred because the scan reached its cost limit."
                    or item["reason"].startswith(
                        "Validation was deferred because the scan reached its cost limit: "
                    )
                )
                for item in deferred
            )
        )
        stopped = manifest.get("scan", {}).get("status") in {
            "failed",
            "canceled",
            "interrupted",
        }
        lines.extend(
            [
                "### No findings",
                "",
                (
                    "No findings were retained before the scan stopped. "
                    "The scan did not complete. No vulnerability conclusion can be drawn."
                    if stopped
                    else (
                        "No source review completed before the configured time limit. "
                        "No vulnerability conclusion can be drawn."
                        if no_source_review
                        else (
                            "No findings were validated before the scan reached its cost limit. "
                            "Review the deferred candidates in Open Questions And Follow Up."
                            if budget_exhausted
                            else "No reportable findings survived the canonical discovery, validation, "
                            "and reportability gates."
                        )
                    )
                ),
            ]
        )
    if hardening_portfolio_path is not None:
        lines.extend(
            [
                "",
                "## Structural Hardening",
                "",
                "The scan also produced derived, unsealed design guidance based on the complete finding collection. These proposals describe options and tradeoffs; they do not indicate that any finding has been remediated.",
                "",
                f"[Open the structural hardening portfolio]({hardening_portfolio_path})",
            ]
        )
    surfaces = coverage.get("surfaces", [])
    if surfaces:
        lines.extend(
            [
                "",
                "## Reviewed Surfaces",
                "",
                "| Surface | Risk Area | Outcome | Notes |",
                "| --- | --- | --- | --- |",
            ]
        )
        for surface in surfaces:
            if not isinstance(surface, dict):
                continue
            lines.append(
                "| "
                + " | ".join(
                    (
                        _cell(surface.get("label", surface.get("id"))),
                        _cell(surface.get("riskArea", "not recorded")),
                        _cell(
                            DISPOSITION_LABELS.get(
                                surface.get("disposition"), surface.get("disposition")
                            )
                        ),
                        _surface_notes(surface),
                    )
                )
                + " |"
            )
    open_questions = coverage.get("openQuestions", [])
    questions = list(open_questions) if isinstance(open_questions, list) else []
    deferred = coverage.get("deferred", [])
    if isinstance(deferred, list):
        questions.extend(
            {
                "question": item.get("reason", "Deferred review requires follow-up."),
                "followUpPrompt": " ".join(
                    (
                        f"Review deferred unit {item.get('id', 'unknown')} and close its stated proof gap.",
                        f"Paths: {', '.join(item.get('paths', []))}." if item.get("paths") else "",
                        (
                            f"Surfaces: {', '.join(item.get('surfaceIds', []))}."
                            if item.get("surfaceIds")
                            else ""
                        ),
                    )
                ).strip(),
            }
            for item in deferred
            if isinstance(item, dict)
        )
    if questions:
        lines.extend(["", "## Open Questions And Follow Up", ""])
        for question in questions:
            if not isinstance(question, dict):
                continue
            lines.append(f"- {_text(question.get('question'), 'Unspecified open question.')}")
            prompt = _text(question.get("followUpPrompt"), "")
            if prompt:
                lines.append(f"  - Follow-up prompt: {prompt}")
    return "\n".join(lines).rstrip() + "\n"


def generate_report_markdown(
    manifest: dict[str, Any],
    findings: dict[str, Any],
    coverage: dict[str, Any],
) -> bytes:
    return build_report_markdown(manifest, findings, coverage).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
