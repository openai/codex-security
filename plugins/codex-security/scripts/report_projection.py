#!/usr/bin/env python3
"""Project canonical Codex Security scan JSON into the standard reports."""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections import Counter
from collections.abc import Iterator
from itertools import chain
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from candidate_identity import (
    CandidateKey,
    coverage_candidate_key,
    coverage_owner,
    finding_candidate_id,
    finding_candidate_key,
    unresolved_candidate_rows,
    unresolved_candidates,
)

SARIF_SECURITY_SCORES = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "informational": 0.0,
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
REPORTABLE_SEVERITIES = {"critical", "high", "medium", "low"}
THREAT_MODEL_SECTIONS = (
    ("Assets", "assets"),
    ("Trust Boundaries", "trustBoundaries"),
    ("Attacker Capabilities", "attackerCapabilities"),
    ("Security Objectives", "securityObjectives"),
    ("Assumptions", "assumptions"),
)
DISPOSITION_LABELS = {
    "reported": "Reported",
    "no_issue_found": "No issue found",
    "rejected": "Rejected",
    "not_applicable": "Not applicable",
    "needs_follow_up": "Needs follow-up",
}
WRITEUP_REPORT_PATH_RE = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")
INLINE_CODE_RE = r"(?<!`)`[^`\n]+`(?!`)"
ENTITY_AMP_RE = r"&(?=(?:#[0-9]+|#[xX][0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]*);)"
WWW_LINK_RE = r"(?<![^\s*_~(])(?i:www)\.[^\s<>]+"


class ReportProjectionError(ValueError):
    """Raised when a canonical scan cannot be projected into a valid report."""


def _sarif_label(value: str) -> str:
    words = re.sub(r"[-_./]+", " ", value).split()
    acronyms = {"api", "csrf", "html", "http", "id", "rce", "sql", "ssrf", "url", "xml", "xss"}
    label = " ".join(word.upper() if word.lower() in acronyms else word for word in words)
    return label[:1].upper() + label[1:]


def _sarif_rule(rule_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    name = ": ".join(_sarif_label(part) for part in rule_id.split("."))
    categories = sorted({finding["taxonomy"]["category"] for finding in findings})
    cwes = sorted({cwe for finding in findings for cwe in finding["taxonomy"]["cwe"]})
    tags = {"security", *categories}
    for cwe in cwes:
        match = re.fullmatch(r"CWE-([0-9]+)", cwe, re.IGNORECASE)
        if match and (digits := match[1].lstrip("0")):
            tags.add(f"external/cwe/cwe-{digits.zfill(3)}")
    description = f"{name}. Categories: {', '.join(map(_sarif_label, categories))}."
    if cwes:
        description += f" Weaknesses: {', '.join(cwes)}."
    remediation = "\n\n".join(sorted({finding["remediation"] for finding in findings}))
    properties: dict[str, Any] = {"tags": sorted(tags)}
    # GitHub assigns security severity to the shared rule, not each result.
    score = max(
        finding["severity"].get("score", SARIF_SECURITY_SCORES[finding["severity"]["level"]])
        for finding in findings
    )
    if score > 0:
        properties["security-severity"] = str(score)
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": name},
        "fullDescription": {"text": description},
        "help": {
            "text": f"{description}\n\nRemediation:\n\n{remediation}",
            "markdown": f"{description}\n\n## Remediation\n\n{remediation}",
        },
        "properties": properties,
    }


def _sarif_finding_message(finding: dict[str, Any]) -> str:
    taxonomy = finding["taxonomy"]
    details = [
        finding["title"],
        finding["summary"],
        f"Severity: {finding['severity']['level']}",
        f"Category: {_sarif_label(taxonomy['category'])}",
    ]
    if taxonomy["cwe"]:
        details.append(f"Weaknesses: {', '.join(taxonomy['cwe'])}")
    details.append(f"Remediation:\n{finding['remediation']}")
    for key, label in (
        ("remediationTests", "Remediation tests"),
        ("preventiveControls", "Preventive controls"),
    ):
        if finding.get(key):
            details.append(f"{label}:\n" + "\n".join(f"- {item}" for item in finding[key]))
    return "\n\n".join(details)


def _sarif_primary_location(finding: dict[str, Any]) -> dict[str, Any]:
    return next(
        (location for location in finding["locations"] if location.get("role") == "root_control"),
        finding["locations"][0],
    )


def csv_cell(value: Any) -> Any:
    if isinstance(value, str) and (
        value.startswith(("'", "\t", "\r", "\n"))
        or value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))
    ):
        return f"'{value}"
    return value


def _csv_candidate_id(finding: dict[str, Any]) -> str | None:
    candidate_id = finding_candidate_id(finding)
    if candidate_id is not None:
        return candidate_id
    # Preserve literal CSV metadata, such as FEFF, that is not a canonical identity.
    for metadata, fields in (
        (finding.get("provenance"), ("candidateId",)),
        (finding.get("extensions"), ("candidateId", "reportId", "ledgerRowId")),
    ):
        if isinstance(metadata, dict):
            for field in fields:
                value = metadata.get(field)
                if isinstance(value, str) and value.strip():
                    return value
    return None


def finding_csv_columns(deep_scan: bool) -> tuple[str, ...]:
    return (
        "occurrence_id",
        "finding_id",
        *(("candidate_id",) if deep_scan else ()),
        "title",
        "summary",
        "severity",
        "confidence",
        "status",
        "close_reason",
        "note",
        "remediation",
        "path",
        "start_line",
        "end_line",
    )


def build_csv_projection(findings: dict[str, Any], coverage: dict[str, Any]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    deep_scan = uses_deep_presentation(coverage, findings["findings"])
    writer.writerow(finding_csv_columns(deep_scan))
    for finding in findings["findings"]:
        location = _sarif_primary_location(finding)
        writer.writerow(
            (
                csv_cell(finding["occurrenceId"]),
                csv_cell(finding["findingId"]),
                *((csv_cell(_csv_candidate_id(finding)),) if deep_scan else ()),
                csv_cell(finding["title"]),
                csv_cell(finding["summary"]),
                csv_cell(finding["severity"]["level"]),
                csv_cell(finding["confidence"]["level"]),
                "open",
                "",
                "",
                csv_cell(finding["remediation"]),
                csv_cell(location["path"]),
                location["startLine"],
                location.get("endLine", location["startLine"]),
            )
        )
    return output.getvalue().encode("utf-8")


def markdown_threat_model_content(model: dict[str, Any]) -> str | None:
    """Return nonblank authored content for a Markdown model, otherwise None."""
    content = model.get("content")
    if model.get("format") == "markdown" and isinstance(content, str) and content.strip():
        return content
    return None


def _escape_markdown(value: str) -> str:
    # Locate whole URLs before matching code spans: a URL can contain backticks.
    urls = [match.span() for match in re.finditer(WWW_LINK_RE, value)]
    # Preserve protocol-relative and fuzzy links without a domain/TLD table.
    for match in re.finditer(r"[^\s<>]+", value):
        token = match[0]
        dot = token.split("/", 1)[0].find(".")
        if "//" in token or (dot >= 0 and re.search(r"[/?#]", token[dot + 1 :])):
            urls.append(match.span())
    punctuation = r"[\\`*_\[\]<>]|" + ENTITY_AMP_RE
    pattern = f"(?P<code>{INLINE_CODE_RE})|{punctuation}"

    def escape(match: re.Match[str]) -> str:
        if match.lastgroup == "code":
            return match[0]
        # GFM autolinks retain backslashes literally, including in query strings.
        if match[0] == "&" and any(start <= match.start() < end for start, end in urls):
            return "&"
        return "\\" + match[0]

    return re.sub(pattern, escape, value)


def _text(value: Any, fallback: str) -> str:
    candidate = value if isinstance(value, str) and value.strip() else fallback
    normalized = " ".join(candidate.split())
    if re.match(r"^(?:#{1,6}\s|[-*+]\s|>\s|```|~~~|\d+[.)]\s|\|)", normalized):
        normalized = f"Text: {normalized}"
    return _escape_markdown(normalized)


def _string_values(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        yield from (item for item in value if isinstance(item, str))


def _strings(value: Any) -> list[str]:
    return [text for item in _string_values(value) if (text := _text(item, ""))]


def _path_label(value: str, *, ensure_ascii: bool = False) -> str:
    if "," in value or value != " ".join(value.split()) or any(ord(c) < 32 for c in value):
        quoted = json.dumps(value, ensure_ascii=ensure_ascii)
        return "".join(c if c.isprintable() else json.dumps(c)[1:-1] for c in quoted)
    return value


def _path_text(value: str, *, ensure_ascii: bool = False) -> str:
    label = _path_label(value, ensure_ascii=ensure_ascii)
    if label != value or re.search(ENTITY_AMP_RE, value):
        marker = _code_fence(label, minimum=1)
        padding = " " if label.startswith("`") or label.endswith("`") else ""
        return f"{marker}{padding}{label}{padding}{marker}"
    return re.sub(r"([\\`*_\[\]<>])", r"\\\1", value)


def _cell(value: Any) -> str:
    return _text(value, "none").replace("|", "\\|").replace("\n", "<br>")


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


def _has_deep_child_metadata(finding: dict[str, Any]) -> bool:
    candidate = finding_candidate_key(finding)
    if candidate is not None and candidate[0] is not None:
        return True
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return False
    return any(
        isinstance(extensions.get(field), str) and extensions[field].strip()
        for field in ("candidateId", "reportId")
    )


def uses_deep_presentation(coverage: dict[str, Any], findings: list[dict[str, Any]]) -> bool:
    """Select deep-report formatting for repository scans in deep mode and scoped scans with deep-child metadata."""
    if coverage.get("mode") == "deep_repository":
        return True
    if coverage.get("mode") != "scoped_path":
        return False
    # Standard scans also use candidate IDs. Deep children add worker ownership
    # or the legacy extension identifiers to scoped_path artifacts.
    return any(_has_deep_child_metadata(finding) for finding in findings)


def _deep_title_parts(finding: dict[str, Any], report_id: str) -> tuple[str, str | None]:
    title = finding.get("title")
    if not isinstance(title, str):
        return "Untitled finding", None
    normalized = " ".join(title.split())
    match = re.fullmatch(r"(.+?)\s+\[([^\[\]\n]+)\]", normalized)
    if match is None:
        return normalized, None
    annotation = match.group(2)
    extensions = finding.get("extensions")
    recognized_ids = [report_id]
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


def _deep_group_levels(
    group: list[tuple[int, dict[str, Any], str | None]],
    field: str,
    order: dict[str, int],
) -> str:
    levels = {finding[field]["level"] for _, finding, _ in group}
    return "<br>".join(sorted(levels, key=lambda level: order.get(level, len(order))))


def _deep_group_row(group: list[tuple[int, dict[str, Any], str | None]]) -> str:
    report_ids = [_deep_report_id(finding) for _, finding, _ in group]
    report_counts = Counter(report_ids)
    titles = []
    labels = []
    for report_id, (_, finding, _) in zip(report_ids, group, strict=True):
        title, annotation = _deep_title_parts(finding, report_id)
        titles.append(_cell(title))
        labels.append(annotation if report_counts[report_id] > 1 and annotation else report_id)

    label_counts = Counter(labels)
    report_links = []
    writeup_links = []
    for report_id, label, (number, finding, path) in zip(report_ids, labels, group, strict=True):
        identity = finding.get("identity")
        if label_counts[label] > 1 and isinstance(identity, dict):
            label = identity.get("instance") or report_id
        label = _cell(label)
        report_links.append(f"[{label}](#finding-{number})")
        writeup_links.append(f"[Open {label}]({path})" if path else f"{label}: inline below")
    return (
        f"| {'<br>'.join(dict.fromkeys(titles))} | {'<br>'.join(report_links)} "
        f"| {_deep_group_levels(group, 'severity', SEVERITY_ORDER)} "
        f"| {_deep_group_levels(group, 'confidence', CONFIDENCE_ORDER)} "
        f"| {'<br>'.join(writeup_links)} |"
    )


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


def _bullet_section(heading: str, items: list[str]) -> list[str]:
    return ["", heading, *(f"- {item}" for item in items)] if items else []


def code_evidence_rows(*catalogs: Any) -> Iterator[dict[str, Any]]:
    """Yield evidence objects with nonblank code in their original order."""
    for items in catalogs:
        if isinstance(items, list):
            yield from (
                item
                for item in items
                if isinstance(item, dict)
                and isinstance(item.get("code"), str)
                and item["code"].strip()
            )


def embedded_code_evidence(section: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Collect code evidence from both supported field spellings."""
    return code_evidence_rows(section.get("codeEvidence"), section.get("code_evidence"))


def _code_evidence_catalog(finding: dict[str, Any]) -> dict[str, dict[str, Any]]:
    catalog = {}
    for item in embedded_code_evidence(finding):
        if isinstance(item.get("id"), str):
            catalog.setdefault(item["id"], item)
    return catalog


def _section_code_evidence(
    catalog: dict[str, dict[str, Any]], *sections: dict[str, Any]
) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for section in sections:
        referenced = (
            catalog[ref]
            for key in ("evidenceRefs", "evidence_refs")
            for ref in _string_values(section.get(key))
            if ref in catalog
        )
        for item in chain(referenced, embedded_code_evidence(section)):
            unique.setdefault((str(item.get("id", "")), item["code"]), item)
    return list(unique.values())


def merged_root_cause(value: dict[str, Any]) -> tuple[str | None, Any]:
    """Return the first recorded root-cause field name and its merged detail, or (None, None) if absent."""
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
            dict.fromkeys(item for evidence in evidence_values for item in _string_values(evidence))
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
    finding: dict[str, Any], root_cause: dict[str, Any], catalog: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    evidence = _section_code_evidence(catalog, root_cause)
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
        return " ".join(location.split())
    if isinstance(location, dict):
        item = location
    path = item.get("path")
    start = item.get("startLine", item.get("start_line"))
    end = item.get("endLine", item.get("end_line", start))
    if not isinstance(path, str) or not path:
        return ""
    path = _path_label(path)
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        return path
    if not isinstance(end, int) or isinstance(end, bool) or end <= start:
        return f"{path}:{start}"
    return f"{path}:{start}-{end}"


def _code_fence(code: str, minimum: int = 3) -> str:
    longest_run = max((len(match.group(0)) for match in re.finditer(r"`+", code)), default=0)
    return "`" * max(minimum, longest_run + 1)


def _code_evidence_lines(evidence: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(evidence):
        label = _text(item.get("label"), f"Code evidence {index + 1}")
        location = _code_evidence_location(item)
        explanation = _text(item.get("explanation"), "")
        language = item.get("language") if isinstance(item.get("language"), str) else ""
        language = language if re.fullmatch(r"[A-Za-z0-9_+.-]*", language) else ""
        code = item["code"]
        fence = _code_fence(code)
        heading = f"**{label}**"
        if location:
            marker = _code_fence(location, minimum=1)
            padding = " " if location.startswith("`") or location.endswith("`") else ""
            heading += f" — {marker}{padding}{location}{padding}{marker}"
        lines.extend(["", heading])
        if explanation:
            lines.extend(["", explanation])
        lines.extend(["", f"{fence}{language}", code, fence])
    return lines


def _level_mix(findings: list[dict[str, Any]], field: str, order: dict[str, int]) -> str:
    counts = Counter(finding[field]["level"] for finding in findings)
    return ", ".join(f"{level}: {counts[level]}" for level in order if counts[level]) or "none"


def _locations(finding: dict[str, Any]) -> str:
    rendered = []
    for location in finding["locations"]:
        start = location["startLine"]
        end = location.get("endLine", start)
        suffix = f":{start}" if end == start else f":{start}-{end}"
        rendered.append(f"{_path_text(location['path'])}{suffix}")
    return ", ".join(rendered)


def _candidate_details(candidate: dict[str, Any], saved: dict[str, Any]) -> tuple[str, str]:
    """Render the evidence shapes saved by discovery and finding validation."""
    locations = []
    evidence = []
    validation = candidate.get("validation")
    for value in (
        candidate.get("evidence"),
        validation.get("evidence") if isinstance(validation, dict) else None,
    ):
        evidence.extend(
            item
            for item in (value if isinstance(value, list) else [value])
            if isinstance(item, str) and item.strip()
        )
    for field in ("locations", "sourceEvidence", "codeEvidence", "code_evidence", "evidence"):
        items = candidate.get(field, [])
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            if location := _code_evidence_location(item):
                locations.append(location)
            if field != "locations":
                evidence.extend(
                    value
                    for key in ("explanation", "code")
                    if isinstance(value := item.get(key), str) and value.strip()
                )
    paths = saved.get("paths", [])
    return (
        ", ".join(dict.fromkeys(locations))
        or ", ".join(path for path in paths if isinstance(path, str)),
        "; ".join(dict.fromkeys(evidence)) or candidate.get("summary", ""),
    )


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


def _remediation_section(finding: dict[str, Any]) -> list[str]:
    remediation = _text(finding.get("remediation"), "No canonical remediation was recorded.")
    lines = ["", "#### Remediation", "", remediation]
    seen = {remediation}
    originals: list[tuple[str, dict[str, Any]]] = []
    pending = [("finding", finding)]
    seen_findings: set[int] = set()
    while pending:
        source_id, original = pending.pop()
        if id(original) in seen_findings:
            continue
        seen_findings.add(id(original))
        originals.append((source_id, original))
        provenance = original.get("provenance")
        if not isinstance(provenance, dict):
            continue
        previous = provenance.get("previousFindings")
        if isinstance(previous, list):
            pending.extend(
                (source_id, item) for item in reversed(previous) if isinstance(item, dict)
            )
        sources = provenance.get("sourceFindings")
        if isinstance(sources, list):
            pending.extend(
                (_text(source.get("id"), "finding"), source["finding"])
                for source in reversed(sources)
                if isinstance(source, dict) and isinstance(source.get("finding"), dict)
            )
    for source_id, original in originals[1:]:
        text = _text(original.get("remediation"), "")
        if text and text not in seen:
            seen.add(text)
            lines.extend(["", f"Source {source_id}: {text}"])
    for field, label in (
        ("remediationTests", "Tests"),
        ("preventiveControls", "Preventive controls"),
    ):
        values = list(
            dict.fromkeys(
                value for _, original in originals for value in _strings(original.get(field))
            )
        )
        lines.extend(_bullet_section(f"{label}:", values))
    return lines


def _finding_header(number: int, finding: dict[str, Any]) -> list[str]:
    cwes = ", ".join(finding["taxonomy"]["cwe"]) or "none"
    title = _text(finding["title"], "Untitled finding")
    return [
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
        "| Affected lines | " + _locations(finding).replace("|", "\\|") + " |",
    ]


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
    for section in dataflow_sections:
        for key in ("summary", "source", "sink", "outcome"):
            value = section.get(key)
            if isinstance(value, str) and value.strip():
                dataflow.setdefault(key, value)
    transformations = dict.fromkeys(
        value
        for section in dataflow_sections
        for value in _string_values(section.get("transformations"))
        if value.strip()
    )
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
    root_cause_summary = _text(
        raw_root_cause if isinstance(raw_root_cause, str) else root_cause.get("summary"),
        "",
    )
    catalog = _code_evidence_catalog(finding)
    root_cause_code_evidence = _root_cause_code_evidence(finding, root_cause, catalog)
    validation_code_evidence = _section_code_evidence(catalog, validation)
    dataflow_code_evidence = _section_code_evidence(catalog, attack_path, *dataflow_sections)
    reachability_code_evidence = _section_code_evidence(catalog, reachability)
    dataflow_summary = _text(dataflow.get("summary"), "") or (
        f"The canonical finding records the affected path at {_locations(finding)}, "
        "but no expanded source-to-sink narrative was recorded."
    )
    reachability_summary = _text(reachability.get("summary"), "") or _text(
        attack_path.get("summary"),
        "Reachability was not recorded beyond the canonical finding summary and affected locations.",
    )
    severity_rationale = _text(
        severity.get("rationale"),
        f"The scan assigned {severity['level']} severity; no separate canonical severity rationale was recorded.",
    )
    severity_change = _text(
        severity.get("changeConditions"),
        "Additional runtime or deployment evidence could raise or lower this severity.",
    )
    lines = [
        *_finding_header(number, finding),
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
    for label, key in (
        ("Assertions", "assertions"),
        ("Evidence", "evidence"),
        ("Counterevidence and remaining uncertainty", "counterEvidence"),
        ("Limitations", "limitations"),
    ):
        lines.extend(_bullet_section(f"{label}:", _strings(validation.get(key))))
    lines.extend(["", "#### Dataflow", "", dataflow_summary])
    lines.extend(_bullet_section("Attack steps:", _strings(attack_path.get("steps"))))
    for label, key in (("Source", "source"), ("Sink", "sink"), ("Outcome", "outcome")):
        if dataflow.get(key):
            lines.extend(["", f"- **{label}:** {_text(dataflow[key], 'not recorded')}"])
    lines.extend(
        _bullet_section("Transformations:", [_text(value, "") for value in transformations])
    )
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
            _strings(attack_path.get("preconditions")) + _strings(reachability.get("preconditions"))
        )
    )
    lines.extend(_bullet_section("Preconditions:", preconditions))
    for label, key in (
        ("Assumptions", "assumptions"),
        ("Existing controls", "controls"),
        ("Blind spots", "blindspots"),
        ("Limitations", "limitations"),
    ):
        lines.extend(_bullet_section(f"{label}:", _strings(attack_path.get(key))))
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
    lines.extend(_remediation_section(finding))
    return lines


def _linked_finding_section(number: int, finding: dict[str, Any], report_path: str) -> list[str]:
    link = f"[detailed technical write-up]({report_path})"
    lines = _finding_header(number, finding)
    for heading in ("Summary", "Validation", "Dataflow", "Reachability", "Severity"):
        lines.extend(["", f"#### {heading}", "", f"See the {link}."])
    if any(
        finding.get("provenance", {}).get(field) for field in ("sourceFindings", "previousFindings")
    ):
        lines.extend(_remediation_section(finding))
    else:
        lines.extend(["", "#### Remediation", "", f"See the {link}."])
    return lines


def build_report_markdown(
    manifest: dict[str, Any], findings_document: dict[str, Any], coverage: dict[str, Any]
) -> str:
    """Render findings and review coverage as a Markdown report ending in a newline.

    Args:
        manifest: Scan metadata, target, and scope.
        findings_document: Canonical findings for the scan.
        coverage: Review coverage for older manifests. Newer scans supply review state inline.

    Raises:
        ReportProjectionError: Reportable findings share a writeup path.
    """
    scan = manifest["scan"]
    if "review" in scan and "coverageRef" not in scan:
        from review_state import review_state

        coverage = review_state(scan)
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
    numbered_findings = [
        (number, finding, _writeup_report_path(finding))
        for number, finding in enumerate(findings, 1)
    ]
    writeup_counts = Counter(path for _, _, path in numbered_findings if path is not None)
    duplicate_writeup_paths = sorted(path for path, count in writeup_counts.items() if count > 1)
    if duplicate_writeup_paths:
        raise ReportProjectionError(
            "reportable findings have duplicate writeup reportPath values: "
            + ", ".join(duplicate_writeup_paths)
        )
    deep_presentation = uses_deep_presentation(coverage, findings)
    sealed = scan.get("sealedAt") is not None
    pending_candidates = unresolved_candidates(
        coverage, findings_document["findings"], sealed=sealed
    )
    pending_rows = unresolved_candidate_rows(coverage, findings_document["findings"], sealed=sealed)
    deep_finding_groups: dict[CandidateKey, list[tuple[int, dict[str, Any], str | None]]] = {}
    if deep_presentation:
        for entry in numbered_findings:
            _, finding, _ = entry
            key = finding_candidate_key(finding) or (None, _deep_report_id(finding))
            deep_finding_groups.setdefault(key, []).append(entry)
    hardening_portfolio_path = _hardening_portfolio_path(scan)
    include_paths = [
        _path_text(path) for path in coverage.get("includePaths", scope.get("includePaths", []))
    ]
    exclude_paths = [
        _path_text(path) for path in coverage.get("excludePaths", scope.get("excludePaths", []))
    ]
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
        f"- Included paths: {', '.join(include_paths) or 'none'}",
        f"- Excluded paths: {', '.join(exclude_paths) or 'none'}",
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
    lines.extend(_bullet_section("Limitations and exclusions:", limitations))
    summary_count_lines = (
        [
            f"| Reportable DSS findings | {len(deep_finding_groups)} |",
            f"| Report instances | {len(findings)} |",
            f"| Report severity mix | {_level_mix(findings, 'severity', SEVERITY_ORDER)} |",
            f"| Report confidence mix | {_level_mix(findings, 'confidence', CONFIDENCE_ORDER)} |",
        ]
        if deep_presentation
        else [
            f"| Reportable findings | {len(findings)} |",
            f"| Severity mix | {_level_mix(findings, 'severity', SEVERITY_ORDER)} |",
            f"| Confidence mix | {_level_mix(findings, 'confidence', CONFIDENCE_ORDER)} |",
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
            f"| Unresolved candidates | {len(pending_candidates)} |",
            f"| Validation mode | {_cell(scope.get('validationMode', 'not recorded'))} |",
            "",
            "Canonical artifacts: `scan-manifest.json` and `findings.json`. This report is a deterministic projection of those files.",
            "",
            "## Threat Model",
            "",
        ]
    )
    content = markdown_threat_model_content(threat_model)
    if content is not None:
        lines.append(content)
    else:
        lines.append(
            _text(
                threat_model.get("summary"),
                "No explicit canonical threat-model summary was recorded.",
            )
        )
        for heading, key in THREAT_MODEL_SECTIONS:
            values = _strings(threat_model.get(key))
            if values:
                lines.extend(["", f"### {heading}", "", *(f"- {value}" for value in values)])
    reviews = scan.get("reviewState", {}).get("reviews")
    if isinstance(reviews, list) and any(
        isinstance(review, dict) and isinstance(review.get("threatModel"), dict)
        for review in reviews
    ):
        lines.extend(
            [
                "",
                (
                    "Other reviews recorded different threat models. See the `threatModel` fields "
                    "in `scan.reviewState.reviews` in the [scan manifest](scan-manifest.json)."
                ),
            ]
        )
    lines.extend(["", "## Findings", ""])
    informational_count = sum(
        finding["severity"]["level"] == "informational" for finding in findings_document["findings"]
    )
    informational_note = ""
    if informational_count:
        noun = "finding" if informational_count == 1 else "findings"
        informational_note = (
            f"This report omits details for {informational_count} informational {noun}. "
            "See `findings.json` or export the findings as SARIF or CSV."
        )
    if findings:
        if informational_note:
            lines.extend([informational_note, ""])
        if deep_presentation:
            lines.extend(
                [
                    "| Findings | Reports | Severity | Confidence | Detailed write-up |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            lines.extend(_deep_group_row(group) for group in deep_finding_groups.values())
        else:
            lines.extend(
                [
                    "| Finding | Severity | Confidence | Detailed write-up |",
                    "| --- | --- | --- | --- |",
                ]
            )
            for number, finding, report_path in numbered_findings:
                title = _cell(finding["title"])
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
        for number, finding, report_path in numbered_findings:
            if report_path is not None:
                lines.extend(["", *_linked_finding_section(number, finding, report_path)])
            else:
                lines.extend(["", *_finding_section(number, finding)])
    else:
        stopped = manifest.get("scan", {}).get("status") in {
            "failed",
            "canceled",
            "interrupted",
        }
        heading = "### No reportable findings" if informational_note else "### No findings"
        message = informational_note or (
            "No findings were retained before the scan stopped."
            if stopped
            else "No findings were reported."
        )
        if stopped:
            message += " The scan did not complete. No vulnerability conclusion can be drawn."
        lines.extend([heading, "", message])
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
    if pending_candidates:
        lines.extend(
            [
                "",
                "## Unresolved candidates",
                "",
                "These saved candidates have not resolved into a saved finding or a terminal disposition.",
                "",
                "| Candidate | Source worker | Title | Remaining review | Locations | Evidence |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for candidate in pending_rows:
            candidate_id = coverage_candidate_key(candidate)[1]
            original = candidate.get("candidate", candidate.get("finding", {}))
            original = original if isinstance(original, dict) else {}
            title = original.get("title", original.get("summary"))
            locations, evidence = _candidate_details(original, candidate)
            lines.append(
                f"| {_cell(candidate_id)} "
                f"| {_cell(coverage_owner(candidate))} "
                f"| {_cell(title or candidate.get('title', candidate_id))} "
                f"| {_cell(candidate.get('reason'))} "
                f"| {_cell(locations)} "
                f"| {_cell(evidence)} |"
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
    deferred = coverage.get("deferred", [])
    follow_ups = (
        [
            item
            for item in deferred
            if isinstance(item, dict) and coverage_candidate_key(item) is None
        ]
        if isinstance(deferred, list)
        else []
    )
    follow_ups.extend(pending_rows)
    deferred_questions = [
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
        for item in follow_ups
    ]
    for heading, questions in (
        ("Deferred Requested Work", deferred_questions),
        ("Open Questions And Follow Up", open_questions),
    ):
        if not isinstance(questions, list) or not questions:
            continue
        lines.extend(["", f"## {heading}", ""])
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
    """Return the Markdown report for the scan as UTF-8 bytes ready to write."""
    return build_report_markdown(manifest, findings, coverage).encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    raise SystemExit(0)
