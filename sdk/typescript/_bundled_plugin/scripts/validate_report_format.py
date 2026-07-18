#!/usr/bin/env python3
"""Validate the shared Codex Security final report shape."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REQUIRED_SECTIONS = ("## Scope", "## Threat Model", "## Findings")
REQUIRED_FINDING_FIELDS = (
    "Severity",
    "Confidence",
    "Confidence rationale",
    "Category",
    "CWE",
    "Affected lines",
)
REQUIRED_FINDING_SUBSECTIONS = (
    "#### Summary",
    "#### Validation",
    "#### Dataflow",
    "#### Reachability",
    "#### Severity",
    "#### Remediation",
)

HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
FINDING_RE = re.compile(r"^### \[(\d+)\]\s+(.+?)\s*$", re.MULTILINE)
FIELD_ROW_RE = re.compile(r"^\|\s*((?:\\.|[^|])+?)\s*\|\s*((?:\\.|[^|])*?)\s*\|\s*$", re.MULTILINE)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def top_level_headings(text: str) -> list[str]:
    return [match.group(0) for match in HEADING_RE.finditer(text) if match.group(1) in {"#", "##"}]


def validate_required_sections(text: str, errors: list[str]) -> None:
    headings = top_level_headings(text)
    if not headings or not headings[0].startswith("# Security Review:"):
        errors.append("line 1: report must start with '# Security Review: <repo_or_target_name>'")

    section_positions: list[int] = []
    for section in REQUIRED_SECTIONS:
        match = re.search(rf"^{re.escape(section)}\s*$", text, re.MULTILINE)
        if not match:
            errors.append(f"missing required section: {section}")
            continue
        section_positions.append(match.start())

    if len(section_positions) == len(REQUIRED_SECTIONS) and section_positions != sorted(
        section_positions
    ):
        errors.append("required sections must appear in order: Scope, Threat Model, Findings")


def finding_body(text: str, finding: re.Match[str], next_finding: re.Match[str] | None) -> str:
    start = finding.end()
    end = next_finding.start() if next_finding else len(text)
    return text[start:end]


def validate_finding_metadata(body: str, line: int, errors: list[str]) -> None:
    first_subsection = body.find("\n#### ")
    metadata_region = body[: first_subsection if first_subsection != -1 else len(body)]
    fields = {
        match.group(1).strip().rstrip(":") for match in FIELD_ROW_RE.finditer(metadata_region)
    }
    missing = [field for field in REQUIRED_FINDING_FIELDS if field not in fields]
    if missing:
        errors.append(f"line {line}: finding metadata table missing fields: {', '.join(missing)}")


def validate_finding_subsections(body: str, line: int, errors: list[str]) -> None:
    positions: list[int] = []
    for subsection in REQUIRED_FINDING_SUBSECTIONS:
        match = re.search(rf"^{re.escape(subsection)}\s*$", body, re.MULTILINE)
        if not match:
            errors.append(f"line {line}: finding missing subsection: {subsection}")
            continue
        positions.append(match.start())
    if len(positions) == len(REQUIRED_FINDING_SUBSECTIONS) and positions != sorted(positions):
        errors.append(f"line {line}: finding subsections are not in the required order")


def validate_findings(text: str, errors: list[str]) -> None:
    findings = list(FINDING_RE.finditer(text))
    if not findings:
        if not re.search(r"^###?\s+No findings\s*$", text, re.IGNORECASE | re.MULTILINE):
            errors.append("missing finding entries or a 'No findings' section under Findings")
        return

    expected_number = 1
    for index, finding in enumerate(findings):
        number = int(finding.group(1))
        line = line_number(text, finding.start())
        if number != expected_number:
            errors.append(f"line {line}: finding number should be {expected_number}, got {number}")
        expected_number += 1

        body = finding_body(
            text, finding, findings[index + 1] if index + 1 < len(findings) else None
        )
        validate_finding_metadata(body, line, errors)
        validate_finding_subsections(body, line, errors)


def validate_report(text: str) -> list[str]:
    errors: list[str] = []
    validate_required_sections(text, errors)
    validate_findings(text, errors)
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the Codex Security report format.")
    parser.add_argument("--report-md", required=True, help="Path to report.md")
    args = parser.parse_args()

    report_path = Path(args.report_md)
    text = report_path.read_text(encoding="utf-8")

    errors = validate_report(text)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print(f"validated report format: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
