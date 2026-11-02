"""ServiceNow Manual AVIT Ingestion CSV template and finding fields."""

from __future__ import annotations

import csv
import io
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

AVIT_APP_FIELDS = {
    "Application": 255,
    "Requested by": 151,
    "Purpose of application": 4000,
    "Types of sensitive data": 40,
    "List of compliance programs": 4000,
    "Technology stack details": 4000,
    "Application team": 100,
    "URLs to test": 4000,
    "Assigned to": 151,
    "Assignment group": 151,
}
AVIT_FINDING_FIELDS = (
    "Risk rating",
    "CWE category",
    "Vulnerability ID",
    "Steps to reproduce",
    "Technical details",
)


def read_template(path: Path) -> tuple[list[str], dict[str, str]]:
    try:
        with path.open(encoding="utf-8-sig", newline="") as source:
            rows = (row for row in csv.reader(source, strict=True) if row)
            headers = next(rows, [])
            values = next(rows, [])
            if len(headers) != len(values) or next(rows, None) is not None:
                raise ValueError("AVIT template must have a header and one application row")
    except (OSError, UnicodeError, csv.Error) as exc:
        raise ValueError(f"Could not read AVIT template {path}: {exc}") from exc

    row = {header.strip().casefold(): value for header, value in zip(headers, values, strict=True)}
    if len(row) != len(headers):
        raise ValueError("AVIT template has duplicate column names")
    for field in (*AVIT_APP_FIELDS, *AVIT_FINDING_FIELDS):
        if field.casefold() not in row:
            raise ValueError(f"AVIT template is missing column {field!r}")
    for field, limit in AVIT_APP_FIELDS.items():
        value = row[field.casefold()]
        if not value.strip() or len(value) > limit:
            raise ValueError(
                f"AVIT template {field!r} requires a value of at most {limit} characters"
            )
    return headers, row


def _narrative(text: str) -> str:
    return text if len(text) <= 1000 else text[:997] + "..."


def finding_fields(finding: dict[str, Any], location: dict[str, Any], steps: str) -> dict[str, str]:
    details = (
        f"{finding['findingId']} | {location['path']}:{location['startLine']}\n"
        f"{finding['title']}\n{finding['summary']}\n{finding['remediation']}"
    )
    cwe = next(
        (
            value.upper()
            for value in finding["taxonomy"]["cwe"]
            if len(value) <= 255 and re.fullmatch(r"CWE-[0-9]+", value, re.I)
        ),
        "",
    )
    level = finding["severity"]["level"]
    return {
        "Risk rating": "None" if level == "informational" else level.title(),
        "CWE category": cwe,
        "Vulnerability ID": "" if cwe else finding["findingId"],
        "Steps to reproduce": _narrative(steps),
        "Technical details": _narrative(details),
    }


def render(template: Path, rows: Iterable[dict[str, str]]) -> bytes:
    headers, row = read_template(template)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(headers)
    missing_steps = 0
    has_findings = False
    for fields in rows:
        has_findings = True
        if not fields["Steps to reproduce"]:
            missing_steps += 1
        for field, value in fields.items():
            row[field.casefold()] = value
        writer.writerow(row.values())
    if has_findings:
        print(
            "Review Steps to reproduce before uploading. Populated steps describe the recorded "
            f"attack path. Rows with no recorded steps: {missing_steps}.",
            file=sys.stderr,
        )
    return output.getvalue().encode("utf-8")
