from __future__ import annotations

import pytest
from test_report_projection import PROJECTION, canonical_documents

pytestmark = pytest.mark.cross_platform


@pytest.mark.parametrize(
    ("details", "expected"),
    [
        ({"notes": "Reviewed parser entrypoints."}, "Reviewed parser entrypoints."),
        ({"reason": "Caller policy is unknown."}, "Caller policy is unknown."),
        (
            {"notes": "Reviewed parser entrypoints.", "reason": "Caller policy is unknown."},
            "Reviewed parser entrypoints. Caller policy is unknown.",
        ),
        ({"notes": "Policy checked.", "reason": "Policy checked."}, "Policy checked."),
        ({"notes": ""}, ""),
        ({"notes": " \t "}, ""),
        ({}, "No additional canonical notes were recorded."),
    ],
)
def test_projection_includes_surface_evidence_receipts(details: dict, expected: str) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["surfaces"] = [
        {
            "id": "parser-surface",
            "label": "Parser",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/receipts/parser.jsonl"],
            **details,
        }
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    row = next(line for line in markdown.splitlines() if "artifacts/receipts/parser.jsonl" in line)
    assert row.endswith(
        f"| {expected + ' ' if expected else ''}Evidence: artifacts/receipts/parser.jsonl |"
    )


def test_linked_writeup_retains_distinct_source_fixes() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["writeup"] = {"reportPath": "findings/parser/parser.md"}
    finding["remediation"] = "Validate the record length."
    finding["provenance"] = {
        "sourceFindings": [
            {"id": "review-1:0", "finding": {"remediation": "Validate the record length."}},
            {"id": "review-2:0", "finding": {"remediation": "Reject duplicate record keys."}},
            {"id": "review-3:0", "finding": {"remediation": "Reject duplicate record keys."}},
        ]
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "findings/parser/parser.md" in markdown
    assert markdown.count("Validate the record length.") == 1
    assert markdown.count("Reject duplicate record keys.") == 1
