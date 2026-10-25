from __future__ import annotations

import pytest
from test_report_projection import PROJECTION, canonical_documents

pytestmark = pytest.mark.cross_platform


@pytest.mark.parametrize("notes", [None, "The filesystem race remains untested."])
def test_coverage_report_preserves_the_recorded_disposition_reason(notes) -> None:
    manifest, findings, coverage = canonical_documents()
    surface = {
        "id": "filesystem-boundary",
        "label": "Filesystem boundary",
        "disposition": "needs_follow_up",
        "reason": "The caller's filesystem policy is unknown.",
        "receiptRefs": ["artifacts/filesystem-review.md"],
    }
    if notes is not None:
        surface["notes"] = notes
    coverage["completeness"] = "partial"
    coverage["surfaces"] = [surface]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert surface["reason"] in markdown
    if notes is not None:
        assert notes in markdown
    assert surface["receiptRefs"][0] in markdown
