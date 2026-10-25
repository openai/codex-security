from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from test_report_projection import PROJECTION, canonical_documents
from workbench_test_support import load_script, write_completed_contract

pytestmark = pytest.mark.cross_platform

CANDIDATES = load_script("candidate_identity")
FINALIZER = load_script("finalize_scan_contract")


def test_projection_counts_saved_candidates_by_worker_and_separates_unfinished_work() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["completeness"] = "partial"
    pending = {
        "id": "candidate-one",
        "candidateId": "candidate-one",
        "sourceWorkerId": "worker-one",
        "candidate": {
            "title": "Review the parser boundary",
            "evidence": "The request value reaches the parser.",
            "locations": [
                {"path": "src/parser.py", "start_line": 12, "end_line": 15},
                {"path": "src/route.py", "startLine": 6},
            ],
        },
        "reason": "The parser call site still needs validation.",
    }
    coverage["deferred"] = [
        pending,
        {**pending, "id": "candidate-one-copy"},
        {**pending, "id": "candidate-one-other", "sourceWorkerId": "worker-two"},
        {"id": "scan-stopped", "reason": "The remaining files were not reviewed."},
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Unresolved candidates | 2 |" in markdown
    assert "## Unresolved candidates" in markdown
    assert "| candidate-one | worker-one | Review the parser boundary |" in markdown
    assert "| candidate-one | worker-two | Review the parser boundary |" in markdown
    assert markdown.count("| candidate-one |") == 3
    assert "src/parser.py:12-15, src/route.py:6" in markdown
    assert "The request value reaches the parser." in markdown
    assert markdown.count("- The parser call site still needs validation.") == 3
    assert "Review deferred unit candidate-one-copy" in markdown
    assert "The remaining files were not reviewed." in markdown


@pytest.mark.parametrize(
    "candidate",
    [
        {
            "title": "Review a saved finding",
            "validation": {"evidence": ["The request value reaches the parser."]},
            "locations": [{"path": "src/parser.py", "startLine": 12, "endLine": 15}],
        },
        {
            "title": "Review a Deep candidate",
            "evidence": [
                {
                    "path": "src/parser.py",
                    "startLine": 12,
                    "endLine": 15,
                    "code": "parse(request.value)",
                    "explanation": "The request value reaches the parser.",
                }
            ],
        },
        {
            "title": "Review a saved candidate",
            "evidence": [{"receiptRef": "artifacts/review.txt"}],
            "sourceEvidence": [
                {
                    "path": "src/parser.py",
                    "startLine": 12,
                    "endLine": 15,
                    "code": "parse(request.value)",
                    "explanation": "The request value reaches the parser.",
                }
            ],
        },
    ],
)
def test_projection_renders_saved_candidate_evidence_shapes(candidate: dict) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["deferred"] = [
        {
            "candidateId": "candidate-one",
            "reason": "Review remains incomplete.",
            "candidate": candidate,
        }
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "The request value reaches the parser." in markdown
    assert "src/parser.py:12-15" in markdown
    if "validation" not in candidate:
        assert "parse(request.value)" in markdown


@pytest.mark.parametrize("owner", [None, "worker-one"])
def test_projection_keeps_distinct_proof_gaps_for_one_candidate(owner: str | None) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["completeness"] = "partial"
    coverage["deferred"] = [
        {
            "id": row_id,
            "candidateId": "candidate-one",
            **({"sourceWorkerId": owner} if owner else {}),
            "reason": reason,
            "paths": [path],
            "surfaceIds": [surface],
            "candidate": {"title": "Synthetic review", "evidence": evidence},
        }
        for row_id, reason, path, surface, evidence in [
            ("first-gap", "First proof gap.", "src/first.py", "first-surface", "First evidence."),
            (
                "second-gap",
                "Second proof gap.",
                "src/second.py",
                "second-surface",
                "Second evidence.",
            ),
        ]
    ]
    original = copy.deepcopy(coverage)
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "| Unresolved candidates | 1 |" in markdown
    for reason, path, surface, evidence in [
        ("First proof gap.", "src/first.py", "first-surface", "First evidence."),
        ("Second proof gap.", "src/second.py", "second-surface", "Second evidence."),
    ]:
        assert markdown.count(reason) == 2
        assert path in markdown
        assert surface in markdown
        assert evidence in markdown
    assert coverage == original


def test_projection_excludes_resolved_candidates_with_the_same_owner() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["provenance"] = {
        "candidateId": "confirmed",
        "workerId": "worker-one",
    }
    coverage["completeness"] = "partial"
    coverage["surfaces"] = [
        {
            "id": "rejected-surface",
            "label": "Reviewed helper",
            "candidateId": "rejected",
            "sourceWorkerId": "worker-one",
            "disposition": "rejected",
            "receiptRefs": [],
        },
        {
            "id": "not-applicable-surface",
            "label": "Unused helper",
            "candidateId": "not-applicable",
            "disposition": "not_applicable",
            "receiptRefs": [],
        },
    ]
    coverage["deferred"] = [
        {
            "id": f"{owner}-{candidate_id}",
            "candidateId": candidate_id,
            **({"sourceWorkerId": owner} if owner else {}),
            "reason": "Validation has not finished.",
        }
        for owner, candidate_id in [
            ("worker-one", "confirmed"),
            ("worker-two", "confirmed"),
            ("worker-one", "rejected"),
            (None, "not-applicable"),
        ]
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Unresolved candidates | 1 |" in markdown
    assert "| confirmed | worker-two |" in markdown
    assert "| confirmed | worker-one |" not in markdown
    assert "| rejected | worker-one |" not in markdown
    assert "Review deferred unit worker-one-confirmed" not in markdown
    assert "Review deferred unit worker-one-rejected" not in markdown
    assert "Review deferred unit None-not-applicable" not in markdown
    assert "Review deferred unit worker-two-confirmed" in markdown


@pytest.mark.parametrize("projected", [False, True], ids=["legacy", "projected"])
@pytest.mark.parametrize("disposition", [None, "rejected", "not_applicable"])
def test_projection_preserves_main_coverage_worker_ownership(
    tmp_path: Path, disposition: str | None, projected: bool
) -> None:
    write_completed_contract(
        tmp_path, "scan-main-worker-ownership", tmp_path, coverage_mode="deep_repository"
    )
    coverage_path = tmp_path / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [
        {
            "id": f"pending-{worker}",
            "candidateId": "shared-candidate",
            "workerId": worker,
            "reason": f"Unfinished evidence from {worker}.",
        }
        for worker in ("worker-one", "worker-two")
    ]
    coverage["surfaces"] = (
        [
            {
                "id": "reviewed-worker-one",
                "label": "First worker review",
                "candidateId": "shared-candidate",
                "workerId": "worker-one",
                "disposition": disposition,
                "receiptRefs": [],
            }
        ]
        if disposition is not None
        else []
    )
    if projected:
        for row in [*coverage["deferred"], *coverage["surfaces"]]:
            worker = row.pop("workerId")
            row["provenance"] = {
                "workerId": worker,
                "attempt": 1,
                "candidateId": row["candidateId"],
            }
            row["candidateId"] = f"{worker}-attempt-1-candidate-projected"
    assert "completeness" not in coverage
    coverage_path.write_text(json.dumps(coverage))
    manifest, findings, coverage = FINALIZER.finalize_scan(tmp_path)
    sealed = {
        name: (tmp_path / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }

    pending = CANDIDATES.unresolved_candidates(coverage, findings["findings"], sealed=True)
    expected_workers = ["worker-one", "worker-two"] if disposition is None else ["worker-two"]
    assert [CANDIDATES.coverage_owner(row) for row in pending] == expected_workers
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert f"| Unresolved candidates | {len(expected_workers)} |" in markdown
    for worker in expected_workers:
        assert f"| shared-candidate | {worker} |" in markdown
        assert f"Unfinished evidence from {worker}." in markdown
    if disposition is not None:
        assert "Unfinished evidence from worker-one." not in markdown
    assert all((tmp_path / name).read_bytes() == contents for name, contents in sealed.items())


@pytest.mark.parametrize("field", ["surfaces", "explicitExclusions"])
def test_recovered_main_coverage_keeps_each_workers_pending_candidate(
    tmp_path: Path, field: str
) -> None:
    write_completed_contract(tmp_path, "scan-recovered-workers", tmp_path)
    coverage_path = tmp_path / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [
        {
            "id": "pending-worker-one",
            "candidateId": "shared-candidate",
            "workerId": "worker-one",
            "reason": "First worker proof gap.",
        }
    ]
    coverage["surfaces"] = []
    coverage[field] = [
        {
            "id": "reviewed-worker-two",
            "label": "Second worker review",
            "candidateId": "shared-candidate",
            "workerId": "worker-two",
            "disposition": "rejected",
            "receiptRefs": ["artifacts/missing-receipt.json"],
            **(
                {"pattern": "src/extract.py", "reason": "Second worker terminal review."}
                if field == "explicitExclusions"
                else {}
            ),
        }
    ]
    coverage_path.write_text(json.dumps(coverage))

    prepared = FINALIZER._prepare_scan_finalization(tmp_path, recover_unsealed=True)
    manifest, findings, coverage = FINALIZER._write_prepared_scan_finalization(prepared)
    pending = CANDIDATES.unresolved_candidates(coverage, findings["findings"], sealed=True)
    assert [row["workerId"] for row in pending] == ["worker-one", "worker-two"]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "| Unresolved candidates | 2 |" in markdown
    assert "| shared-candidate | worker-one |" in markdown
    assert "| shared-candidate | worker-two |" in markdown
    assert "First worker proof gap." in markdown
    assert "Skipped malformed coverage receipt" in markdown


def test_reported_shared_surface_does_not_resolve_an_explicit_deferred_candidate() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["provenance"] = {"candidateId": "confirmed"}
    coverage["completeness"] = "partial"
    coverage["surfaces"] = [
        {
            "id": "shared-surface",
            "label": "Shared source review",
            "candidateId": "pending",
            "disposition": "reported",
            "receiptRefs": [],
        }
    ]
    coverage["deferred"] = [
        {"candidateId": candidate_id, "reason": "Candidate validation needs evidence."}
        for candidate_id in ["pending", "confirmed"]
    ]

    pending = PROJECTION.unresolved_candidates(coverage, findings["findings"])
    assert [item["candidateId"] for item in pending] == ["pending"]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "| Unresolved candidates | 1 |" in markdown


def test_projection_does_not_infer_candidates_from_legacy_deferred_items() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["completeness"] = "partial"
    coverage["deferred"] = [{"id": "legacy-item", "reason": "A saved question."}]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Unresolved candidates | 0 |" in markdown
    assert "## Unresolved candidates" not in markdown
    assert "A saved question." in markdown


@pytest.mark.parametrize(
    ("provenance", "extensions", "resolved_id"),
    [
        ({"candidateId": "provenance-id"}, {"candidateId": "extension-id"}, "provenance-id"),
        ({"candidateId": " "}, {"candidateId": "extension-id"}, "extension-id"),
        ({}, {"candidateId": "extension-id", "reportId": "report-id"}, "extension-id"),
        ({}, {"reportId": "report-id", "ledgerRowId": "ledger-id"}, "report-id"),
        ({}, {"ledgerRowId": "ledger-id"}, "ledger-id"),
    ],
)
def test_candidate_selection_uses_existing_finding_identity_order(
    provenance: dict[str, str], extensions: dict[str, str], resolved_id: str
) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0].update(provenance=provenance, extensions=extensions)
    coverage["completeness"] = "partial"
    coverage["deferred"] = [
        {"id": value, "candidateId": value, "reason": "Earlier saved candidate."}
        for value in ("provenance-id", "extension-id", "report-id", "ledger-id")
    ]

    remaining = CANDIDATES.unresolved_candidates(coverage, findings["findings"])

    assert {row["candidateId"] for row in remaining} == {
        "provenance-id",
        "extension-id",
        "report-id",
        "ledger-id",
    } - {resolved_id}


@pytest.mark.parametrize(
    ("provenance", "extensions", "owner"),
    [
        ({"sourceWorkerId": {"imported": "worker"}}, {}, None),
        ({"sourceWorkerId": ["worker"]}, {}, None),
        ({"sourceWorkerId": " "}, {}, None),
        ({"sourceWorkerId": {}, "workerId": "worker-a"}, {}, "worker-a"),
        ({"sourceWorkerId": " ", "workerId": []}, {"sourceWorkerId": "worker-a"}, "worker-a"),
    ],
)
def test_projection_resolves_candidates_using_string_owner_metadata(
    provenance: dict, extensions: dict, owner: str | None
) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding.update(provenance={**provenance, "candidateId": "confirmed"}, extensions=extensions)
    saved_finding = copy.deepcopy(finding)
    coverage["deferred"] = [
        {
            "id": "resolved",
            "candidateId": "confirmed",
            "sourceWorkerId": owner,
            "reason": "Earlier checkpoint.",
        },
        {
            "id": "other-worker",
            "candidateId": "confirmed",
            "sourceWorkerId": "worker-b",
            "reason": "Independent review.",
        },
    ]

    assert CANDIDATES.unresolved_candidates(coverage, findings["findings"]) == [
        coverage["deferred"][1]
    ]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "| Unresolved candidates | 1 |" in markdown
    assert "Earlier checkpoint." not in markdown
    assert "Independent review." in markdown
    assert finding == saved_finding


@pytest.mark.parametrize(
    ("metadata", "remaining_owners"),
    [
        ({"workerId": "worker-one"}, ["worker-two", None]),
        ({"sourceWorkerId": None, "workerId": "worker-one"}, ["worker-two", None]),
        ({"sourceWorkerId": "worker-two", "workerId": "worker-one"}, ["worker-one", None]),
        ({"sourceWorkerId": {}, "workerId": "worker-one"}, ["worker-one", "worker-two", None]),
        ({"sourceWorkerId": " ", "workerId": "worker-one"}, ["worker-two", None]),
        ({"sourceWorkerId": "", "workerId": "worker-one"}, ["worker-two", None]),
        (
            {"sourceWorkerId": " worker-one ", "workerId": "worker-one"},
            ["worker-one", "worker-two", None],
        ),
        ({"sourceWorkerId": [], "workerId": "worker-one"}, ["worker-one", "worker-two", None]),
        *[
            ({**canonical, "workerId": legacy}, ["worker-one", "worker-two"])
            for canonical in ({"sourceWorkerId": " "}, {"sourceWorkerId": None}, {})
            for legacy in ({}, [])
        ],
        ({"workerId": []}, ["worker-one", "worker-two"]),
    ],
)
def test_projection_preserves_coverage_owner_precedence(
    metadata: dict, remaining_owners: list[str | None]
) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["deferred"] = [
        {
            "id": f"pending-{owner}",
            "candidateId": "shared-candidate",
            "sourceWorkerId": owner,
            "reason": f"Review from {owner}.",
        }
        for owner in ("worker-one", "worker-two", None)
    ]
    coverage["surfaces"] = [
        {"candidateId": "shared-candidate", "disposition": "rejected", **metadata}
    ]
    saved_coverage = copy.deepcopy(coverage)

    pending = CANDIDATES.unresolved_candidates(coverage, [])
    assert [row["sourceWorkerId"] for row in pending] == remaining_owners
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert f"| Unresolved candidates | {len(remaining_owners)} |" in markdown
    assert coverage == saved_coverage
    assert CANDIDATES.coverage_candidate_key(
        {"candidateId": "shared-candidate", **metadata}, "actual-worker"
    ) == ("actual-worker", "shared-candidate")


@pytest.mark.parametrize("source_owner", ["", " "])
def test_projection_finding_resolves_blank_canonical_candidate_owner(source_owner: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["provenance"] = {
        "candidateId": "shared-candidate",
        "workerId": "worker-one",
    }
    coverage["deferred"] = [
        {
            "candidateId": "shared-candidate",
            "sourceWorkerId": source_owner,
            "workerId": worker,
            "reason": f"Evidence retained for {worker}.",
        }
        for worker in ("worker-one", "worker-two")
    ]
    saved = copy.deepcopy((findings, coverage))
    assert CANDIDATES.unresolved_candidates(coverage, findings["findings"]) == [
        coverage["deferred"][1]
    ]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "| Unresolved candidates | 1 |" in markdown
    assert "Evidence retained for worker-one." not in markdown
    assert "Evidence retained for worker-two." in markdown
    assert (findings, coverage) == saved


def test_main_coverage_surface_references_keep_their_worker() -> None:
    deferred = {
        "candidateId": "shared-candidate",
        "workerId": "worker-one",
        "surfaceIds": ["shared-surface"],
    }
    surfaces = [
        {"id": "shared-surface", "workerId": worker} for worker in ("worker-two", "worker-one")
    ]
    assert CANDIDATES.surface_reference_key("shared-surface", deferred, surfaces) == (
        "worker-one",
        "shared-surface",
    )
    assert CANDIDATES._deferred_owner(deferred, None) == "worker-one"
    assert CANDIDATES._deferred_owner(deferred, "actual-worker") == "actual-worker"


@pytest.mark.parametrize("coverage_mode", ["repository", "scoped_path"])
def test_projection_keeps_standard_candidate_findings_in_the_standard_table(
    coverage_mode: str,
) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage.update(mode=coverage_mode, inventoryStrategy=coverage_mode)
    finding = findings["findings"][0]
    finding["title"] = "First parser review"
    finding["provenance"] = {"candidateId": "review/parser"}
    sibling = copy.deepcopy(finding)
    sibling.update(occurrenceId="occ_2", title="Second parser review")
    findings["findings"].append(sibling)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Reportable findings | 2 |" in markdown
    assert "| Finding | Severity | Confidence | Detailed write-up |" in markdown
    assert "[First parser review](#finding-1)" in markdown
    assert "[Second parser review](#finding-2)" in markdown
    assert "Reportable DSS findings" not in markdown
    assert "| Report instances |" not in markdown


@pytest.mark.parametrize(
    ("coverage_mode", "candidate_ids", "legacy_ids", "owner_field", "expected_groups"),
    [
        ("deep_repository", ("candidate-one", "candidate-one"), ("old-one", "old-two"), None, 1),
        ("deep_repository", ("candidate-one", "candidate-two"), ("old-one", "old-one"), None, 2),
        ("scoped_path", ("candidate-one", "candidate-one"), (None, None), "sourceWorkerId", 1),
        ("scoped_path", ("candidate-one", "candidate-one"), (None, None), "workerId", 1),
    ],
)
def test_projection_groups_deep_reports_by_canonical_provenance(
    coverage_mode: str,
    candidate_ids: tuple[str, str],
    legacy_ids: tuple[str | None, str | None],
    owner_field: str | None,
    expected_groups: int,
) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = coverage_mode
    if coverage_mode == "scoped_path":
        coverage["inventoryStrategy"] = "scoped_path"
    finding = findings["findings"][0]
    finding["title"] = "Parser boundary review"
    sibling = copy.deepcopy(finding)
    sibling["occurrenceId"] = "occ_2"
    findings["findings"].append(sibling)
    for report, candidate_id, legacy_id in zip(
        findings["findings"], candidate_ids, legacy_ids, strict=True
    ):
        report["provenance"] = {"candidateId": candidate_id}
        if owner_field is not None:
            report["provenance"][owner_field] = "discovery-worker"
        if legacy_id is not None:
            report["extensions"] = {"candidateId": legacy_id}

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert f"| Reportable DSS findings | {expected_groups} |" in markdown
    assert "| Report instances | 2 |" in markdown
    assert markdown.count("| Parser boundary review |") == expected_groups
    assert '<a id="finding-1"></a>' in markdown
    assert '<a id="finding-2"></a>' in markdown


@pytest.mark.parametrize("coverage_mode", ["deep_repository", "scoped_path"])
@pytest.mark.parametrize(
    "owner_metadata", ["canonical", "legacy-worker", "extension", "canonical-over-extension"]
)
def test_projection_keeps_same_id_deep_candidates_separate_by_worker(
    coverage_mode: str, owner_metadata: str
) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage.update(mode=coverage_mode, inventoryStrategy=coverage_mode)
    template = findings["findings"][0]
    findings["findings"] = []
    for report_id, owner, title, severity in [
        ("first-report", "worker-one", "First parser review", "high"),
        ("first-repeat", "worker-one", "First parser review", "medium"),
        ("second-report", "worker-two", "Second parser review", "low"),
    ]:
        report = copy.deepcopy(template)
        report.update(occurrenceId=report_id, title=title)
        report["severity"]["level"] = severity
        report["extensions"] = {"reportId": report_id}
        if owner_metadata == "extension":
            report["extensions"].update(candidateId="review/auth", sourceWorkerId=owner)
        else:
            owner_field = "workerId" if owner_metadata == "legacy-worker" else "sourceWorkerId"
            report["provenance"] = {"candidateId": "review/auth", owner_field: owner}
            if owner_metadata == "canonical-over-extension":
                report["extensions"]["sourceWorkerId"] = "stale-worker"
        findings["findings"].append(report)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Reportable DSS findings | 2 |" in markdown
    assert "| Report instances | 3 |" in markdown
    assert (
        "| First parser review | [first-report](#finding-1)<br>[first-repeat](#finding-2) "
        "| high<br>medium | high |" in markdown
    )
    assert "| Second parser review | [second-report](#finding-3) | low | high |" in markdown
    assert "First parser review<br>Second parser review" not in markdown


def test_saved_candidate_proof_rows_preserve_order_and_json_equality() -> None:
    first = {
        "candidateId": "same-review",
        "reason": "First proof gap.",
        "evidence": {"count": 1, "checks": [False, {"done": None}]},
    }
    equivalent = {
        "evidence": {"checks": [False, {"done": None}], "count": 1.0},
        "reason": "First proof gap.",
        "candidateId": "same-review",
    }
    other = {**first, "reason": "Second proof gap.", "paths": ["src/handler.ts"]}
    rows = [first, equivalent, other, copy.deepcopy(first)]
    coverage = {"deferred": rows, "surfaces": [], "explicitExclusions": []}
    assert CANDIDATES.unresolved_candidate_rows(coverage) == [first, other]
    assert CANDIDATES.unresolved_candidates(coverage) == [first]
    coverage["surfaces"] = [{"candidateId": "same-review", "disposition": "rejected"}]
    assert CANDIDATES.unresolved_candidate_rows(coverage) == []


@pytest.mark.parametrize(
    ("first", "second", "count"),
    [
        (True, 1, 2),
        (False, 0, 2),
        ({"checks": [True, {"done": False}]}, {"checks": [1, {"done": 0}]}, 2),
        (True, ["bool", 1], 2),
        (False, ["bool", 0], 2),
        (True, True, 1),
        (False, False, 1),
        (1, 1.0, 1),
        (0, 0.0, 1),
        ([1, 2], [2, 1], 2),
        (None, 0, 2),
    ],
)
def test_saved_candidate_proof_rows_distinguish_boolean_evidence(first, second, count) -> None:
    rows = [
        {"candidateId": "same-review", "reason": "Review remains.", "candidate": {"value": value}}
        for value in (first, second)
    ]
    for ordered in (rows, rows[::-1]):
        coverage = {"deferred": ordered, "surfaces": [], "explicitExclusions": []}
        selected = CANDIDATES.unresolved_candidate_rows(coverage)
        assert len(selected) == count
        assert selected[0] is ordered[0]
        assert len(CANDIDATES.unresolved_candidates(coverage)) == 1


def test_large_saved_candidate_projection_preserves_all_identities_and_proof_gaps() -> None:
    rows = [
        {
            "candidateId": f"review-{index}",
            "reason": f"Proof gap {index}",
            "candidate": {"evidence": [index, {"path": "src/handler.ts"}]},
        }
        for index in range(2000)
    ]
    coverage = {"deferred": rows + copy.deepcopy(rows), "surfaces": [], "explicitExclusions": []}
    assert CANDIDATES.unresolved_candidate_rows(coverage) == rows
    assert CANDIDATES.unresolved_candidates(coverage) == rows


@pytest.mark.parametrize("field", ["code_evidence", "codeEvidence"])
@pytest.mark.parametrize("payload", ["candidate", "finding"])
def test_projection_keeps_saved_code_evidence_alias(field: str, payload: str) -> None:
    manifest, findings, coverage = canonical_documents()
    original = {
        "title": "Saved parser review",
        "summary": "Saved candidate summary.",
        field: [
            {
                "path": "src/parser.py",
                "start_line": 12,
                "end_line": 15,
                "code": "parse(request.value)",
                "explanation": "The saved request value reaches the parser.",
            }
        ],
    }
    coverage["deferred"] = [
        {
            "id": "saved-gap",
            "candidateId": "saved-candidate",
            "reason": "Saved review remains incomplete.",
            payload: original,
        }
    ]
    before = copy.deepcopy(coverage)
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "src/parser.py:12-15" in markdown
    assert "parse(request.value)" in markdown
    assert "The saved request value reaches the parser." in markdown
    assert coverage == before
