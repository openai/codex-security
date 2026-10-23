from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from workbench_test_support import load_script, write_completed_contract

pytestmark = pytest.mark.cross_platform

PROJECTION = load_script("report_projection")
CANDIDATES = load_script("candidate_identity")
FINALIZER = load_script("finalize_scan_contract")


def canonical_documents() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    manifest = {
        "scan": {
            "target": {"displayName": "example/repo"},
            "scope": {
                "includePaths": ["src/"],
                "excludePaths": [],
                "summary": "## Injected scope\n- nested item",
            },
            "threatModel": {"summary": "# Queue boundaries\n\nThreat details"},
        }
    }
    findings = {
        "findings": [
            {
                "occurrenceId": "occ_1",
                "title": "Parser | boundary\n## Injected finding heading",
                "summary": "```\ncode fence\n```",
                "severity": {"level": "high"},
                "confidence": {"level": "high", "rationale": "Direct trace."},
                "taxonomy": {"category": "parser | injection", "cwe": ["CWE-20"]},
                "locations": [{"path": "src/parser.py", "startLine": 10}],
                "remediation": "## Injected remediation\n- unsafe instruction",
            }
        ]
    }
    coverage = {
        "mode": "repository",
        "inventoryStrategy": "repository",
        "includePaths": ["src/"],
        "excludePaths": [],
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
    }
    return manifest, findings, coverage


def test_projection_normalizes_structured_fields() -> None:
    markdown = PROJECTION.build_report_markdown(*canonical_documents())

    assert "\n## Injected" not in markdown
    assert "\n# Injected" not in markdown
    assert "\n```" not in markdown
    assert "Text: ## Injected scope - nested item" in markdown
    assert "Text: # Queue boundaries Threat details" in markdown
    assert "\n# Queue boundaries" not in markdown
    assert "Text: \\`\\`\\` code fence \\`\\`\\`" in markdown
    assert "Parser \\| boundary ## Injected finding heading" in markdown
    assert "Text: ## Injected remediation - unsafe instruction" in markdown


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


@pytest.mark.parametrize("disposition", [None, "rejected", "not_applicable"])
def test_projection_preserves_main_coverage_worker_ownership(
    tmp_path: Path, disposition: str | None
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
    assert "completeness" not in coverage
    coverage_path.write_text(json.dumps(coverage))
    manifest, findings, coverage = FINALIZER.finalize_scan(tmp_path)
    sealed = {
        name: (tmp_path / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }

    pending = CANDIDATES.unresolved_candidates(coverage, findings["findings"], sealed=True)
    expected_workers = ["worker-one", "worker-two"] if disposition is None else ["worker-two"]
    assert [row["workerId"] for row in pending] == expected_workers
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


def test_projection_normalizes_tilde_fences_and_parenthesized_lists() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["summary"] = "~~~\ncode fence\n~~~"
    finding["remediation"] = "1) Validate the record length."

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "\n~~~" not in markdown
    assert "Text: ~~~ code fence ~~~" in markdown
    assert "Text: 1) Validate the record length." in markdown


@pytest.mark.parametrize("linked_writeup", [False, True], ids=["inline", "linked"])
def test_projection_retains_distinct_source_fixes(linked_writeup: bool) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    if linked_writeup:
        finding["writeup"] = {"reportPath": "findings/parser/parser.md"}
    finding["remediation"] = "Validate the record length."
    finding["remediationTests"] = ["Reject a record longer than the allowed size."]
    finding["preventiveControls"] = ["Centralize record validation."]
    finding["provenance"] = {
        "sourceFindings": [
            {"id": "review-1:0", "finding": {"remediation": "Validate the record length."}},
            {
                "id": "review-2:0",
                "finding": {
                    "remediation": "Reject duplicate record keys.",
                    "remediationTests": [
                        "Reject a record longer than the allowed size.",
                        "Cover duplicate keys in parser tests.",
                    ],
                    "preventiveControls": [
                        "Centralize record validation.",
                        "Track keys while parsing a record.",
                    ],
                },
            },
            {
                "id": "review-3:0",
                "finding": {
                    "remediation": "Reject duplicate record keys.",
                    "remediationTests": [
                        "Cover duplicate keys in parser tests.",
                        "Reject case-variant duplicate keys.",
                    ],
                    "preventiveControls": ["Track keys while parsing a record."],
                },
            },
        ]
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    if linked_writeup:
        assert "findings/parser/parser.md" in markdown
    assert "Source review-2:0: Reject duplicate record keys." in markdown
    for text in (
        "Validate the record length.",
        "Reject duplicate record keys.",
        "Reject a record longer than the allowed size.",
        "Cover duplicate keys in parser tests.",
        "Reject case-variant duplicate keys.",
        "Centralize record validation.",
        "Track keys while parsing a record.",
    ):
        assert markdown.count(text) == 1


def test_projection_renders_inline_code_and_section_code_evidence() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["summary"] = (
        "The `environment/add` RPC forwards `environmentId` to "
        "`EnvironmentManager::upsert_environment()`."
    )
    finding["codeEvidence"] = [
        {
            "id": "runtime-upsert",
            "label": "Runtime upsert omits the reserved-ID check",
            "path": "codex-rs/exec-server/src/environment.rs",
            "startLine": 253,
            "endLine": 281,
            "language": "rust",
            "code": "self.environments.write().insert(environment_id, environment);",
            "explanation": "The runtime path inserts `local` without reusing the startup check.",
        }
    ]
    finding["rootCause"] = {
        "summary": "`local` is reserved, but `upsert_environment()` accepts it.",
        "evidenceRefs": ["runtime-upsert"],
    }
    finding["validation"] = {
        "summary": "The source trace confirmed the unchecked insert.",
        "evidenceRefs": ["runtime-upsert"],
    }
    finding["attackPath"] = {
        "dataflow": {"summary": "`environment/add` -> shared environment map"},
        "evidenceRefs": ["runtime-upsert"],
    }

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "The `environment/add` RPC forwards `environmentId`" in markdown
    assert "#### Root Cause" in markdown
    assert "**Runtime upsert omits the reserved-ID check**" in markdown
    assert "`codex-rs/exec-server/src/environment.rs:253-281`" in markdown
    assert "```rust" in markdown
    assert "self.environments.write().insert(environment_id, environment);" in markdown
    assert "The runtime path inserts `local` without reusing the startup check." in markdown


@pytest.mark.parametrize("reference_key", ["evidenceRefs", "evidence_refs"])
def test_projection_renders_nested_attack_path_code_evidence(reference_key: str) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["codeEvidence"] = [
        {
            "id": "archive-source",
            "label": "Attacker-controlled archive path",
            "path": "src/archive.py",
            "startLine": 20,
            "code": "entry_path = archive_entry.name",
            "explanation": "The archive controls the path.",
        },
        {
            "id": "archive-sink",
            "label": "Unchecked filesystem write",
            "path": "src/archive.py",
            "startLine": 41,
            "code": "destination.write_bytes(entry.read())",
            "explanation": "The unchecked path reaches the write.",
        },
    ]
    finding["attackPath"] = {
        "dataflow": {
            "summary": "An archive entry path reaches a filesystem write.",
            "evidenceRefs": [],
            "evidence_refs": ["archive-source"],
        },
        "reachability": {
            "summary": "An authenticated uploader can trigger extraction.",
            reference_key: ["archive-sink"],
        },
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "entry_path = archive_entry.name" in markdown
    assert "destination.write_bytes(entry.read())" in markdown


def test_projection_normalizes_scalar_evidence_references() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["codeEvidence"] = [
        {"id": "root-source", "code": "root_source()"},
        {"id": "dataflow-source", "code": "dataflow_source()"},
        {"id": "reachability-source", "code": "reachability_source()"},
    ]
    finding["root_cause"] = {
        "summary": "The authorization check occurs after the write.",
        "evidence_refs": "root-source",
    }
    finding["attackPath"] = {
        "dataflow": {
            "summary": "An attacker-controlled value reaches the write.",
            "evidence_refs": "dataflow-source",
        },
        "reachability": {
            "summary": "An authenticated caller can reach the handler.",
            "evidence_refs": "reachability-source",
        },
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "root_source()" in markdown
    assert "dataflow_source()" in markdown
    assert "reachability_source()" in markdown


def test_projection_merges_transformations_across_data_flow_aliases() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["attackPath"] = {
        "dataFlow": {"transformations": ["decode archive entry", "parse *input*"]},
        "dataflow": {
            "summary": "request -> archive extraction -> filesystem write",
            "transformations": ["dispatch extraction", "decode archive entry"],
        },
        "data_flow": {"transformations": None},
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert markdown.count("- decode archive entry") == 1
    assert "- dispatch extraction" in markdown
    assert "- parse \\*input\\*" in markdown.splitlines()


def test_projection_merges_top_level_and_reachability_preconditions() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["attackPath"] = {
        "preconditions": [
            "The service processes uploaded archives.",
            "The attacker can upload an archive.",
        ],
        "reachability": {
            "summary": "An authenticated uploader can trigger extraction.",
            "preconditions": [
                "The attacker can upload an archive.",
                "Automatic extraction is enabled.",
            ],
        },
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert markdown.count("- The service processes uploaded archives.") == 1
    assert markdown.count("- The attacker can upload an archive.") == 1
    assert markdown.count("- Automatic extraction is enabled.") == 1


def test_projection_uses_top_level_attack_path_summary_as_reachability_fallback() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["attackPath"] = {
        "summary": "An authenticated uploader can trigger parse_file to extract an archive."
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    reachability = markdown.split("#### Reachability", 1)[1].split("#### Severity", 1)[0]
    assert (
        reachability.strip()
        == r"An authenticated uploader can trigger parse\_file to extract an archive."
    )
    assert "Reachability was not recorded" not in reachability


def test_projection_renders_typed_attack_path_steps() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["attackPath"] = {
        "steps": [
            "Upload an archive with a traversal entry.",
            "Trigger automatic extraction.",
        ]
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    dataflow = markdown.split("#### Dataflow", 1)[1].split("#### Reachability", 1)[0]
    assert "Attack steps:" in dataflow
    assert "- Upload an archive with a traversal entry." in dataflow
    assert "- Trigger automatic extraction." in dataflow


def test_projection_renders_typed_assessments_and_validation_outcomes() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["validation"] = {
        "status": "validated",
        "disposition": "reported",
        "result": "The traversal write was confirmed.",
    }
    findings["findings"][0]["attackPath"] = {
        "impact": {
            "level": "high",
            "rationale": "The write can overwrite application files.",
            "why": "The destination escapes the extraction root.",
        },
        "likelihood": "Likely for authenticated uploaders.",
        "reachability": {
            "source": "Attacker-controlled archive entry.",
            "sink": "Unchecked filesystem write.",
        },
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "- **Status:** validated" in markdown
    assert "- **Disposition:** reported" in markdown
    assert "- **Result:** The traversal write was confirmed." in markdown
    assert "- **Source:** Attacker-controlled archive entry." in markdown
    assert "- **Sink:** Unchecked filesystem write." in markdown
    assert "Impact assessment:" in markdown
    assert "- **Level:** high" in markdown
    assert "- **Rationale:** The write can overwrite application files." in markdown
    assert "- **Why:** The destination escapes the extraction root." in markdown
    assert "**Likelihood assessment:** Likely for authenticated uploaders." in markdown


def test_projection_renders_attack_path_context_lists() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["attackPath"] = {
        "assumptions": ["Automatic extraction is enabled."],
        "blindspots": ["A downstream sandbox was not exercised."],
        "controls": ["Archive uploads require authentication."],
        "limitations": ["The exploit was validated statically."],
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    reachability = markdown.split("#### Reachability", 1)[1].split("#### Severity", 1)[0]
    assert "Assumptions:" in reachability
    assert "- Automatic extraction is enabled." in reachability
    assert "Existing controls:" in reachability
    assert "- Archive uploads require authentication." in reachability
    assert "Blind spots:" in reachability
    assert "- A downstream sandbox was not exercised." in reachability
    assert "Limitations:" in reachability
    assert "- The exploit was validated statically." in reachability


def test_projection_preserves_heading_like_source_evidence() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["codeEvidence"] = [
        {
            "id": "markdown-source",
            "label": "Reviewed Markdown source",
            "path": "docs/security.md",
            "startLine": 10,
            "language": "markdown",
            "code": "### [2] Legitimate heading inside reviewed source",
            "explanation": "The source contains a heading that resembles a report finding.",
        }
    ]
    findings["findings"][0]["rootCause"] = {
        "summary": "The reviewed source contains security-relevant Markdown.",
        "evidenceRefs": ["markdown-source"],
    }

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "```markdown\n### [2] Legitimate heading inside reviewed source\n```" in markdown
    assert "Reviewed Markdown source" in markdown


def test_projection_renders_string_root_cause() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["rootCause"] = (
        "The authorization check runs after the privileged `write`."
    )

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert (
        "#### Root Cause\n\nThe authorization check runs after the privileged `write`." in markdown
    )


def test_projection_merges_root_cause_aliases() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["rootCause"] = {"summary": ""}
    findings["findings"][0]["root_cause"] = {
        "summary": "The destination is not contained before the write.",
        "code": "destination.write_bytes(payload)",
        "language": "python",
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "The destination is not contained before the write." in markdown
    assert "```python\ndestination.write_bytes(payload)\n```" in markdown


def test_projection_ignores_malformed_root_cause_alias_fields() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["rootCause"] = {"summary": 42}
    findings["findings"][0]["root_cause"] = {
        "summary": "The valid legacy root cause.",
        "evidence_refs": ["legacy-root"],
    }
    findings["findings"][0]["code_evidence"] = [{"id": "legacy-root", "code": "legacy_root()"}]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "The valid legacy root cause." in markdown
    assert "legacy_root()" in markdown
    assert "42" not in markdown


def test_projection_merges_scalar_and_list_root_cause_evidence_references() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["rootCause"] = {
        "summary": "The source reaches the write.",
        "evidenceRefs": ["canonical-root-source"],
    }
    findings["findings"][0]["root_cause"] = {"evidence_refs": "legacy-root-source"}
    findings["findings"][0]["codeEvidence"] = [
        {"id": "canonical-root-source", "code": "canonical_source()"}
    ]
    findings["findings"][0]["code_evidence"] = [
        {"id": "legacy-root-source", "code": "legacy_source()"}
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "canonical_source()" in markdown
    assert "legacy_source()" in markdown


def test_projection_merges_embedded_evidence_across_root_cause_aliases() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["rootCause"] = {
        "summary": "The canonical root cause.",
        "codeEvidence": [{"id": "canonical-root", "code": "canonical_evidence()"}],
    }
    findings["findings"][0]["root_cause"] = {
        "codeEvidence": [{"id": "legacy-root", "code": "legacy_evidence()"}]
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "canonical_evidence()" in markdown
    assert "legacy_evidence()" in markdown


def test_projection_treats_whitespace_root_cause_fields_as_unpopulated() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["rootCause"] = {
        "summary": "   ",
        "code": "\t",
        "language": "text",
    }
    findings["findings"][0]["root_cause"] = {
        "summary": "The destination is not contained before the write.",
        "code": "destination.write_bytes(payload)",
        "language": "python",
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "The destination is not contained before the write." in markdown
    assert "```python\ndestination.write_bytes(payload)\n```" in markdown


def test_projection_ignores_malformed_data_flow_alias_values() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["attackPath"] = {
        "dataFlow": {"summary": ["invalid canonical value"]},
        "dataflow": {"summary": "request -> validated sink"},
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "request -\\> validated sink" in markdown


def test_projection_links_detailed_writeup_without_repeating_inline_finding() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["writeup"] = {
        "reportPath": "findings/parser-boundary/parser-boundary.md"
    }

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "[Open report](findings/parser-boundary/parser-boundary.md)" in markdown
    assert "### [1] Parser" in markdown
    assert "See the [detailed technical write-up]" in markdown
    assert "## Injected remediation" not in markdown


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


@pytest.mark.parametrize("coverage_mode", ["deep_repository", "scoped_path"])
def test_projection_groups_deep_reports_by_candidate_id(coverage_mode: str) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = coverage_mode
    if coverage_mode == "scoped_path":
        coverage["inventoryStrategy"] = "scoped_path"
    finding = findings["findings"][0]
    finding["title"] = (
        "Render clients can reconfigure device-global firmware logging [DSS-079-RGXFWDBG-rogue]"
    )
    finding["extensions"] = {
        "candidateId": "DSS-079",
        "ledgerRowId": "R07W01-COV-RGXFWDBG",
        "reportId": "DSS-079-RGXFWDBG-rogue",
    }
    finding["severity"]["level"] = "high"
    finding["writeup"] = {"reportPath": "findings/dss-079-rogue/dss-079-rogue.md"}
    sibling = copy.deepcopy(finding)
    sibling["occurrenceId"] = "occ_2"
    sibling["title"] = (
        "Render clients can reconfigure device-global firmware logging [DSS-079-RGXFWDBG-volcanic]"
    )
    sibling["extensions"]["reportId"] = "DSS-079-RGXFWDBG-volcanic"
    sibling["severity"]["level"] = "medium"
    sibling["writeup"] = {"reportPath": "findings/dss-079-volcanic/dss-079-volcanic.md"}
    findings["findings"].append(sibling)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Reportable DSS findings | 1 |" in markdown
    assert "| Report instances | 2 |" in markdown
    assert "| Findings | Reports | Severity | Confidence | Detailed write-up |" in markdown
    assert (
        "| Render clients can reconfigure device-global firmware logging "
        "| [DSS-079-RGXFWDBG-rogue](#finding-1)"
        "<br>[DSS-079-RGXFWDBG-volcanic](#finding-2) | high<br>medium | high "
        "| [Open DSS-079-RGXFWDBG-rogue]"
        "(findings/dss-079-rogue/dss-079-rogue.md)"
        "<br>[Open DSS-079-RGXFWDBG-volcanic]"
        "(findings/dss-079-volcanic/dss-079-volcanic.md) |" in markdown
    )
    assert markdown.count("| Render clients can reconfigure device-global firmware logging |") == 1
    assert '<a id="finding-1"></a>' in markdown
    assert '<a id="finding-2"></a>' in markdown


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


def test_projection_moves_legacy_deep_title_annotations_to_reports() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "deep_repository"
    finding = findings["findings"][0]
    finding["title"] = (
        "Render clients can dump device-global firmware trace and assertion buffers into "
        "PDump output [R07W01-COV-RGXPDUMP-TRACE; COV-PDUMP-004; "
        "new-rgx-pdump-trace-authz:rogue-fw]"
    )
    finding["extensions"] = {
        "candidateId": "DSS-145",
        "ledgerRowId": "R07W01-COV-RGXPDUMP-TRACE; COV-PDUMP-004",
    }
    sibling = copy.deepcopy(finding)
    sibling["occurrenceId"] = "occ_2"
    sibling["title"] = (
        "Render clients can dump device-global firmware trace and assertion buffers into "
        "PDump output [R07W01-COV-RGXPDUMP-TRACE; COV-PDUMP-004; "
        "new-rgx-pdump-trace-authz:rogue-mips]"
    )
    sibling["identity"] = {"instance": "dss-145-rogue-mips"}
    findings["findings"].append(sibling)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    finding_title = (
        "Render clients can dump device-global firmware trace and assertion buffers into "
        "PDump output"
    )
    assert markdown.count(f"| {finding_title} |") == 1
    assert (
        "[R07W01-COV-RGXPDUMP-TRACE; COV-PDUMP-004; "
        "new-rgx-pdump-trace-authz:rogue-fw](#finding-1)" in markdown
    )
    assert (
        "[R07W01-COV-RGXPDUMP-TRACE; COV-PDUMP-004; "
        "new-rgx-pdump-trace-authz:rogue-mips](#finding-2)" in markdown
    )


def test_projection_keeps_standard_findings_table_unchanged() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "scoped_path"
    coverage["inventoryStrategy"] = "scoped_path"
    finding = findings["findings"][0]
    finding["title"] = "Parser boundary [SCAN-001-parser]"
    finding["extensions"] = {"ledgerRowId": "SCAN-001-parser"}

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Finding | Severity | Confidence | Detailed write-up |" in markdown
    assert "| Findings | Reports | Severity | Confidence | Detailed write-up |" not in markdown
    assert "| Reportable findings | 1 |" in markdown
    assert "| Report instances |" not in markdown
    assert "[Parser boundary \\[SCAN-001-parser\\]](#finding-1)" in markdown


def test_projection_rejects_unsafe_detailed_writeup_path() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["writeup"] = {"reportPath": "../outside.md"}

    with pytest.raises(PROJECTION.ReportProjectionError, match="invalid reportPath"):
        PROJECTION.build_report_markdown(manifest, findings, coverage)

    findings["findings"][0]["writeup"] = {"reportPath": "findings/one/two.md"}
    with pytest.raises(PROJECTION.ReportProjectionError, match="invalid reportPath"):
        PROJECTION.build_report_markdown(manifest, findings, coverage)


def test_projection_rejects_duplicate_detailed_writeup_paths() -> None:
    manifest, findings, coverage = canonical_documents()
    report_path = "findings/parser-boundary/parser-boundary.md"
    findings["findings"][0]["writeup"] = {"reportPath": report_path}
    duplicate = copy.deepcopy(findings["findings"][0])
    duplicate["title"] = "Second parser boundary"
    findings["findings"].append(duplicate)

    with pytest.raises(PROJECTION.ReportProjectionError, match="duplicate writeup reportPath"):
        PROJECTION.build_report_markdown(manifest, findings, coverage)

    duplicate["writeup"] = {"reportPath": "findings/second-boundary/second-boundary.md"}
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert f"[Open report]({report_path})" in markdown
    assert "[Open report](findings/second-boundary/second-boundary.md)" in markdown


def test_projection_links_structural_hardening_portfolio() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["hardening"] = {"portfolioPath": "hardening/hardening.md"}

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "## Structural Hardening" in markdown
    assert "[Open the structural hardening portfolio](hardening/hardening.md)" in markdown
    assert "do not indicate that any finding has been remediated" in markdown


def test_projection_omits_absent_structural_hardening_portfolio() -> None:
    markdown = PROJECTION.generate_report_markdown(*canonical_documents()).decode()

    assert "## Structural Hardening" not in markdown


def test_projection_rejects_unsafe_structural_hardening_portfolio() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["hardening"] = {"portfolioPath": "../hardening.md"}

    with pytest.raises(PROJECTION.ReportProjectionError, match="invalid portfolioPath"):
        PROJECTION.build_report_markdown(manifest, findings, coverage)


def test_projection_escapes_markdown_link_syntax_in_finding_title() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["title"] = "Parser ](https://example.com) [boundary"

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "[Parser \\](https://example.com) \\[boundary](#finding-1)" in markdown
    assert "[Parser ](https://example.com) [boundary](" not in markdown


def test_projection_normalizes_target_and_quotes_scope_control_characters() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["target"]["displayName"] = "repo\n## Injected target heading"
    manifest["scan"]["scope"]["includePaths"] = ["src\n## Injected path heading"]
    coverage["includePaths"] = ["src\n## Injected path heading"]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "\n## Injected target heading" not in markdown
    assert "\n## Injected path heading" not in markdown
    assert "# Security Review: repo ## Injected target heading" in markdown
    assert '- Included paths: `"src\\n## Injected path heading"`' in markdown


@pytest.mark.parametrize(
    ("path", "marker"),
    [
        (" ", "`"),
        ("  ", "`"),
        (" service ", "`"),
        ("a,b.ts", "`"),
        ("a  b", "`"),
        (" a`b ", "``"),
        ("a``b,c", "```"),
    ],
)
def test_projection_preserves_ambiguous_literal_paths(path: str, marker: str) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["includePaths"] = [path]
    coverage["excludePaths"] = [path]
    findings["findings"][0]["locations"] = [{"path": path, "startLine": 1}]
    findings["findings"][0]["codeEvidence"] = [
        {"id": "source", "label": "Source", "path": path, "startLine": 1, "code": "source()"}
    ]
    findings["findings"][0]["rootCause"] = {"evidenceRefs": ["source"]}

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert f'- Included paths: {marker}"{path}"{marker}' in markdown
    assert f'- Excluded paths: {marker}"{path}"{marker}' in markdown
    assert f'| Affected lines | {marker}"{path}"{marker}:1 |' in markdown
    assert f'{marker}"{path}":1{marker}' in markdown


def test_projection_distinguishes_repeated_spaces_from_ordinary_path_spacing() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["includePaths"] = ["a  b", "a b", " ", "  "]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert '- Included paths: `"a  b"`, a b, `" "`, `"  "`' in markdown


def test_projection_keeps_printable_non_ascii_in_quoted_paths() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["includePaths"] = ["docs/Résumé, final.md", "docs/a\u202eb, c.md"]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert '- Included paths: `"docs/Résumé, final.md"`, `"docs/a\\u202eb, c.md"`' in markdown


def test_projection_includes_exact_target_identity() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["target"].update(
        {
            "kind": "git_diff",
            "targetId": "repo-1",
            "baseRevision": "base-sha",
            "headRevision": "head-sha",
            "snapshotDigest": "codex-security-snapshot/v1:sha256:" + "a" * 64,
        }
    )

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "- Target kind: git\\_diff" in markdown
    assert "- Target ID: repo-1" in markdown
    assert "- Revision range: base-sha...head-sha" in markdown
    assert "- Snapshot digest: codex-security-snapshot/v1:sha256:" in markdown


def test_generate_report_markdown_accepts_escaped_pipes_in_metadata() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["confidence"]["rationale"] = "Direct | trace."

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage)

    assert "| Confidence rationale | Direct \\| trace. |" in markdown.decode()


def test_projection_treats_escaped_canonical_markdown_as_text() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["title"] = "Parser ](https://example.com) [boundary"
    findings["findings"][0]["remediation"] = "[Open report](file:///tmp/report.md)"

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "[Parser ](https://example.com) [boundary](" not in markdown
    assert "\\[Open report\\](file:///tmp/report.md)" in markdown


def test_projection_escapes_raw_html_in_markdown() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["summary"] = '<img src="x" onerror="alert(1)">'

    markdown_text = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert '<img src="x" onerror="alert(1)">' not in markdown_text
    assert r'\<img src="x" onerror="alert(1)"\>' in markdown_text


def test_projection_omits_informational_findings() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["severity"]["level"] = "informational"

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Reportable findings | 0 |" in markdown
    assert "### No findings" in markdown
    assert "No findings were reported." in markdown
    assert "Parser \\| boundary" not in markdown


def test_projection_does_not_claim_completed_gates_for_stopped_scan() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["status"] = "failed"
    findings["findings"] = []

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "survived the canonical discovery, validation" not in markdown
    assert "No vulnerability conclusion can be drawn" in markdown


@pytest.mark.parametrize(
    "reason",
    [
        "Validation was deferred because the scan reached its cost limit.",
        (
            "The configured discovery time limit elapsed before any source review completed. "
            "Saved findings and pending review were preserved without a completed reduction."
        ),
        "The parser runtime could not be inspected in this environment.",
    ],
)
def test_projection_preserves_follow_up_without_classifying_its_reason(reason: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"] = []
    coverage["deferred"] = [
        {
            "id": "candidate-parser",
            "reason": reason,
            "paths": ["src/parser.py"],
        }
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "No findings were reported." in markdown
    assert "## Open Questions And Follow Up" in markdown
    assert reason in markdown
    assert "Review deferred unit candidate-parser" in markdown
    assert "Paths: src/parser.py." in markdown


def test_finding_summary_link_uses_stable_markdown_anchor() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["title"] = "Missing <tenant_id> check"

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert '<a id="finding-1"></a>' in markdown


def test_projection_keeps_deferred_follow_up_with_open_questions() -> None:
    manifest, findings, coverage = canonical_documents()

    coverage["openQuestions"] = [{"question": "Is production authentication enabled?"}]
    coverage["deferred"] = [
        {
            "id": "parser-review",
            "reason": "Parser review incomplete.",
            "paths": ["src/parser.py"],
            "surfaceIds": ["parser-surface"],
        }
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "Is production authentication enabled?" in markdown
    assert "Parser review incomplete." in markdown
    assert "Review deferred unit parser-review" in markdown
    assert "Paths: src/parser.py." in markdown
    assert "Surfaces: parser-surface." in markdown


def test_projection_includes_surface_evidence_receipts() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["surfaces"] = [
        {
            "id": "parser-surface",
            "label": "Parser",
            "disposition": "no_issue_found",
            "receiptRefs": ["artifacts/receipts/parser.jsonl"],
            "notes": "Reviewed parser entrypoints.",
        }
    ]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "Reviewed parser entrypoints. Evidence: artifacts/receipts/parser.jsonl" in markdown


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


@pytest.mark.parametrize(
    ("source_path", "rendered_location"),
    [
        ("app/api/[id]/route.ts", "`app/api/[id]/route.ts:7`"),
        ("app/api/`id`/route.ts", "``app/api/`id`/route.ts:7``"),
        ("`route`.ts", "`` `route`.ts:7 ``"),
    ],
)
def test_projection_preserves_identifier_text_and_code_path_spelling(
    source_path: str, rendered_location: str
) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["title"] = "__proto__ pollution"
    finding["validation"] = {"evidenceRefs": ["source"]}
    finding["codeEvidence"] = [
        {
            "id": "source",
            "label": "Source control",
            "path": source_path,
            "startLine": 7,
            "code": "handle(request)",
            "explanation": "A source-backed operation.",
        }
    ]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert "\\_\\_proto\\_\\_ pollution" in markdown
    assert rendered_location in markdown


@pytest.mark.parametrize(
    ("bounds", "rendered_location"),
    [
        ({"startLine": 37, "endLine": None}, "`src/evidence.py:37`"),
        ({"startLine": 48, "endLine": 47}, "`src/evidence.py:48`"),
        ({"startLine": 59, "endLine": "60"}, "`src/evidence.py:59`"),
        ({"startLine": 37, "endLine": True}, "`src/evidence.py:37`"),
        ({"startLine": True, "endLine": 4}, "`src/evidence.py`"),
        ({"startLine": 0}, "`src/evidence.py`"),
        ({"startLine": -1}, "`src/evidence.py`"),
    ],
)
def test_projection_normalizes_invalid_legacy_code_evidence_bounds(
    bounds: dict[str, object], rendered_location: str
) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["validation"] = {"evidenceRefs": ["source"]}
    finding["code_evidence"] = [
        {
            "id": "source",
            "label": "Source control",
            "path": "src/evidence.py",
            **bounds,
            "code": "handle(request)",
        }
    ]
    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert rendered_location in markdown
