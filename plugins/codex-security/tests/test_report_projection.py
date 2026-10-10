from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from workbench_test_support import load_script

PLUGIN_DIR = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.cross_platform

PROJECTION = load_script("report_projection")


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
        "completeness": "complete",
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


def test_projection_deduplicates_combined_and_retained_remediation_paragraphs() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    first = "Validate the record length."
    second = "Reject duplicate record keys."
    third = "Normalize keys before checking for duplicates."
    finding["remediation"] = f"{first}\n\n{second}"
    finding["provenance"] = {
        "sourceFindings": [
            {"id": "review-1:0", "finding": {"remediation": first}},
            {"id": "review-2:0", "finding": {"remediation": f"{second}\n\n{third}"}},
            {"id": "review-3:0", "finding": {"remediation": third}},
        ],
        "previousFindings": [{"remediation": f"{first}\n\n{second}\n\n{third}"}],
    }
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    for paragraph in (first, second, third):
        assert markdown.count(paragraph) == 1
    assert f"Source review-2:0: {third}" in markdown
    assert f"Source review-2:0: {second}" not in markdown
    assert findings == original


def test_projection_renders_partial_retained_assessments() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["provenance"] = {
        "sourceFindings": [
            {
                "id": "review-1:0",
                "finding": {
                    "severity": {"rationale": "Prior assessment."},
                    "confidence": {"level": "medium"},
                    "validation": {"method": "Prior validation."},
                },
            }
        ]
    }
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "**Unknown** — Prior assessment." in markdown
    assert "Prior validation." in markdown
    assert findings == original


@pytest.mark.parametrize(
    "retained_fields",
    [
        {"severity": {"level": None}},
        {"severity": {"level": []}},
        {"locations": None},
        {"locations": [None, {}, {"path": "src/retained.py"}]},
        {"confidence": {"rationale": None}},
        {"confidence": {"rationale": {"unstructured": "Historical context"}}},
    ],
)
def test_projection_renders_schema_valid_noncanonical_history(retained_fields: dict) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding.update(
        findingId="csf_" + "0" * 24,
        occurrenceId="occ_" + "0" * 24,
        ruleId="synthetic-check",
        identity={"anchor": "shared-check"},
        fingerprints={
            "algorithm": "codex-security/v1",
            "primary": "codex-security/v1:sha256:" + "0" * 64,
        },
        provenance={
            "source": "local_plugin",
            "previousFindings": [
                {
                    "validation": {"method": "Retained offline evidence."},
                    "rootCause": {"code": "synthetic_check(record)"},
                    **retained_fields,
                }
            ],
        },
    )
    findings.update(documentType="codex-security.findings", schemaVersion="1.0", scanId="test")
    schema = json.loads((PLUGIN_DIR / "schemas/findings.schema.json").read_text())
    Draft202012Validator(schema).validate(findings)
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert markdown.count("Retained offline evidence.") == 1
    assert markdown.count("synthetic_check(record)") == 1
    assert "| Severity | high |" in markdown
    assert findings == original


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


@pytest.mark.parametrize("source_count", [1, 2])
@pytest.mark.parametrize("history_field", ["sourceFindings", "previousFindings"])
def test_projection_renders_composed_details_alongside_source_writeup(
    source_count: int, history_field: str
) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "deep_repository"
    finding = findings["findings"][0]
    report_path = "findings/first-parser/first-parser.md"
    finding["writeup"] = {"reportPath": report_path}
    finding["provenance"] = {
        "source": "local_plugin",
        "sourceFindingIds": [f"scan-{index}:0" for index in range(source_count)],
        "sourceFindings": [
            {"id": f"scan-{index}:0", "finding": copy.deepcopy(finding)}
            for index in range(source_count)
        ],
    }
    if history_field == "previousFindings":
        finding["provenance"][history_field] = [
            source["finding"] for source in finding["provenance"].pop("sourceFindings")
        ]
    finding["summary"] = "Combined evidence establishes both affected entry points."
    finding["remediation"] = "Apply the shared fix to both entry points."
    original = copy.deepcopy(findings)

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert finding["summary"] in markdown
    assert finding["remediation"] in markdown
    assert f"]({report_path})" in markdown
    assert "See the [detailed technical write-up]" not in markdown
    assert findings == original


@pytest.mark.parametrize("linked_writeup", [False, True])
def test_projection_retains_distinct_source_evidence_without_repeating_reports(
    linked_writeup: bool,
) -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["summary"] = "Combined observations of the shared check."
    if linked_writeup:
        finding["writeup"] = {"reportPath": "findings/parser/parser.md"}
    source = copy.deepcopy(finding)
    source["title"] = "Retained source title"
    source["summary"] = "The second source establishes an alternate entry point."
    source["rootCause"] = {
        "summary": "A distinct source identifies the missing check.",
        "evidenceRefs": ["source-check"],
    }
    source["codeEvidence"] = [
        {"id": "source-check", "code": "synthetic_check(record)", "language": "python"}
    ]
    source["validation"] = {
        "summary": "The second source has independent validation.",
        "assertions": ["The alternate path reaches the shared check."],
        "evidence": ["An offline fixture confirms the alternate path."],
        "counterEvidence": ["The protected path rejects the same fixture."],
        "limitations": ["Deployment configuration remains unverified."],
    }
    source["attackPath"] = {
        "dataFlow": {"summary": "The alternate entry point uses the shared check."},
        "reachability": {"summary": "The caller must select the alternate entry point."},
        "preconditions": ["The alternate mode must be enabled."],
    }
    source["severity"]["rationale"] = "The alternate path explains the highest severity."
    historical = {"validation": {"summary": "A prior accepted validation remains relevant."}}
    finding["provenance"] = {
        "sourceFindings": [
            {"id": "first:0", "finding": copy.deepcopy(finding)},
            {"id": "second:0", "finding": source},
            {"id": "third:0", "finding": copy.deepcopy(source)},
        ],
        "previousFindings": [copy.deepcopy(source), historical],
    }
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    for detail in (
        finding["summary"],
        source["summary"],
        source["rootCause"]["summary"],
        "synthetic_check(record)",
        source["validation"]["summary"],
        *source["validation"]["assertions"],
        *source["validation"]["evidence"],
        *source["validation"]["counterEvidence"],
        *source["validation"]["limitations"],
        source["attackPath"]["dataFlow"]["summary"],
        source["attackPath"]["reachability"]["summary"],
        *source["attackPath"]["preconditions"],
        source["severity"]["rationale"],
        historical["validation"]["summary"],
    ):
        assert markdown.count(detail) == 1
    assert "Source second:0:" in markdown
    assert source["title"] not in markdown
    assert markdown.count('id="finding-1"') == 1
    if linked_writeup:
        assert "](findings/parser/parser.md)" in markdown
    assert findings == original


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


@pytest.mark.parametrize("candidate_field", ["provenance", "extensions"])
@pytest.mark.parametrize("same_worker", [False, True])
@pytest.mark.parametrize("source_metadata", ["references", "null", "opaque", "mixed"])
@pytest.mark.parametrize("coverage_mode", ["deep_repository", "scoped_path"])
def test_projection_keeps_worker_local_candidates_distinct(
    candidate_field, same_worker, source_metadata, coverage_mode
) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = coverage_mode
    coverage["inventoryStrategy"] = (
        "scoped_path" if coverage_mode == "scoped_path" else "repository"
    )
    first = findings["findings"][0]
    first["title"] = "First retained finding"
    first["provenance"] = {"sourceFindingIds": ["worker-001:0"]}
    first.setdefault(candidate_field, {})["candidateId"] = "candidate-1"
    second = copy.deepcopy(first)
    second["occurrenceId"] = "occ_2"
    second["title"] = "Second retained finding"
    second["provenance"]["sourceFindingIds"] = ["worker-001:1" if same_worker else "worker-002:0"]
    for finding in (first, second):
        if source_metadata == "null":
            finding["provenance"]["sourceFindingIds"] = None
        elif source_metadata == "opaque":
            finding["provenance"]["sourceFindingIds"] = [{"origin": "saved source"}]
        elif source_metadata == "mixed":
            finding["provenance"]["sourceFindingIds"].append({"origin": "saved source"})
    findings["findings"].append(second)
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    count = (
        1
        if same_worker or candidate_field == "extensions" or source_metadata in ("null", "opaque")
        else 2
    )
    if (
        coverage_mode == "scoped_path"
        and candidate_field == "provenance"
        and source_metadata in ("null", "opaque")
    ):
        assert "| Reportable findings | 2 |" in markdown
        assert "| Report instances |" not in markdown
    else:
        assert f"| Reportable DSS findings | {count} |" in markdown
        assert "| Report instances | 2 |" in markdown
    assert "First retained finding" in markdown
    assert "Second retained finding" in markdown
    assert findings == original


@pytest.mark.parametrize(
    "workers, expected_groups",
    [
        ([["a", "b"], ["a"]], 1),
        ([["a"], ["b"], ["a", "b"]], 1),
        ([["a", "b"], ["b", "c"], ["c"]], 1),
        ([["a"], ["b"]], 2),
    ],
)
def test_projection_groups_partially_corroborated_candidate_reports(workers, expected_groups):
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "deep_repository"
    template = findings["findings"][0]
    findings["findings"] = []
    for index, sources in enumerate(workers):
        finding = copy.deepcopy(template)
        finding["occurrenceId"] = f"occ_{index}"
        finding["title"] = f"Retained report {index}"
        finding["provenance"] = {
            "candidateId": "candidate-1",
            "sourceFindingIds": [f"source:worker-{worker}:{index}" for worker in sources],
        }
        finding["extensions"] = {"candidateId": "candidate-1", "reportId": f"report-{index}"}
        findings["findings"].append(finding)
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert f"| Reportable DSS findings | {expected_groups} |" in markdown
    assert f"| Report instances | {len(workers)} |" in markdown
    for index in range(len(workers)):
        assert f"Retained report {index}" in markdown
    assert findings == original


@pytest.mark.parametrize("candidate_field", ["provenance", "extensions"])
@pytest.mark.parametrize("second_candidate", ["candidate-1", "candidate-2"])
def test_projection_groups_by_retained_worker_candidate(candidate_field, second_candidate):
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "deep_repository"
    template = findings["findings"][0]
    first = copy.deepcopy(template)
    first["provenance"] = {
        "candidateId": "candidate-1",
        "sourceFindingIds": ["source:worker-a:0", "source:worker-b:0"],
        "sourceFindings": [
            {
                "id": "source:worker-a:0",
                "finding": {candidate_field: {"candidateId": "candidate-1"}},
            },
            {
                "id": "source:worker-b:0",
                "finding": {candidate_field: {"candidateId": second_candidate}},
            },
        ],
    }
    second = copy.deepcopy(template)
    second["occurrenceId"] = "occ_2"
    second["provenance"] = {
        "candidateId": "candidate-1",
        "sourceFindingIds": ["source:worker-b:1"],
        "sourceFindings": [
            {
                "id": "source:worker-b:1",
                "finding": {candidate_field: {"candidateId": "candidate-1"}},
            },
        ],
    }
    findings["findings"] = [first, second]
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    count = 1 if second_candidate == "candidate-1" else 2
    assert f"| Reportable DSS findings | {count} |" in markdown
    assert "| Report instances | 2 |" in markdown
    assert findings == original


@pytest.mark.parametrize("shared_instance", [False, True])
def test_projection_keeps_retained_findings_without_optional_ids_distinct(shared_instance):
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "deep_repository"
    template = findings["findings"][0]
    findings["findings"] = []
    for index in range(2):
        finding = copy.deepcopy(template)
        finding["occurrenceId"] = f"occ_{index}"
        finding["extensions"] = {"candidateId": f"candidate-{index}", "reportId": f"report-{index}"}
        source = {"provenance": {"source": "local_plugin"}}
        if shared_instance:
            source.update(
                ruleId=f"rule-{index}",
                identity={"anchor": f"anchor-{index}", "instance": "primary"},
            )
        finding["provenance"] = {
            "sourceFindingIds": [f"worker:{index}"],
            "sourceFindings": [{"id": f"worker:{index}", "finding": source}],
        }
        findings["findings"].append(finding)
    original = copy.deepcopy(findings)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Reportable DSS findings | 2 |" in markdown
    assert "| Report instances | 2 |" in markdown
    assert findings == original


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


@pytest.mark.parametrize("candidate", [False, True])
def test_projection_keeps_standard_findings_table_unchanged(candidate: bool) -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["mode"] = "scoped_path"
    coverage["inventoryStrategy"] = "scoped_path"
    finding = findings["findings"][0]
    finding["title"] = "Parser boundary [SCAN-001-parser]"
    finding["extensions"] = {"ledgerRowId": "SCAN-001-parser"}
    if candidate:
        finding["provenance"] = {"candidateId": "candidate-1"}

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "| Finding | Severity | Confidence | Detailed write-up |" in markdown
    assert "| Findings | Reports | Severity | Confidence | Detailed write-up |" not in markdown
    assert "| Reportable findings | 1 |" in markdown
    assert "| Report instances |" not in markdown
    assert "[Parser boundary \\[SCAN-001-parser\\]](#finding-1)" in markdown


@pytest.mark.parametrize("report_path", ["../outside.md", "findings/one/../../outside.md"])
def test_projection_rejects_unsafe_detailed_writeup_path(report_path: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["writeup"] = {"reportPath": report_path}

    with pytest.raises(PROJECTION.ReportProjectionError, match="invalid reportPath"):
        PROJECTION.build_report_markdown(manifest, findings, coverage)


@pytest.mark.parametrize("report_path", ["findings/one/two.md", "findings/source-scan/one/two.md"])
def test_projection_preserves_original_report_names(report_path: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["writeup"] = {"reportPath": report_path}
    assert report_path in PROJECTION.build_report_markdown(manifest, findings, coverage)


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


@pytest.mark.parametrize("prefix", ["", "artifacts/deep-scan/passes/pass-1/"])
@pytest.mark.parametrize("second_level", ["high", "informational"])
def test_projection_preserves_historical_writeups_in_shared_evidence_directories(
    prefix: str, second_level: str
) -> None:
    manifest, findings, coverage = canonical_documents()
    first = findings["findings"][0]
    first["writeup"] = {"reportPath": prefix + "findings/shared/first.md"}
    second = copy.deepcopy(first)
    second["title"] = "Second parser boundary"
    second["severity"]["level"] = second_level
    second["writeup"] = {"reportPath": prefix + "findings/shared/second.md"}
    findings["findings"].append(second)

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)
    assert first["writeup"]["reportPath"] in markdown
    assert (second["writeup"]["reportPath"] in markdown) == (second_level != "informational")


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


def test_projection_normalizes_target_and_scope_paths() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["target"]["displayName"] = "repo\n## Injected target heading"
    manifest["scan"]["scope"]["includePaths"] = ["src\n## Injected path heading"]
    coverage["includePaths"] = ["src\n## Injected path heading"]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "\n## Injected target heading" not in markdown
    assert "\n## Injected path heading" not in markdown
    assert "# Security Review: repo ## Injected target heading" in markdown
    assert "- Included paths: src ## Injected path heading" in markdown


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
    assert (
        "No reportable findings survived the canonical discovery, validation, "
        "and reportability gates."
    ) in markdown
    assert "Parser \\| boundary" not in markdown


def test_projection_does_not_claim_completed_gates_for_stopped_scan() -> None:
    manifest, findings, coverage = canonical_documents()
    manifest["scan"]["status"] = "failed"
    findings["findings"] = []
    coverage["completeness"] = "partial"

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert "survived the canonical discovery, validation" not in markdown
    assert "No vulnerability conclusion can be drawn" in markdown


@pytest.mark.parametrize(
    "reason",
    [
        (
            "Validation was deferred because the scan reached its cost limit: "
            "parser accepts untrusted input. Evidence: request data reaches a SQL query."
        ),
        "Validation was deferred because the scan reached its cost limit.",
    ],
)
def test_projection_explains_unvalidated_findings_after_cost_limit(reason: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"] = []
    coverage["completeness"] = "partial"
    coverage["deferred"] = [
        {"id": "candidate-parser", "reason": reason, "paths": ["src/parser.py"]}
    ]

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "| Reportable findings | 0 |" in markdown
    assert "| Coverage | partial |" in markdown
    assert (
        "No findings were validated before the scan reached its cost limit. "
        "Review the deferred candidates in Open Questions And Follow Up."
    ) in markdown
    assert "No reportable findings survived" not in markdown
    assert "## Open Questions And Follow Up" in markdown
    assert reason in markdown
    assert "Review deferred unit candidate-parser" in markdown
    assert "Paths: src/parser.py." in markdown


@pytest.mark.parametrize(
    "reason",
    [
        "The parser runtime could not be inspected in this environment.",
        "The retry budget was exhausted before parser validation could finish.",
        "The runtime resource budget prevented the optional check.",
        "An upstream service reached its own cost limit during validation.",
        "Validation was deferred because the scan reached its cost limit unexpectedly.",
    ],
)
def test_projection_preserves_no_findings_text_for_other_partial_coverage(reason: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"] = []
    coverage["completeness"] = "partial"
    coverage["deferred"] = [
        {
            "id": "candidate-parser",
            "reason": reason,
            "paths": ["src/parser.py"],
        }
    ]

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert (
        "No reportable findings survived the canonical discovery, validation, "
        "and reportability gates."
    ) in markdown
    assert "No findings were validated before" not in markdown


def test_projection_explains_timeout_before_source_review() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"] = []
    coverage["completeness"] = "partial"
    coverage["deferred"] = [
        {
            "id": "source-review",
            "reason": (
                "The configured discovery time limit elapsed before any source review completed."
            ),
        }
    ]

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert "| Reportable findings | 0 |" in markdown
    assert "| Coverage | partial |" in markdown
    assert (
        "No source review completed before the configured time limit. "
        "No vulnerability conclusion can be drawn."
    ) in markdown
    assert "No reportable findings survived" not in markdown
    assert "## Open Questions And Follow Up" in markdown


@pytest.mark.parametrize(
    ("completeness", "reason"),
    [
        (
            "complete",
            "The configured discovery time limit elapsed before any source review completed.",
        ),
        (
            "partial",
            "The configured discovery time limit elapsed during source review.",
        ),
        ("partial", "Validation was deferred because a separate cost limit was reached."),
    ],
)
def test_projection_preserves_other_no_findings_results(completeness: str, reason: str) -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"] = []
    coverage["completeness"] = completeness
    coverage["deferred"] = [{"id": "source-review", "reason": reason}]

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert (
        "No reportable findings survived the canonical discovery, validation, "
        "and reportability gates."
    ) in markdown
    assert "No source review completed" not in markdown


def test_finding_summary_link_uses_stable_markdown_anchor() -> None:
    manifest, findings, coverage = canonical_documents()
    findings["findings"][0]["title"] = "Missing <tenant_id> check"

    markdown = PROJECTION.generate_report_markdown(manifest, findings, coverage).decode()

    assert '<a id="finding-1"></a>' in markdown


def test_projection_keeps_deferred_follow_up_with_open_questions() -> None:
    manifest, findings, coverage = canonical_documents()
    coverage["completeness"] = "partial"
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


def test_retained_findings_visit_sources_before_history_and_handle_cycles() -> None:
    previous = {"remediation": "Retain the earlier fix."}
    source = {"provenance": {"previousFindings": [previous, None]}}
    finding = {
        "provenance": {
            "sourceFindings": [{"id": "source:0", "finding": source}, {"finding": None}],
            "previousFindings": [previous],
        }
    }
    previous["provenance"] = {"previousFindings": [finding]}
    assert [
        (source_id, id(value)) for source_id, value in PROJECTION.retained_findings(finding)
    ] == [
        ("finding", id(finding)),
        ("source:0", id(source)),
        ("source:0", id(previous)),
    ]


def test_historical_severity_does_not_borrow_current_rationale() -> None:
    manifest, findings, coverage = canonical_documents()
    finding = findings["findings"][0]
    finding["severity"]["rationale"] = "Current assessment rationale."
    finding["severity"]["changeConditions"] = "Current assessment conditions."
    finding["provenance"] = {"previousFindings": [{"severity": {"level": "low"}}]}

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    assert markdown.count("Current assessment rationale.") == 1
    assert markdown.count("Current assessment conditions.") == 1
    assert (
        "**Low** — The scan assigned low severity; no separate canonical severity rationale was recorded."
        in markdown
    )


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
