from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent


def load_script(name: str) -> ModuleType:
    path = PLUGIN_DIR / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
            "threatModel": {"summary": "# Injected threat heading\nThreat details"},
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


def test_projection_normalizes_multiline_and_block_structural_text() -> None:
    markdown = PROJECTION.build_report_markdown(*canonical_documents())

    assert "\n## Injected" not in markdown
    assert "\n# Injected" not in markdown
    assert "\n```" not in markdown
    assert "Text: ## Injected scope - nested item" in markdown
    assert "Text: # Injected threat heading Threat details" in markdown
    assert "Text: \\`\\`\\` code fence \\`\\`\\`" in markdown
    assert "Parser \\| boundary ## Injected finding heading" in markdown
    assert "Text: ## Injected remediation - unsafe instruction" in markdown


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


def test_projection_renders_nested_attack_path_code_evidence() -> None:
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
            "evidence_refs": ["archive-sink"],
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
        "summary": "An authenticated uploader can trigger archive extraction."
    }

    markdown = PROJECTION.build_report_markdown(manifest, findings, coverage)

    reachability = markdown.split("#### Reachability", 1)[1].split("#### Severity", 1)[0]
    assert "An authenticated uploader can trigger archive extraction." in reachability
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

    assert "- Target kind: git_diff" in markdown
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
