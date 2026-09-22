"""Exercise imported claims through the public workbench command boundary."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import initialize_git_repository, run_workbench


def setup_report(
    tmp_path: Path, *, ecosystem: str = "npm", finding_count: int = 2
) -> tuple[Path, Path, str, list[dict[str, Any]]]:
    """Create an isolated repository and import synthetic scanner claims."""
    target, state = tmp_path / "repo", tmp_path / "state"
    initialize_git_repository(target)
    (target / "app.js").write_text("const parser = require('parser');\nparser.parse(input);\n")
    (target / "package-lock.json").write_text(
        json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/parser": {"version": "1.0.0"}}}
        )
    )
    report_path = tmp_path / "scanner.json"
    report_path.write_text(
        json.dumps(
            {
                "packageManager": ecosystem,
                "targetFile": "package-lock.json",
                "vulnerabilities": [
                    {
                        "id": f"SNYK-{index}",
                        "title": f"Parser issue {index}",
                        "packageName": "parser",
                        "version": "1.0.0",
                        "severity": "high",
                        "from": ["app", "parser@1.0.0"],
                        "reachability": "not-reachable",
                        "fixedIn": ["2.0.0"],
                    }
                    for index in range(finding_count)
                ],
            }
        )
    )
    report = run_workbench(
        state,
        "import-dependency-findings",
        "--target-path",
        str(target),
        "--report-path",
        str(report_path),
        "--vendor",
        "snyk",
    )["report"]
    findings = run_workbench(state, "get-dependency-report", "--report-id", report["id"])[
        "findings"
    ]
    return target, state, report["id"], findings


def start(state: Path, report_id: str, ids: list[str]) -> dict[str, Any]:
    """Start an explicitly selected assessment."""
    arguments = [argument for item in ids for argument in ("--finding-id", item)]
    return run_workbench(state, "start-dependency-assessment", "--report-id", report_id, *arguments)


def result(
    finding_id: str,
    target: Path,
    *,
    verdict: str = "affects_application",
    input_path: str = "package-lock.json",
) -> dict[str, Any]:
    """Describe a checked application call without promoting the vendor label."""
    return {
        "findingId": finding_id,
        "verdict": verdict,
        "basis": "unresolved" if verdict == "inconclusive" else "code_path",
        "versionBasis": "resolved",
        "limitations": [],
        "advisoryEvidence": [],
        "externalEvidence": [],
        "investigation": [
            {
                "action": "Trace parser input in app.js.",
                "result": "The caller passes request input to parser.parse.",
            }
        ],
        "attackPath": {
            "entryPoint": "The application receives a request in app.js.",
            "attackerControl": "The request body supplies input.",
            "vulnerableOperation": "parser.parse consumes input at app.js:2.",
            "prerequisites": "The parser uses the affected default configuration.",
        }
        if verdict == "affects_application"
        else None,
        "summary": "The application parses user input.",
        "packageVersion": "1.0.0",
        "resolution": {
            "argv": ["npm", "ls", "--all", "--json", "--offline", "--silent"],
            "cwd": ".",
            "exitCode": 0,
            "stdout": '{"dependencies":{"parser":{"version":"1.0.0"}}}',
            "stderr": "",
            "package": {"ecosystem": "npm", "name": "parser"},
            "selectedVersions": ["1.0.0"],
            "explanation": "The application graph selects parser 1.0.0.",
            "inputFiles": [
                {
                    "path": input_path,
                    "sha256": hashlib.sha256((target / input_path).read_bytes()).hexdigest(),
                }
            ],
            "issues": [],
        },
        "codeEvidence": [
            {
                "path": "app.js",
                "startLine": 2,
                "explanation": "User input reaches the dependency parser.",
            }
        ],
        "applicability": "The vulnerable parser accepts attacker-controlled input.",
        "unknowns": [],
    }


def record(
    tmp_path: Path,
    state: Path,
    assessment_id: str,
    results: list[dict[str, object]],
    *,
    check: bool = True,
) -> dict[str, Any]:
    """Submit assessment results from a file outside the assessed repository."""
    path = tmp_path / "results.json"
    path.write_text(json.dumps(results))
    return run_workbench(
        state,
        "record-dependency-assessments",
        "--assessment-id",
        assessment_id,
        "--results-path",
        str(path),
        check=check,
    )


@pytest.mark.parametrize("shape", ["artifact", "scores", "ndjson", "array", "wrapper"])
def test_import_socket_report_encodings(tmp_path: Path, shape: str) -> None:
    """Persist Socket JSON and single-event NDJSON without changing source evidence."""
    target, state = tmp_path / "repo", tmp_path / "state"
    initialize_git_repository(target)
    alert = {
        "key": "example-alert",
        "type": "cve",
        "severity": "high",
        "props": {"cveId": "CVE-2099-0001"},
    }
    artifact = {"type": "npm", "name": "example", "version": "1.0", "alerts": [alert]}
    scores = {"_type": "scores", "value": {}}
    content = {
        "artifact": json.dumps(artifact) + "\n",
        "scores": json.dumps(scores) + "\n",
        "ndjson": json.dumps(artifact) + "\n" + json.dumps(scores) + "\n",
        "array": json.dumps([artifact]),
        "wrapper": json.dumps({"ok": True, "data": [artifact]}),
    }[shape]
    report_path = tmp_path / "socket.json"
    report_path.write_text(content)
    report = run_workbench(
        state,
        "import-dependency-findings",
        "--target-path",
        str(target),
        "--report-path",
        str(report_path),
        "--vendor",
        "socket",
    )["report"]
    findings = run_workbench(state, "get-dependency-report", "--report-id", report["id"])[
        "findings"
    ]
    assert report["findingCount"] == (0 if shape == "scores" else 1)
    assert len(findings) == report["findingCount"]
    for finding in findings:
        detail = run_workbench(
            state,
            "get-dependency-finding",
            "--report-id",
            report["id"],
            "--finding-id",
            finding["id"],
        )
        assert detail["finding"]["original"] == alert
    assert all(finding["assessment"] is None for finding in findings)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT original_report FROM dependency_reports WHERE id = ?", (report["id"],)
            ).fetchone()[0]
            == content
        )


def test_import_assess_selection_and_reviewed_fix(tmp_path: Path) -> None:
    target, state, report_id, findings = setup_report(tmp_path)
    assert len(findings) == 2
    assert all(finding["assessment"] is None for finding in findings)
    assert findings[0]["originalSeverity"] == "high"
    assert findings[0]["inputWarnings"] == []
    selected = start(state, report_id, [findings[0]["id"]])
    assessment_id = selected["assessment"]["id"]
    assert start(state, report_id, [findings[0]["id"]])["assessment"]["id"] == assessment_id
    assert [finding["id"] for finding in selected["findings"]] == [findings[0]["id"]]
    output = result(findings[0]["id"], target)
    output["resolution"]["stdout"] += "\n" + " " * 70000
    recorded = record(tmp_path, state, assessment_id, [output])
    assert recorded["results"][0]["codeEvidence"][0]["excerpt"] == "parser.parse(input);"
    assert recorded["assessment"]["state"] == "complete"
    assert recorded["results"][0]["resolution"] == output["resolution"]
    page = run_workbench(
        state, "get-dependency-report", "--report-id", report_id, "--verdict", "pending"
    )
    assert [finding["id"] for finding in page["findings"]] == [findings[1]["id"]]
    detail = run_workbench(
        state,
        "get-dependency-finding",
        "--report-id",
        report_id,
        "--finding-id",
        findings[0]["id"],
        "--require-current",
    )
    assert detail["finding"]["original"]["reachability"] == "not-reachable"
    assert detail["finding"]["assessment"]["verdict"] == "affects_application"
    assert (
        target / "app.js"
    ).read_text() == "const parser = require('parser');\nparser.parse(input);\n"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_assessment_batch_retains_large_native_transcripts(tmp_path: Path) -> None:
    """Record a complete selection whose resolver output exceeds the report import cap."""
    target, state, report_id, findings = setup_report(tmp_path, finding_count=100)
    selected = start(state, report_id, [finding["id"] for finding in findings])
    results = [result(finding["id"], target) for finding in findings]
    for output in results:
        output["resolution"]["stdout"] += "\n" + " " * (90 * 1024)
    assert len(json.dumps(results).encode("utf-8")) > 8 * 1024 * 1024

    recorded = record(tmp_path, state, selected["assessment"]["id"], results)

    assert recorded["assessment"]["state"] == "complete"
    assert len(recorded["results"]) == 100
    assert [output["resolution"] for output in recorded["results"]] == [
        output["resolution"] for output in results
    ]


def test_resolver_hash_works_without_hashlib_file_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workbench_api: dict[str, Any]
) -> None:
    """Hash complete resolver inputs on Python versions without hashlib.file_digest."""
    content = b"resolver input\n" * 100000
    path = tmp_path / "resolver-input.json"
    path.write_bytes(content)
    monkeypatch.delattr(hashlib, "file_digest", raising=False)

    assert (
        workbench_api["dependency_imports"]._file_digest(path)
        == hashlib.sha256(content).hexdigest()
    )


def test_clean_submodule_code_evidence_is_bound_to_its_recorded_revision(tmp_path: Path) -> None:
    """Accept tracked submodule source while rejecting ignored files and later changes."""
    target, state, report_id, findings = setup_report(tmp_path)
    dependency = tmp_path / "dependency"
    initialize_git_repository(dependency)
    source = "parser.parse(request.body);\n"
    (dependency / "app.js").write_text(source)
    (dependency / ".gitignore").write_text("ignored.js\n")
    subprocess.run(["git", "add", "."], cwd=dependency, check=True)
    subprocess.run(
        ["git", "commit", "-qm", "Add synthetic application"], cwd=dependency, check=True
    )
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(dependency),
            "component",
        ],
        cwd=target,
        check=True,
    )
    subprocess.run(["git", "commit", "-qam", "Add synthetic submodule"], cwd=target, check=True)
    selected = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target)
    (target / "component/ignored.js").write_text(source)
    output["codeEvidence"][0].update(path="component/ignored.js", startLine=1)
    rejected = record(tmp_path, state, selected, [output], check=False)
    assert rejected["returncode"] != 0
    assert "Ignored files" in rejected["stderr"]

    output["codeEvidence"][0]["path"] = "component/app.js"
    recorded = record(tmp_path, state, selected, [output])
    assert recorded["results"][0]["codeEvidence"][0]["excerpt"] == source.strip()
    (target / "component/app.js").write_text("parser.parse('changed');\n")
    stale = run_workbench(
        state,
        "get-dependency-finding",
        "--report-id",
        report_id,
        "--finding-id",
        findings[0]["id"],
        "--require-current",
        check=False,
    )
    assert stale["returncode"] != 0
    assert "Dirty Git submodules" in stale["stderr"]


@pytest.mark.parametrize("flaw", ["missing", "unselected", "unknown", "path", "line", "version"])
def test_rejects_incomplete_or_unproven_assessments(tmp_path: Path, flaw: str) -> None:
    target, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target)
    if flaw == "unselected":
        output["findingId"] = findings[1]["id"]
    elif flaw == "unknown":
        output["unknowns"] = ["The call path is unresolved."]
    elif flaw == "path":
        output["codeEvidence"][0]["path"] = "../scanner.json"
    elif flaw == "line":
        output["codeEvidence"][0]["startLine"] = 50
    elif flaw == "version":
        output["packageVersion"] = "2.0.0"
    failed = record(
        tmp_path, state, assessment_id, [] if flaw == "missing" else [output], check=False
    )
    assert failed["returncode"] != 0
    assert (
        run_workbench(state, "get-dependency-assessment", "--assessment-id", assessment_id)[
            "assessment"
        ]["state"]
        == "pending"
    )
    assert (
        run_workbench(
            state,
            "get-dependency-finding",
            "--report-id",
            report_id,
            "--finding-id",
            findings[0]["id"],
        )["finding"]["assessment"]
        is None
    )


def test_changed_repository_blocks_results_and_fix(tmp_path: Path) -> None:
    target, state, report_id, findings = setup_report(tmp_path)
    first = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    pending = start(state, report_id, [findings[1]["id"]])["assessment"]["id"]
    record(tmp_path, state, first, [result(findings[0]["id"], target)])
    (target / "app.js").write_text("changed application\nstill two lines\n")
    assert (
        record(tmp_path, state, pending, [result(findings[1]["id"], target)], check=False)[
            "returncode"
        ]
        != 0
    )
    failed = run_workbench(
        state,
        "get-dependency-finding",
        "--report-id",
        report_id,
        "--finding-id",
        findings[0]["id"],
        "--require-current",
        check=False,
    )
    assert failed["returncode"] != 0


def test_missing_resolution_stays_inconclusive(tmp_path: Path) -> None:
    target, state, report_id, findings = setup_report(tmp_path)
    selection = start(state, report_id, [findings[0]["id"]])
    assert selection["findings"][0]["inputWarnings"] == []
    assessment_id = selection["assessment"]["id"]
    output = result(findings[0]["id"], target)
    output["resolution"] = None
    assert record(tmp_path, state, assessment_id, [output], check=False)["returncode"] != 0
    output.update(
        verdict="inconclusive",
        basis="unresolved",
        versionBasis=None,
        packageVersion=None,
        unknowns=[
            "Resolved package version is unavailable. Run the project-native resolver against its installed environment."
        ],
    )
    assert (
        record(tmp_path, state, assessment_id, [output])["results"][0]["verdict"] == "inconclusive"
    )
    assert (
        run_workbench(
            state,
            "get-dependency-finding",
            "--report-id",
            report_id,
            "--finding-id",
            findings[0]["id"],
            "--require-current",
            check=False,
        )["returncode"]
        != 0
    )


def test_ignored_resolution_input_is_bound_and_ignored_code_is_rejected(tmp_path: Path) -> None:
    target, state, report_id, findings = setup_report(tmp_path)
    metadata = "node_modules/.package-lock.json"
    (target / "node_modules").mkdir()
    (target / metadata).write_bytes((target / "package-lock.json").read_bytes())
    (target / ".gitignore").write_text("node_modules/\nignored.js\n")
    (target / "ignored.js").write_text("parser.parse(secret);\n")
    selected = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target, input_path=metadata)
    output["codeEvidence"][0].update(path="ignored.js", startLine=1)
    rejected = record(tmp_path, state, selected, [output], check=False)
    assert rejected["returncode"] != 0
    output = result(findings[0]["id"], target, input_path=metadata)
    second = start(state, report_id, [findings[1]["id"]])["assessment"]["id"]
    second_output = result(findings[1]["id"], target, input_path=metadata)
    record(tmp_path, state, selected, [output])
    (target / metadata).write_text(
        json.dumps({"packages": {"node_modules/parser": {"version": "2.0.0"}}})
    )
    rejected = record(tmp_path, state, second, [second_output], check=False)
    assert rejected["returncode"] != 0
    assert "native resolver input changed" in rejected["stderr"]
    stale_fix = run_workbench(
        state,
        "get-dependency-finding",
        "--report-id",
        report_id,
        "--finding-id",
        findings[0]["id"],
        "--require-current",
        check=False,
    )
    assert stale_fix["returncode"] != 0
    assert "native resolver input changed" in stale_fix["stderr"]


@pytest.mark.parametrize(
    "flaw",
    [
        "version",
        "ecosystem",
        "name",
        "issues",
        "exit",
        "output",
        "cwd",
        "input",
        "digest",
        "inputs",
    ],
)
def test_native_resolution_must_support_exact_package(tmp_path: Path, flaw: str) -> None:
    """Reject unsupported conclusions while retaining unresolved native evidence."""
    target, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target)
    resolution = output["resolution"]
    if flaw == "version":
        resolution["selectedVersions"] = ["2.0.0"]
    elif flaw in {"ecosystem", "name"}:
        resolution["package"][flaw] = "another-package"
    elif flaw == "issues":
        resolution["issues"] = ["The installed graph does not match this project."]
    elif flaw == "exit":
        resolution["exitCode"] = 1
    elif flaw == "output":
        resolution["stdout"] = ""
    elif flaw == "cwd":
        resolution["cwd"] = ".."
    elif flaw == "input":
        resolution["inputFiles"][0].update(
            path="../scanner.json",
            sha256=hashlib.sha256((tmp_path / "scanner.json").read_bytes()).hexdigest(),
        )
    elif flaw == "digest":
        resolution["inputFiles"][0]["sha256"] = "0" * 64
    elif flaw == "inputs":
        resolution["inputFiles"] = []
    assert record(tmp_path, state, assessment_id, [output], check=False)["returncode"] != 0
    if flaw not in {"cwd", "input", "digest"}:
        output.update(
            verdict="inconclusive",
            basis="unresolved",
            versionBasis=None,
            packageVersion=None,
            unknowns=["Native resolution is incomplete or conflicting."],
        )
        assert (
            record(tmp_path, state, assessment_id, [output])["results"][0]["resolution"]
            == resolution
        )


def test_native_resolution_supports_other_ecosystems(tmp_path: Path) -> None:
    """Accept native evidence independently of a custom lockfile parser."""
    target, state, report_id, findings = setup_report(tmp_path, ecosystem="maven")
    selection = start(state, report_id, [findings[0]["id"]])
    assert selection["findings"][0]["inputWarnings"] == []
    output = result(findings[0]["id"], target)
    output["resolution"].update(
        argv=["mvn", "--offline", "dependency:tree"],
        stdout="example:app:jar:1.0\n\\- parser:jar:1.0.0:compile\n",
        package={"ecosystem": "maven", "name": "parser"},
        explanation="The Maven graph selects parser 1.0.0 for the application.",
    )
    assert (
        record(tmp_path, state, selection["assessment"]["id"], [output])["results"][0]["resolution"]
        == output["resolution"]
    )


def test_current_assessment_preserves_scanner_revision_warning(tmp_path: Path) -> None:
    """Assess the recorded checkout without claiming it matches the old scan."""
    target, state, _, _ = setup_report(tmp_path)
    report_path = tmp_path / "endor.json"
    report_path.write_text(
        json.dumps(
            {
                "uuid": "synthetic-finding",
                "meta": {"name": "dependency_with_vulnerabilities"},
                "spec": {
                    "ecosystem": "ECOSYSTEM_NPM",
                    "target_dependency_name": "parser",
                    "target_dependency_version": "1.0.0",
                    "finding_categories": ["FINDING_CATEGORY_VULNERABILITY"],
                    "source_code_version": {"sha": "a" * 40},
                },
            }
        )
    )
    report_id = run_workbench(
        state,
        "import-dependency-findings",
        "--target-path",
        str(target),
        "--report-path",
        str(report_path),
        "--vendor",
        "endor",
    )["report"]["id"]
    finding = run_workbench(state, "get-dependency-report", "--report-id", report_id)["findings"][0]
    selected = start(state, report_id, [finding["id"]])
    assert selected["findings"][0]["inputWarnings"]
    output = result(finding["id"], target)
    assessment_id = selected["assessment"]["id"]
    output["limitations"] = [
        "The scanner analyzed a different revision; this conclusion covers the recorded checkout only."
    ]
    saved = record(tmp_path, state, assessment_id, [output])
    assert saved["results"][0]["verdict"] == "affects_application"
    assert saved["results"][0]["limitations"] == output["limitations"]
    detail = run_workbench(
        state, "get-dependency-finding", "--report-id", report_id, "--finding-id", finding["id"]
    )["finding"]
    assert detail["inputWarnings"] == finding["inputWarnings"]
    assert detail["sourceRevision"] == "a" * 40


@pytest.mark.parametrize(
    "case",
    [
        "advisory_mismatch",
        "package_absent",
        "version_not_affected",
        "declared",
        "multiple_versions",
    ],
)
def test_conclusion_uses_evidence_for_its_basis(tmp_path: Path, case: str) -> None:
    """Persist useful scoped conclusions without requiring unrelated runtime proof."""
    target, state, report_id, findings = setup_report(tmp_path)
    (target / "package.json").write_text('{"dependencies":{"parser":"1.0.0"}}\n')
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target)
    if case == "advisory_mismatch":
        output.update(
            basis=case,
            verdict="not_applicable",
            packageVersion=None,
            versionBasis=None,
            resolution=None,
            codeEvidence=[],
            summary="The advisory names a different package.",
            applicability="The cited advisory affects legacy-parser, not the reported parser package.",
        )
    elif case == "package_absent":
        output.update(
            basis=case,
            verdict="not_applicable",
            packageVersion=None,
            codeEvidence=[],
            summary="The package is absent from the complete application graph.",
            applicability="Native resolution covers the application and its development dependencies; parser has no occurrences.",
        )
        output["resolution"].update(
            selectedVersions=[],
            stdout='{"dependencies":{}}',
            explanation="The complete application graph contains no parser dependency.",
        )
    elif case == "version_not_affected":
        output.update(
            basis=case,
            verdict="not_applicable",
            packageVersion="2.0.0",
            codeEvidence=[],
            summary="All resolved occurrences are outside the affected range.",
            applicability="Both selected versions, 2.0.0 and 3.0.0, are outside the advisory's affected range below 2.0.0.",
        )
        output["resolution"].update(
            selectedVersions=["2.0.0", "3.0.0"],
            stdout='{"dependencies":{"parser":{"version":"2.0.0"},"helper":{"dependencies":{"parser":{"version":"3.0.0"}}}}}',
            explanation="The native graph selects parser 2.0.0 and 3.0.0; the scanner's 1.0.0 is stale.",
        )
    elif case == "declared":
        output.update(
            versionBasis="declared",
            resolution=None,
            limitations=[
                "This assessment covers the declared 1.0.0 pin; the deployed installation is not verified."
            ],
        )
        output["codeEvidence"].append(
            {
                "path": "package.json",
                "startLine": 1,
                "explanation": "The application declares an exact parser 1.0.0 pin.",
            }
        )
    else:
        output["resolution"].update(
            selectedVersions=["1.0.0", "2.0.0"],
            stdout='{"dependencies":{"parser":{"version":"1.0.0"},"helper":{"dependencies":{"parser":{"version":"2.0.0"}}}}}',
            explanation="The application imports parser 1.0.0; helper uses a separate 2.0.0 occurrence.",
        )
    if case in {"advisory_mismatch", "version_not_affected"}:
        output["advisoryEvidence"] = [
            {
                "url": "https://example.test/advisories/parser",
                "explanation": output["applicability"],
            }
        ]
    saved = record(tmp_path, state, assessment_id, [output])["results"][0]
    for key in (
        "verdict",
        "basis",
        "versionBasis",
        "packageVersion",
        "limitations",
        "advisoryEvidence",
    ):
        assert saved[key] == output[key]
    detail = run_workbench(
        state, "get-dependency-finding", "--report-id", report_id, "--finding-id", findings[0]["id"]
    )["finding"]
    assert detail["assessment"] == saved
    assert detail["package"]["version"] == "1.0.0"


@pytest.mark.parametrize(
    "case",
    [
        "mismatch_without_advisory",
        "mismatch_affects",
        "absent_with_versions",
        "unaffected_without_graph",
        "declared_without_source",
        "unknown_with_conclusion",
        "inconclusive_without_gap",
        "non_http_citation",
    ],
)
def test_conclusion_cannot_skip_its_required_evidence(tmp_path: Path, case: str) -> None:
    """Reject unsupported outcomes while leaving the assessment pending."""
    target, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target)
    if case == "mismatch_without_advisory":
        output.update(basis="advisory_mismatch", verdict="not_applicable")
    elif case == "mismatch_affects":
        output.update(
            basis="advisory_mismatch",
            advisoryEvidence=[
                {"url": "https://example.test/advisory", "explanation": "Different package."}
            ],
        )
    elif case == "absent_with_versions":
        output.update(basis="package_absent", verdict="not_applicable")
    elif case == "unaffected_without_graph":
        output.update(
            basis="version_not_affected",
            verdict="not_applicable",
            versionBasis="declared",
            resolution=None,
            advisoryEvidence=[
                {
                    "url": "https://example.test/advisory",
                    "explanation": "Only earlier versions affected.",
                }
            ],
        )
    elif case == "declared_without_source":
        output.update(versionBasis="declared", resolution=None, codeEvidence=[])
    elif case == "unknown_with_conclusion":
        output["unknowns"] = ["Attacker access to the parser remains unverified."]
    elif case == "inconclusive_without_gap":
        output.update(verdict="inconclusive", basis="unresolved")
    else:
        output["advisoryEvidence"] = [
            {"url": "javascript:alert(1)", "explanation": "Not a source URL."}
        ]
    assert record(tmp_path, state, assessment_id, [output], check=False)["returncode"] != 0
    assert (
        run_workbench(state, "get-dependency-assessment", "--assessment-id", assessment_id)[
            "assessment"
        ]["state"]
        == "pending"
    )


def test_execution_exclusion_does_not_require_nested_version(tmp_path: Path) -> None:
    """Record a mapped workflow exclusion with checked source but no package version."""
    target, state, report_id, findings = setup_report(tmp_path)
    workflow = target / "workflow.yml"
    workflow.write_text("jobs:\n  build:\n    if: false\n")
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target, verdict="not_applicable")
    output.update(
        basis="execution_excluded",
        packageVersion=None,
        versionBasis=None,
        resolution=None,
        summary="The selected action cannot execute in the checked workflow.",
        applicability="The reported parser belongs to the only job, whose condition is false.",
        codeEvidence=[
            {
                "path": "workflow.yml",
                "startLine": 1,
                "endLine": 3,
                "explanation": "The only job is disabled.",
            }
        ],
    )
    for invalid in (
        {**output, "codeEvidence": []},
        {
            **output,
            "verdict": "affects_application",
            "attackPath": result(findings[0]["id"], target)["attackPath"],
        },
    ):
        assert record(tmp_path, state, assessment_id, [invalid], check=False)["returncode"] != 0
    saved = record(tmp_path, state, assessment_id, [output])["results"][0]
    assert saved["basis"] == "execution_excluded"
    assert saved["packageVersion"] is None
    assert saved["versionBasis"] is None
    assert saved["codeEvidence"][0]["excerpt"] == workflow.read_text().rstrip("\n")


def test_external_artifact_version_preserves_inspected_evidence(tmp_path: Path) -> None:
    """Accept artifact provenance without a local pin, retaining source and shipped distinctions."""
    target, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    manifest = '{"dependencies":{"parser":"1.0.0"}}\n'
    output = result(findings[0]["id"], target)
    artifact = {
        "url": "https://example.test/action/0123456789/package.json",
        "revision": "0123456789",
        "sha256": hashlib.sha256(manifest.encode()).hexdigest(),
        "kind": "manifest",
        "package": {"ecosystem": "npm", "name": "parser", "version": "1.0.0"},
        "excerpt": manifest,
        "explanation": "The inspected action manifest declares the parser version; the inspected entrypoint and shipped code establish its execution.",
    }
    output.update(
        versionBasis="artifact",
        resolution=None,
        externalEvidence=[artifact],
        limitations=[
            "This covers the inspected artifact, not an earlier execution of the mutable action tag."
        ],
    )
    for invalid_artifact in (
        {**artifact, "package": {**artifact["package"], "name": "another-parser"}},
        {**artifact, "package": {**artifact["package"], "version": "2.0.0"}},
        {**artifact, "kind": "source"},
        {**artifact, "sha256": "not-a-file-digest"},
        {**artifact, "url": "file:///private/source"},
    ):
        assert (
            record(
                tmp_path,
                state,
                assessment_id,
                [{**output, "externalEvidence": [invalid_artifact]}],
                check=False,
            )["returncode"]
            != 0
        )
    saved = record(tmp_path, state, assessment_id, [output])["results"][0]
    assert saved["versionBasis"] == "artifact"
    assert saved["externalEvidence"] == [artifact]
    assert saved["attackPath"] == output["attackPath"]
    assert saved["resolution"] is None
    fetched = run_workbench(
        state,
        "get-dependency-finding",
        "--report-id",
        report_id,
        "--finding-id",
        findings[0]["id"],
        "--require-current",
    )
    assert fetched["finding"]["assessment"]["externalEvidence"] == [artifact]


def test_inconclusive_requires_attempted_investigation(tmp_path: Path) -> None:
    """Preserve observed access failures rather than accepting only deferred work."""
    target, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target, verdict="inconclusive")
    output.update(
        packageVersion=None,
        versionBasis=None,
        resolution=None,
        investigation=[],
        unknowns=["Obtain the private action bundle and trace parser input."],
    )
    assert record(tmp_path, state, assessment_id, [output], check=False)["returncode"] != 0
    output["investigation"] = [
        {
            "action": "Read the workflow action reference, then request its published bundle.",
            "result": "The referenced artifact returned HTTP 403; no bundle bytes were available.",
        }
    ]
    saved = record(tmp_path, state, assessment_id, [output])["results"][0]
    assert saved["investigation"] == output["investigation"]
    assert saved["attackPath"] is None
    assert saved["unknowns"] == output["unknowns"]


def test_positive_result_requires_attacker_path_and_prerequisites(tmp_path: Path) -> None:
    """Require each piece of the positive claim without manufacturing attacker control."""
    target, state, report_id, findings = setup_report(tmp_path)
    assessment_id = start(state, report_id, [findings[0]["id"]])["assessment"]["id"]
    output = result(findings[0]["id"], target)
    for attack_path in (
        None,
        {**output["attackPath"], "attackerControl": ""},
        {**output["attackPath"], "prerequisites": ""},
    ):
        assert (
            record(
                tmp_path, state, assessment_id, [{**output, "attackPath": attack_path}], check=False
            )["returncode"]
            != 0
        )
    saved = record(tmp_path, state, assessment_id, [output])["results"][0]
    assert saved["attackPath"] == output["attackPath"]


def _pagination_reports(connection: sqlite3.Connection, target: Path) -> None:
    """Create reports with large source bodies that summary pages must not load."""
    connection.executemany(
        "INSERT INTO dependency_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                report_id,
                str(target if report_id != "other" else target / "other"),
                "revision",
                "snapshot",
                "endor",
                report_id,
                "digest",
                "unneeded original report body" * 4096,
                "[]",
                0,
                created_at,
            )
            for report_id, created_at in [
                ("first", "2026-01-01T00:00:00Z"),
                ("second", "2026-01-02T00:00:00Z"),
                ("other", "2026-01-03T00:00:00Z"),
            ]
        ],
    )
    connection.commit()


def _capture_loaded_rows(connection: sqlite3.Connection) -> list[sqlite3.Row]:
    """Observe real SQLite result materialization without replacing its queries."""
    loaded: list[sqlite3.Row] = []

    def capture(cursor: sqlite3.Cursor, values: tuple[object, ...]) -> sqlite3.Row:
        row = sqlite3.Row(cursor, values)
        loaded.append(row)
        return row

    connection.row_factory = capture
    return loaded


def test_report_pagination_loads_only_summary_columns(
    tmp_path: Path, workbench_api: dict[str, Any], workbench_db: sqlite3.Connection
) -> None:
    """Preserve report order, filtering, and cursors without loading source bodies."""
    _pagination_reports(workbench_db, tmp_path)
    loaded = _capture_loaded_rows(workbench_db)
    api = workbench_api["dependency_imports"]
    first = api.list_reports(
        workbench_db, argparse.Namespace(target_path=str(tmp_path), offset=0, limit=1)
    )
    assert [report["id"] for report in first["reports"]] == ["second"]
    assert first["nextOffset"] == 1
    second = api.list_reports(
        workbench_db, argparse.Namespace(target_path=str(tmp_path), offset=1, limit=1)
    )
    assert [report["id"] for report in second["reports"]] == ["first"]
    assert second["nextOffset"] is None
    all_reports = api.list_reports(
        workbench_db, argparse.Namespace(target_path=None, offset=0, limit=100)
    )
    assert [report["id"] for report in all_reports["reports"]] == ["other", "second", "first"]
    assert all_reports["nextOffset"] is None
    assert all("original_report" not in row.keys() for row in loaded)


def test_finding_pagination_filters_before_loading_page(
    tmp_path: Path, workbench_api: dict[str, Any], workbench_db: sqlite3.Connection
) -> None:
    """Load only each requested page while preserving filtered counts and empty pages."""
    _pagination_reports(workbench_db, tmp_path)
    verdicts = [
        None,
        "affects_application",
        "inconclusive",
        "affects_application",
        "not_applicable",
        None,
        "affects_application",
    ]
    workbench_db.executemany(
        "INSERT INTO dependency_imported_findings VALUES (?, ?, ?, ?, ?)",
        [
            (
                f"finding-{index}",
                "first",
                index,
                json.dumps(
                    {"title": f"Finding {index}", "original": "unneeded vendor detail" * 1024}
                ),
                json.dumps({"verdict": verdict, "resolution": {"stdout": "native output" * 4096}})
                if verdict
                else None,
            )
            for index, verdict in enumerate(verdicts)
        ],
    )
    workbench_db.execute(
        "UPDATE dependency_reports SET finding_count = ? WHERE id = 'first'", (len(verdicts),)
    )
    workbench_db.commit()
    loaded = _capture_loaded_rows(workbench_db)
    api = workbench_api["dependency_imports"]
    for verdict, offset, limit, expected_ids, total, next_offset in [
        (None, 2, 2, ["finding-2", "finding-3"], 7, 4),
        ("affects_application", 1, 1, ["finding-3"], 3, 2),
        ("pending", 1, 1, ["finding-5"], 2, None),
        ("inconclusive", 2, 1, [], 1, None),
    ]:
        loaded.clear()
        page = api.get_report(
            workbench_db,
            argparse.Namespace(report_id="first", verdict=verdict, offset=offset, limit=limit),
        )
        assert [finding["id"] for finding in page["findings"]] == expected_ids
        assert page["total"] == total
        assert page["nextOffset"] == next_offset
        materialized = [row for row in loaded if "claim_json" in row.keys()]
        assert [row["id"] for row in materialized] == expected_ids
        assert all("original" not in json.loads(row["claim_json"]) for row in materialized)
        assert all("original_report" not in row.keys() for row in loaded)
