from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
REPORTING_SCRIPT = PLUGIN_ROOT / "scripts" / "dependency_scan_reporting.py"
FINALIZER_SCRIPT = PLUGIN_ROOT / "scripts" / "finalize_scan_contract.py"
REPORT_PROJECTION_SCRIPT = PLUGIN_ROOT / "scripts" / "report_projection.py"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def cloud_result() -> dict[str, Any]:
    return {
        "jobId": "dps_example",
        "status": "completed",
        "packages": [
            {
                "ecosystem": "npm",
                "registry": "https://registry.npmjs.org",
                "package": "@scope/example",
                "oldVersion": "1.0.0",
                "newVersion": "1.1.0",
                "status": "completed",
                "findings": [
                    {
                        "upstreamFindingId": "dep_1234567890abcdef",
                        "lifecycle": "new",
                        "ruleId": "supply-chain.malicious-install-hook",
                        "title": "Malicious installation hook",
                        "summary": "The published dependency executes an unsafe install hook.",
                        "severity": {"level": "high"},
                        "confidence": {
                            "level": "high",
                            "rationale": "Published package metadata invokes the payload.",
                        },
                        "taxonomy": {"category": "malware", "cwe": []},
                        "remediation": "Upgrade to a verified unaffected release.",
                        "artifactDigests": ["sha256:0123456789abcdef"],
                        "codeEvidence": [
                            {
                                "id": "install-hook",
                                "label": "Published installation hook",
                                "path": "package.json",
                                "startLine": 8,
                                "code": '"postinstall": "node install.js"',
                                "explanation": "The published package executes the payload.",
                            }
                        ],
                    }
                ],
            }
        ],
    }


def local_impacts(*, anchor_path: str = "pnpm-lock.yaml") -> dict[str, Any]:
    return {
        "dependencies": [
            {
                "ecosystem": "npm",
                "registry": "https://registry.npmjs.org",
                "package": "@scope/example",
                "oldVersion": "1.0.0",
                "newVersion": "1.1.0",
                "anchorPath": anchor_path,
                "anchorStartLine": 17,
                "affectedProjects": ["services/payments"],
                "dependencyChains": [["payments", "@scope/example"]],
                "usageContext": "Installation runs in CI with credential access.",
            }
        ]
    }


def run_reporting(
    tmp_path: Path,
    *,
    result: dict[str, Any] | None = None,
    impacts: dict[str, Any] | None = None,
    existing_findings: list[dict[str, Any]] | None = None,
    check: bool = True,
) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
    findings_path = tmp_path / "findings.json"
    results_path = tmp_path / "dependency-results.json"
    impacts_path = tmp_path / "dependency-impacts.json"
    write_json(
        findings_path,
        {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": "scan_dependency_test",
            "findings": existing_findings or [],
        },
    )
    write_json(results_path, result or cloud_result())
    write_json(impacts_path, impacts or local_impacts())

    completed = subprocess.run(
        [
            sys.executable,
            str(REPORTING_SCRIPT),
            "--findings",
            str(findings_path),
            "--results",
            str(results_path),
            "--impacts",
            str(impacts_path),
        ],
        check=check,
        capture_output=True,
        text=True,
    )
    return json.loads(findings_path.read_text(encoding="utf-8")), completed


def test_upstream_finding_merges_into_existing_canonical_contract(tmp_path: Path) -> None:
    findings, completed = run_reporting(tmp_path)

    assert json.loads(completed.stdout) == {"merged": 1, "unmapped": 0}
    assert len(findings["findings"]) == 1
    finding = findings["findings"][0]
    assert finding["locations"] == [
        {"path": "pnpm-lock.yaml", "startLine": 17, "role": "root_control"}
    ]
    assert "@scope/example" in finding["title"]
    assert "1.1.0" in finding["title"]
    assert finding["codeEvidence"][0]["path"] == "package.json"
    assert finding["extensions"]["dependency"] == {
        "ecosystem": "npm",
        "registry": "https://registry.npmjs.org",
        "package": "@scope/example",
        "oldVersion": "1.0.0",
        "newVersion": "1.1.0",
        "upstreamFindingId": "dep_1234567890abcdef",
        "lifecycle": "new",
        "artifactDigests": ["sha256:0123456789abcdef"],
        "affectedProjects": ["services/payments"],
        "dependencyChains": [["payments", "@scope/example"]],
        "usageContext": "Installation runs in CI with credential access.",
    }

    spec = importlib.util.spec_from_file_location("dependency_test_finalizer", FINALIZER_SCRIPT)
    assert spec is not None and spec.loader is not None
    finalizer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(finalizer)
    manifest = {
        "scan": {
            "id": "scan_dependency_test",
            "target": {"targetId": "dependency-test-target"},
        }
    }
    finalizer._populate_unsealed_finding_identities(manifest, findings)
    finalizer._validate_finding(finding, "findings.findings[0]")
    assert finding["findingId"].startswith("csf_")
    assert finding["occurrenceId"].startswith("occ_")


def test_existing_findings_and_partial_upstream_results_are_preserved(tmp_path: Path) -> None:
    result = cloud_result()
    result["packages"][0]["status"] = "partial"
    result["packages"].append(
        {
            "ecosystem": "pypi",
            "registry": "https://pypi.org",
            "package": "failed-package",
            "oldVersion": "1.0",
            "newVersion": "2.0",
            "status": "failed",
            "error": "artifact unavailable",
            "findings": [],
        }
    )

    findings, completed = run_reporting(
        tmp_path,
        result=result,
        existing_findings=[{"ruleId": "existing.first-party-finding"}],
    )

    assert [finding["ruleId"] for finding in findings["findings"]] == [
        "existing.first-party-finding",
        "supply-chain.malicious-install-hook",
    ]
    assert json.loads(completed.stdout)["merged"] == 1


def test_validated_known_advisory_survives_later_upstream_finding_merge(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("known_advisory_finalizer", FINALIZER_SCRIPT)
    assert spec is not None and spec.loader is not None
    finalizer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(finalizer)

    known_finding = {
        "ruleId": "dependency.known-prototype-pollution",
        "identity": {
            "anchor": "lodash-zip-object-deep-prototype-pollution",
            "instance": "services-payments-src-normalize-ts-42",
        },
        "title": "Reachable lodash prototype pollution: CVE-2020-8203",
        "summary": (
            "The first-party request handler passes attacker-controlled paths to lodash "
            "4.17.15 zipObjectDeep, matching CVE-2020-8203 / GHSA-p6mc-m468-83gw."
        ),
        "severity": {"level": "high"},
        "confidence": {
            "level": "high",
            "rationale": "The in-scope handler invokes the exact advisory-affected function.",
        },
        "taxonomy": {"category": "prototype-pollution", "cwe": ["CWE-1321"]},
        "locations": [
            {
                "path": "services/payments/src/normalize.ts",
                "startLine": 42,
                "role": "sink",
            },
            {
                "path": "services/payments/package-lock.json",
                "startLine": 17,
                "role": "root_control",
            },
        ],
        "codeEvidence": [
            {
                "id": "first-party-lodash-call",
                "label": "First-party call to the affected lodash function",
                "path": "services/payments/src/normalize.ts",
                "startLine": 42,
                "code": "lodash.zipObjectDeep(request.body.paths, request.body.values)",
                "explanation": "Attacker-controlled paths reach the vulnerable implementation.",
            }
        ],
        "rootCause": {
            "summary": "Untrusted object paths reach the known vulnerable dependency function.",
            "evidenceRefs": ["first-party-lodash-call"],
        },
        "validation": {
            "disposition": "reportable",
            "method": "Static first-party source-to-sink trace.",
            "evidenceRefs": ["first-party-lodash-call"],
            "evidence": ["The request handler calls the advisory-affected zipObjectDeep API."],
        },
        "attackPath": {
            "decision": "reportable",
            "reachability": "The production payments handler accepts attacker-controlled paths.",
            "evidenceRefs": ["first-party-lodash-call"],
        },
        "remediation": "Upgrade lodash to a version patched for CVE-2020-8203.",
        "provenance": {"source": "local_plugin"},
        "extensions": {"candidateId": "candidate-known-lodash-prototype-pollution"},
    }
    manifest = {
        "scan": {
            "id": "scan_dependency_test",
            "target": {"targetId": "dependency-test-target"},
        }
    }
    preexisting_document = {
        "documentType": "codex-security.findings",
        "schemaVersion": "1.0",
        "scanId": "scan_dependency_test",
        "findings": [known_finding],
    }
    finalizer._populate_unsealed_finding_identities(manifest, preexisting_document)
    finalizer._validate_findings(manifest, preexisting_document)
    schema = json.loads((PLUGIN_ROOT / "schemas" / "findings.schema.json").read_text())
    Draft202012Validator(schema).validate(preexisting_document)
    original_bytes = json.dumps(known_finding, sort_keys=True, separators=(",", ":")).encode()

    findings, completed = run_reporting(tmp_path, existing_findings=[deepcopy(known_finding)])

    assert json.loads(completed.stdout) == {"merged": 1, "unmapped": 0}
    assert [finding["ruleId"] for finding in findings["findings"]] == [
        "dependency.known-prototype-pollution",
        "supply-chain.malicious-install-hook",
    ]
    assert (
        json.dumps(findings["findings"][0], sort_keys=True, separators=(",", ":")).encode()
        == original_bytes
    )
    finalizer._populate_unsealed_finding_identities(manifest, findings)
    finalizer._validate_findings(manifest, findings)
    Draft202012Validator(schema).validate(findings)
    assert (
        json.dumps(findings["findings"][0], sort_keys=True, separators=(",", ":")).encode()
        == original_bytes
    )
    assert findings["findings"][0]["findingId"] != findings["findings"][1]["findingId"]
    assert findings["findings"][0]["occurrenceId"] != findings["findings"][1]["occurrenceId"]


def test_unmapped_package_is_not_given_an_invented_first_party_location(tmp_path: Path) -> None:
    findings, completed = run_reporting(tmp_path, impacts={"dependencies": []}, check=False)
    assert findings["findings"] == []
    assert completed.returncode != 0
    assert "require discovery and coverage" in completed.stderr


def test_unmapped_findings_remain_deferred_with_partial_coverage(tmp_path: Path) -> None:
    discovery, impacts, results, coverage = graph_documents()
    impacts["dependencies"] = []
    coverage.update(completeness="complete", deferred=[])
    findings, updated, completed = run_inventory_reporting(
        tmp_path, documents=(discovery, impacts, results, coverage)
    )
    assert findings["findings"] == []
    assert json.loads(completed.stdout)["unmapped"] == 1
    assert updated["completeness"] == "partial"
    assert len(updated["deferred"]) == 1
    assert "dep_1234567890abcdef" in updated["deferred"][0]["reason"]
    assert "no verified local dependency location" in updated["deferred"][0]["reason"]


def test_dependency_results_must_match_discovered_package_versions() -> None:
    spec = importlib.util.spec_from_file_location("dependency_reporting", REPORTING_SCRIPT)
    assert spec is not None and spec.loader is not None
    reporting = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reporting)
    discovery, impacts, results, _ = graph_documents()
    results["packages"][0]["newVersion"] = "999.0.0"
    import pytest

    with pytest.raises(ValueError, match="outside local discovery"):
        reporting.dependency_inventory(discovery, impacts, results)


def test_reporting_rejects_unsafe_first_party_anchor(tmp_path: Path) -> None:
    findings, completed = run_reporting(
        tmp_path,
        impacts=local_impacts(anchor_path="../../outside/package.json"),
        check=False,
    )

    assert completed.returncode != 0
    assert "safe repository-relative" in completed.stderr
    assert findings["findings"] == []


def test_repeated_upstream_finding_is_not_duplicated(tmp_path: Path) -> None:
    first, _ = run_reporting(tmp_path)
    second, completed = run_reporting(tmp_path, existing_findings=first["findings"])

    assert len(second["findings"]) == 1
    assert json.loads(completed.stdout) == {"merged": 0, "unmapped": 0}


def test_independent_first_party_controls_remain_separate(tmp_path: Path) -> None:
    impacts = local_impacts()
    second = dict(impacts["dependencies"][0])
    second["anchorPath"] = "services/admin/package-lock.json"
    second["anchorStartLine"] = 33
    second["affectedProjects"] = ["services/admin"]
    impacts["dependencies"].append(second)

    findings, _ = run_reporting(tmp_path, impacts=impacts)

    assert len(findings["findings"]) == 2
    assert {finding["locations"][0]["path"] for finding in findings["findings"]} == {
        "pnpm-lock.yaml",
        "services/admin/package-lock.json",
    }
    assert len({finding["identity"]["instance"] for finding in findings["findings"]}) == 2


def test_independent_upgrades_preserve_shared_upstream_finding_instances(tmp_path: Path) -> None:
    result = cloud_result()
    second_package = deepcopy(result["packages"][0])
    second_package["oldVersion"] = "0.9.0"
    result["packages"].append(second_package)

    impacts = local_impacts()
    second_impact = deepcopy(impacts["dependencies"][0])
    second_impact["oldVersion"] = "0.9.0"
    impacts["dependencies"].append(second_impact)

    findings, completed = run_reporting(tmp_path, result=result, impacts=impacts)

    assert json.loads(completed.stdout) == {"merged": 2, "unmapped": 0}
    assert len(findings["findings"]) == 2
    assert len({finding["identity"]["anchor"] for finding in findings["findings"]}) == 1
    assert len({finding["identity"]["instance"] for finding in findings["findings"]}) == 2
    assert {
        finding["extensions"]["dependency"]["oldVersion"] for finding in findings["findings"]
    } == {"0.9.0", "1.0.0"}

    repeated, completed = run_reporting(
        tmp_path,
        result=result,
        impacts=impacts,
        existing_findings=findings["findings"],
    )

    assert len(repeated["findings"]) == 2
    assert json.loads(completed.stdout) == {"merged": 0, "unmapped": 0}


def test_verified_finding_introduction_is_preserved_in_local_extension(tmp_path: Path) -> None:
    result = cloud_result()
    result["packages"][0]["findings"][0]["introducedIn"] = {
        "version": "1.0.4",
        "artifactDigest": "sha256:" + "a" * 64,
        "confidence": "high",
        "evidence": [{"path": "package.json", "startLine": 8}],
    }

    findings, _ = run_reporting(tmp_path, result=result)

    assert findings["findings"][0]["extensions"]["dependency"]["introducedIn"] == {
        "version": "1.0.4",
        "artifactDigest": "sha256:" + "a" * 64,
        "confidence": "high",
        "evidence": [{"path": "package.json", "startLine": 8}],
    }


def test_unverified_finding_introduction_is_not_invented(tmp_path: Path) -> None:
    findings, _ = run_reporting(tmp_path)

    assert "introducedIn" not in findings["findings"][0]["extensions"]["dependency"]


def graph_documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    primary = cloud_result()["packages"][0]
    primary["artifacts"] = [{"status": "completed", "cacheHit": True}]
    definitions: list[tuple[str, str | None, str, list[str], str]] = [
        ("@scope/example", "1.0.0", "1.1.0", ["direct"], "completed"),
        ("clean-direct", "2.0.0", "2.1.0", ["direct", "development"], "completed"),
        ("shared-transitive", "3.0.0", "3.1.0", ["transitive", "optional"], "completed"),
        ("failed-transitive", None, "4.0.0", ["transitive"], "failed"),
        ("unscanned-transitive", "5.0.0", "5.1.0", ["transitive"], "not_scanned"),
    ]
    discovered = []
    impact_entries = []
    results = [primary]
    for package, old_version, new_version, dependency_types, status in definitions:
        identity = {
            "ecosystem": "npm",
            "registry": "https://registry.npmjs.org",
            "package": package,
            "oldVersion": old_version,
            "newVersion": new_version,
        }
        discovered.append({**identity, "dependencyTypes": dependency_types})
        if package == "shared-transitive":
            chains = [
                ["services/payments", "@scope/example", "unchanged-bridge", package],
                ["services/payments", "clean-direct", "unchanged-bridge", package],
            ]
        elif package.endswith("transitive"):
            chains = [["services/payments", "@scope/example", "unchanged-bridge", package]]
        else:
            chains = [["services/payments", package]]
        impact_entries.append(
            {
                **identity,
                "anchorPath": "services/payments/package-lock.json",
                "anchorStartLine": 10,
                "affectedProjects": ["services/payments"],
                "dependencyChains": chains,
            }
        )
        if package in {"@scope/example", "unscanned-transitive"}:
            continue
        results.append(
            {
                **identity,
                "status": status,
                "findings": [],
                "artifacts": (
                    [{"status": "completed", "cacheHit": False}]
                    if status == "completed"
                    else [{"status": "failed", "error": "Artifact unavailable"}]
                ),
            }
        )
    coverage = {
        "documentType": "codex-security.coverage",
        "schemaVersion": "1.0",
        "scanId": "scan_dependency_test",
        "mode": "branch_diff",
        "completeness": "partial",
        "inventoryStrategy": "diff",
        "includePaths": ["."],
        "excludePaths": [],
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [{"id": "failed-transitive", "reason": "Artifact unavailable"}],
    }
    return (
        {"dependencies": discovered},
        {"dependencies": impact_entries},
        {"jobId": "dps_graph", "status": "completed", "packages": results},
        coverage,
    )


def run_inventory_reporting(
    tmp_path: Path,
    *,
    reverse_inputs: bool = False,
    documents: tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], subprocess.CompletedProcess[str]]:
    discovery, impacts, results, coverage = graph_documents() if documents is None else documents
    if reverse_inputs:
        for document in (discovery, impacts):
            document["dependencies"].reverse()
        results["packages"].reverse()
        for package in results["packages"]:
            if isinstance(package.get("priorFindingAssessments"), list):
                package["priorFindingAssessments"].reverse()
        for impact in impacts["dependencies"]:
            impact["dependencyChains"].reverse()
    paths = {
        "findings": tmp_path / "findings.json",
        "discovery": tmp_path / "dependency-discovery.json",
        "impacts": tmp_path / "dependency-impacts.json",
        "results": tmp_path / "dependency-results.json",
        "coverage": tmp_path / "coverage.json",
    }
    write_json(
        paths["findings"],
        {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": "scan_dependency_test",
            "findings": [],
        },
    )
    for name, document in (
        ("discovery", discovery),
        ("impacts", impacts),
        ("results", results),
        ("coverage", coverage),
    ):
        write_json(paths[name], document)

    completed = subprocess.run(
        [
            sys.executable,
            str(REPORTING_SCRIPT),
            *(
                argument
                for name in ("findings", "results", "impacts", "discovery", "coverage")
                for argument in (f"--{name}", str(paths[name]))
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return (
        json.loads(paths["findings"].read_text(encoding="utf-8")),
        json.loads(paths["coverage"].read_text(encoding="utf-8")),
        completed,
    )


def test_dependency_inventory_preserves_clean_packages_shared_bridges_and_failures(
    tmp_path: Path,
) -> None:
    findings, coverage, completed = run_inventory_reporting(tmp_path)

    assert json.loads(completed.stdout) == {"merged": 1, "unmapped": 0}
    assert len(findings["findings"]) == 1
    inventory = coverage["dependencies"]
    nodes = {node["name"]: node for node in inventory["nodes"]}
    assert set(nodes) == {
        "services/payments",
        "@scope/example",
        "clean-direct",
        "shared-transitive",
        "failed-transitive",
        "unscanned-transitive",
        "unchanged-bridge",
    }
    assert nodes["services/payments"]["kind"] == "project"
    assert nodes["@scope/example"]["cacheHit"] is True
    assert nodes["@scope/example"]["findingCount"] == 1
    assert nodes["@scope/example"]["oldVersion"] == "1.0.0"
    assert nodes["@scope/example"]["newVersion"] == "1.1.0"
    assert nodes["clean-direct"]["findingCount"] == 0
    assert nodes["clean-direct"]["dependencyTypes"] == ["direct", "development"]
    assert nodes["shared-transitive"]["dependencyTypes"] == ["transitive", "optional"]
    assert nodes["failed-transitive"]["status"] == "failed"
    assert nodes["failed-transitive"]["oldVersion"] is None
    assert nodes["unscanned-transitive"]["status"] == "not_scanned"
    assert nodes["unchanged-bridge"]["status"] == "unchanged"
    assert nodes["unchanged-bridge"]["changed"] is False
    assert nodes["shared-transitive"]["affectedProjects"] == ["services/payments"]

    edges = {(edge["from"], edge["to"]) for edge in inventory["edges"]}
    assert (nodes["@scope/example"]["id"], nodes["unchanged-bridge"]["id"]) in edges
    assert (nodes["clean-direct"]["id"], nodes["unchanged-bridge"]["id"]) in edges
    assert (nodes["unchanged-bridge"]["id"], nodes["shared-transitive"]["id"]) in edges

    schema = json.loads((PLUGIN_ROOT / "schemas" / "coverage.schema.json").read_text())
    Draft202012Validator(schema).validate(coverage)


def test_full_dependency_inventory_does_not_claim_current_packages_changed(tmp_path: Path) -> None:
    discovery, impacts, results, coverage = graph_documents()
    discovery.update(
        {
            "baseRevision": None,
            "headRevision": "current-revision",
            "mode": "repository",
            "changedFiles": [],
        }
    )
    coverage["mode"] = "repository"
    coverage["inventoryStrategy"] = "repository"
    for document, entries in (
        (discovery, "dependencies"),
        (impacts, "dependencies"),
        (results, "packages"),
    ):
        for package in document[entries]:
            package["oldVersion"] = None

    _, updated_coverage, _ = run_inventory_reporting(
        tmp_path,
        documents=(discovery, impacts, results, coverage),
    )

    packages = [
        node
        for node in updated_coverage["dependencies"]["nodes"]
        if node["kind"] == "dependency" and node["status"] != "unchanged"
    ]
    assert len(packages) == 5
    assert all(package["oldVersion"] is None for package in packages)
    assert all(package["changed"] is False for package in packages)
    assert {package["status"] for package in packages} == {
        "completed",
        "failed",
        "not_scanned",
    }
    schema = json.loads((PLUGIN_ROOT / "schemas" / "coverage.schema.json").read_text())
    Draft202012Validator(schema).validate(updated_coverage)


def test_dependency_inventory_is_deterministic_when_inputs_are_reordered(tmp_path: Path) -> None:
    forward = tmp_path / "forward"
    backward = tmp_path / "backward"
    forward.mkdir()
    backward.mkdir()

    _, forward_coverage, _ = run_inventory_reporting(forward)
    _, backward_coverage, _ = run_inventory_reporting(backward, reverse_inputs=True)

    assert forward_coverage["dependencies"] == backward_coverage["dependencies"]


def test_dependency_inventory_preserves_independent_same_target_upgrades(tmp_path: Path) -> None:
    discovery, impacts, results, coverage = graph_documents()
    first_result = results["packages"][0]
    first_result["status"] = "failed"
    first_result["findings"] = []
    first_result["artifacts"] = [{"status": "failed", "error": "Artifact unavailable"}]

    second_discovery = deepcopy(discovery["dependencies"][0])
    second_discovery["oldVersion"] = "2.0.0"
    discovery["dependencies"].append(second_discovery)

    second_impact = deepcopy(impacts["dependencies"][0])
    second_impact["oldVersion"] = "2.0.0"
    second_impact["anchorPath"] = "services/admin/package-lock.json"
    second_impact["affectedProjects"] = ["services/admin"]
    second_impact["dependencyChains"] = [["services/admin", "unchanged-bridge", "@scope/example"]]
    impacts["dependencies"].append(second_impact)

    second_result = cloud_result()["packages"][0]
    second_result["oldVersion"] = "2.0.0"
    second_result["artifacts"] = [{"status": "completed", "cacheHit": False}]
    results["packages"].append(second_result)

    documents = (discovery, impacts, results, coverage)
    forward = tmp_path / "forward"
    backward = tmp_path / "backward"
    forward.mkdir()
    backward.mkdir()

    findings, forward_coverage, completed = run_inventory_reporting(
        forward,
        documents=deepcopy(documents),
    )
    _, backward_coverage, _ = run_inventory_reporting(
        backward,
        documents=deepcopy(documents),
        reverse_inputs=True,
    )

    assert json.loads(completed.stdout) == {"merged": 1, "unmapped": 0}
    assert len(findings["findings"]) == 1
    assert forward_coverage["dependencies"] == backward_coverage["dependencies"]

    inventory = forward_coverage["dependencies"]
    upgrades = {
        node["oldVersion"]: node
        for node in inventory["nodes"]
        if node.get("package") == "@scope/example" and node.get("changed") is True
    }
    assert set(upgrades) == {"1.0.0", "2.0.0"}
    assert upgrades["1.0.0"]["status"] == "failed"
    assert upgrades["1.0.0"]["affectedProjects"] == ["services/payments"]
    assert upgrades["2.0.0"]["status"] == "completed"
    assert upgrades["2.0.0"]["affectedProjects"] == ["services/admin"]
    assert upgrades["2.0.0"]["findingCount"] == 1
    assert upgrades["1.0.0"]["id"] != upgrades["2.0.0"]["id"]

    bridge_id = "npm:https://registry.npmjs.org:unchanged-bridge"
    edges = {(edge["from"], edge["to"]) for edge in inventory["edges"]}
    assert ("project:services/payments", upgrades["1.0.0"]["id"]) in edges
    assert ("project:services/admin", bridge_id) in edges
    assert (bridge_id, upgrades["2.0.0"]["id"]) in edges

    schema = json.loads((PLUGIN_ROOT / "schemas" / "coverage.schema.json").read_text())
    Draft202012Validator(schema).validate(forward_coverage)


def test_unknown_prior_vulnerability_is_visible_as_incomplete_follow_up(tmp_path: Path) -> None:
    discovery, impacts, results, coverage = graph_documents()
    discovery["dependencies"] = discovery["dependencies"][:1]
    impacts["dependencies"] = impacts["dependencies"][:1]
    results["packages"] = results["packages"][:1]
    package = results["packages"][0]
    package["findings"] = []
    package["priorFindingAssessments"] = [
        {
            "upstreamFindingId": "dep_existing_vulnerability",
            "status": "unknown",
            "reason": "The historical implementation moved and could not be inspected.",
            "evidence": [],
        }
    ]
    coverage["completeness"] = "complete"
    coverage["deferred"] = []

    findings, observed_coverage, completed = run_inventory_reporting(
        tmp_path,
        documents=(discovery, impacts, results, coverage),
    )

    assert json.loads(completed.stdout) == {"merged": 0, "unmapped": 0}
    assert findings["findings"] == []
    assert observed_coverage["completeness"] == "partial"
    assert len(observed_coverage["deferred"]) == 1
    deferred = observed_coverage["deferred"][0]
    assert deferred["id"].startswith("dependency-prior-")
    assert "dep_existing_vulnerability" in deferred["reason"]
    assert "@scope/example 1.0.0 → 1.1.0" in deferred["reason"]
    assert "status is unknown" in deferred["reason"]
    assert "could not determine" in deferred["reason"]
    assert "historical implementation moved" in deferred["reason"]
    assert deferred["paths"] == ["services/payments/package-lock.json"]

    schema = json.loads((PLUGIN_ROOT / "schemas" / "coverage.schema.json").read_text())
    Draft202012Validator(schema).validate(observed_coverage)

    spec = importlib.util.spec_from_file_location(
        "dependency_test_projection", REPORT_PROJECTION_SCRIPT
    )
    assert spec is not None and spec.loader is not None
    projection = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(projection)
    manifest = {
        "scan": {
            "target": {"displayName": "example/repository"},
            "scope": {"includePaths": ["."], "excludePaths": []},
        }
    }
    markdown = projection.build_report_markdown(manifest, findings, observed_coverage)

    assert "| Coverage | partial |" in markdown
    assert "## Open Questions And Follow Up" in markdown
    assert "status is unknown" in markdown
    assert "could not determine" in markdown


def test_unknown_prior_assessments_preserve_existing_work_and_deduplicate_deterministically(
    tmp_path: Path,
) -> None:
    discovery, impacts, results, coverage = graph_documents()
    primary = results["packages"][0]
    primary["priorFindingAssessments"] = [
        {
            "upstreamFindingId": "dep_shared",
            "status": "unknown",
            "reason": "The macOS artifact was inconclusive.",
            "artifactDigest": "sha256:macos",
        },
        {
            "upstreamFindingId": "dep_shared",
            "status": "unknown",
            "reason": "The Linux artifact was inconclusive.",
            "artifactDigest": "sha256:linux",
        },
        {
            "upstreamFindingId": "dep_verified",
            "status": "fixed",
            "reason": "The previous vulnerability was removed.",
        },
    ]
    clean = next(package for package in results["packages"] if package["package"] == "clean-direct")
    clean["priorFindingAssessments"] = [
        {
            "upstreamFindingId": "dep_other",
            "status": "unknown",
            "reason": "The prior control could not be determined.",
        }
    ]

    documents = (discovery, impacts, results, coverage)
    forward = tmp_path / "forward"
    backward = tmp_path / "backward"
    forward.mkdir()
    backward.mkdir()

    forward_findings, forward_coverage, _ = run_inventory_reporting(
        forward,
        documents=deepcopy(documents),
    )
    backward_findings, backward_coverage, _ = run_inventory_reporting(
        backward,
        documents=deepcopy(documents),
        reverse_inputs=True,
    )

    assert forward_findings == backward_findings
    assert forward_coverage == backward_coverage
    assert forward_coverage["completeness"] == "partial"
    assert len(forward_findings["findings"]) == 1
    assert forward_coverage["deferred"][0] == {
        "id": "failed-transitive",
        "reason": "Artifact unavailable",
    }
    unknown = forward_coverage["deferred"][1:]
    assert len(unknown) == 2
    assert len({item["id"] for item in unknown}) == 2
    shared = next(item for item in unknown if "dep_shared" in item["reason"])
    assert "Linux artifact was inconclusive" in shared["reason"]
    assert "macOS artifact was inconclusive" in shared["reason"]
    assert all("dep_verified" not in item["reason"] for item in unknown)


def test_reporting_requires_discovery_and_coverage_together(tmp_path: Path) -> None:
    run_reporting(tmp_path)
    completed = subprocess.run(
        [
            sys.executable,
            str(REPORTING_SCRIPT),
            "--findings",
            str(tmp_path / "findings.json"),
            "--results",
            str(tmp_path / "dependency-results.json"),
            "--impacts",
            str(tmp_path / "dependency-impacts.json"),
            "--discovery",
            str(tmp_path / "dependency-discovery.json"),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "--discovery and --coverage must be supplied together" in completed.stderr
