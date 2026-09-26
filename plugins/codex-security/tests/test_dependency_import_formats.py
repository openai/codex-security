"""Check vendor format mapping and reject unsupported import shapes."""

from __future__ import annotations

import importlib
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "scripts"))

parse_report = importlib.import_module("dependency_imports.formats").parse_report

FIXTURES = Path(__file__).parent / "fixtures" / "dependency-imports"


def _fixture(vendor: str) -> dict[str, object]:
    """Read a small, documented vendor fixture."""
    return json.loads((FIXTURES / f"{vendor}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("vendor", "package", "severity", "advisory", "excluded"),
    [
        ("endor", "example-package", "FINDING_LEVEL_HIGH", "CVE-2099-0001", 1),
        ("snyk", "org.example:parser", "medium", "CVE-2099-0001", 0),
        ("socket", "example-package", "critical", None, 3),
    ],
)
def test_vendor_mapping_preserves_source_evidence(
    vendor: str, package: str, severity: str, advisory: str | None, excluded: int
) -> None:
    """Retain vendor identity, package, evidence and fixes without a verdict."""
    payload = _fixture(vendor)
    before = deepcopy(payload)
    result = parse_report(payload, vendor)
    assert payload == before
    assert result["excludedCount"] == excluded
    findings = result["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["package"]["name"] == package
    assert finding["originalSeverity"] == severity
    assert finding["sourceId"]
    assert finding["locations"]
    assert finding["fix"]
    assert finding["original"]
    assert "verdict" not in finding
    if advisory:
        assert advisory in finding["advisoryIds"]
    if vendor == "endor":
        assert finding["evidence"]["finding_tags"] == ["FINDING_TAGS_REACHABLE_FUNCTION"]
        assert finding["evidence"]["reachable_paths"]
        assert finding["dependencyPaths"] == []
        assert finding["fix"]["proposed_version"] == "1.0.1"
    elif vendor == "snyk":
        assert finding["evidence"]["reachability"] == "reachable"
        assert finding["dependencyPaths"][0][-1] == f"{package}@3.1"
        assert finding["fix"]["fixedIn"] == ["3.2.2"]
    else:
        assert finding["kind"] == "malware"
        assert finding["fix"]["fix"]["type"] == "remove"
        assert finding["evidence"]["package"]["type"] == "pypi"


def test_snyk_preserves_separate_paths_and_missing_package_metadata() -> None:
    """Repeated advisories on different paths survive and license alerts do not."""
    payload = _fixture("snyk")
    records = payload["vulnerabilities"]
    second = deepcopy(records[0])
    second["from"] = ["other-project@1", "org.example:parser@3.1"]
    del second["version"]
    records.extend([second, {"type": "license", "id": "license-example"}])
    result = parse_report([payload], "snyk")
    findings = result["findings"]
    assert len(findings) == 2
    assert findings[0]["sourceId"] == findings[1]["sourceId"]
    assert findings[0]["dependencyPaths"] != findings[1]["dependencyPaths"]
    assert "version" not in findings[1]["package"]
    assert result["excludedCount"] == 1
    assert len(result["warnings"]) == 2
    findings[0]["original"]["title"] = "changed copy"
    assert records[0]["title"] != "changed copy"


def test_snyk_preserves_grouped_dependency_paths() -> None:
    """Keep every dependency chain emitted by Snyk's grouped JSON output."""
    payload = _fixture("snyk")
    record = payload["vulnerabilities"][0]
    chains = [
        record["from"],
        ["other-project@1", "org.example:parser@3.1"],
    ]
    record["from"] = deepcopy(chains)
    before = deepcopy(payload)

    result = parse_report(payload, "snyk")

    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    assert finding["dependencyPaths"] == chains
    assert finding["original"] == before["vulnerabilities"][0]
    assert payload == before


def test_socket_offsets_and_scanner_reachability_remain_evidence() -> None:
    """Keep offsets as positions, package namespaces, and exact reachability."""
    artifact = {
        "type": "npm",
        "namespace": "@example",
        "name": "library",
        "version": "1.0",
        "manifestFiles": [{"file": "package-lock.json", "start": 40}],
        "alerts": [
            {
                "key": "test-alert",
                "type": "cve",
                "severity": "middle",
                "category": "vulnerability",
                "file": "library/index.js",
                "start": 500,
                "end": 900,
                "props": {"cveId": "CVE-2099-0001", "firstPatchedVersionIdentifier": "1.1"},
                "reachability": {"head": {"type": "full-scan", "results": []}},
            }
        ],
    }
    result = parse_report([artifact, {"_type": "scores", "value": {}}], "socket")
    finding = result["findings"][0]
    assert finding["package"]["name"] == "@example/library"
    assert finding["originalSeverity"] == "middle"
    assert finding["locations"] == [{"path": "library/index.js"}, {"path": "package-lock.json"}]
    assert finding["evidence"]["start"] == 500
    assert finding["evidence"]["reachability"] == artifact["alerts"][0]["reachability"]
    assert finding["fix"]["firstPatchedVersionIdentifier"] == "1.1"


@pytest.mark.parametrize(
    ("vendor", "payload"),
    [
        ("other", {}),
        ("snyk", {"issues": {"vulnerabilities": []}}),
        ("snyk", {"packageManager": "npm", "vulnerabilities": [None]}),
        ("endor", {"findings": []}),
        ("endor", {"list": {"objects": [{"meta": {}}]}}),
        ("socket", {"ok": True, "data": {"self": {"alerts": []}}}),
        ("socket", [{"type": "cve", "severity": "high"}]),
    ],
)
def test_unsupported_shapes_fail_explicitly(vendor: str, payload: object) -> None:
    """Malformed or different export formats cannot silently import nothing."""
    with pytest.raises(ValueError):
        parse_report(payload, vendor)


@pytest.mark.parametrize("vendor", ["endor", "snyk", "socket"])
def test_source_count_is_bounded_before_filtering(vendor: str) -> None:
    """Excluded source records also consume the pre-normalization import limit."""
    if vendor == "endor":
        payload = {
            "list": {
                "objects": [
                    {"meta": {}, "spec": {"finding_categories": ["FINDING_CATEGORY_LICENSE_RISK"]}}
                ]
                * 10001
            }
        }
    elif vendor == "snyk":
        payload = {"packageManager": "npm", "vulnerabilities": [{"type": "license"}] * 10001}
    else:
        payload = {
            "ok": True,
            "data": [
                {
                    "type": "npm",
                    "alerts": [{"type": "unidentifiedLicense", "category": "license"}] * 10001,
                }
            ],
        }
    with pytest.raises(ValueError, match="at most 10000 source findings"):
        parse_report(payload, vendor)


def test_socket_does_not_amplify_shared_metadata() -> None:
    """Store original alerts without copying irrelevant artifact metadata per alert."""
    alert = {"key": "example-alert", "type": "cve", "props": {"cveId": "CVE-2099-0001"}}
    artifact = {
        "type": "npm",
        "name": "example",
        "version": "1.0",
        "alerts": [alert] * 20,
        "licenseDetails": {"largeVendorValue": "x" * 100000},
        "alertKeysToReachabilitySummaries": {"example-alert": [{"type": "reachable"}]},
    }
    result = parse_report({"ok": True, "data": [artifact]}, "socket")
    assert len(json.dumps(result)) < 50000
    assert len(result["findings"]) == 20
    assert all(finding["original"] == alert for finding in result["findings"])
    assert result["findings"][0]["evidence"]["reachabilitySummary"] == [{"type": "reachable"}]


@pytest.mark.parametrize("vendor", ["snyk", "socket"])
def test_oversized_shared_context_is_rejected(vendor: str) -> None:
    """Oversized repeated project or package context cannot multiply report size."""
    if vendor == "snyk":
        payload = {"packageManager": "npm", "projectName": "x" * 20000, "vulnerabilities": []}
    else:
        payload = {"ok": True, "data": [{"type": "npm", "name": "x" * 20000, "alerts": []}]}
    with pytest.raises(ValueError, match="Shared package or project context"):
        parse_report(payload, vendor)


def test_normalized_storage_is_bounded() -> None:
    """A valid source report cannot produce unlimited repeated stored context."""
    payload = {"packageManager": "npm", "projectName": "x" * 12000, "vulnerabilities": [{}] * 1500}
    with pytest.raises(ValueError, match="Normalized findings"):
        parse_report(payload, "snyk")
