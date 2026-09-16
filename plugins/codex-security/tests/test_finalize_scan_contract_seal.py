from __future__ import annotations

import hashlib

import pytest
import test_finalize_scan_contract as contract_tests

FINALIZER = contract_tests.FINALIZER


@pytest.fixture
def scan():
    case = contract_tests.FinalizeScanContractTest()
    case.setUp()
    try:
        yield case
    finally:
        case.tearDown()


@pytest.mark.parametrize("finding_count", [0, 1])
def test_finalize_draft_with_empty_artifacts(scan, finding_count):
    scan.manifest["scan"]["artifacts"] = []
    scan.findings["findings"] = scan.findings["findings"][:finding_count]
    scan.coverage["mode"] = "diff"
    scan.coverage["inventoryStrategy"] = "diff"
    scan.coverage["surfaces"][0]["disposition"] = "reported" if finding_count else "no_issue_found"
    scan.write_scan()
    (scan.scan_dir / "report.md").unlink()

    with pytest.raises(FINALIZER.ContractError, match="requires a sealed scan"):
        FINALIZER.build_sarif_projection(scan.scan_dir)

    FINALIZER.finalize_scan(scan.scan_dir, expected_coverage_mode="diff")

    manifest = scan.read_json("scan-manifest.json")
    assert manifest["scan"]["sealedAt"] == manifest["scan"]["completedAt"]
    assert [artifact["path"] for artifact in manifest["scan"]["artifacts"]] == [
        "findings.json",
        "coverage.json",
    ]
    for artifact in manifest["scan"]["artifacts"]:
        assert (
            artifact["sha256"]
            == hashlib.sha256((scan.scan_dir / artifact["path"]).read_bytes()).hexdigest()
        )
    assert len(scan.read_json("findings.json")["findings"]) == finding_count
    assert (scan.scan_dir / "report.md").is_file()
    assert len(scan.read_json("exports/results.sarif")["runs"][0]["results"]) == finding_count
    sealed_manifest = (scan.scan_dir / "scan-manifest.json").read_bytes()
    FINALIZER.finalize_scan(scan.scan_dir)
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == sealed_manifest


def test_finalize_rejects_empty_artifacts_with_existing_seal(scan):
    scan.write_scan()
    FINALIZER.finalize_scan(scan.scan_dir)
    manifest = scan.read_json("scan-manifest.json")
    manifest["scan"]["artifacts"] = []
    scan.write_json("scan-manifest.json", manifest)
    manifest_bytes = (scan.scan_dir / "scan-manifest.json").read_bytes()

    with pytest.raises(FINALIZER.ContractError, match="requires artifact records"):
        FINALIZER.finalize_scan(scan.scan_dir)
    with pytest.raises(FINALIZER.ContractError, match="requires artifact records"):
        FINALIZER.build_sarif_projection(scan.scan_dir)
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == manifest_bytes
