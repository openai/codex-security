from __future__ import annotations

import copy

import pytest
import test_finalize_scan_contract as contract_tests

FINALIZER = contract_tests.FINALIZER


@pytest.fixture
def scan_case():
    case = contract_tests.FinalizeScanContractTest()
    case.setUp()
    yield case
    case.tearDown()


def test_rejects_case_aliases_for_sealed_artifacts(scan_case) -> None:
    scan_case.write_scan()
    FINALIZER.finalize_scan(scan_case.scan_dir)
    manifest = scan_case.read_json("scan-manifest.json")
    artifact = copy.deepcopy(manifest["scan"]["artifacts"][0])
    artifact["path"] = artifact["path"].upper()
    manifest["scan"]["artifacts"].append(artifact)
    scan_case.write_json("scan-manifest.json", manifest)
    with pytest.raises(FINALIZER.ContractError, match="duplicate artifact path"):
        FINALIZER.finalize_scan(scan_case.scan_dir)


@pytest.mark.parametrize(
    "path",
    [
        "D:/escape",
        "D:escape",
        "../escape",
        "artifacts\\escape",
        "artifacts/report.json.",
        "artifacts/report.json ",
        "artifacts/CON.txt",
        "artifacts/COM¹.txt",
        "artifacts/report?.json",
        "artifacts/report:stream",
        "artifacts/control\x01.json",
    ],
)
def test_rejects_windows_ambiguous_artifact_paths(scan_case, path: str) -> None:
    scan_case.write_scan()
    FINALIZER.finalize_scan(scan_case.scan_dir)
    manifest = scan_case.read_json("scan-manifest.json")
    manifest["scan"]["artifacts"].append(
        {"path": path, "sha256": "0" * 64, "mediaType": "text/plain"}
    )
    scan_case.write_json("scan-manifest.json", manifest)
    with pytest.raises(FINALIZER.ContractError, match="safe .*relative POSIX path"):
        FINALIZER.finalize_scan(scan_case.scan_dir)


def test_preserves_unix_valid_source_paths(scan_case) -> None:
    source = "src/CON.py:fixture"
    scan_case.manifest["scan"]["scope"]["includePaths"] = [source]
    scan_case.coverage["includePaths"] = [source]
    scan_case.coverage["surfaces"][0]["paths"] = [source]
    scan_case.findings["findings"][0]["locations"][0]["path"] = source
    scan_case.write_scan()
    _, findings, _ = FINALIZER.finalize_scan(scan_case.scan_dir)
    assert findings["findings"][0]["locations"][0]["path"] == source
