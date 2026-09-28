from __future__ import annotations

import hashlib

import pytest
import test_finalize_scan_contract as contract


@pytest.fixture
def scan():
    case = contract.FinalizeScanContractTest()
    case.setUp()
    try:
        yield case
    finally:
        case.tearDown()


def test_file_inventory_is_normalized_written_and_sealed(scan):
    scan.coverage["fileInventory"] = {
        "inScopeFiles": ["src/z.py", "src/a space.py", "./src/z.py", "src/é.py"],
        "reviewedFiles": ["./src/z.py", "src/z.py", "support/outside.py", "src/é.py"],
    }
    scan.write_scan()
    manifest, _, coverage = contract.FINALIZER.finalize_scan(scan.scan_dir)
    assert coverage["completeness"] == "partial"
    assert coverage["fileInventory"]["reviewedFiles"] == ["src/z.py", "src/é.py"]
    expected = {
        "in_scope_files.txt": "src/a space.py\nsrc/z.py\nsrc/é.py\n",
        "reviewed_files.txt": "src/z.py\nsrc/é.py\n",
        "remaining_files.txt": "src/a space.py\n",
    }
    artifacts = {item["path"]: item for item in manifest["scan"]["artifacts"]}
    for name, contents in expected.items():
        path = f"artifacts/coverage/{name}"
        assert (scan.scan_dir / path).read_text(encoding="utf-8") == contents
        assert artifacts[path]["sha256"] == hashlib.sha256(contents.encode()).hexdigest()
    contract.FINALIZER.finalize_scan(scan.scan_dir)
    (scan.scan_dir / "artifacts/coverage/reviewed_files.txt").write_text("src/other.py\n")
    with pytest.raises(contract.FINALIZER.ContractError):
        contract.FINALIZER.finalize_scan(scan.scan_dir)


def test_complete_file_inventory_writes_empty_remaining_list(scan):
    scan.coverage["fileInventory"] = {
        "inScopeFiles": ["src/extract.py"],
        "reviewedFiles": ["src/extract.py"],
    }
    scan.write_scan()
    _, _, coverage = contract.FINALIZER.finalize_scan(scan.scan_dir)
    assert coverage["completeness"] == "complete"
    assert (scan.scan_dir / "artifacts/coverage/remaining_files.txt").read_bytes() == b""


def test_missing_inventory_does_not_claim_zero_reviewed_files(scan):
    scan.write_scan()
    _, _, coverage = contract.FINALIZER.finalize_scan(scan.scan_dir)
    assert "fileInventory" not in coverage
    assert not (scan.scan_dir / "artifacts/coverage").exists()


def test_inventory_output_rejects_symlink_directory(scan, tmp_path):
    scan.coverage["fileInventory"] = {"inScopeFiles": [], "reviewedFiles": []}
    scan.write_scan()
    (scan.scan_dir / "artifacts").mkdir()
    try:
        (scan.scan_dir / "artifacts/coverage").symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    before = (scan.scan_dir / "scan-manifest.json").read_bytes()
    with pytest.raises(contract.FINALIZER.ContractError):
        contract.FINALIZER.finalize_scan(scan.scan_dir)
    assert (scan.scan_dir / "scan-manifest.json").read_bytes() == before
    assert list(tmp_path.iterdir()) == []
