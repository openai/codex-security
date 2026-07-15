from __future__ import annotations

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from openai_codex_security import ContractValidationError
from openai_codex_security.contract import ScanExpectation, load_contract
from openai_codex_security.models import (
    CoverageMode,
    FindingSeverity,
    ScanTargetRecord,
)
from openai_codex_security.runtime import bundled_plugin_root
from openai_codex_security.targets import NormalizedTarget, ScanMode

PLUGIN_ROOT = bundled_plugin_root()
EXAMPLE = PLUGIN_ROOT / "examples/completed-scan"


def _copy_example(tmp_path: Path) -> Path:
    scan_dir = tmp_path / "scan"
    shutil.copytree(EXAMPLE, scan_dir)
    return scan_dir


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _reseal(scan_dir: Path) -> None:
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = _read(manifest_path)
    for artifact in manifest["scan"]["artifacts"]:
        path = scan_dir / artifact["path"]
        if path.is_file():
            artifact["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    _write(manifest_path, manifest)


def _expectation(
    tmp_path: Path,
    *,
    target: NormalizedTarget | None = None,
    mode: ScanMode = "standard",
    revision: str | None = "deadbeef",
    plugin_version: str = "0.1.0",
) -> ScanExpectation:
    return ScanExpectation(
        repository=tmp_path,
        repository_revision=revision,
        target=target or NormalizedTarget(kind="repository"),
        mode=mode,
        plugin_version=plugin_version,
    )


def test_load_contract_example(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    manifest, findings, coverage = load_contract(scan_dir)
    assert manifest.document_type == "codex-security.scan-manifest"
    assert findings.document_type == "codex-security.findings"
    assert coverage.document_type == "codex-security.coverage"
    assert findings.scan_id == coverage.scan_id == manifest.scan.id


def test_contract_exposes_typed_nested_models(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    manifest, findings, coverage = load_contract(scan_dir)
    assert isinstance(manifest.scan.target, ScanTargetRecord)
    assert manifest.scan.target.target_id == "target_sha256_example"
    assert isinstance(findings.findings[0].severity, FindingSeverity)
    assert findings.findings[0].severity.level == "high"
    assert coverage.mode == CoverageMode.repository
    assert coverage.surfaces[0].receipt_refs == []


def test_contract_scan_ids_must_match(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    path = scan_dir / "findings.json"
    payload = _read(path)
    payload["scanId"] = "other"
    _write(path, payload)
    _reseal(scan_dir)
    with pytest.raises(ContractValidationError, match="scan IDs"):
        load_contract(scan_dir)


def test_contract_requires_all_documents(tmp_path: Path) -> None:
    with pytest.raises(ContractValidationError, match="scan-manifest.json"):
        load_contract(tmp_path)


def test_contract_rejects_changed_sealed_artifact(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    path = scan_dir / "findings.json"
    payload = _read(path)
    payload["findings"][0]["title"] = "tampered"
    _write(path, payload)

    with pytest.raises(ContractValidationError, match="sealed artifact changed"):
        load_contract(scan_dir)


def test_contract_rejects_duplicate_artifact_paths(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = _read(manifest_path)
    manifest["scan"]["artifacts"].append(copy.deepcopy(manifest["scan"]["artifacts"][0]))
    _write(manifest_path, manifest)

    with pytest.raises(ContractValidationError, match="duplicate artifact path"):
        load_contract(scan_dir)


def test_contract_rejects_unsealed_coverage_receipt(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = _read(coverage_path)
    coverage["surfaces"][0]["receiptRefs"] = ["artifacts/receipt.jsonl"]
    _write(coverage_path, coverage)
    _reseal(scan_dir)

    with pytest.raises(ContractValidationError, match="missing from sealed artifacts"):
        load_contract(scan_dir)


def test_contract_rejects_inconsistent_seal_time(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = _read(manifest_path)
    manifest["scan"]["sealedAt"] = "2026-05-31T18:10:00Z"
    _write(manifest_path, manifest)

    with pytest.raises(ContractValidationError, match="sealedAt"):
        load_contract(scan_dir)


def test_contract_rejects_windows_drive_artifact_path(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = _read(manifest_path)
    manifest["scan"]["artifacts"].append(
        {"path": "D:/escape", "sha256": "0" * 64, "mediaType": "text/plain"}
    )
    _write(manifest_path, manifest)

    with pytest.raises(ContractValidationError, match="safe scan-relative"):
        load_contract(scan_dir)


def test_contract_rejects_symlink_artifact(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    artifacts = scan_dir / "artifacts"
    artifacts.mkdir()
    target = artifacts / "target.txt"
    target.write_text("receipt\n", encoding="utf-8")
    link = artifacts / "link.txt"
    link.symlink_to(target)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = _read(manifest_path)
    manifest["scan"]["artifacts"].append(
        {
            "path": "artifacts/link.txt",
            "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            "mediaType": "text/plain",
        }
    )
    _write(manifest_path, manifest)

    with pytest.raises(ContractValidationError, match="non-symlink"):
        load_contract(scan_dir)


def test_contract_accepts_legacy_finding_shapes(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    findings_path = scan_dir / "findings.json"
    findings = _read(findings_path)
    finding = findings["findings"][0]
    finding["validation"] = {"evidence": "legacy evidence"}
    finding["attackPath"] = {
        "dataflow": "legacy dataflow",
        "reachability": "legacy reachability",
    }
    _write(findings_path, findings)
    _reseal(scan_dir)

    _, loaded, _ = load_contract(scan_dir)
    assert loaded.findings[0].validation.evidence == "legacy evidence"
    assert loaded.findings[0].attack_path.dataflow == "legacy dataflow"
    assert loaded.findings[0].attack_path.reachability == "legacy reachability"


def test_contract_uses_effective_plugin_schemas(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    plugin = tmp_path / "plugin"
    schemas = plugin / "schemas"
    shutil.copytree(PLUGIN_ROOT / "schemas", schemas)
    coverage_schema_path = schemas / "coverage.schema.json"
    coverage_schema = _read(coverage_schema_path)
    coverage_schema["properties"]["mode"]["enum"] = ["scoped_path"]
    _write(coverage_schema_path, coverage_schema)

    with pytest.raises(ContractValidationError, match="coverage.json:mode"):
        load_contract(scan_dir, plugin_root=plugin)


def test_contract_binds_path_scope_and_plugin_version(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = _read(coverage_path)
    coverage["mode"] = "scoped_path"
    _write(coverage_path, coverage)
    _reseal(scan_dir)

    expectation = _expectation(
        tmp_path,
        target=NormalizedTarget(kind="paths", paths=("src",)),
    )
    manifest, _, _ = load_contract(scan_dir, expectation=expectation)
    assert manifest.scan.producer.version == "0.1.0"

    wrong = _expectation(
        tmp_path,
        target=NormalizedTarget(kind="paths", paths=("packages/auth",)),
    )
    with pytest.raises(ContractValidationError, match="include paths"):
        load_contract(scan_dir, expectation=wrong)


def test_contract_rejects_wrong_mode_and_plugin_version(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    with pytest.raises(ContractValidationError, match="Coverage mode"):
        load_contract(scan_dir, expectation=_expectation(tmp_path, mode="deep"))
    with pytest.raises(ContractValidationError, match="producer version"):
        load_contract(scan_dir, expectation=_expectation(tmp_path, plugin_version="9.9.9"))


def test_contract_binds_diff_revisions(tmp_path: Path) -> None:
    scan_dir = _copy_example(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = _read(manifest_path)
    manifest["scan"]["target"].update(
        {"kind": "git_diff", "baseRevision": "base-sha", "headRevision": "head-sha"}
    )
    _write(manifest_path, manifest)
    coverage_path = scan_dir / "coverage.json"
    coverage = _read(coverage_path)
    coverage["mode"] = "branch_diff"
    _write(coverage_path, coverage)
    _reseal(scan_dir)

    expectation = _expectation(
        tmp_path,
        target=NormalizedTarget(kind="refs", base="wrong-base", head="head-sha"),
    )
    with pytest.raises(ContractValidationError, match="base revision"):
        load_contract(scan_dir, expectation=expectation)
