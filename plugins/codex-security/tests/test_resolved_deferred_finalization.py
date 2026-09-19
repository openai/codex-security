from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType

import pytest


def load_finalizer() -> ModuleType:
    script = Path(__file__).resolve().parent.parent / "scripts" / "finalize_scan_contract.py"
    spec = importlib.util.spec_from_file_location("resolved_deferred_finalizer", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FINALIZER = load_finalizer()
EXAMPLE_DIR = Path(__file__).resolve().parent.parent / "examples" / "completed-scan"


def test_finalization_seals_resolved_deferred_receipts(tmp_path: Path) -> None:
    scan_dir = tmp_path / "scan"
    shutil.copytree(EXAMPLE_DIR, scan_dir)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["scan"].pop("sealedAt", None)
    manifest["scan"].pop("artifacts", None)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    receipt_ref = "artifacts/review/source-review.json"
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    coverage["resolvedDeferred"] = [
        {
            "id": "source-review",
            "resolution": "completed",
            "surfaceIds": [coverage["surfaces"][0]["id"]],
            "receiptRefs": [receipt_ref],
        }
    ]
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    receipt_path = scan_dir / receipt_ref
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text('{"status":"completed"}\n', encoding="utf-8")

    warnings: list[str] = []
    recovered = FINALIZER._prepare_scan_finalization(scan_dir, completion_warnings=warnings)[4]
    assert recovered["resolvedDeferred"] == []
    assert recovered["completeness"] == "partial"
    assert any("resolved deferred" in warning for warning in warnings)

    coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    findings["findings"][0].pop("title")
    findings_path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    warnings = []
    recovered = FINALIZER._prepare_scan_finalization(scan_dir, completion_warnings=warnings)[4]
    assert recovered["resolvedDeferred"] == []
    assert any("needs_follow_up" in warning for warning in warnings)
    shutil.copyfile(EXAMPLE_DIR / "findings.json", findings_path)
    coverage["surfaces"][0]["receiptRefs"] = []
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")

    coverage["resolvedDeferred"][0]["id"] = []
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    with pytest.raises(FINALIZER.ContractError, match=r"resolvedDeferred\[0\]\.id"):
        FINALIZER.finalize_scan(scan_dir)
    coverage["resolvedDeferred"][0]["id"] = "source-review"
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(FINALIZER.ContractError, match="no matching generic deferred"):
        FINALIZER.finalize_scan(scan_dir)

    checkpoint_dir = scan_dir / "checkpoints"
    checkpoint_dir.mkdir()
    checkpoint = {
        "scanId": coverage["scanId"],
        "complete": False,
        "coverage": {
            "deferred": [
                {
                    "id": "source-review",
                    "reason": "Independent source review remains pending.",
                }
            ]
        },
    }
    (checkpoint_dir / "partial.json").write_text(
        json.dumps(checkpoint, indent=2) + "\n", encoding="utf-8"
    )

    with pytest.raises(FINALIZER.ContractError, match="must be attached"):
        FINALIZER.finalize_scan(scan_dir)

    coverage["surfaces"][0]["receiptRefs"] = [receipt_ref]
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")

    FINALIZER.finalize_scan(scan_dir)

    sealed = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert receipt_ref in [artifact["path"] for artifact in sealed["scan"]["artifacts"]]
    receipt_path.write_text('{"status":"changed"}\n', encoding="utf-8")
    with pytest.raises(FINALIZER.ContractError, match="sealed artifact changed"):
        FINALIZER.finalize_scan(scan_dir)
