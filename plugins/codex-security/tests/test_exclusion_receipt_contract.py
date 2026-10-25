from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from workbench_test_support import (
    empty_target_scan,
    load_script,
    run_workbench,
    write_completed_contract,
)

FINALIZER = load_script("finalize_scan_contract")
IDENTITY = load_script("candidate_identity")


def exclusion_scan(
    tmp_path: Path, disposition: str | None, receipt: str, field="explicitExclusions"
):
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    findings = json.loads((scan_dir / "findings.json").read_text())
    findings["findings"] = []
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    pending = {
        "id": "saved-proof-gap",
        "candidateId": "candidate-é",
        "sourceWorkerId": "reviewer",
        "reason": "Original candidate proof gap remains unanswered.",
        "paths": ["app.py"],
        "candidate": {"evidence": "Saved evidence", "future": [1, {"value": None}]},
        "futureGapMetadata": {"preserve": ["all", "values"]},
    }
    refs = {
        "valid": ["artifacts/review.bin"],
        "missing": ["artifacts/missing.bin"],
        "unsafe": ["../outside.bin"],
        "malformed": None,
        "none": [],
    }[receipt]
    decision = {
        "id": "review-decision",
        "label": "Reviewed candidate",
        "pattern": "app.py",
        "reason": "Saved terminal decision.",
        "candidateId": pending["candidateId"],
        "sourceWorkerId": pending["sourceWorkerId"],
        **({} if disposition is None else {"disposition": disposition}),
        "receiptRefs": refs,
        "futureDecisionMetadata": {"retained": True},
    }
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    coverage.update(
        completeness="partial",
        surfaces=[],
        explicitExclusions=[],
        deferred=[pending] if receipt in {"missing", "unsafe", "malformed"} else [],
    )
    coverage[field] = [decision]
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    if receipt == "valid":
        (scan_dir / "artifacts").mkdir(exist_ok=True)
        (scan_dir / "artifacts/review.bin").write_bytes(bytes([0, 255, 128, 10]))
    return state, scan_id, scan_dir, pending, decision


def publish(state: Path, scan_id: str, scan_dir: Path, entrypoint: str):
    if entrypoint == "workbench":
        run_workbench(state, "complete-scan", "--scan-id", scan_id)
    else:
        completed = subprocess.run(
            [sys.executable, FINALIZER.__file__, "--scan-dir", str(scan_dir)],
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("entrypoint", ["standalone", "workbench"])
@pytest.mark.parametrize("disposition", ["rejected", "not_applicable", "needs_follow_up", None])
@pytest.mark.parametrize("receipt", ["valid", "missing", "unsafe", "malformed", "none"])
def test_exclusion_proof_recovery_matches_public_entrypoints(
    tmp_path: Path, entrypoint: str, disposition: str | None, receipt: str
):
    state, scan_id, scan_dir, pending, decision = exclusion_scan(tmp_path, disposition, receipt)
    publish(state, scan_id, scan_dir, entrypoint)
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    reopened = receipt in {"missing", "unsafe", "malformed"}
    assert len(IDENTITY.unresolved_candidates(coverage, [])) == int(reopened)
    assert (
        coverage["explicitExclusions"][0]["futureDecisionMetadata"]
        == decision["futureDecisionMetadata"]
    )
    assert coverage["explicitExclusions"][0].get("disposition") == (
        "needs_follow_up" if reopened else disposition
    )
    report = (scan_dir / "report.md").read_text()
    assert (pending["reason"] in report) is reopened
    if reopened:
        assert pending in coverage["deferred"]
        assert "completeness" not in coverage
    sarif = json.loads((scan_dir / "exports/results.sarif").read_text())
    assert sarif["runs"][0]["results"] == []
    before = {
        name: (scan_dir / name).read_bytes()
        for name in (
            "scan-manifest.json",
            "findings.json",
            "coverage.json",
            "report.md",
            "exports/results.sarif",
        )
    }
    FINALIZER.finalize_scan(scan_dir)
    assert all((scan_dir / name).read_bytes() == contents for name, contents in before.items())


@pytest.mark.parametrize("entrypoint", ["standalone", "workbench"])
@pytest.mark.parametrize("receipt", ["valid", "missing", "malformed"])
def test_generic_exclusion_receipt_metadata_remains_opaque_on_publication(
    tmp_path: Path, entrypoint: str, receipt: str
):
    state, scan_id, scan_dir, _, decision = exclusion_scan(tmp_path, "rejected", receipt)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = []
    decision.pop("candidateId")
    coverage["explicitExclusions"] = [decision]
    coverage_path.write_text(json.dumps(coverage))

    publish(state, scan_id, scan_dir, entrypoint)
    published = json.loads(coverage_path.read_text())
    assert published["receiptSealVersion"] == 1
    assert published["explicitExclusions"] == [decision]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert "artifacts/review.bin" not in {row["path"] for row in manifest["scan"]["artifacts"]}
    (scan_dir / "artifacts/review.bin").unlink(missing_ok=True)
    assert FINALIZER.finalize_scan(scan_dir)[2] == published


@pytest.mark.parametrize("entrypoint", ["standalone", "workbench"])
@pytest.mark.parametrize("field", ["surfaces", "explicitExclusions"])
@pytest.mark.parametrize("change", ["delete", "modify"])
def test_exclusion_and_surface_proof_are_sealed_and_verified(
    tmp_path: Path, entrypoint: str, field: str, change: str
):
    state, scan_id, scan_dir, _, _ = exclusion_scan(tmp_path, "rejected", "valid", field)
    publish(state, scan_id, scan_dir, entrypoint)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    receipt = scan_dir / "artifacts/review.bin"
    if change == "delete":
        receipt.unlink()
    else:
        receipt.write_bytes(b"Changed proof")
    with pytest.raises(FINALIZER.ContractError):
        FINALIZER.finalize_scan(scan_dir)
    exported = subprocess.run(
        [sys.executable, FINALIZER.__file__, "--scan-dir", str(scan_dir), "--sarif-only"],
        capture_output=True,
        text=True,
    )
    assert exported.returncode != 0
    assert "artifacts/review.bin" in {item["path"] for item in manifest["scan"]["artifacts"]}


def test_sealed_exclusion_cannot_reference_proof_outside_its_artifact_inventory(tmp_path: Path):
    state, scan_id, scan_dir, _, _ = exclusion_scan(tmp_path, "rejected", "valid")
    publish(state, scan_id, scan_dir, "standalone")
    path = scan_dir / "scan-manifest.json"
    manifest = json.loads(path.read_text())
    manifest["scan"]["artifacts"] = [
        item for item in manifest["scan"]["artifacts"] if item["path"] != "artifacts/review.bin"
    ]
    path.write_text(json.dumps(manifest))
    with pytest.raises(FINALIZER.ContractError, match="missing from sealed artifacts"):
        FINALIZER.finalize_scan(scan_dir)


def test_sealed_exclusion_receipt_version_rejects_boolean(tmp_path: Path) -> None:
    state, scan_id, scan_dir, _, _ = exclusion_scan(tmp_path, "rejected", "valid")
    publish(state, scan_id, scan_dir, "standalone")
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["receiptSealVersion"] = True
    coverage_path.write_text(json.dumps(coverage))
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["scan"]["artifacts"]:
        if artifact["path"] == "coverage.json":
            artifact["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(FINALIZER.ContractError, match="receiptSealVersion"):
        FINALIZER.finalize_scan(scan_dir)


@pytest.mark.parametrize("entrypoint", ["standalone", "workbench"])
@pytest.mark.parametrize("identity", [7, {"opaque": [1, None]}, "", " ", "authored-task"])
def test_exclusion_metadata_does_not_become_task_or_surface_identity(
    tmp_path: Path, entrypoint: str, identity
):
    state, scan_id, scan_dir, _, _ = exclusion_scan(tmp_path, "rejected", "missing")
    path = scan_dir / "coverage.json"
    coverage = json.loads(path.read_text())
    coverage["deferred"] = []
    coverage["explicitExclusions"][0]["id"] = identity
    path.write_text(json.dumps(coverage))
    publish(state, scan_id, scan_dir, entrypoint)
    coverage = json.loads(path.read_text())
    assert coverage["explicitExclusions"][0]["id"] == identity
    pending = IDENTITY.unresolved_candidates(coverage, [])
    assert len(pending) == 1
    assert pending[0]["id"] == (
        identity if isinstance(identity, str) and identity.strip() else "candidate-é"
    )
    assert "surfaceIds" not in pending[0]
    assert FINALIZER.finalize_scan(scan_dir)[2] == coverage


@pytest.mark.parametrize(
    "receipt_refs",
    [["artifacts/proof.bin"], ["artifacts/missing.bin"], {"opaque": True}, [7, {"opaque": True}]],
)
def test_legacy_sealed_exclusion_extensions_remain_opaque(tmp_path: Path, receipt_refs):
    # Legacy coverage was hashed, but exclusion receipts were not inventoried.
    scan_dir = tmp_path / "legacy"
    shutil.copytree(Path(__file__).resolve().parents[1] / "examples" / "completed-scan", scan_dir)
    scan_dir.chmod(0o700)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.pop("receiptSealVersion", None)
    reason = "Legacy candidate proof gap remains unanswered."
    coverage.update(
        surfaces=[],
        completeness="partial",
        deferred=[{"id": "legacy-gap", "candidateId": "legacy-candidate", "reason": reason}],
        explicitExclusions=[
            {
                "pattern": "src/extract.py",
                "reason": "Opaque historical decision.",
                "id": {"opaque": 7},
                "candidateId": "legacy-candidate",
                "disposition": "rejected",
                "receiptRefs": receipt_refs,
            }
        ],
    )
    coverage_path.write_text(json.dumps(coverage))
    receipt = scan_dir / "artifacts" / "proof.bin"
    receipt.parent.mkdir(exist_ok=True)
    receipt.write_bytes(b"Synthetic legacy proof")
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for artifact in manifest["scan"]["artifacts"]:
        if artifact["path"] == "coverage.json":
            artifact["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    original = {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "coverage.json", "findings.json")
    }
    assert FINALIZER.finalize_scan(scan_dir)[2] == coverage
    assert reason in (scan_dir / "report.md").read_text()
    for arguments in (["--sarif-only"], ["--export-format", "json"]):
        exported = subprocess.run(
            [sys.executable, FINALIZER.__file__, "--scan-dir", str(scan_dir), *arguments],
            capture_output=True,
            text=True,
        )
        assert exported.returncode == 0, exported.stderr
    assert all((scan_dir / name).read_bytes() == value for name, value in original.items())


@pytest.mark.parametrize("version", ["legacy", "current", "draft", "no-manifest"])
def test_saved_candidate_count_respects_actual_seal(tmp_path: Path, version: str):
    state, scan_id, scan_dir, pending, _ = exclusion_scan(tmp_path, "rejected", "valid")
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [pending]
    coverage_path.write_text(json.dumps(coverage))
    manifest_path = scan_dir / "scan-manifest.json"
    if version in {"legacy", "current"}:
        publish(state, scan_id, scan_dir, "standalone")
    if version == "legacy":
        coverage = json.loads(coverage_path.read_text())
        coverage.pop("receiptSealVersion")
        coverage_path.write_text(json.dumps(coverage))
        manifest = json.loads(manifest_path.read_text())
        manifest["scan"]["artifacts"] = [
            item for item in manifest["scan"]["artifacts"] if item["path"] != "artifacts/review.bin"
        ]
        for item in manifest["scan"]["artifacts"]:
            if item["path"] == "coverage.json":
                item["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    elif version == "no-manifest":
        manifest_path.unlink()
    original = {
        path.name: path.read_bytes()
        for path in (coverage_path, manifest_path, scan_dir / "findings.json")
        if path.exists()
    }
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unresolved"] == int(version == "legacy")
    if version in {"legacy", "current"}:
        FINALIZER.finalize_scan(scan_dir)
        assert (pending["reason"] in (scan_dir / "report.md").read_text()) == (version == "legacy")
    assert all((scan_dir / name).read_bytes() == contents for name, contents in original.items())
