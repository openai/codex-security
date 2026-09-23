from __future__ import annotations

import json
import sqlite3
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    create_saved_workspace,
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    run_workbench,
    write_completed_contract,
)

OWNER_THREAD = "compact-completion-owner"
CANONICAL_OUTPUTS = ("scan-manifest.json", "findings.json", "coverage.json", "report.md")


@dataclass(frozen=True)
class CompactScan:
    state_dir: Path
    target: Path
    scan_dir: Path
    scan_id: str
    claim_token: str
    ledger_path: Path
    inventory_path: Path


def _validation(disposition: str = "reportable") -> dict[str, Any]:
    return {
        "disposition": disposition,
        "method": "Static source-to-sink trace.",
        "confidence": "high",
        "confidence_rationale": "The reviewed source directly reaches the sensitive sink.",
        "rubric": ["Attacker-controlled input reaches the sink."],
        "evidence": ["The reviewed source passes its argument to the sink."],
        "counterevidence_or_proof_gap": "No effective control was observed.",
        "remaining_uncertainty": "",
    }


def _report(
    *,
    title: str = "Untrusted query reaches SQL execution",
    instance: str | None = None,
    location_indexes: list[int] | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "category": "sql-injection",
        "remediation": "Use a parameterized SQL statement.",
        "title": title,
        "ruleId": "sql-injection.query-execution",
        "summary": "An attacker-controlled query reaches SQL execution.",
        "rootCause": "The query is executed without parameterization.",
        "remediationTests": ["A crafted query is treated as a parameter."],
        "preventiveControls": ["Require parameterized statements at database boundaries."],
    }
    if instance is not None:
        report["instance"] = instance
    if location_indexes is not None:
        report["locationIndexes"] = location_indexes
    return report


def _attack_path(
    *,
    decision: str = "reportable",
    reports: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    attack_path: dict[str, Any] = {
        "decision": decision,
        "dataflow": "Request input reaches the SQL execution sink.",
        "reachability": "The request handler exposes the execution helper.",
        "counterevidence": "No parameterization or equivalent control was observed.",
        "impact": "high",
        "likelihood": "medium",
        "severity": "ignore" if decision == "ignore" else "high",
        "severity_rationale": "Untrusted input can alter the executed SQL statement.",
        "change_conditions": "Parameterized queries would remove the issue.",
    }
    if decision == "reportable":
        attack_path["reports"] = reports if reports is not None else [_report()]
    if decision == "deferred":
        attack_path["proof_gap"] = "Production route reachability has not been confirmed."
    return attack_path


def _candidate(
    candidate_id: str = "candidate-compact-sql",
    *,
    disposition: str = "reportable",
    path: str = "src/query.py",
    reports: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "candidate_id": candidate_id,
        "cwe_ids": ["CWE-89", "CWE-20"],
        "locations": [
            {"path": path, "start_line": 1, "end_line": 1, "role": "source"},
            {"path": path, "start_line": 2, "end_line": 2, "role": "sink"},
        ],
        "summary": "An attacker-controlled query reaches SQL execution.",
        "evidence": "The reviewed function executes its query argument directly.",
        "validation": _validation(disposition),
    }
    if disposition == "reportable":
        row["attack_path"] = _attack_path(reports=reports)
    elif disposition == "deferred":
        row["attack_path"] = _attack_path(decision="deferred")
    return row


def _start_compact_scan(
    tmp_path: Path,
    *,
    mode: str = "standard",
    rows: list[dict[str, Any]] | None = None,
    phase: str = "reporting",
    review_items_total: int = 4,
    review_items_completed: int = 4,
    complete_coordinator: bool = True,
) -> CompactScan:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    source = target / "src"
    source.mkdir(parents=True)
    for name in ("query.py", "archive.py", "guarded.py", "deferred.py"):
        (source / name).write_text(
            "def execute(connection, query):\n    return connection.execute(query)\n",
            encoding="utf-8",
        )

    workspace = create_saved_workspace(state_dir, target, thread_id=OWNER_THREAD, mode=mode)
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(workspace["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    claim_token = str(uuid.uuid4())

    run_workbench(
        state_dir,
        "claim-handoff-delivery",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
    )
    run_workbench(
        state_dir,
        "attach-scan-continuation-thread",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        OWNER_THREAD,
    )
    run_workbench(
        state_dir,
        "mark-handoff-delivered",
        "--scan-id",
        scan_id,
        "--claim-token",
        claim_token,
        "--thread-id",
        OWNER_THREAD,
    )

    if mode == "deep":
        run_workbench(
            state_dir,
            "begin-deep-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            OWNER_THREAD,
            "--claim-token",
            claim_token,
            "--available-parallelism",
            "8",
            environment={"CODEX_HOME": str(tmp_path / "codex-home")},
        )
        if complete_coordinator:
            mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)

    discovery = scan_dir / "artifacts" / "02_discovery"
    discovery.mkdir(parents=True, exist_ok=True)
    inventory_path = discovery / "in_scope_files.txt"
    inventory_path.write_text(
        "src/query.py\nsrc/archive.py\nsrc/guarded.py\nsrc/deferred.py\n",
        encoding="utf-8",
    )
    ledger_path = discovery / "candidate_ledger.jsonl"
    candidates = [_candidate()] if rows is None else rows
    ledger_path.write_text(
        "".join(f"{json.dumps(candidate, sort_keys=True)}\n" for candidate in candidates),
        encoding="utf-8",
    )

    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        phase,
        "--review-items-total",
        str(review_items_total),
        "--review-items-completed",
        str(review_items_completed),
        "--claim-token",
        claim_token,
    )

    return CompactScan(
        state_dir=state_dir,
        target=target,
        scan_dir=scan_dir,
        scan_id=scan_id,
        claim_token=claim_token,
        ledger_path=ledger_path,
        inventory_path=inventory_path,
    )


def _complete(scan: CompactScan, *, check: bool = True) -> dict[str, object]:
    return run_workbench(
        scan.state_dir,
        "complete-scan",
        "--scan-id",
        scan.scan_id,
        "--claim-token",
        scan.claim_token,
        check=check,
    )


def _read_document(scan: CompactScan, filename: str) -> dict[str, Any]:
    document = json.loads((scan.scan_dir / filename).read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _assert_running_without_outputs(scan: CompactScan) -> None:
    with sqlite3.connect(scan.state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, completed_at, seal_manifest_digest FROM scans WHERE id = ?",
            (scan.scan_id,),
        ).fetchone() == ("running", None, None)
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ?",
            (scan.scan_id,),
        ).fetchone() == (0,)
    for filename in CANONICAL_OUTPUTS:
        assert not (scan.scan_dir / filename).exists(), filename


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_ordinary_native_premature_completion_preserves_missing_manifest_error(
    tmp_path: Path,
    mode: str,
) -> None:
    scan = _start_compact_scan(tmp_path, mode=mode, phase="preflight")

    failed = _complete(scan, check=False)

    assert failed["returncode"] != 0
    assert "scan-manifest.json" in str(failed["stderr"])
    assert "reporting phase" not in str(failed["stderr"])
    assert not (scan.scan_dir / "scan-manifest.json").exists()


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_ordinary_native_authored_completion_preserves_legacy_behavior(
    tmp_path: Path,
    mode: str,
) -> None:
    scan = _start_compact_scan(tmp_path, mode=mode, phase="preflight")
    write_completed_contract(
        scan.scan_dir,
        scan.scan_id,
        scan.target,
        relative_path="src/query.py",
        coverage_mode="deep_repository" if mode == "deep" else "repository",
    )

    completed = _complete(scan)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1


def _start_dependency_artifact_sdk_scan(
    tmp_path: Path,
    *,
    mode: str = "standard",
    rows: list[dict[str, Any]] | None = None,
    phase: str = "reporting",
) -> tuple[Path, Path, str, str, str]:
    state_dir = tmp_path / "artifact-state"
    target = tmp_path / "artifact-repository"
    base_revision = initialize_git_repository(target)
    source = target / "src" / "query.py"
    source.parent.mkdir()
    source.write_text(
        "def execute(connection, query):\n    return connection.execute(query)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "src/query.py"], cwd=target, check=True)
    subprocess.run(["git", "commit", "-qm", "Add dependency artifact"], cwd=target, check=True)
    head_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=target,
        capture_output=True,
        check=True,
        text=True,
    ).stdout.strip()
    scan_dir = tmp_path / "artifact-scan"
    scan_dir.mkdir(mode=0o700)
    requested_target: dict[str, Any] = (
        {"kind": "refs", "base": base_revision, "head": head_revision, "paths": []}
        if mode == "diff"
        else {"kind": "repository", "paths": []}
    )
    registered = run_workbench(
        state_dir,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(target),
                "target": requested_target,
            }
        ),
    )
    scan_id = str(registered["scanId"])
    discovery_dir = scan_dir / "artifacts" / "02_discovery"
    discovery_dir.mkdir(parents=True)
    (discovery_dir / "in_scope_files.txt").write_text("src/query.py\n", encoding="utf-8")
    candidates = [] if rows is None else rows
    (discovery_dir / "candidate_ledger.jsonl").write_text(
        "".join(f"{json.dumps(candidate, sort_keys=True)}\n" for candidate in candidates),
        encoding="utf-8",
    )
    run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        phase,
    )
    return state_dir, scan_dir, scan_id, base_revision, head_revision


@pytest.mark.parametrize(
    ("mode", "coverage_mode", "inventory_strategy"),
    (("standard", "repository", "repository"), ("diff", "branch_diff", "diff")),
)
def test_trusted_dependency_artifact_sdk_scan_compiles_empty_findings(
    tmp_path: Path,
    mode: str,
    coverage_mode: str,
    inventory_strategy: str,
) -> None:
    state_dir, scan_dir, scan_id, base_revision, head_revision = (
        _start_dependency_artifact_sdk_scan(tmp_path, mode=mode)
    )
    environment = {"CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN": "1"}

    prepared = run_workbench(
        state_dir,
        "prepare-scan-completion",
        "--scan-id",
        scan_id,
        environment=environment,
    )
    completed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        environment=environment,
    )

    assert prepared["scan"]["progress"]["status"] == "running"
    assert completed["scan"]["progress"]["status"] == "complete"
    findings = json.loads((scan_dir / "findings.json").read_text(encoding="utf-8"))
    assert findings["findings"] == []
    coverage = json.loads((scan_dir / "coverage.json").read_text(encoding="utf-8"))
    assert coverage["mode"] == coverage_mode
    assert coverage["inventoryStrategy"] == inventory_strategy
    assert coverage["completeness"] == "complete"
    if mode == "diff":
        target = json.loads((scan_dir / "scan-manifest.json").read_text(encoding="utf-8"))["scan"][
            "target"
        ]
        assert target["kind"] == "git_diff"
        assert target["baseRevision"] == base_revision
        assert target["headRevision"] == head_revision
        assert target["snapshotDigest"].startswith("codex-security-snapshot/v1:sha256:")


def test_dependency_artifact_sdk_scan_requires_trusted_environment_marker(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id, _, _ = _start_dependency_artifact_sdk_scan(tmp_path)

    failed = run_workbench(
        state_dir,
        "prepare-scan-completion",
        "--scan-id",
        scan_id,
        check=False,
    )

    assert failed["returncode"] != 0
    assert not (scan_dir / "scan-manifest.json").exists()


def test_dependency_artifact_preauthored_contract_cannot_bypass_reporting_phase(
    tmp_path: Path,
) -> None:
    state_dir, scan_dir, scan_id, _, _ = _start_dependency_artifact_sdk_scan(
        tmp_path, phase="preflight"
    )
    write_completed_contract(
        scan_dir, scan_id, tmp_path / "artifact-repository", relative_path="src/query.py"
    )
    authored_bytes = {
        filename: (scan_dir / filename).read_bytes() for filename in CANONICAL_OUTPUTS
    }

    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
        environment={"CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN": "1"},
    )

    assert failed["returncode"] != 0
    assert "reporting phase" in str(failed["stderr"])
    assert {
        filename: (scan_dir / filename).read_bytes() for filename in CANONICAL_OUTPUTS
    } == authored_bytes
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, completed_at, seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("running", None, None)


def test_dependency_artifact_semantic_finding_preserves_evidence_without_extra_extensions(
    tmp_path: Path,
) -> None:
    candidate = _candidate("dependency-unsafe-install")
    semantic_finding = {
        "ruleId": "supply-chain.unsafe-install-hook",
        "identity": {"anchor": "dependency-unsafe-install", "instance": "postinstall"},
        "title": "Published installation hook executes untrusted input",
        "summary": "The distributed installation hook reaches an unsafe sink.",
        "severity": {"level": "high"},
        "confidence": {"level": "high", "rationale": "The installation hook is executable."},
        "taxonomy": {"category": "supply-chain", "cwe": ["CWE-94"]},
        "locations": [
            {"path": "src/query.py", "startLine": 2, "endLine": 2, "role": "root_control"}
        ],
        "remediation": "Remove the unsafe installation hook.",
        "rootCause": {"summary": "Installation executes an attacker-controlled query."},
        "codeEvidence": [
            {
                "id": "install-hook",
                "label": "Published installation hook",
                "path": "src/query.py",
                "startLine": 2,
                "code": "return connection.execute(query)",
                "explanation": "The package executes its untrusted query.",
            }
        ],
    }
    candidate["validation"]["dependencyFinding"] = semantic_finding
    state_dir, scan_dir, scan_id, _, _ = _start_dependency_artifact_sdk_scan(
        tmp_path, mode="diff", rows=[candidate]
    )

    completed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        environment={"CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN": "1"},
    )

    assert completed["scan"]["findingCount"] == 1
    finding = json.loads((scan_dir / "findings.json").read_text(encoding="utf-8"))["findings"][0]
    assert finding["ruleId"] == semantic_finding["ruleId"]
    assert finding["identity"] == semantic_finding["identity"]
    assert finding["title"] == semantic_finding["title"]
    assert finding["summary"] == semantic_finding["summary"]
    assert finding["severity"]["level"] == semantic_finding["severity"]["level"]
    assert finding["confidence"] == semantic_finding["confidence"]
    assert finding["taxonomy"] == semantic_finding["taxonomy"]
    assert finding["locations"] == semantic_finding["locations"]
    assert finding["codeEvidence"] == semantic_finding["codeEvidence"]
    assert finding["rootCause"] == semantic_finding["rootCause"]
    assert finding["remediation"] == semantic_finding["remediation"]
    assert "dependency" not in finding["extensions"]


@pytest.mark.parametrize("unsafe_path", ("../private-key", "/etc/passwd", "src/../query.py"))
def test_dependency_artifact_semantic_finding_rejects_unsafe_evidence_paths(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    candidate = _candidate("dependency-unsafe-evidence")
    candidate["validation"]["dependencyFinding"] = {
        "codeEvidence": [
            {
                "id": "unsafe-path",
                "label": "Evidence",
                "path": unsafe_path,
                "startLine": 1,
                "code": "unsafe",
                "explanation": "Unsafe evidence path.",
            }
        ]
    }
    state_dir, scan_dir, scan_id, _, _ = _start_dependency_artifact_sdk_scan(
        tmp_path, rows=[candidate]
    )

    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
        environment={"CODEX_SECURITY_DEPENDENCY_ARTIFACT_SCAN": "1"},
    )

    assert failed["returncode"] != 0
    assert "path" in str(failed["stderr"]).lower()
    assert not (scan_dir / "scan-manifest.json").exists()
