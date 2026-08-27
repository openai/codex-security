from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from workbench_test_support import (
    create_saved_workspace,
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    run_workbench,
    source_plugin_version,
    stable_target_id,
    write_completed_contract,
)


def _start_scan_with_draft_findings(tmp_path: Path) -> tuple[Path, str, Path]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    return state_dir, scan_id, scan_dir


def _start_deep_scan_with_draft_findings(tmp_path: Path) -> tuple[Path, str, Path]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(
        state_dir, target, thread_id="thread-completion-binding", mode="deep"
    )
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-completion-binding",
        environment={"CODEX_HOME": str(tmp_path / "codex-home")},
    )
    mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
    write_completed_contract(scan_dir, scan_id, target, coverage_mode="deep_repository")
    return state_dir, scan_id, scan_dir


def register_cli_scan(state_dir: Path, target: Path, scan_dir: Path) -> dict[str, Any]:
    scan_dir.mkdir(mode=0o700)
    return run_workbench(
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
                "target": {"kind": "repository", "paths": []},
            }
        ),
    )


def test_cli_registration_returns_authoritative_target_contract(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"

    for name, dirty in (("clean", False), ("dirty", True)):
        target = tmp_path / name
        revision = initialize_git_repository(target)
        if dirty:
            (target / "README.md").write_text("changed after commit\n")

        scan_dir = tmp_path / f"{name}-scan"
        registered = register_cli_scan(state_dir, target, scan_dir)

        target_contract = registered["contract"]["target"]
        assert target_contract["allowedKinds"] == ["git_worktree" if dirty else "git_revision"]
        assert target_contract["targetId"] == registered["targetId"]
        assert target_contract["displayName"] == name
        assert registered["targetRevision"] == revision
        if dirty:
            with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
                (snapshot_digest,) = connection.execute(
                    "SELECT target_snapshot_digest FROM scans WHERE id = ?",
                    (registered["scanId"],),
                ).fetchone()
            assert target_contract["requiredSnapshotDigest"] == snapshot_digest
        else:
            assert "requiredSnapshotDigest" not in target_contract


def test_prepared_completion_does_not_publish_scan_before_acceptance(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    registered = register_cli_scan(state_dir, target, scan_dir)
    scan_id = str(registered["scanId"])
    write_completed_contract(scan_dir, scan_id, target)

    prepared = run_workbench(
        state_dir,
        "prepare-scan-completion",
        "--scan-id",
        scan_id,
    )

    assert prepared["scan"]["progress"]["status"] == "running"
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]
    assert (scan_dir / "report.md").is_file()
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("running", None)

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, completed_at FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("complete", manifest["scan"]["completedAt"])


def test_rejected_prepared_completion_can_be_marked_failed(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    registered = register_cli_scan(state_dir, target, scan_dir)
    scan_id = str(registered["scanId"])
    write_completed_contract(scan_dir, scan_id, target)
    run_workbench(
        state_dir,
        "prepare-scan-completion",
        "--scan-id",
        scan_id,
    )
    (scan_dir / "findings.json").write_text("corrupted\n")

    failed = run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Sealed scan could not be accepted.",
    )

    assert failed["scan"]["progress"]["status"] == "failed"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("failed",)


def test_cli_completion_accepts_sealed_clean_git_revision_without_snapshot_digest(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    scan_dir = tmp_path / "scan"
    registered = register_cli_scan(state_dir, target, scan_dir)
    scan_id = str(registered["scanId"])
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="README.md",
        target_kind="git_revision",
        target_revision=revision,
    )
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["target"].pop("snapshotDigest")
    manifest_path.write_text(json.dumps(manifest))
    subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve().parent.parent / "scripts" / "finalize_scan_contract.py"),
            "--scan-dir",
            str(scan_dir),
            "--source-root",
            str(target),
        ],
        capture_output=True,
        check=True,
        text=True,
    )

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    sealed_manifest = json.loads(manifest_path.read_text())
    assert sealed_manifest["scan"]["target"]["kind"] == "git_revision"
    assert sealed_manifest["scan"]["target"]["revision"] == revision
    assert "snapshotDigest" not in sealed_manifest["scan"]["target"]


def test_completion_populates_coverage_mode_from_selected_scan_mode(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    cases = [
        ("standard", ".", "repository", "scoped_path"),
        ("standard", "src", "scoped_path", "repository"),
        ("deep", ".", "deep_repository", "repository"),
    ]
    for index, (mode, scope, expected, wrong) in enumerate(cases):
        target = tmp_path / f"target-{index}"
        (target / "src").mkdir(parents=True)
        workspace_id = str(uuid.uuid4())
        run_workbench(
            state_dir,
            "create-workspace",
            "--workspace-id",
            workspace_id,
            "--thread-id",
            "thread-completion-binding",
            "--target-path",
            str(target),
        )
        run_workbench(
            state_dir,
            "save-workspace",
            "--workspace-id",
            workspace_id,
            "--target-path",
            str(target),
            "--scope",
            scope,
            "--mode",
            mode,
        )
        started = run_workbench(
            state_dir,
            "start-scan",
            "--workspace-id",
            workspace_id,
            "--scan-root",
            str(tmp_path / "scans"),
        )
        scan_id = str(started["results"]["scanId"])
        scan_dir = Path(str(started["results"]["scanDir"]))
        if mode == "deep":
            run_workbench(
                state_dir,
                "begin-deep-scan",
                "--scan-id",
                scan_id,
                "--thread-id",
                "thread-completion-binding",
                environment={"CODEX_HOME": str(codex_home)},
            )
            coordinator_manifest = scan_dir / "coordinator-manifest.json"
            coordinator_manifest.write_text("{}\n")
            with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
                connection.execute(
                    """
                    UPDATE deep_scan_runs
                    SET status = 'succeeded', phase = 'terminal',
                        terminal_reason = 'capped', manifest_path = ?,
                        completed_at = updated_at
                    WHERE scan_id = ?
                    """,
                    (str(coordinator_manifest), scan_id),
                )
        write_completed_contract(
            scan_dir,
            scan_id,
            target,
            include_paths=[scope],
            coverage_mode=wrong,
        )
        completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
        assert completed["scan"]["progress"]["status"] == "complete"
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        assert coverage["mode"] == expected


def test_completion_populates_workbench_owned_unsealed_envelope(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["results"]["scanId"])
    scan_dir = Path(str(started["results"]["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    findings = json.loads((scan_dir / "findings.json").read_text())
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    manifest["documentType"] = "wrong.manifest"
    manifest["schemaVersion"] = "wrong"
    manifest["scan"]["id"] = "wrong-scan"
    manifest["scan"]["status"] = "running"
    manifest["scan"]["producer"] = {"name": "wrong-producer", "version": "wrong-version"}
    manifest["scan"]["startedAt"] = "wrong"
    manifest["scan"]["completedAt"] = "wrong"
    manifest["scan"]["coverageRef"] = "wrong-coverage.json"
    manifest["scan"]["findingsRef"] = "wrong-findings.json"
    manifest["scan"]["target"]["targetId"] = "wrong-target"
    manifest["scan"]["target"]["displayName"] = "wrong-name"
    manifest["scan"]["target"]["snapshotDigest"] = (
        "codex-security-snapshot/v1:sha256:"
        "1111111111111111111111111111111111111111111111111111111111111111"
    )
    manifest["scan"]["target"]["baseRevision"] = "stale-base"
    manifest["scan"]["target"]["headRevision"] = "stale-head"
    manifest["scan"]["scope"]["includePaths"] = ["wrong/"]
    manifest["scan"]["scope"]["excludePaths"] = ["wrong/"]
    findings["documentType"] = "wrong.findings"
    findings["schemaVersion"] = "wrong"
    findings["scanId"] = "wrong-scan"
    findings["findings"][0]["findingId"] = "csf_wrong"
    findings["findings"][0]["occurrenceId"] = "occ_wrong"
    findings["findings"][0]["fingerprints"] = {
        "algorithm": "codex-security/v0",
        "primary": "codex-security/v0:sha256:wrong",
    }
    coverage["documentType"] = "wrong.coverage"
    coverage["schemaVersion"] = "wrong"
    coverage["scanId"] = "wrong-scan"
    coverage["mode"] = "scoped_path"
    coverage["includePaths"] = ["wrong/"]
    coverage["excludePaths"] = ["wrong/"]
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    sealed_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    sealed_findings = json.loads((scan_dir / "findings.json").read_text())
    sealed_coverage = json.loads((scan_dir / "coverage.json").read_text())
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        stored_started_at, stored_completed_at = connection.execute(
            "SELECT started_at, completed_at FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    assert sealed_manifest["documentType"] == "codex-security.scan-manifest"
    assert sealed_manifest["schemaVersion"] == "1.0"
    assert sealed_manifest["scan"]["id"] == scan_id
    assert sealed_manifest["scan"]["status"] == "completed"
    assert sealed_manifest["scan"]["producer"] == {
        "name": "codex-security-plugin",
        "version": source_plugin_version(),
    }
    assert sealed_manifest["scan"]["startedAt"] == stored_started_at
    assert sealed_manifest["scan"]["completedAt"] == stored_completed_at
    assert sealed_manifest["scan"]["sealedAt"] == stored_completed_at
    assert sealed_manifest["scan"]["coverageRef"] == "coverage.json"
    assert sealed_manifest["scan"]["findingsRef"] == "findings.json"
    assert sealed_manifest["scan"]["target"]["targetId"] == stable_target_id(target)
    assert sealed_manifest["scan"]["target"]["displayName"] == target.name
    assert "baseRevision" not in sealed_manifest["scan"]["target"]
    assert "headRevision" not in sealed_manifest["scan"]["target"]
    assert sealed_manifest["scan"]["scope"] == {"includePaths": ["."], "excludePaths": []}
    assert sealed_findings["documentType"] == "codex-security.findings"
    assert sealed_findings["schemaVersion"] == "1.0"
    assert sealed_findings["scanId"] == scan_id
    assert sealed_findings["findings"][0]["findingId"].startswith("csf_")
    assert sealed_findings["findings"][0]["occurrenceId"].startswith("occ_")
    assert sealed_findings["findings"][0]["fingerprints"]["algorithm"] == "codex-security/v1"
    assert sealed_coverage["documentType"] == "codex-security.coverage"
    assert sealed_coverage["schemaVersion"] == "1.0"
    assert sealed_coverage["scanId"] == scan_id
    assert sealed_coverage["mode"] == "repository"
    assert sealed_coverage["includePaths"] == ["."]
    assert sealed_coverage["excludePaths"] == []


def test_completion_keeps_invalid_prewrite_drafts_resumable(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    target_kind = manifest["scan"]["target"]["kind"]
    manifest["scan"]["target"]["kind"] = "git_worktree"
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))

    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
    )

    assert failed["returncode"] != 0
    assert "target.kind" in str(failed["stderr"])
    pending = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert pending["progress"]["status"] == "running"
    manifest["scan"]["target"]["kind"] = target_kind
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1


def test_completion_keeps_recoverable_prewrite_failures_resumable(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    inventory_strategy = coverage["inventoryStrategy"]
    coverage["inventoryStrategy"] = ""
    coverage_path.write_text(json.dumps(coverage))

    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
    )

    assert failed["returncode"] != 0
    assert "inventoryStrategy" in str(failed["stderr"])
    pending = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert pending["progress"]["status"] == "running"
    coverage["inventoryStrategy"] = inventory_strategy
    coverage_path.write_text(json.dumps(coverage))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1


def test_deep_completion_recovers_malformed_inventory_without_dropping_findings(
    tmp_path: Path,
) -> None:
    for index, inventory in enumerate((None, "", "invalid_strategy")):
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        state_dir, scan_id, scan_dir = _start_deep_scan_with_draft_findings(case_dir)
        coverage_path = scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        if inventory is None:
            coverage.pop("inventoryStrategy")
        else:
            coverage["inventoryStrategy"] = inventory
        coverage_path.write_text(json.dumps(coverage))

        completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

        assert completed["scan"]["progress"]["status"] == "complete"
        assert completed["scan"]["findingCount"] == 1
        assert completed["scan"]["warnings"] == [
            "Recovered malformed Deep Scan inventory strategy; marked coverage as partial."
        ]
        sealed_coverage = json.loads(coverage_path.read_text())
        assert sealed_coverage["mode"] == "deep_repository"
        assert sealed_coverage["inventoryStrategy"] == "repository"
        assert sealed_coverage["completeness"] == "partial"
        assert len(json.loads((scan_dir / "findings.json").read_text())["findings"]) == 1
        assert (scan_dir / "report.md").is_file()


def test_deep_completion_rejects_invalid_target_even_with_recoverable_inventory(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_deep_scan_with_draft_findings(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["target"]["kind"] = "git_worktree"
    manifest_path.write_text(json.dumps(manifest))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["inventoryStrategy"] = ""
    coverage_path.write_text(json.dumps(coverage))

    failed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id, check=False)

    assert failed["returncode"] != 0
    assert "target.kind" in str(failed["stderr"])
    recorded = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert recorded["progress"]["status"] == "failed"
    preserved_coverage = json.loads(coverage_path.read_text())
    assert preserved_coverage["inventoryStrategy"] == "repository"
    assert preserved_coverage["completeness"] == "partial"
    assert len(json.loads((scan_dir / "findings.json").read_text())["findings"]) == 1


def test_deep_completion_preserves_running_scan_after_transient_report_failure(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_deep_scan_with_draft_findings(tmp_path)
    hook_dir = tmp_path / "report-failure-hook"
    hook_dir.mkdir()
    (hook_dir / "sitecustomize.py").write_text(
        "import importlib.util\n"
        "original_spec = importlib.util.spec_from_file_location\n"
        "def injected_spec(name, *args, **kwargs):\n"
        "    spec = original_spec(name, *args, **kwargs)\n"
        "    if name == 'codex_security_report_projection':\n"
        "        original_load = spec.loader.exec_module\n"
        "        def injected_load(module):\n"
        "            original_load(module)\n"
        "            def unavailable(*args, **kwargs):\n"
        "                raise OSError('fixture report projection temporarily unavailable')\n"
        "            module.generate_report_markdown = unavailable\n"
        "        spec.loader.exec_module = injected_load\n"
        "    return spec\n"
        "importlib.util.spec_from_file_location = injected_spec\n"
    )
    before = {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }

    failed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
        environment={"PYTHONPATH": str(hook_dir)},
    )

    assert failed["returncode"] != 0
    assert "fixture report projection temporarily unavailable" in str(failed["stderr"])
    preserved = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert preserved["progress"]["status"] == "running"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == ("succeeded",)
    assert {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    } == before

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1


def test_deep_completion_retries_transient_report_failure_within_one_invocation(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_deep_scan_with_draft_findings(tmp_path)
    hook_dir = tmp_path / "report-failure-hook"
    hook_dir.mkdir()
    marker_path = hook_dir / "first-projection-attempt"
    (hook_dir / "sitecustomize.py").write_text(
        "import importlib.util\n"
        "from pathlib import Path\n"
        f"marker = Path({str(marker_path)!r})\n"
        "original_spec = importlib.util.spec_from_file_location\n"
        "def injected_spec(name, *args, **kwargs):\n"
        "    spec = original_spec(name, *args, **kwargs)\n"
        "    if name == 'codex_security_report_projection':\n"
        "        original_load = spec.loader.exec_module\n"
        "        def injected_load(module):\n"
        "            original_load(module)\n"
        "            original_report = module.generate_report_markdown\n"
        "            def unavailable_once(*args, **kwargs):\n"
        "                if not marker.exists():\n"
        "                    marker.touch()\n"
        "                    raise OSError('fixture report projection temporarily unavailable')\n"
        "                return original_report(*args, **kwargs)\n"
        "            module.generate_report_markdown = unavailable_once\n"
        "        spec.loader.exec_module = injected_load\n"
        "    return spec\n"
        "importlib.util.spec_from_file_location = injected_spec\n"
    )

    completed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        environment={"PYTHONPATH": str(hook_dir)},
    )

    assert marker_path.is_file()
    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1
    assert (scan_dir / "report.md").is_file()


def test_completion_recovers_malformed_finding_identity(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings = json.loads((scan_dir / "findings.json").read_text())
    findings["findings"][0]["ruleId"] = "Path Traversal: Archive Extraction"
    findings["findings"][0]["identity"]["anchor"] = "Archive Entry Write Without Containment"
    findings["findings"][0]["identity"]["instance"] = "User Input #1"
    (scan_dir / "findings.json").write_text(json.dumps(findings))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1
    assert completed["scan"]["warnings"] == [
        "Recovered finding 1: normalized rule identifier, semantic anchor, instance."
    ]
    sealed_findings = json.loads((scan_dir / "findings.json").read_text())
    assert sealed_findings["findings"][0]["ruleId"] == "path-traversal-archive-extraction"
    assert sealed_findings["findings"][0]["identity"] == {
        "anchor": "archive-entry-write-without-containment",
        "instance": "user-input-1",
    }
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["warnings"]
        == (completed["scan"]["warnings"])
    )


def test_completion_keeps_valid_findings_and_warns_about_bad_ones(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings = json.loads((scan_dir / "findings.json").read_text())
    valid = findings["findings"][0]
    missing_summary = copy.deepcopy(valid)
    missing_summary["identity"]["anchor"] = "missing-summary"
    missing_summary["summary"] = ""
    unsafe_location = copy.deepcopy(valid)
    unsafe_location["identity"]["anchor"] = "unsafe-location"
    unsafe_location["locations"][0]["path"] = "../outside.py"
    missing_identity = copy.deepcopy(valid)
    missing_identity.pop("identity")
    invalid_evidence_id = copy.deepcopy(valid)
    invalid_evidence_id["identity"]["anchor"] = "invalid-evidence-id"
    invalid_evidence_id["codeEvidence"][0]["id"] = "src/extract.py:41"
    invalid_evidence_id["rootCause"] = {
        "summary": "The write occurs before containment is checked.",
        "evidenceRefs": ["src/extract.py:41"],
    }
    findings["findings"].extend(
        [
            missing_summary,
            unsafe_location,
            missing_identity,
            invalid_evidence_id,
            copy.deepcopy(valid),
            None,
        ]
    )
    (scan_dir / "findings.json").write_text(json.dumps(findings))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1
    warnings = completed["scan"]["warnings"]
    assert len(warnings) == 6
    assert all(warning.startswith("Skipped malformed finding") for warning in warnings)
    assert any("summary" in warning for warning in warnings)
    assert any("safe repository-relative" in warning for warning in warnings)
    assert any("identity" in warning for warning in warnings)
    assert any("codeEvidence[0].id" in warning for warning in warnings)
    assert any("duplicate logical finding" in warning for warning in warnings)
    assert any("expected an object" in warning for warning in warnings)
    assert len(json.loads((scan_dir / "findings.json").read_text())["findings"]) == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    assert len(coverage["deferred"]) == 5
    assert (scan_dir / "report.md").is_file()


def test_completion_recovers_unknown_optional_root_cause_evidence_reference(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings_path = scan_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    finding = document["findings"][0]
    evidence_id = finding["codeEvidence"][0]["id"]
    finding["rootCause"] = {
        "summary": "The destination is not constrained to the extraction root.",
        "evidenceRefs": [evidence_id, "missing-evidence"],
    }
    findings_path.write_text(json.dumps(document))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    recovered = json.loads(findings_path.read_text())["findings"][0]
    assert recovered["rootCause"] == {
        "summary": "The destination is not constrained to the extraction root.",
        "evidenceRefs": [evidence_id],
    }
    assert recovered["codeEvidence"] == finding["codeEvidence"]


def test_completion_retains_strongest_duplicate_finding_regardless_of_order(
    tmp_path: Path,
) -> None:
    cases = (
        (
            "severity-ascending",
            (("informational", "high", 1), ("critical", "high", 1)),
            ("critical", "high", 1),
        ),
        (
            "severity-descending",
            (("critical", "high", 1), ("informational", "high", 1)),
            ("critical", "high", 1),
        ),
        (
            "confidence-ascending",
            (("critical", "low", 1), ("critical", "high", 1)),
            ("critical", "high", 1),
        ),
        (
            "confidence-descending",
            (("critical", "high", 1), ("critical", "low", 1)),
            ("critical", "high", 1),
        ),
        (
            "evidence-ascending",
            (("critical", "high", 1), ("critical", "high", 2)),
            ("critical", "high", 2),
        ),
        (
            "evidence-descending",
            (("critical", "high", 2), ("critical", "high", 1)),
            ("critical", "high", 2),
        ),
    )
    for case, candidates, expected in cases:
        case_dir = tmp_path / case
        case_dir.mkdir()
        state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(case_dir)
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        baseline = findings["findings"][0]
        findings["findings"] = []
        for severity, confidence, evidence_count in candidates:
            finding = copy.deepcopy(baseline)
            finding["severity"]["level"] = severity
            finding["confidence"]["level"] = confidence
            if evidence_count == 2:
                evidence = copy.deepcopy(finding["codeEvidence"][0])
                evidence["id"] = "additional-evidence"
                finding["codeEvidence"].append(evidence)
            findings["findings"].append(finding)
        findings_path.write_text(json.dumps(findings))

        completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

        assert completed["scan"]["progress"]["status"] == "complete", case
        assert completed["scan"]["findingCount"] == 1, case
        assert len(completed["scan"]["warnings"]) == 1, case
        assert "duplicate logical finding" in completed["scan"]["warnings"][0], case
        recovered = json.loads(findings_path.read_text())["findings"][0]
        assert (
            recovered["severity"]["level"],
            recovered["confidence"]["level"],
            len(recovered["codeEvidence"]),
        ) == expected, case
        weaker = next(candidate for candidate in candidates if candidate != expected)
        assert any(
            (
                original["severity"]["level"],
                original["confidence"]["level"],
                len(original["codeEvidence"]),
            )
            == weaker
            for original in recovered["provenance"].get("previousFindings", [])
        ), case
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        assert coverage["completeness"] == "complete", case
        assert "### No findings" not in (scan_dir / "report.md").read_text(), case
        sarif = json.loads((scan_dir / "exports/results.sarif").read_text())
        assert sarif["runs"][0]["results"][0]["properties"]["severity"] == "critical", case


def test_completion_preserves_findings_with_invalid_or_duplicate_writeups(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    valid = findings["findings"][0]
    linked_report = "findings/linked-writeup/linked-writeup.md"
    linked_path = scan_dir / linked_report
    linked_path.parent.mkdir(parents=True)
    linked_path.write_text("# Verified finding\n")
    symlink_report = "findings/symlink-writeup/symlink-writeup.md"
    symlink_path = scan_dir / symlink_report
    symlink_path.parent.mkdir(parents=True)
    symlink_path.symlink_to(linked_path)

    for anchor, writeup in (
        ("linked-writeup", {"reportPath": linked_report}),
        ("duplicate-writeup", {"reportPath": linked_report}),
        ("missing-writeup", {"reportPath": "findings/missing-writeup/missing-writeup.md"}),
        ("symlink-writeup", {"reportPath": symlink_report}),
        ("unsafe-writeup", {"reportPath": "../outside.md"}),
        ("invalid-writeup", "not an object"),
    ):
        finding = copy.deepcopy(valid)
        finding["identity"]["anchor"] = anchor
        finding["writeup"] = writeup
        findings["findings"].append(finding)
    findings_path.write_text(json.dumps(findings))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 7
    warnings = completed["scan"]["warnings"]
    assert len(warnings) == 5
    assert all(warning.startswith("Skipped malformed writeup for finding") for warning in warnings)
    assert any("duplicate report path" in warning for warning in warnings)
    assert any("inside the scan directory" in warning for warning in warnings)
    assert any("non-symlink" in warning for warning in warnings)
    assert any("schema pattern" in warning for warning in warnings)
    assert any("schema type" in warning for warning in warnings)
    assert "../outside.md" not in " ".join(warnings)
    recovered = {
        finding["identity"]["anchor"]: finding
        for finding in json.loads(findings_path.read_text())["findings"]
    }
    assert recovered["linked-writeup"]["writeup"] == {"reportPath": linked_report}
    for anchor in (
        "duplicate-writeup",
        "missing-writeup",
        "symlink-writeup",
        "unsafe-writeup",
        "invalid-writeup",
    ):
        assert "writeup" not in recovered[anchor]
    assert (scan_dir / "report.md").is_file()


def test_valid_checkpoint_survives_malformed_replacement_finding(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings = json.loads((scan_dir / "findings.json").read_text())
    checkpoint = {
        "scanId": scan_id,
        "findings": copy.deepcopy(findings["findings"]),
        "coverage": json.loads((scan_dir / "coverage.json").read_text()),
    }
    (scan_dir / "checkpoints").mkdir()
    (scan_dir / "checkpoints" / ("a" * 64 + ".json")).write_text(json.dumps(checkpoint))
    findings["findings"][0]["summary"] = ""
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["findingCount"] == 1
    assert completed["findings"][0]["summary"] == checkpoint["findings"][0]["summary"]


def test_duplicate_finding_with_malformed_history_does_not_block_valid_results(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    path = scan_dir / "findings.json"
    document = json.loads(path.read_text())
    weak = document["findings"][0]
    weak["provenance"]["previousFindings"] = None
    strong = copy.deepcopy(weak)
    strong["severity"]["level"] = "critical"
    strong["provenance"]["previousFindings"] = "malformed optional history"
    document["findings"].append(strong)
    path.write_text(json.dumps(document))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["findingCount"] == 1
    finding = json.loads(path.read_text())["findings"][0]
    assert finding["severity"]["level"] == "critical"
    assert any(
        original["severity"]["level"] == "high"
        for original in finding["provenance"]["previousFindings"]
    )


def test_completion_succeeds_when_all_findings_are_malformed(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings = json.loads((scan_dir / "findings.json").read_text())
    findings["findings"][0]["summary"] = ""
    (scan_dir / "findings.json").write_text(json.dumps(findings))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 0
    assert len(completed["scan"]["warnings"]) == 1
    assert "summary" in completed["scan"]["warnings"][0]
    assert json.loads((scan_dir / "findings.json").read_text())["findings"] == []
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    assert coverage["deferred"] == [
        {
            "id": "discarded-finding-1",
            "reason": completed["scan"]["warnings"][0],
        }
    ]
    report = (scan_dir / "report.md").read_text()
    assert "| Coverage | partial |" in report
    assert "Skipped malformed finding 1" in report
    sarif = json.loads((scan_dir / "exports/results.sarif").read_text())
    run = sarif["runs"][0]
    assert run["properties"]["codexSecurityCoverageCompleteness"] == "partial"
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["toolExecutionNotifications"] == [
        {
            "level": "warning",
            "message": {"text": completed["scan"]["warnings"][0]},
        }
    ]


def test_completion_recovers_lone_surrogate_in_malformed_finding(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"][0]["severity"]["changeConditions"] = ["\ud800"]
    findings_path.write_text(json.dumps(findings))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 0
    assert "severity.changeConditions" in completed["scan"]["warnings"][0]


def test_completion_keeps_verified_receipts_and_downgrades_invalid_coverage(
    tmp_path: Path,
) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    receipt_ref = "artifacts/02_discovery/work_ledger.jsonl"
    receipt_path = scan_dir / receipt_ref
    receipt_path.parent.mkdir(parents=True)
    receipt_path.write_text('{"status":"reviewed"}\n')
    symlink_ref = "artifacts/02_discovery/aliased_work_ledger.jsonl"
    (scan_dir / symlink_ref).symlink_to(receipt_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"][0]["receiptRefs"] = [
        receipt_ref,
        "report.md",
        "../outside.json",
        "artifacts/02_discovery/missing.jsonl",
        None,
        symlink_ref,
    ]
    coverage_path.write_text(json.dumps(coverage))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1
    warnings = completed["scan"]["warnings"]
    assert len(warnings) == 5
    assert all(warning.startswith("Skipped malformed coverage receipt") for warning in warnings)
    assert any("under artifacts/" in warning for warning in warnings)
    assert any("safe repository-relative" in warning for warning in warnings)
    assert any("inside the scan directory" in warning for warning in warnings)
    assert any("expected a string" in warning for warning in warnings)
    assert any("non-symlink" in warning for warning in warnings)
    assert "../outside.json" not in " ".join(warnings)
    sealed_coverage = json.loads(coverage_path.read_text())
    assert sealed_coverage["completeness"] == "partial"
    assert sealed_coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    assert sealed_coverage["surfaces"][0]["receiptRefs"] == [receipt_ref]
    sealed_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert receipt_ref in {artifact["path"] for artifact in sealed_manifest["scan"]["artifacts"]}
    assert run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["warnings"] == (
        warnings
    )
    assert (scan_dir / "report.md").is_file()


def test_completion_recovers_malformed_coverage_rows(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    surface = coverage["surfaces"][0]
    surface["disposition"] = "checked"
    coverage["surfaces"].extend(
        [
            copy.deepcopy(surface),
            None,
            {
                "id": "surface_invalid_risk_area",
                "label": "Invalid risk area",
                "disposition": "reported",
                "receiptRefs": [],
                "riskArea": "",
            },
        ]
    )
    coverage["explicitExclusions"] = [
        {"pattern": "docs/", "reason": "Documentation only."},
        {"pattern": "vendor/"},
    ]
    coverage["deferred"] = [
        {
            "id": "deferred_archive_review",
            "reason": "Archive extraction requires a follow-up review.",
            "surfaceIds": [surface["id"]],
        },
        {"id": "deferred_missing_reason"},
    ]
    coverage_path.write_text(json.dumps(coverage))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1
    warnings = completed["scan"]["warnings"]
    assert any("review disposition could not be verified" in warning for warning in warnings)
    assert any("duplicate surface id" in warning for warning in warnings)
    assert any("expected an object" in warning for warning in warnings)
    assert any("riskArea" in warning for warning in warnings)
    assert any("coverage exclusion" in warning for warning in warnings)
    assert any("deferred coverage item" in warning for warning in warnings)
    assert any("deferred review work" in warning for warning in warnings)
    sealed_coverage = json.loads(coverage_path.read_text())
    assert sealed_coverage["completeness"] == "partial"
    assert len(sealed_coverage["surfaces"]) == 1
    assert sealed_coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    assert sealed_coverage["explicitExclusions"] == [
        {"pattern": "docs/", "reason": "Documentation only."}
    ]
    assert sealed_coverage["deferred"] == [
        {
            "id": "deferred_archive_review",
            "reason": "Archive extraction requires a follow-up review.",
            "surfaceIds": [surface["id"]],
        }
    ]


def test_completion_recovers_malformed_coverage_collections(tmp_path: Path) -> None:
    state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(tmp_path)
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["completeness"] = "finished"
    coverage["surfaces"] = {"id": "not-an-array"}
    coverage["explicitExclusions"] = None
    coverage["deferred"] = "later"
    coverage_path.write_text(json.dumps(coverage))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["findingCount"] == 1
    assert len(completed["scan"]["warnings"]) == 4
    sealed_coverage = json.loads(coverage_path.read_text())
    assert sealed_coverage["completeness"] == "partial"
    assert sealed_coverage["surfaces"] == []
    assert sealed_coverage["explicitExclusions"] == []
    assert sealed_coverage["deferred"] == []
    assert (scan_dir / "report.md").is_file()


def test_completion_recovers_malformed_hardening_portfolios(tmp_path: Path) -> None:
    for case, hardening in (
        ("invalid-object", "not an object"),
        ("unsafe-path", {"portfolioPath": "../outside.md"}),
        ("missing-file", {"portfolioPath": "hardening/hardening.md"}),
        ("symlink", {"portfolioPath": "hardening/hardening.md"}),
    ):
        case_dir = tmp_path / case
        case_dir.mkdir()
        state_dir, scan_id, scan_dir = _start_scan_with_draft_findings(case_dir)
        manifest_path = scan_dir / "scan-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["scan"]["hardening"] = hardening
        manifest_path.write_text(json.dumps(manifest))
        if case == "symlink":
            portfolio = scan_dir / "hardening/hardening.md"
            portfolio.parent.mkdir(parents=True)
            portfolio.symlink_to(scan_dir / "report.md")

        completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)

        assert completed["scan"]["progress"]["status"] == "complete", case
        assert completed["scan"]["findingCount"] == 1, case
        warnings = completed["scan"]["warnings"]
        assert len(warnings) == 1, case
        assert warnings[0].startswith("Skipped malformed hardening portfolio:"), case
        assert "../outside.md" not in warnings[0], case
        assert "hardening" not in json.loads(manifest_path.read_text())["scan"], case
        assert (scan_dir / "report.md").is_file(), case
