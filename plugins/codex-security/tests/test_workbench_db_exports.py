from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    create_saved_git_workspace,
    create_saved_workspace,
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
def test_stopped_scan_keeps_saved_findings_and_exports(tmp_path: Path, termination: str) -> None:
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
    )["results"]
    scan_id = str(started["scanId"])
    scan_dir = Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    extra = (
        ("--message", "Stopped after recording a finding.") if termination == "fail-scan" else ()
    )
    run_workbench(state_dir, termination, "--scan-id", scan_id, *extra)

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    expected_status = "failed" if termination == "fail-scan" else "canceled"
    assert stopped["progress"]["status"] == expected_status
    assert stopped["findingCount"] == 1
    assert stopped["findings"][0]["ruleId"] == "path-traversal.archive-extraction"
    assert stopped["reportAvailable"] is True
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"]
        == expected_status
    )
    assert json.loads((scan_dir / "coverage.json").read_text())["completeness"] == "partial"
    for export_format in ("json", "csv", "sarif"):
        exported = run_workbench(
            state_dir,
            "export-findings",
            "--scan-id",
            scan_id,
            "--format",
            export_format,
        )
        assert Path(str(exported["export"]["path"])).is_file()
        assert exported["scan"]["progress"]["status"] == expected_status
    sarif = json.loads((scan_dir / "exports" / "results.sarif").read_text())
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False

    original = (scan_dir / "scan-manifest.json").read_bytes()
    (scan_dir / "scan-manifest.json").write_bytes(original + b" ")
    rejected = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "json",
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "sealed scan manifest changed" in str(rejected["stderr"])


def test_late_parent_draft_is_retained_without_mutating_frozen_stopped_seal(
    tmp_path: Path,
) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    documents = {
        key: json.loads((scan_dir / filename).read_text())
        for key, filename in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    documents["findings"]["findings"][0]["identity"]["anchor"] = "late-independent-finding"
    documents["coverage"]["completeness"] = "partial"
    documents["coverage"]["deferred"] = [
        {"id": "late-review", "reason": "This review completed after cancellation."}
    ]
    payload = {
        "scanId": scan_id,
        "complete": False,
        "findings": documents["findings"]["findings"],
        "coverage": documents["coverage"],
    }
    checkpoint_path = write_checkpoint(scan_dir / "checkpoints", payload)
    drafts = scan_dir / "drafts"
    drafts.mkdir()
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))
    rejected = run_workbench(
        state_dir,
        "write-scan-draft",
        "--scan-id",
        scan_id,
        "--draft-path",
        str(staged),
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "saved checkpoint" in str(rejected["stderr"])
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal
    assert checkpoint_path.read_bytes() == json.dumps(payload).encode()
    recovered = run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)["scan"]
    assert recovered["findingCount"] == 2
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert any(item.get("id") == "late-review" for item in coverage["deferred"])
    assert recovered["progress"]["status"] == "failed"
    assert recovered["progress"]["updatedAt"] > stopped["progress"]["updatedAt"]
    assert recovered["updatedAt"] > stopped["updatedAt"]
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["completedAt"]
        == json.loads(seal)["scan"]["completedAt"]
    )
    unchanged = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert unchanged["progress"]["updatedAt"] == recovered["progress"]["updatedAt"]
    assert unchanged["updatedAt"] == recovered["updatedAt"]


def test_canceled_scan_does_not_accept_checkpoints_written_after_cancellation(
    tmp_path: Path,
) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)

    run_workbench(state_dir, "cancel-scan", "--scan-id", scan_id)
    canceled = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    sealed_manifest = (scan_dir / "scan-manifest.json").read_bytes()
    late_finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    late_finding["identity"]["anchor"] = "late-after-cancellation"
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [late_finding],
        "coverage": {"completeness": "partial", "surfaces": []},
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)

    unchanged = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert canceled["progress"]["status"] == "canceled"
    assert unchanged["findingCount"] == canceled["findingCount"] == 1
    assert (scan_dir / "scan-manifest.json").read_bytes() == sealed_manifest
    assert unchanged["updatedAt"] == canceled["updatedAt"]


def test_stopped_clean_git_checkpoint_uses_revision_target(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    saved = create_saved_git_workspace(state_dir, target)
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_snapshot_digest = NULL WHERE id = ?", (scan_id,)
        )
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [{"id": "pending-review", "reason": "Review stopped early."}],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["kind"] == "git_revision"
    assert manifest["scan"]["target"]["revision"] == revision
    assert "snapshotDigest" not in manifest["scan"]["target"]


@pytest.mark.parametrize(
    ("diff_kind", "coverage_mode"), (("commit", "commit"), ("range", "branch_diff"))
)
def test_stopped_diff_checkpoint_uses_canonical_snapshot_digest(
    tmp_path: Path, diff_kind: str, coverage_mode: str
) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    base_revision, head_revision = "base-revision", "head-revision"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            UPDATE scans
            SET mode = 'diff', diff_target_kind = ?, diff_base_revision = ?,
                diff_head_revision = ?, diff_content_digest = NULL,
                target_snapshot_digest = NULL
            WHERE id = ?
            """,
            (diff_kind, base_revision, head_revision, scan_id),
        )
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [{"id": "pending-review", "reason": "Review stopped early."}],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)

    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")

    target_contract = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["target"]
    expected = hashlib.sha256(
        b"codex-security-diff/v1\0"
        + diff_kind.encode()
        + b"\0"
        + base_revision.encode()
        + b"\0"
        + head_revision.encode()
    ).hexdigest()
    assert target_contract["kind"] == "git_diff"
    assert target_contract["snapshotDigest"] == (f"codex-security-snapshot/v1:sha256:{expected}")
    assert json.loads((scan_dir / "coverage.json").read_text())["mode"] == coverage_mode


def test_frozen_stopped_results_ignore_late_index_field_changes(tmp_path: Path) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    original = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["findings"][0]
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        str(original["occurrenceId"]),
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Retain this review decision across checkpoint refreshes.",
    )
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    finding.update(
        title="Critical archive extraction escapes the output directory",
        summary="A strengthened late checkpoint confirms attacker-controlled arbitrary file writes.",
        remediation="Resolve and verify every archive destination before opening the output file.",
    )
    finding["severity"] = {
        "level": "critical",
        "rationale": "The late validation confirmed arbitrary file replacement.",
    }
    finding["locations"][0]["role"] = "root_control"
    finding["codeEvidence"].append(
        {
            "id": "late-validation",
            "label": "Late validation",
            "path": finding["locations"][0]["path"],
            "startLine": 41,
            "endLine": 44,
            "language": "python",
            "code": "destination.write_bytes(entry.read())",
            "explanation": "The late replay confirms the attacker controls the final destination.",
        }
    )
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": json.loads((scan_dir / "coverage.json").read_text()),
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)

    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert refreshed["findingCount"] == 1
    updated = refreshed["findings"][0]
    assert updated["occurrenceId"] == original["occurrenceId"]
    assert updated["title"] == original["title"]
    assert updated["summary"] == original["summary"]
    assert updated["severity"] == original["severity"]
    assert updated["remediation"] == original["remediation"]
    assert updated["locations"] == original["locations"]
    assert updated["triage"]["closeReason"] == "wont_fix"
    assert updated["triage"]["note"] == ("Retain this review decision across checkpoint refreshes.")
    assert updated["triage"]["status"] == "closed"
    exported = run_workbench(state_dir, "export-findings", "--scan-id", scan_id, "--format", "csv")[
        "export"
    ]
    with Path(str(exported["path"])).open(newline="") as source:
        row = next(csv.DictReader(source))
    assert row["title"] == original["title"]
    assert row["summary"] == original["summary"]
    assert row["severity"] == original["severity"]["level"]
    assert row["remediation"] == original["remediation"]
    assert row["status"] == "closed"
    assert row["close_reason"] == "wont_fix"


def test_frozen_stopped_results_skip_late_checkpoint_reindexing(tmp_path: Path) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    finding["identity"]["anchor"] = "late-independent-finding"
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": json.loads((scan_dir / "coverage.json").read_text()),
    }
    checkpoint_path = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    output_paths = (
        "findings.json",
        "coverage.json",
        "scan-manifest.json",
        "report.md",
        "report.html",
        "exports/results.sarif",
    )
    before = {
        relative: (scan_dir / relative).read_bytes() if (scan_dir / relative).exists() else None
        for relative in output_paths
    }
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        digest_before = connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_index.py"
    wrapper.write_text(
        "import sys\n"
        "from dataclasses import replace\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "def fail_index(*args, **kwargs):\n"
        "    raise RuntimeError('injected indexing failure')\n"
        "workbench_db._WORKBENCH_DB_CONTEXT = replace(\n"
        "    workbench_db._WORKBENCH_DB_CONTEXT, index_findings=fail_index\n"
        ")\n"
        "raise SystemExit(workbench_db.main())\n"
    )

    preserved = subprocess.run(
        [sys.executable, str(wrapper), "preserve-scan-results", "--scan-id", scan_id],
        capture_output=True,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
        text=True,
    )

    assert preserved.returncode == 0, preserved.stderr
    assert "injected indexing failure" not in preserved.stderr
    for relative, contents in before.items():
        path = scan_dir / relative
        assert (path.read_bytes() if path.exists() else None) == contents
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
            == digest_before
        )
    assert checkpoint_path.exists()
    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert refreshed["findingCount"] == 1
    assert refreshed["reportAvailable"] is True


def test_frozen_stopped_results_ignore_late_foreign_checkpoint_warning(tmp_path: Path) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    foreign = {
        "scanId": str(uuid.uuid4()),
        "complete": False,
        "findings": [],
        "coverage": {"completeness": "partial"},
    }
    write_checkpoint(scan_dir / "checkpoints", foreign)

    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert all("belongs to a different scan" not in warning for warning in refreshed["warnings"])
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["warnings"]
        == (refreshed["warnings"])
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal


@pytest.mark.parametrize("disposition", ["reported", "rejected", "provenance-reported"])
def test_final_candidate_disposition_supersedes_pending_checkpoint(
    tmp_path: Path, disposition: str
) -> None:
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
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    pending = {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [{"candidateId": "candidate-x", "reason": "Validation is pending."}],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", pending)
    findings = json.loads((scan_dir / "findings.json").read_text())
    if disposition == "provenance-reported":
        findings["findings"][0]["provenance"]["candidateId"] = "candidate-x"
    elif disposition == "reported":
        findings["findings"][0]["extensions"] = {"candidateId": "candidate-x"}
    else:
        findings["findings"] = []
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    disposition = disposition.removeprefix("provenance-")
    coverage["surfaces"][0].update(
        candidateId="candidate-x", disposition=disposition, notes="Final source review disposition."
    )
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    final_coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert completed["progress"]["status"] == "complete"
    assert final_coverage["completeness"] == "complete"
    assert not any(item.get("candidateId") == "candidate-x" for item in final_coverage["deferred"])
    assert any(
        item.get("candidateId") == "candidate-x" and item["disposition"] == disposition
        for item in final_coverage["surfaces"]
    )


def test_incomplete_parent_checkpoint_cannot_complete_scan(tmp_path: Path) -> None:
    state_dir, target = tmp_path / "state", tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    started = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )["results"]
    scan_id, scan_dir = str(started["scanId"]), Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    manifest["scan"]["complete"] = False
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    rejected = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id, check=False)
    assert rejected["returncode"] != 0
    assert "incomplete" in str(rejected["stderr"]).lower()
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["progress"]["status"]
        == "running"
    )


def test_completed_findings_export_inside_scan_directory(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "src/extract.py"
    source.parent.mkdir()
    source.write_text("".join(f"line {line}\n" for line in range(1, 46)))
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
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["artifacts"]["sarifReport"] == str(scan_dir / "exports" / "results.sarif")
    sarif_path = scan_dir / "exports" / "results.sarif"
    sealed_sarif = sarif_path.read_bytes()
    source.write_text("".join(f"changed line {line}\n" for line in range(1, 46)))
    sarif_path.write_text("{}")

    sarif_exported = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "sarif",
    )
    assert sarif_exported["export"] == {"format": "sarif", "path": str(sarif_path)}
    assert sarif_path.read_bytes() == sealed_sarif

    exported = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
    )
    csv_path = scan_dir / "exports" / "findings.csv"
    assert exported["export"] == {"format": "csv", "path": str(csv_path)}
    assert csv_path.read_text().startswith("occurrence_id,finding_id,title,summary")

    json_exported = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "json",
    )
    assert json_exported["export"] == {
        "format": "json",
        "path": str(scan_dir / "findings.json"),
    }
    manifest_path = scan_dir / "scan-manifest.json"
    sealed_manifest_bytes = manifest_path.read_bytes()
    mutated_manifest = json.loads(sealed_manifest_bytes)
    mutated_manifest["scan"]["target"]["displayName"] = "forged-target"
    manifest_path.write_text(json.dumps(mutated_manifest))
    repeated_completion = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan_id,
        check=False,
    )
    assert "sealed scan manifest changed after completion" in str(repeated_completion["stderr"])
    assert sarif_path.read_bytes() == sealed_sarif
    mutated_export = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "json",
        check=False,
    )
    assert "sealed scan manifest changed after completion" in str(mutated_export["stderr"])
    assert sarif_path.read_bytes() == sealed_sarif
    manifest_path.write_bytes(sealed_manifest_bytes)
    findings_path = scan_dir / "findings.json"
    sealed_findings_bytes = findings_path.read_bytes()
    mutated_findings = json.loads(sealed_findings_bytes)
    mutated_findings["findings"][0]["summary"] = "Coordinated post-completion rewrite"
    mutated_findings_bytes = json.dumps(mutated_findings).encode()
    findings_path.write_bytes(mutated_findings_bytes)
    coordinated_manifest = json.loads(manifest_path.read_text())
    for artifact in coordinated_manifest["scan"]["artifacts"]:
        if artifact["path"] == "findings.json":
            artifact["sha256"] = hashlib.sha256(mutated_findings_bytes).hexdigest()
    manifest_path.write_text(json.dumps(coordinated_manifest))
    coordinated_export = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "json",
        check=False,
    )
    assert "sealed scan manifest changed after completion" in str(coordinated_export["stderr"])
    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert refreshed["scan"]["findings"][0]["summary"] != ("Coordinated post-completion rewrite")
    findings_path.write_bytes(sealed_findings_bytes)
    manifest_path.write_bytes(sealed_manifest_bytes)
    findings_path.write_text("{}")
    tampered_json = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "json",
        check=False,
    )
    assert "sealed artifact changed" in str(tampered_json["stderr"])


@pytest.mark.parametrize(
    ("extensions", "expected_candidate_id"),
    (
        ({"candidateId": "DSS-145", "reportId": "DSS-145-rogue"}, "DSS-145"),
        ({"candidateId": " ", "reportId": "DSS-145"}, "DSS-145"),
        ({"reportId": "DSS-145", "ledgerRowId": "DSS-145-rogue"}, "DSS-145"),
        ({"ledgerRowId": "DSS-145"}, "DSS-145"),
    ),
    ids=("candidate-id", "blank-candidate-id", "report-id", "ledger-row-id"),
)
def test_deep_csv_export_adds_only_candidate_id_column(
    tmp_path: Path, extensions: dict[str, str], expected_candidate_id: str
) -> None:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    workspace_id = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "create-workspace",
        "--workspace-id",
        workspace_id,
        "--thread-id",
        "thread-deep-export",
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
        ".",
        "--mode",
        "deep",
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
    run_workbench(
        state_dir,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-deep-export",
        environment={"CODEX_HOME": str(codex_home)},
    )
    mark_deep_coordinator_succeeded(state_dir, scan_id, scan_dir)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        coverage_mode="deep_repository",
    )
    findings_path = scan_dir / "findings.json"
    findings_document = json.loads(findings_path.read_text())
    finding = findings_document["findings"][0]
    original_title = "Unsafe archive extraction [DSS-145-rogue]"
    finding["title"] = original_title
    finding["extensions"] = extensions
    findings_path.write_text(json.dumps(findings_document))

    run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    exported = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
    )["export"]
    with Path(exported["path"]).open(newline="") as source:
        reader = csv.DictReader(source)
        rows = list(reader)

    assert reader.fieldnames == [
        "occurrence_id",
        "finding_id",
        "candidate_id",
        "title",
        "summary",
        "severity",
        "confidence",
        "status",
        "close_reason",
        "note",
        "remediation",
        "path",
        "start_line",
        "end_line",
    ]
    assert len(rows) == 1
    assert rows[0]["candidate_id"] == expected_candidate_id
    assert rows[0]["title"] == original_title
    assert "report_id" not in rows[0]
    assert "detailed_writeup" not in rows[0]


def test_csv_export_escapes_newline_and_full_width_formula_prefixes(tmp_path: Path) -> None:
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
    findings_path = scan_dir / "findings.json"
    findings_document = json.loads(findings_path.read_text())
    finding = findings_document["findings"][0]
    finding["title"] = "\n=1+1"
    finding["summary"] = "＝1+1"
    finding["remediation"] = " \t＋1+1"
    findings_path.write_text(json.dumps(findings_document))

    run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    exported = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
    )["export"]
    with Path(exported["path"]).open(newline="") as source:
        row = next(csv.DictReader(source))

    assert row["title"] == "'\n=1+1"
    assert row["summary"] == "'＝1+1"
    assert row["remediation"] == "' \t＋1+1"


def test_completed_findings_are_returned_in_bounded_pages(tmp_path: Path) -> None:
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
    findings_path = scan_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    template = document["findings"][0]
    document["findings"] = [
        {
            **template,
            "identity": {"anchor": f"archive-entry-write-without-containment-{index:03d}"},
            "title": f"Unsafe archive extraction finding {index:03d}",
        }
        for index in range(75)
    ]
    findings_path.write_text(json.dumps(document))
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["findingCount"] == 75
    assert completed["findingsTruncated"] is True
    assert len(completed["findings"]) == 20
    embedded_occurrence_ids = {finding["occurrenceId"] for finding in completed["findings"]}
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        rows = connection.execute(
            "SELECT id, details_json FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
        ).fetchall()
        off_prefix_occurrence_id = next(
            occurrence_id
            for occurrence_id, _ in rows
            if occurrence_id not in embedded_occurrence_ids
        )
        for index, (occurrence_id, details_json) in enumerate(rows):
            details = json.loads(details_json)
            details["evidenceExcerpt"] = "x" * 300_000
            if index == 0:
                details["attackPath"] = {
                    f"outer-{outer:02d}-{'x' * 120}": {
                        f"middle-{middle:02d}-{'x' * 120}": {
                            f"inner-{inner:02d}-{'x' * 120}": {
                                f"leaf-{leaf:02d}-{'x' * 120}": leaf for leaf in range(20)
                            }
                            for inner in range(20)
                        }
                        for middle in range(20)
                    }
                    for outer in range(20)
                }
            connection.execute(
                """
                UPDATE finding_occurrences
                SET details_json = ?, title = ?, summary = ?, remediation = ?,
                    severity = ?, confidence = ?
                WHERE id = ?
                """,
                (
                    json.dumps(details),
                    "t" * 100_000,
                    "s" * 100_000,
                    "r" * 100_000,
                    "v" * 100_000,
                    "c" * 100_000,
                    occurrence_id,
                ),
            )
            connection.execute(
                "UPDATE finding_locations SET relative_path = ?, role = ? WHERE occurrence_id = ?",
                ("p" * 100_000, "o" * 100_000, occurrence_id),
            )
    selected = run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        "--occurrence-id",
        off_prefix_occurrence_id,
    )["scan"]
    assert any(
        finding["occurrenceId"] == off_prefix_occurrence_id for finding in selected["findings"]
    )
    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert len(json.dumps(refreshed)) < 4 * 1024 * 1024
    finding = refreshed["scan"]["findings"][0]
    assert len(finding["evidenceExcerpt"].encode()) <= 8_000
    assert len(finding["title"].encode()) <= 512
    assert len(finding["summary"].encode()) <= 2_000
    assert len(finding["remediation"].encode()) <= 2_000
    assert len(finding["severity"]["level"].encode()) <= 128
    assert len(finding["confidence"]["level"].encode()) <= 128
    assert len(finding["locations"][0]["path"].encode()) <= 2_048
    assert len(finding["locations"][0]["role"].encode()) <= 128
    assert len(finding["locations"][0]["absolutePath"].encode()) <= 4_096
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE finding_locations SET role = NULL WHERE occurrence_id = ?",
            (finding["occurrenceId"],),
        )
    roleless = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)
    assert roleless["scan"]["findings"][0]["locations"][0]["role"] is None
    second_page = run_workbench(
        state_dir,
        "list-findings",
        "--scan-id",
        scan_id,
        "--offset",
        "20",
        "--limit",
        "50",
    )["findingsPage"]
    assert len(json.dumps(second_page)) < 4 * 1024 * 1024
    assert second_page["offset"] == 20
    assert second_page["nextOffset"] == 40
    assert second_page["total"] == 75
    assert len(second_page["findings"]) == 20


def test_embedded_and_paged_findings_normalize_scalar_attack_path_assessments(
    tmp_path: Path,
) -> None:
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
    findings_path = scan_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    template = document["findings"][0]
    document["findings"] = [
        {
            **template,
            "identity": {"anchor": f"attack-path-assessment-{index:02d}"},
            "title": f"Attack path assessment finding {index:02d}",
        }
        for index in range(22)
    ]
    embedded_finding = document["findings"][0]
    embedded_finding["severity"] = {**template["severity"], "level": "critical"}
    embedded_finding["attackPath"] = {
        **template["attackPath"],
        "impact": "high",
        "likelihood": "medium",
    }
    structured_finding = document["findings"][1]
    absent_finding = document["findings"][2]
    absent_finding["attackPath"] = {
        key: value
        for key, value in template["attackPath"].items()
        if key not in {"impact", "likelihood"}
    }
    paged_finding = document["findings"][-1]
    paged_finding["severity"] = {**template["severity"], "level": "low"}
    paged_finding["attackPath"] = {
        **template["attackPath"],
        "impact": "medium",
        "likelihood": "low",
    }
    findings_path.write_text(json.dumps(document))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["findingCount"] == 22
    assert completed["findingsTruncated"] is True
    assert len(completed["findings"]) == 20
    returned_embedded_finding = next(
        finding
        for finding in completed["findings"]
        if finding["title"] == embedded_finding["title"]
    )
    assert returned_embedded_finding["attackPath"]["impact"] == {"level": "high"}
    assert returned_embedded_finding["attackPath"]["likelihood"] == {"level": "medium"}

    refreshed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    refreshed_embedded_finding = next(
        finding
        for finding in refreshed["findings"]
        if finding["title"] == embedded_finding["title"]
    )
    assert refreshed_embedded_finding["attackPath"]["impact"] == {"level": "high"}
    assert refreshed_embedded_finding["attackPath"]["likelihood"] == {"level": "medium"}

    second_page = run_workbench(
        state_dir,
        "list-findings",
        "--scan-id",
        scan_id,
        "--offset",
        "20",
        "--limit",
        "50",
    )["findingsPage"]
    assert second_page["offset"] == 20
    assert second_page["nextOffset"] is None
    assert second_page["total"] == 22
    assert len(second_page["findings"]) == 2
    returned_findings = {
        finding["title"]: finding for finding in [*completed["findings"], *second_page["findings"]]
    }
    assert returned_findings[paged_finding["title"]]["attackPath"]["impact"] == {"level": "medium"}
    assert returned_findings[paged_finding["title"]]["attackPath"]["likelihood"] == {"level": "low"}
    assert (
        returned_findings[structured_finding["title"]]["attackPath"]["impact"]
        == (template["attackPath"]["impact"])
    )
    assert (
        returned_findings[structured_finding["title"]]["attackPath"]["likelihood"]
        == (template["attackPath"]["likelihood"])
    )
    assert "impact" not in returned_findings[absent_finding["title"]]["attackPath"]
    assert "likelihood" not in returned_findings[absent_finding["title"]]["attackPath"]

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        stored_findings = {
            title: json.loads(details_json)
            for title, details_json in connection.execute(
                "SELECT title, details_json FROM finding_occurrences WHERE scan_id = ?", (scan_id,)
            )
        }
    assert stored_findings[embedded_finding["title"]]["attackPath"]["impact"] == "high"
    assert stored_findings[embedded_finding["title"]]["attackPath"]["likelihood"] == "medium"
    assert stored_findings[paged_finding["title"]]["attackPath"]["impact"] == "medium"
    assert stored_findings[paged_finding["title"]]["attackPath"]["likelihood"] == "low"
    canonical_findings = {
        finding["title"]: finding for finding in json.loads(findings_path.read_text())["findings"]
    }
    assert canonical_findings[embedded_finding["title"]]["attackPath"]["impact"] == "high"
    assert canonical_findings[paged_finding["title"]]["attackPath"]["likelihood"] == "low"


def test_primary_location_prefers_root_control_in_bounded_and_csv_results(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    for index in range(9):
        (target / f"support-{index}.py").write_text("support\n")
    (target / "root.py").write_text("vulnerable\n")
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
    findings_path = scan_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    document["findings"][0]["locations"] = [
        {
            "path": f"support-{index}.py",
            "startLine": 1,
            "role": "supporting_evidence",
        }
        for index in range(9)
    ] + [{"path": "root.py", "startLine": 1, "role": "root_control"}]
    findings_path.write_text(json.dumps(document))

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    assert len(completed["findings"][0]["locations"]) == 8
    assert completed["findings"][0]["locations"][0]["path"] == "root.py"
    exported = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
    )["export"]
    with Path(exported["path"]).open(newline="") as source:
        row = next(csv.DictReader(source))
    assert row["path"] == "root.py"


def test_csv_export_rejects_symlinked_exports_directory(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
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
    run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    (scan_dir / "exports" / "results.sarif").unlink()
    (scan_dir / "exports").rmdir()
    (scan_dir / "exports").symlink_to(outside, target_is_directory=True)
    failed = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
        check=False,
    )
    assert "expected a regular directory inside the scan directory" in str(failed["stderr"])
    assert not (outside / "findings.csv").exists()


def test_export_rejects_replaced_scan_directory(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
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
    run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    moved_scan_dir = scan_dir.with_name(f"{scan_dir.name}.moved")
    scan_dir.rename(moved_scan_dir)
    scan_dir.symlink_to(outside, target_is_directory=True)
    failed = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
        check=False,
    )
    assert failed["returncode"] != 0
    assert not (outside / "exports" / "findings.csv").exists()


def test_csv_export_rejects_replaced_scan_directory_ancestor(tmp_path: Path) -> None:
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
    run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)
    stored_parent = scan_dir.parent
    moved_parent = stored_parent.with_name(f"{stored_parent.name}.moved")
    stored_parent.rename(moved_parent)
    replacement_parent = tmp_path / "replacement-parent"
    shutil.copytree(moved_parent, replacement_parent)
    stored_parent.symlink_to(replacement_parent, target_is_directory=True)
    replacement_scan_dir = replacement_parent / scan_dir.name
    failed = run_workbench(
        state_dir,
        "export-findings",
        "--scan-id",
        scan_id,
        "--format",
        "csv",
        check=False,
    )
    assert failed["returncode"] != 0
    assert not (replacement_scan_dir / "exports" / "findings.csv").exists()


def test_completion_rejects_replaced_scan_directory(tmp_path: Path) -> None:
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
    moved_scan_dir = scan_dir.with_name(f"{scan_dir.name}.moved")
    scan_dir.rename(moved_scan_dir)
    scan_dir.symlink_to(moved_scan_dir, target_is_directory=True)
    failed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id, check=False)
    assert failed["returncode"] != 0
    assert not (moved_scan_dir / "exports" / "results.sarif").exists()


def test_completion_rejects_replaced_scan_directory_ancestor(tmp_path: Path) -> None:
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
    stored_parent = scan_dir.parent
    moved_parent = stored_parent.with_name(f"{stored_parent.name}.moved")
    stored_parent.rename(moved_parent)
    replacement_parent = tmp_path / "replacement-parent"
    shutil.copytree(moved_parent, replacement_parent)
    stored_parent.symlink_to(replacement_parent, target_is_directory=True)
    replacement_scan_dir = replacement_parent / scan_dir.name
    failed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id, check=False)
    assert failed["returncode"] != 0
    assert not (replacement_scan_dir / "exports" / "results.sarif").exists()


def test_remediation_apply_rejects_replaced_scan_directory_ancestor(tmp_path: Path) -> None:
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
    completed = run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]
    occurrence_id = str(completed["findings"][0]["occurrenceId"])
    request_id = str(uuid.uuid4())
    generation_token = str(uuid.uuid4())
    run_workbench(
        state_dir,
        "request-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
    )
    patch_path = scan_dir / "remediation.patch"
    patch_path.write_text("diff --git a/src/extract.py b/src/extract.py\n")
    run_workbench(
        state_dir,
        "set-finding-remediation",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--action-token",
        generation_token,
        "--expected-version",
        "1",
        "--state",
        "generated",
        "--patch-path",
        patch_path.name,
        "--patch-digest",
        f"sha256:{hashlib.sha256(patch_path.read_bytes()).hexdigest()}",
    )
    stored_parent = scan_dir.parent
    moved_parent = stored_parent.with_name(f"{stored_parent.name}.moved")
    stored_parent.rename(moved_parent)
    replacement_parent = tmp_path / "replacement-parent"
    shutil.copytree(moved_parent, replacement_parent)
    stored_parent.symlink_to(replacement_parent, target_is_directory=True)
    failed = run_workbench(
        state_dir,
        "request-finding-remediation-action",
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        request_id,
        "--expected-version",
        "2",
        "--action",
        "apply",
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )
    assert "canonical non-symlink directory" in str(failed["stderr"])
