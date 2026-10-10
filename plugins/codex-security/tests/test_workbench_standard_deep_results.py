from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import (
    begin_legacy_scan,
    finding_fixture,
    get_scan,
    preserve_scan_results,
    run_workbench,
    saved_coverage,
    scan_command,
    worker_paths,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize("historical_count", [0, 5, 20])
def test_recovery_validation_does_not_scale_with_superseded_checkpoints(
    tmp_path: Path, workbench_api, historical_count: int
) -> None:
    saved = workbench_api["saved_results"]
    scan_dir, target = tmp_path / "scan", tmp_path / "target"
    scan_dir.mkdir(mode=0o700)
    target.mkdir()
    scan_id = str(uuid.uuid4())
    write_completed_contract(scan_dir, scan_id, target)
    findings = [finding_fixture(identity_anchor=f"finding-{index}") for index in range(3)]
    (scan_dir / "findings.json").write_text(json.dumps({"findings": findings}))
    scan = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    for index in range(historical_count):
        write_checkpoint(
            scan_dir / "checkpoints",
            {
                "scanId": scan_id,
                "findings": [],
                "coverage": {"openQuestions": [f"Superseded question {index}"]},
            },
        )
    binding = {
        "status": "completed",
        "allowedTargetKinds": [scan["target"]["kind"]],
        "target": scan["target"],
        "scope": scan["scope"],
        "coverageMode": "repository",
    }
    with (
        mock.patch.object(saved, "_read_json", wraps=saved._read_json) as read_schema,
        mock.patch.object(
            saved, "_recover_unsealed_findings", wraps=saved._recover_unsealed_findings
        ) as recover,
    ):
        result = saved.merge_saved_results(
            scan_dir, scan_id, binding, [], [], stopped=False, reason=""
        )
    assert result is not None
    assert result[1]["findings"] == findings
    assert read_schema.call_count == 2
    assert recover.call_count == len(findings)


@pytest.mark.parametrize("termination", ["failed", "canceled"])
def test_stopped_scan_ignores_late_checkpoints_until_explicit_recovery(
    tmp_path: Path,
    termination: str,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    result_path = write_checkpoint(scan_dir / "checkpoints", checkpoint_draft(scan_id))
    finding = finding_fixture(relative_path="app.py")
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [
                {
                    "candidateId": "pending-query",
                    "reason": "Query validation remains pending.",
                    "paths": ["app.py"],
                }
            ],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    # The latest incomplete attempt need not be parseable for a saved checkpoint to survive.
    result_path.write_text("{incomplete")
    environment = {"CODEX_HOME": str(codex_home)}
    if termination == "canceled":
        run_workbench(
            state_dir,
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment=environment,
        )
    else:
        stop_scan(state_dir, scan_id, "Worker stopped.", status=termination)

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id[:12])["scan"]
    assert stopped["progress"]["status"] == ("canceled" if termination == "canceled" else "failed")
    assert stopped["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert any(item.get("candidateId") == "pending-query" for item in coverage["deferred"])
    assert result_path.read_text() == "{incomplete"
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == termination
    )
    first_seal = (scan_dir / "scan-manifest.json").read_bytes()
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    archived = scan_dir / "checkpoints"
    write_checkpoint(archived, late)
    recovery_needed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert recovery_needed["resultsRecoveryNeeded"] is (termination != "canceled")
    if termination == "canceled":
        rejected = run_workbench(
            state_dir,
            "recover-scan-results",
            "--scan-id",
            scan_id,
            check=False,
        )
        assert rejected["returncode"] != 0
        assert "Canceled scans cannot recover" in str(rejected["stderr"])
    wrong_owner = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "not-the-owner",
        check=False,
    )
    assert wrong_owner["returncode"] != 0
    assert (scan_dir / "scan-manifest.json").read_bytes() == first_seal
    refreshed = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment=environment,
    )["scan"]
    expected_count = 1
    assert refreshed["findingCount"] == expected_count
    assert len({finding["occurrenceId"] for finding in refreshed["findings"]}) == expected_count
    assert refreshed["findings"][0]["locations"][0]["startLine"] != 91
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    assert seal == first_seal
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["findingCount"]
        == expected_count
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal


def test_scan_reads_require_explicit_late_result_recovery(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    finding = finding_fixture(relative_path="app.py")
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["resultsRecoveryNeeded"] is False
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    late_path = write_checkpoint(scan_dir / "checkpoints", late)
    manifest_path = scan_dir / "scan-manifest.json"
    published_after_checkpoint = late_path.stat().st_mtime_ns + 1_000_000
    os.utime(manifest_path, ns=(published_after_checkpoint, published_after_checkpoint))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        workspace_id = connection.execute(
            "SELECT workspace_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]

    reopened = run_workbench(
        state_dir,
        "get-workspace",
        "--workspace-id",
        workspace_id,
        environment={"CODEX_HOME": str(codex_home)},
    )
    assert reopened["results"]["findingCount"] == 1
    stale = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stale["findingCount"] == 1
    assert stale["resultsRecoveryNeeded"] is True
    assert (
        run_workbench(state_dir, "list-findings", "--scan-id", scan_id)["findingsPage"]["total"]
        == 1
    )

    recovered = run_workbench(
        state_dir,
        "recover-scan-results",
        "--scan-id",
        scan_id,
        environment={"CODEX_HOME": str(codex_home)},
    )

    assert recovered["scan"]["findingCount"] == 2
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    assert len(json.loads((scan_dir / "findings.json").read_text())["findings"]) == 2


def test_explicit_recovery_rejects_changed_frozen_source(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    finding = finding_fixture(relative_path="app.py")
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    manifest_path = scan_dir / "scan-manifest.json"
    original_manifest = manifest_path.read_bytes()
    original_findings = (scan_dir / "findings.json").read_bytes()
    preserved_sources = json.loads(original_manifest)["scan"]["preservedSources"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        original_record = connection.execute(
            "SELECT seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    frozen_path = scan_dir / next(iter(preserved_sources))
    frozen_path.write_text("{truncated")

    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    write_checkpoint(scan_dir / "checkpoints", late)
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )

    rejected = run_workbench(
        state_dir,
        "recover-scan-results",
        "--scan-id",
        scan_id,
        environment={"CODEX_HOME": str(codex_home)},
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "Frozen stopped-scan checkpoint set is incomplete" in str(rejected["stderr"])
    assert (scan_dir / "scan-manifest.json").read_bytes() == original_manifest
    assert (scan_dir / "findings.json").read_bytes() == original_findings
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
            == original_record
        )


def test_explicit_recovery_preserves_unfrozen_parent_with_late_checkpoint(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    parent_finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_before_sources_are_frozen.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_before_sources_are_frozen(*args, **kwargs):\n"
        "    raise OSError('injected early publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_before_sources_are_frozen\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    failed = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "fail-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Worker stopped.",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
        check=False,
    )
    assert failed.returncode == 0, failed.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
            is None
        )

    late_finding = copy.deepcopy(parent_finding)
    late_finding["occurrenceId"] = "occ_111111111111111111111111"
    late_finding["ruleId"] = "late.checkpoint"
    late_finding["title"] = "Late checkpoint finding"
    late = checkpoint_draft(scan_id)
    late["complete"] = False
    late["findings"] = [late_finding]
    write_checkpoint(scan_dir / "checkpoints", late)

    recovered = run_workbench(
        state_dir,
        "recover-scan-results",
        "--scan-id",
        scan_id,
        environment={"CODEX_HOME": str(codex_home)},
    )["scan"]

    assert recovered["findingCount"] == 2
    assert {finding["title"] for finding in recovered["findings"]} == {
        parent_finding["title"],
        late_finding["title"],
    }


def test_explicit_recovery_preserves_sealed_parent_with_empty_source_map(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    write_completed_contract(
        contract_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="repository",
    )
    subprocess.run(
        [
            sys.executable,
            str(scripts_dir / "finalize_scan_contract.py"),
            "--scan-dir",
            str(contract_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    sealed_manifest = (scan_dir / "scan-manifest.json").read_bytes()
    parent_finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
            (f"sha256:{hashlib.sha256(sealed_manifest).hexdigest()}", scan_id),
        )

    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"] == {}
    )

    late_finding = copy.deepcopy(parent_finding)
    late_finding["occurrenceId"] = "occ_111111111111111111111111"
    late_finding["identity"]["anchor"] = "late-checkpoint"
    late_finding["ruleId"] = "late.checkpoint"
    late_finding["title"] = "Late checkpoint finding"
    late = {
        "scanId": scan_id,
        "complete": False,
        "findings": [late_finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", late)

    manifest_before_failed_recovery = (scan_dir / "scan-manifest.json").read_bytes()
    findings_before_failed_recovery = (scan_dir / "findings.json").read_bytes()
    wrapper = tmp_path / "fail_parent_checkpoint_write.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "original_write = workbench_saved_results.write_scan_local_bytes\n"
        "def fail_parent_checkpoint(scan_dir, relative_path, payload, **kwargs):\n"
        "    if relative_path.startswith('checkpoints/'):\n"
        "        raise OSError('injected parent checkpoint failure')\n"
        "    return original_write(scan_dir, relative_path, payload, **kwargs)\n"
        "workbench_saved_results.write_scan_local_bytes = fail_parent_checkpoint\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    failed = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "recover-scan-results",
            "--scan-id",
            scan_id,
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
        check=False,
    )
    assert failed.returncode != 0
    assert "injected parent checkpoint failure" in failed.stderr
    assert (scan_dir / "scan-manifest.json").read_bytes() == manifest_before_failed_recovery
    assert (scan_dir / "findings.json").read_bytes() == findings_before_failed_recovery

    recovered = scan_command(
        state_dir, "recover-scan-results", scan_id, environment={"CODEX_HOME": str(codex_home)}
    )["scan"]

    assert recovered["findingCount"] == 2
    assert {finding["title"] for finding in recovered["findings"]} == {
        parent_finding["title"],
        late_finding["title"],
    }

    later_finding = copy.deepcopy(parent_finding)
    later_finding["occurrenceId"] = "occ_222222222222222222222222"
    later_finding["identity"]["anchor"] = "later-checkpoint"
    later_finding["ruleId"] = "later.checkpoint"
    later_finding["title"] = "Later checkpoint finding"
    later = copy.deepcopy(late)
    later["findings"] = [later_finding]
    write_checkpoint(scan_dir / "checkpoints", later)

    recovered_again = scan_command(
        state_dir, "recover-scan-results", scan_id, environment={"CODEX_HOME": str(codex_home)}
    )["scan"]

    assert recovered_again["findingCount"] == 3
    assert {finding["title"] for finding in recovered_again["findings"]} == {
        parent_finding["title"],
        late_finding["title"],
        later_finding["title"],
    }


@pytest.mark.parametrize(
    "published_sources",
    [None, {}],
    ids=["missing-source-map", "empty-source-map"],
)
def test_explicit_recovery_retries_frozen_parent_after_write_failure(
    tmp_path: Path,
    published_sources: dict[str, str] | None,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    write_completed_contract(
        contract_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="repository",
    )
    subprocess.run(
        [
            sys.executable,
            str(scripts_dir / "finalize_scan_contract.py"),
            "--scan-dir",
            str(contract_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    if published_sources is not None:
        manifest_path = contract_dir / "scan-manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["scan"]["preservedSources"] = published_sources
        manifest_path.write_text(json.dumps(manifest))
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    parent_manifest = (scan_dir / "scan-manifest.json").read_bytes()
    parent_finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    parent_scan = json.loads(parent_manifest)["scan"]
    if published_sources is None:
        assert "preservedSources" not in parent_scan
    else:
        assert parent_scan["preservedSources"] == published_sources

    late_finding = copy.deepcopy(parent_finding)
    late_finding["occurrenceId"] = "occ_111111111111111111111111"
    late_finding["identity"]["anchor"] = "late-checkpoint"
    late_finding["ruleId"] = "late.checkpoint"
    late_finding["title"] = "Late checkpoint finding"
    late = checkpoint_draft(scan_id)
    late["complete"] = False
    late["findings"] = [late_finding]
    write_checkpoint(scan_dir / "checkpoints", late)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
            (f"sha256:{hashlib.sha256(parent_manifest).hexdigest()}", scan_id),
        )

    wrapper = tmp_path / "fail_after_sources_are_frozen.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_after_sources_are_frozen(prepared, **kwargs):\n"
        "    raise OSError('injected late publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = "
        "fail_after_sources_are_frozen\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    failed = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "fail-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Worker stopped.",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
        check=False,
    )
    assert failed.returncode == 0, failed.stderr
    assert (scan_dir / "scan-manifest.json").read_bytes() == parent_manifest
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        seal_digest, frozen_before = connection.execute(
            "SELECT seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert seal_digest is not None
    assert json.loads(frozen_before)
    assert get_scan(state_dir, scan_id)["scan"]["resultsRecoveryNeeded"] is True

    recovered = scan_command(
        state_dir, "recover-scan-results", scan_id, environment={"CODEX_HOME": str(codex_home)}
    )["scan"]

    assert recovered["resultsRecoveryNeeded"] is False
    assert recovered["findingCount"] == 2
    assert {finding["title"] for finding in recovered["findings"]} == {
        parent_finding["title"],
        late_finding["title"],
    }
    published_sources = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
        "preservedSources"
    ]
    frozen_sources = json.loads(frozen_before)
    assert published_sources.items() >= frozen_sources.items()
    added_sources = published_sources.keys() - frozen_sources.keys()
    parent_sources = {path for path in added_sources if path.startswith("checkpoints/")}
    assert all(
        path.startswith(("checkpoints/", "checkpoint-heads/", "source-order/"))
        for path in added_sources
    )
    assert len(parent_sources) == 1
    parent_source = next(iter(parent_sources))
    assert parent_source.startswith("checkpoints/")
    assert Path(parent_source).stem == published_sources[parent_source]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            json.loads(
                connection.execute(
                    "SELECT retained_source_digests_json FROM scans WHERE id = ?",
                    (scan_id,),
                ).fetchone()[0]
            )
            == published_sources
        )


def test_unsealed_manifest_without_saved_results_does_not_offer_recovery(
    tmp_path: Path,
) -> None:
    state_dir, _, _, scan_dir, scan_id = scan_fixture(tmp_path)
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"scan": {"status": "failed"}}))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET status = 'failed', failure_message = 'Worker stopped.' WHERE id = ?",
            (scan_id,),
        )

    failed = get_scan(state_dir, scan_id)["scan"]

    assert failed["resultsRecoveryNeeded"] is False


@pytest.mark.parametrize(
    ("command", "collection", "count_field"),
    [
        ("list-scans", "scans", "findingCount"),
        ("list-global-findings", "findings", None),
        ("list-repositories", "repositories", "openFindingsCount"),
    ],
)
def test_aggregate_queries_ignore_late_stopped_scan_checkpoints(
    tmp_path: Path,
    command: str,
    collection: str,
    count_field: str | None,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    finding = finding_fixture(relative_path="app.py")
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["identity"]["anchor"] = "late-independent-finding"
    write_checkpoint(scan_dir / "checkpoints", late)

    rows = run_workbench(state_dir, command, environment={"CODEX_HOME": str(codex_home)})[
        collection
    ]

    if command == "list-global-findings":
        assert len([row for row in rows if row["scanId"] == scan_id]) == 1
    else:
        assert count_field is not None
        row = next(
            row
            for row in rows
            if row.get("scanId") == scan_id or row.get("targetPath") == str(target)
        )
        assert row[count_field] == 1


def test_unreadable_only_checkpoint_records_recovery_warning(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = scan_fixture(tmp_path)
    result_path = write_checkpoint(scan_dir / "checkpoints", checkpoint_draft(scan_id))
    result_path.write_text("{not-json")

    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert any("Preserved unreadable checkpoint" in warning for warning in failed["warnings"])


def test_malformed_current_finding_retains_parent_rejection_history(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = "rejected-candidate"
    checkpoint = checkpoint_draft(scan_id)
    checkpoint["complete"] = False
    checkpoint["findings"] = [copy.deepcopy(finding)]
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    finding["summary"] = ""
    coverage = json.loads((contract_dir / "coverage.json").read_text())
    coverage["surfaces"] = [
        {
            "id": "rejected-candidate",
            "label": "Rejected candidate",
            "candidateId": "rejected-candidate",
            "disposition": "rejected",
            "receiptRefs": [],
            "notes": "The parent rejected this checkpointed candidate.",
        }
    ]
    (scan_dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    (scan_dir / "scan-manifest.json").write_bytes(
        (contract_dir / "scan-manifest.json").read_bytes()
    )

    stop_scan(
        state_dir, scan_id, "Stopped after rejecting a malformed current finding.", status="failed"
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert failed["reportAvailable"] is True
    assert failed["resultsRecoveryNeeded"] is False
    assert failed["findingCount"] == 0
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    # Ordinary publication preserves rejection history but flags malformed current evidence.
    assert coverage["surfaces"][0]["disposition"] == "needs_follow_up"
    assert coverage["surfaces"][0]["previousFindings"] == checkpoint["findings"]
    assert any(item["id"] == "discarded-finding-1" for item in coverage["deferred"])


def test_stopped_recovery_accepts_trailing_slash_scope(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(
        contract_dir,
        scan_id,
        target,
        include_paths=["src/"],
        relative_path="src/app.py",
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    checkpoint = checkpoint_draft(scan_id)
    checkpoint["complete"] = False
    checkpoint["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    checkpoint["coverage"] = json.loads((contract_dir / "coverage.json").read_text())
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET scope = 'src/' WHERE id = ?", (scan_id,))

    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert failed["findingCount"] == 1
    assert failed["findings"][0]["locations"][0]["path"] == "src/app.py"


def test_canceled_scan_retries_failed_publication_from_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    finding = finding_fixture(relative_path="app.py")
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(scan_dir / "checkpoints", checkpoint)

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_canceled_publication.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    canceled = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )
    assert canceled.returncode == 0, canceled.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        row = connection.execute(
            "SELECT retained_source_digests_json, completion_warnings_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert row[0]
    assert "injected publication failure" in row[1]

    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    archived = scan_dir / "checkpoints"
    write_checkpoint(archived, late)

    preserved = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )["scan"]
    assert preserved["findingCount"] == 1
    assert preserved["findings"][0]["locations"][0]["startLine"] != 91
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == "canceled"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        warnings = json.loads(
            connection.execute(
                "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
        )
    assert not any("result publication needs follow-up" in warning for warning in warnings)


@pytest.mark.parametrize("deep_status", ["failed", "interrupted"])
def test_existing_non_canceled_output_recovers_structured_publication_failure(
    tmp_path: Path, deep_status: str
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = scan_fixture(tmp_path, legacy=True)
    write_checkpoint(scan_dir / "checkpoints", checkpoint_draft(scan_id))
    stop_scan(state_dir, scan_id, "Synthetic scan failure", status=deep_status)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET publication_error_message = ? WHERE scan_id = ?",
            ("Synthetic publication failure", scan_id),
        )
    assert run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT publication_error_message FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
            is None
        )


def test_canceled_scan_reports_noop_coordinator_publication(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = scan_fixture(tmp_path)
    result_path = write_checkpoint(scan_dir / "checkpoints", checkpoint_draft(scan_id))
    result_path.write_text("{incomplete")

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_before_canceled_sources_are_frozen.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_before_sources_are_frozen(*args, **kwargs):\n"
        "    raise OSError('injected early publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_before_sources_are_frozen\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    canceled = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )
    assert canceled.returncode == 0, canceled.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
            is None
        )

    preserved = preserve_scan_results(
        state_dir,
        scan_id,
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
        check=False,
    )
    assert preserved["returncode"] != 0
    assert "could not be published or verified" in preserved["stderr"]


def test_canceled_scan_reseals_prepared_completion_with_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = checkpoint_draft(scan_id)
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path = write_checkpoint(scan_dir / "checkpoints", result)
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    relative_result_path = result_path.relative_to(scan_dir).as_posix()
    manifest["scan"]["preservedSources"] = {
        relative_result_path: hashlib.sha256(
            json.dumps(
                result,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    }
    manifest_path.write_text(json.dumps(manifest))
    run_workbench(state_dir, "prepare-scan-completion", "--scan-id", scan_id)
    assert json.loads(manifest_path.read_text())["scan"]["status"] == "completed"

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_prepared_canceled_publication.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    canceled = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )
    assert canceled.returncode == 0, canceled.stderr
    assert json.loads(manifest_path.read_text())["scan"]["status"] == "completed"

    run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )

    assert json.loads(manifest_path.read_text())["scan"]["status"] == "canceled"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]


def test_stopped_scan_recovers_when_parent_manifest_has_no_scan(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    result = checkpoint_draft(scan_id)
    result["findings"] = [finding]
    write_checkpoint(scan_dir / "checkpoints", result)
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"documentType": "broken-parent"}))

    stop_scan(state_dir, scan_id, "Worker stopped.", status="failed")

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["findingCount"] == 1
    assert any("has no scan object" in warning for warning in stopped["warnings"])
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == ("failed")


def checkpoint_draft(scan_id: str) -> dict:
    return {
        "scanId": scan_id,
        "findings": [],
        "coverage": {
            "completeness": "complete",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }


def scan_fixture(tmp_path: Path, *, legacy: bool = False):
    state_dir, codex_home, target = tmp_path / "state", tmp_path / "codex-home", tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("# Synthetic legacy scan target\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
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
                "mode": "deep" if legacy else "standard",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
            }
        ),
    )
    scan_id = registered["scanId"]
    run_workbench(
        state_dir, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "standard-worker-thread"
    )
    if legacy:
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_runs (scan_id,schema_version,workflow_version,status,phase,workers,"
                "subagents,stop_after_no_new,max_discovery_runs,created_at,updated_at) "
                "SELECT id,1,'deep-security-scan/v1','running','discovery',?,3,4,8,started_at,updated_at "
                "FROM scans WHERE id = ?",
                (1, scan_id),
            )
    return state_dir, codex_home, target, scan_dir, scan_id


def stop_scan(state_dir, scan_id, message, *, status="failed"):
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = ?, error_message = ? WHERE scan_id = ?",
            (status, message, scan_id),
        )
    return run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", message)


def test_stopped_scan_rebinds_prepared_completion_seal(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = checkpoint_draft(scan_id)
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    write_checkpoint(scan_dir / "checkpoints", result)
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_bytes(
        (contract_dir / "scan-manifest.json").read_bytes()
    )
    run_workbench(state_dir, "prepare-scan-completion", "--scan-id", scan_id)
    prepared_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert prepared_manifest["scan"]["status"] == "completed"

    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Completion was not accepted.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    failed_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert failed_manifest["scan"]["status"] == "failed"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        seal_digest = connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    assert seal_digest


@pytest.mark.parametrize(
    "command",
    [
        ("request-finding-remediation",),
        ("request-finding-remediation-action", "--expected-version", "1", "--action", "apply"),
        ("claim-finding-remediation-resend",),
        ("mark-finding-remediation-delivered",),
        ("release-finding-remediation-claim",),
        ("cancel-finding-remediation-request",),
        ("set-finding-remediation", "--expected-version", "1", "--state", "failed"),
    ],
)
def test_stopped_findings_cannot_enter_remediation(
    tmp_path: Path, command: tuple[str, ...]
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    result = checkpoint_draft(scan_id)
    result["findings"] = [finding_fixture(relative_path="app.py")]
    write_checkpoint(scan_dir / "checkpoints", result)
    stop_scan(state_dir, scan_id, "Stopped with a provisional finding.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["remediationAvailable"] is False
    assert failed["remediationUnavailableReason"] == (
        "Remediation is available only for successfully completed scans."
    )
    occurrence_id = failed["findings"][0]["occurrenceId"]

    blocked = run_workbench(
        state_dir,
        *command,
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        str(uuid.uuid4()),
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )

    assert blocked["returncode"] != 0
    assert "successfully completed scans" in blocked["stderr"]


def test_complete_parent_supersedes_obsolete_checkpoint_coverage(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    write_completed_contract(scan_dir, scan_id, target, relative_path="app.py")
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [
                {
                    "id": "obsolete-surface",
                    "label": "Obsolete review",
                    "disposition": "needs_follow_up",
                    "receiptRefs": [],
                }
            ],
            "explicitExclusions": [],
            "deferred": [{"id": "obsolete-work", "reason": "This was later completed."}],
        },
    }
    path = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    earlier = (scan_dir / "coverage.json").stat().st_mtime_ns - 1
    os.utime(path, ns=(earlier, earlier))

    stop_scan(state_dir, scan_id, "Stopped after the parent draft completed.", status="failed")

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert not any(item.get("id") == "obsolete-surface" for item in coverage["surfaces"])
    assert not any(item.get("id") == "obsolete-work" for item in coverage["deferred"])


def test_complete_partial_parent_supersedes_obsolete_checkpoint_questions(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="repository",
    )
    coverage_path = scan_dir / "coverage.json"
    final_coverage = json.loads(coverage_path.read_text())
    final_coverage["completeness"] = "partial"
    final_coverage["openQuestions"] = []
    coverage_path.write_text(json.dumps(final_coverage))
    path = write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
                "openQuestions": ["This question was answered by the final parent draft."],
            },
        },
    )

    earlier = coverage_path.stat().st_mtime_ns - 1
    os.utime(path, ns=(earlier, earlier))
    stop_scan(state_dir, scan_id, "Stopped after the final partial parent draft.", status="failed")

    recovered = json.loads(coverage_path.read_text())
    assert recovered.get("openQuestions", []) == []


def test_recovery_selects_strongest_same_finding_checkpoint(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    weak = finding_fixture(relative_path="app.py")
    weak["severity"]["level"] = "low"
    weak["confidence"]["level"] = "low"
    weak["summary"] = "Earlier weak checkpoint evidence."
    strong = copy.deepcopy(weak)
    strong["severity"]["level"] = "high"
    strong["confidence"]["level"] = "high"
    strong["summary"] = "Later strong checkpoint evidence."
    checkpoint_dir = scan_dir / "checkpoints"
    (checkpoint_dir / "pending").mkdir(parents=True)
    for name, finding in (("0" * 64, weak), ("f" * 64, strong)):
        (checkpoint_dir / "pending" / f"{name}.json").write_bytes(b"")
        (checkpoint_dir / f"{name}.json").write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "complete": False,
                    "findings": [finding],
                    "coverage": {
                        "completeness": "partial",
                        "surfaces": [],
                        "explicitExclusions": [],
                        "deferred": [],
                    },
                }
            )
        )

    stop_scan(state_dir, scan_id, "Stopped between checkpoints.", status="failed")

    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["severity"]["level"] == "high"
    assert retained["confidence"]["level"] == "high"
    assert retained["summary"] == "Later strong checkpoint evidence."
    assert any(
        finding.get("summary") == "Earlier weak checkpoint evidence."
        for finding in retained["provenance"]["previousFindings"]
    )


def test_recovery_does_not_promote_already_retained_historical_finding(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = scan_fixture(tmp_path)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    historical = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    historical["extensions"] = {"candidateId": "candidate-refined-location"}
    historical["provenance"]["candidateId"] = "candidate-refined-location"
    historical["locations"][0]["startLine"] = 1
    historical["locations"][0]["endLine"] = 2
    historical["severity"]["level"] = "critical"
    historical["confidence"]["level"] = "high"
    historical.pop("identity")
    checkpoint_historical = copy.deepcopy(historical)
    historical["provenance"]["originalCandidates"] = [
        {"candidateId": "candidate-refined-location", "title": historical["title"]}
    ]

    current = copy.deepcopy(historical)
    current["identity"] = {"anchor": "refined-location-finding"}
    current["locations"][0]["startLine"] = 2
    current["severity"]["level"] = "medium"
    current["confidence"]["level"] = "medium"
    current["provenance"]["previousFindings"] = [copy.deepcopy(historical)]
    (scan_dir / "findings.json").write_text(json.dumps({"findings": [current]}))
    for filename in ("coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    checkpoint = checkpoint_draft(scan_id)
    checkpoint["complete"] = False
    checkpoint["findings"] = [checkpoint_historical]
    write_checkpoint(scan_dir / "checkpoints", checkpoint)

    stop_scan(
        state_dir, scan_id, "Stopped after the canonical result was retained.", status="failed"
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["locations"][0]["startLine"] == 2
    assert retained["severity"]["level"] == "medium"
    assert retained["confidence"]["level"] == "medium"
    assert retained["provenance"]["previousFindings"] == [historical]


@pytest.mark.parametrize("converted", [False, True])
def test_retired_runtime_resume_requires_a_fresh_scan(tmp_path: Path, converted: bool) -> None:
    state, _, _, scan_dir, scan_id = scan_fixture(tmp_path, legacy=True)
    evidence = scan_dir / "saved-evidence.json"
    evidence.write_text('{"summary":"Saved legacy work"}')
    if converted:
        checkpoint = scan_dir / "artifacts/deep-scan/checkpoint.json"
        checkpoint.parent.mkdir(parents=True)
        checkpoint.write_text(json.dumps({"version": 2, "legacy": {"discoveryRuns": 1}}))
    before = evidence.read_bytes()
    rejected = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id, check=False)
    assert "retired runtime. Start a fresh scan" in rejected["stderr"]
    assert evidence.read_bytes() == before
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, continuation_thread_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone() == ("running", "standard-worker-thread")
        assert connection.execute(
            "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == ("running",)


@pytest.mark.parametrize(
    ("questions", "checkpoint_questions", "expected"),
    [
        pytest.param(
            ["Q1", "Q2", "Q3"],
            None,
            [{"question": "Q1"}, {"question": "Q2"}, {"question": "Q3"}],
            id="string-questions",
        ),
        pytest.param(
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            id="identical-follow-up",
        ),
        pytest.param(
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Windows tests."}],
            [
                {"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."},
                {"question": "Which tests remain?", "followUpPrompt": "Run the Windows tests."},
            ],
            id="distinct-follow-ups",
        ),
    ],
)
def test_merge_saved_results_deduplicates_open_questions(
    tmp_path: Path,
    questions: list[str | dict[str, str]],
    checkpoint_questions: list[dict[str, str]] | None,
    expected: list[dict[str, str]],
) -> None:
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import workbench_saved_results

    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "test-scan-open-questions"

    manifest = {
        "scan": {
            "id": scan_id,
            "target": {"kind": "git_revision", "repository": "test", "revision": "head"},
            "scope": {"includePaths": ["."], "excludePaths": []},
            "status": "in_progress",
            "complete": False,
        }
    }
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    (scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                "completeness": "partial",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
                "openQuestions": questions,
            }
        )
    )
    if checkpoint_questions is not None:
        write_checkpoint(
            scan_dir / "checkpoints",
            {
                "scanId": scan_id,
                "complete": False,
                "findings": [],
                "coverage": {
                    "completeness": "partial",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                    "openQuestions": checkpoint_questions,
                },
            },
        )

    binding = {
        "status": "in_progress",
        "allowedTargetKinds": ["git_revision"],
        "target": {"kind": "git_revision", "repository": "test", "revision": "head"},
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "repository",
    }

    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=False, reason=""
    )
    assert result is not None
    _, _, coverage = result
    assert coverage.get("openQuestions") == expected


@pytest.mark.parametrize("checkpoint_count", [0, 4])
def test_parent_validation_does_not_scale_with_superseded_checkpoints(
    tmp_path: Path, workbench_api, checkpoint_count: int
) -> None:
    saved_results = workbench_api["saved_results"]
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    scan_id = "parent-validation"
    write_completed_contract(scan_dir, scan_id, target)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    findings = json.loads((scan_dir / "findings.json").read_text())
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    for index in range(checkpoint_count):
        earlier = copy.deepcopy(findings["findings"][0])
        earlier["summary"] = f"Superseded observation {index}."
        path = write_checkpoint(
            scan_dir / "checkpoints",
            {"scanId": scan_id, "findings": [earlier], "coverage": coverage},
        )
        modified = (scan_dir / "coverage.json").stat().st_mtime_ns - 1
        os.utime(path, ns=(modified, modified))
    binding = {
        "status": "completed",
        "allowedTargetKinds": [manifest["target"]["kind"]],
        "target": manifest["target"],
        "scope": manifest["scope"],
        "coverageMode": "repository",
    }
    with mock.patch.object(
        saved_results, "_recover_unsealed_findings", wraps=saved_results._recover_unsealed_findings
    ) as recover:
        result = saved_results.merge_saved_results(
            scan_dir, scan_id, binding, [], [], stopped=False, reason=""
        )
    assert result is not None
    assert result[1]["findings"] == findings["findings"]
    # The unchanged parent and merged output share one cached validation result.
    assert recover.call_count == 1


def run_workbench_with_fault(script_path, state_dir, codex_home, setup, *args):
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    script_path.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n" + setup + "raise SystemExit(workbench_db.main())\n"
    )
    return subprocess.run(
        [sys.executable, str(script_path), *args],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )


def deep_scan_fixture(
    tmp_path: Path, *, budget: bool = False, workers: int = 1
) -> tuple[Path, Path, Path, Path, str]:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = request.args['value']\n")
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(f"[deep_scan]\nworkers = {workers}\nmax_discovery_runs = {workers}\n")
    begun = begin_legacy_scan(
        state_dir, codex_home, target, tmp_path / "scans", thread_id="standard-worker-thread"
    )["deepScan"]
    scan_id = str(begun["scanId"])
    scan_dir = Path(str(begun["scanDir"]))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET workers = ?, max_discovery_runs = ? WHERE scan_id = ?",
            (workers, workers, scan_id),
        )
        if budget:
            recipe = {
                "config": {},
                "mode": "deep",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
                "maxCostUsd": 0.005,
            }
            connection.execute(
                "UPDATE scans SET recipe_json = ? WHERE id = ?", (json.dumps(recipe), scan_id)
            )

    return state_dir, codex_home, target, scan_dir, scan_id


def accepted_standard_worker(
    state_dir: Path,
    codex_home: Path,
    scan_dir: Path,
    scan_id: str,
    *,
    name: str = "standard-worker",
) -> tuple[str, Path]:
    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, name)
    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "findings": [],
                "coverage": saved_coverage(),
                "threatModel": {"summary": "The ordinary Standard worker threat model."},
            }
        )
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_workers "
            "(id,scan_id,kind,status,prompt_path,artifact_dir,result_manifest_path,attempt,"
            "created_at,started_at,completed_at,updated_at) "
            "SELECT ?,id,'discovery','succeeded',?,?,?,1,started_at,started_at,updated_at,updated_at "
            "FROM scans WHERE id = ?",
            (worker_id, str(prompt_path), str(artifact_dir), str(result_path), scan_id),
        )
    return worker_id, result_path


def write_saved_parent(scan_dir: Path, draft: dict, modified: int) -> None:
    (scan_dir / "scan-manifest.json").write_text(
        json.dumps({"scan": {"complete": draft["complete"]}})
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": draft["findings"]}))
    (scan_dir / "coverage.json").write_text(json.dumps(draft["coverage"]))
    os.utime(scan_dir / "coverage.json", ns=(modified, modified))
