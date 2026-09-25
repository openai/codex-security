from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.mark.parametrize("termination", ["failed", "interrupted", "canceled"])
def test_stopped_deep_scan_ignores_late_worker_checkpoints_without_reducer(
    tmp_path: Path,
    termination: str,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
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
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    # The latest incomplete attempt need not be parseable for a saved checkpoint to survive.
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )
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
        stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status=termination)

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
    archived = result_path.parent / "attempts" / "attempt-01" / "checkpoints"
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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
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
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["resultsRecoveryNeeded"] is False
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    late_path = write_checkpoint(
        result_path.parent / "attempts" / "attempt-01" / "checkpoints", late
    )
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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
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
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")
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
    write_checkpoint(result_path.parent / "attempts" / "attempt-01" / "checkpoints", late)
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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
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
    late = json.loads(result_path.read_text())
    late["complete"] = False
    late["findings"] = [late_finding]
    write_checkpoint(result_path.parent / "checkpoints", late)

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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    result_path.unlink()
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    write_completed_contract(
        contract_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
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

    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")
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
    write_checkpoint(result_path.parent / "checkpoints", late)

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

    later_finding = copy.deepcopy(parent_finding)
    later_finding["occurrenceId"] = "occ_222222222222222222222222"
    later_finding["identity"]["anchor"] = "later-checkpoint"
    later_finding["ruleId"] = "later.checkpoint"
    later_finding["title"] = "Later checkpoint finding"
    later = copy.deepcopy(late)
    later["findings"] = [later_finding]
    write_checkpoint(result_path.parent / "attempts" / "attempt-02" / "checkpoints", later)

    recovered_again = run_workbench(
        state_dir,
        "recover-scan-results",
        "--scan-id",
        scan_id,
        environment={"CODEX_HOME": str(codex_home)},
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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    write_completed_contract(
        contract_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
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
    late = json.loads(result_path.read_text())
    late["complete"] = False
    late["findings"] = [late_finding]
    result_path.write_text(json.dumps(late))
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
        "def fail_after_sources_are_frozen(prepared):\n"
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
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )

    recovered = run_workbench(
        state_dir,
        "recover-scan-results",
        "--scan-id",
        scan_id,
        environment={"CODEX_HOME": str(codex_home)},
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
    parent_sources = published_sources.keys() - frozen_sources.keys()
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
    state_dir, _, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"scan": {"status": "failed"}}))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET status = 'failed', failure_message = 'Worker stopped.' WHERE id = ?",
            (scan_id,),
        )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
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
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["identity"]["anchor"] = "late-independent-finding"
    write_checkpoint(result_path.parent / "attempts" / "attempt-01" / "checkpoints", late)

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
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    result_path.write_text("{not-json")

    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert any("Preserved unreadable checkpoint" in warning for warning in failed["warnings"])


def test_malformed_current_finding_does_not_override_worker_rejection(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = "rejected-candidate"
    checkpoint = json.loads(result_path.read_text())
    checkpoint["complete"] = False
    checkpoint["findings"] = [copy.deepcopy(finding)]
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    finding["summary"] = ""
    current = json.loads(result_path.read_text())
    current["findings"] = [finding]
    current["coverage"]["surfaces"] = [
        {
            "label": "Rejected candidate",
            "candidateId": "rejected-candidate",
            "disposition": "rejected",
            "notes": "The completed worker rejected this checkpointed candidate.",
        }
    ]
    result_path.write_text(json.dumps(current))

    stop_legacy_scan(
        state_dir, scan_id, "Stopped after rejecting a malformed current finding.", status="failed"
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert failed["findingCount"] == 0
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"][0]["disposition"] == "rejected"
    assert len(coverage["surfaces"][0]["previousFindings"]) == 1


def test_stopped_recovery_accepts_trailing_slash_scope(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
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
    checkpoint = json.loads(result_path.read_text())
    checkpoint["complete"] = False
    checkpoint["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    checkpoint["coverage"] = json.loads((contract_dir / "coverage.json").read_text())
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET scope = 'src/' WHERE id = ?", (scan_id,))

    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert failed["findingCount"] == 1
    assert failed["findings"][0]["locations"][0]["path"] == "src/app.py"


def test_canceled_scan_retries_failed_publication_from_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
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
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )

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
    archived = result_path.parent / "attempts" / "attempt-01" / "checkpoints"
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
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    stop_legacy_scan(state_dir, scan_id, "Synthetic scan failure", status=deep_status)
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
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
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

    preserved = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
        check=False,
    )
    assert preserved["returncode"] != 0
    assert "could not be published or verified" in preserved["stderr"]


def test_canceled_scan_reseals_prepared_completion_with_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
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
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at "
            "WHERE scan_id = ?",
            (str(manifest_path), scan_id),
        )
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


def test_stopped_deep_scan_recovers_when_parent_manifest_has_no_scan(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    result = json.loads(result_path.read_text())
    result["findings"] = [finding]
    result_path.write_text(json.dumps(result))
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"documentType": "broken-parent"}))

    stop_legacy_scan(state_dir, scan_id, "Worker stopped.", status="failed")

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["findingCount"] == 1
    assert any("has no scan object" in warning for warning in stopped["warnings"])
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == ("failed")


def deep_scan_fixture(tmp_path: Path, *, workers: int = 1, budget: bool = False):
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
                "mode": "deep",
                "repository": str(target),
                "target": {"kind": "repository", "paths": []},
                **({"maxCostUsd": 0.005} if budget else {}),
            }
        ),
    )
    scan_id = registered["scanId"]
    run_workbench(
        state_dir, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "standard-worker-thread"
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id,schema_version,workflow_version,status,phase,workers,"
            "subagents,stop_after_no_new,max_discovery_runs,created_at,updated_at) "
            "SELECT id,1,'deep-security-scan/v1','running','discovery',?,3,4,8,started_at,updated_at "
            "FROM scans WHERE id = ?",
            (workers, scan_id),
        )
    return state_dir, codex_home, target, scan_dir, scan_id


def seed_legacy_worker(state_dir, scan_id, worker_id, *, kind, status, prompt, directory):
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_workers (id,scan_id,kind,status,prompt_path,artifact_dir,attempt,"
            "result_manifest_path,created_at,updated_at,completed_at) "
            "SELECT ?,id,?,?,?,?,1,?,started_at,updated_at,updated_at FROM scans WHERE id = ?",
            (
                worker_id,
                kind,
                status,
                str(prompt),
                str(directory),
                str(Path(directory) / "result.json"),
                scan_id,
            ),
        )


def stop_legacy_scan(state_dir, scan_id, message, *, status="failed"):
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = ?, error_message = ? WHERE scan_id = ?",
            (status, message, scan_id),
        )
    return run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", message)


def worker_paths(scan_dir: Path, name: str) -> tuple[Path, Path, Path]:
    artifact_dir = scan_dir / "artifacts" / "deep_discovery" / name
    artifact_dir.mkdir(parents=True)
    prompt_path = artifact_dir / "prompt.md"
    prompt_path.write_text(f"Prompt for {name}\n")
    return prompt_path, artifact_dir, artifact_dir / "result.json"


def accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id, *, name="standard-worker"):
    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, name)
    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "findings": [],
                "coverage": {
                    "completeness": "complete",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                },
                "threatModel": {"summary": "The ordinary Standard worker threat model."},
            }
        )
    )
    seed_legacy_worker(
        state_dir,
        scan_id,
        worker_id,
        kind="discovery",
        status="succeeded",
        prompt=prompt_path,
        directory=artifact_dir,
    )
    return worker_id, result_path


def committed_standard_reducer(
    state_dir,
    codex_home,
    scan_dir,
    scan_id,
    discovery_worker_id,
    discovery_result,
    *,
    additional_worker_ids=(),
):
    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, "standard-reducer")
    result_path.write_text(discovery_result.read_text())
    seed_legacy_worker(
        state_dir,
        scan_id,
        reducer_id,
        kind="dedup",
        status="succeeded",
        prompt=prompt_path,
        directory=artifact_dir,
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        for ordinal, worker_id in enumerate((discovery_worker_id, *additional_worker_ids)):
            connection.execute(
                "INSERT INTO deep_scan_dedup_inputs (scan_id,dedup_worker_id,discovery_worker_id,input_order) VALUES (?,?,?,?)",
                (scan_id, reducer_id, worker_id, ordinal),
            )
            connection.execute(
                "UPDATE deep_scan_workers SET merge_state = 'merged' WHERE id = ?", (worker_id,)
            )
    return reducer_id, result_path, {}


def test_failure_preserves_last_committed_reducer_without_parent_draft(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    draft = json.loads(result_path.read_text())
    draft["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(draft))
    _, reducer_path, _ = committed_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, result_path
    )
    reduced = json.loads(reducer_path.read_text())
    reduced["findings"][0]["summary"] = (
        "The reducer retained additional independently reviewed evidence."
    )
    reducer_path.write_text(json.dumps(reduced))
    stop_legacy_scan(state_dir, scan_id, "Later reducer failed.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 1
    assert failed["findings"][0]["summary"] == reduced["findings"][0]["summary"]


def test_stopped_rejection_recovers_malformed_parent_surfaces(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "rejected-candidate"}
    finding["provenance"]["candidateId"] = "rejected-candidate"
    finding["provenance"]["workerId"] = worker_id
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": [finding]}))
    malformed_coverage = json.loads((contract_dir / "coverage.json").read_text())
    malformed_coverage["surfaces"] = None
    (scan_dir / "coverage.json").write_text(json.dumps(malformed_coverage))
    (scan_dir / "scan-manifest.json").write_bytes(
        (contract_dir / "scan-manifest.json").read_bytes()
    )
    current = json.loads(result_path.read_text())
    checkpoint = copy.deepcopy(current)
    checkpoint["complete"] = False
    checkpoint["findings"] = [copy.deepcopy(finding)]
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    current["coverage"]["surfaces"] = [
        {
            "label": "Rejected candidate",
            "candidateId": "rejected-candidate",
            "disposition": "rejected",
            "notes": "The completed worker rejected this checkpointed candidate.",
        }
    ]
    result_path.write_text(json.dumps(current))

    stop_legacy_scan(
        state_dir, scan_id, "Stopped after rejecting a checkpointed candidate.", status="failed"
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert isinstance(coverage["surfaces"], list)


def test_stopped_scan_rebinds_prepared_completion_seal(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_bytes(
        (contract_dir / "scan-manifest.json").read_bytes()
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at "
            "WHERE scan_id = ?",
            (str(scan_dir / "scan-manifest.json"), scan_id),
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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
    stop_legacy_scan(state_dir, scan_id, "Stopped with a provisional finding.", status="failed")
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


def test_complete_worker_supersedes_obsolete_checkpoint_coverage(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
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
    checkpoints = result_path.parent / "checkpoints"
    checkpoints.mkdir()
    (checkpoints / ("0" * 64 + ".json")).write_text(json.dumps(checkpoint))

    stop_legacy_scan(state_dir, scan_id, "Stopped after the worker completed.", status="failed")

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert not any(item.get("id") == "obsolete-surface" for item in coverage["surfaces"])
    assert not any(item.get("id") == "obsolete-work" for item in coverage["deferred"])


def test_complete_partial_parent_supersedes_obsolete_checkpoint_questions(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    coverage_path = scan_dir / "coverage.json"
    final_coverage = json.loads(coverage_path.read_text())
    final_coverage["completeness"] = "partial"
    final_coverage["openQuestions"] = []
    coverage_path.write_text(json.dumps(final_coverage))
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
                "openQuestions": ["This question was answered by the final parent draft."],
            },
        },
    )

    stop_legacy_scan(
        state_dir, scan_id, "Stopped after the final partial parent draft.", status="failed"
    )

    recovered = json.loads(coverage_path.read_text())
    assert recovered.get("openQuestions", []) == []


def test_canceled_reducer_checkpoint_supersedes_discovery_result(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    baseline = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    baseline["extensions"] = {"candidateId": "candidate-reducer"}
    baseline["provenance"]["candidateId"] = "candidate-reducer"
    discovery = json.loads(worker_result.read_text())
    discovery["findings"] = [baseline]
    discovery["coverage"]["surfaces"] = [
        {
            "id": "reducer-surface",
            "label": "Reducer-reviewed route",
            "disposition": "reported",
            "notes": "Discovery evidence only.",
            "receiptRefs": [],
        }
    ]
    worker_result.write_text(json.dumps(discovery))

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, reducer_result = worker_paths(scan_dir, "canceled-reducer")
    seed_legacy_worker(
        state_dir,
        scan_id,
        reducer_id,
        kind="dedup",
        status="running",
        prompt=str(prompt_path),
        directory=str(artifact_dir),
    )
    reduced = copy.deepcopy(discovery)
    reduced["findings"][0]["summary"] = "The reducer retained stronger merged evidence."
    reduced["coverage"]["surfaces"][0]["notes"] = "Reducer-validated merged evidence."
    reducer_result.write_text(json.dumps(reduced))
    checkpoints = reducer_result.parent / "checkpoints"
    checkpoints.mkdir()
    (checkpoints / ("a" * 64 + ".json")).write_text(json.dumps(reduced))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'canceled', completed_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), reducer_id),
        )

    stop_legacy_scan(state_dir, scan_id, "Canceled after reducer validation.", status="failed")

    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert findings[0]["summary"] == reduced["findings"][0]["summary"]
    assert coverage["surfaces"][0]["notes"] == "Reducer-validated merged evidence."


def test_archived_reducer_checkpoint_supersedes_discovery_result(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    discovery = json.loads(worker_result.read_text())
    discovery["findings"] = [finding]
    worker_result.write_text(json.dumps(discovery))

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, reducer_result = worker_paths(scan_dir, "archived-reducer")
    seed_legacy_worker(
        state_dir,
        scan_id,
        reducer_id,
        kind="dedup",
        status="running",
        prompt=str(prompt_path),
        directory=str(artifact_dir),
    )
    reduced = copy.deepcopy(discovery)
    reduced["findings"][0]["summary"] = "The archived reducer retained the newest evidence."
    archived = artifact_dir / "attempts" / "attempt-01"
    archived.mkdir(parents=True)
    (archived / "result.json").write_text(json.dumps(reduced))
    write_checkpoint(archived / "checkpoints", reduced)
    reducer_result.write_text("{incomplete current reducer")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'canceled', completed_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), reducer_id),
        )

    stop_legacy_scan(
        state_dir, scan_id, "Canceled after archiving a validated reducer attempt.", status="failed"
    )

    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["summary"] == reduced["findings"][0]["summary"]


def test_recovery_selects_strongest_same_finding_checkpoint(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    weak = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    weak["severity"]["level"] = "low"
    weak["confidence"]["level"] = "low"
    weak["summary"] = "Earlier weak checkpoint evidence."
    strong = copy.deepcopy(weak)
    strong["severity"]["level"] = "high"
    strong["confidence"]["level"] = "high"
    strong["summary"] = "Later strong checkpoint evidence."
    checkpoint_dir = result_path.parent / "checkpoints"
    checkpoint_dir.mkdir()
    for name, finding in (("0" * 64, weak), ("f" * 64, strong)):
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
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )

    stop_legacy_scan(state_dir, scan_id, "Stopped between checkpoints.", status="failed")

    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["severity"]["level"] == "high"
    assert retained["confidence"]["level"] == "high"
    assert retained["summary"] == "Later strong checkpoint evidence."
    assert any(
        finding.get("summary") == "Earlier weak checkpoint evidence."
        for finding in retained["provenance"]["previousFindings"]
    )


def test_failed_reducer_preserves_later_successful_worker_findings(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=3)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    baseline = json.loads((contract_dir / "findings.json").read_text())["findings"][0]

    first_worker_id, first_result = accepted_standard_worker(
        state_dir, codex_home, scan_dir, scan_id, name="first-worker"
    )
    first_document = json.loads(first_result.read_text())
    first_document["findings"] = [baseline]
    first_result.write_text(json.dumps(first_document))
    empty_worker_id, _ = accepted_standard_worker(
        state_dir, codex_home, scan_dir, scan_id, name="empty-worker"
    )
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        first_worker_id,
        first_result,
        additional_worker_ids=(empty_worker_id,),
    )

    second_worker_id, second_result = accepted_standard_worker(
        state_dir, codex_home, scan_dir, scan_id, name="later-worker"
    )
    later = copy.deepcopy(baseline)
    later["identity"]["anchor"] = "later-successful-worker-finding"
    later["title"] = "Later successful worker finding"
    later["summary"] = "This finding completed after the last successful reduction."
    second_document = json.loads(second_result.read_text())
    second_document["findings"] = [later]
    second_result.write_text(json.dumps(second_document))

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, _ = worker_paths(scan_dir, "failed-reducer")
    seed_legacy_worker(
        state_dir,
        scan_id,
        reducer_id,
        kind="dedup",
        status="failed",
        prompt=prompt_path,
        directory=artifact_dir,
    )

    stop_legacy_scan(state_dir, scan_id, "Later reducers failed.", status="failed")

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 2
    assert {finding["identity"]["anchor"] for finding in failed["findings"]} == {
        baseline["identity"]["anchor"],
        later["identity"]["anchor"],
    }
    assert json.loads((scan_dir / "coverage.json").read_text())["completeness"] == ("partial")


def test_recovery_does_not_promote_already_retained_historical_finding(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
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
    source_finding = copy.deepcopy(current)
    source_finding["provenance"].pop("sourceFindings", None)
    current["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": source_finding}]

    worker_document = json.loads(worker_result.read_text())
    worker_document["findings"] = [current]
    worker_result.write_text(json.dumps(worker_document))
    checkpoint = copy.deepcopy(worker_document)
    checkpoint["complete"] = False
    checkpoint["findings"] = [checkpoint_historical]
    write_checkpoint(worker_result.parent / "checkpoints", checkpoint)
    committed_standard_reducer(state_dir, codex_home, scan_dir, scan_id, worker_id, worker_result)

    stop_legacy_scan(
        state_dir, scan_id, "Stopped after the canonical result was retained.", status="failed"
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["locations"][0]["startLine"] == 2
    assert retained["severity"]["level"] == "medium"
    assert retained["confidence"]["level"] == "medium"
    assert retained["provenance"]["previousFindings"] == [historical]


def test_recovery_retains_same_worker_checkpoint_version_as_history(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    checkpoint_finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    checkpoint_finding["extensions"] = {"candidateId": "candidate-refined-location"}
    checkpoint_finding["provenance"]["candidateId"] = "candidate-refined-location"
    checkpoint_finding["locations"][0]["startLine"] = 1
    checkpoint_finding["locations"][0]["endLine"] = 2
    checkpoint_finding.pop("identity")
    checkpoint_finding["provenance"]["previousFindings"] = [
        None,
        "malformed checkpoint history",
    ]

    current = copy.deepcopy(checkpoint_finding)
    current["locations"][0]["startLine"] = 2
    current["provenance"]["previousFindings"] = [17]
    source_finding = copy.deepcopy(current)
    source_finding["provenance"].pop("sourceFindings", None)
    current["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": source_finding}]

    worker_document = json.loads(worker_result.read_text())
    worker_document["findings"] = [current]
    worker_result.write_text(json.dumps(worker_document))
    checkpoint = copy.deepcopy(worker_document)
    checkpoint["complete"] = False
    checkpoint["findings"] = [checkpoint_finding]
    write_checkpoint(worker_result.parent / "checkpoints", checkpoint)
    committed_standard_reducer(state_dir, codex_home, scan_dir, scan_id, worker_id, worker_result)

    stop_legacy_scan(
        state_dir, scan_id, "Stopped after the canonical result was retained.", status="failed"
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["locations"][0]["startLine"] == 2
    assert retained["identity"] == {"anchor": "candidate-refined-location"}
    expected_checkpoint = copy.deepcopy(checkpoint_finding)
    expected_checkpoint["provenance"].pop("previousFindings")
    assert retained["provenance"]["previousFindings"] == [expected_checkpoint]


def test_independent_worker_candidate_ids_do_not_share_rejection(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    for ordinal, name in enumerate(("rejecting", "reporting"), 1):
        prompt, output, result = worker_paths(scan_dir, name)
        seed_legacy_worker(
            state_dir,
            scan_id,
            f"00000000-0000-4000-8000-{ordinal:012}",
            kind="discovery",
            status="running",
            prompt=str(prompt),
            directory=str(output),
        )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "findings": [finding] if name == "reporting" else [],
                    "coverage": {
                        "completeness": "complete",
                        "surfaces": []
                        if name == "reporting"
                        else [
                            {
                                "label": "Safe route",
                                "candidateId": "candidate-1",
                                "disposition": "rejected",
                                "notes": "This route enforces containment.",
                            }
                        ],
                        "explicitExclusions": [],
                        "deferred": [],
                    },
                }
            )
        )
    stop_legacy_scan(state_dir, scan_id, "Stopped.", status="failed")
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    canonical_findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert canonical_findings[0]["extensions"]["candidateId"] == "candidate-1"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    rejected = next(item for item in coverage["surfaces"] if item["disposition"] == "rejected")
    assert "previousFindings" not in rejected


@pytest.mark.parametrize(
    ("completeness", "unreadable_checkpoint"),
    [("complete", False), ("partial", False), ("complete", True)],
    ids=["complete", "partial", "checkpoint-warning"],
)
def test_succeeded_legacy_resume_preserves_parent_coverage(
    tmp_path: Path, completeness: str, unreadable_checkpoint: bool
) -> None:
    state, _, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    original = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["completeness"] = completeness
    if completeness == "partial":
        coverage["deferred"] = [
            {"id": "pending-review", "reason": "A synthetic surface remains unreviewed."}
        ]
    coverage_path.write_text(json.dumps(coverage))
    if unreadable_checkpoint:
        checkpoints = scan_dir / "checkpoints"
        checkpoints.mkdir()
        (checkpoints / ("0" * 64 + ".json")).write_text("{incomplete")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at "
            "WHERE scan_id = ?",
            (str(scan_dir / "scan-manifest.json"), scan_id),
        )

    run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)

    checkpoint = json.loads((scan_dir / "artifacts/deep-scan/checkpoint.json").read_text())
    assert checkpoint["terminalReason"] == "saturated"
    retained = checkpoint["aggregate"]["findings"]
    assert len(retained) == 1
    assert retained[0]["identity"] == original["identity"]
    assert retained[0]["locations"] == original["locations"]
    migrated = checkpoint["aggregate"]["coverage"]
    assert migrated == checkpoint["legacy"]["coverage"]
    assert migrated["completeness"] == ("partial" if unreadable_checkpoint else completeness)
    assert not any(item.get("id") == "scan-stopped" for item in migrated["deferred"])
    for item in coverage["deferred"]:
        assert item in migrated["deferred"]
    if unreadable_checkpoint:
        assert any(
            "Preserved unreadable checkpoint" in item["reason"] for item in migrated["deferred"]
        )


def test_legacy_resume_imports_accepted_progress_once(tmp_path: Path) -> None:
    state, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    original = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    document = json.loads(result.read_text())
    document["findings"] = [original]
    result.write_text(json.dumps(document))
    _, reducer, _ = committed_standard_reducer(
        state, codex_home, scan_dir, scan_id, worker_id, result
    )
    reduced = json.loads(reducer.read_text())
    reduced["findings"][0]["summary"] = "Accepted reducer detail retained during migration."
    reducer.write_text(json.dumps(reduced))
    pending_worker_id, pending = accepted_standard_worker(
        state, codex_home, scan_dir, scan_id, name="unmerged"
    )
    unmerged = json.loads(pending.read_text())
    unmerged["findings"] = [{**original, "identity": {"anchor": "unmerged-finding"}}]
    pending.write_text(json.dumps(unmerged))
    snapshots = {path: path.read_bytes() for path in (result, reducer, pending)}
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET discovery_runs_dispatched=3, "
            "consecutive_no_new=2, consecutive_errors=1 WHERE scan_id=?",
            (scan_id,),
        )
        connection.execute("UPDATE scans SET cost_json=? WHERE id=?", (json.dumps(cost), scan_id))
    metadata = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert metadata["threadId"] is None
    assert not (scan_dir / "artifacts/deep-scan/checkpoint.json").exists()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT continuation_thread_id FROM scans WHERE id=?", (scan_id,)
            ).fetchone()[0]
            == "standard-worker-thread"
        )
    resumed = run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)
    assert resumed["threadId"] is None
    checkpoint_path = scan_dir / "artifacts/deep-scan/checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text())
    assert checkpoint["legacy"]["originThreadId"] == "standard-worker-thread"
    assert checkpoint["legacy"]["discoveryRuns"] == 3
    assert checkpoint["legacy"]["cost"] == cost
    assert checkpoint["noNewStreak"] == 2
    assert checkpoint["consecutiveErrors"] == 1
    assert checkpoint["passes"] == checkpoint["mergedScanIds"] == []
    findings = checkpoint["aggregate"]["findings"]
    assert len(findings) == 2
    retained = next(finding for finding in findings if finding["identity"] == original["identity"])
    assert retained["identity"] == original["identity"]
    assert retained["summary"] == reduced["findings"][0]["summary"]
    assert retained["provenance"]["sourceFindings"][0]["finding"]["summary"] == retained["summary"]
    unmerged_finding = next(
        finding for finding in findings if finding["identity"] == {"anchor": "unmerged-finding"}
    )
    assert unmerged_finding["summary"] == original["summary"]
    assert unmerged_finding["provenance"]["workerId"] == pending_worker_id
    assert not any(
        "unmerged" in item["reason"] for item in checkpoint["legacy"]["coverage"]["deferred"]
    )
    assert all(path.read_bytes() == contents for path, contents in snapshots.items())
    checkpoint["mergeFailures"] = 2
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan_id,
        "--artifact-path",
        "artifacts/deep-scan/checkpoint.json",
        input_text=json.dumps(checkpoint),
    )
    first_checkpoint = checkpoint_path.read_bytes()
    run_workbench(state, "set-scan-thread", "--scan-id", scan_id, "--thread-id", "ordinary-merge")
    assert (
        run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)["threadId"]
        == "ordinary-merge"
    )
    assert checkpoint_path.read_bytes() == first_checkpoint
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT deep_scan_owner_thread_id FROM scans WHERE id=?", (scan_id,)
            ).fetchone()[0]
            == "standard-worker-thread"
        )
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1

    failed = run_workbench(
        state, "fail-scan", "--scan-id", scan_id, "--message", "New scan stopped."
    )["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 2
    assert {finding["identity"]["anchor"] for finding in failed["findings"]} == {
        original["identity"]["anchor"],
        "unmerged-finding",
    }
    assert all(path.read_bytes() == contents for path, contents in snapshots.items())


@pytest.mark.parametrize("merge_state", ["buffered", "merging"])
def test_legacy_resume_at_discovery_cap_retains_unmerged_results(
    tmp_path: Path, merge_state: str
) -> None:
    state, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    rejected = {**finding, "identity": {"anchor": "rejected-history"}}
    rejected["extensions"] = {"candidateId": "rejected-candidate"}
    document = json.loads(result.read_text())
    write_checkpoint(
        result.parent / "checkpoints",
        {**document, "complete": False, "findings": [rejected]},
    )
    document["findings"] = [finding]
    document["coverage"]["surfaces"] = [
        {
            "label": "Rejected candidate",
            "candidateId": "rejected-candidate",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    ]
    result.write_text(json.dumps(document))
    saved_result = result.read_bytes()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET discovery_runs_dispatched = 1, max_discovery_runs = 1, "
            "completion_sequence = 1 WHERE scan_id = ?",
            (scan_id,),
        )
        connection.execute(
            "UPDATE deep_scan_workers SET merge_state = ?, completion_sequence = 1 WHERE id = ?",
            (merge_state, worker_id),
        )

    run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)

    checkpoint_path = scan_dir / "artifacts/deep-scan/checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text())
    assert checkpoint["legacy"]["discoveryRuns"] == 1
    assert checkpoint["passes"] == []
    aggregate = checkpoint["aggregate"]
    assert len(aggregate["findings"]) == 1
    retained = aggregate["findings"][0]
    assert retained["identity"] == finding["identity"]
    assert retained["provenance"]["workerId"] == worker_id
    assert (
        retained["provenance"]["sourceFindings"][0]["finding"]["validation"]
        == finding["validation"]
    )
    assert any(row["disposition"] == "rejected" for row in aggregate["coverage"]["surfaces"])

    # With the discovery cap exhausted, the host publishes this migrated aggregate
    # without another child scan or merge; exercise the ordinary completion path.
    checkpoint["terminalReason"] = "capped"
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan_id,
        "--artifact-path",
        "artifacts/deep-scan/checkpoint.json",
        input_text=json.dumps(checkpoint),
    )
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": aggregate["findings"]}))
    coverage_path = scan_dir / "coverage.json"
    coverage = {**json.loads(coverage_path.read_text()), **aggregate["coverage"]}
    coverage_path.write_text(json.dumps(coverage))
    completed = run_workbench(state, "complete-scan", "--scan-id", scan_id)["scan"]
    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert completed["findings"][0]["identity"] == finding["identity"]
    assert finding["title"] in (scan_dir / "report.md").read_text()
    assert result.read_bytes() == saved_result


@pytest.mark.parametrize(
    ("history", "expected"),
    [
        (
            [
                ("dedup", "failed"),
                ("discovery", "succeeded"),
                ("dedup", "canceled"),
                ("dedup", "failed"),
                ("discovery", "failed"),
                ("dedup", "failed"),
            ],
            3,
        ),
        (
            [
                ("dedup", "failed"),
                ("dedup", "queued"),
                ("discovery", "canceled"),
                ("dedup", "failed"),
                ("dedup", "running"),
            ],
            2,
        ),
        (
            [
                ("dedup", "failed"),
                ("dedup", "failed"),
                ("dedup", "succeeded"),
                ("dedup", "failed"),
                ("discovery", "succeeded"),
                ("dedup", "canceled"),
            ],
            1,
        ),
    ],
    ids=["threshold", "under-threshold", "success-resets"],
)
def test_legacy_resume_preserves_merger_failure_streak(
    tmp_path: Path, history: list[tuple[str, str]], expected: int
) -> None:
    state, _, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    for index, (kind, status) in enumerate(history):
        prompt, directory, result = worker_paths(scan_dir, f"history-{index}")
        seed_legacy_worker(
            state,
            scan_id,
            f"history-{index}",
            kind=kind,
            status=status,
            prompt=prompt,
            directory=directory,
        )
        if status == "succeeded":
            result.write_text(
                json.dumps(
                    {
                        "scanId": scan_id,
                        "findings": [],
                        "coverage": {
                            "completeness": "complete",
                            "surfaces": [],
                            "explicitExclusions": [],
                            "deferred": [],
                        },
                    }
                )
            )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at='2000-01-01T00:00:00Z', "
            "consecutive_no_new=2, consecutive_errors=1, stop_after_consecutive_errors=3 "
            "WHERE scan_id=?",
            (scan_id,),
        )
        connection.execute("UPDATE deep_scan_workers SET attempt=4 WHERE scan_id=?", (scan_id,))
        workers_before = connection.execute(
            "SELECT * FROM deep_scan_workers WHERE scan_id=? ORDER BY created_at,id", (scan_id,)
        ).fetchall()
    run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)
    checkpoint = json.loads((scan_dir / "artifacts/deep-scan/checkpoint.json").read_text())
    assert checkpoint["mergeFailures"] == expected
    assert checkpoint["consecutiveErrors"] == 1
    assert checkpoint["noNewStreak"] == 2
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT * FROM deep_scan_workers WHERE scan_id=? ORDER BY created_at,id", (scan_id,)
            ).fetchall()
            == workers_before
        )
        assert connection.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone() == (
            "running",
        )


def test_legacy_conversion_crash_does_not_resume_old_conversation(tmp_path: Path) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "interrupt_conversion.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts)!r})\n"
        "import workbench_db, workbench_saved_results\n"
        "original = workbench_saved_results.write_scan_local_bytes\n"
        "def interrupt(directory, relative, payload):\n"
        "    if relative == 'artifacts/deep-scan/checkpoint.json':\n"
        "        raise OSError('injected checkpoint interruption')\n"
        "    return original(directory, relative, payload)\n"
        "workbench_saved_results.write_scan_local_bytes = interrupt\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    failed = subprocess.run(
        [sys.executable, str(wrapper), "get-cli-scan-resume", "--migrate", "--scan-id", scan_id],
        env={**os.environ, "CODEX_HOME": str(codex_home), "CODEX_SECURITY_STATE_DIR": str(state)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode != 0
    assert "injected checkpoint interruption" in failed.stderr
    assert not (scan_dir / "artifacts/deep-scan/checkpoint.json").exists()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT continuation_thread_id,deep_scan_owner_thread_id FROM scans WHERE id=?",
            (scan_id,),
        ).fetchone() == (None, "standard-worker-thread")
    resumed = run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)
    assert resumed["threadId"] is None
    assert (
        json.loads((scan_dir / "artifacts/deep-scan/checkpoint.json").read_text())["version"] == 2
    )


@pytest.mark.parametrize("generation", [1, 2])
def test_legacy_migration_waits_for_existing_owner_lease(tmp_path: Path, generation: int) -> None:
    state, _, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    timestamp = datetime.now(timezone.utc)
    expired = (timestamp - timedelta(minutes=5)).isoformat()
    prompt, directory, _ = worker_paths(scan_dir, "active")
    seed_legacy_worker(
        state,
        scan_id,
        str(uuid.uuid4()),
        kind="discovery",
        status="running",
        prompt=prompt,
        directory=directory,
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET coordinator_generation=?, updated_at=? WHERE scan_id=?",
            (generation, timestamp.isoformat() if generation == 1 else expired, scan_id),
        )
    heartbeat = scan_dir / f"artifacts/deep_discovery/coordinator-heartbeat-{generation}.json"
    if generation == 2:
        heartbeat.write_text(
            json.dumps({"coordinatorGeneration": generation, "updatedAt": timestamp.isoformat()})
        )
    rejected = run_workbench(
        state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id, check=False
    )
    assert "previous Deep Scan owner is still active" in rejected["stderr"]
    assert not (scan_dir / "artifacts/deep-scan/checkpoint.json").exists()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT continuation_thread_id FROM scans WHERE id=?", (scan_id,)
            ).fetchone()[0]
            == "standard-worker-thread"
        )
        connection.execute(
            "UPDATE deep_scan_runs SET updated_at=? WHERE scan_id=?", (expired, scan_id)
        )
    if generation == 2:
        heartbeat.write_text(
            json.dumps({"coordinatorGeneration": generation, "updatedAt": expired})
        )
    assert (
        run_workbench(state, "get-cli-scan-resume", "--migrate", "--scan-id", scan_id)["threadId"]
        is None
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status,cancel_requested,coordinator_generation FROM deep_scan_runs WHERE scan_id=?",
            (scan_id,),
        ).fetchone() == ("interrupted", 1, generation + 1)


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
