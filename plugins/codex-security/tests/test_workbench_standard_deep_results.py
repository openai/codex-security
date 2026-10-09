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
from workbench_test_support import (
    BUDGET_COST,
    begin_deep_scan,
    cancel_scan,
    claim_deep_scan_dedup,
    commit_deep_dedup,
    fail_deep_scan,
    fail_scan,
    finish_deep_scan,
    get_deep_scan,
    get_scan,
    preserve_scan_results,
    replay_saved_results,
    run_workbench,
    saved_binding,
    saved_coverage,
    saved_discovery_worker,
    saved_draft,
    scan_command,
    upsert_deep_worker,
    worker_paths,
    workspace_command,
    write_checkpoint,
    write_completed_contract,
)

scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))
import workbench_saved_results


@pytest.mark.parametrize("termination", ["failed", "interrupted", "canceled"])
def test_stopped_deep_scan_ignores_late_worker_checkpoints_without_reducer(
    tmp_path: Path,
    termination: str,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "threatModel": {
            "summary": "Queue producers cross a service boundary.",
            "scope": {"includePaths": ["app.py"]},
            "origin": "generated",
        },
        "findings": [finding],
        "coverage": saved_coverage(
            deferred=[
                {
                    "candidateId": "pending-query",
                    "reason": "Query validation remains pending.",
                    "paths": ["app.py"],
                }
            ]
        ),
    }
    checkpoint_dir = result_path.parent / "checkpoints"
    write_checkpoint(checkpoint_dir, checkpoint)
    revised = copy.deepcopy(checkpoint)
    revised["threatModel"]["summary"] = "Queue consumers cross a service boundary."
    write_checkpoint(checkpoint_dir, revised)
    head = max(checkpoint_dir.glob("*.json"))
    latest_model = json.loads(head.read_text())["threatModel"]
    (result_path.parent / "checkpoint-head.json").write_text(json.dumps({"checkpoint": head.name}))
    # The latest incomplete attempt need not be parseable for a saved checkpoint to survive.
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )
    environment = {"CODEX_HOME": str(codex_home)}
    if termination == "canceled":
        cancel_scan(state_dir, scan_id, "standard-worker-thread", environment=environment)
    else:
        fail_deep_scan(state_dir, codex_home, scan_id, deep_status=termination)

    stopped = get_scan(state_dir, scan_id[:12])["scan"]
    assert stopped["progress"]["status"] == ("canceled" if termination == "canceled" else "failed")
    assert "threatModel" not in stopped
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"] == {
        **latest_model,
        "origin": "recovered",
    }
    assert stopped["threatModelProvenance"]["provisional"] is True
    model_document = (scan_dir / "threatmodel.md").read_text()
    assert latest_model["summary"] in model_document
    assert "Model scope: app.py" in model_document
    assert "Model origin: recovered" in model_document
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
    recovery_needed = get_scan(state_dir, scan_id)["scan"]
    assert recovery_needed["resultsRecoveryNeeded"] is (termination != "canceled")
    if termination == "canceled":
        rejected = scan_command(state_dir, "recover-scan-results", scan_id, check=False)
        assert rejected["returncode"] != 0
        assert "Canceled scans cannot recover" in str(rejected["stderr"])
    wrong_owner = preserve_scan_results(state_dir, scan_id, "not-the-owner", check=False)
    assert wrong_owner["returncode"] != 0
    assert (scan_dir / "scan-manifest.json").read_bytes() == first_seal
    refreshed = preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment=environment
    )["scan"]
    expected_count = 1
    assert refreshed["findingCount"] == expected_count
    assert len({finding["occurrenceId"] for finding in refreshed["findings"]}) == expected_count
    assert refreshed["findings"][0]["locations"][0]["startLine"] != 91
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    assert seal == first_seal
    assert get_scan(state_dir, scan_id)["scan"]["findingCount"] == expected_count
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal


@pytest.mark.parametrize("head_available", [True, False], ids=["head", "fallback"])
@pytest.mark.parametrize("legacy_retry", [False, True], ids=["new-freeze", "legacy-freeze"])
@pytest.mark.parametrize("result_state", ["unreadable", "incomplete", "complete"])
def test_stopped_model_selection_survives_publication_retry(
    tmp_path: Path, head_available: bool, legacy_retry: bool, result_state: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = standard_contract(tmp_path, scan_id, target)
    checkpoint = json.loads(result_path.read_text())
    checkpoint["complete"] = result_state == "complete"
    checkpoint["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    checkpoint_dir = result_path.parent / "checkpoints"
    for summary in ("Queue producers cross a boundary.", "Queue consumers cross a boundary."):
        checkpoint["threatModel"] = {"summary": summary}
        write_checkpoint(checkpoint_dir, checkpoint)
    selected = (max if head_available else min)(checkpoint_dir.glob("*.json"))
    head_path = result_path.parent / "checkpoint-head.json"
    if head_available:
        head_path.write_text(json.dumps({"checkpoint": selected.name}))
    if result_state != "unreadable":
        stale = {**checkpoint, "threatModel": {"summary": "The earlier worker model."}}
        result_path.write_text(json.dumps(stale))
        if not head_available:
            selected = result_path
    else:
        result_path.write_text("{incomplete")
    if head_available and result_state == "complete":
        os.utime(result_path, ns=(1_000_000_000, 1_000_000_000))
        os.utime(head_path, ns=(2_000_000_000, 2_000_000_000))
    expected_model = {**json.loads(selected.read_text())["threatModel"], "origin": "recovered"}

    wrapper = tmp_path / "fail_model_publication.py"
    failed = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n",
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
    )
    assert failed.returncode == 0, failed.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        frozen = json.loads(
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
        )
    assert frozen["threatModelSource"] == selected.relative_to(scan_dir).as_posix()
    if legacy_retry:
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
                (json.dumps(frozen["sources"]), scan_id),
            )
        retry = subprocess.run(
            [
                sys.executable,
                str(wrapper),
                "preserve-scan-results",
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
            check=False,
        )
        assert retry.returncode != 0
        assert "injected publication failure" in retry.stderr
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            assert (
                json.loads(
                    connection.execute(
                        "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
                    ).fetchone()[0]
                )
                == frozen
            )

    checkpoint["threatModel"] = {"summary": "The later worker model."}
    late = write_checkpoint(checkpoint_dir, checkpoint)
    head_path.write_text(json.dumps({"checkpoint": late.name}))
    environment = {"CODEX_HOME": str(codex_home)}
    retried = preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment=environment
    )["scan"]
    manifest_path = scan_dir / "scan-manifest.json"
    published = json.loads(manifest_path.read_text())["scan"]
    assert published["threatModel"] == expected_model
    assert expected_model["summary"] in (scan_dir / "threatmodel.md").read_text()
    assert published["preservedSources"] == frozen["sources"]
    assert late.relative_to(scan_dir).as_posix() not in published["preservedSources"]
    assert retried["findingCount"] == 1

    # Older plain-map rows still refresh the existing sealed result unchanged.
    first_seal = manifest_path.read_bytes()
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
            (json.dumps(frozen["sources"]), scan_id),
        )
    preserve_scan_results(state_dir, scan_id, "standard-worker-thread", environment=environment)
    assert manifest_path.read_bytes() == first_seal
    recovered = scan_command(state_dir, "recover-scan-results", scan_id, environment=environment)[
        "scan"
    ]
    published = json.loads(manifest_path.read_text())["scan"]
    assert published["threatModel"] == {**checkpoint["threatModel"], "origin": "recovered"}
    assert late.relative_to(scan_dir).as_posix() in published["preservedSources"]
    assert recovered["findingCount"] == 1


def test_scan_reads_require_explicit_late_result_recovery(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    checkpoint = saved_draft(scan_id, findings=[finding], completeness="partial")
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    fail_deep_scan(state_dir, codex_home, scan_id, deep_status="failed")
    stopped = get_scan(state_dir, scan_id)["scan"]
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

    reopened = workspace_command(
        state_dir, "get-workspace", workspace_id, environment={"CODEX_HOME": str(codex_home)}
    )
    assert reopened["results"]["findingCount"] == 1
    stale = get_scan(state_dir, scan_id)["scan"]
    assert stale["findingCount"] == 1
    assert stale["resultsRecoveryNeeded"] is True
    assert scan_command(state_dir, "list-findings", scan_id)["findingsPage"]["total"] == 1

    recovered = scan_command(
        state_dir, "recover-scan-results", scan_id, environment={"CODEX_HOME": str(codex_home)}
    )

    assert recovered["scan"]["findingCount"] == 2
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    assert len(json.loads((scan_dir / "findings.json").read_text())["findings"]) == 2


def test_explicit_recovery_rejects_changed_frozen_source(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    checkpoint = saved_draft(scan_id, findings=[finding], completeness="partial")
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    fail_deep_scan(state_dir, codex_home, scan_id, deep_status="failed")
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
    assert get_scan(state_dir, scan_id)["scan"]["resultsRecoveryNeeded"] is True

    rejected = scan_command(
        state_dir,
        "recover-scan-results",
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
    contract_dir = standard_contract(tmp_path, scan_id, target)
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    parent_finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]

    wrapper = tmp_path / "fail_before_sources_are_frozen.py"
    failed = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "def fail_before_sources_are_frozen(*args, **kwargs):\n"
        "    raise OSError('injected early publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_before_sources_are_frozen\n",
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
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

    recovered = scan_command(
        state_dir, "recover-scan-results", scan_id, environment={"CODEX_HOME": str(codex_home)}
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

    fail_deep_scan(state_dir, codex_home, scan_id)
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"] == {}
    )

    late_finding = copy.deepcopy(parent_finding)
    late_finding["occurrenceId"] = "occ_111111111111111111111111"
    late_finding["identity"]["anchor"] = "late-checkpoint"
    late_finding["ruleId"] = "late.checkpoint"
    late_finding["title"] = "Late checkpoint finding"
    late = saved_draft(scan_id, findings=[late_finding], completeness="partial")
    write_checkpoint(result_path.parent / "checkpoints", late)

    manifest_before_failed_recovery = (scan_dir / "scan-manifest.json").read_bytes()
    findings_before_failed_recovery = (scan_dir / "findings.json").read_bytes()
    wrapper = tmp_path / "fail_parent_checkpoint_write.py"
    failed = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "original_write = workbench_saved_results.write_scan_local_bytes\n"
        "def fail_parent_checkpoint(scan_dir, relative_path, payload, **kwargs):\n"
        "    if relative_path.startswith('checkpoints/'):\n"
        "        raise OSError('injected parent checkpoint failure')\n"
        "    return original_write(scan_dir, relative_path, payload, **kwargs)\n"
        "workbench_saved_results.write_scan_local_bytes = fail_parent_checkpoint\n",
        "recover-scan-results",
        "--scan-id",
        scan_id,
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
    write_checkpoint(result_path.parent / "attempts" / "attempt-02" / "checkpoints", later)

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
    failed = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "def fail_after_sources_are_frozen(prepared, *, projection_warnings=None):\n"
        "    raise OSError('injected late publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_after_sources_are_frozen\n",
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
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
    published_scan = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    published_sources = published_scan["preservedSources"]
    assert published_scan["threatModel"] == {**late["threatModel"], "origin": "recovered"}
    frozen_state = json.loads(frozen_before)
    frozen_sources = frozen_state["sources"]
    model_source = result_path.relative_to(scan_dir).as_posix()
    assert frozen_state["threatModelSource"] == model_source
    assert published_sources.items() >= frozen_sources.items()
    parent_sources = published_sources.keys() - frozen_sources.keys()
    assert any(path.startswith("checkpoint-heads/") for path in parent_sources)
    parent_source = next(path for path in parent_sources if path.startswith("checkpoints/"))
    assert (
        json.loads((scan_dir / "checkpoint-head.json").read_text())["checkpoint"]
        == Path(parent_source).name
    )
    assert parent_source.startswith("checkpoints/")
    assert Path(parent_source).stem == published_sources[parent_source]
    ordering = next(path for path in parent_sources if path.startswith("source-order/"))
    assert json.loads((scan_dir / ordering).read_text())["sources"][parent_source] == {
        "digest": published_sources[parent_source],
        "observedAtNs": str((scan_dir / parent_source).stat().st_mtime_ns),
    }
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert json.loads(
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()[0]
        ) == {"sources": published_sources, "threatModelSource": model_source}


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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    checkpoint = saved_draft(scan_id, findings=[finding], completeness="partial")
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    fail_deep_scan(state_dir, codex_home, scan_id, deep_status="failed")
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

    fail_deep_scan(state_dir, codex_home, scan_id, deep_status="failed")
    failed = get_scan(state_dir, scan_id)["scan"]

    assert any("Preserved unreadable checkpoint" in warning for warning in failed["warnings"])


def test_malformed_current_finding_does_not_override_worker_rejection(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
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

    fail_deep_scan(
        state_dir,
        codex_home,
        scan_id,
        message="Stopped after rejecting a malformed current finding.",
    )
    failed = get_scan(state_dir, scan_id)["scan"]

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

    fail_deep_scan(state_dir, codex_home, scan_id)
    failed = get_scan(state_dir, scan_id)["scan"]

    assert failed["findingCount"] == 1
    assert failed["findings"][0]["locations"][0]["path"] == "src/app.py"


def test_canceled_scan_retries_failed_publication_from_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    checkpoint = saved_draft(scan_id, findings=[finding], completeness="partial")
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )

    wrapper = tmp_path / "fail_canceled_publication.py"
    canceled = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n",
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
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

    preserved = preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
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
    tmp_path: Path,
    deep_status: str,
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    original = "Saved result publication failed: genuine worker failure"
    publication = "Saved result publication failed: stale publication timeout"
    environment = {"CODEX_HOME": str(codex_home)}
    fail_deep_scan(state_dir, codex_home, scan_id, message=original, deep_status=deep_status)

    if deep_status == "failed":
        scan_command(
            state_dir,
            "record-deep-scan-publication-failure",
            scan_id,
            "--message",
            publication,
            environment=environment,
        )
        after_race = get_deep_scan(
            state_dir, scan_id, "standard-worker-thread", environment=environment
        )["deepScan"]
        assert after_race["error"] == original

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET publication_error_message = ? WHERE scan_id = ?",
            (publication, scan_id),
        )
    before_recovery = get_deep_scan(
        state_dir, scan_id, "standard-worker-thread", environment=environment
    )["deepScan"]
    assert publication in before_recovery["error"]
    assert original in before_recovery["error"]

    scan_command(state_dir, "recover-scan-results", scan_id, environment=environment)
    recovered = get_deep_scan(
        state_dir, scan_id, "standard-worker-thread", environment=environment
    )["deepScan"]
    assert recovered["error"] == original
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT publication_error_message FROM deep_scan_runs WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()[0]
            is None
        )


def test_canceled_scan_reports_noop_coordinator_publication(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    result_path.write_text("{incomplete")

    wrapper = tmp_path / "fail_before_canceled_sources_are_frozen.py"
    canceled = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "def fail_before_sources_are_frozen(*args, **kwargs):\n"
        "    raise OSError('injected early publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_before_sources_are_frozen\n",
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
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
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = standard_contract(tmp_path, scan_id, target)
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
    scan_command(state_dir, "prepare-scan-completion", scan_id)
    assert json.loads(manifest_path.read_text())["scan"]["status"] == "completed"

    wrapper = tmp_path / "fail_prepared_canceled_publication.py"
    canceled = run_workbench_with_fault(
        wrapper,
        state_dir,
        codex_home,
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n",
        "cancel-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
    )
    assert canceled.returncode == 0, canceled.stderr
    assert json.loads(manifest_path.read_text())["scan"]["status"] == "completed"

    preserve_scan_results(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )

    assert json.loads(manifest_path.read_text())["scan"]["status"] == "canceled"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]


def test_stopped_deep_scan_recovers_when_parent_manifest_has_no_scan(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = standard_contract(tmp_path, scan_id, target)
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    result = json.loads(result_path.read_text())
    result["findings"] = [finding]
    result_path.write_text(json.dumps(result))
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"documentType": "broken-parent"}))

    fail_deep_scan(state_dir, codex_home, scan_id, deep_status="failed")

    stopped = get_scan(state_dir, scan_id)["scan"]
    assert stopped["findingCount"] == 1
    assert any("has no scan object" in warning for warning in stopped["warnings"])
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == ("failed")


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


def standard_contract(tmp_path: Path, scan_id: str, target: Path) -> Path:
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    return contract_dir


def standard_finding(tmp_path: Path, scan_id: str, target: Path) -> dict[str, object]:
    contract_dir = standard_contract(tmp_path, scan_id, target)
    return json.loads((contract_dir / "findings.json").read_text())["findings"][0]


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
    environment = {"CODEX_HOME": str(codex_home)}

    if budget:
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir(mode=0o700)
        registered = run_workbench(
            state_dir,
            "register-cli-scan",
            "--scan-dir",
            str(scan_dir),
            "--repository",
            str(target),
            "--recipe-json",
            json.dumps(
                {
                    "config": {},
                    "mode": "deep",
                    "repository": str(target),
                    "target": {"kind": "repository", "paths": []},
                    "maxCostUsd": 0.005,
                }
            ),
        )
        scan_id = str(registered["scanId"])
        begin_deep_scan(
            state_dir, "standard-worker-thread", "--scan-id", scan_id, environment=environment
        )
    else:
        begun = begin_deep_scan(
            state_dir,
            "standard-worker-thread",
            "--target-path",
            str(target),
            "--scope",
            ".",
            "--scan-root",
            str(tmp_path / "scans"),
            "--available-parallelism",
            "16",
            environment=environment,
        )["deepScan"]
        scan_id = str(begun["scanId"])
        scan_dir = Path(str(begun["scanDir"]))

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
    base_args = (
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "1",
    )
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(state_dir, *base_args, "--status", "running", environment=environment)
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
    run_workbench(
        state_dir,
        *base_args,
        "--status",
        "succeeded",
        "--result-manifest-path",
        str(result_path),
        environment=environment,
    )
    return worker_id, result_path


def running_standard_reducer(
    state_dir: Path,
    codex_home: Path,
    scan_dir: Path,
    scan_id: str,
    discovery_worker_id: str,
    *,
    name: str = "standard-reducer",
    attempt: str = "1",
    additional_worker_ids: tuple[str, ...] = (),
) -> tuple[str, Path]:
    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, name)
    environment = {"CODEX_HOME": str(codex_home)}
    input_worker_args = [
        argument
        for worker_id in (discovery_worker_id, *additional_worker_ids)
        for argument in ("--input-worker-id", worker_id)
    ]
    claim_deep_scan_dedup(
        state_dir,
        scan_id,
        reducer_id,
        str(prompt_path),
        str(artifact_dir),
        *input_worker_args,
        environment=environment,
    )
    upsert_deep_worker(
        state_dir,
        scan_id,
        reducer_id,
        "dedup",
        "running",
        str(prompt_path),
        str(artifact_dir),
        "--attempt",
        attempt,
        environment=environment,
    )
    return reducer_id, result_path


def committed_standard_reducer(
    state_dir: Path,
    codex_home: Path,
    scan_dir: Path,
    scan_id: str,
    discovery_worker_id: str,
    discovery_result: Path,
    *,
    additional_worker_ids: tuple[str, ...] = (),
) -> tuple[str, Path, dict[str, object]]:
    reducer_id, result_path = running_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        discovery_worker_id,
        additional_worker_ids=additional_worker_ids,
    )
    environment = {"CODEX_HOME": str(codex_home)}
    result_path.write_text(discovery_result.read_text())
    committed = commit_deep_dedup(
        state_dir, scan_id, reducer_id, str(result_path), "0", environment=environment
    )["deepScan"]
    return reducer_id, result_path, committed


def standard_parent_results_fixture(
    tmp_path: Path, *, budget: bool = False
) -> tuple[Path, Path, Path, Path, str]:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, budget=budget)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    return state_dir, codex_home, target, scan_dir, scan_id


def test_failure_preserves_last_committed_reducer_without_parent_draft(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = standard_contract(tmp_path, scan_id, target)
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
    fail_deep_scan(state_dir, codex_home, scan_id, message="Later reducer failed.")
    failed = get_scan(state_dir, scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 1
    assert failed["findings"][0]["summary"] == reduced["findings"][0]["summary"]


@pytest.mark.parametrize("tied_head", [False, True])
def test_stopped_rejection_recovers_malformed_parent_surfaces(
    tmp_path: Path, tied_head: bool
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = standard_contract(tmp_path, scan_id, target)
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
    if tied_head:
        parent_checkpoint = write_checkpoint(
            scan_dir / "checkpoints",
            {
                "scanId": scan_id,
                "complete": True,
                "findings": [finding],
                "coverage": {**malformed_coverage, "surfaces": []},
            },
        )
        head = scan_dir / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": parent_checkpoint.name}))
        os.utime(head, ns=(200, 200))
        os.utime(scan_dir / "coverage.json", ns=(200, 200))
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

    fail_deep_scan(
        state_dir, codex_home, scan_id, message="Stopped after rejecting a checkpointed candidate."
    )

    failed = get_scan(state_dir, scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert isinstance(coverage["surfaces"], list)


def test_stopped_scan_rebinds_prepared_completion_seal(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = standard_contract(tmp_path, scan_id, target)
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
    scan_command(state_dir, "prepare-scan-completion", scan_id)
    prepared_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert prepared_manifest["scan"]["status"] == "completed"

    fail_scan(
        state_dir,
        scan_id,
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
    contract_dir = standard_contract(tmp_path, scan_id, target)
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
    fail_deep_scan(state_dir, codex_home, scan_id, message="Stopped with a provisional finding.")
    failed = get_scan(state_dir, scan_id)["scan"]
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


@pytest.mark.parametrize("explicit_complete", [True, False], ids=["explicit", "default"])
@pytest.mark.parametrize(
    "head_time",
    [3_000_000_000, 2_000_000_000, 1_000_000_000],
    ids=["newer-head", "tied-head", "newer-result"],
)
def test_complete_worker_model_uses_latest_terminal_source(
    tmp_path: Path, head_time: int, explicit_complete: bool
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    result = json.loads(result_path.read_text())
    checkpoint = copy.deepcopy(result)
    if explicit_complete:
        checkpoint["complete"] = True
    checkpoint["threatModel"] = {"summary": "The revised completed worker model."}
    head = write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    head_path = result_path.parent / "checkpoint-head.json"
    head_path.write_text(json.dumps({"checkpoint": head.name}))
    # Timestamp ordering represents an interruption between head and result publication,
    # or a successfully replaced result whose older head remains available.
    os.utime(result_path, ns=(2_000_000_000, 2_000_000_000))
    newer_head = head_time >= 2_000_000_000
    os.utime(head_path, ns=(head_time, head_time))

    scan_command(
        state_dir,
        "fail-deep-scan",
        scan_id,
        "--message",
        "Stopped after the worker completed.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    expected = checkpoint["threatModel"] if newer_head else result["threatModel"]
    published = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    assert published["threatModel"] == {**expected, "origin": "recovered"}
    assert expected["summary"] in (scan_dir / "threatmodel.md").read_text()
    if newer_head:
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            frozen = json.loads(
                connection.execute(
                    "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()[0]
            )
        assert frozen["threatModelSource"] == head.relative_to(scan_dir).as_posix()
        assert frozen["sources"] == published["preservedSources"]


def test_complete_worker_supersedes_obsolete_checkpoint_coverage(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    completed_model = json.loads(result_path.read_text())["threatModel"]
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "threatModel": {"summary": "An obsolete worker model."},
        "findings": [],
        "coverage": saved_coverage(
            surfaces=[
                {
                    "id": "obsolete-surface",
                    "label": "Obsolete review",
                    "disposition": "needs_follow_up",
                    "receiptRefs": [],
                }
            ],
            deferred=[{"id": "obsolete-work", "reason": "This was later completed."}],
        ),
    }
    checkpoints = result_path.parent / "checkpoints"
    head = write_checkpoint(checkpoints, checkpoint)
    (result_path.parent / "checkpoint-head.json").write_text(json.dumps({"checkpoint": head.name}))

    # This accepted checkpoint predates the successful result; a newer head reopens work.
    for path in (head, result_path.parent / "checkpoint-head.json"):
        os.utime(path, ns=(100, 100))
    os.utime(result_path, ns=(200, 200))

    fail_deep_scan(state_dir, codex_home, scan_id, message="Stopped after the worker completed.")

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert not any(item.get("id") == "obsolete-surface" for item in coverage["surfaces"])
    assert not any(item.get("id") == "obsolete-work" for item in coverage["deferred"])
    model = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"]
    assert model == {**completed_model, "origin": "recovered"}


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
    checkpoint = write_checkpoint(
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

    os.utime(checkpoint, (1, 1))
    os.utime(coverage_path, (2, 2))

    fail_deep_scan(
        state_dir, codex_home, scan_id, message="Stopped after the final partial parent draft."
    )

    recovered = json.loads(coverage_path.read_text())
    assert recovered.get("openQuestions", []) == []


def test_canceled_reducer_checkpoint_supersedes_discovery_result(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    baseline = standard_finding(tmp_path, scan_id, target)
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

    reducer_id, reducer_result = running_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, name="canceled-reducer", attempt="1"
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

    fail_deep_scan(state_dir, codex_home, scan_id, message="Canceled after reducer validation.")

    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert findings[0]["summary"] == reduced["findings"][0]["summary"]
    assert coverage["surfaces"][0]["notes"] == "Reducer-validated merged evidence."


def test_archived_reducer_checkpoint_supersedes_discovery_result(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    discovery = json.loads(worker_result.read_text())
    discovery["findings"] = [finding]
    worker_result.write_text(json.dumps(discovery))

    reducer_id, reducer_result = running_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, name="archived-reducer", attempt="2"
    )
    reduced = copy.deepcopy(discovery)
    reduced["findings"][0]["summary"] = "The archived reducer retained the newest evidence."
    archived = reducer_result.parent / "attempts" / "attempt-01"
    archived.mkdir(parents=True)
    (archived / "result.json").write_text(json.dumps(reduced))
    write_checkpoint(archived / "checkpoints", reduced)
    reducer_result.write_text("{incomplete current reducer")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'canceled', completed_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), reducer_id),
        )

    fail_deep_scan(
        state_dir,
        codex_home,
        scan_id,
        message="Canceled after archiving a validated reducer attempt.",
    )

    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["summary"] == reduced["findings"][0]["summary"]


def test_recovery_selects_strongest_same_finding_checkpoint(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    weak = standard_finding(tmp_path, scan_id, target)
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
            json.dumps(saved_draft(scan_id, findings=[finding], completeness="partial"))
        )
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )

    fail_deep_scan(state_dir, codex_home, scan_id, message="Stopped between checkpoints.")

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
    baseline = standard_finding(tmp_path, scan_id, target)
    environment = {"CODEX_HOME": str(codex_home)}

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
    claim_deep_scan_dedup(
        state_dir,
        scan_id,
        reducer_id,
        str(prompt_path),
        str(artifact_dir),
        "--input-worker-id",
        second_worker_id,
        environment=environment,
    )
    base_args = (
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--kind",
        "dedup",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "1",
    )
    run_workbench(state_dir, *base_args, "--status", "running", environment=environment)
    run_workbench(
        state_dir,
        *base_args,
        "--status",
        "failed",
        "--error-message",
        "Synthetic reducer process failure.",
        environment=environment,
    )

    fail_deep_scan(state_dir, codex_home, scan_id, message="Later reducers failed.")

    failed = get_scan(state_dir, scan_id)["scan"]
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
    historical = standard_finding(tmp_path, scan_id, target)
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

    fail_deep_scan(
        state_dir, codex_home, scan_id, message="Stopped after the canonical result was retained."
    )

    failed = get_scan(state_dir, scan_id)["scan"]
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
    checkpoint_finding = standard_finding(tmp_path, scan_id, target)
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

    fail_deep_scan(
        state_dir, codex_home, scan_id, message="Stopped after the canonical result was retained."
    )

    failed = get_scan(state_dir, scan_id)["scan"]
    assert failed["findingCount"] == 1
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["locations"][0]["startLine"] == 2
    assert retained["identity"] == {"anchor": "candidate-refined-location"}
    expected_checkpoint = copy.deepcopy(checkpoint_finding)
    expected_checkpoint["provenance"].pop("previousFindings")
    assert retained["provenance"]["previousFindings"] == [expected_checkpoint]


def test_independent_worker_candidate_ids_do_not_share_rejection(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    finding = standard_finding(tmp_path, scan_id, target)
    finding["extensions"] = {"candidateId": "candidate-1"}
    environment = {"CODEX_HOME": str(codex_home)}
    for ordinal, name in enumerate(("rejecting", "reporting"), 1):
        prompt, output, result = worker_paths(scan_dir, name)
        upsert_deep_worker(
            state_dir,
            scan_id,
            f"00000000-0000-4000-8000-{ordinal:012}",
            "discovery",
            "running",
            str(prompt),
            str(output),
            "--attempt",
            "1",
            environment=environment,
        )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "findings": [finding] if name == "reporting" else [],
                    "coverage": saved_coverage(
                        surfaces=[]
                        if name == "reporting"
                        else [
                            {
                                "label": "Safe route",
                                "candidateId": "candidate-1",
                                "disposition": "rejected",
                                "notes": "This route enforces containment.",
                            }
                        ]
                    ),
                }
            )
        )
    fail_deep_scan(state_dir, codex_home, scan_id, message="Stopped.")
    failed = get_scan(state_dir, scan_id)["scan"]
    assert failed["findingCount"] == 1
    canonical_findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert canonical_findings[0]["extensions"]["candidateId"] == "candidate-1"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    rejected = next(item for item in coverage["surfaces"] if item["disposition"] == "rejected")
    assert "previousFindings" not in rejected


def test_standard_worker_results_commit_and_recover_without_discovery_ledgers(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    reducer_id, reducer_result, committed = committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )

    assert committed["canonicalArtifacts"] is None
    assert committed["completionSequence"] == 1
    workers = {worker["id"]: worker for worker in committed["workers"]}
    assert workers[worker_id]["mergeState"] == "merged"
    assert workers[worker_id]["resultManifestPath"] == str(worker_result)
    assert workers[reducer_id]["resultManifestPath"] == str(reducer_result)
    assert not (scan_dir / "artifacts" / "02_discovery").exists()

    recovered = get_deep_scan(
        state_dir, scan_id, "standard-worker-thread", environment={"CODEX_HOME": str(codex_home)}
    )["deepScan"]
    assert recovered["canonicalArtifacts"] is None
    assert recovered["workers"] == committed["workers"]


def test_standard_worker_results_finish_with_only_canonical_parent_manifest(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = standard_parent_results_fixture(tmp_path)
    manifest_path = scan_dir / "scan-manifest.json"

    finished = finish_deep_scan(
        state_dir,
        scan_id,
        "capped",
        str(manifest_path),
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]

    assert finished["status"] == "succeeded"
    assert finished["manifestPath"] == str(manifest_path)
    assert finished["canonicalArtifacts"] is None
    assert not (scan_dir / "artifacts" / "02_discovery").exists()


@pytest.mark.parametrize(
    "incidental_artifacts",
    ("inventory", "ledger", "both", "inventory_symlink", "ledger_symlink"),
)
def test_standard_worker_results_ignore_incidental_legacy_discovery_artifacts(
    tmp_path: Path, incidental_artifacts: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    discovery_dir = scan_dir / "artifacts" / "02_discovery"
    discovery_dir.mkdir(parents=True)
    inventory = discovery_dir / "in_scope_files.txt"
    ledger = discovery_dir / "candidate_ledger.jsonl"
    outside = tmp_path / "outside-discovery-artifact"
    outside.write_text("unrelated legacy artifact\n")

    if incidental_artifacts in {"inventory", "both"}:
        inventory.write_text("unrelated.py\n")
    elif incidental_artifacts == "inventory_symlink":
        inventory.symlink_to(outside)
    if incidental_artifacts in {"ledger", "both"}:
        ledger.write_text("unrelated legacy candidate\n")
    elif incidental_artifacts == "ledger_symlink":
        ledger.symlink_to(outside)

    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    _, _, committed = committed_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, worker_result
    )
    assert committed["canonicalArtifacts"] is None

    def recovered() -> dict[str, object]:
        return get_deep_scan(
            state_dir,
            scan_id,
            "standard-worker-thread",
            environment={"CODEX_HOME": str(codex_home)},
        )["deepScan"]

    assert recovered()["canonicalArtifacts"] is None
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    finished = finish_deep_scan(
        state_dir,
        scan_id,
        "capped",
        str(scan_dir / "scan-manifest.json"),
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]
    assert finished["status"] == "succeeded"
    assert finished["canonicalArtifacts"] is None
    assert recovered()["canonicalArtifacts"] is None
    assert outside.read_text() == "unrelated legacy artifact\n"
    if incidental_artifacts.endswith("_symlink"):
        assert (inventory if incidental_artifacts.startswith("inventory") else ledger).is_symlink()


def test_standard_worker_deadline_can_finish_without_any_completed_worker(
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
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["completeness"] = "partial"
    coverage["surfaces"] = []
    coverage["deferred"] = [
        {
            "reason": "The configured discovery time limit elapsed before any source review completed."
        }
    ]
    coverage_path.write_text(json.dumps(coverage))
    manifest_path = scan_dir / "scan-manifest.json"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(hours=97)).isoformat(), scan_id),
        )

    finished = finish_deep_scan(
        state_dir,
        scan_id,
        "capped",
        str(manifest_path),
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]

    assert finished["status"] == "succeeded"
    assert finished["completionSequence"] == 0
    assert finished["canonicalArtifacts"] is None
    assert not (scan_dir / "artifacts" / "02_discovery").exists()


def test_standard_worker_finish_preserves_running_state_when_parent_draft_is_incomplete(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = standard_parent_results_fixture(tmp_path)
    (scan_dir / "findings.json").unlink()

    rejected = finish_deep_scan(
        state_dir,
        scan_id,
        "capped",
        str(scan_dir / "scan-manifest.json"),
        environment={"CODEX_HOME": str(codex_home)},
        check=False,
    )

    assert "Canonical parent findings.json must be an existing path" in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, manifest_path FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == ("running", None)


def test_budget_exhaustion_preserves_validated_standard_results_without_candidate_ledgers(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = standard_parent_results_fixture(
        tmp_path, budget=True
    )
    manifest_path = scan_dir / "scan-manifest.json"
    finish_deep_scan(
        state_dir,
        scan_id,
        "capped",
        str(manifest_path),
        environment={"CODEX_HOME": str(codex_home)},
    )
    warning = "Scan stopped: estimated cost $0.00625 exceeded the $0.005 cost limit."

    completed = scan_command(
        state_dir,
        "complete-budget-exhausted-scan",
        scan_id,
        "--cost-json",
        json.dumps(BUDGET_COST),
        "--message",
        warning,
    )["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert "Unsafe archive extraction" in completed["findings"][0]["title"]
    assert completed["warnings"] == [warning]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["deferred"] == [
        {
            "id": "scan-cost-limit",
            "reason": "Validation was deferred because the scan reached its cost limit.",
        }
    ]
    sarif = json.loads((scan_dir / "exports/results.sarif").read_text())
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert not (scan_dir / "artifacts" / "02_discovery").exists()


def test_budget_exhaustion_rejects_incomplete_standard_result_draft(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = standard_parent_results_fixture(
        tmp_path, budget=True
    )
    finish_deep_scan(
        state_dir,
        scan_id,
        "capped",
        str(scan_dir / "scan-manifest.json"),
        environment={"CODEX_HOME": str(codex_home)},
    )
    (scan_dir / "findings.json").unlink()

    rejected = scan_command(
        state_dir,
        "complete-budget-exhausted-scan",
        scan_id,
        "--cost-json",
        json.dumps(BUDGET_COST),
        check=False,
    )

    assert "incomplete canonical scan draft" in str(rejected["stderr"])


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

    binding = saved_binding(status="in_progress")

    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=False, reason=""
    )
    assert result is not None
    _, _, coverage = result
    assert coverage.get("openQuestions") == expected


@pytest.mark.parametrize(
    "canonical_state",
    ["missing", "incomplete", "terminal", "implicit", "reopened", "checkpoint_reopened"],
)
def test_recovery_retains_generic_closures_without_a_canonical_write(
    tmp_path: Path, canonical_state: str
) -> None:
    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "generic-closure-recovery"
    pending_closeout = {
        "id": "review-closeout",
        "reason": "Final submission remains.",
        "paths": ["src/example.py"],
    }
    closure = {
        "id": "review-closeout",
        "reason": "All review decisions are recorded.",
    }
    unresolved = {"id": "unavailable-library", "reason": "Source is unavailable."}
    candidate = {"candidateId": "pending-candidate", "reason": "Validation remains."}
    coverage = saved_coverage(
        deferred=[
            pending_closeout,
            unresolved,
            candidate,
        ]
    )
    initial = {"scanId": scan_id, "complete": False, "findings": [], "coverage": coverage}
    if canonical_state != "missing":
        scan = (
            {} if canonical_state == "implicit" else {"complete": canonical_state != "incomplete"}
        )
        (scan_dir / "scan-manifest.json").write_text(json.dumps({"scan": scan}))
        (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
        canonical_coverage = {
            **coverage,
            "deferred": [{**pending_closeout, "id": closure["id"]}, unresolved, candidate],
        }
        (scan_dir / "coverage.json").write_text(json.dumps(canonical_coverage))
        os.utime(scan_dir / "coverage.json", ns=(100, 100))
    original = write_checkpoint(scan_dir / "checkpoints", initial)
    os.utime(original, ns=(100, 100))
    original_bytes = original.read_bytes()
    terminal = write_checkpoint(
        scan_dir / "checkpoints",
        {
            **initial,
            "complete": True,
            "coverage": {
                **coverage,
                "deferred": [unresolved, candidate],
                "resolvedDeferred": [closure],
            },
        },
    )
    os.utime(terminal, ns=(200, 200))
    if canonical_state == "reopened":
        os.utime(scan_dir / "coverage.json", ns=(300, 300))
    if canonical_state == "checkpoint_reopened":
        # A matching checkpoint can be a newer observation of reopened work.
        # Recovery must preserve its existing time when snapshotting the parent.
        payload = workbench_saved_results._encoded(
            {**initial, "complete": True, "coverage": canonical_coverage}
        )
        existing_checkpoint = (
            scan_dir / "checkpoints" / f"{hashlib.sha256(payload).hexdigest()}.json"
        )
        existing_checkpoint.write_bytes(payload)
        os.utime(existing_checkpoint, ns=(300, 300))
    binding = saved_binding()
    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    assert result is not None
    recovered = result[2]
    reopened = canonical_state in {"reopened", "checkpoint_reopened"}
    assert recovered.get("resolvedDeferred", []) == ([] if reopened else [closure])
    assert {row.get("candidateId") or row["id"] for row in recovered["deferred"]} == {
        unresolved["id"],
        candidate["candidateId"],
        "scan-stopped",
    } | ({closure["id"]} if reopened else set())
    assert recovered["completeness"] == "partial"
    assert original.read_bytes() == original_bytes
    if canonical_state == "checkpoint_reopened":
        assert existing_checkpoint.stat().st_mtime_ns == 300
    if canonical_state == "terminal":
        # Publication can fail after snapshotting the old canonical state. A later
        # recovery may have only that frozen checkpoint set left to work with.
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan_dir / name).unlink()
        replay = replay_saved_results(
            workbench_saved_results, result, scan_dir, scan_id, binding, [], stopped=True
        )
        assert replay is not None
        assert replay[2]["resolvedDeferred"] == [closure]
        assert closure["id"] not in {row.get("id") for row in replay[2]["deferred"]}


@pytest.mark.parametrize("closure_time", [100, 200])
def test_recovered_generic_closure_cannot_close_another_workers_same_id(
    tmp_path: Path, closure_time: int
) -> None:
    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "worker-closure-recovery"
    workers = []
    for worker_id in ("worker-one", "worker-two"):
        output = scan_dir / "workers" / worker_id
        output.mkdir(parents=True)
        workers.append(
            {
                "id": worker_id,
                "kind": "discovery",
                "artifact_dir": str(output),
                "result_manifest_path": None,
            }
        )
        draft = saved_draft(
            scan_id, deferred=[{"id": "shared-review", "reason": f"Pending in {worker_id}."}]
        )
        pending = write_checkpoint(output / "checkpoints", draft)
        os.utime(pending, ns=(100, 100))
        if worker_id == "worker-one":
            # Recover the accepted final checkpoint after an interrupted result write.
            terminal = write_checkpoint(
                output / "checkpoints",
                {
                    **draft,
                    "complete": True,
                    "coverage": {
                        **draft["coverage"],
                        "completeness": "complete",
                        "deferred": [],
                        "resolvedDeferred": [
                            {"id": "shared-review", "reason": "Review completed."}
                        ],
                    },
                },
            )
            os.utime(terminal, ns=(closure_time, closure_time))
        else:
            (output / "result.json").write_text(json.dumps(draft))
    binding = saved_binding("deep_repository")
    result = workbench_saved_results.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        [],
        stopped=True,
        reason="interrupted",
    )
    assert result is not None
    coverage = result[2]
    expected = {"Pending in worker-two."}
    if closure_time == 100:
        expected.add("Pending in worker-one.")
    assert {
        row["reason"] for row in coverage["deferred"] if row["id"] != "scan-stopped"
    } == expected
    assert coverage["completeness"] == "partial"
    assert not coverage.get("resolvedDeferred")


@pytest.mark.parametrize("canonical_time", [100, 200, 300])
def test_recovery_keeps_latest_generic_closure_reason(tmp_path: Path, canonical_time: int) -> None:
    scan_dir = tmp_path.resolve()
    scan_id = "closure-reason-recovery"
    closure = {"id": "review-closeout", "reason": "Review and follow-up are complete."}
    coverage = {
        "completeness": "complete",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "resolvedDeferred": [closure],
    }
    (scan_dir / "scan-manifest.json").write_text(
        json.dumps({"scan": {"complete": True, "sealedAt": "2026-01-01T00:00:00Z"}})
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    os.utime(scan_dir / "coverage.json", ns=(canonical_time, canonical_time))
    previous = write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan_id,
            "complete": True,
            "findings": [],
            "coverage": {
                **coverage,
                "resolvedDeferred": [{**closure, "reason": "Initial review completed."}],
            },
        },
    )
    os.utime(previous, ns=(200, 200))
    binding = saved_binding()
    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    assert result is not None
    expected = (
        closure if canonical_time >= 200 else {**closure, "reason": "Initial review completed."}
    )
    assert result[2]["resolvedDeferred"] == [expected]


@pytest.mark.parametrize(
    "case", ["candidate", "finding", "extra_property", "mixed_closures", "duplicate_closures"]
)
def test_recovery_rejects_closures_that_would_discard_saved_evidence(
    tmp_path: Path, case: str
) -> None:
    scan_dir = tmp_path.resolve()
    scan_id = "retained-evidence-recovery"
    pending = {"id": "pending-review", "reason": "Validation remains.", "paths": ["src/example.py"]}
    if case in {"candidate", "finding"}:
        pending[case] = {
            "title": "Retained review evidence",
            "evidence": "Unverified source trace.",
        }
    coverage = saved_coverage(deferred=[pending])
    draft = {"scanId": scan_id, "complete": False, "findings": [], "coverage": coverage}
    original = write_checkpoint(scan_dir / "checkpoints", draft)
    os.utime(original, ns=(100, 100))
    original_bytes = original.read_bytes()
    closure = {"id": pending["id"], "reason": "Review closed."}
    closures = [closure]
    if case == "extra_property":
        closure["evidence"] = "Unsupported closure field."
    elif case == "mixed_closures":
        closures.append({"id": "another-review", "reason": "Done.", "evidence": "Invalid field."})
    elif case == "duplicate_closures":
        closures.append(dict(closure))
    terminal = write_checkpoint(
        scan_dir / "checkpoints",
        {
            **draft,
            "complete": True,
            "coverage": {
                **coverage,
                "completeness": "complete",
                "deferred": [],
                "resolvedDeferred": closures,
            },
        },
    )
    os.utime(terminal, ns=(200, 200))
    binding = {
        "scanId": scan_id,
        "startedAt": "2026-01-01T00:00:00Z",
        "completedAt": "2026-01-01T00:01:00Z",
        "producer": {"name": "codex-security-plugin", "version": "0.1.0"},
        "status": "interrupted",
        "allowedTargetKinds": ["git_revision"],
        "target": {"targetId": "target_sha256_test", "displayName": "test", "revision": "head"},
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "repository",
    }
    documents = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    assert documents is not None
    prepared = workbench_saved_results._prepare_scan_finalization(
        scan_dir, completion_binding=binding, completion_warnings=[], draft_documents=documents
    )
    workbench_saved_results._write_prepared_scan_finalization(prepared)
    recovered = json.loads((scan_dir / "coverage.json").read_text())
    assert pending in recovered["deferred"]
    assert not recovered.get("resolvedDeferred")
    assert recovered["completeness"] == "partial"
    assert original.read_bytes() == original_bytes


@pytest.mark.parametrize("keep_other_closure", [False, True])
def test_recovery_restores_work_reopened_after_parent_closure(
    tmp_path: Path, keep_other_closure: bool
) -> None:
    scan_dir = tmp_path.resolve()
    scan_id = "reopened-parent-recovery"
    closure = {"id": "review-closeout", "reason": "Initial review completed."}
    other = {"id": "other-review", "reason": "Separate review completed."}
    coverage = {
        "completeness": "complete",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "resolvedDeferred": [closure, other] if keep_other_closure else [closure],
    }
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"scan": {"complete": True}}))
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    os.utime(scan_dir / "coverage.json", ns=(100, 100))
    pending = {"id": closure["id"], "reason": "New source evidence needs review."}
    reopened = write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan_id,
            "complete": True,
            "findings": [],
            "coverage": {
                **coverage,
                "completeness": "partial",
                "deferred": [pending],
                "resolvedDeferred": [],
            },
        },
    )
    os.utime(reopened, ns=(200, 200))
    binding = saved_binding()
    documents = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], [], stopped=True, reason="interrupted"
    )
    assert documents is not None
    assert pending in documents[2]["deferred"]
    assert documents[2].get("resolvedDeferred", []) == ([other] if keep_other_closure else [])
    replay = replay_saved_results(
        workbench_saved_results, documents, scan_dir, scan_id, binding, [], stopped=True
    )
    assert replay is not None
    assert pending in replay[2]["deferred"]
    assert replay[2].get("resolvedDeferred", []) == ([other] if keep_other_closure else [])


@pytest.mark.parametrize(
    "layout", ["current", "archived", "new_attempt_reopens", "legacy_attempt_reopens"]
)
def test_recovery_uses_frozen_worker_head_for_identical_reclosure(
    tmp_path: Path, layout: str
) -> None:
    scan_dir = tmp_path.resolve()
    scan_id = "replayed-worker-closure"
    worker_root = scan_dir / "workers" / "worker-one"
    output = worker_root / "output"
    output.mkdir(parents=True)
    attempt = output if layout == "current" else worker_root / "attempts" / "attempt-01"
    attempt.mkdir(parents=True, exist_ok=True)
    pending = {"id": "review-closeout", "reason": "Reopened source review."}
    coverage = saved_coverage(deferred=[pending])
    draft = {"scanId": scan_id, "complete": True, "findings": [], "coverage": coverage}
    closed = write_checkpoint(
        attempt / "checkpoints",
        {
            **draft,
            "coverage": {
                **coverage,
                "completeness": "complete",
                "deferred": [],
                "resolvedDeferred": [{"id": pending["id"], "reason": "Review completed."}],
            },
        },
    )
    os.utime(closed, ns=(100, 100))
    reopened = write_checkpoint(attempt / "checkpoints", draft)
    os.utime(reopened, ns=(200, 200))
    (attempt / "result.json").write_text(json.dumps(draft))
    os.utime(attempt / "result.json", ns=(200, 200))
    head = attempt / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": closed.name}))
    os.utime(head, ns=(300, 300))
    if layout != "current":
        current = (
            draft
            if layout.endswith("attempt_reopens")
            else {**draft, "coverage": {**coverage, "completeness": "complete", "deferred": []}}
        )
        (output / "result.json").write_text(json.dumps(current))
        os.utime(output / "result.json", ns=(300, 300))
    workers = [saved_discovery_worker(output, "worker-one", 1 if layout == "current" else 2)]
    if layout == "legacy_attempt_reopens":
        workers[0].pop("attempt")
    binding = saved_binding("deep_repository")
    documents = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    assert documents is not None
    assert (pending in documents[2]["deferred"]) is layout.endswith("attempt_reopens")
    frozen = documents[0]["scan"]["preservedSources"]
    head_path = next(path for path in frozen if "/checkpoint-heads/" in path)
    assert closed.stat().st_mtime_ns == 100
    replay = workbench_saved_results.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=frozen,
    )
    assert replay is not None
    assert replay[2] == documents[2]
    for checkpoint in (reopened, closed):
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(400, 400))
        replay = workbench_saved_results.merge_saved_results(
            scan_dir,
            scan_id,
            binding,
            workers,
            [],
            stopped=True,
            reason="interrupted",
            frozen_source_digests=frozen,
        )
        assert replay is not None
        assert replay[2] == documents[2]
    # Legacy frozen evidence did not bind a head; a later head cannot change its result.
    head.write_text(json.dumps({"checkpoint": closed.name}))
    legacy = workbench_saved_results.merge_saved_results(
        scan_dir,
        scan_id,
        binding,
        workers,
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests={
            path: digest
            for path, digest in frozen.items()
            if path != head_path and not path.startswith("source-order/")
        },
    )
    assert legacy is not None
    assert pending in legacy[2]["deferred"]


@pytest.mark.parametrize("pending_modified", [200, 300])
def test_recovery_keeps_worker_pending_saved_before_head_update(
    tmp_path: Path, pending_modified: int
) -> None:
    scan_dir = tmp_path.resolve()
    scan_id = "worker-head-interruption"
    output = scan_dir / "workers" / "worker-one" / "output"
    coverage = {
        "completeness": "complete",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "resolvedDeferred": [{"id": "review-closeout", "reason": "Initial review completed."}],
    }
    draft = {"scanId": scan_id, "complete": True, "findings": [], "coverage": coverage}
    closed = write_checkpoint(output / "checkpoints", draft)
    os.utime(closed, ns=(100, 100))
    (output / "result.json").write_text(json.dumps(draft))
    os.utime(output / "result.json", ns=(200, 200))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": closed.name}))
    os.utime(head, ns=(200, 200))
    pending = {"id": "review-closeout", "reason": "New evidence needs review."}
    reopened = write_checkpoint(
        output / "checkpoints",
        {
            **draft,
            "coverage": {
                **coverage,
                "completeness": "partial",
                "deferred": [pending],
                "resolvedDeferred": [],
            },
        },
    )
    os.utime(reopened, ns=(pending_modified, pending_modified))
    workers = [saved_discovery_worker(output, "worker-one", 1)]
    binding = saved_binding("deep_repository")
    documents = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    assert documents is not None
    assert pending in documents[2]["deferred"]
    replay = replay_saved_results(
        workbench_saved_results, documents, scan_dir, scan_id, binding, workers, stopped=True
    )
    assert replay is not None
    assert replay[2] == documents[2]


@pytest.fixture
def generic_review_recovery():
    pending = saved_draft(
        "generic-review-recovery",
        deferred=[{"id": "review", "reason": "Review remains."}],
        complete=True,
    )
    closed = saved_draft(
        "generic-review-recovery",
        closures=[{"id": "review", "reason": "Review completed."}],
        complete=True,
    )
    binding = {
        "status": "interrupted",
        "allowedTargetKinds": ["git_revision"],
        "target": {
            "kind": "git_revision",
            "targetId": "target_sha256_test",
            "displayName": "test",
            "revision": "head",
        },
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "repository",
    }
    return workbench_saved_results, pending, closed, binding


def write_saved_parent(scan_dir: Path, draft: dict, modified: int) -> None:
    (scan_dir / "scan-manifest.json").write_text(
        json.dumps({"scan": {"complete": draft["complete"]}})
    )
    (scan_dir / "findings.json").write_text(json.dumps({"findings": draft["findings"]}))
    (scan_dir / "coverage.json").write_text(json.dumps(draft["coverage"]))
    os.utime(scan_dir / "coverage.json", ns=(modified, modified))


@pytest.mark.parametrize("reopened", [False, True])
def test_frozen_parent_retains_identical_latest_observation(
    tmp_path: Path, generic_review_recovery, reopened: bool
) -> None:
    module, pending, closed, binding = generic_review_recovery
    latest, middle = (pending, closed) if reopened else (closed, pending)
    # The host snapshots canonical JSON with its own encoding.
    payload = module._encoded(latest)
    original = tmp_path / "checkpoints" / f"{hashlib.sha256(payload).hexdigest()}.json"
    original.parent.mkdir()
    original.write_bytes(payload)
    os.utime(original, ns=(100, 100))
    checkpoint = write_checkpoint(original.parent, middle)
    os.utime(checkpoint, ns=(200, 200))
    write_saved_parent(tmp_path, latest, 300)
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, [], [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert (pending["coverage"]["deferred"][0] in first[2]["deferred"]) is reopened
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (tmp_path / name).unlink()
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, [], stopped=True
    )
    assert replay is not None
    assert (pending["coverage"]["deferred"][0] in replay[2]["deferred"]) is reopened
    assert replay[2].get("resolvedDeferred", []) == first[2].get("resolvedDeferred", [])
    assert original.read_bytes() == payload
    assert original.stat().st_mtime_ns == 100


@pytest.mark.parametrize(
    "layout",
    [
        "incomplete_parent",
        "terminal_parent",
        "worker",
        "worker_idless_terminal",
        "worker_idless_progress",
        "worker_idless_reopened",
        "worker_idless_shared_pending",
        "worker_idless_other_surface",
        "reopened_parent",
        "mixed_manifest",
    ],
)
def test_recovery_applies_surface_update_with_generic_closure(
    tmp_path: Path, generic_review_recovery, layout: str
) -> None:
    module, pending, closed, binding = generic_review_recovery
    pending["coverage"]["deferred"][0]["surfaceIds"] = ["api"]
    pending["coverage"]["surfaces"] = [
        {"id": "api", "label": "API", "disposition": "needs_follow_up", "receiptRefs": []}
    ]
    closed["coverage"]["surfaces"] = [
        {"id": "api", "label": "API", "disposition": "no_issue_found", "receiptRefs": []}
    ]
    idless = layout.startswith("worker_idless")
    if idless:
        pending["coverage"]["deferred"][0].pop("surfaceIds")
        for draft in (pending, closed):
            draft["coverage"]["surfaces"][0].pop("id")
            draft["coverage"]["surfaces"][0].pop("receiptRefs")
    if layout in {"worker_idless_progress", "worker_idless_other_surface"}:
        pending["complete"] = False
    if layout == "worker_idless_shared_pending":
        remaining = {"id": "other-review", "reason": "Another caller needs review."}
        pending["coverage"]["deferred"].append(remaining)
        closed["coverage"]["deferred"].append(remaining)
        closed["coverage"]["completeness"] = "partial"
    if layout in {"reopened_parent", "worker_idless_reopened"}:
        pending, closed = closed, pending
    output = tmp_path / "worker" if layout.startswith("worker") else tmp_path
    output.mkdir(exist_ok=True)
    workers = []
    if layout.startswith("worker"):
        (output / "result.json").write_text(json.dumps(pending))
        os.utime(output / "result.json", ns=(100, 100))
        workers = [saved_discovery_worker(output, "worker", 1)]
    else:
        pending["complete"] = layout in {"terminal_parent", "reopened_parent"}
        write_saved_parent(tmp_path, pending, 100)
    checkpoint = write_checkpoint(output / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    terminal_draft = copy.deepcopy(closed)
    if layout == "mixed_manifest":
        terminal_draft["coverage"]["surfaces"][0].pop("receiptRefs")
    terminal = write_checkpoint(output / "checkpoints", terminal_draft)
    os.utime(terminal, ns=(200, 200))
    if layout == "worker_idless_other_surface":
        other = copy.deepcopy(pending)
        other["coverage"]["surfaces"] = [
            {"label": "Other surface", "disposition": "needs_follow_up"}
        ]
        remaining = {"id": "other-review", "reason": "Independent review remains."}
        other["coverage"]["deferred"] = [remaining]
        checkpoint = write_checkpoint(output / "checkpoints", other)
        os.utime(checkpoint, ns=(300, 300))
    if layout == "mixed_manifest":
        canonical = {**closed, "complete": False}
        write_saved_parent(tmp_path, canonical, 300)
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    if layout == "worker_idless_shared_pending":
        assert any(row["disposition"] == "needs_follow_up" for row in first[2]["surfaces"])
        assert remaining in first[2]["deferred"]
    elif idless:
        # Labels alone cannot replace saved surface evidence.
        old_surface = pending["coverage"]["surfaces"][0]
        assert any(
            {key: value for key, value in row.items() if key not in {"id", "receiptRefs"}}
            == old_surface
            for row in first[2]["surfaces"]
        )
        if layout == "worker_idless_other_surface":
            assert remaining in first[2]["deferred"]
    else:
        assert first[2]["surfaces"] == closed["coverage"]["surfaces"]
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert replay[2] == first[2]


@pytest.mark.parametrize("outcome", ["rejected", "reported", "other_worker"])
@pytest.mark.parametrize("candidate_identity", ["explicit", "id_only", "alias"])
def test_reopened_candidate_respects_current_outcome(
    tmp_path: Path,
    generic_review_recovery,
    outcome: str,
    candidate_identity: str,
) -> None:
    module, pending, closed, binding = generic_review_recovery
    candidate = pending["coverage"]["deferred"][0]
    candidate["candidate"] = {"title": "Caller needs validation."}
    if candidate_identity != "id_only":
        candidate["candidateId"] = candidate["id"]
    if candidate_identity == "alias":
        candidate["id"] = "pending-review"
    for draft, modified in ((closed, 100), (pending, 200)):
        checkpoint = write_checkpoint(tmp_path / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    terminal = copy.deepcopy(closed)
    terminal["coverage"].pop("resolvedDeferred")
    terminal["coverage"]["surfaces"] = [
        {
            "id": "candidate-outcome",
            "candidateId": "review",
            "label": "API",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    ]
    workers = []
    if outcome == "reported":
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding.setdefault("extensions", {})["candidateId"] = "review"
        terminal["findings"] = [finding]
        terminal["coverage"]["surfaces"] = []
    if outcome == "other_worker":
        output = tmp_path / "worker"
        output.mkdir()
        (output / "result.json").write_text(json.dumps(terminal))
        workers = [saved_discovery_worker(output, "worker", 1)]
        parent = copy.deepcopy(terminal)
        parent["coverage"]["surfaces"] = []
        write_saved_parent(tmp_path, parent, 300)
    else:
        write_saved_parent(tmp_path, terminal, 300)
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=False, reason=""
    )
    assert first is not None
    assert (candidate in first[2]["deferred"]) is (outcome == "other_worker")
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert (candidate in replay[2]["deferred"]) is (outcome == "other_worker")


@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("variant", ["distinct", "identical", "rename"])
def test_worker_closure_preserves_ambiguous_legacy_surface_ids(
    tmp_path: Path, generic_review_recovery, complete: bool, variant: str
) -> None:
    module, pending, closed, binding = generic_review_recovery
    pending["complete"] = complete
    pending["coverage"]["deferred"][0]["surfaceIds"] = ["entry"]
    pending["coverage"]["surfaces"] = [
        {
            "id": "entry",
            "label": "Previous label" if variant == "rename" else "Entry A",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
    ]
    if variant != "rename":
        pending["coverage"]["surfaces"].append(
            {
                **pending["coverage"]["surfaces"][0],
                "label": "Entry B" if variant == "distinct" else "Entry A",
            }
        )
    closed["coverage"]["surfaces"] = [
        {
            "id": "entry",
            "label": "Updated label" if variant == "rename" else "Entry A",
            "disposition": "no_issue_found",
            "receiptRefs": [],
        }
    ]
    output = tmp_path / "worker"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(json.dumps(pending))
    original = write_checkpoint(output / "checkpoints", pending)
    for path in (result_path, original):
        os.utime(path, ns=(100, 100))
    terminal = write_checkpoint(output / "checkpoints", closed)
    os.utime(terminal, ns=(200, 200))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": terminal.name}))
    os.utime(head, ns=(200, 200))
    original_bytes = {path: path.read_bytes() for path in (result_path, original, terminal, head)}
    workers = [saved_discovery_worker(output, "worker", 1)]

    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )

    for documents in (first, replay):
        surfaces = documents[2]["surfaces"]
        if variant == "distinct":
            assert any(
                row["label"] == "Entry B" and row["disposition"] == "needs_follow_up"
                for row in surfaces
            )
            assert len({row["id"] for row in surfaces}) == len(surfaces)
        else:
            assert surfaces == closed["coverage"]["surfaces"]
    assert replay[2] == first[2]
    assert all(path.read_bytes() == contents for path, contents in original_bytes.items())


def test_parent_closure_cannot_discard_reopened_worker_same_id(
    tmp_path: Path, generic_review_recovery
) -> None:
    module, pending, closed, binding = generic_review_recovery
    write_saved_parent(tmp_path, closed, 300)
    output = tmp_path / "worker"
    output.mkdir()
    (output / "result.json").write_text(json.dumps(closed))
    os.utime(output / "result.json", ns=(100, 100))
    for draft, modified in ((closed, 100), (pending, 200)):
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert pending["coverage"]["deferred"][0] in first[2]["deferred"]


@pytest.mark.parametrize("layout", ["newer_raw", "newer_head", "legacy", "legacy_parent"])
def test_parent_head_preserves_newer_and_frozen_observations(
    tmp_path: Path, generic_review_recovery, layout: str
) -> None:
    module, pending, closed, binding = generic_review_recovery
    closed_checkpoint = write_checkpoint(tmp_path / "checkpoints", closed)
    os.utime(closed_checkpoint, ns=(100, 100))
    pending_checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(pending_checkpoint, ns=(300, 300))
    head = tmp_path / "checkpoint-head.json"
    selected = pending_checkpoint if layout == "newer_head" else closed_checkpoint
    head.write_text(json.dumps({"checkpoint": selected.name}))
    head_time = 400 if layout == "newer_head" else 200
    os.utime(head, ns=(head_time, head_time))
    original_head = head.read_bytes()
    write_saved_parent(tmp_path, closed, 350 if layout.startswith("legacy") else 100)
    frozen = None
    if layout.startswith("legacy"):
        frozen = {
            path.relative_to(tmp_path).as_posix(): module._read_saved_result(
                tmp_path, path.relative_to(tmp_path).as_posix(), pending["scanId"]
            )[1]
            for path in (closed_checkpoint, pending_checkpoint)
        }
    first = module.merge_saved_results(
        tmp_path,
        pending["scanId"],
        binding,
        [],
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=frozen,
        allow_frozen_legacy_parent=layout == "legacy_parent",
    )
    assert first is not None
    expected_pending = layout != "legacy_parent"
    assert (pending["coverage"]["deferred"][0] in first[2]["deferred"]) is expected_pending
    preserved = first[0]["scan"]["preservedSources"]
    assert any(path.startswith("checkpoint-heads/") for path in preserved) is (layout != "legacy")
    replay = module.merge_saved_results(
        tmp_path,
        pending["scanId"],
        binding,
        [],
        [],
        stopped=True,
        reason="interrupted",
        frozen_source_digests=preserved,
    )
    assert replay is not None
    assert (pending["coverage"]["deferred"][0] in replay[2]["deferred"]) is expected_pending
    if layout != "legacy_parent":
        assert head.read_bytes() == original_head
        assert head.stat().st_mtime_ns == head_time


@pytest.mark.parametrize("later", ["shared_pending", "candidate", "ambiguous", "other_worker"])
@pytest.mark.parametrize("idless", [False, True])
def test_generic_surface_recovery_preserves_unresolved_evidence(
    tmp_path: Path, generic_review_recovery, later: str, idless: bool
) -> None:
    module, pending, closed, binding = generic_review_recovery
    old_surface = {"id": "api", "label": "API", "disposition": "needs_follow_up", "receiptRefs": []}
    pending["coverage"]["surfaces"] = [old_surface]
    pending["coverage"]["deferred"][0]["surfaceIds"] = ["api"]
    if idless:
        old_surface.pop("id")
        old_surface.pop("receiptRefs")
        pending["coverage"]["deferred"][0].pop("surfaceIds")
    closed["coverage"]["surfaces"] = [{**old_surface, "disposition": "no_issue_found"}]
    for draft, modified in ((pending, 100), (closed, 200)):
        checkpoint = write_checkpoint(tmp_path / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    latest = copy.deepcopy(closed)
    latest["coverage"]["surfaces"] = [old_surface]
    workers = []
    if later == "shared_pending":
        latest["coverage"]["deferred"] = [
            {"id": "other-review", "reason": "New review remains.", "surfaceIds": ["api"]}
        ]
    elif later == "candidate":
        old_surface["candidateId"] = "other-candidate"
        latest["coverage"]["deferred"] = [
            {
                "id": "other-candidate",
                "candidateId": "other-candidate",
                "reason": "Validation remains.",
            }
        ]
    elif later == "ambiguous":
        latest["coverage"]["surfaces"].append({**old_surface, "id": "other-api"})
    else:
        output = tmp_path / "worker"
        output.mkdir()
        latest["coverage"].pop("resolvedDeferred")
        latest["coverage"]["deferred"] = pending["coverage"]["deferred"]
        (output / "result.json").write_text(json.dumps(latest))
        workers = [saved_discovery_worker(output, "worker", 1)]
    if later != "other_worker":
        checkpoint = write_checkpoint(tmp_path / "checkpoints", latest)
        os.utime(checkpoint, ns=(300, 300))
    result = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert result is not None
    assert any(row["disposition"] == "needs_follow_up" for row in result[2]["surfaces"])
    replay = replay_saved_results(
        module, result, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert any(row["disposition"] == "needs_follow_up" for row in replay[2]["surfaces"])


@pytest.mark.parametrize("pending_time", [200, 300, 400])
@pytest.mark.parametrize(
    ("candidate_identity", "prior_closure"),
    [("explicit", True), ("id_only", True), ("alias", True), ("explicit", False)],
    ids=["explicit", "id-only", "alias", "ordinary"],
)
def test_worker_head_candidate_outcome_respects_newer_pending(
    tmp_path: Path,
    generic_review_recovery,
    pending_time: int,
    candidate_identity: str,
    prior_closure: bool,
) -> None:
    module, pending, closed, binding = generic_review_recovery
    output = tmp_path / "worker"
    output.mkdir()
    candidate = pending["coverage"]["deferred"][0]
    candidate["candidate"] = {"title": "Caller needs validation."}
    if candidate_identity != "id_only":
        candidate["candidateId"] = candidate["id"]
    if candidate_identity == "alias":
        candidate["id"] = "pending-review"
    observations = [(closed, 100)] if prior_closure else []
    for draft, modified in [*observations, (pending, pending_time)]:
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    (output / "result.json").write_text(json.dumps(pending))
    os.utime(output / "result.json", ns=(200, 200))
    terminal = copy.deepcopy(closed)
    terminal["coverage"].pop("resolvedDeferred")
    terminal["coverage"]["surfaces"] = [
        {
            "id": "outcome",
            "candidateId": "review",
            "label": "API",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    ]
    selected = write_checkpoint(output / "checkpoints", terminal)
    os.utime(selected, ns=(150, 150))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(300, 300))
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert (candidate in first[2]["deferred"]) is (pending_time >= 300)
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert (candidate in replay[2]["deferred"]) is (pending_time >= 300)


def test_frozen_parent_keeps_unrelated_candidate_outcome(
    tmp_path: Path, generic_review_recovery
) -> None:
    module, pending, closed, binding = generic_review_recovery
    candidate = {
        "id": "candidate-review",
        "candidateId": "candidate-review",
        "reason": "Validation remains.",
    }
    pending["coverage"]["deferred"].append(candidate)
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    closed["coverage"]["surfaces"] = [
        {
            "id": "candidate-outcome",
            "candidateId": "candidate-review",
            "label": "Other review",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    ]
    write_saved_parent(tmp_path, closed, 300)
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, [], [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert candidate not in first[2]["deferred"]
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, [], stopped=True
    )
    assert replay is not None
    assert candidate not in replay[2]["deferred"]
    assert replay[2]["surfaces"] == closed["coverage"]["surfaces"]


@pytest.mark.parametrize("canonical_pending", [False, True])
@pytest.mark.parametrize("progress", [False, True])
def test_equal_time_parent_and_head_preserve_pending_on_replay(
    tmp_path: Path, generic_review_recovery, canonical_pending: bool, progress: bool
) -> None:
    module, pending, closed, binding = generic_review_recovery
    other = {"id": "other-review", "reason": "Independent review remains."}
    closed["coverage"]["deferred"] = [other]
    closed["coverage"]["completeness"] = "partial"
    pending["coverage"]["resolvedDeferred"] = [
        {"id": "other-review", "reason": "Previously reviewed."}
    ]
    if progress:
        pending["complete"] = False
    canonical, previous = (pending, closed) if canonical_pending else (closed, pending)
    payload = module._encoded(canonical)
    old = tmp_path / "checkpoints" / f"{hashlib.sha256(payload).hexdigest()}.json"
    old.parent.mkdir()
    old.write_bytes(payload)
    os.utime(old, ns=(100, 100))
    checkpoint = write_checkpoint(old.parent, previous)
    os.utime(checkpoint, ns=(100, 100))
    head = tmp_path / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(200, 200))
    write_saved_parent(tmp_path, canonical, 200)
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, [], [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert pending["coverage"]["deferred"][0] in first[2]["deferred"]
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, [], stopped=True
    )
    assert replay is not None
    assert pending["coverage"]["deferred"][0] in replay[2]["deferred"]
    assert old.stat().st_mtime_ns == 100
    assert other in first[2]["deferred"] and other in replay[2]["deferred"]
    assert first[2]["completeness"] == replay[2]["completeness"] == "partial"
    assert not replay[2].get("resolvedDeferred")


@pytest.mark.parametrize("stopped", [False, True])
@pytest.mark.parametrize("outcome", ["rejected", "reported"])
@pytest.mark.parametrize(
    ("candidate_identity", "prior_closure"),
    [("explicit", True), ("id_only", True), ("alias", True), ("explicit", False)],
    ids=["explicit", "id-only", "alias", "ordinary"],
)
def test_selected_candidate_outcome_keeps_its_evidence(
    tmp_path: Path,
    generic_review_recovery,
    stopped: bool,
    outcome: str,
    candidate_identity: str,
    prior_closure: bool,
) -> None:
    module, pending, closed, binding = generic_review_recovery
    output = tmp_path / "worker"
    output.mkdir()
    candidate = pending["coverage"]["deferred"][0]
    candidate["candidate"] = {"title": "Caller needs validation."}
    if candidate_identity != "id_only":
        candidate["candidateId"] = "review"
    if candidate_identity == "alias":
        candidate["id"] = "pending-review"
    pending["coverage"]["surfaces"] = [
        {"id": "api", "label": "API", "disposition": "needs_follow_up", "candidateId": "review"}
    ]
    observations = [(closed, 100)] if prior_closure else []
    for draft, modified in [*observations, (pending, 200)]:
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    (output / "result.json").write_text(json.dumps(pending))
    os.utime(output / "result.json", ns=(200, 200))
    terminal = copy.deepcopy(closed)
    terminal["coverage"].pop("resolvedDeferred")
    rejection = {
        "id": "api",
        "label": "API",
        "disposition": outcome,
        "candidateId": "review",
        "notes": "The reviewed caller has a recorded outcome.",
        "candidate": candidate["candidate"],
        "receiptRefs": [],
    }
    unrelated = {
        "id": "other",
        "label": "Other",
        "disposition": "no_issue_found",
        "receiptRefs": [],
    }
    terminal["coverage"]["surfaces"] = [rejection, unrelated]
    if outcome == "reported":
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding.setdefault("extensions", {})["candidateId"] = "review"
        other_finding = copy.deepcopy(finding)
        other_finding["extensions"]["candidateId"] = "other-candidate"
        other_finding["identity"]["anchor"] = "another-entry-point"
        terminal["findings"] = [finding, other_finding]
    selected = write_checkpoint(output / "checkpoints", terminal)
    os.utime(selected, ns=(300, 300))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(300, 300))
    workers = [saved_discovery_worker(output, "worker", 1)]
    if not stopped:
        parent = copy.deepcopy(closed)
        parent["coverage"].pop("resolvedDeferred")
        write_saved_parent(tmp_path, parent, 100)
    result = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=stopped, reason="interrupted"
    )
    assert result is not None
    assert candidate not in result[2]["deferred"]
    assert result[2]["surfaces"] == [rejection, unrelated]
    replay = replay_saved_results(
        module, result, tmp_path, pending["scanId"], binding, workers, stopped=stopped
    )
    assert replay is not None
    assert replay[2]["surfaces"] == [rejection, unrelated]
    assert candidate not in replay[2]["deferred"]
    if outcome == "reported":
        for documents in (result, replay):
            candidate_ids = {module.finding_candidate_id(row) for row in documents[1]["findings"]}
            assert "review" in candidate_ids
            assert "other-candidate" in candidate_ids


@pytest.mark.parametrize("candidate_identity", ["explicit", "id_only", "alias"])
def test_interrupted_worker_reopening_preserves_candidate_identity(
    tmp_path: Path, generic_review_recovery, candidate_identity: str
) -> None:
    module, pending, closed, binding = generic_review_recovery
    output = tmp_path / "worker"
    output.mkdir()
    candidate = pending["coverage"]["deferred"][0]
    candidate["candidate"] = {"title": "Caller needs validation."}
    if candidate_identity != "id_only":
        candidate["candidateId"] = "review"
    if candidate_identity == "alias":
        candidate["id"] = "pending-review"
        pending["coverage"]["deferred"].append(
            {**candidate, "id": "other-pending-review", "reason": "Another caller remains."}
        )
    (output / "result.json").write_text(json.dumps(closed))
    os.utime(output / "result.json", ns=(100, 100))
    for draft, modified in ((closed, 100), (pending, 200)):
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(modified, modified))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(200, 200))
    workers = [saved_discovery_worker(output, "worker", 1)]
    result = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert result is not None
    assert all(row in result[2]["deferred"] for row in pending["coverage"]["deferred"])
    replay = replay_saved_results(
        module, result, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert all(row in replay[2]["deferred"] for row in pending["coverage"]["deferred"])
