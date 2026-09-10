from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_workbench_continuation_decisions import continued_candidate, decision
from test_workbench_scan_checkpoints import save
from workbench_test_support import SCRIPT, run_workbench, write_checkpoint


@pytest.mark.parametrize(
    "interruption", ["worker-error", "worker-exit", "root-record", "root-head"]
)
def test_continuation_commits_workers_with_cost_and_baseline(tmp_path: Path, interruption: str):
    state, repository, _, _, parent, parent_id, worker_id, finding = continued_candidate(tmp_path)
    save(
        state,
        parent_id,
        write_checkpoint(
            parent / "checkpoints", decision(parent_id, worker_id, finding, "rejected")
        ),
    )
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child = tmp_path / "grandchild"
    child.mkdir(mode=0o700)
    child_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        parent_id,
    )["scanId"]
    cost = {
        "model": "test-model",
        "inputTokens": 100,
        "outputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "estimatedUsd": 12.5,
    }
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import json, os, runpy, sqlite3, sys
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

script, state, child, child_id, parent_id, cost, interruption = sys.argv[1:]
sys.path.insert(0, str(Path(script).parent))
import workbench_scan_checkpoints as checkpoints
api = runpy.run_path(script, run_name="continuation_transaction_test")
deep = api["deep_scan"]
deep.configure(deep.DeepScanDependencies(**{
    field.name: api["preserve_stopped_results_after_transition"
                    if field.name == "preserve_stopped_results" else field.name]
    for field in fields(deep.DeepScanDependencies)
}))
child = Path(child)
args = SimpleNamespace(scan_id=child_id, parent_scan_id=parent_id, cost_json=cost)
class Interrupted(Exception):
    pass
def interrupt():
    if interruption == "worker-error":
        raise Interrupted()
    os._exit(72)
record = checkpoints.record_checkpoint
def interrupted_record(connection, scan, path, timestamp, **options):
    result = record(connection, scan, path, timestamp, **options)
    if scan["id"] == child_id:
        relative = path.relative_to(child)
        if interruption.startswith("worker-") and relative.parts[0] == "artifacts":
            interrupt()
        if interruption == "root-record" and relative.parent == Path("checkpoints"):
            interrupt()
    return result
write = checkpoints.write_scan_local_bytes
def interrupted_write(root, relative, contents):
    if interruption == "root-head" and root == child and relative == "checkpoint-head.json":
        interrupt()
    return write(root, relative, contents)
checkpoints.record_checkpoint = interrupted_record
checkpoints.write_scan_local_bytes = interrupted_write
connection = sqlite3.connect(Path(state) / "workbench.sqlite3")
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
try:
    checkpoints.continue_checkpoint(api["_WORKBENCH_DB_CONTEXT"], connection, args)
except Interrupted:
    assert not connection.in_transaction, "the caller must roll back before propagating failure"
    sys.exit(71)
finally:
    connection.close()
raise AssertionError("The injected interruption did not fire")
""",
            str(SCRIPT),
            str(state),
            str(child),
            child_id,
            parent_id,
            json.dumps(cost),
            interruption,
        ],
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == (71 if interruption == "worker-error" else 72), process.stderr
    committed = interruption == "root-head"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        row = connection.execute(
            "SELECT continuation_cost_json, continuation_checkpoint_path, inference_started, "
            "continuation_sources_json "
            "FROM scans WHERE id = ?",
            (child_id,),
        ).fetchone()
        for table, expected in (("deep_scan_runs", 1), ("deep_scan_workers", 5)):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE scan_id = ?", (child_id,)
            ).fetchone() == (expected if committed else 0,)
        receipts = connection.execute(
            "SELECT COUNT(*) FROM scan_checkpoints WHERE scan_id = ?", (child_id,)
        ).fetchone()[0]
        assert (receipts > 0) == committed
        if committed:
            assert json.loads(row[0]) == cost
            assert (child / row[1]).is_file()
            assert row[2] == 0
            derived_sources = json.loads(row[3])
            assert derived_sources
            assert all((child / path).is_file() for path in derived_sources)
            assert "preservedSources" not in json.loads((child / row[1]).read_text())
        else:
            assert row == (None, None, None, None)
    assert not (child / "checkpoint-head.json").exists()
    assert list(child.glob("artifacts/deep_discovery/workers/*/output/checkpoint-head.json"))
    recovered = run_workbench(
        state, "get-cli-scan-resume", "--scan-id", child_id, "--allow-unavailable"
    )
    if committed:
        assert recovered["previousCost"] == cost
        assert recovered["checkpoint"]
    else:
        assert "No completed source work can be resumed" in recovered["unavailable"]

    arguments = ("continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id)
    run_workbench(state, *arguments, "--cost-json", json.dumps(cost))
    recovered = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)
    assert recovered["previousCost"] == cost
    head = json.loads((child / "checkpoint-head.json").read_text())
    baseline = f"checkpoints/{head['checkpoint']}"
    assert any(
        source["checkpointPath"] == baseline for source in recovered["checkpoint"]["sources"]
    )
    assert json.loads((child / "coverage.json").read_text())["deferred"] == []

    # Repeating the same semantic seed must still commit its cost binding and
    # identify the exact acceptance that owns the inherited baseline.
    revised_cost = {**cost, "estimatedUsd": 13.0}
    run_workbench(state, *arguments, "--cost-json", json.dumps(revised_cost))
    recovered = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)
    assert recovered["previousCost"] == revised_cost
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT continuation_checkpoint_path FROM scans WHERE id = ?", (child_id,)
        ).fetchone() == (baseline,)
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_workers WHERE scan_id = ?", (child_id,)
        ).fetchone() == (5,)
        acceptance_id = connection.execute(
            "SELECT continuation_checkpoint_acceptance_id FROM scans WHERE id = ?", (child_id,)
        ).fetchone()[0]
        assert (
            acceptance_id
            == json.loads((child / "checkpoint-head.json").read_text())["acceptanceId"]
        )
        assert connection.execute(
            "SELECT checkpoint_path FROM scan_checkpoints WHERE scan_id = ? AND acceptance_id = ?",
            (child_id, acceptance_id),
        ).fetchone() == (baseline,)


def test_fresh_baseline_content_is_a_current_decision_in_the_next_continuation(tmp_path: Path):
    state, repository, _, _, child, child_id, worker_id, finding = continued_candidate(tmp_path)
    baseline_head = json.loads((child / "checkpoint-head.json").read_text())
    baseline = child / "checkpoints" / baseline_head["checkpoint"]
    baseline_bytes = baseline.read_bytes()
    # The worker resolves the inherited pending candidate, then the parent accepts
    # the exact inherited bytes again as a new pending decision.
    worker = child / "artifacts/deep_discovery/workers/discovery-0004/output"
    save(
        state,
        child_id,
        write_checkpoint(
            worker / "checkpoints", decision(child_id, worker_id, finding, "rejected")
        ),
    )
    receipt = save(state, child_id, baseline)
    assert baseline.read_bytes() == baseline_bytes
    assert receipt["acceptanceId"] != baseline_head["acceptanceId"]
    recovered = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)["checkpoint"]
    matching = [
        source
        for source in recovered["sources"]
        if source["checkpointPath"] == baseline.relative_to(child).as_posix()
    ]
    assert {source["acceptanceId"] for source in matching} == {
        baseline_head["acceptanceId"],
        receipt["acceptanceId"],
    }
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", child_id)["recipe"]
    grandchild = tmp_path / "grandchild"
    grandchild.mkdir(mode=0o700)
    grandchild_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(grandchild),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        child_id,
    )["scanId"]
    run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        grandchild_id,
        "--parent-scan-id",
        child_id,
    )
    findings = json.loads((grandchild / "findings.json").read_text())["findings"]
    coverage = json.loads((grandchild / "coverage.json").read_text())
    assert len(findings) == 1
    assert findings[0]["codeEvidence"] == finding["codeEvidence"]
    assert len(coverage["deferred"]) == 1
    assert coverage["deferred"][0]["candidateId"] == "candidate-1"
    assert not [item for item in coverage["surfaces"] if item.get("disposition") == "rejected"]
    worker = grandchild / "artifacts/deep_discovery/workers/discovery-0004/output"
    head = json.loads((worker / "checkpoint-head.json").read_text())
    pending = json.loads((worker / "checkpoints" / head["checkpoint"]).read_text())
    assert len(pending["coverage"]["deferred"]) == 1
    assert pending["coverage"]["deferred"][0]["candidateId"] == "candidate-1"
