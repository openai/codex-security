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

import pytest
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    committed_standard_reducer,
    deep_scan_fixture,
    write_saved_parent,
)
from test_workbench_standard_deep_results import (
    generic_review_recovery as generic_review_recovery,
)
from workbench_test_support import (
    empty_target_scan,
    get_scan,
    preserve_scan_results,
    replay_saved_results,
    run_workbench,
    saved_discovery_worker,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize("same_worker", [True, False])
def test_legacy_stopped_parent_yields_to_current_worker_resolution(
    tmp_path: Path, disposition: str, same_worker: bool
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    current = json.loads(result_path.read_text())
    result_path.unlink()
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(
        contract_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = contract_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"].update(
        candidateId="candidate-one", workerId=worker_id if same_worker else str(uuid.uuid4())
    )
    findings_path.write_text(json.dumps(findings))
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
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
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
            (f"sha256:{hashlib.sha256(sealed_manifest).hexdigest()}", scan_id),
        )
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        environment=environment,
    )
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"] == {}
    )
    current["coverage"]["surfaces"] = [
        {
            "label": "Reviewed candidate",
            "candidateId": "candidate-one",
            "disposition": disposition,
            "notes": "Current worker validation resolved this candidate.",
        }
    ]
    result_path.write_text(json.dumps(current))

    recovered = run_workbench(
        state_dir, "recover-scan-results", "--scan-id", scan_id, environment=environment
    )["scan"]

    assert recovered["findingCount"] == (0 if same_worker else 1)
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    resolution = next(
        item for item in coverage["surfaces"] if item.get("candidateId") == "candidate-one"
    )
    assert resolution["disposition"] == disposition
    assert resolution["sourceWorkerId"] == worker_id
    assert len(resolution.get("previousFindings", [])) == (1 if same_worker else 0)


@pytest.mark.parametrize("pending_candidate_id", ["candidate-one", "candidate-two"])
def test_stopped_recovery_resolves_reported_candidates_from_findings(
    tmp_path: Path, pending_candidate_id: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = "candidate-two"
    current = json.loads(result_path.read_text())
    current["findings"] = [finding]
    current["coverage"]["deferred"] = [
        {"candidateId": pending_candidate_id, "reason": "This candidate still needs validation."}
    ]
    current["coverage"]["surfaces"] = [
        {
            "label": "Shared candidate surface",
            "candidateId": pending_candidate_id,
            "disposition": "reported",
            "notes": "The surface contains a reported candidate and unfinished validation.",
        }
    ]
    result_path.write_text(json.dumps(current))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item.get("candidateId")]
    assert [item["candidateId"] for item in pending] == (
        ["candidate-one"] if pending_candidate_id == "candidate-one" else []
    )
    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["provenance"]["candidateId"] == "candidate-two"


@pytest.mark.parametrize("scope", [".", "app.py"])
def test_stopped_reducer_candidates_without_coverage_preserve_scope(
    tmp_path: Path, scope: str
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    _, reducer_path, _ = committed_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, result_path
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET scope = ? WHERE id = ?", (scope, scan_id))
    reduced = json.loads(reducer_path.read_text())
    reduced.pop("coverage")
    reduced["unresolvedCandidates"] = [
        {
            "candidateId": "pending-reducer",
            "sourceWorkerId": worker_id,
            "candidate": {"title": "Review parser bounds"},
            "reason": "The parser route still needs validation.",
        }
    ]
    reducer_path.write_text(json.dumps(reduced))
    reducer_bytes = reducer_path.read_bytes()

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped before the parent draft was written.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["progress"]["candidates"]["unresolved"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["inventoryStrategy"] == ("repository" if scope == "." else "scoped_path")
    assert coverage["includePaths"] == [scope]
    assert coverage["completeness"] == "partial"
    pending = [item for item in coverage["deferred"] if item.get("candidateId")]
    assert len(pending) == 1
    assert pending[0]["candidateId"] == "pending-reducer"
    assert pending[0]["sourceWorkerId"] == worker_id
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]
    assert manifest["scan"]["status"] == "failed"
    assert "| Unresolved candidates | 1 |" in (scan_dir / "report.md").read_text()
    assert reducer_path.read_bytes() == reducer_bytes


@pytest.mark.parametrize("resolve_first", [False, True])
def test_recovery_keeps_pending_candidate_identity_scoped_to_its_worker(
    tmp_path: Path, resolve_first: bool
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    workers = [
        accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id, name=f"worker-{index}")
        for index in range(2)
    ]
    for index, (_, result_path) in enumerate(workers):
        draft = json.loads(result_path.read_text())
        draft["coverage"].update(
            completeness="partial",
            deferred=[
                {
                    "candidateId": "candidate-one",
                    "reason": "The parser route still needs validation.",
                    "candidate": {"title": "Review parser bounds"},
                }
            ],
        )
        write_checkpoint(result_path.parent / "checkpoints", draft)
        if index == 0 and resolve_first:
            draft["coverage"].update(
                completeness="complete",
                deferred=[],
                surfaces=[
                    {
                        "candidateId": "candidate-one",
                        "label": "Parser route",
                        "disposition": "rejected",
                        "notes": "The existing bounds check covers this route.",
                    }
                ],
            )
        result_path.write_text(json.dumps(draft))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after candidate checkpoints.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item.get("candidateId")]
    expected_owners = {workers[1][0]} if resolve_first else {worker[0] for worker in workers}
    assert {item["sourceWorkerId"] for item in pending} == expected_owners
    assert stopped["progress"]["candidates"]["unresolved"] == len(expected_owners)


@pytest.mark.parametrize("owner_field", ["workerId", "sourceWorkerId"])
@pytest.mark.parametrize("termination", ["failed", "canceled"])
@pytest.mark.parametrize("source", ["worker", "legacy-reducer"])
def test_recovery_preserves_bound_worker_owner_over_imported_metadata(
    tmp_path: Path, owner_field: str, termination: str, source: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    workers = [
        accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id, name=f"worker-{index}")
        for index in range(2)
    ]
    owner_a, result_a = workers[0]
    owner_b, result_b = workers[1]
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, target, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(candidateId="shared-candidate", **{owner_field: owner_b})
    finding["summary"] = "Stronger current worker finding."
    draft_a = json.loads(result_a.read_text())
    draft_a["findings"] = [finding]
    earlier = copy.deepcopy(draft_a)
    earlier["findings"][0]["severity"]["level"] = "low"
    earlier["findings"][0]["summary"] = "Earlier weaker worker finding."
    checkpoint = write_checkpoint(result_a.parent / "checkpoints", earlier)
    result_a.write_text(json.dumps(draft_a))
    draft_b = json.loads(result_b.read_text())
    draft_b["coverage"].update(
        completeness="partial",
        deferred=[
            {
                "candidateId": "shared-candidate",
                "reason": "Independent worker review remains pending.",
                "candidate": {"title": "Independent saved candidate"},
            }
        ],
    )
    result_b.write_text(json.dumps(draft_b))
    source_paths = [result_a, result_b, checkpoint]
    if source == "legacy-reducer":
        _, reducer_path, _ = committed_standard_reducer(
            state_dir,
            codex_home,
            scan_dir,
            scan_id,
            owner_a,
            result_a,
            additional_worker_ids=(owner_b,),
        )
        reduced = copy.deepcopy(draft_a)
        reduced["findings"][0]["provenance"]["sourceFindings"] = [
            {"id": f"{owner_a}:0", "finding": copy.deepcopy(finding)}
        ]
        reduced["coverage"] = copy.deepcopy(draft_b["coverage"])
        reduced["coverage"]["deferred"][0]["sourceWorkerId"] = owner_b
        reducer_path.write_text(json.dumps(reduced))
        source_paths.extend(
            [reducer_path, write_checkpoint(reducer_path.parent / "checkpoints", reduced)]
        )
    originals = {path: path.read_bytes() for path in source_paths}
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
        run_workbench(
            state_dir,
            "fail-deep-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Stopped after worker review.",
            environment=environment,
        )

    def assert_owned_results() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 1
        assert scan["progress"]["candidates"]["unresolved"] == 1
        history = run_workbench(state_dir, "list-scans")["scans"][0]
        assert "unresolved" not in history["progress"]["candidates"]
        retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
        assert retained["summary"] == finding["summary"]
        assert retained["provenance"]["sourceWorkerId"] == owner_a
        if owner_field == "workerId":
            assert retained["provenance"][owner_field] == owner_b
        else:
            originals_in_history = retained["provenance"].get("previousFindings", []) + [
                source["finding"] for source in retained["provenance"].get("sourceFindings", [])
            ]
            assert finding in originals_in_history
        if source == "legacy-reducer":
            assert (
                retained["provenance"]["sourceFindings"]
                == reduced["findings"][0]["provenance"]["sourceFindings"]
            )
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        pending = [item for item in coverage["deferred"] if item.get("candidateId")]
        assert len(pending) == 1
        assert pending[0]["sourceWorkerId"] == owner_b
        report = (scan_dir / "report.md").read_text()
        assert "| Unresolved candidates | 1 |" in report
        assert f"| shared-candidate | {owner_b} |" in report
        assert "- Independent worker review remains pending." in report
        assert all(path.read_bytes() == content for path, content in originals.items())

    assert_owned_results()
    frozen = {
        scan_dir / relative: (scan_dir / relative).read_bytes()
        for relative in json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
            "preservedSources"
        ]
    }
    if termination == "failed":
        later = copy.deepcopy(draft_a)
        later.update(complete=False, findings=[])
        later["coverage"]["deferred"] = [{"id": "later-work", "reason": "Later saved work."}]
        write_checkpoint(result_a.parent / "checkpoints", later)
        run_workbench(
            state_dir, "recover-scan-results", "--scan-id", scan_id, environment=environment
        )
    else:
        run_workbench(
            state_dir, "preserve-scan-results", "--scan-id", scan_id, environment=environment
        )
    assert_owned_results()
    assert all(path.read_bytes() == content for path, content in frozen.items())


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize("owner_field", ["workerId", "sourceWorkerId"])
@pytest.mark.parametrize("same_worker", [False, True])
def test_stopped_recovery_applies_worker_decisions_to_parent_checkpoints(
    tmp_path: Path, disposition: str, owner_field: str, same_worker: bool
) -> None:
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import workbench_saved_results

    target = tmp_path.resolve() / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n")
    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "stopped-worker-decision"
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    manifest["scan"]["complete"] = True
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(
        candidateId="candidate-one",
        **{owner_field: "worker-one" if same_worker else "worker-two"},
    )
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints",
        {"scanId": scan_id, "complete": False, "findings": [finding], "coverage": coverage},
    )
    checkpoint_bytes = checkpoint.read_bytes()
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": []}))
    coverage["surfaces"] = [
        {
            "label": "Reviewed candidate",
            "candidateId": "candidate-one",
            "sourceWorkerId": "worker-one",
            "disposition": disposition,
            "notes": "The completed review dismissed this worker's candidate.",
        }
    ]
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    warnings: list[str] = []

    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], warnings, stopped=True, reason="Stopped after review."
    )

    assert result is not None
    assert warnings == []
    recovered = result[1]["findings"]
    assert len(recovered) == (0 if same_worker else 1)
    if same_worker:
        assert result[2]["surfaces"][0]["previousFindings"] == [finding]
    else:
        assert recovered[0]["provenance"][owner_field] == "worker-two"
        assert recovered[0]["summary"] == finding["summary"]
    assert checkpoint.read_bytes() == checkpoint_bytes


@pytest.mark.parametrize("pending_time", [100, 200, 300])
def test_absorbed_source_identity_respects_pending_checkpoint_order(
    tmp_path: Path, generic_review_recovery, pending_time: int
) -> None:
    module, pending, _, binding = generic_review_recovery
    output = tmp_path / "worker"
    output.mkdir()
    candidate = pending["coverage"]["deferred"][0]
    candidate["candidateId"] = candidate["id"]
    candidate["candidate"] = {"title": "Worker-local candidate still needs review."}
    candidate["originalCandidates"] = [{"title": "Earlier worker candidate evidence."}]
    candidate["previousFindings"] = [{"title": "Earlier worker finding evidence."}]
    checkpoint = write_checkpoint(output / "checkpoints", pending)
    os.utime(checkpoint, ns=(pending_time, pending_time))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(pending_time, pending_time))
    empty = {**pending, "coverage": {**pending["coverage"], "deferred": []}}
    (output / "result.json").write_text(json.dumps(empty))
    os.utime(output / "result.json", ns=(50, 50))
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
    local = json.loads((contract / "findings.json").read_text())["findings"][0]
    local["provenance"]["candidateId"] = "review"
    canonical = copy.deepcopy(local)
    canonical["provenance"]["candidateId"] = "canonical-parent"
    canonical["provenance"]["sourceFindings"] = [{"id": "worker:0", "finding": local}]
    parent = {**empty, "findings": [canonical]}
    write_saved_parent(tmp_path, parent, 200)
    workers = [saved_discovery_worker(output, "worker", 1)]
    source_bytes = {path: path.read_bytes() for path in [checkpoint, head, output / "result.json"]}

    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )

    assert first is not None
    assert any(
        row.get("candidateId") == "review" and row.get("sourceWorkerId") == "worker"
        for row in first[2]["deferred"]
    ) is (pending_time >= 200)
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert any(
        row.get("candidateId") == "review" and row.get("sourceWorkerId") == "worker"
        for row in replay[2]["deferred"]
    ) is (pending_time >= 200)
    if pending_time < 200:
        for recovered in (first, replay):
            provenance = recovered[1]["findings"][0]["provenance"]
            assert candidate["candidate"] in provenance.get("originalCandidates", [])
            assert candidate["originalCandidates"][0] in provenance.get("originalCandidates", [])
            assert candidate["previousFindings"][0] in provenance.get("previousFindings", [])
    else:
        for recovered in (first, replay):
            saved = next(
                row for row in recovered[2]["deferred"] if row.get("candidateId") == "review"
            )
            for field in ("candidate", "originalCandidates", "previousFindings"):
                assert saved[field] == candidate[field]
    assert all(path.read_bytes() == data for path, data in source_bytes.items())


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize("terminal_field", ["surfaces", "explicitExclusions"])
@pytest.mark.parametrize("pending_time", [200, 300, 400])
@pytest.mark.parametrize(
    "owner", [None, "worker", "other-worker"], ids=["parent", "same-worker", "other-worker"]
)
@pytest.mark.parametrize(
    "source_layout", ["result", "checkpoint-head", "checkpoint-head-with-prior-pending"]
)
@pytest.mark.parametrize("alias", [False, True], ids=["candidate-id", "task-alias"])
def test_parent_owned_pending_respects_worker_outcome_order(
    tmp_path: Path,
    generic_review_recovery,
    pending_time: int,
    owner: str | None,
    source_layout: str,
    alias: bool,
    disposition: str,
    terminal_field: str,
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    candidate = pending["coverage"]["deferred"][0]
    candidate.update(candidateId="review", paths=["app.py"])
    if alias:
        candidate["id"] = "review-task"
    if owner is not None:
        candidate["sourceWorkerId"] = owner
    write_saved_parent(tmp_path, pending, pending_time)
    terminal["coverage"].pop("resolvedDeferred")
    terminal["coverage"][terminal_field] = [
        {
            "id": "outcome",
            "candidateId": "review",
            "label": "API",
            "pattern": "app.py",
            "reason": "The worker finished its review.",
            "disposition": disposition,
            "receiptRefs": [],
        }
    ]
    output = tmp_path / "worker"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(json.dumps(terminal))
    os.utime(result_path, ns=(300, 300))
    if source_layout == "checkpoint-head-with-prior-pending":
        earlier = copy.deepcopy(pending)
        earlier["coverage"]["deferred"][0].pop("sourceWorkerId", None)
        older_checkpoint = write_checkpoint(output / "checkpoints", earlier)
        os.utime(older_checkpoint, ns=(100, 100))
    if source_layout != "result":
        checkpoint = write_checkpoint(output / "checkpoints", terminal)
        os.utime(checkpoint, ns=(150, 150))
        head = output / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(300, 300))
    original_worker = result_path.read_bytes()
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    expected_pending = owner != "worker" or pending_time >= 300
    assert first is not None
    assert (candidate in first[2]["deferred"]) is expected_pending
    assert len(module.unresolved_candidates(first[2], first[1])) == int(expected_pending)
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert (candidate in replay[2]["deferred"]) is expected_pending
    assert len(module.unresolved_candidates(replay[2], replay[1])) == int(expected_pending)
    assert result_path.read_bytes() == original_worker


@pytest.mark.parametrize("candidate", [False, True], ids=["generic", "candidate"])
@pytest.mark.parametrize("owner", [None, "worker"], ids=["parent", "worker"])
def test_owned_candidate_survives_newer_parent_generic_alias(
    tmp_path: Path, generic_review_recovery, candidate: bool, owner: str | None
) -> None:
    module, pending, _, binding = generic_review_recovery
    historical = pending["coverage"]["deferred"][0]
    historical["reason"] = "The earlier proof gap remains."
    if candidate:
        historical.update(candidateId="candidate-review", candidate={"title": "Review the API."})
    if owner is not None:
        historical["sourceWorkerId"] = owner
    checkpoint = write_checkpoint(tmp_path / "checkpoints", pending)
    os.utime(checkpoint, ns=(200, 200))
    original = checkpoint.read_bytes()
    current = copy.deepcopy(pending)
    current["complete"] = False
    current["coverage"]["deferred"] = [{"id": "review", "reason": "A separate new task remains."}]
    write_saved_parent(tmp_path, current, 300)
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, [], [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert (
        any(
            {key: value for key, value in row.items() if key != "id"}
            == {key: value for key, value in historical.items() if key != "id"}
            for row in first[2]["deferred"]
            if isinstance(row, dict)
        )
        is candidate
    )
    assert len(module.unresolved_candidates(first[2], first[1])) == int(candidate)
    assert current["coverage"]["deferred"][0] in first[2]["deferred"]
    replay = replay_saved_results(module, first, tmp_path, pending["scanId"], binding, stopped=True)
    assert replay is not None
    assert (
        any(
            {key: value for key, value in row.items() if key != "id"}
            == {key: value for key, value in historical.items() if key != "id"}
            for row in replay[2]["deferred"]
            if isinstance(row, dict)
        )
        is candidate
    )
    assert len(module.unresolved_candidates(replay[2], replay[1])) == int(candidate)
    assert checkpoint.read_bytes() == original
    assert checkpoint.stat().st_mtime_ns == 200


@pytest.mark.parametrize("pending_time", [100, 200, 300])
def test_new_worker_pending_keeps_parent_outcome_chronology(
    tmp_path: Path, generic_review_recovery, pending_time: int
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    pending["coverage"]["deferred"][0].update(candidateId="review", paths=["app.py"])
    terminal["coverage"].pop("resolvedDeferred")
    terminal["coverage"]["surfaces"] = [
        {
            "id": "outcome",
            "candidateId": "review",
            "sourceWorkerId": "worker",
            "label": "API",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    ]
    write_saved_parent(tmp_path, terminal, 200)
    output = tmp_path / "worker"
    output.mkdir()
    result = output / "result.json"
    result.write_text(json.dumps(pending))
    os.utime(result, ns=(pending_time, pending_time))
    original = result.read_bytes()
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    assert len(module.unresolved_candidates(first[2], first[1])) == int(pending_time >= 200)
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert len(module.unresolved_candidates(replay[2], replay[1])) == int(pending_time >= 200)
    assert result.read_bytes() == original


@pytest.mark.parametrize("malformed", [None, 1, ["Malformed saved row"]])
def test_resolved_owned_gap_preserves_valid_parent_findings_with_malformed_rows(
    tmp_path: Path, generic_review_recovery, malformed
) -> None:
    module, pending, closed, binding = generic_review_recovery
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    pending["findings"] = [malformed, finding]
    row = pending["coverage"]["deferred"][0]
    row.update(candidateId="review", sourceWorkerId="worker")
    write_saved_parent(tmp_path, pending, 100)
    output = tmp_path / "worker"
    output.mkdir()
    closed["coverage"].pop("resolvedDeferred")
    closed["coverage"]["surfaces"] = [
        {
            "candidateId": "review",
            "label": "Final review",
            "disposition": "rejected",
            "receiptRefs": [],
        }
    ]
    (output / "result.json").write_text(json.dumps(closed))
    os.utime(output / "result.json", ns=(200, 200))
    saved = module.merge_saved_results(
        tmp_path,
        pending["scanId"],
        binding,
        [saved_discovery_worker(output, "worker", 1)],
        [],
        stopped=True,
        reason="interrupted",
    )
    assert saved is not None
    assert malformed in saved[1]["findings"]
    assert any(
        isinstance(row, dict) and row.get("title") == finding["title"]
        for row in saved[1]["findings"]
    )


@pytest.mark.parametrize("provenance", ["missing", None, []])
def test_resolved_parent_archive_uses_valid_finding_before_malformed_sibling(
    tmp_path: Path, generic_review_recovery, provenance
) -> None:
    module, pending, _, binding = generic_review_recovery
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = "review"
    malformed = {"title": "Malformed sibling", "extensions": {"candidateId": "review"}}
    if provenance != "missing":
        malformed["provenance"] = provenance
    pending["findings"] = [finding, malformed]
    row = pending["coverage"]["deferred"][0]
    row.update(
        candidateId="review", candidate={"candidate_id": "review", "evidence": "Prior evidence."}
    )
    write_saved_parent(tmp_path, pending, 100)
    saved = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, [], [], stopped=True, reason="interrupted"
    )
    assert saved is not None
    malformed_retained = next(
        row for row in saved[1]["findings"] if row.get("title") == malformed["title"]
    )
    assert all(malformed_retained.get(field) == value for field, value in malformed.items())
    retained = next(row for row in saved[1]["findings"] if row.get("title") == finding["title"])
    assert (
        pending["coverage"]["deferred"][0]["candidate"]
        in retained["provenance"]["originalCandidates"]
    )


@pytest.mark.parametrize("outcome", ["rejected", "reported"])
@pytest.mark.parametrize(
    "payload", ["candidate", "finding", "originalCandidates", "previousFindings"]
)
@pytest.mark.parametrize("parent_outcome", [False, True])
def test_newer_outcome_archives_owned_gap(
    tmp_path: Path, generic_review_recovery, outcome: str, payload: str, parent_outcome: bool
) -> None:
    module, pending, closed, binding = generic_review_recovery
    evidence = {
        "title": "Original parent evidence",
        "evidence": "Keep the authored diagnostic text.",
    }
    row = pending["coverage"]["deferred"][0]
    row.update(
        {
            "candidateId": "review",
            "sourceWorkerId": "worker",
            payload: [evidence]
            if payload in {"originalCandidates", "previousFindings"}
            else evidence,
        }
    )
    write_saved_parent(tmp_path, pending, 100)
    output = tmp_path / "worker"
    output.mkdir()
    closed["coverage"].pop("resolvedDeferred")
    closed["coverage"]["surfaces"] = [
        {
            "candidateId": "review",
            "label": "Final review",
            "disposition": outcome,
            "receiptRefs": [],
        }
    ]
    if outcome == "reported":
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding.setdefault("extensions", {})["candidateId"] = "review"
        closed["findings"] = [finding]
    if parent_outcome:
        row.pop("sourceWorkerId")
        closed["coverage"]["surfaces"][0]["sourceWorkerId"] = "worker"
        for finding in closed["findings"]:
            finding["provenance"]["sourceWorkerId"] = "worker"
        (output / "result.json").write_text(json.dumps(pending))
        os.utime(output / "result.json", ns=(100, 100))
        write_saved_parent(tmp_path, closed, 200)
    else:
        (output / "result.json").write_text(json.dumps(closed))
        os.utime(output / "result.json", ns=(200, 200))
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )

    def contains(value):
        return (
            value == evidence
            or (isinstance(value, list) and any(contains(child) for child in value))
            or (isinstance(value, dict) and any(contains(child) for child in value.values()))
        )

    for result in (first, replay):
        assert result is not None
        assert not any(item.get("candidateId") == "review" for item in result[2]["deferred"])
        assert contains(result[1] if outcome == "reported" else result[2])


@pytest.mark.parametrize("receipt", ["none", "valid", "missing", "unsafe", "null"])
@pytest.mark.parametrize("checkpoint", [False, True])
@pytest.mark.parametrize("worker_deferred", [[], None, 1, {}, "malformed"])
def test_worker_decision_recovers_receipts_before_consuming_saved_proof(
    tmp_path: Path, generic_review_recovery, receipt: str, checkpoint: bool, worker_deferred
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    original = pending["coverage"]["deferred"][0]
    original.update(
        candidateId="review",
        sourceWorkerId="worker",
        paths=["app.py"],
        candidate={"evidence": "Original saved proof gap."},
    )
    write_saved_parent(tmp_path, pending, 100)
    terminal["coverage"].pop("resolvedDeferred")
    terminal["coverage"]["deferred"] = worker_deferred
    refs = {
        "none": [],
        "valid": ["artifacts/review.txt"],
        "missing": ["artifacts/missing.txt"],
        "unsafe": ["../outside.txt"],
        "null": None,
    }[receipt]
    terminal["coverage"]["surfaces"] = [
        {
            "id": "decision",
            "candidateId": "review",
            "label": "API",
            "disposition": "rejected",
            "receiptRefs": refs,
        }
    ]
    output = tmp_path / "worker"
    output.mkdir()
    if receipt == "valid":
        (output / "artifacts").mkdir()
        (output / "artifacts/review.txt").write_text("Synthetic review receipt.\n")
    result = output / "result.json"
    result.write_text(json.dumps(terminal))
    os.utime(result, ns=(300, 300))
    if checkpoint:
        saved = write_checkpoint(output / "checkpoints", terminal)
        head = output / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": saved.name}))
        os.utime(head, ns=(300, 300))
    source_bytes = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    unresolved = receipt not in {"none", "valid"}
    assert (original in first[2]["deferred"]) is unresolved
    assert len(module.unresolved_candidates(first[2], first[1])) == int(unresolved)
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    assert replay is not None
    assert (original in replay[2]["deferred"]) is unresolved
    assert all(path.read_bytes() == data for path, data in source_bytes.items())


@pytest.mark.parametrize("deferred_id", [False, True])
@pytest.mark.parametrize("surface_id", [False, True])
@pytest.mark.parametrize("receipt", ["valid", "missing"])
def test_worker_receipt_recovery_preserves_optional_semantic_ids(
    tmp_path: Path, generic_review_recovery, deferred_id: bool, surface_id: bool, receipt: str
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    write_saved_parent(tmp_path, pending, 100)
    terminal["coverage"].pop("resolvedDeferred")
    unrelated = {
        "candidateId": "unrelated",
        "reason": "Unrelated pending proof.",
        "candidate": {"evidence": "Unrelated opaque evidence."},
    }
    if deferred_id:
        unrelated["id"] = "unrelated-gap"
    terminal["coverage"]["deferred"] = [unrelated]
    terminal["coverage"]["surfaces"] = [
        {
            "candidateId": "decision",
            "label": "Decision review",
            "disposition": "rejected",
            "receiptRefs": ["artifacts/review.txt"],
        }
    ]
    if surface_id:
        terminal["coverage"]["surfaces"][0]["id"] = "decision-surface"
    output = tmp_path / "worker"
    output.mkdir()
    if receipt == "valid":
        (output / "artifacts").mkdir()
        (output / "artifacts/review.txt").write_text("Synthetic verified receipt.\n")
    result = output / "result.json"
    result.write_text(json.dumps(terminal))
    os.utime(result, ns=(300, 300))
    before = result.read_bytes()
    workers = [saved_discovery_worker(output, "worker", 1)]
    saved = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert saved is not None
    unresolved = [row for row in saved[2]["deferred"] if row.get("candidateId") == "unrelated"]
    assert len(unresolved) == 1 and unresolved[0]["candidate"] == unrelated["candidate"]
    decisions = [row for row in saved[2]["surfaces"] if row.get("candidateId") == "decision"]
    assert len(decisions) == 1
    assert decisions[0]["disposition"] == ("rejected" if receipt == "valid" else "needs_follow_up")
    pending_decisions = [
        row for row in saved[2]["deferred"] if row.get("candidateId") == "decision"
    ]
    assert len(pending_decisions) == int(receipt == "missing")
    assert len(module.unresolved_candidates(saved[2], saved[1])) == (
        2 if receipt == "missing" else 1
    )
    assert result.read_bytes() == before


@pytest.mark.parametrize("receipt_present", [False, True])
@pytest.mark.parametrize("result_present", [False, True])
@pytest.mark.parametrize("valid_closure", [False, True])
def test_worker_receipt_recovery_keeps_unrelated_generic_closures(
    tmp_path: Path,
    generic_review_recovery,
    receipt_present: bool,
    result_present: bool,
    valid_closure: bool,
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    pending["complete"] = False
    pending["coverage"]["deferred"] = [
        {"id": "review", "reason": "Review the candidate surface."},
        {"id": "independent", "reason": "Review unrelated work."},
    ]
    terminal["coverage"]["resolvedDeferred"] = [
        {"id": "review", "reason": "Review completed." if valid_closure else ""},
        {"id": "independent", "reason": "Unrelated work completed."},
    ]
    terminal["coverage"]["surfaces"] = [
        {
            "id": "candidate-decision",
            "candidateId": "review",
            "label": "Reviewed candidate",
            "disposition": "rejected",
            "receiptRefs": ["artifacts/review.txt"],
        }
    ]
    output = tmp_path / "worker"
    output.mkdir()
    older = write_checkpoint(output / "checkpoints", pending)
    os.utime(older, ns=(100, 100))
    selected = write_checkpoint(output / "checkpoints", terminal)
    os.utime(selected, ns=(200, 200))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(300, 300))
    if result_present:
        result_path = output / "result.json"
        result_path.write_text(json.dumps(terminal))
        os.utime(result_path, ns=(300, 300))
    if receipt_present:
        (output / "artifacts").mkdir()
        (output / "artifacts/review.txt").write_text("Synthetic candidate review.\n")
    originals = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    for documents in (first, replay):
        assert documents is not None
        deferred = documents[2]["deferred"]
        assert any(item.get("id") == "independent" for item in deferred) is (
            not valid_closure and not result_present
        )
        candidates = module.unresolved_candidates(documents[2], documents[1])
        assert [item["candidateId"] for item in candidates] == (
            [] if receipt_present else ["review"]
        )
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("saved_gap", [False, True])
@pytest.mark.parametrize("result_present", [False, True])
def test_worker_receipt_recovery_retains_complete_evidence_archives(
    tmp_path: Path, generic_review_recovery, saved_gap: bool, result_present: bool
) -> None:
    module, pending, terminal, binding = generic_review_recovery
    old_candidate = {"evidence": "Earlier candidate evidence"}
    old_finding = {"summary": "Earlier finding evidence"}
    current_candidate = {"evidence": "Terminal candidate evidence"}
    terminal["coverage"] = {
        "completeness": "partial" if saved_gap else "complete",
        "surfaces": [
            {
                "id": "decision",
                "candidateId": "candidate",
                "label": "Reviewed candidate",
                "disposition": "rejected",
                "receiptRefs": ["artifacts/missing.txt"],
                "candidate": current_candidate,
                "originalCandidates": [old_candidate],
                "previousFindings": [old_finding],
            }
        ],
        "explicitExclusions": [],
        "deferred": [
            {
                "candidateId": "candidate",
                "reason": "Authored gap",
                "candidate": {"evidence": "Saved pending evidence"},
            }
        ]
        if saved_gap
        else [],
    }
    output = tmp_path / "worker"
    output.mkdir()
    if result_present:
        result = output / "result.json"
        result.write_text(json.dumps(terminal))
    else:
        checkpoint = write_checkpoint(output / "checkpoints", terminal)
        (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    originals = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    for documents in [
        first,
        replay_saved_results(
            module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
        ),
    ]:
        assert documents is not None
        unresolved = module.unresolved_candidates(documents[2], documents[1])
        assert len(unresolved) == 1
        retained = unresolved[0]
        assert old_candidate in retained["originalCandidates"]
        assert old_finding in retained["previousFindings"]
        if saved_gap:
            assert retained["reason"] == "Authored gap"
            assert current_candidate in retained["originalCandidates"]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("archived", [False, True])
@pytest.mark.parametrize("receipt", ["binary", "empty", "missing", "partial"])
def test_stopped_worker_receipts_survive_parent_publication_and_replay(
    tmp_path: Path, archived: bool, receipt: str
) -> None:
    from finalize_scan_contract import finalize_scan

    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    draft = json.loads(result_path.read_text())
    output = result_path.parent
    if archived:
        output = output / "attempts" / "attempt-01"
        output.mkdir(parents=True)
        result_path.unlink()
        result_path = output / "result.json"
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE deep_scan_workers SET attempt = 2, result_manifest_path = NULL WHERE id = ?",
                (worker_id,),
            )
    contents = b"" if receipt == "empty" else bytes([0, 255, 128, 10, 65])
    ref = "artifacts/review.bin"
    (output / "artifacts").mkdir()
    if receipt != "missing":
        (output / ref).write_bytes(contents)
    # The same name at the parent must not become the worker's proof.
    if receipt == "missing":
        (scan_dir / ref).write_bytes(b"Unrelated parent receipt")
    draft["complete"] = True
    draft["coverage"] = {
        "completeness": "complete",
        "surfaces": [
            {
                "id": "decision",
                "label": "Reviewed candidate",
                "candidateId": "candidate",
                "disposition": "rejected",
                "receiptRefs": [ref, "artifacts/missing.txt"] if receipt == "partial" else [ref],
            }
        ],
        "explicitExclusions": [],
        "deferred": [],
    }
    result_path.write_text(json.dumps(draft))
    originals = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Synthetic interruption.",
        environment=environment,
    )
    expected = int(receipt in {"missing", "partial"})
    for replay in (False, True):
        if replay:
            preserve_scan_results(
                state_dir, scan_id, "standard-worker-thread", environment=environment
            )
        scan = get_scan(state_dir, scan_id)["scan"]
        assert scan["progress"]["candidates"]["unresolved"] == expected
        _, _, coverage = finalize_scan(scan_dir, expected_coverage_mode="deep_repository")
        pending = [row for row in coverage["deferred"] if row.get("candidateId")]
        assert len(pending) == expected
        surface = next(row for row in coverage["surfaces"] if row.get("candidateId") == "candidate")
        assert surface["disposition"] == ("needs_follow_up" if expected else "rejected")
        if receipt != "missing":
            assert surface["receiptRefs"] == [(output / ref).relative_to(scan_dir).as_posix()]
            assert (scan_dir / surface["receiptRefs"][0]).read_bytes() == contents
        report = (scan_dir / "report.md").read_text()
        assert f"Unresolved candidates | {expected}" in report
        assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("outcome", ["reported", "rejected", "not_applicable"])
@pytest.mark.parametrize("select_pending", [False, True])
def test_worker_terminal_copies_do_not_reopen_their_own_candidate(
    tmp_path: Path, generic_review_recovery, outcome: str, select_pending: bool
) -> None:
    module, pending, _, binding = generic_review_recovery
    candidate = pending["coverage"]["deferred"][0]
    candidate.update(candidateId="review", paths=["app.py"])
    terminal = copy.deepcopy(pending)
    terminal["complete"] = True
    if outcome == "reported":
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding["provenance"]["candidateId"] = "review"
        terminal["findings"] = [finding]
    else:
        terminal["coverage"]["surfaces"] = [
            {
                "id": "decision",
                "candidateId": "review",
                "label": "Candidate review",
                "disposition": outcome,
                "receiptRefs": [],
            }
        ]
    output = tmp_path / "worker"
    output.mkdir()
    result_path = output / "result.json"
    result_path.write_text(json.dumps(terminal))
    os.utime(result_path, ns=(200, 200))
    closed = write_checkpoint(output / "checkpoints", terminal)
    older_pending = write_checkpoint(output / "checkpoints", pending)
    for checkpoint in (closed, older_pending):
        os.utime(checkpoint, ns=(100, 100))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": closed.name}))
    os.utime(head, ns=(200, 200))
    if select_pending:
        module._capture_saved_source(tmp_path, "worker/checkpoint-head.json", pending["scanId"])
        head.write_text(json.dumps({"checkpoint": older_pending.name}))
        os.utime(head, ns=(300, 300))
    originals = {file: file.read_bytes() for file in output.rglob("*.json")}
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    for recovered in (first, replay):
        assert len(module.unresolved_candidates(recovered[2], recovered[1])) == int(select_pending)
        if outcome == "reported":
            assert len(recovered[1]["findings"]) == 1
            assert (
                recovered[1]["findings"][0]["provenance"].get("candidateReopened") is True
            ) is select_pending
        else:
            decisions = [
                row for row in recovered[2]["surfaces"] if row.get("candidateId") == "review"
            ]
            assert len(decisions) == (0 if select_pending else 1)
            if decisions:
                assert decisions[0]["disposition"] == outcome
    assert all(file.read_bytes() == original for file, original in originals.items())


@pytest.mark.parametrize("work", ["general-same", "general-other", "candidate"])
@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("selected", [False, True])
def test_selected_reopened_report_keeps_general_task_identity_separate(
    tmp_path: Path, generic_review_recovery, work: str, complete: bool, selected: bool
) -> None:
    module, pending, _, binding = generic_review_recovery
    pending["coverage"]["deferred"][0]["candidateId"] = "review"
    terminal = copy.deepcopy(pending)
    terminal["complete"] = complete
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, pending["scanId"], tmp_path, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(candidateId="review", candidateReopened=True)
    terminal["findings"] = [finding]
    work_row = {
        "id": "other-review" if work == "general-other" else "review",
        "reason": "Independent review remains.",
        **({"candidateId": "review"} if work == "candidate" else {}),
    }
    terminal["coverage"]["deferred"] = [work_row]
    output = tmp_path / "worker"
    output.mkdir()
    result = output / "result.json"
    result.write_text(json.dumps(terminal))
    os.utime(result, ns=(200, 200))
    current = write_checkpoint(output / "checkpoints", terminal)
    older = write_checkpoint(output / "checkpoints", pending)
    for checkpoint in (current, older):
        os.utime(checkpoint, ns=(100, 100))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": current.name}))
    os.utime(head, ns=(200, 200))
    if not selected:
        module._capture_saved_source(tmp_path, "worker/checkpoint-head.json", pending["scanId"])
        head.write_text(json.dumps({"checkpoint": older.name}))
        os.utime(head, ns=(300, 300))
    originals = {file: file.read_bytes() for file in output.rglob("*.json")}
    workers = [saved_discovery_worker(output, "worker", 1)]
    first = module.merge_saved_results(
        tmp_path, pending["scanId"], binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first is not None
    replay = replay_saved_results(
        module, first, tmp_path, pending["scanId"], binding, workers, stopped=True
    )
    expected_pending = not (selected and complete and work != "candidate")
    for recovered in (first, replay):
        assert len(module.unresolved_candidates(recovered[2], recovered[1])) == int(
            expected_pending
        )
        assert len(recovered[1]["findings"]) == 1
        assert (
            recovered[1]["findings"][0]["provenance"].get("candidateReopened") is True
        ) is expected_pending
        if work != "candidate":
            assert any(
                row.get("reason") == work_row["reason"] and not row.get("candidateId")
                for row in recovered[2]["deferred"]
            )
    assert all(file.read_bytes() == original for file, original in originals.items())


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan", "complete-scan"])
@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"candidateId": None},
        {"candidateId": 0},
        {"candidateId": False},
        {"candidateId": {}},
        {"candidateId": []},
        {"candidateId": "candidate-one"},
    ],
)
def test_public_generic_metadata_closure_survives_later_progress(
    tmp_path: Path, termination: str, metadata: dict[str, object]
) -> None:
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    documents = {
        key: json.loads((scan_dir / filename).read_text())
        for key, filename in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["findings"]["findings"] = []
    documents["coverage"].update(surfaces=[], explicitExclusions=[], deferred=[])
    task = {"id": "generic-review", "reason": "Review the endpoint.", **metadata}
    closure = {"id": task["id"], "reason": "Review completed."}
    candidate = isinstance(metadata.get("candidateId"), str)
    writes = [(False, {"deferred": [task]}), (True, {"resolvedDeferred": [closure]})]
    if termination != "complete-scan":
        writes.append((False, {}))
    for complete, update in writes:
        documents["manifest"]["scan"]["complete"] = complete
        documents["coverage"].update(
            completeness="complete" if complete else "partial", deferred=[]
        )
        documents["coverage"].pop("resolvedDeferred", None)
        documents["coverage"].update(update)
        staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
        staged.parent.mkdir(exist_ok=True)
        staged.write_text(json.dumps(documents))
        run_workbench(state, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    originals = {path: path.read_bytes() for path in (scan_dir / "checkpoints").iterdir()}
    commands = (
        ("prepare-scan-completion", "complete-scan")
        if termination == "complete-scan"
        else (termination, "preserve-scan-results", "preserve-scan-results")
    )
    for command in commands:
        run_workbench(
            state,
            command,
            "--scan-id",
            scan_id,
            *(["--message", "Synthetic interruption."] if command == "fail-scan" else []),
        )
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        assert any(row.get("id") == task["id"] for row in coverage["deferred"]) is (
            candidate and termination != "complete-scan"
        )
        assert (closure in coverage.get("resolvedDeferred", [])) is not candidate
    assert all(path.read_bytes() == content for path, content in originals.items())
