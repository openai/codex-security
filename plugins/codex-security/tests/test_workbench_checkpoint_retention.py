from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from test_workbench_deep_continuation import completed_deep_fixture
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


def continue_unsealed(state: Path, repository: Path, parent_id: str, child: Path):
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
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
    return child_id, run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )


def saved_bytes(directory: Path):
    return {
        path.relative_to(directory): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
def test_stopped_standard_scan_matches_worker_provenance_to_root_decision(
    tmp_path: Path, disposition: str
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    write_completed_contract(scan_dir, scan_id, repository, relative_path="clean.ts")
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"].update(workerId="investigator-1", candidateId="candidate-1")
    finding["extensions"] = {"candidateId": "candidate-1"}
    pending = semantic(scan_id, ["clean.ts"])
    pending["findings"] = [finding]
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", pending))

    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(completeness="partial", surfaces=[], explicitExclusions=[], deferred=[])
    coverage["explicitExclusions" if disposition == "not_applicable" else "surfaces"] = [
        {
            "id": "validated-candidate",
            "candidateId": "candidate-1",
            "label": "Saved candidate validation",
            "disposition": disposition,
            "reason": "The existing containment check prevents the candidate.",
            "receiptRefs": [],
            **({"pattern": "clean.ts"} if disposition == "not_applicable" else {}),
        }
    ]
    coverage_path.write_text(json.dumps(coverage))
    run_workbench(
        state, "fail-scan", "--scan-id", scan_id, "--message", "Interrupted after validation"
    )

    assert json.loads(findings_path.read_text())["findings"] == []
    result = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert result["findingCount"] == 0


@pytest.mark.parametrize(
    ("mode", "pending_validation", "stopped"),
    [
        (mode, pending, stopped)
        for mode, pending in [("standard", False), ("deep", False), ("standard", True)]
        for stopped in (True, False)
    ],
)
def test_continuation_retains_unaccepted_findings_without_crediting_reviewed_files(
    tmp_path: Path, mode: str, pending_validation: bool, stopped: bool
) -> None:
    if mode == "deep":
        state, parent, parent_id, _, _, _ = completed_deep_fixture(tmp_path)
        repository = tmp_path / "repository"
        # An accepted empty reducer must not erase separately retained evidence.
        for result in parent.glob("artifacts/deep_discovery/*/*/output/result.json"):
            payload = semantic(parent_id, [])
            payload["complete"] = True
            payload["coverage"].update(completeness="complete", deferred=[])
            result.write_text(json.dumps(payload))
            (result.parent / "checkpoint-head.json").unlink()
    else:
        state, repository, parent, parent_id = scan_fixture(tmp_path)
    accepted = semantic(parent_id, ["clean.ts"])
    accepted["coverage"]["deferred"] = []
    if pending_validation:
        accepted["complete"] = True
        accepted["coverage"].update(
            completeness="complete", reviewedFiles=["clean.ts", "pending.ts"]
        )
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["writeup"] = {"reportPath": "findings/retained/retained.md"}
    finding["extensions"] = {"receiptRefs": ["artifacts/review/retained.json"]}
    artifacts = {
        "findings/retained/retained.md": b"# Retained finding\n\n[Proof](poc/example.bin)\n",
        "findings/retained/poc/example.bin": b"\x00retained proof\xff",
        "artifacts/review/retained.json": b'{"evidence": "saved before acceptance"}\n',
    }
    for relative, contents in artifacts.items():
        artifact = parent / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(contents)
    unaccepted = semantic(parent_id, ["clean.ts", "pending.ts"])
    unaccepted["complete"] = True
    unaccepted["findings"] = [finding]
    unaccepted["coverage"] = json.loads((contract / "coverage.json").read_text())
    unaccepted["coverage"]["reviewedFiles"] = ["clean.ts", "pending.ts"]
    unaccepted["coverage"]["surfaces"][0]["receiptRefs"] = ["artifacts/review/retained.json"]
    if pending_validation:
        unaccepted["complete"] = False
        unaccepted["coverage"].update(
            completeness="partial",
            deferred=[
                {
                    "id": "retained-validation",
                    "candidateId": "retained-validation",
                    "reason": "Additional source validation remains unresolved.",
                }
            ],
        )
    path = write_checkpoint(parent / "checkpoints", unaccepted)
    original = path.read_bytes()
    if stopped:
        run_workbench(
            state,
            "fail-scan",
            "--scan-id",
            parent_id,
            "--message",
            "Stopped before checkpoint acceptance",
        )
        retained = json.loads((parent / "findings.json").read_text())["findings"]
        assert len(retained) == 1
    else:
        # Simulate process death before head publication, acceptance, or cleanup.
        retained = [finding]
    manifest_path = parent / "scan-manifest.json"
    original_manifest = manifest_path.read_bytes() if manifest_path.exists() else None
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", parent_id)["recipe"]
    child = tmp_path / "continued"
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
    result = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child_id, "--parent-scan-id", parent_id
    )
    reviewed = ["clean.ts", "pending.ts"] if pending_validation else ["clean.ts"]
    assert result["checkpoint"]["reviewedFiles"] == reviewed
    assert result["checkpoint"]["remainingFiles"] == ([] if pending_validation else ["pending.ts"])
    assert result["completionReady"] is False
    continued = json.loads((child / "findings.json").read_text())["findings"]
    assert len(continued) == 1
    assert continued[0]["title"] == retained[0]["title"]
    assert continued[0]["codeEvidence"] == retained[0]["codeEvidence"]
    assert continued[0]["writeup"] == finding["writeup"]
    assert continued[0]["extensions"] == retained[0]["extensions"]
    for relative, contents in artifacts.items():
        assert (child / relative).read_bytes() == contents
    coverage = json.loads((child / "coverage.json").read_text())
    if mode == "standard":
        assert any(
            "artifacts/review/retained.json" in item.get("receiptRefs", [])
            for item in coverage["surfaces"]
        )
    assert all(item.get("id") != "scan-stopped" for item in coverage["deferred"])
    if pending_validation:
        assert any(
            item.get("candidateId") == "retained-validation" for item in coverage["deferred"]
        )
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)
    assert resumed["checkpoint"]["reviewedFiles"] == reviewed
    assert resumed["checkpoint"]["sources"][0]["complete"] is False
    assert resumed["checkpoint"]["sources"][0]["findings"][0]["title"] == finding["title"]
    assert (manifest_path.read_bytes() if manifest_path.exists() else None) == original_manifest
    assert path.read_bytes() == original


@pytest.mark.parametrize("rejected", [False, True])
def test_unsealed_continuation_keeps_accepted_history_resolved(tmp_path: Path, rejected: bool):
    state, repository, parent, parent_id = scan_fixture(tmp_path)
    pending = semantic(parent_id, ["clean.ts"])
    save(state, parent_id, write_checkpoint(parent / "checkpoints", pending))
    accepted = semantic(parent_id, ["clean.ts", "pending.ts"])
    accepted["complete"] = True
    accepted["coverage"].update(completeness="complete", deferred=[])
    if rejected:
        accepted["coverage"]["surfaces"] = [
            {
                "candidateId": "candidate-1",
                "label": "Reviewed candidate",
                "disposition": "rejected",
                "reason": "The source containment check prevents the candidate.",
                "receiptRefs": [],
            }
        ]
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    if rejected:
        contract = tmp_path / "contract"
        contract.mkdir()
        write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
        finding = json.loads((contract / "findings.json").read_text())["findings"][0]
        finding["extensions"] = {"candidateId": "candidate-1"}
        finding["provenance"].update(workerId="model-authored-owner", candidateId="candidate-1")
        unaccepted = semantic(parent_id, [])
        unaccepted["findings"] = [finding]
        write_checkpoint(parent / "checkpoints", unaccepted)
    original = saved_bytes(parent)
    child = tmp_path / "continued"
    _, result = continue_unsealed(state, repository, parent_id, child)
    assert result["completionReady"] is True
    assert json.loads((child / "findings.json").read_text())["findings"] == []
    coverage = json.loads((child / "coverage.json").read_text())
    assert coverage["deferred"] == []
    if rejected:
        assert coverage["surfaces"][0]["disposition"] == "rejected"
    assert saved_bytes(parent) == original


@pytest.mark.parametrize("fresh_pending", [False, True])
def test_standard_repeated_continuation_distinguishes_derived_and_fresh_pending_work(
    tmp_path: Path, fresh_pending: bool
):
    state, repository, parent, parent_id = scan_fixture(tmp_path)
    pending = semantic(parent_id, ["clean.ts"])
    save(state, parent_id, write_checkpoint(parent / "checkpoints", pending))
    for index in range(2):
        original = saved_bytes(parent)
        child = tmp_path / f"continued-{index}"
        child_id, result = continue_unsealed(state, repository, parent_id, child)
        assert result["completionReady"] is False
        deferred = json.loads((child / "coverage.json").read_text())["deferred"]
        assert len(deferred) == 1
        assert deferred[0]["candidateId"] == "candidate-1"
        assert saved_bytes(parent) == original
        parent, parent_id = child, child_id
    accepted = semantic(parent_id, ["clean.ts", "pending.ts"])
    accepted["complete"] = True
    accepted["coverage"].update(completeness="complete", deferred=[])
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    resume = run_workbench(state, "get-cli-scan-resume", "--scan-id", parent_id)
    assert len(resume["checkpoint"]["sources"]) == 1
    assert resume["checkpoint"]["sources"][0]["complete"] is True
    summary = run_workbench(state, "get-scan", "--scan-id", parent_id)["scan"]["checkpoint"]
    assert summary["pendingCount"] == 0
    if fresh_pending:
        fresh = semantic(parent_id, [])
        fresh["coverage"]["deferred"][0]["candidateId"] = "fresh-candidate"
        write_checkpoint(parent / "checkpoints", fresh)
    original = saved_bytes(parent)
    child = tmp_path / "continued-final"
    _, result = continue_unsealed(state, repository, parent_id, child)
    assert result["completionReady"] is not fresh_pending
    deferred = json.loads((child / "coverage.json").read_text())["deferred"]
    assert [row["candidateId"] for row in deferred] == (
        ["fresh-candidate"] if fresh_pending else []
    )
    assert saved_bytes(parent) == original


def test_raw_deep_workers_keep_distinct_owners_without_restorable_worker_checkpoints(
    tmp_path: Path,
):
    state, parent, parent_id, _, _, worker_ids = completed_deep_fixture(tmp_path)
    repository = tmp_path / "repository"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'failed' WHERE scan_id = ?", (parent_id,)
        )
        outputs = {
            row[0]: Path(row[1])
            for row in connection.execute(
                "SELECT id, artifact_dir FROM deep_scan_workers WHERE scan_id = ?", (parent_id,)
            )
        }
    for output in outputs.values():
        empty = semantic(parent_id, [])
        empty["coverage"]["deferred"] = []
        (output / "result.json").write_text(json.dumps(empty))
        (output / "checkpoint-head.json").unlink()
    accepted = semantic(parent_id, [])
    accepted["coverage"].update(
        deferred=[],
        surfaces=[
            {
                "candidateId": "candidate-1",
                "label": "First worker decision",
                "disposition": "rejected",
                "reason": "The first worker's candidate is prevented.",
                "receiptRefs": [],
                "provenance": {"workerId": worker_ids[0]},
            }
        ],
    )
    save(state, parent_id, write_checkpoint(parent / "checkpoints", accepted))
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    finding["provenance"].update(workerId=worker_ids[0], candidateId="candidate-1")
    raw = semantic(parent_id, [])
    raw["findings"] = [finding]
    write_checkpoint(outputs[worker_ids[1]] / "checkpoints", raw)
    original = saved_bytes(parent)
    child = tmp_path / "continued"
    _, result = continue_unsealed(state, repository, parent_id, child)
    assert result["restoredWorkers"] == 0
    findings = json.loads((child / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["provenance"]["workerId"] == worker_ids[1]
    assert saved_bytes(parent) == original


@pytest.mark.parametrize("accepted_in_archive", [False, True])
def test_unsealed_continuation_retains_archive_bytes_with_registered_worker_ownership(
    tmp_path: Path, accepted_in_archive: bool
):
    state, parent, parent_id, _, _, worker_ids = completed_deep_fixture(tmp_path)
    repository = tmp_path / "repository"
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        workers = {
            row["id"]: Path(row["artifact_dir"])
            for row in connection.execute(
                "SELECT id, artifact_dir FROM deep_scan_workers WHERE scan_id = ?", (parent_id,)
            )
        }
    for output in workers.values():
        draft = semantic(parent_id, [])
        draft["complete"] = True
        draft["coverage"].update(completeness="complete", deferred=[])
        (output / "result.json").write_text(json.dumps(draft))
        (output / "checkpoint-head.json").unlink()
    first, second = (workers[worker_id] for worker_id in worker_ids[:2])
    accepted = semantic(parent_id, [])
    accepted["coverage"].update(
        deferred=[],
        surfaces=[
            {
                "candidateId": "shared-candidate",
                "label": "First worker decision",
                "disposition": "rejected",
                "reason": "The first worker's candidate is prevented.",
                "receiptRefs": [],
            }
        ],
    )
    save(state, parent_id, write_checkpoint(first / "checkpoints", accepted))
    pending = semantic(parent_id, [])
    pending["coverage"]["deferred"][0]["candidateId"] = "old-accepted-candidate"
    old = write_checkpoint(second / "checkpoints", pending)
    save(state, parent_id, old)
    archive = second.parent / "attempts" / "attempt-1"
    (archive / "checkpoints").mkdir(parents=True)
    old.rename(archive / "checkpoints" / old.name)
    complete = semantic(parent_id, [])
    complete["complete"] = True
    complete["coverage"].update(completeness="complete", deferred=[])
    if accepted_in_archive:
        complete["coverage"]["surfaces"] = [
            {
                "candidateId": "archived-decision",
                "label": "Accepted archived decision",
                "disposition": "rejected",
                "reason": "Saved validation evidence rules out the candidate.",
                "receiptRefs": ["artifacts/receipts/saved.json"],
            }
        ]
    complete_path = write_checkpoint(second / "checkpoints", complete)
    save(state, parent_id, complete_path)
    if accepted_in_archive:
        complete_path.rename(archive / "checkpoints" / complete_path.name)
        (second / "checkpoint-head.json").rename(archive / "checkpoint-head.json")

    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(workerId=worker_ids[0], candidateId="shared-candidate")
    finding["extensions"] = {
        "candidateId": "shared-candidate",
        "receiptRefs": ["artifacts/receipts/saved.json"],
    }
    finding["writeup"] = {"reportPath": "findings/saved/saved.md"}
    artifacts = {
        "findings/saved/saved.md": b"# Archived evidence\n\n[Proof](poc/proof.bin)\n",
        "findings/saved/poc/proof.bin": b"\x00archived proof\xff",
        "artifacts/receipts/saved.json": b'{"evidence":"archive"}\n',
    }
    physical_source = second if accepted_in_archive else archive
    other_source = archive if accepted_in_archive else second
    for relative, contents in artifacts.items():
        for directory, prefix in [(physical_source, b""), (other_source, b"different bytes: ")]:
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(prefix + contents)
    raw = semantic(parent_id, ["pending.ts"])
    raw["findings"] = [finding]
    raw["coverage"]["deferred"][0]["candidateId"] = "shared-candidate"
    write_checkpoint(physical_source / "checkpoints", raw)
    # A neighboring partial write cannot hide the intact checkpoint.
    (archive / "checkpoints" / ("f" * 64 + ".json")).write_text('{"scanId":')
    original = saved_bytes(parent)
    child = tmp_path / "continued"
    child_id, result = continue_unsealed(state, repository, parent_id, child)
    assert result["checkpoint"]["reviewedFiles"] == []
    assert result["completionReady"] is False
    findings = json.loads((child / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        second_id = connection.execute(
            "SELECT id FROM deep_scan_workers WHERE scan_id = ? AND artifact_dir = ?",
            (child_id, str(child / second.relative_to(parent))),
        ).fetchone()[0]
    assert findings[0]["provenance"]["workerId"] == second_id
    report = child / findings[0]["writeup"]["reportPath"]
    assert report.read_bytes() == artifacts["findings/saved/saved.md"]
    assert (report.parent / "poc" / "proof.bin").read_bytes() == artifacts[
        "findings/saved/poc/proof.bin"
    ]
    receipt = findings[0]["extensions"]["receiptRefs"][0]
    assert (child / receipt).read_bytes() == artifacts["artifacts/receipts/saved.json"]
    coverage = json.loads((child / "coverage.json").read_text())
    if accepted_in_archive:
        decision = next(
            row for row in coverage["surfaces"] if row.get("candidateId") == "archived-decision"
        )
        saved_receipt = decision["receiptRefs"][0]
        assert saved_receipt != receipt
        assert (child / saved_receipt).read_bytes() == (
            b"different bytes: " + artifacts["artifacts/receipts/saved.json"]
        )
    else:
        assert receipt == (archive.relative_to(parent) / "artifacts/receipts/saved.json").as_posix()
    deferred = coverage["deferred"]
    assert not any(item.get("candidateId") == "old-accepted-candidate" for item in deferred)
    assert any(
        item.get("candidateId") == "shared-candidate"
        and item.get("provenance", {}).get("workerId") == second_id
        for item in deferred
    )
    assert saved_bytes(parent) == original
