from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sqlite3
import uuid
from pathlib import Path, PureWindowsPath

import pytest
from test_workbench_checkpoint_attachments import continue_scan
from test_workbench_scan_checkpoints import save, scan_fixture, semantic
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.mark.parametrize("archived", [False, True])
def test_worker_writeups_keep_local_and_aggregate_ownership_after_continuation(
    tmp_path: Path, workbench_api, archived: bool
):
    state, repository, parent, parent_id = scan_fixture(tmp_path, "deep")
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    template = json.loads((contract / "findings.json").read_text())["findings"][0]
    local_report = "findings/shared/shared.md"
    local_poc = "findings/shared/poc/input.bin"

    def write_report(output: Path, report: str, label: str) -> tuple[bytes, bytes]:
        contents = f"# {label}\n\n[Proof](poc/input.bin)\n".encode()
        poc = b"\x00" + label.encode() + b"\xff"
        (output / report).parent.mkdir(parents=True, exist_ok=True)
        (output / report).write_bytes(contents)
        poc_path = output / Path(report).parent / "poc/input.bin"
        poc_path.parent.mkdir(parents=True, exist_ok=True)
        poc_path.write_bytes(poc)
        return contents, poc

    def finding(label: str, owner: str | None, report: str) -> dict:
        value = copy.deepcopy(template)
        value["title"] = label
        value["identity"]["anchor"] = label
        value["extensions"] = {"candidateId": label}
        value["provenance"]["candidateId"] = label
        if owner:
            value["provenance"]["workerId"] = owner
        value["writeup"] = {"reportPath": report}
        return value

    original_workers = {}
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, discovery_runs_dispatched, "
            "created_at, updated_at) VALUES (?, 1, 'deep-security-scan/v1', 'failed', 'terminal', "
            "2, 0, 2, 2, 2, '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
            (parent_id,),
        )
        for index in range(2):
            worker_id = str(uuid.uuid4())
            output = parent / f"artifacts/deep_discovery/workers/discovery-{index}/output"
            output.mkdir(parents=True)
            prompt = output.parent / "prompt.md"
            prompt.write_text("Synthetic resumed discovery\n")
            original_workers[worker_id] = output.relative_to(parent).as_posix()
            connection.execute(
                "INSERT INTO deep_scan_workers (id, scan_id, kind, status, prompt_path, artifact_dir, "
                "attempt, created_at, updated_at) VALUES (?, ?, 'discovery', 'failed', ?, ?, 1, "
                "'2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
                (worker_id, parent_id, str(prompt), str(output)),
            )

    evidence = {}
    original_snapshots = {}
    for index, (owner, source) in enumerate([(None, "."), *original_workers.items()]):
        label = f"source-{index}"
        output = parent / source
        evidence[label] = write_report(output, local_report, label)
        payload = semantic(parent_id, ["clean.ts"])
        payload["findings"] = [finding(label, owner, local_report)]
        deferred = payload["coverage"]["deferred"][0]
        deferred["candidateId"] = label
        deferred["candidate"] = {
            "summary": f"Finish validation for {label}",
            "writeup": {"reportPath": local_report},
        }
        if owner:
            deferred["provenance"] = {"workerId": owner}
        snapshot = write_checkpoint(output / "checkpoints", payload)
        save(state, parent_id, snapshot)
        if archived and owner:
            old_output = output.parent / "attempts/attempt-01"
            old_output.parent.mkdir()
            shutil.move(output, old_output)
            output.mkdir()
            snapshot = old_output / "checkpoints" / snapshot.name
        original_snapshots[snapshot] = snapshot.read_bytes()

    def assert_report(output: Path, report: str, label: str) -> None:
        contents, poc = evidence[label]
        assert (output / report).read_bytes() == contents
        assert (output / Path(report).parent / "poc/input.bin").read_bytes() == poc

    owners = original_workers
    aggregate_paths = None
    for attempt in range(2):
        child = tmp_path / f"child-{attempt}"
        child_id = continue_scan(state, repository, parent_id, child)
        owners = {
            str(uuid.uuid5(uuid.UUID(child_id), owner)): source for owner, source in owners.items()
        }
        findings = json.loads((child / "findings.json").read_text())["findings"]
        paths = {item["title"]: item["writeup"]["reportPath"] for item in findings}
        assert len(findings) == len(set(paths.values())) == 3
        assert paths["source-0"] == local_report
        if aggregate_paths is not None:
            assert paths == aggregate_paths
        aggregate_paths = paths
        for label, report in paths.items():
            assert_report(child, report, label)
        coverage = json.loads((child / "coverage.json").read_text())
        assert len(coverage["deferred"]) == 3
        for item in coverage["deferred"]:
            label = item["candidateId"]
            assert item["candidate"]["writeup"]["reportPath"] == paths[label]

        checkpoint = run_workbench(state, "get-cli-scan-resume", "--scan-id", child_id)[
            "checkpoint"
        ]
        for source in checkpoint["sources"]:
            if source["source"] == ".":
                continue
            saved = source["findings"][0]
            assert saved["writeup"]["reportPath"] == local_report
            assert (
                source["coverage"]["deferred"][0]["candidate"]["writeup"]["reportPath"]
                == local_report
            )
            assert_report(child / source["source"], local_report, saved["title"])
            assert saved["provenance"]["workerId"] in owners
        parent_id = child_id

    for snapshot, contents in original_snapshots.items():
        assert snapshot.read_bytes() == contents
    worker_id, source = next(iter(owners.items()))
    saved = next(item for item in checkpoint["sources"] if item["source"] == source)
    output = child / source
    resumed_report = "findings/resumed/resumed.md"
    evidence["resumed"] = write_report(output, resumed_report, "resumed")
    result = semantic(child_id, ["clean.ts", "pending.ts"])
    result["complete"] = True
    result["findings"] = [*saved["findings"], finding("resumed", worker_id, resumed_report)]
    result["coverage"].update(completeness="complete", deferred=[])
    result_path = output / "result.json"
    result_path.write_text(json.dumps(result))
    arguments = (
        "--scan-id",
        child_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--prompt-path",
        str(output.parent / "prompt.md"),
        "--artifact-dir",
        str(output),
        "--attempt",
        "1",
    )
    run_workbench(state, "upsert-deep-scan-worker", *arguments, "--status", "running")
    run_workbench(
        state,
        "upsert-deep-scan-worker",
        *arguments,
        "--status",
        "succeeded",
        "--result-manifest-path",
        str(result_path),
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        documents = workbench_api["scan_checkpoints"].continued_deep_documents(
            connection,
            scan,
            workbench_api["workbench_completion_binding"](scan, workbench_api["now"]()),
            [],
        )
    final_findings = documents[1]["findings"]
    assert {item["title"] for item in final_findings} == {*evidence}
    for item in final_findings:
        assert_report(child, item["writeup"]["reportPath"], item["title"])
    assert (output / resumed_report).read_bytes() == evidence["resumed"][0]
    assert (parent / local_poc).read_bytes() == evidence["source-0"][1]

    # The host reducer retains each source finding but does not copy discovery
    # reports into its own output directory.
    other_id, other_source = next(item for item in owners.items() if item[0] != worker_id)
    other_output = child / other_source
    other_saved = next(item for item in checkpoint["sources"] if item["source"] == other_source)
    other_result = semantic(child_id, ["clean.ts", "pending.ts"])
    other_result["complete"] = True
    other_result["findings"] = other_saved["findings"]
    other_result["coverage"].update(completeness="complete", deferred=[])
    other_path = other_output / "result.json"
    other_path.write_text(json.dumps(other_result))
    for status in ("running", "succeeded"):
        run_workbench(
            state,
            "upsert-deep-scan-worker",
            "--scan-id",
            child_id,
            "--worker-id",
            other_id,
            "--kind",
            "discovery",
            "--status",
            status,
            "--prompt-path",
            str(other_output.parent / "prompt.md"),
            "--artifact-dir",
            str(other_output),
            "--attempt",
            "1",
            *(("--result-manifest-path", str(other_path)) if status == "succeeded" else ()),
        )
    source_results = {worker_id: result, other_id: other_result}
    reducer_id = str(uuid.uuid4())
    reducer_output = child / "artifacts/deep_discovery/dedup/reducer/output"
    reducer_output.mkdir(parents=True)
    reducer_prompt = reducer_output.parent / "prompt.md"
    reducer_prompt.write_text("Synthetic reduction\n")
    run_workbench(
        state,
        "claim-deep-scan-dedup",
        "--scan-id",
        child_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(reducer_prompt),
        "--artifact-dir",
        str(reducer_output),
        "--input-worker-id",
        worker_id,
        "--input-worker-id",
        other_id,
    )
    run_workbench(
        state,
        "upsert-deep-scan-worker",
        "--scan-id",
        child_id,
        "--worker-id",
        reducer_id,
        "--kind",
        "dedup",
        "--status",
        "running",
        "--prompt-path",
        str(reducer_prompt),
        "--artifact-dir",
        str(reducer_output),
        "--attempt",
        "1",
    )
    reduction = {"scanId": child_id, "findings": []}
    for owner, source_result in source_results.items():
        for index, original in enumerate(source_result["findings"]):
            item = copy.deepcopy(original)
            source_id = f"{owner}:{index}"
            item["provenance"]["sourceFindingIds"] = [source_id]
            item["provenance"]["sourceFindings"] = [
                {"id": source_id, "finding": copy.deepcopy(original)}
            ]
            reduction["findings"].append(item)
    reducer_result = reducer_output / "result.json"
    reducer_result.write_text(json.dumps(reduction))
    original_reduction = reducer_result.read_bytes()
    run_workbench(
        state,
        "commit-deep-scan-dedup",
        "--scan-id",
        child_id,
        "--worker-id",
        reducer_id,
        "--result-manifest-path",
        str(reducer_result),
        "--new-findings-count",
        "0",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        scan = connection.execute("SELECT * FROM scans WHERE id = ?", (child_id,)).fetchone()
        reduced = workbench_api["scan_checkpoints"].continued_deep_documents(
            connection,
            scan,
            workbench_api["workbench_completion_binding"](scan, workbench_api["now"]()),
            [],
        )
    reduced_findings = reduced[1]["findings"]
    assert {item["title"] for item in reduced_findings} == set(evidence)
    retained_sources = []
    for item in reduced_findings:
        assert_report(child, item["writeup"]["reportPath"], item["title"])
        for retained in item.get("provenance", {}).get("sourceFindings", []):
            source_finding = retained["finding"]
            assert_report(child, source_finding["writeup"]["reportPath"], source_finding["title"])
            retained_sources.append(retained["id"])
    # Unchanged inherited findings can reuse the baseline; this new finding
    # must come from the reducer together with its retained discovery source.
    assert f"{worker_id}:1" in retained_sources
    assert reducer_result.read_bytes() == original_reduction
    assert not (reducer_output / "findings").exists()


@pytest.mark.parametrize(
    ("changed_owner", "changed_artifact"),
    [
        ("canonical", "report"),
        ("canonical", "poc"),
        ("canonical", "extra-poc"),
        ("worker", "report"),
        ("worker", "poc"),
        ("worker", "removed-poc"),
    ],
)
def test_finalization_preserves_distinct_canonical_and_worker_writeups(
    tmp_path: Path, changed_owner: str, changed_artifact: str
):
    state, repository, parent, parent_id = scan_fixture(tmp_path, "deep")
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, parent_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    report = "findings/shared/shared.md"
    finding["writeup"] = {"reportPath": report}
    finding["extensions"] = {"candidateId": "inherited-candidate"}
    worker_id = str(uuid.uuid4())
    finding["provenance"]["workerId"] = worker_id
    source = "artifacts/deep_discovery/workers/discovery-0001/output"
    output = parent / source
    output.mkdir(parents=True)
    prompt = output.parent / "prompt.md"
    prompt.write_text("Synthetic independent review\n")
    original_report = b"# Original report\n\n[Proof](poc/input.bin)\n"
    original_poc = b"\x00original proof\xff"
    (output / report).parent.mkdir(parents=True)
    (output / report).write_bytes(original_report)
    (output / Path(report).parent / "poc").mkdir()
    (output / Path(report).parent / "poc/input.bin").write_bytes(original_poc)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, "
            "workers, subagents, stop_after_no_new, max_discovery_runs, discovery_runs_dispatched, "
            "created_at, updated_at) VALUES (?, 1, 'deep-security-scan/v1', 'failed', 'terminal', "
            "1, 0, 2, 2, 1, '2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
            (parent_id,),
        )
        connection.execute(
            "INSERT INTO deep_scan_workers (id, scan_id, kind, status, prompt_path, artifact_dir, "
            "attempt, created_at, updated_at) VALUES (?, ?, 'discovery', 'failed', ?, ?, 1, "
            "'2026-01-01T00:00:00Z', '2026-01-01T01:00:00Z')",
            (worker_id, parent_id, str(prompt), str(output)),
        )
    partial = semantic(parent_id, ["clean.ts"])
    partial["findings"] = [finding]
    partial["coverage"]["deferred"] = []
    save(state, parent_id, write_checkpoint(output / "checkpoints", partial))
    child = tmp_path / "child"
    child_id = continue_scan(state, repository, parent_id, child)
    worker_id = str(uuid.uuid5(uuid.UUID(child_id), worker_id))
    output = child / source
    canonical_findings = json.loads((child / "findings.json").read_text())
    canonical_coverage = json.loads((child / "coverage.json").read_text())
    canonical_report = canonical_findings["findings"][0]["writeup"]["reportPath"]
    write_completed_contract(child, child_id, repository, relative_path="clean.ts")
    (child / "findings.json").write_text(json.dumps(canonical_findings))
    (child / "coverage.json").write_text(json.dumps(canonical_coverage))
    worker_finding = copy.deepcopy(finding)
    worker_finding["provenance"]["workerId"] = worker_id
    if changed_owner == "worker":
        worker_finding["identity"]["anchor"] = "new-worker-candidate"
        worker_finding["title"] = "New independent finding"
        worker_finding["extensions"]["candidateId"] = "new-worker-candidate"
    changed_root = child if changed_owner == "canonical" else output
    changed_report = canonical_report if changed_owner == "canonical" else report
    updated_report = b"# Updated report\n\n[Proof](poc/input.bin)\n"
    updated_poc = b"\x00updated proof\xff"
    changed_path = changed_root / (
        changed_report
        if changed_artifact == "report"
        else Path(changed_report).parent / "poc/input.bin"
    )
    if changed_artifact == "removed-poc":
        changed_path.unlink()
    elif changed_artifact == "extra-poc":
        changed_path.with_name("extra.bin").write_bytes(updated_poc)
    else:
        changed_path.write_bytes(updated_report if changed_artifact == "report" else updated_poc)
    result = semantic(child_id, ["clean.ts"])
    result.update(complete=True, findings=[worker_finding])
    result["coverage"].update(completeness="complete", deferred=[])
    result_path = output / "result.json"
    result_path.write_text(json.dumps(result))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'succeeded', result_manifest_path = ? WHERE id = ?",
            (str(result_path), worker_id),
        )
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', manifest_path = ? WHERE scan_id = ?",
            (str(child / "scan-manifest.json"), child_id),
        )

    run_workbench(state, "prepare-scan-completion", "--scan-id", child_id)
    final_findings = json.loads((child / "findings.json").read_text())["findings"]
    inherited = next(item for item in final_findings if item["title"] == finding["title"])
    assert inherited["writeup"]["reportPath"] == canonical_report
    assert (child / canonical_report).read_bytes() == (
        updated_report
        if (changed_owner, changed_artifact) == ("canonical", "report")
        else original_report
    )
    assert (child / Path(canonical_report).parent / "poc/input.bin").read_bytes() == (
        updated_poc if (changed_owner, changed_artifact) == ("canonical", "poc") else original_poc
    )
    if changed_owner == "worker":
        current = next(
            item for item in final_findings if item["title"] == "New independent finding"
        )
        current_report = current["writeup"]["reportPath"]
        assert current_report != canonical_report
        assert (child / current_report).read_bytes() == (
            updated_report if changed_artifact == "report" else original_report
        )
        current_poc = child / Path(current_report).parent / "poc/input.bin"
        if changed_artifact == "removed-poc":
            assert not current_poc.exists()
        else:
            assert current_poc.read_bytes() == (
                updated_poc if changed_artifact == "poc" else original_poc
            )
    else:
        historical = next(
            item
            for item in inherited["provenance"]["previousFindings"]
            if item.get("writeup", {}).get("reportPath") != canonical_report
        )
        historical_report = historical["writeup"]["reportPath"]
        assert (child / historical_report).read_bytes() == original_report
        assert (
            child / Path(historical_report).parent / "poc/input.bin"
        ).read_bytes() == original_poc
        assert not (child / Path(historical_report).parent / "poc/extra.bin").exists()
        if changed_artifact == "extra-poc":
            assert (
                child / Path(canonical_report).parent / "poc/extra.bin"
            ).read_bytes() == updated_poc
    retained = {
        path: path.read_bytes() for path in (child / "findings").rglob("*") if path.is_file()
    }
    run_workbench(state, "prepare-scan-completion", "--scan-id", child_id)
    assert retained == {path: path.read_bytes() for path in retained}


def test_sealed_writeup_copy_distinguishes_case_sensitive_windows_directories(
    tmp_path: Path, workbench_api
):
    parent = tmp_path / "scan"
    child = tmp_path / "SCAN"
    parent.mkdir()
    if child.exists():
        pytest.skip("The fixture filesystem does not support case-distinct directories")
    child.mkdir()
    report = "findings/shared/shared.md"
    contents = b"# Retained report\n"
    (parent / report).parent.mkdir(parents=True)
    (parent / report).write_bytes(contents)

    class WindowsEqualityPath(type(Path())):
        def __hash__(self):
            return hash(PureWindowsPath(str(self)))

        def __eq__(self, other):
            return PureWindowsPath(str(self)) == PureWindowsPath(str(other))

    assert WindowsEqualityPath(parent) == WindowsEqualityPath(child)
    assert not parent.samefile(child)
    result, _, missing = workbench_api["scan_checkpoints"].copy_checkpoint_writeups(
        WindowsEqualityPath(parent),
        WindowsEqualityPath(child),
        {"findings": [{"writeup": {"reportPath": report}}]},
        ".",
        sealed_artifacts={report: hashlib.sha256(contents).hexdigest()},
    )
    assert result["findings"][0]["writeup"]["reportPath"] == report
    assert not missing
    assert (child / report).read_bytes() == (parent / report).read_bytes() == contents
