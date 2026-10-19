from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import (
    add_worker,
    complete,
    fail_scan,
    preserve_scan_results,
    recover_scan_results,
)
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_standard_deep_results import deep_scan_fixture, worker_paths
from workbench_test_support import (
    interrupt_publication,
    read_review_state,
    run_workbench,
    saved_draft,
    sort_checkpoint_entries,
    write_checkpoint,
    write_completed_contract,
)


def captured_head(scan_dir, directory):
    head = scan_dir / directory / "checkpoint-head.json"
    observation = {
        **json.loads(head.read_text()),
        "observedAtNs": str(head.stat().st_mtime_ns),
    }
    digest = hashlib.sha256(
        json.dumps(observation, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    relative = (Path(directory) / "checkpoint-heads" / f"{digest}.json").as_posix()
    assert json.loads((scan_dir / relative).read_text()) == observation
    return relative


@pytest.mark.parametrize("source_name", ["ordinary-source.json", "sourceTimes"])
@pytest.mark.parametrize("replay", ["preserve", "recover"])
def test_flat_retained_source_name_replays(
    workbench_api, workbench_db, publication_scan, source_name, replay
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    add_worker(workbench_db, scan, status="canceled")
    source = scan.scan_dir / source_name
    source.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": scan.findings,
                "coverage": scan.coverage,
            }
        )
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE scan_id = ?",
            (str(source), scan.scan_id),
        )
    stopped = fail_scan(workbench_api, workbench_db, scan, "Stopped scan.")
    assert stopped["findingCount"] == 1
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert isinstance(retained[source_name], str)
    if replay == "preserve":
        replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    else:
        replayed = recover_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == 1
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == findings


def test_public_stop_retains_accepted_partial_evidence_and_newer_rejection(tmp_path):
    state, home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    environment = {"CODEX_HOME": str(home)}
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, target, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    deferred = {
        "candidateId": "pending-query",
        "reason": "Validation is pending.",
        "paths": ["app.py"],
    }
    coverage = {
        "completeness": "partial",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [deferred],
    }
    workers = []
    for accepted in (True, False):
        name = "accepted" if accepted else "interrupted"
        prompt, output, result = worker_paths(scan_dir, name)
        worker_id = str(uuid.uuid4())
        worker_args = (
            "upsert-deep-scan-worker",
            "--scan-id",
            scan_id,
            "--worker-id",
            worker_id,
            "--kind",
            "discovery",
            "--prompt-path",
            str(prompt),
            "--artifact-dir",
            str(output),
            "--attempt",
            "1",
        )
        run_workbench(state, *worker_args, "--status", "running", environment=environment)
        current = copy.deepcopy(finding)
        current["identity"]["anchor"] = name
        current["extensions"] = {"candidateId": name}
        draft = {"scanId": scan_id, "complete": True, "findings": [current], "coverage": coverage}
        result.write_text(json.dumps(draft))
        write_checkpoint(output / "checkpoints", draft)
        if accepted:
            run_workbench(
                state,
                *worker_args,
                "--status",
                "succeeded",
                "--result-manifest-path",
                str(result),
                environment=environment,
            )
        else:
            rejected = {
                **draft,
                "complete": False,
                "findings": [],
                "coverage": {
                    **coverage,
                    "surfaces": [
                        {
                            "candidateId": name,
                            "label": "Reviewed candidate",
                            "disposition": "rejected",
                            "receiptRefs": [],
                        }
                    ],
                },
            }
            head = write_checkpoint(output / "checkpoints", rejected)
            pointer = output / "checkpoint-head.json"
            pointer.write_text(json.dumps({"checkpoint": head.name}))
            observed = result.stat().st_mtime_ns
            os.utime(pointer, ns=(observed, observed))
        workers.append(worker_id)

    stopped = run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Original worker failure.",
        "--deep-status",
        "interrupted",
        environment=environment,
    )["deepScan"]
    assert stopped["status"] == "interrupted"
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == 1
    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert [item["identity"]["anchor"] for item in findings] == ["accepted"]
    retained_coverage = read_review_state(state, scan_dir)
    assert "completeness" not in retained_coverage
    assert any(item.get("candidateId") == "pending-query" for item in retained_coverage["deferred"])
    assert any(
        item.get("candidateId") == "interrupted" and item["disposition"] == "rejected"
        for item in retained_coverage["surfaces"]
    )
    assert scan["failureMessage"] == "Original worker failure."
    assert {worker["id"]: worker["status"] for worker in stopped["workers"]} == {
        workers[0]: "succeeded",
        workers[1]: "canceled",
    }


@pytest.mark.parametrize("archived", [False, True], ids=["current", "archived"])
@pytest.mark.parametrize("has_head", [True, False], ids=["committed-head", "legacy"])
@pytest.mark.parametrize("complete", [False, True], ids=["checkpoint", "complete"])
def test_recovery_honors_rejection_committed_before_result_replacement(
    workbench_api, workbench_db, publication_scan, archived, has_head, complete
):
    scan = publication_scan()
    provisional = copy.deepcopy(scan.findings[0])
    provisional["extensions"] = {"candidateId": "candidate-rejected"}
    retained = copy.deepcopy(scan.findings[0])
    retained["identity"]["anchor"] = "independent-finding"
    retained["extensions"] = {"candidateId": "candidate-retained"}
    retained["locations"][0]["startLine"] = 20
    retained["locations"][0]["endLine"] = 21
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result_path = add_worker(workbench_db, scan, status="canceled")
    if archived:
        result_path = result_path.parent / "attempts" / "attempt-1" / "result.json"
        result_path.parent.mkdir(parents=True)
    previous = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [provisional, retained],
        "coverage": scan.coverage,
    }
    result_path.write_text(json.dumps(previous))
    old_checkpoint = write_checkpoint(result_path.parent / "checkpoints", previous)
    rejected = {
        **previous,
        "complete": complete,
        "findings": [retained],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-rejected",
                    "label": "Validated candidate disposition",
                    "disposition": "rejected",
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(result_path.parent / "checkpoints", rejected)
    if has_head:
        head = result_path.parent / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        # Model a committed replacement after the older result, even when the
        # filesystem assigns the same timestamp to these consecutive writes.
        observed = max(result_path.stat().st_mtime_ns, checkpoint.stat().st_mtime_ns) + 1
        os.utime(head, ns=(observed, observed))
    saved_bytes = {path: path.read_bytes() for path in (result_path, old_checkpoint, checkpoint)}

    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert stopped["findingCount"] == len(findings) == (1 if has_head else 2)
    assert any(finding["identity"]["anchor"] == "independent-finding" for finding in findings)
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())
    if has_head:
        coverage = read_review_state(workbench_db, scan.scan_dir)
        assert any(
            surface.get("candidateId") == "candidate-rejected"
            and surface.get("disposition") == "rejected"
            for surface in coverage["surfaces"]
        )


def save_disposition(scan, directory, disposition):
    directory.mkdir(parents=True, exist_ok=True)
    finding = copy.deepcopy(scan.findings[0])
    finding["extensions"] = {"candidateId": "candidate-disposition"}
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [finding] if disposition == "reported" else [],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-disposition",
                    "label": "Validated candidate disposition",
                    "disposition": disposition,
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(directory / "checkpoints", draft)
    head = directory / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    result = directory / "result.json"
    observed = (
        max(
            checkpoint.stat().st_mtime_ns,
            result.stat().st_mtime_ns if result.exists() else 0,
        )
        + 1
    )
    os.utime(head, ns=(observed, observed))
    return draft


@pytest.mark.parametrize("legacy_publication", [False, True], ids=["observation", "payload"])
@pytest.mark.parametrize("selected_time", [100, 300], ids=["restored-older", "unchanged-latest"])
def test_recovery_needed_compares_checkpoint_observation(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    legacy_publication,
    selected_time,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    os.utime(result, ns=(200, 200))
    save_disposition(scan, result.parent, "rejected")
    head = result.parent / "checkpoint-head.json"
    os.utime(head, ns=(100, 100))
    directory = result.parent.relative_to(scan.scan_dir).as_posix()
    saved = workbench_api["saved_results"]
    capture = saved._capture_saved_source

    def capture_legacy_head(scan_dir, relative, scan_id, **kwargs):
        captured = capture(scan_dir, relative, scan_id, **kwargs)
        heads = kwargs.get("checkpoint_heads")
        if heads is not None and relative == f"{directory}/checkpoint-head.json":
            # Legacy writers selected the payload while retaining every observation.
            heads[directory] = next(
                path for path in captured if Path(path).parent.name == "checkpoints"
            )
        return captured

    with monkeypatch.context() as patch:
        if legacy_publication:
            patch.setattr("workbench.retained_coverage._capture_saved_source", capture_legacy_head)
            patch.setattr(saved, "_capture_saved_source", capture_legacy_head)
        stopped = fail_scan(workbench_api, workbench_db, scan)
        assert stopped["findingCount"] == 1
        os.utime(head, ns=(300, 300))
        published = recover_scan_results(workbench_api, workbench_db, scan)
        assert published["findingCount"] == 0

    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    sources = manifest["preservedSources"]
    assert sorted(
        int(json.loads((scan.scan_dir / path).read_text())["observedAtNs"])
        for path in sources
        if Path(path).parent.as_posix() == f"{directory}/checkpoint-heads"
    ) == [100, 300]
    assert Path(manifest["preservedCheckpointHeads"][directory]).parent.name == (
        "checkpoints" if legacy_publication else "checkpoint-heads"
    )
    assert not workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    os.utime(head, ns=(selected_time, selected_time))
    assert workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ] is (selected_time == 100)
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == (1 if selected_time == 100 else 0)
    assert not recovered["resultsRecoveryNeeded"]
    final = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert final["preservedSources"] == sources
    assert final["preservedCheckpointHeads"][directory] == captured_head(scan.scan_dir, directory)


@pytest.mark.parametrize("archived", [False, True], ids=["current-head", "newer-archive"])
@pytest.mark.parametrize("disposition", ["reported", "rejected"])
def test_newer_checkpoint_disposition_precedes_older_archived_head(
    workbench_api, workbench_db, publication_scan, archived, disposition
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = 3 WHERE scan_id = ?", (scan.scan_id,)
        )
    old = result.parent / "attempts" / "attempt-2"
    save_disposition(scan, old, "rejected" if disposition == "reported" else "reported")
    current = result.parent / "attempts" / "attempt-10" if archived else result.parent
    draft = save_disposition(scan, current, disposition)
    (current / "result.json").write_text(json.dumps(draft))

    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")

    assert stopped["findingCount"] == (1 if disposition == "reported" else 0)


@pytest.mark.parametrize("head_change", ["replaced", "removed", "missing-checkpoint"])
@pytest.mark.parametrize("root_head", [False, True], ids=["worker", "root"])
def test_frozen_stopped_replay_ignores_later_worker_head_changes(
    workbench_api, workbench_db, publication_scan, monkeypatch, head_change, root_head
):
    import finalize_scan_contract

    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = (
        scan.scan_dir / "result.json"
        if root_head
        else add_worker(workbench_db, scan, status="canceled")
    )
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    directory = result.parent.relative_to(scan.scan_dir).as_posix()
    head = result.parent / "checkpoint-head.json"
    original_head = (head.read_bytes(), head.stat().st_mtime_ns)
    original_outputs = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
        if (scan.scan_dir / name).exists()
    }
    write_bytes = finalize_scan_contract.write_scan_local_bytes
    failed_writes = []

    def fail_manifest_write(directory, relative, payload, **kwargs):
        if relative != "scan-manifest.json" or failed_writes:
            return write_bytes(directory, relative, payload, **kwargs)
        # Exercise the real writer after findings have reached disk. Remove the
        # temporary obstruction before the publisher restores its old outputs.
        failed_writes.append(json.loads((directory / "findings.json").read_text()))
        path = directory / relative
        previous_bytes = path.read_bytes()
        path.unlink()
        path.mkdir()
        try:
            return write_bytes(directory, relative, payload, **kwargs)
        finally:
            path.rmdir()
            path.write_bytes(previous_bytes)

    with monkeypatch.context() as patch:
        patch.setattr(finalize_scan_contract, "write_scan_local_bytes", fail_manifest_write)
        fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    if not root_head:
        assert (head.read_bytes(), head.stat().st_mtime_ns) == original_head
    expected_heads = {directory: captured_head(scan.scan_dir, directory)}
    assert len(failed_writes) == 1
    assert "scanId" in failed_writes[0]
    assert row["status"] == "failed"
    assert row["failure_message"] == "Audit stopped."
    assert row["retained_source_digests_json"]
    assert row["seal_manifest_digest"] is None
    assert all(
        (scan.scan_dir / name).read_bytes() == contents
        for name, contents in original_outputs.items()
    )
    original_sources = row["retained_source_digests_json"]
    original_run = dict(
        workbench_db.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()
    )
    if head_change == "replaced":
        save_disposition(scan, result.parent, "reported")
    elif head_change == "removed":
        head.unlink()
    else:
        head.write_text(json.dumps({"checkpoint": "a" * 64 + ".json"}))

    replayed = preserve_scan_results(workbench_api, workbench_db, scan)

    assert replayed["findingCount"] == 0
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == []
    assert json.loads(result.read_text()) == previous
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["failure_message"] == "Audit stopped."
    assert row["retained_source_digests_json"] == original_sources
    assert json.loads(row["retained_checkpoint_heads_json"]) == expected_heads
    assert row["seal_manifest_digest"]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["preservedCheckpointHeads"] == expected_heads
    assert (
        dict(
            workbench_db.execute(
                "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
            ).fetchone()
        )
        == original_run
    )


def test_explicit_recovery_observes_head_change_between_existing_checkpoints(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    assert stopped["findingCount"] == 0

    save_disposition(scan, result.parent, "reported")

    context = workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]
    assert context["resultsRecoveryNeeded"] is True
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


def test_legacy_frozen_publication_keeps_result_fallback_without_saved_heads(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    (result.parent / "checkpoint-head.json").unlink()

    with monkeypatch.context() as patch:
        patch.setattr(
            workbench_api["saved_results"],
            "_write_prepared_scan_finalization",
            interrupt_publication,
        )
        fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    save_disposition(scan, result.parent, "rejected")

    replayed = preserve_scan_results(workbench_api, workbench_db, scan)

    assert replayed["findingCount"] == 1


@pytest.mark.parametrize("head_time", [0, 1, -1], ids=["tie", "newer", "older"])
@pytest.mark.parametrize("root_head", [False, True], ids=["worker", "root"])
def test_recovery_uses_live_selection_regardless_of_head_timestamp(
    workbench_api, workbench_db, publication_scan, head_time, root_head
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = (
        scan.scan_dir / "result.json"
        if root_head
        else add_worker(workbench_db, scan, status="canceled")
    )
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    head = result.parent / "checkpoint-head.json"
    observed = head.stat().st_mtime_ns
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    save_disposition(scan, result.parent, "reported")
    os.utime(head, ns=(observed + head_time, observed + head_time))
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


@pytest.mark.parametrize("pending_offset", [-100, 0, 100], ids=["older", "tied", "newer"])
@pytest.mark.parametrize("head_time", [100, 300], ids=["older-selection", "tied-selection"])
@pytest.mark.parametrize("generic", [False, True], ids=["candidate", "generic-task"])
@pytest.mark.parametrize("reverse_order", [False, True])
@pytest.mark.parametrize("root_head", [False, True], ids=["worker", "root"])
def test_head_reselection_preserves_equal_or_newer_pending_evidence(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    pending_offset,
    head_time,
    generic,
    reverse_order,
    root_head,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = (
        scan.scan_dir / "result.json"
        if root_head
        else add_worker(workbench_db, scan, status="canceled")
    )
    if root_head:
        for name in ("findings.json", "coverage.json", "scan-manifest.json"):
            os.utime(scan.scan_dir / name, ns=(0, 0))
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    os.utime(result, ns=(50, 50))
    head = result.parent / "checkpoint-head.json"
    os.utime(head, ns=(300, 300))
    saved = workbench_api["saved_results"]
    saved._capture_saved_source(
        scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
    )
    selected = save_disposition(scan, result.parent, "rejected")
    if generic:
        selected["coverage"]["resolvedDeferred"] = [
            {"id": "review-task", "reason": "Review completed."}
        ]
        checkpoint = write_checkpoint(result.parent / "checkpoints", selected)
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(head_time, head_time))
    identity = {"id": "review-task"} if generic else {"candidateId": "candidate-disposition"}
    pending = write_checkpoint(
        result.parent / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                **scan.coverage,
                "deferred": [
                    {**identity, "reason": "Validation remains pending.", "paths": ["app.py"]}
                ],
            },
        },
    )
    pending_time = head_time + pending_offset
    os.utime(pending, ns=(pending_time, pending_time))
    sort_checkpoint_entries(monkeypatch, reverse=reverse_order)

    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")

    coverage = read_review_state(workbench_db, scan.scan_dir)
    key, value = next(iter(identity.items()))
    if generic and not root_head:
        value = f"{result.parent.name}/{value}"
    pending_rows = [row for row in coverage["deferred"] if row.get(key) == value]
    assert bool(pending_rows) is (pending_offset >= 0)


@pytest.mark.parametrize("head_time", [100, 300], ids=["older-selection", "tied-selection"])
@pytest.mark.parametrize("result_time", [50, 400], ids=["older-result", "newer-result"])
@pytest.mark.parametrize("reverse_order", [False, True])
def test_reselection_keeps_the_selected_model_and_newer_result_precedence(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    head_time,
    result_time,
    reverse_order,
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    saved = workbench_api["saved_results"]
    head = result.parent / "checkpoint-head.json"
    draft = save_disposition(scan, result.parent, "reported")
    draft["threatModel"] = {"summary": "The current result model."}
    result.write_text(json.dumps(draft))
    os.utime(result, ns=(result_time, result_time))
    for summary, observed in (("The earlier model.", 300), ("The selected model.", head_time)):
        draft["threatModel"] = {"summary": summary}
        checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))
        if summary == "The earlier model.":
            saved._capture_saved_source(
                scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
            )
    sort_checkpoint_entries(monkeypatch, reverse=reverse_order)

    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")

    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    expected = "The current result model." if result_time > head_time else "The selected model."
    assert manifest["threatModel"]["summary"] == expected


@pytest.mark.parametrize("head_time", [100, 300], ids=["older-selection", "tied-selection"])
@pytest.mark.parametrize("reverse_order", [False, True])
def test_partial_reselection_keeps_independent_accepted_dispositions(
    workbench_api, workbench_db, publication_scan, monkeypatch, head_time, reverse_order
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    os.utime(result, ns=(50, 50))
    selected = save_disposition(scan, result.parent, "rejected")
    head = result.parent / "checkpoint-head.json"
    os.utime(head, ns=(300, 300))
    saved = workbench_api["saved_results"]
    saved._capture_saved_source(
        scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
    )
    selected["complete"] = False
    selected["coverage"]["surfaces"][0]["candidateId"] = "independent-candidate"
    checkpoint = write_checkpoint(result.parent / "checkpoints", selected)
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(head_time, head_time))
    sort_checkpoint_entries(monkeypatch, reverse=reverse_order)

    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")

    assert stopped["findingCount"] == 0


@pytest.mark.parametrize("root_head", [False, True], ids=["worker", "root"])
def test_publication_metadata_uses_the_captured_head(
    workbench_api, workbench_db, publication_scan, monkeypatch, root_head
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = (
        scan.scan_dir / "result.json"
        if root_head
        else add_worker(workbench_db, scan, status="canceled")
    )
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    saved = workbench_api["saved_results"]
    capture = saved._capture_saved_source
    relative_head = (result.parent / "checkpoint-head.json").relative_to(scan.scan_dir).as_posix()

    changed = False

    def replace_before_capture(directory, relative, *args, **kwargs):
        nonlocal changed
        if relative == relative_head and not changed:
            changed = True
            save_disposition(scan, result.parent, "rejected")
        return capture(directory, relative, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("workbench.retained_coverage._capture_saved_source", replace_before_capture)
        stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    directory = result.parent.relative_to(scan.scan_dir).as_posix()
    assert manifest["preservedCheckpointHeads"] == {
        directory: captured_head(scan.scan_dir, directory)
    }
    assert stopped["findingCount"] == 0
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )


@pytest.mark.parametrize("legacy_state", ["published", "failed-publication"])
def test_legacy_checkpoint_selection_is_reconstructed_from_frozen_sources(
    workbench_api, workbench_db, publication_scan, monkeypatch, legacy_state
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]
    prepare = saved._prepare_scan_finalization

    def legacy_documents(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"].pop("preservedCheckpointHeads")
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        if legacy_state == "published":
            patch.setattr(saved, "_prepare_scan_finalization", legacy_documents)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
        fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    if legacy_state == "failed-publication":
        preserve_scan_results(workbench_api, workbench_db, scan)
    context = workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]
    assert context["findingCount"] == 0
    assert context["resultsRecoveryNeeded"] is False


def test_legacy_omitted_root_head_does_not_require_recovery(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    saved = workbench_api["saved_results"]
    _, parent = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", parent)
    head = scan.scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    prepare = saved._prepare_scan_finalization

    def legacy_documents(*args, **kwargs):
        heads = kwargs["draft_documents"][0]["scan"]["preservedCheckpointHeads"]
        heads.pop(".")
        for directory, snapshot in heads.items():
            checkpoint = json.loads((scan.scan_dir / snapshot).read_text())["checkpoint"]
            heads[directory] = (Path(directory) / "checkpoints" / checkpoint).as_posix()
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_prepare_scan_finalization", legacy_documents)
        fail_scan(workbench_api, workbench_db, scan)
    manifest_path = scan.scan_dir / "scan-manifest.json"
    original = manifest_path.read_bytes()
    manifest = json.loads(original)["scan"]
    assert "." not in manifest["preservedCheckpointHeads"]
    assert captured_head(scan.scan_dir, ".") in manifest["preservedSources"]
    assert not workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    preserved = preserve_scan_results(workbench_api, workbench_db, scan)
    assert not preserved["resultsRecoveryNeeded"]
    assert manifest_path.read_bytes() == original
    observed = head.stat().st_mtime_ns + 1_000_000
    os.utime(head, ns=(observed, observed))
    assert workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    assert manifest_path.read_bytes() == original


@pytest.mark.parametrize("change", ["new-checkpoint", "identical-result-rewrite"])
def test_explicit_recovery_preserves_database_only_source_times(
    workbench_api, workbench_db, publication_scan, monkeypatch, change
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    os.utime(result, ns=(100, 100))
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes

    def fail_source_order(root, relative, contents):
        if relative.startswith("source-order/"):
            raise OSError("Synthetic ordering snapshot failure")
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_source_order)
        fail_scan(workbench_api, workbench_db, scan)
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    relative_result = result.relative_to(scan.scan_dir).as_posix()
    assert retained["sourceTimes"][relative_result] == 100
    assert not any(path.startswith("source-order/") for path in retained["sources"])
    if change == "new-checkpoint":
        save_disposition(scan, result.parent, "rejected")
    else:
        result.write_bytes(result.read_bytes())
        os.utime(result, ns=(300, 300))
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == (0 if change == "new-checkpoint" else 1)
    assert not recovered["resultsRecoveryNeeded"]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    sources = manifest["preservedSources"]
    times = saved._frozen_source_times(scan.scan_dir, scan.scan_id, sources)
    for relative, digest in retained["sources"].items():
        assert sources[relative] == digest
        assert times[relative] == retained["sourceTimes"][relative]
    assert len(sources) > len(retained["sources"])


@pytest.mark.parametrize("retry", ["preserve", "recover"])
@pytest.mark.parametrize("root_head", [False, True])
@pytest.mark.parametrize("failure", ["publication", "source-order", "checkpoint-heads"])
def test_failed_explicit_recovery_replays_its_frozen_selection(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry, failure, root_head
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = (
        scan.scan_dir / "result.json"
        if root_head
        else add_worker(workbench_db, scan, status="canceled")
    )
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    original = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
        if (scan.scan_dir / name).exists()
    }
    original_digest = workbench_db.execute(
        "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    save_disposition(scan, result.parent, "reported")
    saved = workbench_api["saved_results"]

    write = saved.write_scan_local_bytes

    def fail_snapshot(root, relative, contents):
        if Path(relative).parent.name == failure:
            raise OSError("Synthetic publication interruption")
        return write(root, relative, contents)

    selected_head = (result.parent / "checkpoint-head.json").read_bytes()
    selected_time = (result.parent / "checkpoint-head.json").stat().st_mtime_ns
    with monkeypatch.context() as patch:
        if failure == "publication":
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
        else:
            patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_snapshot)
        with pytest.raises(
            (OSError, saved.ContractError), match="Synthetic publication interruption"
        ):
            recover_scan_results(workbench_api, workbench_db, scan)
    assert all((scan.scan_dir / name).read_bytes() == data for name, data in original.items())
    assert (
        workbench_db.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == original_digest
    )
    # The live head returns to the prior published disposition; pending recovery
    # still needs to publish the selection made before the failed write.
    save_disposition(scan, result.parent, "rejected")
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    if failure == "checkpoint-heads":
        # Without an immutable head snapshot, replay must reject a changed raw
        # head until the selected bytes are restored, just like initial stopping.
        replay = saved.recover_scan_results if retry == "recover" else saved.preserve_scan_results
        with pytest.raises(
            saved.ContractError,
            match="changed after the scan stopped|Frozen stopped-scan checkpoint set is incomplete",
        ):
            replay(
                workbench_api["_WORKBENCH_DB_CONTEXT"],
                workbench_db,
                Namespace(
                    scan_id=scan.scan_id,
                    claim_token=None,
                    thread_id=None,
                    coordinator_generation=None,
                ),
            )
        head = result.parent / "checkpoint-head.json"
        head.write_bytes(selected_head)
        os.utime(head, ns=(selected_time, selected_time))
    if retry == "recover":
        recovered = recover_scan_results(workbench_api, workbench_db, scan)
    else:
        recovered = preserve_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 1
    assert recovered["failureMessage"] == "Audit stopped."
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_checkpoint_heads_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert "recoveryBaseDigest" not in retained


@pytest.mark.parametrize("failure", ["publication", "source-order", "checkpoint-heads"])
def test_failed_recovery_keeps_model_when_worker_registers_an_unselected_checkpoint(
    workbench_api, workbench_db, publication_scan, monkeypatch, failure
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    original = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(original))
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    saved = workbench_api["saved_results"]
    head = result.parent / "checkpoint-head.json"
    unselected = write_checkpoint(
        result.parent / "checkpoints",
        {**original, "threatModel": {"summary": "Unselected worker model."}},
    )
    os.utime(unselected, ns=(400, 400))
    accepted = write_checkpoint(
        result.parent / "checkpoints",
        {**original, "threatModel": {"summary": "Latest accepted model."}},
    )
    os.utime(accepted, ns=(200, 200))
    head.write_text(json.dumps({"checkpoint": accepted.name}))
    os.utime(head, ns=(200, 200))
    saved._capture_saved_source(
        scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
    )
    selected = write_checkpoint(result.parent / "checkpoints", original)
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(300, 300))
    args = Namespace(scan_id=scan.scan_id)

    write = saved.write_scan_local_bytes

    def fail_snapshot(root, relative, contents):
        if Path(relative).parent.name == failure:
            raise OSError("Synthetic publication interruption")
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        if failure == "publication":
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
        else:
            patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_snapshot)
        with pytest.raises(
            (OSError, saved.ContractError), match="Synthetic publication interruption"
        ):
            saved.recover_scan_results(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args)
    retained = workbench_db.execute(
        "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    assert (
        json.loads(retained)["threatModelSource"] == accepted.relative_to(scan.scan_dir).as_posix()
    )

    # A late worker update must not replace the model already selected for publication.
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE artifact_dir = ?",
            (str(unselected), str(result.parent)),
        )
    saved.recover_scan_results(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args)
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["threatModel"]["summary"] == "Latest accepted model."
    published_sources = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert published_sources["threatModelSource"] == json.loads(retained)["threatModelSource"]


@pytest.mark.parametrize("bad_head", ["malformed", "missing-checkpoint", "missing-head"])
@pytest.mark.parametrize("prior_disposition", ["reported", "rejected"])
def test_unreadable_worker_head_does_not_hide_other_recoverable_evidence(
    workbench_api, workbench_db, publication_scan, bad_head, prior_disposition
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    bad = add_worker(workbench_db, scan, status="canceled")
    bad.write_text(json.dumps(save_disposition(scan, bad.parent, "reported")))
    save_disposition(scan, bad.parent, prior_disposition)
    head = bad.parent / "checkpoint-head.json"
    original_head = (head.read_bytes(), head.stat().st_mtime_ns)
    scan.findings[0]["identity"]["anchor"] = "independent-worker"
    scan.findings[0]["locations"][0]["startLine"] = 20
    scan.findings[0]["locations"][0]["endLine"] = 21
    good = add_worker(workbench_db, scan, status="canceled")
    save_disposition(scan, good.parent, "rejected")
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    assert (head.read_bytes(), head.stat().st_mtime_ns) == original_head
    directory = bad.parent.relative_to(scan.scan_dir).as_posix()
    prior_head = captured_head(scan.scan_dir, directory)
    if bad_head == "missing-head":
        head.unlink()
    else:
        head.write_text(
            "{" if bad_head == "malformed" else json.dumps({"checkpoint": "a" * 64 + ".json"})
        )
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )
    save_disposition(scan, good.parent, "reported")
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == (2 if prior_disposition == "reported" else 1)
    assert recovered["resultsRecoveryNeeded"] is False
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["preservedCheckpointHeads"][directory] == prior_head


def test_failed_head_snapshot_does_not_claim_uncaptured_authority(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes
    directory = result.parent.relative_to(scan.scan_dir).as_posix()

    def fail_snapshot(root, relative, *args, **kwargs):
        if relative.startswith(f"{directory}/checkpoint-heads/"):
            raise OSError("Synthetic snapshot write failure")
        return write(root, relative, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_snapshot)
        stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["seal_manifest_digest"] is None
    heads = json.loads(row["retained_checkpoint_heads_json"])
    relative_head = f"{directory}/checkpoint-head.json"
    assert heads[directory] == relative_head
    retained = json.loads(row["retained_source_digests_json"])
    _, digest, observed = saved._read_saved_result(scan.scan_dir, relative_head, scan.scan_id)
    assert retained["sources"][relative_head] == digest
    assert retained["sourceTimes"][relative_head] == observed
    assert not (result.parent / "checkpoint-heads").exists()
    assert stopped["resultsRecoveryNeeded"] is True
    warnings = json.loads(
        workbench_db.execute(
            "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert any("Synthetic snapshot write failure" in warning for warning in warnings)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == 0


@pytest.mark.parametrize("root_head", [False, True], ids=["worker", "root"])
def test_legacy_recovery_can_reselect_an_already_frozen_head(
    workbench_api, workbench_db, publication_scan, monkeypatch, root_head
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = (
        scan.scan_dir / "result.json"
        if root_head
        else add_worker(workbench_db, scan, status="canceled")
    )
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    head = result.parent / "checkpoint-head.json"
    original_head, original_time = head.read_bytes(), head.stat().st_mtime_ns
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]
    prepare = saved._prepare_scan_finalization

    def legacy_documents(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"].pop("preservedCheckpointHeads")
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_prepare_scan_finalization", legacy_documents)
        rejected = recover_scan_results(workbench_api, workbench_db, scan)
    assert rejected["findingCount"] == 0
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    head.write_bytes(original_head)
    os.utime(head, ns=(original_time, original_time))
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


def test_recovery_keeps_newer_result_with_legacy_frozen_live_head(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    reported = save_disposition(scan, result.parent, "reported")
    save_disposition(scan, result.parent, "rejected")
    head = result.parent / "checkpoint-head.json"
    checkpoint = result.parent / "checkpoints" / json.loads(head.read_text())["checkpoint"]
    os.utime(checkpoint, ns=(100, 100))
    os.utime(head, ns=(200, 200))
    result.write_text(json.dumps(reported))
    os.utime(result, ns=(300, 300))
    saved = workbench_api["saved_results"]
    sources = {
        path.relative_to(scan.scan_dir).as_posix(): saved._read_saved_result(
            scan.scan_dir, path.relative_to(scan.scan_dir).as_posix(), scan.scan_id
        )[1]
        for path in (checkpoint, head, result)
    }
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET status = 'failed', completed_at = ?, "
            "retained_source_digests_json = ?, retained_checkpoint_heads_json = NULL "
            "WHERE id = ?",
            (scan.timestamp, json.dumps(sources), scan.scan_id),
        )
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


@pytest.mark.parametrize("directory_name", ["recoveryBaseDigest", "heads"])
def test_worker_directory_does_not_collide_with_recovery_metadata(
    workbench_api, workbench_db, publication_scan, directory_name
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    original = add_worker(workbench_db, scan, status="canceled")
    directory = scan.scan_dir / directory_name
    result = directory / "result.json"
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? "
            "WHERE scan_id = ? AND artifact_dir = ?",
            (str(directory), str(result), scan.scan_id, str(original.parent)),
        )
    result.write_text(json.dumps(save_disposition(scan, directory, "reported")))
    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    assert stopped["findingCount"] == 1
    preserved = preserve_scan_results(workbench_api, workbench_db, scan)
    assert preserved["findingCount"] == 1
    save_disposition(scan, directory, "rejected")
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 0
    assert recovered["resultsRecoveryNeeded"] is False


@pytest.mark.parametrize("legacy_heads", ["ambiguous", "headless"])
@pytest.mark.parametrize("reverse_order", [False, True])
@pytest.mark.parametrize("bad_head", ["malformed", "missing-checkpoint"])
def test_unreadable_heads_preserve_legacy_accepted_results(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    reverse_order,
    bad_head,
    legacy_heads,
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    saved = workbench_api["saved_results"]
    sources = {}
    for disposition in ("reported", "rejected"):
        draft = save_disposition(scan, result.parent, disposition)
        if disposition == "reported":
            result.write_text(json.dumps(draft))
            os.utime(result, ns=(300, 300))
        head = result.parent / "checkpoint-head.json"
        os.utime(head, ns=(300, 300))
        sources.update(
            {
                path: digest
                for path, (digest, _) in saved._capture_saved_source(
                    scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
                ).items()
            }
        )
    if legacy_heads == "headless":
        for relative in list(sources):
            if "/checkpoint-heads/" in relative:
                (scan.scan_dir / relative).unlink()
                del sources[relative]
    head.unlink()
    # Content-addressed filenames can place either disposition first.
    sort_checkpoint_entries(monkeypatch, reverse=reverse_order)
    relative = result.relative_to(scan.scan_dir).as_posix()
    sources[relative] = saved._read_saved_result(scan.scan_dir, relative, scan.scan_id)[1]
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET status = 'failed', completed_at = ?, "
            "retained_source_digests_json = ?, retained_checkpoint_heads_json = NULL "
            "WHERE id = ?",
            (scan.timestamp, json.dumps(sources), scan.scan_id),
        )
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == 1
    assert replayed["resultsRecoveryNeeded"] is False

    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    head.write_text(
        "{" if bad_head == "malformed" else json.dumps({"checkpoint": "a" * 64 + ".json"})
    )
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )
    scan.findings[0]["identity"]["anchor"] = "independent-worker"
    scan.findings[0]["locations"][0]["startLine"] = 20
    scan.findings[0]["locations"][0]["endLine"] = 21
    good = add_worker(workbench_db, scan, status="canceled")
    save_disposition(scan, good.parent, "reported")
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == 2
    assert recovered["resultsRecoveryNeeded"] is False


@pytest.mark.parametrize(
    ("invalid_binding", "snapshot_failure"),
    [(False, None), (True, None), (True, "source-order"), (True, "checkpoint-heads")],
)
def test_invalid_explicit_recovery_does_not_freeze_unpublishable_selection(
    workbench_api, workbench_db, publication_scan, invalid_binding, snapshot_failure, monkeypatch
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    original = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(original))
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    prior = tuple(
        workbench_db.execute(
            "SELECT retained_source_digests_json, retained_checkpoint_heads_json FROM scans WHERE id = ?",
            (scan.scan_id,),
        ).fetchone()
    )
    candidate = {
        **original,
        "threatModel": {"summary": "Valid first model."},
    }
    checkpoint = write_checkpoint(result.parent / "checkpoints", candidate)
    head = result.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    args = Namespace(scan_id=scan.scan_id)
    if invalid_binding:
        saved = workbench_api["saved_results"]
        write = saved.write_scan_local_bytes
        prepare = saved._prepare_scan_finalization

        def prepare_mismatched_binding(directory, **kwargs):
            kwargs["expected_coverage_mode"] = "scoped_path"
            return prepare(directory, **kwargs)

        def fail_snapshot(root, relative, contents):
            if Path(relative).parent.name == snapshot_failure:
                raise OSError("Synthetic snapshot failure")
            return write(root, relative, contents)

        with monkeypatch.context() as patch:
            patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_snapshot)
            patch.setattr(saved, "_prepare_scan_finalization", prepare_mismatched_binding)
            with pytest.raises(saved.ContractError, match="completion binding coverage mode"):
                saved.recover_scan_results(
                    workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args
                )
        retained = tuple(
            workbench_db.execute(
                "SELECT retained_source_digests_json, retained_checkpoint_heads_json FROM scans WHERE id = ?",
                (scan.scan_id,),
            ).fetchone()
        )
        assert retained == prior
    else:
        workbench_api["saved_results"].recover_scan_results(
            workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args
        )
    corrected = write_checkpoint(
        result.parent / "checkpoints",
        {**original, "threatModel": {"summary": "Corrected selected model."}},
    )
    head.write_text(json.dumps({"checkpoint": corrected.name}))
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args
    )["scan"]
    assert recovered["resultsRecoveryNeeded"] is False
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["threatModel"]["summary"] == "Corrected selected model."


@pytest.mark.parametrize("selected_model", [False, True], ids=["omitted", "replacement"])
@pytest.mark.parametrize(
    "result_model", [False, True], ids=["unmodeled-result", "older-result-model"]
)
def test_model_less_selected_head_keeps_latest_accepted_model(
    workbench_api, workbench_db, publication_scan, selected_model, result_model
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    original = save_disposition(scan, result.parent, "reported")
    modeled = {}
    for summary in ("First synthetic accepted model.", "Second synthetic accepted model."):
        draft = {**original, "threatModel": {"summary": summary}}
        checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
        modeled[checkpoint] = summary
    older, newer = sorted(modeled)
    head = result.parent / "checkpoint-head.json"
    saved = workbench_api["saved_results"]
    for checkpoint, observed in ((older, 100), (newer, 200)):
        os.utime(checkpoint, ns=(observed, observed))
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))
        saved._capture_saved_source(
            scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
        )
    selected = {
        **original,
        **({"threatModel": {"summary": "Selected replacement model."}} if selected_model else {}),
    }
    checkpoint = write_checkpoint(result.parent / "checkpoints", selected)
    os.utime(checkpoint, ns=(300, 300))
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(300, 300))
    result.write_text(
        json.dumps(
            {
                **original,
                **({"threatModel": {"summary": "Older result model."}} if result_model else {}),
            }
        )
    )
    os.utime(result, ns=(150, 150) if result_model else (400, 400))
    originals = {path: path.read_bytes() for path in [result, older, newer, checkpoint, head]}
    fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    expected = "Selected replacement model." if selected_model else modeled[newer]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["threatModel"]["summary"] == expected
    recover_scan_results(workbench_api, workbench_db, scan)
    assert (
        json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"][
            "summary"
        ]
        == expected
    )
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize(
    ("mode", "root_head"), [("standard", True), ("deep", True), ("deep", False)]
)
@pytest.mark.parametrize("newer_sorts_first", [False, True])
@pytest.mark.parametrize("restore_model", [False, True], ids=["model-less", "modeled"])
def test_restored_head_keeps_latest_model_fallback(
    workbench_api, workbench_db, publication_scan, mode, root_head, newer_sorts_first, restore_model
):
    scan = publication_scan(mode=mode)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    draft = saved_draft(scan.scan_id, complete=True)
    draft["coverage"] = {**scan.coverage, **draft["coverage"]}
    if root_head:
        directory = scan.scan_dir
    else:
        result = add_worker(workbench_db, scan, status="canceled")
        result.write_text(json.dumps(draft))
        os.utime(result, ns=(0, 0))
        directory = result.parent
    head = directory / "checkpoint-head.json"
    saved = workbench_api["saved_results"]

    def select(checkpoint, observed):
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))
        return head.read_bytes(), observed

    def model():
        return json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"][
            "threatModel"
        ]["summary"]

    empty = write_checkpoint(directory / "checkpoints", draft)
    os.utime(empty, ns=(50, 50))
    unmodeled_head = select(empty, 100)
    saved._capture_saved_source(
        scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
    )
    models = {
        write_checkpoint(
            directory / "checkpoints", {**draft, "threatModel": {"summary": text}}
        ): text
        for text in ("Synthetic model A.", "Synthetic model B.")
    }
    for checkpoint in models:
        os.utime(checkpoint, ns=(50, 50))
    older, newer = sorted(models, reverse=newer_sorts_first)
    modeled_head = select(older, 200)
    fail_scan(workbench_api, workbench_db, scan, "Synthetic stop.")
    assert model() == models[older]
    select(newer, 300)
    recover_scan_results(workbench_api, workbench_db, scan)
    assert model() == models[newer]
    originals = {
        filename: (filename.read_bytes(), filename.stat().st_mtime_ns)
        for subdirectory in ("checkpoints", "checkpoint-heads")
        for filename in (directory / subdirectory).glob("*.json")
    }
    restored_contents, restored_time = modeled_head if restore_model else unmodeled_head
    head.write_bytes(restored_contents)
    os.utime(head, ns=(restored_time, restored_time))
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
    assert model() == models[older if restore_model else newer]
    assert not recovered["resultsRecoveryNeeded"]
    published = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "report.md")
        if (scan.scan_dir / name).exists()
    }
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert not replayed["resultsRecoveryNeeded"]
    assert all(
        (scan.scan_dir / name).read_bytes() == contents for name, contents in published.items()
    )
    assert (head.read_bytes(), head.stat().st_mtime_ns) == (restored_contents, restored_time)
    assert all(
        (filename.read_bytes(), filename.stat().st_mtime_ns) == contents
        for filename, contents in originals.items()
    )


@pytest.mark.parametrize(
    "checkpoint_result", [False, True], ids=["ordinary-result", "registered-checkpoint"]
)
def test_registered_checkpoint_result_keeps_newer_accepted_outcome(
    workbench_api, workbench_db, publication_scan, checkpoint_result
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan)
    reported = {
        **save_disposition(scan, result.parent, "reported"),
        "threatModel": {"summary": "Newer accepted model."},
    }
    head = result.parent / "checkpoint-head.json"
    accepted = write_checkpoint(result.parent / "checkpoints", reported)
    head.write_text(json.dumps({"checkpoint": accepted.name}))
    os.utime(accepted, ns=(300, 300))
    os.utime(head, ns=(300, 300))
    workbench_api["saved_results"]._capture_saved_source(
        scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
    )
    if checkpoint_result:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
                (str(accepted), result.parent.name),
            )
    else:
        result.write_text(json.dumps(reported))
        os.utime(result, ns=(300, 300))
    rejected = {
        **save_disposition(scan, result.parent, "rejected"),
        "threatModel": {"summary": "Older selected model."},
    }
    older = write_checkpoint(result.parent / "checkpoints", rejected)
    os.utime(older, ns=(200, 200))
    head.write_text(json.dumps({"checkpoint": older.name}))
    os.utime(head, ns=(200, 200))
    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    assert stopped["findingCount"] == 1
    assert stopped["resultsRecoveryNeeded"] is False

    assert (
        json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"][
            "summary"
        ]
        == "Newer accepted model."
    )
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == 1
    assert (
        json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"][
            "summary"
        ]
        == "Newer accepted model."
    )


@pytest.mark.parametrize("registered", [False, True], ids=["head-only", "registered-result"])
@pytest.mark.parametrize("interrupted", [False, True], ids=["published", "publication-retry"])
def test_restored_observation_keeps_independent_registered_result(
    workbench_api, workbench_db, publication_scan, monkeypatch, registered, interrupted
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="succeeded")
    reported = {
        **save_disposition(scan, result.parent, "reported"),
        "threatModel": {"summary": "Registered reporting model."},
    }
    surface = {
        "id": "registered-surface",
        "label": "Synthetic reviewed surface",
        "disposition": "no_issue_found",
        "receiptRefs": [],
    }
    reported["coverage"]["surfaces"].append(surface)
    accepted = write_checkpoint(result.parent / "checkpoints", reported)
    os.utime(accepted, ns=(50, 50))
    stale = {
        **save_disposition(scan, result.parent, "rejected"),
        "threatModel": {"summary": "Stale result model."},
    }
    stale["coverage"]["surfaces"].append({**surface, "disposition": "needs_follow_up"})
    stale["coverage"]["openQuestions"] = [{"question": "Obsolete synthetic question."}]
    stale["coverage"]["explicitExclusions"] = [
        {"pattern": "old-scope/**", "reason": "Obsolete synthetic exclusion."}
    ]
    result.write_text(json.dumps(stale))
    os.utime(result, ns=(200, 200))
    head = result.parent / "checkpoint-head.json"
    saved = workbench_api["saved_results"]

    def select(observed):
        head.write_text(json.dumps({"checkpoint": accepted.name}))
        os.utime(head, ns=(observed, observed))

    select(100)
    saved._capture_saved_source(
        scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
    )
    select(300)
    if registered:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
                (str(accepted), result.parent.name),
            )
    stopped = fail_scan(workbench_api, workbench_db, scan)
    assert stopped["findingCount"] == 1
    sources = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"][
        "preservedSources"
    ]
    prior_coverage = read_review_state(workbench_db, scan.scan_dir)
    assert not prior_coverage.get("openQuestions")
    assert not prior_coverage["explicitExclusions"]
    original = {path: (scan.scan_dir / path).read_bytes() for path in sources}
    select(100)
    assert workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    prepared_counts = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_counts.append(len(prepared[3]["findings"]))
        if interrupted:
            raise OSError("Synthetic publication interruption")
        return write(prepared, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        if interrupted:
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                recover_scan_results(workbench_api, workbench_db, scan)
        else:
            recover_scan_results(workbench_api, workbench_db, scan)
    assert prepared_counts == [int(registered)]
    recovered = preserve_scan_results(workbench_api, workbench_db, scan)
    assert recovered["findingCount"] == int(registered)
    assert not recovered["resultsRecoveryNeeded"]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["preservedSources"] == sources
    assert manifest["threatModel"]["summary"] == (
        "Registered reporting model." if registered else "Stale result model."
    )
    coverage = read_review_state(workbench_db, scan.scan_dir)
    if registered:
        for field in ("surfaces", "openQuestions", "explicitExclusions"):
            assert coverage.get(field) == prior_coverage.get(field)
    else:
        assert coverage["openQuestions"] == [
            {**row, "provenance": {"workerId": result.parent.name, "attempt": 1}}
            for row in stale["coverage"]["openQuestions"]
        ]
        assert any(row["pattern"] == "old-scope/**" for row in coverage["explicitExclusions"])
    assert all((scan.scan_dir / path).read_bytes() == content for path, content in original.items())


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("interrupted", [False, True], ids=["published", "publication-retry"])
@pytest.mark.parametrize(
    "model_choice", ["latest-accepted", "selected-head", "canonical-fallback", "older-accepted"]
)
@pytest.mark.parametrize("legacy_format", [False, True], ids=["current-format", "legacy-format"])
def test_inherited_model_uses_same_selection_on_initial_and_frozen_publication(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    interrupted,
    model_choice,
    legacy_format,
):
    scan = publication_scan(mode=mode)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["threatModel"] = {"summary": "Old canonical model."}
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    draft = saved_draft(scan.scan_id, complete=True)
    draft["coverage"] = {**scan.coverage, **draft["coverage"]}
    if model_choice == "selected-head":
        draft["threatModel"] = {"summary": "Selected root model."}
    selected = write_checkpoint(scan.scan_dir / "checkpoints", draft)
    os.utime(selected, ns=(50, 50))
    head = scan.scan_dir / "checkpoint-head.json"
    saved = workbench_api["saved_results"]

    if model_choice in {"canonical-fallback", "older-accepted"}:
        unselected = write_checkpoint(
            scan.scan_dir / "checkpoints",
            {**draft, "threatModel": {"summary": "Unaccepted model."}},
        )
        os.utime(unselected, ns=(50, 50))
        sort_checkpoint_entries(monkeypatch, key=lambda name: name != unselected.name)

    def select(checkpoint, observed):
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))

    select(selected, 200)
    saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    if model_choice != "canonical-fallback":
        other_model = write_checkpoint(
            scan.scan_dir / "checkpoints",
            {**draft, "threatModel": {"summary": "Latest accepted model."}},
        )
        os.utime(other_model, ns=(50, 50))
        select(other_model, 100 if model_choice == "older-accepted" else 300)
        saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
        select(selected, 200)
    prepared_models = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_models.append(prepared[2]["scan"]["threatModel"]["summary"])
        if interrupted:
            raise OSError("Synthetic publication interruption")
        return write(prepared, **kwargs)

    encode = saved._encode_retained_sources
    prepare = saved._prepare_scan_finalization

    def legacy_documents(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"]["preservedCheckpointHeads"].pop(".", None)
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        if legacy_format:
            patch.setattr(saved, "_prepare_scan_finalization", legacy_documents)
            patch.setattr(
                saved,
                "_encode_retained_sources",
                lambda sources, model_source, source_times=None: encode(sources, [], source_times),
            )
        fail_scan(workbench_api, workbench_db, scan)
    retained = workbench_db.execute(
        "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    if legacy_format:
        recover_scan_results(workbench_api, workbench_db, scan)
    preserved = preserve_scan_results(workbench_api, workbench_db, scan)
    expected = {
        "latest-accepted": "Latest accepted model.",
        "selected-head": "Selected root model.",
        "canonical-fallback": "Old canonical model.",
        "older-accepted": "Old canonical model.",
    }[model_choice]
    assert prepared_models == [expected]
    assert json.loads(manifest_path.read_text())["scan"]["threatModel"]["summary"] == expected
    assert not preserved["resultsRecoveryNeeded"]
    replayed = workbench_db.execute(
        "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    assert (
        saved._retained_source_state(json.loads(replayed))[0]
        == saved._retained_source_state(json.loads(retained))[0]
    )
    if legacy_format:
        model_source = saved._retained_source_state(json.loads(replayed))[1]
        if model_source is not None:
            assert (
                json.loads((scan.scan_dir / model_source).read_text())["threatModel"]["summary"]
                == expected
            )
    elif not legacy_format:
        assert replayed == retained


@pytest.mark.parametrize("prepare_only", [False, True], ids=["complete", "prepare"])
@pytest.mark.parametrize(
    "model_choice", ["canonical-fallback", "latest-accepted", "selected-head", "older-accepted"]
)
def test_successful_completion_keeps_accepted_root_model_fallback(
    workbench_api, workbench_db, publication_scan, monkeypatch, prepare_only, model_choice
):
    scan = publication_scan(mode="standard")
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["threatModel"] = {"summary": "Old canonical model."}
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    draft = saved_draft(scan.scan_id, complete=True)
    draft["coverage"] = {**scan.coverage, **draft["coverage"]}
    if model_choice == "selected-head":
        draft["threatModel"] = {"summary": "Selected root model."}
    selected = write_checkpoint(scan.scan_dir / "checkpoints", draft)
    os.utime(selected, ns=(50, 50))
    head = scan.scan_dir / "checkpoint-head.json"
    saved = workbench_api["saved_results"]

    def select(checkpoint, observed):
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))

    select(selected, 200)
    saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    unaccepted = write_checkpoint(
        scan.scan_dir / "checkpoints",
        {**draft, "threatModel": {"summary": "Unaccepted model."}},
    )
    os.utime(unaccepted, ns=(50, 50))
    sort_checkpoint_entries(monkeypatch, key=lambda name: name != unaccepted.name)
    if model_choice != "canonical-fallback":
        modeled = write_checkpoint(
            scan.scan_dir / "checkpoints",
            {**draft, "threatModel": {"summary": "Latest accepted model."}},
        )
        os.utime(modeled, ns=(50, 50))
        select(modeled, 100 if model_choice == "older-accepted" else 300)
        saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
        select(selected, 200)
    original = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for directory in ("checkpoints", "checkpoint-heads")
        for path in (scan.scan_dir / directory).glob("*.json")
    }
    completed = complete(workbench_api, workbench_db, scan, prepare_only=prepare_only)
    expected = {
        "canonical-fallback": "Old canonical model.",
        "latest-accepted": "Latest accepted model.",
        "selected-head": "Selected root model.",
        "older-accepted": "Old canonical model.",
    }[model_choice]
    published = json.loads(manifest_path.read_text())["scan"]
    assert published["threatModel"]["summary"] == expected
    assert published["sealedAt"]
    assert completed["threatModelAvailable"]
    assert completed["progress"]["status"] == ("running" if prepare_only else "complete")
    assert all(
        (path.read_bytes(), path.stat().st_mtime_ns) == value for path, value in original.items()
    )


@pytest.mark.parametrize("duplicate_order", [None, "first", "last"])
@pytest.mark.parametrize("new_model", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("legacy_model_source", [False, True])
def test_recovery_keeps_known_model_source_with_equal_model_duplicates(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    duplicate_order,
    new_model,
    interrupted,
    legacy_model_source,
):
    scan = publication_scan(mode="standard")
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"].update(complete=True, threatModel={"summary": "Canonical model."})
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    saved = workbench_api["saved_results"]
    _, canonical = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    older = write_checkpoint(
        scan.scan_dir / "checkpoints", {**canonical, "threatModel": {"summary": "Older model."}}
    )
    os.utime(older, ns=(50, 50))
    if duplicate_order is not None:
        duplicate = copy.deepcopy(canonical)
        duplicate["reviewState"]["openQuestions"] = [{"question": "Earlier synthetic review."}]
        duplicate_path = write_checkpoint(scan.scan_dir / "checkpoints", duplicate)
        os.utime(duplicate_path, ns=(50, 50))
        sort_checkpoint_entries(
            monkeypatch,
            key=lambda name: (
                name != duplicate_path.name
                if duplicate_order == "first"
                else name == duplicate_path.name
            ),
        )
    head = scan.scan_dir / "checkpoint-head.json"

    def select(checkpoint, observed):
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))

    select(older, 100)
    saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    empty = {key: value for key, value in canonical.items() if key != "threatModel"}
    selected = write_checkpoint(scan.scan_dir / "checkpoints", empty)
    os.utime(selected, ns=(50, 50))
    select(selected, 200)
    fail_scan(workbench_api, workbench_db, scan)
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert retained["threatModelSource"] == f"checkpoints/{saved._digest(canonical)}.json"
    assert (
        json.loads(manifest_path.read_text())["scan"]["threatModel"]["summary"]
        == "Canonical model."
    )
    if legacy_model_source:
        with workbench_db:
            workbench_db.execute(
                "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
                (json.dumps(retained["sources"]), scan.scan_id),
            )
    if new_model:
        newer = write_checkpoint(
            scan.scan_dir / "checkpoints", {**canonical, "threatModel": {"summary": "New model."}}
        )
        os.utime(newer, ns=(50, 50))
        select(newer, 250)
        saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    select(selected, 300)
    prepared_models = []
    write = saved._write_prepared_scan_finalization

    def publish(prepared, **kwargs):
        prepared_models.append(prepared[2]["scan"]["threatModel"]["summary"])
        if interrupted:
            raise OSError("Synthetic publication interruption")
        return write(prepared, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", publish)
        if interrupted:
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                recover_scan_results(workbench_api, workbench_db, scan)
        else:
            recover_scan_results(workbench_api, workbench_db, scan)
    expected = "New model." if new_model else "Canonical model."
    assert prepared_models == [expected]
    preserve_scan_results(workbench_api, workbench_db, scan)
    assert json.loads(manifest_path.read_text())["scan"]["threatModel"]["summary"] == expected


@pytest.mark.parametrize("corrupt", [False, True])
@pytest.mark.parametrize("flow", ["stop", "interrupted-stop", "complete", "prepare"])
def test_skipped_canonical_checkpoint_keeps_valid_model_and_findings(
    workbench_api, workbench_db, publication_scan, monkeypatch, corrupt, flow
):
    scan = publication_scan(mode="standard")
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"].update(complete=True, threatModel={"summary": "Canonical model."})
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    saved = workbench_api["saved_results"]
    _, canonical = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    checkpoint_dir = scan.scan_dir / "checkpoints"
    checkpoint_dir.mkdir()
    canonical_path = checkpoint_dir / f"{saved._digest(canonical)}.json"
    canonical_path.write_bytes(saved._encoded(canonical))
    os.utime(canonical_path, ns=(150, 150))
    if corrupt:
        canonical_path.write_text("{")
    original = canonical_path.read_bytes()
    selected = write_checkpoint(
        scan.scan_dir / "checkpoints",
        {key: value for key, value in canonical.items() if key != "threatModel"},
    )
    os.utime(selected, ns=(50, 50))
    head = scan.scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(200, 200))
    if flow in {"complete", "prepare"}:
        published = complete(workbench_api, workbench_db, scan, prepare_only=flow == "prepare")
    else:
        with monkeypatch.context() as patch:
            if flow == "interrupted-stop":
                patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
            fail_scan(workbench_api, workbench_db, scan)
        published = preserve_scan_results(workbench_api, workbench_db, scan)
        os.utime(head, ns=(300, 300))
        published = recover_scan_results(workbench_api, workbench_db, scan)
    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 1
    if flow != "prepare":
        assert published["findingCount"] == 1
    final = json.loads(manifest_path.read_text())["scan"]
    assert final["sealedAt"]
    assert final["threatModel"]["summary"] == "Canonical model."
    assert canonical_path.read_bytes() == original
    if corrupt:
        assert canonical_path.relative_to(scan.scan_dir).as_posix() not in final["preservedSources"]
        if flow in {"stop", "interrupted-stop"}:
            warnings = json.loads(
                workbench_db.execute(
                    "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan.scan_id,)
                ).fetchone()[0]
            )
            assert any("Preserved unreadable checkpoint" in warning for warning in warnings)


@pytest.mark.parametrize("registered", [None, "A", "B"])
@pytest.mark.parametrize("restored_time", [100, 300])
@pytest.mark.parametrize("interrupted", [False, True])
def test_selected_terminal_coverage_excludes_unselected_history(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    registered,
    restored_time,
    interrupted,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    saved = workbench_api["saved_results"]
    checkpoints = {}
    for name in ("A", "B"):
        draft = saved_draft(
            scan.scan_id,
            complete=True,
            surfaces=[
                {
                    "id": "surface",
                    "label": f"{name} surface",
                    "disposition": "no_issue_found",
                    "receiptRefs": [],
                }
            ],
        )
        draft["threatModel"] = {"summary": f"{name} model"}
        draft["coverage"]["openQuestions"] = [{"question": f"{name} question"}]
        draft["coverage"]["explicitExclusions"] = [
            {"pattern": f"{name}/**", "reason": f"{name} exclusion"}
        ]
        checkpoints[name] = write_checkpoint(result.parent / "checkpoints", draft)
        os.utime(checkpoints[name], ns=(50, 50))
    head = result.parent / "checkpoint-head.json"

    def select(name, observed):
        head.write_text(json.dumps({"checkpoint": checkpoints[name].name}))
        os.utime(head, ns=(observed, observed))

    for name, observed in (("A", 100), ("B", 200), ("A", 300)):
        select(name, observed)
        saved._capture_saved_source(
            scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
        )
    if registered is not None:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
                (str(checkpoints[registered]), result.parent.name),
            )
    fail_scan(workbench_api, workbench_db, scan)
    select("A", restored_time)
    expected = "B" if registered == "B" and restored_time == 100 else "A"

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
        if interrupted and restored_time == 100:
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                recover_scan_results(workbench_api, workbench_db, scan)
        else:
            recover_scan_results(workbench_api, workbench_db, scan)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert [row["label"] for row in coverage["surfaces"]] == [f"{expected} surface"]
    assert [row["question"] for row in coverage["openQuestions"]] == [f"{expected} question"]
    assert [row["pattern"] for row in coverage["explicitExclusions"]] == [f"{expected}/**"]
    assert (
        json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"][
            "summary"
        ]
        == f"{expected} model"
    )
    assert not replayed["resultsRecoveryNeeded"]


@pytest.mark.parametrize(
    "mode,layout", [("standard", "root"), ("deep", "root"), ("deep", "worker")]
)
@pytest.mark.parametrize("failure_at", [None, "restore", "modelless"])
@pytest.mark.parametrize("modelless_time", [200, 400])
def test_selected_model_identity_survives_restore_then_modelless_head(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    layout,
    failure_at,
    modelless_time,
):
    scan = publication_scan(mode=mode)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if layout == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    saved = workbench_api["saved_results"]
    draft = saved_draft(scan.scan_id, complete=True)
    draft["coverage"] = {**scan.coverage, **draft["coverage"]}
    checkpoints = {
        name: write_checkpoint(
            directory / "checkpoints", {**draft, "threatModel": {"summary": name}}
        )
        for name in ("A", "B")
    }
    checkpoints["empty"] = write_checkpoint(directory / "checkpoints", draft)
    for checkpoint in checkpoints.values():
        os.utime(checkpoint, ns=(50, 50))
    head = directory / "checkpoint-head.json"
    models = []

    for index, (name, observed, phase) in enumerate(
        (
            ("A", 100, "initial"),
            ("B", 300, "newer"),
            ("A", 100, "restore"),
            ("empty", modelless_time, "modelless"),
        )
    ):
        head.write_text(json.dumps({"checkpoint": checkpoints[name].name}))
        os.utime(head, ns=(observed, observed))
        if index == 0:
            fail_scan(workbench_api, workbench_db, scan)
        else:
            with monkeypatch.context() as patch:
                if phase == failure_at:
                    patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
                    with pytest.raises(OSError, match="Synthetic publication interruption"):
                        recover_scan_results(workbench_api, workbench_db, scan)
                else:
                    recover_scan_results(workbench_api, workbench_db, scan)
        replayed = preserve_scan_results(workbench_api, workbench_db, scan)
        models.append(
            json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"][
                "summary"
            ]
        )
        assert not replayed["resultsRecoveryNeeded"]
    assert models == ["A", "B", "A", "B"]
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert retained["threatModelSource"] == checkpoints["B"].relative_to(scan.scan_dir).as_posix()


@pytest.mark.parametrize(
    "mode,layout", [("standard", "root"), ("deep", "root"), ("deep", "worker")]
)
@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
def test_selected_terminal_coverage_has_root_worker_parity(
    workbench_api, workbench_db, publication_scan, monkeypatch, mode, layout, terminal, interrupted
):
    scan = publication_scan(mode=mode)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage_path = scan.scan_dir / "coverage.json"
    initial_coverage = json.loads(coverage_path.read_text())
    for field in ("surfaces", "explicitExclusions", "openQuestions"):
        initial_coverage[field] = []
    coverage_path.write_text(json.dumps(initial_coverage))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if layout == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    saved = workbench_api["saved_results"]
    checkpoints = {}
    for name in ("A", "B"):
        draft = saved_draft(scan.scan_id, complete=terminal if name == "A" else True)
        draft["coverage"] = {**scan.coverage, **draft["coverage"]}
        draft["coverage"].update(
            surfaces=[
                {
                    "id": f"surface-{name}",
                    "label": name,
                    "disposition": "no_issue_found",
                    "receiptRefs": [],
                }
            ],
            explicitExclusions=[{"pattern": f"{name}/**", "reason": f"{name} exclusion"}],
            openQuestions=[{"question": f"{name} question"}],
        )
        draft["threatModel"] = {"summary": f"{name} model"}
        checkpoints[name] = write_checkpoint(directory / "checkpoints", draft)
        os.utime(checkpoints[name], ns=(50, 50))
    head = directory / "checkpoint-head.json"
    for name, observed in (("A", 100), ("B", 200), ("A", 300)):
        head.write_text(json.dumps({"checkpoint": checkpoints[name].name}))
        os.utime(head, ns=(observed, observed))
        saved._capture_saved_source(
            scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
        )
    fail_scan(workbench_api, workbench_db, scan)
    head.write_text(json.dumps({"checkpoint": checkpoints["A"].name}))
    os.utime(head, ns=(100, 100))

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                recover_scan_results(workbench_api, workbench_db, scan)
        else:
            recover_scan_results(workbench_api, workbench_db, scan)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    expected = {"A"} if terminal else {"A", "B"}
    assert {row["label"] for row in coverage["surfaces"]} == expected
    assert {row["pattern"] for row in coverage["explicitExclusions"]} == {
        f"{name}/**" for name in expected
    }
    assert {row["question"] for row in coverage["openQuestions"]} == {
        f"{name} question" for name in expected
    }
    assert (
        json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]["threatModel"][
            "summary"
        ]
        == "A model"
    )
    assert not replayed["resultsRecoveryNeeded"]


@pytest.mark.parametrize("archived_terminal", [False, True])
@pytest.mark.parametrize("current_terminal", [False, True])
@pytest.mark.parametrize("registered", [False, True])
@pytest.mark.parametrize("interrupted", [False, True])
def test_terminal_coverage_replacement_does_not_cross_into_a_partial_attempt(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    archived_terminal,
    current_terminal,
    registered,
    interrupted,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    directory = result.parent
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = 2 WHERE scan_id = ?", (scan.scan_id,)
        )
    archive = directory / "attempts" / "attempt-1"
    old = write_checkpoint(
        archive / "checkpoints", saved_draft(scan.scan_id, complete=archived_terminal)
    )
    os.utime(old, ns=(50, 50))
    (archive / "checkpoint-head.json").write_text(json.dumps({"checkpoint": old.name}))
    os.utime(archive / "checkpoint-head.json", ns=(100, 100))
    accepted = saved_draft(scan.scan_id, complete=True)
    accepted["coverage"].update(
        surfaces=[
            {
                "id": "accepted-surface",
                "label": "Accepted",
                "disposition": "no_issue_found",
                "receiptRefs": [],
            }
        ],
        explicitExclusions=[{"pattern": "accepted/**", "reason": "Accepted exclusion"}],
        openQuestions=[{"question": "Accepted question"}],
    )
    accepted_path = write_checkpoint(directory / "checkpoints", accepted)
    os.utime(accepted_path, ns=(200, 200))
    head = directory / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": accepted_path.name}))
    os.utime(head, ns=(200, 200))
    if registered:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
                (str(accepted_path), directory.name),
            )
    saved = workbench_api["saved_results"]
    fail_scan(workbench_api, workbench_db, scan)
    current = write_checkpoint(
        directory / "checkpoints", saved_draft(scan.scan_id, complete=current_terminal)
    )
    os.utime(current, ns=(300, 300))
    head.write_text(json.dumps({"checkpoint": current.name}))
    os.utime(head, ns=(300, 300))

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                recover_scan_results(workbench_api, workbench_db, scan)
        else:
            recover_scan_results(workbench_api, workbench_db, scan)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    expected = [] if current_terminal else ["Accepted"]
    assert [row["label"] for row in coverage["surfaces"]] == expected
    assert [row["pattern"] for row in coverage["explicitExclusions"]] == (
        [] if current_terminal else ["accepted/**"]
    )
    assert [row["question"] for row in coverage["openQuestions"]] == (
        [] if current_terminal else ["Accepted question"]
    )
    if not current_terminal:
        assert "completeness" not in coverage
    assert not replayed["resultsRecoveryNeeded"]


@pytest.mark.parametrize("valid_rejection", [False, True], ids=["malformed", "valid"])
def test_tied_rejection_requires_valid_surface_before_removing_finding(
    workbench_api, workbench_db, publication_scan, valid_rejection
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    os.utime(result, ns=(300, 300))
    rejected = save_disposition(scan, result.parent, "rejected")
    if not valid_rejection:
        rejected["coverage"]["surfaces"][0].pop("label")
        checkpoint = write_checkpoint(result.parent / "checkpoints", rejected)
        (result.parent / "checkpoint-head.json").write_text(
            json.dumps({"checkpoint": checkpoint.name})
        )
    os.utime(result.parent / "checkpoint-head.json", ns=(300, 300))
    original = result.read_bytes()
    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    assert stopped["findingCount"] == (0 if valid_rejection else 1)
    assert result.read_bytes() == original


@pytest.mark.parametrize(
    "receipt_state",
    ["missing", "present", "present-relative", "optional", "shared", "shared-collision"],
)
@pytest.mark.parametrize("head_time", [300, 400], ids=["tied", "newer"])
def test_rejection_receipt_is_verified_before_suppressing_accepted_finding(
    workbench_api, workbench_db, publication_scan, receipt_state, head_time
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    # Worker receipts are published beneath the parent artifact directory.
    output = scan.scan_dir / "artifacts" / "workers" / result.parent.name
    output.parent.mkdir(parents=True, exist_ok=True)
    result.parent.rename(output)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET artifact_dir = ?, result_manifest_path = ? WHERE id = ?",
            (str(output), str(output / result.name), output.name),
        )
    result = output / result.name
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    os.utime(result, ns=(300, 300))
    rejected = save_disposition(scan, result.parent, "rejected")
    if receipt_state != "optional":
        rejected["coverage"]["surfaces"][0]["receiptRefs"] = [
            "./artifacts/review.txt"
            if receipt_state == "present-relative"
            else "artifacts/review.txt"
        ]
        if receipt_state.startswith("shared"):
            prior_ref = (
                "artifacts/Review.txt"
                if receipt_state == "shared-collision"
                else "artifacts/review.txt"
            )
            parent_surface = {
                "id": "earlier-review",
                "label": "Earlier review",
                "disposition": "no_issue_found",
                "receiptRefs": [prior_ref],
            }
            (scan.scan_dir / "coverage.json").write_text(
                json.dumps({**scan.coverage, "surfaces": [parent_surface]})
            )
            (scan.scan_dir / prior_ref).write_text("Synthetic parent review.")
        if receipt_state.startswith(("present", "shared")):
            receipt_dir = scan.scan_dir if receipt_state.startswith("shared") else result.parent
            receipt = receipt_dir / "artifacts" / "review.txt"
            receipt.parent.mkdir(exist_ok=True)
            receipt.write_text("Synthetic rejected candidate review.")
        checkpoint = write_checkpoint(result.parent / "checkpoints", rejected)
        (result.parent / "checkpoint-head.json").write_text(
            json.dumps({"checkpoint": checkpoint.name})
        )
    os.utime(result.parent / "checkpoint-head.json", ns=(head_time, head_time))
    originals = {
        path: path.read_bytes() for path in (result, result.parent / "checkpoint-head.json")
    }
    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    unverified = receipt_state in {"missing", "shared-collision"}
    assert stopped["findingCount"] == int(unverified)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    assert ("needs_follow_up" if unverified else "rejected") in {
        surface["disposition"] for surface in coverage["surfaces"]
    }
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == stopped["findingCount"]
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("rejection", [False, True], ids=["finding", "finding-and-rejection"])
def test_checkpoint_registered_as_result_keeps_its_own_finding(
    workbench_api, workbench_db, publication_scan, rejection
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan)
    draft = save_disposition(scan, result.parent, "reported")
    if rejection:
        draft["coverage"]["surfaces"][0]["disposition"] = "rejected"
    checkpoint = write_checkpoint(result.parent / "checkpoints", draft)
    head = result.parent / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
            (str(checkpoint), result.parent.name),
        )
    original = checkpoint.read_bytes()
    stopped = fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
    assert stopped["findingCount"] == 1
    assert checkpoint.read_bytes() == original


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory write permission fixture")
@pytest.mark.parametrize("writable", [False, True], ids=["blocked-snapshot", "writable-snapshot"])
@pytest.mark.parametrize("replace_head", [False, True], ids=["late-file", "late-selection"])
def test_cancellation_snapshot_failure_keeps_the_original_source_boundary(
    workbench_api, workbench_db, publication_scan, writable, replace_head
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="running")
    draft = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(draft))
    head = result.parent / "checkpoint-head.json"
    original_head = head.read_bytes()
    original_head_time = head.stat().st_mtime_ns
    snapshots = result.parent / "checkpoint-heads"
    snapshots.mkdir()
    try:
        if not writable:
            snapshots.chmod(0o500)
            if os.access(snapshots, os.W_OK):
                pytest.skip("Current user can write through POSIX directory permissions")
        workbench_api["saved_results"].cancel_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, thread_id=None),
        )
    finally:
        snapshots.chmod(0o700)
    late = copy.deepcopy(draft)
    late["findings"][0]["identity"]["anchor"] = "written-after-cancellation"
    late["findings"][0]["extensions"]["candidateId"] = "post-cancellation-candidate"
    late["coverage"]["surfaces"][0]["candidateId"] = "post-cancellation-candidate"
    checkpoint = write_checkpoint(result.parent / "checkpoints", late)
    if replace_head:
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    saved = workbench_api["saved_results"]

    def replay():
        return preserve_scan_results(workbench_api, workbench_db, scan)

    if not writable and replace_head:
        with pytest.raises(
            saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
        ):
            replay()
        head.write_bytes(original_head)
        os.utime(head, ns=(original_head_time, original_head_time))
    retained = replay()
    assert retained["findingCount"] == 1
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert all(item["identity"]["anchor"] != "written-after-cancellation" for item in findings)
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert (
        checkpoint.relative_to(scan.scan_dir).as_posix() not in manifest["scan"]["preservedSources"]
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory write permission fixture")
@pytest.mark.parametrize("writable", [False, True], ids=["blocked-snapshot", "writable-snapshot"])
@pytest.mark.parametrize("disposition", ["reported", "rejected"])
def test_snapshot_write_failure_keeps_stopped_publication_pending(
    workbench_api, workbench_db, publication_scan, writable, disposition
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    if disposition == "rejected":
        save_disposition(scan, result.parent, disposition)
    snapshots = result.parent / "checkpoint-heads"
    snapshots.mkdir()
    original_outputs = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
        if (scan.scan_dir / name).exists()
    }
    originals = {
        path: path.read_bytes() for path in (result, result.parent / "checkpoint-head.json")
    }
    try:
        if not writable:
            snapshots.chmod(0o500)
            if os.access(snapshots, os.W_OK):
                pytest.skip("Current user can write through POSIX directory permissions")
        fail_scan(workbench_api, workbench_db, scan, "Audit stopped.")
        row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
        assert row["status"] == "failed"
        if not writable:
            assert row["seal_manifest_digest"] is None
            retained = json.loads(row["retained_source_digests_json"])
            heads = json.loads(row["retained_checkpoint_heads_json"])
            directory = result.parent.relative_to(scan.scan_dir).as_posix()
            relative_head = f"{directory}/checkpoint-head.json"
            assert heads[directory] == relative_head
            assert set(retained["sourceTimes"]) == set(retained["sources"])
            for relative, digest in retained["sources"].items():
                _, expected_digest, observed = workbench_api["saved_results"]._read_saved_result(
                    scan.scan_dir, relative, scan.scan_id
                )
                assert digest == expected_digest
                assert retained["sourceTimes"][relative] == observed
            assert not list(snapshots.iterdir())
            assert any(
                "result publication needs follow-up" in warning
                for warning in json.loads(row["completion_warnings_json"])
            )
            assert all(
                (scan.scan_dir / name).read_bytes() == value
                for name, value in original_outputs.items()
            )
        else:
            assert row["seal_manifest_digest"]
    finally:
        snapshots.chmod(0o700)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == (1 if disposition == "reported" else 0)
    assert all(path.read_bytes() == value for path, value in originals.items())


@pytest.mark.parametrize("snapshot_failure", [False, True])
@pytest.mark.parametrize("advance_after_cancel", [False, True])
def test_cancellation_captures_each_remaining_workers_current_head(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    snapshot_failure,
    advance_after_cancel,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    first = add_worker(workbench_db, scan, status="running")
    first.write_text(json.dumps(save_disposition(scan, first.parent, "reported")))
    second = add_worker(workbench_db, scan, status="running")
    scan.findings[0]["identity"]["anchor"] = "second-original"
    second.write_text(json.dumps(save_disposition(scan, second.parent, "reported")))
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET created_at = ? WHERE artifact_dir = ?",
            ("2026-01-01T00:00:00Z", str(first.parent)),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET created_at = ? WHERE artifact_dir = ?",
            ("2026-01-02T00:00:00Z", str(second.parent)),
        )
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes
    first_directory = first.parent.relative_to(scan.scan_dir).as_posix()
    raced = False

    def publish_second_during_first_snapshot(root, relative, contents):
        nonlocal raced
        if relative.startswith(first_directory + "/checkpoint-heads/") and not raced:
            raced = True
            scan.findings[0]["identity"]["anchor"] = "second-selected-before-cancel"
            save_disposition(scan, second.parent, "reported")
            if snapshot_failure:
                raise OSError("Synthetic first worker snapshot failure")
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        patch.setattr(
            "workbench.saved_sources.write_scan_local_bytes", publish_second_during_first_snapshot
        )
        saved.cancel_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, thread_id=None),
        )
    assert raced
    if advance_after_cancel:
        scan.findings[0]["identity"]["anchor"] = "second-selected-after-cancel"
        save_disposition(scan, second.parent, "reported")
    retained = preserve_scan_results(workbench_api, workbench_db, scan)
    assert retained["findingCount"] >= 2
    anchors = {
        finding["identity"]["anchor"]
        for finding in json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    }
    assert "second-selected-before-cancel" in anchors
    assert "second-selected-after-cancel" not in anchors


@pytest.mark.parametrize("blocked_report", [False, True])
def test_cancellation_freezes_sources_before_report_preparation(
    workbench_api,
    workbench_db,
    publication_scan,
    blocked_report,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="running")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    report = scan.scan_dir / "report.md"
    if blocked_report:
        report.unlink()
        report.mkdir()
    saved = workbench_api["saved_results"]
    saved.cancel_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, thread_id=None),
    )
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["canceled_at"] is not None
    assert row["retained_source_digests_json"] is not None
    if blocked_report:
        report.rmdir()
    scan.findings[0]["identity"]["anchor"] = "published-after-cancellation"
    save_disposition(scan, result.parent, "reported")
    retained = preserve_scan_results(workbench_api, workbench_db, scan)
    assert retained["findingCount"] == 1
    assert all(
        finding["identity"]["anchor"] != "published-after-cancellation"
        for finding in json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    )


@pytest.mark.parametrize("missing_old_checkpoint", [False, True])
def test_legacy_unreadable_head_does_not_hide_another_workers_new_evidence(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    missing_old_checkpoint,
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    checkpoint = (
        result.parent
        / "checkpoints"
        / json.loads((result.parent / "checkpoint-head.json").read_text())["checkpoint"]
    )
    saved = workbench_api["saved_results"]
    prepare = saved._prepare_scan_finalization

    def legacy_publication(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"].pop("preservedCheckpointHeads")
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_prepare_scan_finalization", legacy_publication)
        fail_scan(workbench_api, workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    before = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "report.md")
        if (scan.scan_dir / name).exists()
    }
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )
    if missing_old_checkpoint:
        checkpoint.unlink()
    scan.findings[0]["identity"]["anchor"] = "independent-new-worker"
    other = add_worker(workbench_db, scan, status="canceled")
    save_disposition(scan, other.parent, "reported")
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    assert all((scan.scan_dir / name).read_bytes() == content for name, content in before.items())


@pytest.mark.parametrize("head_state", ["malformed", "missing-checkpoint", "missing-head", "valid"])
def test_first_stop_keeps_registered_result_when_head_is_unreadable(
    workbench_api, workbench_db, publication_scan, head_state
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan)
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    head = result.parent / "checkpoint-head.json"
    if head_state == "missing-head":
        head.unlink()
    elif head_state != "valid":
        head.write_text(
            "{" if head_state == "malformed" else json.dumps({"checkpoint": "a" * 64 + ".json"})
        )
    original = result.read_bytes()
    stopped = fail_scan(workbench_api, workbench_db, scan)
    assert stopped["findingCount"] == 1
    assert not stopped["resultsRecoveryNeeded"]
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    assert replayed["findingCount"] == 1
    assert result.read_bytes() == original


@pytest.mark.parametrize("ordering", ["missing", "malformed", "valid"])
def test_legacy_ordering_failure_does_not_hide_new_worker_evidence(
    workbench_api, workbench_db, publication_scan, monkeypatch, ordering
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    saved = workbench_api["saved_results"]
    prepare = saved._prepare_scan_finalization

    def legacy_publication(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"].pop("preservedCheckpointHeads")
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_prepare_scan_finalization", legacy_publication)
        fail_scan(workbench_api, workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    assert not workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    ordering_path = next((scan.scan_dir / "source-order").glob("*.json"))
    if ordering == "missing":
        ordering_path.unlink()
    elif ordering == "malformed":
        ordering_path.write_text("{")
    original = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "report.md")
        if (scan.scan_dir / name).exists()
    }
    scan.findings[0]["identity"]["anchor"] = "independent-new-worker"
    other = add_worker(workbench_db, scan, status="canceled")
    save_disposition(scan, other.parent, "reported")
    assert workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"][
        "resultsRecoveryNeeded"
    ]
    assert all(
        (scan.scan_dir / name).read_bytes() == contents for name, contents in original.items()
    )
    if ordering != "valid":
        with pytest.raises(saved.ContractError):
            recover_scan_results(workbench_api, workbench_db, scan)
    else:
        assert recover_scan_results(workbench_api, workbench_db, scan)["findingCount"] == 2


@pytest.mark.parametrize("canceled", [False, True], ids=["failed", "canceled"])
def test_legacy_retained_heads_survive_loss_after_terminal_output(
    workbench_api, workbench_db, publication_scan, tmp_path, canceled
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    fail_scan(workbench_api, workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL, seal_manifest_digest = NULL, "
            "canceled_at = ? WHERE id = ?",
            (scan.timestamp if canceled else None, scan.scan_id),
        )
    for name in ("scan-manifest.json", "findings.json", "report.md"):
        (scan.scan_dir / name).unlink()
    database = tmp_path / "legacy-stop.sqlite3"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)
    child_program = """
import json, os, runpy, sqlite3, sys
from argparse import Namespace
from types import SimpleNamespace
api = runpy.run_path(sys.argv[1], run_name="legacy_stopped_publication_loss")
api["deep_scan"].configure(SimpleNamespace(**{**api, "preserve_stopped_results": api["preserve_stopped_results_after_transition"]}))
saved = api["saved_results"]
write = saved._write_prepared_scan_finalization
def lose_process(*args, **kwargs):
    write(*args, **kwargs)
    os._exit(73)
saved._write_prepared_scan_finalization = lose_process
connection = sqlite3.connect(sys.argv[2])
connection.row_factory = sqlite3.Row
connection.execute("PRAGMA foreign_keys = ON")
saved.preserve_scan_results(api["_WORKBENCH_DB_CONTEXT"], connection, Namespace(scan_id=sys.argv[3], claim_token=None, thread_id=None, coordinator_generation=None))
raise AssertionError("terminal write was not reached")
"""
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            child_program,
            workbench_api["__file__"],
            str(database),
            scan.scan_id,
        ],
        capture_output=True,
        text=True,
    )
    assert child.returncode == 73, child.stderr
    assert len(json.loads((scan.scan_dir / "findings.json").read_text())["findings"]) == 1
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        replayed = preserve_scan_results(workbench_api, connection, scan)
        assert replayed["findingCount"] == 1
        assert not replayed["resultsRecoveryNeeded"]
        assert (
            connection.execute(
                "SELECT retained_checkpoint_heads_json FROM scans WHERE id = ?", (scan.scan_id,)
            ).fetchone()[0]
            is not None
        )
