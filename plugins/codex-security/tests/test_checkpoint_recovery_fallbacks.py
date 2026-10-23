from __future__ import annotations

import copy
import json
import os
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import saved_draft, write_checkpoint


@pytest.mark.parametrize(
    ("mode", "owner"), [("standard", "root"), ("deep", "root"), ("deep", "worker")]
)
@pytest.mark.parametrize("interrupted", [False, True])
def test_published_raw_head_compatibility_converts_before_later_selection(
    workbench_api, workbench_db, publication_scan, monkeypatch, mode, owner, interrupted
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    for name in ("scan-manifest.json", "coverage.json", "findings.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if owner == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    initial = saved_draft(scan.scan_id, complete=True)
    initial["coverage"] = {**scan.coverage, **initial["coverage"]}
    checkpoint = write_checkpoint(directory / "checkpoints", initial)
    head = directory / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(100, 100))
    capture = saved._capture_saved_source

    def legacy_capture(root, relative, scan_id, *, checkpoint_heads=None, **kwargs):
        if Path(relative).name == "checkpoint-head.json" and checkpoint_heads is not None:
            checkpoint_heads[Path(relative).parent.as_posix()] = relative
        return capture(root, relative, scan_id, **{**kwargs, "snapshot_head": False})

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_capture_saved_source", legacy_capture)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    original = (scan.scan_dir / "scan-manifest.json").read_bytes()
    assert (
        head.relative_to(scan.scan_dir).as_posix()
        in json.loads(original)["scan"]["preservedSources"]
    )
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )

    def fail_write(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_write)
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                saved.preserve_scan_results(context, workbench_db, args)
            assert (scan.scan_dir / "scan-manifest.json").read_bytes() == original
    result = saved.preserve_scan_results(context, workbench_db, args)["scan"]
    assert not result["resultsRecoveryNeeded"]
    normalized = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert not any(
        Path(path).name == "checkpoint-head.json" for path in normalized["preservedSources"]
    )
    later = write_checkpoint(directory / "checkpoints", {**initial, "findings": scan.findings})
    head.write_text(json.dumps({"checkpoint": later.name}))
    os.utime(head, ns=(200, 200))
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))[
        "scan"
    ]
    assert recovered["findingCount"] == 1
    assert not recovered["resultsRecoveryNeeded"]


def test_early_head_error_keeps_captured_records_during_sibling_capture(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    first = add_worker(workbench_db, scan, status="canceled").parent
    second = add_worker(workbench_db, scan, status="canceled").parent
    with workbench_db:
        for directory, created_at in [
            (first, "2026-01-01T00:00:00Z"),
            (second, "2026-01-02T00:00:00Z"),
        ]:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET created_at = ? WHERE artifact_dir = ?",
                (created_at, str(directory)),
            )
    original = None
    for directory, anchor in [(first, "before"), (second, "second")]:
        finding = copy.deepcopy(scan.findings[0])
        finding["identity"]["anchor"] = anchor
        checkpoint = write_checkpoint(
            directory / "checkpoints", saved_draft(scan.scan_id, complete=True, findings=[finding])
        )
        head = directory / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(100, 100))
        if directory == first:
            original = head.read_bytes()
    write = saved.write_scan_local_bytes
    changed = False

    def capture_sibling(root, relative, contents):
        nonlocal changed
        path = Path(relative)
        if path.parent == first.relative_to(scan.scan_dir) / "checkpoint-heads":
            raise OSError("Synthetic first head failure")
        if path.parent == second.relative_to(scan.scan_dir) / "checkpoint-heads" and not changed:
            changed = True
            finding = copy.deepcopy(scan.findings[0])
            finding["identity"]["anchor"] = "after"
            checkpoint = write_checkpoint(
                first / "checkpoints", saved_draft(scan.scan_id, complete=True, findings=[finding])
            )
            (first / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
            os.utime(first / "checkpoint-head.json", ns=(200, 200))
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", capture_sibling)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    assert changed
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    with pytest.raises(
        saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
    ):
        saved.preserve_scan_results(context, workbench_db, args)
    head = first / "checkpoint-head.json"
    later = head.read_bytes()
    head.write_bytes(original)
    os.utime(head, ns=(100, 100))
    saved.preserve_scan_results(context, workbench_db, args)
    _, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert {row["identity"]["anchor"] for row in findings["findings"]} == {"before", "second"}
    head.write_bytes(later)
    os.utime(head, ns=(200, 200))
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    _, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert "after" in {row["identity"]["anchor"] for row in findings["findings"]}


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("late_model", [False, True])
@pytest.mark.parametrize("failure", ["source-order", "publication"])
def test_frozen_model_ignores_unselected_live_manifest_changes(
    workbench_api, workbench_db, publication_scan, monkeypatch, mode, late_model, failure
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    model = {"summary": "Original canonical model"}
    manifest["scan"].update(complete=True, threatModel=model)
    manifest_path.write_text(json.dumps(manifest))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    _, canonical = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    selected = write_checkpoint(
        scan.scan_dir / "checkpoints", {k: v for k, v in canonical.items() if k != "threatModel"}
    )
    os.utime(selected, ns=(50, 50))
    head = scan.scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(200, 200))
    write = saved.write_scan_local_bytes

    def fail_order(root, relative, contents):
        if relative.startswith("source-order/"):
            raise OSError("Synthetic ordering snapshot failure")
        return write(root, relative, contents)

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        if failure == "source-order":
            patch.setattr(saved, "write_scan_local_bytes", fail_order)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.cancel_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, thread_id=None, claim_token=None),
        )
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    digest = saved._digest(canonical)
    assert retained["sources"][f"checkpoints/{digest}.json"] == digest
    if late_model:
        manifest["scan"]["threatModel"] = {"summary": "Late unselected model"}
        manifest_path.write_text(json.dumps(manifest))
    replayed = saved.preserve_scan_results(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]
    published, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert published["scan"]["threatModel"] == model
    assert len(findings["findings"]) == replayed["findingCount"] == 1
    assert not replayed["resultsRecoveryNeeded"]
    assert "Late unselected model" not in (scan.scan_dir / "threatmodel.md").read_text()


@pytest.mark.parametrize(
    ("mode", "owner"), [("standard", "root"), ("deep", "root"), ("deep", "worker")]
)
@pytest.mark.parametrize("snapshot_failure", [False, True])
@pytest.mark.parametrize("resume", ["preserve", "recover"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_resumed_head_snapshot_allows_later_recovery(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    owner,
    snapshot_failure,
    resume,
    interrupted,
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    for name in ("scan-manifest.json", "coverage.json", "findings.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if owner == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    relative = directory.relative_to(scan.scan_dir)
    initial = saved_draft(scan.scan_id, complete=True)
    initial["coverage"] = {**scan.coverage, **initial["coverage"]}
    checkpoint = write_checkpoint(directory / "checkpoints", initial)
    os.utime(checkpoint, ns=(50, 50))
    head = directory / "checkpoint-head.json"
    original_head = json.dumps({"checkpoint": checkpoint.name})
    head.write_text(original_head)
    os.utime(head, ns=(100, 100))
    write = saved.write_scan_local_bytes

    def fail_head(root, path, contents):
        if Path(path).parent == relative / "checkpoint-heads":
            raise OSError("Synthetic head snapshot failure")
        return write(root, path, contents)

    with monkeypatch.context() as patch:
        if snapshot_failure:
            patch.setattr(saved, "write_scan_local_bytes", fail_head)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    retry = saved.preserve_scan_results if resume == "preserve" else saved.recover_scan_results

    def fail_write(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        if interrupted and snapshot_failure:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_write)
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                retry(context, workbench_db, args)
        else:
            retry(context, workbench_db, args)
    saved.preserve_scan_results(context, workbench_db, args)
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert not any(
        Path(path).name == "checkpoint-head.json" for path in manifest["preservedSources"]
    )
    observation = manifest["preservedCheckpointHeads"][relative.as_posix()]
    assert json.loads((scan.scan_dir / observation).read_text()) == {
        "checkpoint": checkpoint.name,
        "observedAtNs": "100",
    }
    assert head.read_text() == original_head
    later = write_checkpoint(directory / "checkpoints", {**initial, "findings": scan.findings})
    os.utime(later, ns=(50, 50))
    head.write_text(json.dumps({"checkpoint": later.name}))
    os.utime(head, ns=(200, 200))
    result = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))[
        "scan"
    ]
    assert result["findingCount"] == 1
    assert not result["resultsRecoveryNeeded"]
    published, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert len(findings["findings"]) == 1
    assert observation in published["scan"]["preservedSources"]


@pytest.mark.parametrize(
    ("mode", "failure"),
    [
        ("standard", "none"),
        ("standard", "root-head"),
        ("deep", "root-head"),
        ("deep", "worker-head"),
        ("deep", "source-order"),
    ],
)
@pytest.mark.parametrize("model_choice", ["canonical", "accepted", "selected"])
@pytest.mark.parametrize("live_change", ["coverage", "model"])
def test_early_head_failure_keeps_frozen_model_choice(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    failure,
    model_choice,
    live_change,
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["threatModel"] = {"summary": "Canonical model"}
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "coverage.json", "findings.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    draft = saved_draft(scan.scan_id, complete=True, findings=scan.findings)
    draft["coverage"] = {**scan.coverage, **draft["coverage"]}
    head = scan.scan_dir / "checkpoint-head.json"
    for label, observed in [
        ("Accepted model", 180 if model_choice == "accepted" else 100),
        ("Selected model" if model_choice == "selected" else None, 200),
    ]:
        payload = {**draft, **({"threatModel": {"summary": label}} if label else {})}
        checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", payload)
        os.utime(checkpoint, ns=(50, 50))
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))
        if label == "Accepted model":
            saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    if failure == "worker-head":
        directory = add_worker(workbench_db, scan, status="canceled").parent
        worker_checkpoint = write_checkpoint(
            directory / "checkpoints", saved_draft(scan.scan_id, complete=True)
        )
        worker_head = directory / "checkpoint-head.json"
        worker_head.write_text(json.dumps({"checkpoint": worker_checkpoint.name}))
        os.utime(worker_head, ns=(200, 200))
    write = saved.write_scan_local_bytes

    def fail_snapshot(root, relative, contents):
        parent = Path(relative).parent
        if (
            (failure == "root-head" and parent == Path("checkpoint-heads"))
            or (
                failure == "worker-head"
                and parent.name == "checkpoint-heads"
                and parent != Path("checkpoint-heads")
            )
            or (failure == "source-order" and parent == Path("source-order"))
        ):
            raise OSError("Synthetic snapshot failure")
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", fail_snapshot)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    if failure != "none":
        if live_change == "coverage":
            coverage_path = scan.scan_dir / "coverage.json"
            coverage = json.loads(coverage_path.read_text())
            coverage["openQuestions"] = [{"question": "Late coverage update"}]
            coverage_path.write_text(json.dumps(coverage))
        else:
            manifest["scan"]["threatModel"] = {"summary": "Late unselected model"}
            manifest_path.write_text(json.dumps(manifest))
    result = saved.preserve_scan_results(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]
    published, findings, _ = saved.finalize_scan(scan.scan_dir)
    expected = {
        "canonical": "Canonical model",
        "accepted": "Accepted model",
        "selected": "Selected model",
    }[model_choice]
    assert published["scan"]["threatModel"] == {"summary": expected}
    assert result["findingCount"] == len(findings["findings"]) == 1
    assert not result["resultsRecoveryNeeded"]


@pytest.mark.parametrize(
    ("mode", "owner"), [("standard", "root"), ("deep", "root"), ("deep", "worker")]
)
@pytest.mark.parametrize("change", ["head", "timestamp", "payload"])
@pytest.mark.parametrize("resume", ["preserve", "recover"])
def test_failed_head_fallback_rejects_changes_before_resume(
    workbench_api, workbench_db, publication_scan, monkeypatch, mode, owner, change, resume
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    for name in ("scan-manifest.json", "coverage.json", "findings.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if owner == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    relative = directory.relative_to(scan.scan_dir)
    initial = saved_draft(scan.scan_id, complete=True)
    initial["coverage"] = {**scan.coverage, **initial["coverage"]}
    checkpoint = write_checkpoint(directory / "checkpoints", initial)
    original_checkpoint = checkpoint.read_bytes()
    os.utime(checkpoint, ns=(50, 50))
    head = directory / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(100, 100))
    original_head = head.read_bytes()
    original_outputs = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    write = saved.write_scan_local_bytes

    def fail_head(root, path, contents):
        if Path(path).parent == relative / "checkpoint-heads":
            raise OSError("Synthetic head snapshot failure")
        return write(root, path, contents)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", fail_head)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    if change == "head":
        later = write_checkpoint(directory / "checkpoints", {**initial, "findings": scan.findings})
        head.write_text(json.dumps({"checkpoint": later.name}))
        os.utime(head, ns=(100, 100))
    elif change == "timestamp":
        os.utime(head, ns=(200, 200))
    else:
        checkpoint.write_text(json.dumps({**initial, "findings": scan.findings}))
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    retry = saved.preserve_scan_results if resume == "preserve" else saved.recover_scan_results
    with pytest.raises(
        saved.ContractError,
        match="changed after the scan stopped|Frozen stopped-scan checkpoint set is incomplete",
    ):
        retry(context, workbench_db, args)
    assert all(
        (scan.scan_dir / name).read_bytes() == value for name, value in original_outputs.items()
    )
    head.write_bytes(original_head)
    os.utime(head, ns=(100, 100))
    checkpoint.write_bytes(original_checkpoint)
    os.utime(checkpoint, ns=(50, 50))
    if change == "head":
        later.unlink()
    result = saved.preserve_scan_results(context, workbench_db, args)["scan"]
    assert result["findingCount"] == 0
    assert not result["resultsRecoveryNeeded"]


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("model_format", ["structured", "markdown"])
@pytest.mark.parametrize("replacement", ["omitted", "valid", "invalid"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_rejected_historical_model_does_not_poison_recovery(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    model_format,
    replacement,
    interrupted,
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    model = {"summary": "Valid canonical model"}
    invalid = (
        {"summary": 42} if model_format == "structured" else {"format": "markdown", "content": " "}
    )
    manifest["scan"]["threatModel"] = model
    manifest_path.write_text(json.dumps(manifest))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    draft = saved_draft(scan.scan_id, complete=True)
    draft.update(findings=scan.findings, coverage={**scan.coverage, **draft["coverage"]})

    def select(value, observed):
        path = write_checkpoint(scan.scan_dir / "checkpoints", value)
        os.utime(path, ns=(50, 50))
        head = scan.scan_dir / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": path.name}))
        os.utime(head, ns=(observed, observed))
        return path.relative_to(scan.scan_dir).as_posix()

    rejected = select({**draft, "threatModel": invalid}, 200)
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    assert "sealedAt" not in json.loads(manifest_path.read_text())["scan"]
    args = Namespace(scan_id=scan.scan_id)
    chosen = (
        draft
        if replacement == "omitted"
        else {
            **draft,
            "threatModel": invalid
            if replacement == "invalid"
            else {"summary": "Replacement model"},
        }
    )
    select(chosen, 300)
    if replacement == "invalid":
        with pytest.raises(saved.ContractError, match="threatModel"):
            saved.recover_scan_results(context, workbench_db, args)
        select({**draft, "threatModel": {"summary": "Replacement model"}}, 400)

    def fail_write(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_write)
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                saved.recover_scan_results(context, workbench_db, args)
        else:
            saved.recover_scan_results(context, workbench_db, args)
    replayed = saved.preserve_scan_results(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]
    published, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert published["scan"]["threatModel"] == (
        model if replacement == "omitted" else {"summary": "Replacement model"}
    )
    assert rejected in published["scan"]["preservedSources"]
    assert len(findings["findings"]) == replayed["findingCount"] == 1
    assert not replayed["resultsRecoveryNeeded"]


@pytest.mark.parametrize(
    ("mode", "owner", "registered"),
    [
        ("standard", "root", False),
        ("deep", "root", False),
        ("deep", "worker", False),
        ("deep", "worker", True),
    ],
)
@pytest.mark.parametrize("partial_time", [150, 300])
@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("repeated_terminal", [False, True])
def test_partial_head_retains_previous_terminal_coverage_boundary(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    owner,
    registered,
    partial_time,
    interrupted,
    repeated_terminal,
):
    scan = publication_scan(mode=mode)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage = {
        **scan.coverage,
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "openQuestions": [],
    }
    (scan.scan_dir / "coverage.json").write_text(json.dumps(coverage))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if owner == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    for label, observed in [("Obsolete", 100), ("Replacement", 200), ("Partial", partial_time)]:
        draft = saved_draft(scan.scan_id, complete=label != "Partial")
        draft["coverage"] = {**coverage, **draft["coverage"]}
        if label != "Partial":
            draft["coverage"].update(
                surfaces=[
                    {
                        "id": label,
                        "label": label,
                        "disposition": "no_issue_found",
                        "receiptRefs": [],
                    }
                ],
                explicitExclusions=[{"pattern": label + "/**", "reason": label}],
                openQuestions=[{"question": label}],
            )
        checkpoint = write_checkpoint(directory / "checkpoints", draft)
        os.utime(checkpoint, ns=(50, 50))
        head = directory / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))
        if label == "Replacement" and registered:
            with workbench_db:
                workbench_db.execute(
                    "UPDATE deep_scan_workers SET result_manifest_path = ? WHERE id = ?",
                    (str(checkpoint), directory.name),
                )
        if label == "Obsolete":
            saved.fail_scan(
                context,
                workbench_db,
                Namespace(
                    scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."
                ),
            )
        elif label == "Replacement":
            saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
            if repeated_terminal:
                os.utime(head, ns=(400, 400))
                saved._capture_saved_source(
                    scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
                )
        else:

            def fail_write(*args, **kwargs):
                raise OSError("Synthetic publication interruption")

            with monkeypatch.context() as patch:
                if interrupted:
                    patch.setattr(saved, "_write_prepared_scan_finalization", fail_write)
                    with pytest.raises(OSError, match="Synthetic publication interruption"):
                        saved.recover_scan_results(
                            context, workbench_db, Namespace(scan_id=scan.scan_id)
                        )
                else:
                    saved.recover_scan_results(
                        context, workbench_db, Namespace(scan_id=scan.scan_id)
                    )
    replayed = saved.preserve_scan_results(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]
    _, _, coverage = saved.finalize_scan(scan.scan_dir)
    expected = {"Replacement"} if partial_time == 300 or registered else {"Obsolete", "Replacement"}
    assert {row["label"] for row in coverage["surfaces"]} == expected
    assert {row["pattern"] for row in coverage["explicitExclusions"]} == {
        label + "/**" for label in expected
    }
    assert {row["question"] for row in coverage["openQuestions"]} == expected
    assert not replayed["resultsRecoveryNeeded"]


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("failed_capture", [False, True])
@pytest.mark.parametrize("late_model", [False, True])
@pytest.mark.parametrize("replay", ["preserve", "recover"])
def test_inherited_model_capture_is_bound_before_publication_retry(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    mode,
    failed_capture,
    late_model,
    replay,
):
    scan = publication_scan(mode=mode)
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    model = {"summary": "Original canonical model"}
    manifest["scan"].update(complete=True, threatModel=model)
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(150, 150))
    _, canonical = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    selected = write_checkpoint(
        scan.scan_dir / "checkpoints", {k: v for k, v in canonical.items() if k != "threatModel"}
    )
    os.utime(selected, ns=(50, 50))
    broken = scan.scan_dir / f"checkpoints/{saved._digest(canonical)}.json"
    broken.write_text("{")
    head = scan.scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(200, 200))
    model_draft = saved._parent_scan_draft(
        scan.scan_id, {"threatModel": model}, {"findings": []}, {}
    )
    model_source = f"checkpoints/{saved._digest(model_draft)}.json"
    write = saved.write_scan_local_bytes

    def fail_capture(root, relative, contents):
        if relative == model_source:
            raise OSError("Synthetic model capture failure")
        return write(root, relative, contents)

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        if failed_capture:
            patch.setattr(saved, "write_scan_local_bytes", fail_capture)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    row = workbench_db.execute(
        "SELECT retained_source_digests_json, completion_warnings_json FROM scans WHERE id = ?",
        (scan.scan_id,),
    ).fetchone()
    retained = json.loads(row[0])
    assert retained["sources"][model_source] == saved._digest(model_draft)
    assert (scan.scan_dir / model_source).exists() is not failed_capture
    assert any("Preserved unreadable checkpoint" in warning for warning in json.loads(row[1]))
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    retry = saved.preserve_scan_results if replay == "preserve" else saved.recover_scan_results
    if late_model:
        late = copy.deepcopy(manifest)
        late["scan"]["threatModel"] = {"summary": "Late unselected model"}
        manifest_path.write_text(json.dumps(late))
        if failed_capture:
            with pytest.raises(
                saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
            ):
                retry(context, workbench_db, args)
            assert "sealedAt" not in json.loads(manifest_path.read_text())["scan"]
            manifest_path.write_text(json.dumps(manifest))
    result = retry(context, workbench_db, args)["scan"]
    published, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert published["scan"]["threatModel"] == model
    assert len(findings["findings"]) == result["findingCount"] == 1
    assert not result["resultsRecoveryNeeded"]
    assert broken.read_text() == "{"
    assert (
        saved._frozen_source_times(
            scan.scan_dir, scan.scan_id, published["scan"]["preservedSources"]
        )[model_source]
        == 150
    )


@pytest.mark.parametrize(
    ("mode", "owner"), [("standard", "root"), ("deep", "root"), ("deep", "worker")]
)
@pytest.mark.parametrize("pending", ["linked", "unlinked", "closed"])
@pytest.mark.parametrize("interrupted", [False, True])
def test_restored_terminal_keeps_surfaces_for_surviving_deferred_work(
    workbench_api, workbench_db, publication_scan, monkeypatch, mode, owner, pending, interrupted
):
    scan = publication_scan(mode=mode)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage = {
        **scan.coverage,
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
        "openQuestions": [],
    }
    (scan.scan_dir / "coverage.json").write_text(json.dumps(coverage))
    for name in ("findings.json", "coverage.json", "scan-manifest.json"):
        os.utime(scan.scan_dir / name, ns=(0, 0))
    directory = (
        scan.scan_dir
        if owner == "root"
        else add_worker(workbench_db, scan, status="canceled").parent
    )
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    terminal = saved_draft(scan.scan_id, complete=True)
    terminal["coverage"] = {**coverage, **terminal["coverage"]}
    task = {"id": "review-task", "reason": "Review remains pending."}
    if pending != "unlinked":
        task["surfaceIds"] = ["pending-surface"]
    surface = {
        "id": "pending-surface",
        "label": "Unfinished authorization review",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    partial = saved_draft(scan.scan_id, complete=False, deferred=[task], surfaces=[surface])
    partial["coverage"] = {**coverage, **partial["coverage"]}
    sequence = [(terminal, 100), (partial, 200)]
    if pending == "closed":
        closed = copy.deepcopy(terminal)
        closed["coverage"]["resolvedDeferred"] = [{"id": task["id"], "reason": "Review completed."}]
        sequence.append((closed, 300))
    sequence.append((terminal, 100))
    for index, (draft, observed) in enumerate(sequence):
        checkpoint = write_checkpoint(directory / "checkpoints", draft)
        os.utime(checkpoint, ns=(50, 50))
        head = directory / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        os.utime(head, ns=(observed, observed))
        if index == 0:
            saved.fail_scan(
                context,
                workbench_db,
                Namespace(
                    scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."
                ),
            )
        else:

            def fail_write(*args, **kwargs):
                raise OSError("Synthetic publication interruption")

            with monkeypatch.context() as patch:
                if interrupted and index == len(sequence) - 1:
                    patch.setattr(saved, "_write_prepared_scan_finalization", fail_write)
                    with pytest.raises(OSError, match="Synthetic publication interruption"):
                        saved.recover_scan_results(
                            context, workbench_db, Namespace(scan_id=scan.scan_id)
                        )
                else:
                    saved.recover_scan_results(
                        context, workbench_db, Namespace(scan_id=scan.scan_id)
                    )
    replayed = saved.preserve_scan_results(
        context,
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]
    _, _, coverage = saved.finalize_scan(scan.scan_dir)
    if owner == "worker":
        surface = {**surface, "id": f"{directory.name}/pending-surface", "workerId": directory.name}
        task = {**task, "id": f"{directory.name}/review-task", "workerId": directory.name}
        if "surfaceIds" in task:
            task["surfaceIds"] = [surface["id"]]
    assert coverage["surfaces"] == ([surface] if pending == "linked" else [])
    assert (task in coverage["deferred"]) is (pending != "closed")
    assert (surface["label"] in (scan.scan_dir / "report.md").read_text()) is (pending == "linked")
    assert not replayed["resultsRecoveryNeeded"]
