from __future__ import annotations

import copy
import json
import os
from argparse import Namespace
from pathlib import Path

import pytest
from test_deep_scan_successful_publication import (
    add_worker,
    fail_scan,
    preserve_scan_results,
    recover_scan_results,
)
from test_deep_scan_successful_publication import publication_scan as publication_scan
from workbench_test_support import (
    interrupt_publication,
    read_review_state,
    saved_draft,
    write_checkpoint,
)


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
        patch.setattr("workbench.retained_coverage._capture_saved_source", legacy_capture)
        fail_scan(workbench_api, workbench_db, scan)
    original = (scan.scan_dir / "scan-manifest.json").read_bytes()
    assert (
        head.relative_to(scan.scan_dir).as_posix()
        in json.loads(original)["scan"]["preservedSources"]
    )
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
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
    recovered = recover_scan_results(workbench_api, workbench_db, scan)
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
        patch.setattr("workbench.saved_sources.write_scan_local_bytes", capture_sibling)
        fail_scan(workbench_api, workbench_db, scan)
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
    recover_scan_results(workbench_api, workbench_db, scan)
    _, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert "after" in {row["identity"]["anchor"] for row in findings["findings"]}


@pytest.mark.parametrize("restore_capture", [False, True])
def test_frozen_model_capture_keeps_earlier_worker_finding(
    workbench_api, workbench_db, publication_scan, monkeypatch, restore_capture
):
    scan = publication_scan()
    saved = workbench_api["saved_results"]
    model = {"summary": "Retained scan model."}
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["threatModel"] = model
    manifest_path.write_text(json.dumps(manifest))
    (scan.scan_dir / "findings.json").unlink()
    result = add_worker(workbench_db, scan, status="succeeded")
    worker_draft = saved_draft(scan.scan_id, findings=scan.findings, complete=True)
    result.write_text(json.dumps(worker_draft))
    partial = saved_draft(scan.scan_id, complete=False)
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", partial)
    head = scan.scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    for path, timestamp in ((result, 100_000), (manifest_path, 150_000), (head, 200_000)):
        os.utime(path, ns=(timestamp, timestamp))
    model_draft = saved._parent_scan_draft(
        scan.scan_id, {"threatModel": model}, {"findings": []}, {}
    )
    model_path = f"checkpoints/{saved._digest(model_draft)}.json"
    initial = []
    write = saved.write_scan_local_bytes

    def interrupt_capture(root, relative, content):
        if relative == model_path:
            raise OSError("Synthetic model capture failure.")
        return write(root, relative, content)

    def interrupt(prepared, **kwargs):
        initial.append(prepared.findings["findings"])
        interrupt_publication()

    with monkeypatch.context() as patch:
        if restore_capture:
            patch.setattr("workbench.retained_coverage.write_scan_local_bytes", interrupt_capture)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt)
        fail_scan(workbench_api, workbench_db, scan)
    if not restore_capture:
        assert len(initial) == len(initial[0]) == 1
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    capture = scan.scan_dir / retained["threatModelSource"]
    assert retained["threatModelSource"] == model_path
    assert capture.exists() is not restore_capture
    preserve_scan_results(workbench_api, workbench_db, scan)
    final_manifest, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert final_manifest["scan"]["threatModel"] == model
    assert len(findings["findings"]) == 1
    assert findings["findings"][0]["identity"] == scan.findings[0]["identity"]
    if not restore_capture:
        assert findings["findings"] == initial[0]
    assert capture.read_bytes() == saved._encoded(model_draft)


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

    with monkeypatch.context() as patch:
        if failure == "source-order":
            patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_order)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
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
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
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
            patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_head)
        fail_scan(workbench_api, workbench_db, scan)
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    retry = saved.preserve_scan_results if resume == "preserve" else saved.recover_scan_results

    with monkeypatch.context() as patch:
        if interrupted and snapshot_failure:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
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
    result = recover_scan_results(workbench_api, workbench_db, scan)
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
        patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_snapshot)
        fail_scan(workbench_api, workbench_db, scan)
    if failure != "none":
        if live_change == "coverage":
            coverage_path = scan.scan_dir / "coverage.json"
            coverage = json.loads(coverage_path.read_text())
            coverage["openQuestions"] = [{"question": "Late coverage update"}]
            coverage_path.write_text(json.dumps(coverage))
        else:
            manifest["scan"]["threatModel"] = {"summary": "Late unselected model"}
            manifest_path.write_text(json.dumps(manifest))
    result = preserve_scan_results(workbench_api, workbench_db, scan)
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
        if (scan.scan_dir / name).exists()
    }
    write = saved.write_scan_local_bytes

    def fail_head(root, path, contents):
        if Path(path).parent == relative / "checkpoint-heads":
            raise OSError("Synthetic head snapshot failure")
        return write(root, path, contents)

    with monkeypatch.context() as patch:
        patch.setattr("workbench.saved_sources.write_scan_local_bytes", fail_head)
        fail_scan(workbench_api, workbench_db, scan)
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

    _, canonical = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    canonical_source = f"checkpoints/{saved._digest(canonical)}.json"
    select({**draft, "threatModel": {"summary": "Older accepted model"}}, 100)
    saved._capture_saved_source(scan.scan_dir, "checkpoint-head.json", scan.scan_id)
    invalid_source = select({**draft, "threatModel": invalid}, 200)
    stopped = fail_scan(workbench_api, workbench_db, scan)
    assert stopped["findingCount"] == 1
    assert any("Skipped malformed saved threat model" in warning for warning in stopped["warnings"])
    assert json.loads(manifest_path.read_text())["scan"]["threatModel"] == model
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
    selected_source = select(chosen, 300)

    with monkeypatch.context() as patch:
        if interrupted:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                saved.recover_scan_results(context, workbench_db, args)
        else:
            saved.recover_scan_results(context, workbench_db, args)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    published, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert published["scan"]["threatModel"] == (
        {"summary": "Replacement model"} if replacement == "valid" else model
    )
    retained = workbench_db.execute(
        "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    assert json.loads(retained)["threatModelSource"] == (
        selected_source if replacement == "valid" else canonical_source
    )
    assert invalid_source in published["scan"]["preservedSources"]
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
            fail_scan(workbench_api, workbench_db, scan)
        elif label == "Replacement":
            recover_scan_results(workbench_api, workbench_db, scan)
            if repeated_terminal:
                os.utime(head, ns=(400, 400))
                saved._capture_saved_source(
                    scan.scan_dir, head.relative_to(scan.scan_dir).as_posix(), scan.scan_id
                )
        else:
            with monkeypatch.context() as patch:
                if interrupted:
                    patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
                    with pytest.raises(OSError, match="Synthetic publication interruption"):
                        recover_scan_results(workbench_api, workbench_db, scan)
                else:
                    recover_scan_results(workbench_api, workbench_db, scan)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    saved.finalize_scan(scan.scan_dir)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    expected = {"Replacement"} if partial_time == 300 or registered else {"Obsolete", "Replacement"}
    assert {row["label"] for row in coverage["surfaces"]} == expected
    assert {row["pattern"] for row in coverage["explicitExclusions"]} == {
        label + "/**" for label in expected
    }
    assert {row["question"] for row in coverage["openQuestions"]} == expected
    assert not replayed["resultsRecoveryNeeded"]


@pytest.mark.parametrize("head_time", [100_000, 200_000], ids=["older", "tied"])
def test_retry_keeps_canonical_finding_when_its_checkpoint_copy_is_unreadable(
    workbench_api, workbench_db, publication_scan, monkeypatch, head_time
):
    scan = publication_scan(mode="standard")
    saved = workbench_api["saved_results"]
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    model = {"summary": "Canonical model"}
    manifest["scan"].update(complete=True, threatModel=model)
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(scan.scan_dir / name, ns=(200_000, 200_000))
    _, canonical = saved._read_saved_parent_result(scan.scan_dir, scan.scan_id)
    empty = {key: value for key, value in canonical.items() if key != "threatModel"}
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", {**empty, "findings": []})
    broken = checkpoint.parent / f"{saved._digest(canonical)}.json"
    broken.write_bytes(b"{")
    head = scan.scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(head, ns=(head_time, head_time))

    attempted = []

    def interrupt(prepared, **kwargs):
        attempted.append(
            (prepared.findings["findings"][0]["title"], prepared.manifest["scan"]["threatModel"])
        )
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", interrupt)
        fail_scan(workbench_api, workbench_db, scan)
    assert attempted == [(scan.findings[0]["title"], model)]
    with pytest.raises(
        saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
    ):
        preserve_scan_results(workbench_api, workbench_db, scan)
    assert broken.read_bytes() == b"{"
    assert "sealedAt" not in json.loads(manifest_path.read_text())["scan"]


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

    with monkeypatch.context() as patch:
        if failed_capture:
            patch.setattr("workbench.retained_coverage.write_scan_local_bytes", fail_capture)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
        fail_scan(workbench_api, workbench_db, scan)
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
            fail_scan(workbench_api, workbench_db, scan)
        else:
            with monkeypatch.context() as patch:
                if interrupted and index == len(sequence) - 1:
                    patch.setattr(saved, "_write_prepared_scan_finalization", interrupt_publication)
                    with pytest.raises(OSError, match="Synthetic publication interruption"):
                        recover_scan_results(workbench_api, workbench_db, scan)
                else:
                    recover_scan_results(workbench_api, workbench_db, scan)
    replayed = preserve_scan_results(workbench_api, workbench_db, scan)
    saved.finalize_scan(scan.scan_dir)
    coverage = read_review_state(workbench_db, scan.scan_dir)
    if owner == "worker":
        surface = {**surface, "id": f"{directory.name}/pending-surface", "workerId": directory.name}
        task = {**task, "id": f"{directory.name}/review-task", "workerId": directory.name}
        if "surfaceIds" in task:
            task["surfaceIds"] = [surface["id"]]
    assert coverage["surfaces"] == ([surface] if pending == "linked" else [])
    assert (task in coverage["deferred"]) is (pending != "closed")
    assert surface["label"] not in (scan.scan_dir / "report.md").read_text()
    assert not replayed["resultsRecoveryNeeded"]


def test_source_order_failure_retains_accepted_parent_input(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    from workbench import saved_sources

    scan = publication_scan()
    saved = workbench_api["saved_results"]
    scan_dir = scan.scan_dir
    manifest = scan_dir / "scan-manifest.json"
    contents = json.loads(manifest.read_text())
    contents["scan"]["complete"] = True
    manifest.write_text(json.dumps(contents))
    _, projected = saved._read_saved_parent_result(scan_dir, scan.scan_id)
    checkpoints = scan_dir / "checkpoints"
    publication = {"previousCheckpoint": None, "previousInputCheckpoint": None}
    accepted = write_checkpoint(
        checkpoints,
        {
            **saved_draft(scan.scan_id, findings=scan.findings, complete=True),
            "publication": publication,
        },
    )
    selected = write_checkpoint(checkpoints, projected)
    abandoned = write_checkpoint(
        checkpoints, {**saved_draft(scan.scan_id, complete=True), "publication": publication}
    )
    head = scan_dir / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name, "inputCheckpoint": accepted.name}))
    for path in (
        accepted,
        selected,
        head,
        manifest,
        scan_dir / "findings.json",
        scan_dir / "coverage.json",
    ):
        os.utime(path, ns=(200, 200))
    os.utime(abandoned, ns=(300, 300))

    write = saved_sources.write_scan_local_bytes

    def fail_order(root, path, data):
        if Path(path).parent == Path("source-order"):
            raise OSError("Synthetic source-order failure")
        return write(root, path, data)

    with monkeypatch.context() as patch:
        patch.setattr(saved_sources, "write_scan_local_bytes", fail_order)
        fail_scan(workbench_api, workbench_db, scan)
    assert "sealedAt" not in json.loads(manifest.read_text())["scan"]
    head.write_text(json.dumps({"checkpoint": abandoned.name, "inputCheckpoint": abandoned.name}))
    os.utime(head, ns=(400, 400))
    preserve_scan_results(workbench_api, workbench_db, scan)
    _, findings, _ = saved.finalize_scan(scan_dir)
    assert [finding["title"] for finding in findings["findings"]] == [scan.findings[0]["title"]]


def test_headless_canonical_snapshot_failure(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    from workbench import saved_sources

    scan = publication_scan()
    saved = workbench_api["saved_results"]
    write = saved_sources.write_scan_local_bytes
    original = scan.findings[0]["title"]
    head = scan.scan_dir / "checkpoint-head.json"
    assert not head.exists()

    def fail_snapshot(root, path, data):
        if Path(path).parent == Path("checkpoint-heads"):
            raise OSError("Synthetic canonical observation failure")
        return write(root, path, data)

    with monkeypatch.context() as patch:
        patch.setattr(saved_sources, "write_scan_local_bytes", fail_snapshot)
        fail_scan(workbench_api, workbench_db, scan)
    assert not head.exists()
    assert "sealedAt" not in json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    raw = write_checkpoint(
        scan.scan_dir / "checkpoints",
        {
            **saved_draft(scan.scan_id, complete=True),
            "publication": {"previousCheckpoint": None, "previousInputCheckpoint": None},
        },
    )
    head.write_text(json.dumps({"checkpoint": raw.name, "inputCheckpoint": raw.name}))
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    preserve_scan_results(workbench_api, workbench_db, scan)
    manifest, findings, _ = saved.finalize_scan(scan.scan_dir)
    assert [f["title"] for f in findings["findings"]] == [original]
    assert "." not in manifest["scan"]["preservedCheckpointHeads"]


@pytest.mark.parametrize(
    ("retry", "selection"),
    [
        ("preserve", "first"),
        ("recover", "first"),
        ("recover", "old-journal"),
        ("recover", "frozen"),
    ],
)
def test_interrupted_recovery_keeps_frozen_parent_reconciliation(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry, selection
):
    scan = publication_scan(mode="deep")
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    args = Namespace(
        scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
    )
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET status = 'failed', completed_at = started_at WHERE id = ?",
            (scan.scan_id,),
        )
    worker = add_worker(workbench_db, scan, status="canceled")
    draft = saved_draft(scan.scan_id, complete=True)
    worker.write_text(json.dumps({**draft, "findings": scan.findings}))
    os.utime(worker, ns=(100_000, 100_000))
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", draft)
    os.utime(checkpoint, ns=(250_000, 250_000))
    manifest = scan.scan_dir / "scan-manifest.json"
    contents = json.loads(manifest.read_text())
    contents["scan"]["complete"] = True
    manifest.write_text(json.dumps(contents))
    findings_file = scan.scan_dir / "findings.json"
    findings_file.write_text(json.dumps({"findings": []}))
    for path in (manifest, findings_file, scan.scan_dir / "coverage.json"):
        os.utime(path, ns=(300_000, 300_000))

    expected = [] if selection == "frozen" else [scan.findings[0]["title"]]

    def interrupt(prepared, **kwargs):
        assert [row["title"] for row in prepared.findings["findings"]] == expected
        interrupt_publication()

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", interrupt)
        if selection == "frozen":
            with pytest.raises(OSError, match="Synthetic publication interruption"):
                saved.preserve_scan_results(context, workbench_db, args)
        with pytest.raises(OSError, match="Synthetic publication interruption"):
            saved.recover_scan_results(context, workbench_db, args)
    if selection == "old-journal":
        retained = json.loads(
            workbench_db.execute(
                "SELECT retained_checkpoint_heads_json FROM scans WHERE id = ?", (scan.scan_id,)
            ).fetchone()[0]
        )
        del retained["legacyParent"]
        with workbench_db:
            workbench_db.execute(
                "UPDATE scans SET retained_checkpoint_heads_json = ? WHERE id = ?",
                (json.dumps(retained), scan.scan_id),
            )
    findings_file.write_text(
        json.dumps({"findings": [{**scan.findings[0], "title": "Late unselected report"}]})
    )
    resume = saved.preserve_scan_results if retry == "preserve" else saved.recover_scan_results
    result = resume(context, workbench_db, args)["scan"]
    assert result["findingCount"] == len(expected)
    assert [row["title"] for row in json.loads(findings_file.read_text())["findings"]] == expected
