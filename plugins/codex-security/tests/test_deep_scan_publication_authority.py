from __future__ import annotations

import copy
import errno
import json
import os
import sys
import uuid
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


def stage_publication(scan, *, generation, result_path, title, complete=True):
    draft_dir = scan.scan_dir / "drafts"
    draft_dir.mkdir(exist_ok=True)
    draft_path = draft_dir / f"{uuid.uuid4()}.json"
    checkpoint_path = draft_dir / f"{uuid.uuid4()}.checkpoint.json"
    findings = copy.deepcopy(scan.findings)
    findings[0]["title"] = title
    draft = {
        "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
        "findings": {"findings": findings},
        "coverage": scan.coverage,
    }
    if not complete:
        draft["manifest"]["scan"]["complete"] = False
    if generation is not None:
        draft["deepScanPublication"] = {
            "coordinatorGeneration": generation,
            "resultPath": str(result_path),
        }
    draft_path.write_text(json.dumps(draft))
    checkpoint_path.write_text(
        json.dumps({"scanId": scan.scan_id, "findings": findings, "coverage": scan.coverage})
    )
    return Namespace(
        scan_id=scan.scan_id,
        claim_token=None,
        draft_path=str(draft_path),
        checkpoint_path=str(checkpoint_path),
        expected_draft_digest=None,
    )


@pytest.mark.parametrize(
    ("stale", "complete"),
    [
        ("generation", True),
        ("generation", False),
        ("aggregate", True),
        ("aggregate", False),
        ("unfenced", True),
    ],
)
def test_stale_coordinator_cannot_replace_newer_canonical_publication(
    workbench_api, workbench_db, publication_scan, stale, complete
):
    scan = publication_scan()
    old_result = add_worker(workbench_db, scan)
    new_result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = 3 WHERE scan_id = ?",
            (scan.scan_id,),
        )
        for sequence, result in enumerate((old_result, new_result), start=1):
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none', "
                "prompt_path = ?, completed_at = ? "
                "WHERE result_manifest_path = ?",
                (
                    str(scan.scan_dir / f"dedup-{sequence:04d}" / "prompt.md"),
                    f"2026-01-0{sequence}",
                    str(result),
                ),
            )
    current = stage_publication(
        scan, generation=3, result_path=new_result, title="Current accepted aggregate"
    )
    workbench_api["write_scan_draft"](workbench_db, current)
    saved = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    }
    old = stage_publication(
        scan,
        generation=None if stale == "unfenced" else 2 if stale == "generation" else 3,
        result_path=old_result if stale == "aggregate" else new_result,
        title="Superseded aggregate",
        complete=complete,
    )

    with pytest.raises(SystemExit, match="coordinator|aggregate"):
        workbench_api["write_scan_draft"](workbench_db, old)

    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == saved


@pytest.mark.parametrize("generation", [None, 3], ids=["legacy-generation-one", "current-lease"])
def test_current_publication_replays_without_changing_checkpoint_or_worker_state(
    workbench_api, workbench_db, publication_scan, generation
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET coordinator_generation = ? WHERE scan_id = ?",
            (generation or 1, scan.scan_id),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    draft = stage_publication(
        scan, generation=generation, result_path=result, title="Accepted aggregate"
    )
    run_before = dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone())
    worker_before = dict(workbench_db.execute("SELECT * FROM deep_scan_workers").fetchone())

    workbench_api["write_scan_draft"](workbench_db, draft)
    published = {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    }
    replay = workbench_api["write_scan_draft"](workbench_db, draft)

    assert replay == {"scanId": scan.scan_id, "status": "draft_written"}
    assert {
        path: path.read_bytes()
        for path in scan.scan_dir.rglob("*.json")
        if "drafts" not in path.parts
    } == published
    assert len(list((scan.scan_dir / "checkpoints").glob("*.json"))) == 1
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_runs").fetchone()) == run_before
    assert dict(workbench_db.execute("SELECT * FROM deep_scan_workers").fetchone()) == worker_before
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["title"] == "Accepted aggregate"


@pytest.mark.parametrize(
    "failure",
    ["validation", "findings.json", "coverage.json", "scan-manifest.json"]
    + [
        f"windows-emulated:{name}"
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
    ],
)
def test_failed_publication_does_not_acknowledge_staged_input(
    workbench_api, workbench_db, publication_scan, monkeypatch, failure
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-scan-mcp/v1', "
            "coordinator_generation = 2 WHERE scan_id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    args = stage_publication(scan, generation=2, result_path=result, title="Accepted aggregate")
    staged = {path: path.read_bytes() for path in (scan.scan_dir / "drafts").iterdir()}
    saved_results = workbench_api["saved_results"]
    original_write = saved_results.write_scan_local_bytes

    def fail_validation(*args):
        raise OSError("Synthetic validation failure")

    def fail_write(scan_dir, filename, contents):
        if filename == failure:
            raise OSError("Synthetic canonical write failure")
        if failure == f"windows-emulated:{filename}":
            with monkeypatch.context() as patch:
                finalizer = sys.modules[original_write.__module__]
                backend = emulate_windows_atomic_write(patch, finalizer)
                patch.setattr(backend, "_rename_handle", fail_validation)
                return original_write(scan_dir, filename, contents)
        original_write(scan_dir, filename, contents)

    if failure == "validation":
        monkeypatch.setattr(saved_results, "_validate_completion_binding", fail_validation)
    else:
        monkeypatch.setattr(saved_results, "write_scan_local_bytes", fail_write)

    expected_error = (
        saved_results.ContractError if failure.startswith("windows-emulated:") else OSError
    )
    with pytest.raises(expected_error, match="Synthetic"):
        workbench_api["write_scan_draft"](workbench_db, args)

    assert {path: path.read_bytes() for path in (scan.scan_dir / "drafts").iterdir()} == staged


def emulate_windows_atomic_write(monkeypatch, finalizer, *, reparse_point=False):
    """Run the real Windows atomic writer with emulated handles, not native Win32 I/O."""
    backend = finalizer._windows_scan_local_files()
    paths = {}
    pending_deletions = set()

    @contextmanager
    def locked_parent(scan_dir, relative_path, **kwargs):
        parts = backend._validated_parts(relative_path)
        yield scan_dir.joinpath(*parts[:-1]), parts[-1]

    def create_file(path, **kwargs):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        paths[descriptor] = path
        return backend._OwnedHandle(descriptor)

    def rename_handle(handle, destination):
        os.replace(paths[handle], destination)
        paths[handle] = destination

    def close_handle(handle):
        os.close(handle)
        if handle in pending_deletions:
            paths[handle].unlink()

    monkeypatch.setattr(finalizer, "_descriptor_relative_writes_available", lambda: False)
    monkeypatch.setattr(finalizer, "_is_windows", lambda: True)
    monkeypatch.setattr(backend, "_locked_parent", locked_parent)
    monkeypatch.setattr(backend, "_validate_existing_output", lambda path: None)
    monkeypatch.setattr(backend, "_create_file", create_file)
    monkeypatch.setattr(backend, "_close_handle", close_handle)
    monkeypatch.setattr(
        backend,
        "_attributes",
        lambda handle: SimpleNamespace(
            FileAttributes=backend._FILE_ATTRIBUTE_REPARSE_POINT if reparse_point else 0
        ),
    )
    monkeypatch.setattr(
        backend, "_GetFileType", lambda handle: backend._FILE_TYPE_DISK, raising=False
    )
    monkeypatch.setattr(backend, "_verify_handle_path", lambda *args: None)
    monkeypatch.setattr(backend, "_write_all", os.write)
    monkeypatch.setattr(backend, "_rename_handle", rename_handle)
    monkeypatch.setattr(backend, "_mark_handle_for_deletion", pending_deletions.add)
    return backend


@pytest.mark.parametrize("workflow", ["deep-scan-mcp/v1", "deep-security-scan/v1"])
@pytest.mark.parametrize(
    ("backend_kind", "failure"),
    [("host", "write"), ("host", "rename")]
    + [("windows-emulated", failure) for failure in ("create", "write", "rename")],
)
def test_receipt_io_failure_preserves_successful_publication(
    workbench_api, workbench_db, publication_scan, monkeypatch, workflow, backend_kind, failure
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = ?, coordinator_generation = 2 "
            "WHERE scan_id = ?",
            (workflow, scan.scan_id),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    args = stage_publication(scan, generation=2, result_path=result, title="Accepted aggregate")
    draft = json.loads(Path(args.draft_path).read_text())
    staged = {path: path.read_bytes() for path in (scan.scan_dir / "drafts").iterdir()}
    saved_results = workbench_api["saved_results"]
    original_write = saved_results.write_scan_local_bytes
    original_replace = os.replace
    failures = []

    def fail_receipt(filename):
        failures.append(filename)
        # The fault occurs only after all three canonical files have been published.
        for name, document in (
            ("findings.json", draft["findings"]),
            ("coverage.json", draft["coverage"]),
            ("scan-manifest.json", draft["manifest"]),
        ):
            assert json.loads((scan.scan_dir / name).read_text()) == document
        raise OSError(errno.ENOSPC, "Synthetic receipt I/O failure", filename)

    def write_file(scan_dir, filename, contents):
        if not filename.endswith(".accepted.json"):
            return original_write(scan_dir, filename, contents)
        with monkeypatch.context() as patch:
            finalizer = sys.modules[original_write.__module__]
            if backend_kind == "windows-emulated":
                backend = emulate_windows_atomic_write(patch, finalizer)
            elif os.name == "nt":
                backend = finalizer._windows_scan_local_files()
            else:
                if failure == "write":
                    fail_receipt(filename)
                return original_write(scan_dir, filename, contents)

            def fail_backend(*args, **kwargs):
                fail_receipt(filename)

            operation = {
                "create": "_create_file",
                "write": "_write_all",
                "rename": "_rename_handle",
            }
            patch.setattr(backend, operation[failure], fail_backend)
            return original_write(scan_dir, filename, contents)

    def replace_file(source, destination, *args, **kwargs):
        if failure == "rename" and str(destination).endswith(".accepted.json"):
            fail_receipt(destination)
        return original_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(saved_results, "write_scan_local_bytes", write_file)
    monkeypatch.setattr(os, "replace", replace_file)

    assert workbench_api["write_scan_draft"](workbench_db, args) == {
        "scanId": scan.scan_id,
        "status": "draft_written",
    }
    assert len(failures) == 1
    assert {path: path.read_bytes() for path in (scan.scan_dir / "drafts").iterdir()} == staged
    assert len(list((scan.scan_dir / "checkpoints").glob("*.json"))) == 1


@pytest.mark.parametrize("failure", ["validation", "unsafe-path", "windows-reparse-emulated"])
def test_receipt_contract_errors_still_reject_publication(
    workbench_api, workbench_db, publication_scan, monkeypatch, failure
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET workflow_version = 'deep-scan-mcp/v1', "
            "coordinator_generation = 2 WHERE scan_id = ?",
            (scan.scan_id,),
        )
        workbench_db.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    args = stage_publication(scan, generation=2, result_path=result, title="Accepted aggregate")
    staged = {path: path.read_bytes() for path in (scan.scan_dir / "drafts").iterdir()}
    saved_results = workbench_api["saved_results"]
    original_write = saved_results.write_scan_local_bytes
    finalizer = sys.modules[original_write.__module__]
    attempts = []

    def write_file(scan_dir, filename, contents):
        if not filename.endswith(".accepted.json"):
            return original_write(scan_dir, filename, contents)
        attempts.append(filename)
        if failure == "validation":
            raise finalizer.ContractError("Synthetic receipt validation failure")
        if failure == "unsafe-path":
            return original_write(scan_dir, "../outside.accepted.json", contents)
        with monkeypatch.context() as patch:
            emulate_windows_atomic_write(patch, finalizer, reparse_point=True)
            return original_write(scan_dir, filename, contents)

    monkeypatch.setattr(saved_results, "write_scan_local_bytes", write_file)
    with pytest.raises(finalizer.ContractError, match="validation|safe|reparse"):
        workbench_api["write_scan_draft"](workbench_db, args)
    assert len(attempts) == 1
    assert {path: path.read_bytes() for path in (scan.scan_dir / "drafts").iterdir()} == staged
    assert not (scan.scan_dir.parent / "outside.accepted.json").exists()
