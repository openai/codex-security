from __future__ import annotations

import hashlib
import json
import shutil
from argparse import Namespace
from contextlib import closing
from pathlib import Path

import pytest
from test_workbench_stopped_worker_coverage import child_scan, composed_scan
from workbench_test_support import register, run_workbench, write_completed_contract


def test_canceled_composition_retries_publication_after_io_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workbench_api
) -> None:
    state, target, parent, directory = composed_scan(tmp_path)
    _, child_directory, selected = child_scan(state, target, parent, "review", finding=True)
    original = selected.read_bytes()
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    saved = workbench_api["saved_results"]
    write = saved._write_prepared_scan_finalization

    def fail_parent(prepared, **kwargs):
        if prepared.scan_dir == directory:
            raise OSError("Synthetic cancellation publication failure")
        return write(prepared, **kwargs)

    with closing(workbench_api["connect"]()) as connection:
        with monkeypatch.context() as patch:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_parent)
            saved.cancel_scan_locked(
                workbench_api["_WORKBENCH_DB_CONTEXT"],
                connection,
                Namespace(scan_id=parent["scanId"], thread_id=None),
            )
        row = workbench_api["require_scan"](connection, parent["scanId"])
        assert row["seal_manifest_digest"] is None
        assert row["retained_source_digests_json"] is not None
        assert "Synthetic cancellation publication failure" in row["completion_warnings_json"]
    recovered = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert recovered["progress"]["status"] == "canceled"
    assert recovered["findingCount"] == 1
    assert recovered["reportAvailable"] is True
    assert not any("publication needs follow-up" in warning for warning in recovered["warnings"])
    assert len(json.loads((child_directory / "findings.json").read_text())["findings"]) == 1
    assert selected.read_bytes() == original


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_legacy_sealed_results_survive_publication_failure_and_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workbench_api, mode: str
) -> None:
    state, target, directory = tmp_path / "state", tmp_path / "target", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, directory, mode=mode)
    write_completed_contract(
        directory,
        scan["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository" if mode == "deep" else "repository",
    )
    run_workbench(state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop")
    manifest_path = directory / "scan-manifest.json"
    legacy = json.loads(manifest_path.read_text())
    legacy["scan"]["status"] = "completed"
    legacy["scan"].pop("preservedSources", None)
    manifest_path.write_text(json.dumps(legacy))
    for name in ("checkpoints", "checkpoint-heads"):
        shutil.rmtree(directory / name, ignore_errors=True)
    original = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    saved = workbench_api["saved_results"]

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic legacy publication failure")

    with closing(workbench_api["connect"]()) as connection:
        with connection:
            connection.execute(
                "UPDATE scans SET seal_manifest_digest = NULL, retained_source_digests_json = NULL WHERE id = ?",
                (scan["scanId"],),
            )
        with monkeypatch.context() as patch:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
            with pytest.raises(OSError, match="Synthetic legacy publication failure"):
                saved.preserve_scan_results_locked(
                    workbench_api["_WORKBENCH_DB_CONTEXT"], connection, scan["scanId"]
                )
        assert {name: (directory / name).read_bytes() for name in original} == original
        assert saved.preserve_scan_results_locked(
            workbench_api["_WORKBENCH_DB_CONTEXT"], connection, scan["scanId"]
        )
        row = workbench_api["require_scan"](connection, scan["scanId"])
        frozen = json.loads(row["retained_source_digests_json"])
        assert frozen
        for relative, digest in frozen.items():
            assert hashlib.sha256((directory / relative).read_bytes()).hexdigest() == digest
    manifest = json.loads(manifest_path.read_text())["scan"]
    assert manifest["status"] == "failed"
    assert manifest["preservedSources"] == frozen
    assert len(json.loads((directory / "findings.json").read_text())["findings"]) == 1
