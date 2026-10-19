from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import write_saved_parent
from workbench_test_support import (
    replay_saved_results,
    run_workbench,
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_saved_results as saved


@pytest.mark.parametrize("layout", ["parent", "worker"])
def test_recovery_retains_reviewed_files_across_checkpoints(tmp_path: Path, layout: str) -> None:
    scan_id = "reviewed-files"
    output = tmp_path if layout == "parent" else tmp_path / "worker" / "output"
    binding = saved_binding("repository" if layout == "parent" else "deep_repository")
    workers = [] if layout == "parent" else [saved_discovery_worker(output)]
    for paths in (["./src/a.ts"], ["src/b.ts", "src/a.ts"], []):
        draft = saved_draft(scan_id)
        draft["coverage"]["reviewedFiles"] = paths
        write_checkpoint(output / "checkpoints", draft)
    latest = saved_draft(scan_id)
    if layout == "parent":
        write_saved_parent(output, latest, 500)
    else:
        (output / "result.json").write_text(json.dumps(latest))
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    assert first[2]["reviewedFiles"] == ["src/a.ts", "src/b.ts"]
    replay = replay_saved_results(saved, first, tmp_path, scan_id, binding, workers, stopped=True)
    assert replay[2]["reviewedFiles"] == first[2]["reviewedFiles"]


@pytest.mark.parametrize("files", [None, []])
def test_recovery_preserves_unknown_and_empty_accounting(tmp_path: Path, files) -> None:
    scan_id = "reviewed-files"
    draft = saved_draft(scan_id)
    if files is not None:
        draft["coverage"]["reviewedFiles"] = files
    write_checkpoint(tmp_path / "checkpoints", draft)
    result = saved.merge_saved_results(
        tmp_path, scan_id, saved_binding(), [], [], stopped=True, reason="interrupted"
    )
    assert ("reviewedFiles" in result[2]) is (files is not None)
    if files is not None:
        assert result[2]["reviewedFiles"] == files


@pytest.mark.parametrize("unknown", ["absent_field", "missing", "malformed", "empty_coverage"])
def test_recovery_does_not_present_partial_worker_accounting_as_complete(
    tmp_path: Path, unknown: str
) -> None:
    scan_id = "reviewed-files"
    workers = []
    for name, files in (("known", ["src/a.ts"]), ("unknown", None)):
        output = tmp_path / name / "output"
        output.mkdir(parents=True)
        workers.append(saved_discovery_worker(output, name))
        draft = saved_draft(scan_id)
        if files is not None:
            draft["coverage"]["reviewedFiles"] = files
        elif unknown == "missing":
            continue
        elif unknown == "malformed":
            (output / "result.json").write_text("{broken")
            continue
        elif unknown == "empty_coverage":
            draft["coverage"] = {}
        write_checkpoint(output / "checkpoints", draft)
    result = saved.merge_saved_results(
        tmp_path,
        scan_id,
        saved_binding("deep_repository"),
        workers,
        [],
        stopped=True,
        reason="stopped",
    )
    assert "reviewedFiles" not in result[2]


def test_recovery_ignores_reducers_when_accounting_for_workers(tmp_path: Path) -> None:
    output = tmp_path / "worker" / "output"
    draft = saved_draft("reviewed-files")
    draft["coverage"]["reviewedFiles"] = ["src/a.ts"]
    write_checkpoint(output / "checkpoints", draft)
    reducer = {
        **saved_discovery_worker(tmp_path / "reducer", "reducer"),
        "kind": "dedup",
        "status": "failed",
    }
    result = saved.merge_saved_results(
        tmp_path,
        "reviewed-files",
        saved_binding("deep_repository"),
        [saved_discovery_worker(output), reducer],
        [],
        stopped=True,
        reason="stopped",
    )
    assert result[2]["reviewedFiles"] == ["src/a.ts"]


@pytest.mark.parametrize("operation", ["complete-scan", "cancel-scan"])
@pytest.mark.parametrize("extra_path", [None, "outside.ts", "src/missing.ts"])
def test_file_authored_accounting_uses_registered_scope_and_inventory(
    tmp_path: Path, operation: str, extra_path: str | None
) -> None:
    target, scan, state = tmp_path / "repo", tmp_path / "scan", tmp_path / "state"
    (target / "src").mkdir(parents=True)
    (target / "src/a.ts").write_text("export const a = 1\n")
    (target / "outside.ts").write_text("export const outside = 1\n")
    scan.mkdir(mode=0o700)
    registered = run_workbench(
        state,
        "register-cli-scan",
        "--scan-dir",
        str(scan),
        "--repository",
        str(target),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(target),
                "target": {"kind": "paths", "paths": ["src"]},
            }
        ),
    )
    scan_id = registered["scanId"]
    write_completed_contract(
        scan,
        scan_id,
        target,
        relative_path="src/a.ts",
        include_paths=["src"],
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    coverage_path = scan / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["reviewedFiles"] = ["./src/a.ts", "src/a.ts"]
    if extra_path is not None:
        coverage["reviewedFiles"].append(extra_path)
    coverage_path.write_text(json.dumps(coverage))
    run_workbench(state, operation, "--scan-id", scan_id)

    coverage = json.loads(coverage_path.read_text())
    if extra_path is None:
        assert coverage["reviewedFiles"] == ["src/a.ts"]
    else:
        assert "reviewedFiles" not in coverage
    assert len(json.loads((scan / "findings.json").read_text())["findings"]) == 1
    manifest = json.loads((scan / "scan-manifest.json").read_text())
    assert "sealedAt" in manifest["scan"]
    assert manifest["scan"]["status"] == (
        "completed" if operation == "complete-scan" else "canceled"
    )


@pytest.mark.parametrize("mode", ["commit", "branch_diff", "working_tree"])
def test_recovered_diff_accounting_uses_selected_changes(tmp_path: Path, mode: str) -> None:
    target = tmp_path / "repo"
    target.mkdir()

    def git(*args: str) -> str:
        return subprocess.check_output(["git", "-C", str(target), *args], text=True).strip()

    git("init", "--quiet")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.com")
    (target / "deleted.ts").write_text("export const deleted = 1\n")
    (target / "unchanged.ts").write_text("export const unchanged = 1\n")
    git("add", ".")
    git("commit", "--quiet", "-m", "base")
    base = git("rev-parse", "HEAD")
    (target / "deleted.ts").unlink()
    if mode != "working_tree":
        git("add", ".")
        git("commit", "--quiet", "-m", "delete file")
    binding = saved_binding(mode)
    binding["target"].update(baseRevision=base, headRevision=git("rev-parse", "HEAD"))
    for path in ["deleted.ts", "unchanged.ts"]:
        scan = tmp_path / path
        draft = saved_draft("reviewed-files")
        draft["coverage"]["reviewedFiles"] = [path]
        write_checkpoint(scan / "checkpoints", draft)
        warnings = []
        result = saved.merge_saved_results(
            scan,
            "reviewed-files",
            binding,
            [],
            warnings,
            stopped=True,
            reason="stopped",
            source_root=target,
        )
        if path == "deleted.ts":
            assert result[2]["reviewedFiles"] == [path]
        else:
            assert "reviewedFiles" not in result[2]
            assert any("not in the source inventory" in warning for warning in warnings)


@pytest.mark.parametrize("mode", ["deep_repository", "scoped_path"])
def test_successful_deep_parent_does_not_gain_unaccepted_worker_claims(
    tmp_path: Path, mode: str
) -> None:
    scan_id = "reviewed-files"
    parent = saved_draft(scan_id, complete=True)
    parent["coverage"]["reviewedFiles"] = ["src/accepted.ts"]
    write_saved_parent(tmp_path, parent, 500)
    output = tmp_path / "worker" / "output"
    worker = saved_draft(scan_id)
    worker["coverage"]["reviewedFiles"] = ["src/unfinished.ts"]
    write_checkpoint(output / "checkpoints", worker)
    result = saved.merge_saved_results(
        tmp_path,
        scan_id,
        saved_binding(mode),
        [saved_discovery_worker(output)],
        [],
        stopped=False,
        reason="",
    )
    assert result[2]["reviewedFiles"] == ["src/accepted.ts"]
