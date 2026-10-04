from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from unittest import mock

import pytest
from workbench_test_support import (
    SCRIPT,
    checkpoint,
    recipe,
    register,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)

CHECKPOINT = "artifacts/deep-scan/checkpoint.json"


def _scan_workspace(tmp_path: Path, source: str = "print('fixture')\n") -> tuple[Path, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text(source)
    return tmp_path / "state", target


@pytest.mark.parametrize("name", ["current", "legacy"])
def test_checkpoint_reads_shared_sdk_fixtures(tmp_path, workbench_api, monkeypatch, name):
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    fixture = Path(__file__).parent / "fixtures/composition-checkpoints" / f"{name}.json"
    original = json.loads(fixture.read_text())
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=fixture.read_text(),
    )
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    stored = {"id": scan["scanId"], "scan_dir": scan["scanDir"]}
    loaded = workbench_api["load_composition"].__globals__["read_composition_checkpoint"](stored)
    assert loaded == original
    encoded = json.dumps(
        loaded, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()
    assert json.loads(encoded) == original
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=encoded.decode(),
    )
    assert (
        workbench_api["load_composition"].__globals__["read_composition_checkpoint"](stored)
        == original
    )


def test_checkpoint_read_blocks_other_threads_and_atomic_writers(
    tmp_path: Path, workbench_api, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan", mode="deep")
    original = checkpoint(state, scan)
    updated = {**original, "noNewStreak": 1}
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    read_checkpoint = workbench_api["load_composition"].__globals__["read_composition_checkpoint"]
    reading, release_read, thread_waiting, thread_acquired = (Event() for _ in range(4))

    def paused_read(scan_dir: Path, relative: str, context: str) -> dict:
        descriptor = workbench_api["open_scan_local_file_descriptor"](scan_dir, relative, context)
        with os.fdopen(descriptor, "rb") as source:
            reading.set()
            assert release_read.wait(10)
            return json.load(source)

    def competing_thread() -> None:
        thread_waiting.set()
        with workbench_api["scan_completion_lock"](scan["scanId"]):
            thread_acquired.set()

    writer_script = """
import runpy, sys
sys.path.insert(0, sys.argv[1])
from workbench import storage
acquire = storage.acquire_completion_file_lock
def announce_acquire(descriptor):
    print("waiting", flush=True)
    acquire(descriptor)
storage.acquire_completion_file_lock = announce_acquire
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
"""
    with (
        mock.patch.dict(read_checkpoint.__globals__, _read_scan_local_json=paused_read),
        ThreadPoolExecutor(max_workers=3) as executor,
    ):
        reader = executor.submit(
            read_checkpoint, {"id": scan["scanId"], "scan_dir": scan["scanDir"]}
        )
        writer = None
        try:
            assert reading.wait(5)
            contender = executor.submit(competing_thread)
            assert thread_waiting.wait(5)
            assert not thread_acquired.wait(0.1)
            writer = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    writer_script,
                    str(SCRIPT.parent),
                    str(SCRIPT),
                    "save-scan-artifact",
                    "--scan-id",
                    scan["scanId"],
                    "--artifact-path",
                    CHECKPOINT,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            writer.stdin.write(json.dumps(updated))
            writer.stdin.close()
            writer.stdin = None
            assert executor.submit(writer.stdout.readline).result(timeout=5).strip() == "waiting"
            with pytest.raises(subprocess.TimeoutExpired):
                writer.wait(timeout=0.1)
            assert json.loads((Path(scan["scanDir"]) / CHECKPOINT).read_text()) == original
        finally:
            release_read.set()
            if writer is not None:
                try:
                    stdout, stderr = writer.communicate(timeout=10)
                finally:
                    if writer.poll() is None:
                        writer.kill()
                        writer.communicate()
        assert reader.result(timeout=5) == original
        contender.result(timeout=5)
        assert writer.returncode == 0, stderr
        assert json.loads(stdout)["scanId"] == scan["scanId"]
    assert json.loads((Path(scan["scanDir"]) / CHECKPOINT).read_text()) == updated


@pytest.mark.parametrize("missing", ["checkpoint", "output"])
def test_history_hides_composition_children_without_parent_artifacts(
    tmp_path: Path, missing: str
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent_dir = tmp_path / "scan"
    parent = register(state, target, parent_dir, mode="deep")
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, parent_dir / child_path, parent=parent["scanId"], role="deep_pass"
    )
    checkpoint(state, parent, passes=[{"directory": child_path, "scanId": child["scanId"]}])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for day, scan in enumerate((parent, rerun, child), 1):
            connection.execute(
                "UPDATE scans SET started_at = ? WHERE id = ?",
                (f"2026-01-0{day}T00:00:00Z", scan["scanId"]),
            )
    for scan in (rerun, child):
        write_completed_contract(
            Path(scan["scanDir"]), scan["scanId"], target, relative_path="app.py"
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    if missing == "checkpoint":
        (parent_dir / CHECKPOINT).unlink()
    else:
        parent_dir.rename(tmp_path / "removed-output")

    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        rerun["scanId"],
    }
    assert (
        run_workbench(state, "list-scans", "--status", "complete", "--limit", "1")["scans"][0][
            "scanId"
        ]
        == rerun["scanId"]
    )
    indexed = run_workbench(state, "list-global-findings")["findings"]
    assert len(indexed) == 1
    assert indexed[0]["scanId"] == rerun["scanId"]
    assert indexed[0]["occurrenceCount"] == 1
    assert indexed[0]["knownScanIds"] == [rerun["scanId"]]
    visible = run_workbench(state, "get-scan", "--scan-id", rerun["scanId"])["scan"]
    assert "knownScanIds" not in visible["findings"][0]
    assert "matches" not in visible["findings"][0]
    repository = run_workbench(state, "list-repositories")["repositories"][0]
    assert repository["scanCount"] == 2
    assert repository["latestScan"]["scanId"] == rerun["scanId"]
    explicit = run_workbench(state, "list-scans", "--scan-root", child["scanDir"])["scans"]
    assert [scan["scanId"] for scan in explicit] == [child["scanId"]]
    assert (
        run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["findingCount"] == 1
    )


def test_archive_rejects_a_running_child_of_a_stopped_parent(tmp_path: Path) -> None:
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_dir = directory / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET status = 'failed' WHERE id = ?", (parent["scanId"],))
    archived = tmp_path / "scan.previous-test"
    directory.rename(archived)
    directory.mkdir(mode=0o700)
    response = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe(target, "deep")),
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
        check=False,
    )
    assert response["returncode"] != 0
    assert "child scan is running" in response["stderr"]
    saved = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]
    assert saved["scanDir"] == str(child_dir)
    assert saved["progress"]["status"] == "running"


def test_archiving_composition_preserves_children_and_reuses_pass_directories(
    tmp_path: Path,
) -> None:
    state, target = _scan_workspace(tmp_path)
    directory = tmp_path / "scan"
    parent = register(state, target, directory, mode="deep")
    child_path = "artifacts/deep-scan/passes/pass-1"
    child = register(
        state, target, directory / child_path, parent=parent["scanId"], role="deep_pass"
    )
    checkpoint(state, parent, passes=[{"directory": child_path}])
    unrelated = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    for scan in (child, unrelated):
        write_completed_contract(
            Path(scan["scanDir"]),
            scan["scanId"],
            target,
            relative_path="app.py",
            identity_anchor=scan["scanId"],
        )
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption."
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        old_scans = {row["id"]: dict(row) for row in connection.execute("SELECT * FROM scans")}
        old_artifacts = [dict(row) for row in connection.execute("SELECT * FROM scan_artifacts")]
        old_findings = connection.execute("SELECT * FROM finding_occurrences").fetchall()
    child_manifest = (directory / child_path / "scan-manifest.json").read_bytes()
    archived = tmp_path / "scan.previous-test"
    directory.rename(archived)
    directory.mkdir(mode=0o700)
    current = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--recipe-json",
        json.dumps(recipe(target, "deep")),
        "--archive-existing",
        "--archived-scan-dir",
        str(archived),
    )

    archived_child = run_workbench(state, "get-scan", "--scan-id", child["scanId"])
    assert archived_child["scan"]["scanDir"] == str(archived / child_path)
    assert archived_child["scan"]["findingCount"] == 1
    assert (archived / child_path / "scan-manifest.json").read_bytes() == child_manifest
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])
    assert "compositionCheckpoint" not in context
    assert context["scan"]["progress"]["independentReviews"]["completed"] == 1
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        current["scanId"],
        unrelated["scanId"],
    }
    assert {
        finding["scanId"] for finding in run_workbench(state, "list-global-findings")["findings"]
    } == {parent["scanId"], unrelated["scanId"]}
    assert run_workbench(state, "list-repositories")["repositories"][0]["scanCount"] == 3
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        for scan_id, old in old_scans.items():
            if scan_id != unrelated["scanId"]:
                old["scan_dir"] = str(archived / Path(old["scan_dir"]).relative_to(directory))
                old.pop("updated_at")
            actual = dict(
                connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            )
            assert {key: actual[key] for key in old} == old
        for artifact in old_artifacts:
            if artifact["scan_id"] != unrelated["scanId"]:
                artifact["path"] = str(archived / Path(artifact["path"]).relative_to(directory))
            actual = connection.execute(
                "SELECT * FROM scan_artifacts WHERE scan_id = ? AND kind = ?",
                (artifact["scan_id"], artifact["kind"]),
            ).fetchone()
            assert dict(actual) == artifact
            assert Path(actual["path"]).is_file()
        assert connection.execute("SELECT * FROM finding_occurrences").fetchall() == old_findings
    replacement = register(
        state, target, directory / child_path, parent=current["scanId"], role="deep_pass"
    )
    assert replacement["scanId"] != child["scanId"]
    assert replacement["scanDir"] == str(directory / child_path)


@pytest.mark.parametrize("legacy_reviews,saved_maximum_only", [(0, False), (3, False), (3, True)])
@pytest.mark.parametrize("with_child", [False, True])
def test_get_scan_counts_saved_reviews_without_reading_composition_checkpoint(
    tmp_path: Path,
    workbench_api,
    monkeypatch,
    legacy_reviews: int,
    with_child: bool,
    saved_maximum_only: bool,
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    if with_child:
        child = register(
            state,
            target,
            tmp_path / "parent/artifacts/deep-scan/passes/pass-1",
            parent=parent["scanId"],
            role="deep_pass",
        )
        write_completed_contract(
            Path(child["scanDir"]), child["scanId"], target, relative_path="app.py"
        )
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    value = checkpoint(state, parent, passes=[{"directory": "artifacts/deep-scan/passes/pass-1"}])
    if legacy_reviews:
        value["legacy"] = {"discoveryRuns": legacy_reviews, "coverage": {"completeness": "partial"}}
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, "
                "phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
                "completion_sequence, created_at, updated_at) "
                "SELECT id, 1, 'synthetic-legacy', 'succeeded', 'terminal', 1, 0, 3, 8, ?, "
                "started_at, updated_at FROM scans WHERE id = ?",
                (legacy_reviews, parent["scanId"]),
            )
    if saved_maximum_only:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET recipe_json = json_remove(recipe_json, '$.deepScan') WHERE id = ?",
                (parent["scanId"],),
            )
    path = Path(parent["scanDir"]) / CHECKPOINT
    path.write_text(json.dumps(value))
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    load = workbench_api["load_composition"]
    reader = load.__globals__["read_composition_checkpoint"]
    with mock.patch.dict(load.__globals__, read_composition_checkpoint=mock.Mock(wraps=reader)):
        with workbench_api["connect"]() as connection:
            context = workbench_api["scan_context"](connection, parent["scanId"])
        load.__globals__["read_composition_checkpoint"].assert_not_called()
    assert context["scan"]["progress"]["independentReviews"] == {
        "active": 0,
        "completed": legacy_reviews + int(with_child),
        "maximum": 8,
        "consolidating": False,
    }
    assert "compositionCheckpoint" not in context
    assert json.loads(path.read_text()) == value
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"]
    }


def test_failed_deep_scan_keeps_followup_thread_before_composition_checkpoint(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic failure."
    )
    for thread_id in ["failed-follow-up", "repeated-follow-up"]:
        run_workbench(
            state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", thread_id
        )
    context = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])
    assert "compositionCheckpoint" not in context
    assert context["scan"]["continuationThreadId"] is None
    assert context["scan"]["progress"]["status"] == "failed"
    assert context["scan"]["threadIds"] == ["failed-follow-up", "repeated-follow-up"]
    assert context["scan"]["executionThreadIds"] == context["scan"]["threadIds"]


def test_stopped_standard_does_not_rebind_another_scans_coverage(tmp_path: Path) -> None:
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    scan = register(state, target, tmp_path / "scan")
    directory = Path(scan["scanDir"])
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    coverage = json.loads((directory / "coverage.json").read_text())
    coverage["scanId"] = "00000000-0000-4000-8000-000000000000"
    raw = json.dumps(coverage).encode()
    (directory / "coverage.json").write_bytes(raw)
    for name in ("scan-manifest.json", "findings.json", "report.md"):
        (directory / name).unlink()
    run_workbench(state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Interrupted.")
    assert (directory / "coverage.json").read_bytes() == raw
    assert not (directory / "scan-manifest.json").exists()
    assert not (directory / "findings.json").exists()
    assert not list((directory / "checkpoints").glob("*.json"))
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findingCount"] == 0
    )


@pytest.mark.parametrize("accepted_membership", ["merged", "represented"])
def test_native_cancel_retains_accepted_and_later_unmerged_findings(
    tmp_path: Path, accepted_membership: str
) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index, anchor in enumerate(("accepted-finding", "separate-unmerged-finding"), 1):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        write_completed_contract(
            directory, child["scanId"], target, relative_path="app.py", identity_anchor=anchor
        )
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        protected = {
            name: (directory / name).read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json")
        }
        children.append((child, directory, protected))
    first, _, first_bytes = children[0]
    original = json.loads(first_bytes["findings.json"])["findings"][0]
    accepted = copy.deepcopy(original)
    accepted["provenance"]["sourceFindingIds"] = [f"{first['scanId']}:0"]
    accepted["provenance"]["sourceFindings"] = [{"id": f"{first['scanId']}:0", "finding": original}]
    saved = checkpoint(
        state,
        parent,
        passes=[
            {"directory": directory.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
            for child, directory, _ in children
        ],
        merged=[first["scanId"]] if accepted_membership == "merged" else [],
    )
    saved["noNewStreak"] = 2
    saved["aggregate"] = {
        "scanId": parent["scanId"],
        "findings": [accepted],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [{"reason": "Accepted pass still needs dependency review."}],
        },
    }
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        parent["scanId"],
        "--artifact-path",
        CHECKPOINT,
        input_text=json.dumps(saved),
    )
    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])
    context = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert context["progress"]["status"] == "canceled"
    assert context["findingCount"] == 2
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
    preserved = next(finding for finding in retained if finding["identity"] == accepted["identity"])
    assert preserved["findingId"] == accepted["findingId"]
    assert preserved["provenance"]["sourceFindings"] == accepted["provenance"]["sourceFindings"]
    later, _, later_bytes = children[1]
    recovered = next(
        finding
        for finding in retained
        if finding["provenance"]["sourceFindingIds"] == [f"{later['scanId']}:0"]
    )
    assert recovered["identity"]["anchor"] == "separate-unmerged-finding"
    assert (
        recovered["provenance"]["sourceFindings"][0]["finding"]
        == json.loads(later_bytes["findings.json"])["findings"][0]
    )
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert any(row["reason"].startswith("Accepted pass still") for row in coverage["deferred"])
    assert any("artifacts/deep-scan/passes/pass-2" in row["reason"] for row in coverage["deferred"])
    for child, directory, protected in children:
        for name, contents in protected.items():
            assert (directory / name).read_bytes() == contents
        assert (
            run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["progress"][
                "status"
            ]
            == "complete"
        )
    assert json.loads((parent_dir / CHECKPOINT).read_text()) == saved


def test_composed_recovery_records_child_failure_and_continues(workbench_api, monkeypatch) -> None:
    saved = workbench_api["saved_results"]
    root = Path("/synthetic-scan")
    children = [
        {"id": "broken", "scan_dir": str(root / "broken")},
        {"id": "retained", "scan_dir": str(root / "retained")},
    ]
    composition = workbench_api["load_composition"].__globals__["CompositionView"](
        None, tuple(children), (), None
    )
    db = mock.Mock(
        require_scan=lambda _, child_id: next(
            child for child in children if child["id"] == child_id
        )
    )
    monkeypatch.setattr(saved, "save_pending_checkpoint", lambda *_: None)
    retained_coverage = {"surfaces": [{"id": "retained/surface", "summary": "Saved work"}]}
    with mock.patch.object(
        saved,
        "_stopped_child_draft",
        side_effect=[
            ValueError("Synthetic malformed artifact"),
            {"findings": [], "coverage": retained_coverage},
        ],
    ):
        result = saved.save_composed_checkpoint(
            db, None, {"id": "parent", "scan_dir": str(root)}, root, composition
        )
    assert result["coverage"]["surfaces"] == retained_coverage["surfaces"]
    assert result["coverage"]["deferred"][0] == {
        "id": "unmerged-broken",
        "reason": "Independent scan did not complete and merge. Saved work: broken. "
        "Recovery failed: Synthetic malformed artifact",
    }
    assert result["complete"] is False


@pytest.mark.parametrize("alias", ["exact", "case", "directory"])
def test_stopped_projection_retains_report_and_colliding_evidence(tmp_path: Path, alias: str):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    state = tmp_path / "state"
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    findings_path = child_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    document["findings"][0]["writeup"] = {"reportPath": "findings/issue/issue.md"}
    findings_path.write_text(json.dumps(document))
    reports = child_dir / "findings/issue"
    reports.mkdir(parents=True)
    report = reports / "issue.md"
    report.write_text("# Original report\n")
    name = f"{child['scanId']}-issue.md"
    evidence = reports / (name.upper() if alias == "case" else name)
    if alias == "directory":
        evidence.mkdir()
        evidence = evidence / "trace.txt"
    evidence.write_text("Synthetic supporting evidence\n")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
    )
    run_workbench(state, "cancel-scan", "--scan-id", parent["scanId"])
    saved = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert saved["progress"]["status"] == "canceled"
    assert not any(
        "conflicts with its projected report" in warning for warning in saved.get("warnings", [])
    )
    assert not (parent_dir / "findings").exists()
    parent_findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
    assert parent_findings[0]["writeup"]["reportPath"] == report.relative_to(parent_dir).as_posix()
    assert report.read_text() == "# Original report\n"
    assert evidence.read_text() == "Synthetic supporting evidence\n"


@pytest.mark.parametrize("child_state", ["complete", "checkpoint"])
@pytest.mark.parametrize("stop_command", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize("candidate_location", ["provenance", "extensions"])
def test_parent_stop_keeps_child_candidates_separate(
    tmp_path: Path, child_state: str, stop_command: str, candidate_location: str
) -> None:
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        write_completed_contract(
            directory,
            child["scanId"],
            target,
            relative_path="app.py",
            identity_anchor=f"child-{index}",
        )
        findings = json.loads((directory / "findings.json").read_text())["findings"]
        findings[0].setdefault(candidate_location, {})["candidateId"] = "shared-candidate"
        (directory / "findings.json").write_text(json.dumps({"findings": findings}))
        if child_state == "complete":
            run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        else:
            write_checkpoint(
                directory / "checkpoints",
                {
                    "scanId": child["scanId"],
                    "findings": findings,
                    "coverage": json.loads((directory / "coverage.json").read_text()),
                    "complete": False,
                },
            )
            for name in ("scan-manifest.json", "findings.json", "coverage.json"):
                (directory / name).unlink()
        children.append(child)
    write_completed_contract(
        parent_dir,
        parent["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    (parent_dir / "findings.json").write_text(json.dumps({"findings": []}))
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    coverage["completeness"] = "partial"
    coverage["surfaces"] = [
        {
            "id": "parent-decision",
            "label": "Parent candidate",
            "disposition": "rejected",
            "candidateId": "shared-candidate",
        }
    ]
    (parent_dir / "coverage.json").write_text(json.dumps(coverage))
    manifest = json.loads((parent_dir / "scan-manifest.json").read_text())
    manifest["scan"]["complete"] = False
    (parent_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    checkpoint(
        state,
        parent,
        passes=[
            {
                "directory": Path(child["scanDir"]).relative_to(parent_dir).as_posix(),
                "scanId": child["scanId"],
            }
            for child in children
        ],
    )
    extra = ("--message", "Synthetic scan stopped.") if stop_command == "fail-scan" else ()
    run_workbench(state, stop_command, "--scan-id", parent["scanId"], *extra)
    assert "| Reportable DSS findings | 2 |" in (parent_dir / "report.md").read_text()
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
    assert len(retained) == 2
    for child in children:
        status = run_workbench(state, "get-scan", "--scan-id", child["scanId"])["scan"]["progress"][
            "status"
        ]
        assert status == ("complete" if child_state == "complete" else "failed")
        finding = next(
            item
            for item in retained
            if item["provenance"]["sourceFindingIds"] == [f"{child['scanId']}:0"]
        )
        assert finding["provenance"]["candidateId"].startswith(child["scanId"] + ":")
        original = finding["provenance"]["sourceFindings"][0]["finding"]
        assert original[candidate_location]["candidateId"] == "shared-candidate"


def test_standard_resume_retains_registration_before_and_after_thread_binding(
    tmp_path: Path,
) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan")
    resume = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resume["scanId"] == scan["scanId"]
    assert resume["threadId"] is None
    assert resume["recipe"] == recipe(target)
    run_workbench(state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "execution")
    resume = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resume["threadId"] == "execution"
    assert len(run_workbench(state, "list-scans")["scans"]) == 1
    (target / "app.py").write_text("print('changed')\n")
    rejected = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False)
    assert "original checkout revision or contents changed" in rejected["stderr"]


@pytest.mark.parametrize("compact", [False, True])
def test_resume_distinguishes_empty_artifact_drafts_from_sealed_results(
    tmp_path: Path, compact: bool
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    state, directory = tmp_path / "state", tmp_path / "scan"
    scan = register(state, target, directory)
    run_workbench(state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "execution")
    path = directory / "scan-manifest.json"
    path.write_text(json.dumps({"scan": {"artifacts": []}}))
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert "sealedProducerVersion" not in resumed
    assert not (directory / "findings.json").exists()

    write_completed_contract(directory, scan["scanId"], target)
    manifest = json.loads(path.read_text())
    manifest["scan"]["artifacts"] = []
    if compact:
        del manifest["scan"]["producer"]
    path.write_text(json.dumps(manifest))
    draft = path.read_bytes()

    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert "sealedProducerVersion" not in resumed
    assert path.read_bytes() == draft

    run_workbench(state, "prepare-scan-completion", "--scan-id", scan["scanId"])
    sealed = path.read_bytes()
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resumed["sealedProducerVersion"] == json.loads(sealed)["scan"]["producer"]["version"]
    assert path.read_bytes() == sealed


@pytest.mark.parametrize("scope", ["src/app.py", "src"])
def test_sealed_scoped_resume_retains_deleted_source(tmp_path: Path, scope: str) -> None:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    source = target / "src/app.py"
    source.write_text("\n" * 50)
    state, directory = tmp_path / "state", tmp_path / "scan"
    scan = register(state, target, directory, paths=[scope])
    write_completed_contract(
        directory,
        scan["scanId"],
        target,
        relative_path="src/app.py",
        include_paths=[scope],
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    source.unlink()
    unavailable = run_workbench(
        state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False
    )
    assert "revision or contents changed" in unavailable["stderr"]
    source.write_text("\n" * 50)
    run_workbench(state, "prepare-scan-completion", "--scan-id", scan["scanId"])
    artifacts = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    source.unlink()
    if scope == "src":
        (target / "src").rmdir()
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
    assert resumed["sealedProducerVersion"]
    assert resumed["recipe"]["target"] == {"kind": "paths", "paths": [scope]}
    run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    assert {name: (directory / name).read_bytes() for name in artifacts} == artifacts


@pytest.mark.parametrize("action", ["fail-scan", "cancel-scan"])
def test_stopped_standard_cannot_resume_and_preserves_checkpoint(
    tmp_path: Path, action: str
) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan")
    write_completed_contract(Path(scan["scanDir"]), scan["scanId"], target, relative_path="app.py")
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "synthetic interruption") if action == "fail-scan" else ()),
    )
    before = (Path(scan["scanDir"]) / "scan-manifest.json").read_bytes()
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False)
    assert "completed, failed, and canceled scans cannot resume" in resumed["stderr"]
    assert (Path(scan["scanDir"]) / "scan-manifest.json").read_bytes() == before
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findingCount"] == 1
    )


def test_running_pass_retains_paid_receipt_before_resume_and_failure(tmp_path: Path) -> None:
    state, target = _scan_workspace(tmp_path)
    scan = register(state, target, tmp_path / "scan")
    run_workbench(state, "set-scan-thread", "--scan-id", scan["scanId"], "--thread-id", "paid-pass")
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    receipt = run_workbench(
        state, "preserve-scan-results", "--scan-id", scan["scanId"], "--cost-json", json.dumps(cost)
    )["scan"]
    assert receipt["progress"]["status"] == "running"
    assert receipt["cost"] == cost
    assert (
        run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])["threadId"]
        == "paid-pass"
    )
    assert (
        run_workbench(state, "list-scans", "--scan-root", scan["scanDir"])["scans"][0]["cost"]
        == cost
    )
    run_workbench(state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Retry exhausted.")
    assert run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["cost"] == cost


@pytest.mark.parametrize("missing_outputs", [False, True])
@pytest.mark.parametrize("already_applied", [False, True])
def test_membership_migration_backfills_stored_paths_once(
    tmp_path: Path, missing_outputs: bool, already_applied: bool
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    parent_dir = tmp_path / "parent.previous-synthetic"
    parent = register(state, target, parent_dir, mode="deep")
    child = register(
        state, target, parent_dir / "artifacts/deep-scan/passes/pass-1", parent=parent["scanId"]
    )
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    database = state / "workbench.sqlite3"
    marker = parent_dir / "saved-output.txt"
    marker.write_bytes(b"Saved outputs must not change during migration.")
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM schema_migrations WHERE version = 48")
        if already_applied:
            connection.execute("UPDATE scans SET parent_scan_role = NULL")
        else:
            connection.execute("DROP INDEX scans_by_composition_parent")
            connection.execute("ALTER TABLE scans DROP COLUMN parent_scan_role")
            connection.execute("DELETE FROM schema_migrations WHERE version = 43")
        before = connection.execute(
            "SELECT id, parent_scan_id, scan_dir, status FROM scans ORDER BY id"
        ).fetchall()
    if missing_outputs:
        parent_dir.rename(tmp_path / "removed-output")
    run_workbench(state, "database-info")
    run_workbench(state, "database-info")
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT id, parent_scan_id, scan_dir, status FROM scans ORDER BY id"
            ).fetchall()
            == before
        )
        assert dict(connection.execute("SELECT id, parent_scan_role FROM scans")) == {
            parent["scanId"]: None,
            child["scanId"]: "deep_pass",
            rerun["scanId"]: None,
        }
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version = 43"
        ).fetchone() == (1,)
    saved_marker = tmp_path / "removed-output/saved-output.txt" if missing_outputs else marker
    assert saved_marker.read_bytes() == b"Saved outputs must not change during migration."
    assert {scan["scanId"] for scan in run_workbench(state, "list-scans")["scans"]} == {
        parent["scanId"],
        rerun["scanId"],
    }


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
def test_stopped_parent_rejects_late_pass_registration(tmp_path: Path, action: str) -> None:
    state, target = _scan_workspace(tmp_path)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    run_workbench(
        state,
        action,
        "--scan-id",
        parent["scanId"],
        *(("--message", "Synthetic failure") if action == "fail-scan" else ()),
    )
    with pytest.raises(subprocess.CalledProcessError) as error:
        register(
            state,
            target,
            tmp_path / "parent/artifacts/deep-scan/passes/pass-1",
            parent=parent["scanId"],
            role="deep_pass",
        )
    assert "requires a running parent" in error.value.stderr
    # An ordinary rerun remains independent of the parent's terminal status.
    rerun = register(state, target, tmp_path / "rerun", parent=parent["scanId"])
    assert rerun["scanId"] != parent["scanId"]


def test_child_completion_during_parent_stop_does_not_interrupt_publication(
    workbench_api, monkeypatch
) -> None:
    from contextlib import nullcontext
    from types import SimpleNamespace

    saved = workbench_api["saved_results"]
    child = {"id": "child", "status": "running", "handoff_claim_token": "claim"}
    composition = SimpleNamespace(checkpoint=None, children=[child])
    db = SimpleNamespace(
        scan_completion_lock=lambda _: nullcontext(),
        require_scan=lambda *_: {**child, "status": "complete"},
    )
    called = []
    monkeypatch.setattr(saved, "fail_scan", lambda *args: called.append(args))
    monkeypatch.setattr(saved, "fail_scan_locked", lambda *args: called.append(args))
    saved.stop_composition_children(db, None, composition)
    assert not called


@pytest.mark.parametrize(
    ("accepted", "failure"), [(False, "checkpoint"), (True, "checkpoint"), (False, "projection")]
)
def test_explicit_recovery_materializes_unfrozen_composition_after_checkpoint_failure(
    tmp_path: Path, workbench_api, accepted: bool, failure: str
) -> None:
    state, target = _scan_workspace(tmp_path, "\n" * 50)
    parent = register(state, target, tmp_path / "scan", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    findings = json.loads((child_dir / "findings.json").read_text())
    findings["findings"][0]["writeup"] = {"reportPath": "findings/proof/proof.md"}
    (child_dir / "findings.json").write_text(json.dumps(findings))
    report_dir = child_dir / "findings/proof"
    report_dir.mkdir(parents=True)
    (report_dir / "proof.md").write_text("# Retained observation\n[Trace](trace.txt)\n")
    (report_dir / "trace.txt").write_text("Synthetic supporting evidence\n")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    child_bytes = {name: (child_dir / name).read_bytes() for name in names}
    saved = checkpoint(
        state,
        parent,
        passes=[
            {"directory": child_dir.relative_to(parent_dir).as_posix(), "scanId": child["scanId"]}
        ],
        merged=[child["scanId"]] if accepted else [],
    )
    if accepted:
        saved["aggregate"] = workbench_api["saved_results"].project_scan_artifacts(
            parent["scanId"],
            child["scanId"],
            child_dir,
            parent_dir,
            *(json.loads(child_bytes[name]) for name in names),
        )["draft"]
        run_workbench(
            state,
            "save-scan-artifact",
            "--scan-id",
            parent["scanId"],
            "--artifact-path",
            CHECKPOINT,
            input_text=json.dumps(saved),
        )
    composition_bytes = (parent_dir / CHECKPOINT).read_bytes()
    wrapper = tmp_path / "fail_first_parent_checkpoint.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(SCRIPT.parent)!r})\n"
        "import workbench_db, workbench_saved_results\n"
        "original = workbench_saved_results.write_scan_local_bytes\n"
        "def write(directory, relative, payload, **kwargs):\n"
        f"    if str(directory) == {str(parent_dir)!r} and relative.startswith('checkpoints/'):\n"
        "        raise OSError('Synthetic first parent checkpoint failure.')\n"
        "    return original(directory, relative, payload, **kwargs)\n"
        "workbench_saved_results.write_scan_local_bytes = write\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    if failure == "projection":
        wrapper.write_text(
            "import sys\n"
            f"sys.path.insert(0, {str(SCRIPT.parent)!r})\n"
            "import workbench_db, workbench_saved_results\n"
            "def project(*args, **kwargs):\n"
            "    raise OSError('Synthetic first parent checkpoint failure.')\n"
            "workbench_saved_results._stopped_child_draft = project\n"
            "raise SystemExit(workbench_db.main())\n"
        )
    stopped = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "fail-scan",
            "--scan-id",
            parent["scanId"],
            "--message",
            "Synthetic scan interruption.",
        ],
        capture_output=True,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state)},
        text=True,
        check=False,
    )
    assert stopped.returncode == 0, stopped.stderr
    failed = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert failed["resultsRecoveryNeeded"]
    assert any("Synthetic first parent checkpoint failure" in item for item in failed["warnings"])
    if failure == "checkpoint":
        assert not list((parent_dir / "checkpoints").glob("*.json"))
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (parent["scanId"],)
            ).fetchone() == (None,)
    else:
        assert (parent_dir / "scan-manifest.json").exists()
        assert failed["findingCount"] == 0

    recovery = ("recover-scan-results", "--scan-id", parent["scanId"])
    recovered = run_workbench(state, *recovery)["scan"]
    assert recovered["findingCount"] == 1
    assert not recovered["resultsRecoveryNeeded"]
    assert recovered["findings"][0]["title"] == findings["findings"][0]["title"]
    assert json.loads((parent_dir / "coverage.json").read_text())["completeness"] == "partial"
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"][0]
    report = parent_dir / retained["writeup"]["reportPath"]
    assert report.read_bytes() == (report_dir / "proof.md").read_bytes()
    assert (report.parent / "trace.txt").read_bytes() == (report_dir / "trace.txt").read_bytes()
    assert {name: (child_dir / name).read_bytes() for name in names} == child_bytes
    assert (parent_dir / CHECKPOINT).read_bytes() == composition_bytes

    published = {name: (parent_dir / name).read_bytes() for name in (*names, "report.md")}
    frozen = json.loads(published["scan-manifest.json"])["scan"]["preservedSources"]
    assert frozen
    sources = {path.name: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    saved["aggregate"] = {
        "scanId": parent["scanId"],
        "findings": [retained],
        "coverage": json.loads(published["coverage.json"]),
    }
    saved["aggregate"]["findings"][0]["title"] = (
        "Later composition must not replace frozen evidence"
    )
    (parent_dir / CHECKPOINT).write_text(json.dumps(saved))
    for manifest_only in (False, True):
        if manifest_only:
            with sqlite3.connect(state / "workbench.sqlite3") as connection:
                connection.execute(
                    "UPDATE scans SET retained_source_digests_json = NULL WHERE id = ?",
                    (parent["scanId"],),
                )
        assert run_workbench(state, *recovery)["scan"]["findingCount"] == 1
        assert {name: (parent_dir / name).read_bytes() for name in published} == published
        assert {
            path.name: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")
        } == sources
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            recorded = connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (parent["scanId"],)
            ).fetchone()[0]
        assert json.loads(recorded) == frozen
