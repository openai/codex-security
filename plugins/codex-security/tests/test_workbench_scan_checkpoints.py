from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import accepted_standard_worker, deep_scan_fixture
from workbench_test_support import SCRIPT, run_workbench, write_checkpoint, write_completed_contract


def scan_fixture(tmp_path: Path, mode: str = "standard") -> tuple[Path, Path, Path, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "clean.ts").write_text("export const count = 1;\n")
    (repository / "pending.ts").write_text("export const count = 2;\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    state = tmp_path / "state"
    result = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
                "mode": mode,
                "config": {},
            }
        ),
    )
    return state, repository, scan_dir, str(result["scanId"])


def semantic(scan_id: str, reviewed: list[str]) -> dict[str, object]:
    return {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [
                {
                    "candidateId": "candidate-1",
                    "reason": "Validation pending",
                    "candidate": {"summary": "Inspect the control"},
                }
            ],
            "reviewedFiles": reviewed,
        },
    }


def save(state: Path, scan_id: str, path: Path, *, check: bool = True) -> dict[str, object]:
    return run_workbench(
        state,
        "record-scan-checkpoint",
        "--scan-id",
        scan_id,
        "--checkpoint-path",
        str(path),
        check=check,
    )


def test_checkpoint_survives_new_process_with_clean_coverage_and_pending_evidence(
    tmp_path: Path,
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    payload = semantic(scan_id, ["clean.ts"])
    checkpoint = write_checkpoint(scan_dir / "checkpoints", payload)
    save(state, scan_id, checkpoint)
    result = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert result["progress"]["status"] == "running"
    assert result["findingCount"] == 0
    assert result["checkpoint"]["reviewedFileCount"] == 1
    assert result["checkpoint"]["remainingFileCount"] == 1
    assert result["checkpoint"]["pendingCount"] == 1
    assert "coverage" not in result["checkpoint"]["sources"][0]
    assert "reviewedFiles" not in result["checkpoint"]
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["checkpoint"]["sources"][0]["coverage"] == payload["coverage"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        stored = connection.execute("SELECT snapshot_json FROM scan_checkpoints").fetchone()[0]
        assert json.loads(stored) == payload
    run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["checkpoint"]
        == result["checkpoint"]
    )


def test_checkpoint_normalizes_reviewed_path_spellings_without_changing_saved_bytes(
    tmp_path: Path,
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    payload = semantic(scan_id, ["clean.ts", "./clean.ts", "././clean.ts"])
    checkpoint = write_checkpoint(scan_dir / "checkpoints", payload)
    original = checkpoint.read_bytes()
    save(state, scan_id, checkpoint)
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert resumed["checkpoint"]["remainingFiles"] == ["pending.ts"]
    assert checkpoint.read_bytes() == original
    assert resumed["checkpoint"]["sources"][0]["coverage"]["reviewedFiles"] == [
        "clean.ts",
        "./clean.ts",
        "././clean.ts",
    ]


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_full_directory_registration_with_ignore_files_does_not_require_ripgrep(
    tmp_path: Path, mode: str
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".gitignore").write_text("ignored.ts\n")
    (repository / "ignored.ts").write_text("export const ignored = true;\n")
    (repository / "source.ts").write_text("export const reviewed = true;\n")
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    state = tmp_path / "state"
    result = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "repository", "paths": []},
                "mode": mode,
                "config": {},
            }
        ),
        environment={"PATH": ""},
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT relative_path FROM scan_review_files WHERE scan_id = ? ORDER BY relative_path",
            (result["scanId"],),
        ).fetchall() == [(".gitignore",), ("ignored.ts",), ("source.ts",)]


def test_registration_hashes_inventory_before_taking_the_shared_database_write_lock(
    tmp_path: Path, workbench_api, monkeypatch
) -> None:
    state, repository, _, existing_scan_id = scan_fixture(tmp_path)
    scan_dir = tmp_path / "second-scan"
    scan_dir.mkdir(mode=0o700)
    checkpoints = workbench_api["scan_checkpoints"]
    original_digest = checkpoints.file_digest
    hashed = []

    def digest_while_other_scan_updates(path):
        with sqlite3.connect(state / "workbench.sqlite3", timeout=0) as other:
            other.execute("UPDATE scans SET phase = 'discovery' WHERE id = ?", (existing_scan_id,))
        hashed.append(path.name)
        return original_digest(path)

    monkeypatch.setattr(checkpoints, "file_digest", digest_while_other_scan_updates)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        registered = workbench_api["register_cli_scan"](
            connection,
            argparse.Namespace(
                repository=str(repository),
                scan_dir=str(scan_dir),
                registration_json_stdin=False,
                recipe_json_stdin=False,
                recipe_json=json.dumps(
                    {
                        "repository": str(repository),
                        "target": {"kind": "repository", "paths": []},
                        "mode": "standard",
                        "config": {},
                    }
                ),
                parent_scan_id=None,
                archived_scan_dir=None,
                archive_existing=False,
            ),
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM scan_review_files WHERE scan_id = ?", (registered["scanId"],)
            ).fetchone()[0]
            == 2
        )
    assert sorted(hashed) == ["clean.ts", "pending.ts"]


@pytest.mark.parametrize("source_changed", [False, True])
def test_existing_deep_scan_initializes_migrated_inventory_from_original_source(
    tmp_path: Path, source_changed: bool
) -> None:
    state, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, budget=True)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    # Migration 42 adds an empty inventory to already-running scans.
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("DELETE FROM scan_review_files WHERE scan_id = ?", (scan_id,))
    run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )
    if source_changed:
        (target / "app.py").write_text("changed after the original scan started\n")
    path = write_checkpoint(result_path.parent / "checkpoints", semantic(scan_id, ["app.py"]))
    result = save(state, scan_id, path, check=not source_changed)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        reviewed = connection.execute(
            "SELECT relative_path FROM scan_review_files WHERE reviewed_at IS NOT NULL"
        ).fetchall()
        if source_changed:
            assert result["returncode"] != 0
            assert "changed" in result["stderr"]
            assert reviewed == []
            assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (0,)
        else:
            assert reviewed == [("app.py",)]
            assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (1,)


def test_rejected_coverage_batch_does_not_commit_other_paths(tmp_path: Path) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    (repository / "pending.ts").write_text("changed source\n")
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints", semantic(scan_id, ["clean.ts", "pending.ts"])
    )
    result = save(state, scan_id, checkpoint, check=False)
    assert result["returncode"] != 0
    assert "changed: pending.ts" in result["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM scan_review_files WHERE reviewed_at IS NOT NULL"
        ).fetchone() == (0,)


def test_first_deep_coordinator_after_migration_requires_original_inventory(
    tmp_path: Path,
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path, "deep")
    codex_home = tmp_path / "codex-home"
    config = codex_home / "codex-security" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text("[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n")
    # An older registered scan has neither the new inventory nor a coordinator yet.
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("DELETE FROM scan_review_files WHERE scan_id = ?", (scan_id,))
    source = repository / "clean.ts"
    original = source.read_bytes()
    source.write_text("changed before the first coordinator started\n")
    arguments = ("begin-deep-scan", "--scan-id", scan_id, "--thread-id", "migrated-worker-thread")
    rejected = run_workbench(
        state, *arguments, environment={"CODEX_HOME": str(codex_home)}, check=False
    )
    assert rejected["returncode"] != 0
    assert "original source changed" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for table in ("scan_review_files", "deep_scan_runs", "scan_checkpoints"):
            assert connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE scan_id = ?", (scan_id,)
            ).fetchone() == (0,)

    source.write_bytes(original)
    run_workbench(state, *arguments, environment={"CODEX_HOME": str(codex_home)})
    save(
        state, scan_id, write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    )
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert resumed["checkpoint"]["remainingFiles"] == ["pending.ts"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == (1,)


def test_resume_reconciles_checkpoint_written_before_projection(tmp_path: Path) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path, "deep")
    run_workbench(state, "set-scan-thread", "--scan-id", scan_id, "--thread-id", str(uuid.uuid4()))
    checkpoint = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    (scan_dir / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
    resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
    assert resumed["checkpoint"]["reviewedFiles"] == ["clean.ts"]
    assert resumed["checkpoint"]["remainingFiles"] == ["pending.ts"]


def test_checkpoint_binding_rejects_wrong_scan_unknown_worker_and_changed_content(
    tmp_path: Path,
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    wrong_scan = write_checkpoint(scan_dir / "checkpoints", semantic(str(uuid.uuid4()), []))
    assert "this scan" in save(state, scan_id, wrong_scan, check=False)["stderr"]
    worker = write_checkpoint(
        scan_dir / "unregistered-worker" / "checkpoints", semantic(scan_id, [])
    )
    assert "registered scan worker" in save(state, scan_id, worker, check=False)["stderr"]
    changed = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, []))
    changed.write_text(changed.read_text() + " ")
    assert "saved content" in save(state, scan_id, changed, check=False)["stderr"]


@pytest.mark.parametrize("legacy_head", [False, True])
def test_checkpoint_acceptance_distinguishes_replay_from_fresh_identical_content(
    tmp_path: Path, legacy_head: bool
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    first = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    save(state, scan_id, first)
    first_head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    payload = semantic(scan_id, ["clean.ts", "pending.ts"])
    payload["coverage"]["deferred"] = []
    second = write_checkpoint(scan_dir / "checkpoints", payload)
    os.utime(second, ns=(1, 1))
    save(state, scan_id, second)
    second_head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    # A delayed replay of the original acceptance cannot overtake the newer decision.
    replay_head = {"checkpoint": first.name} if legacy_head else first_head
    (scan_dir / "checkpoint-head.json").write_text(json.dumps(replay_head))
    result = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert result["remainingFiles"] == []
    assert result["sources"][0]["coverage"] == payload["coverage"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (2,)
    # A new live submission of those exact same bytes is a new decision.
    (scan_dir / "checkpoint-head.json").write_text(json.dumps(second_head))
    receipt = save(state, scan_id, first)
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    assert head["checkpoint"] == first.name
    assert head["acceptanceId"] == receipt["acceptanceId"]
    assert head["acceptanceId"] not in {first_head["acceptanceId"], second_head["acceptanceId"]}
    for _ in range(2):
        result = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
        assert result["sources"][0]["coverage"] == semantic(scan_id, ["clean.ts"])["coverage"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (3,)


@pytest.mark.parametrize("interruption", ["head", "receipt"])
def test_identical_content_acceptance_recovers_once_after_process_exit(
    tmp_path: Path, interruption: str
) -> None:
    state, _, scan_dir, scan_id = scan_fixture(tmp_path)
    first = write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    first_receipt = save(state, scan_id, first)
    resolved = semantic(scan_id, ["clean.ts"])
    resolved["coverage"]["deferred"] = []
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", resolved))
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import os, sqlite3, sys
from pathlib import Path
scripts, state, scan_id, checkpoint, interruption = sys.argv[1:]
sys.path.insert(0, scripts)
import workbench_scan_checkpoints as checkpoints
connection = sqlite3.connect(Path(state) / "workbench.sqlite3")
connection.row_factory = sqlite3.Row
scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
write = checkpoints._write_checkpoint_head
def interrupted_write(*args):
    write(*args)
    os._exit(72)
if interruption == "head":
    checkpoints._write_checkpoint_head = interrupted_write
checkpoints.record_checkpoint(connection, scan, Path(checkpoint), "2026-09-09T00:00:00Z")
os._exit(72)
""",
            str(SCRIPT.parent),
            str(state),
            scan_id,
            str(first),
            interruption,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 72, process.stderr
    head = json.loads((scan_dir / "checkpoint-head.json").read_text())
    assert head["checkpoint"] == first.name
    assert head["acceptanceId"] != first_receipt["acceptanceId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (
            2 if interruption == "head" else 3,
        )
    for _ in range(2):
        recovered = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)
        assert (
            recovered["checkpoint"]["sources"][0]["coverage"]
            == semantic(scan_id, ["clean.ts"])["coverage"]
        )
        assert json.loads((scan_dir / "checkpoint-head.json").read_text()) == head
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_checkpoints").fetchone() == (3,)
        assert connection.execute(
            "SELECT acceptance_id FROM scan_checkpoints ORDER BY sequence DESC LIMIT 1"
        ).fetchone() == (head["acceptanceId"],)


@pytest.mark.parametrize("mode", ["standard", "deep"])
def test_scoped_checkpoint_inventory_matches_ignore_aware_review_input(
    tmp_path: Path, mode: str
) -> None:
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    for relative, contents in {
        ".gitignore": "src/*.ignored\nexplicit.ignored\n",
        ".ignore": "src/*.cache\n",
        ".rgignore": "src/*.generated\n",
        "src/.gitignore": "*.tmp\n!keep.tmp\n",
        "src/main.ts": "export const count = 1;\n",
        "src/excluded.ignored": "ignored\n",
        "src/excluded.cache": "ignored\n",
        "src/excluded.generated": "ignored\n",
        "src/excluded.tmp": "ignored\n",
        "src/keep.tmp": "selected by negation\n",
        "explicit.ignored": "explicit selection\n",
        "outside.ts": "outside scope\n",
    }.items():
        (repository / relative).write_text(contents)
    scopes = ["src", "explicit.ignored"]
    scopes_file = tmp_path / "scopes.json"
    scopes_file.write_text(json.dumps(scopes))
    ranked = tmp_path / "scope.jsonl"
    process = subprocess.run(
        [
            sys.executable,
            str(SCRIPT.parent / "generate_rank_input.py"),
            "make-repo-scope-input",
            "--repo",
            str(repository),
            "--scopes-file",
            str(scopes_file),
            "--out",
            str(ranked),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stderr
    expected = [json.loads(line)["path"] for line in ranked.read_text().splitlines()]
    assert expected == ["explicit.ignored", "src/.gitignore", "src/keep.tmp", "src/main.ts"]
    state = tmp_path / "state"
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir(mode=0o700)
    scan_id = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(scan_dir),
        "--recipe-json",
        json.dumps(
            {
                "repository": str(repository),
                "target": {"kind": "paths", "paths": scopes},
                "mode": mode,
                "config": {},
            }
        ),
    )["scanId"]
    if mode == "deep":
        codex_home = tmp_path / "codex-home"
        config = codex_home / "codex-security" / "config.toml"
        config.parent.mkdir(parents=True)
        config.write_text("[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\n")
        begun = run_workbench(
            state,
            "begin-deep-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "scoped-worker-thread",
            environment={"CODEX_HOME": str(codex_home)},
        )
        assert begun["deepScan"]["scopePaths"] == scopes
    rejected = save(
        state,
        scan_id,
        write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["outside.ts"])),
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "outside.ts" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert [
            row[0]
            for row in connection.execute(
                "SELECT relative_path FROM scan_review_files ORDER BY relative_path"
            )
        ] == expected
    payload = semantic(scan_id, expected)
    payload["complete"] = True
    payload["coverage"].update(completeness="complete", deferred=[])
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", payload))
    recovered = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan_id)["checkpoint"]
    assert recovered["reviewedFiles"] == expected
    assert recovered["remainingFiles"] == []


def test_child_inherits_saved_findings_coverage_and_cost_without_changing_parent_seal(
    tmp_path: Path,
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, repository, relative_path="clean.ts")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    payload = semantic(scan_id, ["clean.ts"])
    payload["findings"] = [finding]
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", payload))
    run_workbench(state, "fail-scan", "--scan-id", scan_id, "--message", "Connection closed")
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        scan_id,
    )["scanId"]
    cost = {
        "model": "test-model",
        "inputTokens": 100,
        "outputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "estimatedUsd": 2.5,
    }
    result = run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child,
        "--parent-scan-id",
        scan_id,
        "--cost-json",
        json.dumps(cost),
    )["checkpoint"]
    assert result["reviewedFiles"] == ["clean.ts"]
    assert result["remainingFiles"] == ["pending.ts"]
    assert result["sources"][0]["findings"][0]["title"] == finding["title"]
    assert (
        json.loads((child_dir / "findings.json").read_text())["findings"][0]["title"]
        == finding["title"]
    )
    assert json.loads((child_dir / "scan-manifest.json").read_text())["scan"]["complete"] is False
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        baseline, attempt = connection.execute(
            "SELECT continuation_cost_json, cost_json FROM scans WHERE id = ?",
            (child,),
        ).fetchone()
        assert json.loads(baseline) == cost
        assert attempt is None


def test_child_registration_against_changed_source_cannot_reuse_parent_coverage(
    tmp_path: Path,
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    save(
        state, scan_id, write_checkpoint(scan_dir / "checkpoints", semantic(scan_id, ["clean.ts"]))
    )
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    (repository / "pending.ts").write_text("changed target\n")
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        scan_id,
    )["scanId"]
    result = run_workbench(
        state,
        "continue-scan-checkpoint",
        "--scan-id",
        child,
        "--parent-scan-id",
        scan_id,
        check=False,
    )
    assert "original source" in result["stderr"]
    assert not (child_dir / "findings.json").exists()


@pytest.mark.parametrize(
    ("artifact", "receipt_change"),
    [("receipt", None)]
    + [("receipt", change) for change in ("contents", "symlink", "missing")]
    + [("report", "symlink")],
)
def test_completed_checkpoint_continuation_keeps_bound_reports_receipts_and_poc_files(
    tmp_path: Path,
    artifact: str,
    receipt_change: str | None,
) -> None:
    state, repository, scan_dir, scan_id = scan_fixture(tmp_path)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, repository, relative_path="clean.ts")
    payload = semantic(scan_id, ["clean.ts", "pending.ts"])
    payload["complete"] = True
    payload["findings"] = json.loads((contract / "findings.json").read_text())["findings"]
    payload["findings"][0]["writeup"] = {"reportPath": "findings/saved/saved.md"}
    payload["coverage"] = json.loads((contract / "coverage.json").read_text())
    payload["coverage"]["reviewedFiles"] = ["clean.ts", "pending.ts"]
    payload["coverage"]["surfaces"][0]["receiptRefs"] = ["artifacts/review/clean.json"]
    payload["scope"] = {
        "summary": "Saved source review",
        "runtimeStatus": "Unit tests completed",
        "context": "Review of the current parser design",
        "limitations": ["Integration tests were unavailable"],
    }
    artifacts = {
        "findings/saved/saved.md": b"# Saved finding\n\n[Proof](poc/sample.bin)\n",
        "findings/saved/poc/sample.bin": b"\x00saved evidence\xff",
        "artifacts/review/clean.json": b'{"reviewed": ["clean.ts", "pending.ts"]}\n',
        "hardening/hardening.md": b"# Hardening\n\n[Proposal](proposals/parser.md)\n",
        "hardening/proposals/parser.md": b"# Parser design\n\n[Diagram](../diagrams/parser.mmd)\n",
        "hardening/diagrams/parser.mmd": b"graph LR\n  Input --> Parser\n",
    }
    for relative, contents in artifacts.items():
        path = scan_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    save(state, scan_id, write_checkpoint(scan_dir / "checkpoints", payload))
    manifest = json.loads((contract / "scan-manifest.json").read_text())
    manifest["scan"]["scope"].update(payload["scope"])
    manifest["scan"]["hardening"] = {"portfolioPath": "hardening/hardening.md"}
    for filename, document in (
        ("scan-manifest.json", manifest),
        ("findings.json", {"findings": payload["findings"]}),
        ("coverage.json", payload["coverage"]),
    ):
        (scan_dir / filename).write_text(json.dumps(document))
    run_workbench(state, "fail-scan", "--scan-id", scan_id, "--message", "Export interrupted")
    parent_seal = (scan_dir / "scan-manifest.json").read_bytes()
    recipe = run_workbench(state, "get-scan-recipe", "--scan-id", scan_id)["recipe"]
    child_dir = tmp_path / "child"
    child_dir.mkdir(mode=0o700)
    child = run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(repository),
        "--scan-dir",
        str(child_dir),
        "--recipe-json",
        json.dumps(recipe),
        "--parent-scan-id",
        scan_id,
    )["scanId"]
    if receipt_change is not None:
        receipt = scan_dir / (
            "artifacts/review/clean.json" if artifact == "receipt" else "findings/saved/saved.md"
        )
        if receipt_change == "contents":
            receipt.write_text("changed receipt\n")
        elif receipt_change == "missing":
            receipt.unlink()
        else:
            outside = tmp_path / "outside.json"
            outside.write_text("outside evidence\n")
            receipt.unlink()
            receipt.symlink_to(outside)
        rejected = run_workbench(
            state,
            "continue-scan-checkpoint",
            "--scan-id",
            child,
            "--parent-scan-id",
            scan_id,
            check=False,
        )
        assert rejected["returncode"] != 0
        assert (
            "sealed artifact changed"
            if receipt_change == "contents"
            else "inside the scan directory"
        ) in rejected["stderr"]
        assert not (child_dir / "scan-manifest.json").exists()
        assert (scan_dir / "scan-manifest.json").read_bytes() == parent_seal
        return
    continued = run_workbench(
        state, "continue-scan-checkpoint", "--scan-id", child, "--parent-scan-id", scan_id
    )
    assert continued["completionReady"] is True
    run_workbench(state, "prepare-scan-completion", "--scan-id", child)
    completed = run_workbench(state, "complete-scan", "--scan-id", child)["scan"]
    assert completed["progress"]["status"] == "complete"
    assert json.loads((child_dir / "coverage.json").read_text())["completeness"] == "complete"
    findings = json.loads((child_dir / "findings.json").read_text())["findings"]
    assert findings[0]["writeup"] == {"reportPath": "findings/saved/saved.md"}
    child_manifest = json.loads((child_dir / "scan-manifest.json").read_text())["scan"]
    assert child_manifest["hardening"] == {"portfolioPath": "hardening/hardening.md"}
    assert child_manifest["scope"]["includePaths"] == ["."]
    for key, value in payload["scope"].items():
        assert child_manifest["scope"][key] == value
    report = (child_dir / "report.md").read_text()
    assert "Unit tests completed" in report
    assert "Review of the current parser design" in report
    assert "Integration tests were unavailable" in report
    assert "hardening/hardening.md" in report
    for relative, contents in artifacts.items():
        assert (child_dir / relative).read_bytes() == contents
        assert (scan_dir / relative).read_bytes() == contents
    assert (scan_dir / "scan-manifest.json").read_bytes() == parent_seal


def test_worker_checkpoint_commits_under_registered_scan_with_clean_source_coverage(
    tmp_path: Path,
) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    payload = semantic(scan_id, ["app.py"])
    path = write_checkpoint(result_path.parent / "checkpoints", payload)
    save(state, scan_id, path)
    result = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["checkpoint"]
    assert result["sources"][0]["source"] == result_path.parent.relative_to(scan_dir).as_posix()
    assert result["reviewedFileCount"] == 1
    assert result["pendingCount"] == 1
    assert result["sources"][0]["checkpointPath"] == path.relative_to(scan_dir).as_posix()
