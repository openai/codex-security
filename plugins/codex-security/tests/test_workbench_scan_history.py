from __future__ import annotations

import copy
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from test_workbench_db import HEAD_CHANGED_WARNING, create_saved_workspace
from workbench_test_support import (
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    stable_target_id,
    write_completed_contract,
)

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
FINALIZER = SCRIPT.with_name("finalize_scan_contract.py")


def run_workbench(state_dir: Path, *args: str, check: bool = True) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=check,
        capture_output=True,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
        text=True,
    )
    if not check:
        return {"returncode": completed.returncode, "stderr": completed.stderr}
    return json.loads(completed.stdout)


def compare_scan_pair(
    state_dir: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    *arguments: str,
    check: bool = True,
) -> dict[str, Any]:
    return run_workbench(
        state_dir,
        "compare-scans",
        "--before-scan-id",
        before["scanId"],
        "--after-scan-id",
        after["scanId"],
        *arguments,
        check=check,
    )


def save_scan_matches(
    state_dir: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    *matches: dict[str, Any],
    uncertain: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    return run_workbench(
        state_dir,
        "save-scan-comparison",
        "--before-scan-id",
        before["scanId"],
        "--after-scan-id",
        after["scanId"],
        "--matches-json",
        json.dumps({"matches": matches, "uncertain": uncertain}),
    )


def confirmed_match(
    before: str | list[str], after: str | list[str], reason: str = "Same root cause."
) -> dict[str, Any]:
    return {
        "beforeOccurrenceIds": before if isinstance(before, list) else [before],
        "afterOccurrenceIds": after if isinstance(after, list) else [after],
        "confidence": "high",
        "reason": reason,
    }


def create_cli_scan(
    state_dir: Path,
    root: Path,
    repository: Path,
    *,
    complete: bool = True,
    completeness: str = "complete",
    extra_anchors: tuple[str, ...] = (),
    finding: bool = True,
    identity_anchor: str = "archive-entry-write-without-containment",
    mode: str = "standard",
    parent_scan_id: str | None = None,
    paths: list[str] | None = None,
    cost: dict[str, Any] | None = None,
    target: dict[str, Any] | None = None,
    target_revision: str | None = None,
) -> dict[str, Any]:
    scan_dir = root / str(uuid.uuid4())
    scan_dir.mkdir(mode=0o700, parents=True)
    recipe = {
        "config": {"model": "gpt-5.6-sol", "model_reasoning_effort": "high"},
        "mode": mode,
        "repository": str(repository.resolve()),
        "target": target or {"kind": "paths" if paths else "repository", "paths": paths or []},
    }
    arguments = [
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(repository),
        "--recipe-json",
        json.dumps(recipe),
    ]
    if parent_scan_id is not None:
        arguments.extend(("--parent-scan-id", parent_scan_id))
    launched = run_workbench(state_dir, *arguments)
    if not complete:
        return launched
    if mode == "deep":
        run_workbench(
            state_dir,
            "begin-deep-scan",
            "--scan-id",
            launched["scanId"],
            "--thread-id",
            "thread-scan-history",
        )
        mark_deep_coordinator_succeeded(state_dir, launched["scanId"], scan_dir)

    coverage_mode = (
        "scoped_path" if paths else "deep_repository" if mode == "deep" else "repository"
    )
    snapshot_digest = None
    if target_revision is not None:
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            snapshot_digest = connection.execute(
                "SELECT target_snapshot_digest FROM scans WHERE id = ?", (launched["scanId"],)
            ).fetchone()[0]
    write_completed_contract(
        scan_dir,
        launched["scanId"],
        repository,
        identity_anchor=identity_anchor,
        include_paths=paths,
        coverage_mode=coverage_mode,
        inventory_strategy="scoped_path" if paths else "repository",
        target_kind="git_revision" if target_revision is not None else "directory_snapshot",
        target_revision=target_revision,
        snapshot_digest=snapshot_digest,
    )
    if not finding or extra_anchors:
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        if not finding:
            findings["findings"] = []
        else:
            for index, anchor in enumerate(extra_anchors, start=1):
                additional = copy.deepcopy(findings["findings"][0])
                additional["identity"]["anchor"] = anchor
                additional["title"] += f" ({index})"
                findings["findings"].append(additional)
        findings_path.write_text(json.dumps(findings))
    if completeness != "complete":
        coverage_path = scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["completeness"] = completeness
        coverage["surfaces"][0]["disposition"] = "needs_follow_up"
        coverage["deferred"] = [
            {"id": "unreviewed-path", "reason": "Review incomplete", "paths": ["src/extract.py"]}
        ]
        coverage_path.write_text(json.dumps(coverage))
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)
    completion = ["complete-scan", "--scan-id", launched["scanId"]]
    if cost is not None:
        completion.extend(("--cost-json", json.dumps(cost)))
    run_workbench(state_dir, *completion)
    return launched


def insert_scan(
    connection: sqlite3.Connection,
    *,
    workspace_id: str,
    scan_id: str,
    mode: str,
    status: str,
    phase: str,
    timestamp: str,
    seal: str | None = None,
    failure: str | None = None,
    canceled: bool = False,
) -> None:
    connection.execute(
        """
        INSERT INTO scans (
            id, workspace_id, target_path, target_revision, scope, mode,
            scan_dir, status, phase, handoff_status, failure_message,
            started_at, completed_at, created_at, updated_at, canceled_at,
            seal_manifest_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            workspace_id,
            "/tmp/target",
            "fixture-revision",
            ".",
            mode,
            f"/tmp/scans/{scan_id}",
            status,
            phase,
            "delivered",
            failure,
            timestamp,
            timestamp if status != "running" else None,
            timestamp,
            timestamp,
            timestamp if canceled else None,
            seal,
        ),
    )


def test_cli_scan_lifecycle_persists_recipes_lineage_and_filtered_history(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "tests").mkdir()
    root = tmp_path / "results"
    first = create_cli_scan(state_dir, root, repository)
    rerun = create_cli_scan(
        state_dir,
        root,
        repository,
        parent_scan_id=first["scanId"],
        paths=["src", "tests"],
    )
    failed = create_cli_scan(state_dir, root, repository, complete=False)
    run_workbench(state_dir, "fail-scan", "--scan-id", failed["scanId"], "--message", "interrupted")

    assert str(uuid.UUID(first["scanId"])) == first["scanId"]
    assert first["targetId"] == stable_target_id(repository)
    assert first["scanDir"].startswith(str(root))
    detail = run_workbench(state_dir, "get-scan", "--scan-id", rerun["scanId"])
    assert detail["parentScanId"] == first["scanId"]
    assert detail["recipe"]["target"]["paths"] == ["src", "tests"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT parent_scan_id FROM scans WHERE id = ?", (rerun["scanId"],)
        ).fetchone() == (first["scanId"],)
    assert run_workbench(state_dir, "get-scan-recipe", "--scan-id", first["scanId"])["recipe"][
        "config"
    ] == {"model": "gpt-5.6-sol", "model_reasoning_effort": "high"}

    other = tmp_path / "other"
    other.mkdir()
    create_cli_scan(state_dir, tmp_path / "other-results", other)
    history = run_workbench(
        state_dir, "list-scans", "--repository", str(repository), "--scan-root", str(root)
    )
    assert {scan["scanId"] for scan in history["scans"]} == {
        first["scanId"],
        rerun["scanId"],
        failed["scanId"],
    }
    assert any(scan["progress"]["status"] == "failed" for scan in history["scans"])
    assert all(scan["recipeAvailable"] for scan in history["scans"])
    assert len(run_workbench(state_dir, "list-scans", "--repository", str(other))["scans"]) == 1


def test_cli_scan_persists_its_continuation_thread(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)

    result = run_workbench(
        state_dir,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "thread-1",
    )

    assert result == {"scanId": scan["scanId"], "threadId": "thread-1"}
    detail = run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])
    assert detail["scan"]["continuationThreadId"] == "thread-1"


def test_cli_scan_preserves_original_revision_when_head_moves(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    readme = repository / "README.md"
    readme.write_text(
        "\n".join(f"source line {line_number}" for line_number in range(1, 51)) + "\n"
    )
    subprocess.run(["git", "-C", str(repository), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Add scanned source"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    launched = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)
    scan_dir = Path(launched["scanDir"])
    write_completed_contract(
        scan_dir,
        launched["scanId"],
        repository,
        relative_path="README.md",
        target_kind="git_revision",
        target_revision=revision,
    )
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)

    readme.write_text("replacement source\n")
    subprocess.run(["git", "-C", str(repository), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repository), "commit", "-qm", "Move HEAD"], check=True)

    completed = run_workbench(state_dir, "complete-scan", "--scan-id", launched["scanId"])

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["targetRevision"] == revision
    assert completed["scan"]["warnings"] == [HEAD_CHANGED_WARNING]
    assert "41  source line 41" in completed["scan"]["findings"][0]["sourceExcerpt"]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["revision"] == revision
    history = run_workbench(state_dir, "list-scans", "--repository", str(repository))
    assert history["scans"][0]["warnings"] == completed["scan"]["warnings"]


def test_cli_scan_history_persists_per_scan_cost(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    cost = {
        "model": "gpt-5.6-sol",
        "inputTokens": 1250,
        "cachedInputTokens": 200,
        "cacheWriteInputTokens": 0,
        "outputTokens": 30,
        "estimatedUsd": 0.00625,
    }
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, cost=cost)

    listed = run_workbench(state_dir, "list-scans", "--repository", str(repository))
    assert listed["scans"][0]["cost"] == cost
    assert run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]["cost"] == cost
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        stored = connection.execute(
            "SELECT cost_json FROM scans WHERE id = ?", (scan["scanId"],)
        ).fetchone()
    assert stored is not None
    assert json.loads(stored[0]) == cost


def test_cli_scan_completion_persists_authoritative_cost_after_plugin_completion(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository)
    cost = {
        "model": "gpt-5.6-sol",
        "inputTokens": 1250,
        "cachedInputTokens": 200,
        "cacheWriteInputTokens": 0,
        "outputTokens": 30,
        "estimatedUsd": 0.00625,
    }
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET cost_json = ? WHERE id = ?",
            (
                json.dumps(
                    {
                        "usage": {
                            "status": "complete",
                            "inputTokens": 5_000,
                            "outputTokens": 120,
                        }
                    }
                ),
                scan["scanId"],
            ),
        )

    completed = run_workbench(
        state_dir,
        "complete-scan",
        "--scan-id",
        scan["scanId"],
        "--cost-json",
        json.dumps(cost),
    )

    assert completed["scan"]["cost"] == cost
    assert completed["scan"]["usage"]["inputTokens"] == 5_000
    assert run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]["cost"] == cost


def test_failed_cli_scan_history_persists_measured_cost(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    cost = {
        "model": "gpt-5.6-terra",
        "inputTokens": 1250,
        "cachedInputTokens": 200,
        "cacheWriteInputTokens": 0,
        "outputTokens": 30,
        "estimatedUsd": 0.003125,
    }
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)

    failed = run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan["scanId"],
        "--message",
        "Scan stopped: cost limit exceeded.",
        "--cost-json",
        json.dumps(cost),
    )

    assert failed["scan"]["cost"] == cost
    assert failed["scan"]["progress"]["status"] == "failed"
    assert run_workbench(state_dir, "list-scans")["scans"][0]["cost"] == cost
    assert run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]["cost"] == cost


def test_scan_failure_rejects_invalid_cost_without_stopping_the_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)

    rejected = run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan["scanId"],
        "--message",
        "Scan stopped.",
        "--cost-json",
        "{}",
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "Scan cost" in rejected["stderr"]
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]["progress"][
            "status"
        ]
        == "running"
    )


def test_scan_completion_rejects_invalid_cost_without_overwriting_history(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository)
    invalid = [
        "null",
        "{}",
        "NaN",
        json.dumps(
            {
                "model": "gpt-5.6-sol",
                "inputTokens": 1,
                "cachedInputTokens": 2,
                "cacheWriteInputTokens": 0,
                "outputTokens": 1,
                "estimatedUsd": 0.01,
            }
        ),
        "x" * 8193,
    ]

    for value in invalid:
        rejected = run_workbench(
            state_dir,
            "complete-scan",
            "--scan-id",
            scan["scanId"],
            "--cost-json",
            value,
            check=False,
        )
        assert rejected["returncode"] != 0
        assert "Scan cost" in rejected["stderr"]

    assert "cost" not in run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]


def test_scan_history_resolves_unique_prefixes_and_rejects_ambiguity(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    scan = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository)
    prefix = scan["scanId"][:8]
    after_prefix = after["scanId"][:8]

    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", prefix)["scan"]["scanId"]
        == scan["scanId"]
    )
    assert (
        run_workbench(state_dir, "get-scan-recipe", "--scan-id", prefix)["scanId"] == scan["scanId"]
    )
    compared = run_workbench(
        state_dir,
        "compare-scans",
        "--before-scan-id",
        prefix,
        "--after-scan-id",
        after_prefix,
        "--include-matching-inputs",
    )
    assert (compared["beforeScanId"], compared["afterScanId"]) == (
        scan["scanId"],
        after["scanId"],
    )
    saved = run_workbench(
        state_dir,
        "save-scan-comparison",
        "--before-scan-id",
        prefix,
        "--after-scan-id",
        after_prefix,
        "--matches-json",
        '{"matches":[],"uncertain":[]}',
    )
    assert (saved["beforeScanId"], saved["afterScanId"]) == (
        scan["scanId"],
        after["scanId"],
    )

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        workspace_id = connection.execute(
            "SELECT workspace_id FROM scans WHERE id = ?", (scan["scanId"],)
        ).fetchone()[0]
        insert_scan(
            connection,
            workspace_id=workspace_id,
            scan_id=f"{prefix}-ffff-4000-8000-000000000000",
            mode="standard",
            status="complete",
            phase="reporting",
            timestamp="2026-07-24T00:00:00Z",
        )

    for arguments in (
        ("get-scan", "--scan-id", prefix),
        ("get-scan-recipe", "--scan-id", prefix),
        (
            "compare-scans",
            "--before-scan-id",
            prefix,
            "--after-scan-id",
            after_prefix,
        ),
        (
            "save-scan-comparison",
            "--before-scan-id",
            prefix,
            "--after-scan-id",
            after_prefix,
            "--matches-json",
            '{"matches":[],"uncertain":[]}',
        ),
    ):
        ambiguous = run_workbench(state_dir, *arguments, check=False)
        assert ambiguous["returncode"] != 0
        assert "matches multiple scans; use a longer prefix" in ambiguous["stderr"]
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]["scanId"]
        == scan["scanId"]
    )


def test_scan_list_includes_related_git_worktrees_and_clones(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    worktree = tmp_path / "worktree"
    clone = tmp_path / "clone"
    unrelated = tmp_path / "unrelated"
    initialize_git_repository(repository)
    initialize_git_repository(clone)
    initialize_git_repository(unrelated)
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(worktree)],
        check=True,
    )
    for target, origin in (
        (repository, "https://user:token@GITHUB.com/example/project.git"),
        (clone, "git@github.com:example/project"),
        (unrelated, "https://github.com/example/unrelated"),
    ):
        subprocess.run(["git", "-C", str(target), "remote", "add", "origin", origin], check=True)

    root = tmp_path / "results"
    original_scan = create_cli_scan(state_dir, root / "original", repository, complete=False)
    worktree_scan = create_cli_scan(state_dir, root / "worktree", worktree, complete=False)
    clone_scan = create_cli_scan(state_dir, root / "clone", clone, complete=False)
    unrelated_scan = create_cli_scan(state_dir, root / "unrelated", unrelated, complete=False)

    for target in (repository, worktree, clone):
        scans = run_workbench(state_dir, "list-scans", "--repository", str(target))["scans"]
        assert [scan["scanId"] for scan in scans] == [
            clone_scan["scanId"],
            worktree_scan["scanId"],
            original_scan["scanId"],
        ]

    for offset, expected in enumerate((clone_scan, worktree_scan, original_scan)):
        page = run_workbench(
            state_dir,
            "list-scans",
            "--repository",
            str(repository),
            "--limit",
            "1",
            "--offset",
            str(offset),
        )
        assert [scan["scanId"] for scan in page["scans"]] == [expected["scanId"]]
        assert page["nextOffset"] == (offset + 1 if offset < 2 else None)

    queried = run_workbench(
        state_dir, "list-scans", "--repository", str(repository), "--query", "clone"
    )["scans"]
    assert [scan["scanId"] for scan in queried] == [clone_scan["scanId"]]

    scoped = run_workbench(
        state_dir,
        "list-scans",
        "--repository",
        str(repository),
        "--scan-root",
        str(root / "worktree"),
    )["scans"]
    assert [scan["scanId"] for scan in scoped] == [worktree_scan["scanId"]]
    other = run_workbench(state_dir, "list-scans", "--repository", str(unrelated))["scans"]
    assert [scan["scanId"] for scan in other] == [unrelated_scan["scanId"]]


def test_cli_scan_comparison_tracks_stable_findings_without_copying_triage(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository, parent_scan_id=before["scanId"])
    fixed = create_cli_scan(state_dir, root, repository, finding=False)

    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    persisted = save_scan_matches(
        state_dir,
        before,
        after,
        confirmed_match(inputs["before"][0]["occurrenceId"], inputs["after"][0]["occurrenceId"]),
    )
    assert persisted["comparable"] is True
    assert persisted["summary"]["persisting"] == 1
    occurrence = persisted["findings"][0]["beforeOccurrenceId"]
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
    )
    reopened = compare_scan_pair(state_dir, before, after)
    assert reopened["summary"]["reopened"] == 1
    assert reopened["findings"][0]["triage"] == {"closeReason": None, "status": "open"}

    resolved = compare_scan_pair(state_dir, after, fixed)
    assert resolved["summary"]["resolved"] == 1
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM findings").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM finding_occurrences").fetchone() == (2,)


def test_scan_comparison_requires_saved_matches_and_remains_read_only(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository)
    database = state_dir / "workbench.sqlite3"

    rejected = compare_scan_pair(state_dir, before, after, "--require-matches", check=False)
    assert rejected["returncode"] != 0
    assert "Run 'codex-security scans match BEFORE AFTER' first" in rejected["stderr"]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone() == (0,)

    save_scan_matches(state_dir, before, after)
    with sqlite3.connect(database) as connection:
        comparisons = connection.execute("SELECT * FROM scan_comparisons").fetchall()
        occurrences = connection.execute("SELECT * FROM finding_occurrences").fetchall()

    reversed_comparison = compare_scan_pair(
        state_dir, after, before, "--require-matches", check=False
    )
    assert reversed_comparison["returncode"] != 0
    assert (
        f"These scans are in the wrong order. "
        f"Run 'codex-security scans compare {before['scanId']} {after['scanId']}'."
        in reversed_comparison["stderr"]
    )

    compared = compare_scan_pair(state_dir, before, after, "--require-matches")
    assert compared["summary"]["new"] == compared["summary"]["resolved"] == 1
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT * FROM scan_comparisons").fetchall() == comparisons
        assert connection.execute("SELECT * FROM finding_occurrences").fetchall() == occurrences


def test_list_unmatched_scan_pairs_groups_pending_pairs_and_skips_saved_results(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    first, second, third = (create_cli_scan(state_dir, root, repository) for _ in range(3))
    save_scan_matches(state_dir, first, second)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE finding_occurrences SET details_json = '{}' WHERE scan_id = ?",
            (first["scanId"],),
        )

    pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert pending["repository"] == str(repository.resolve())
    assert pending["scanCount"] == 3
    assert pending["skippedPairs"] == 1
    assert pending["unavailableScans"] == 0
    assert [batch["afterScanId"] for batch in pending["batches"]] == [third["scanId"]]
    assert [[scan["scanId"] for scan in batch["beforeScans"]] for batch in pending["batches"]] == [
        [first["scanId"], second["scanId"]],
    ]
    assert pending["batches"][0]["beforeScans"][0]["findings"][0]["rootCause"]["summary"]

    forced = run_workbench(
        state_dir, "list-unmatched-scan-pairs", "--repository", str(repository), "--force"
    )
    assert forced["scanCount"] == 3
    assert forced["skippedPairs"] == 0
    assert forced["unavailableScans"] == 0
    assert [[scan["scanId"] for scan in batch["beforeScans"]] for batch in forced["batches"]] == [
        [first["scanId"]],
        [first["scanId"], second["scanId"]],
    ]


def test_list_unmatched_scan_pairs_skips_unavailable_scan_artifacts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    first, unavailable, last = (create_cli_scan(state_dir, root, repository) for _ in range(3))
    save_scan_matches(state_dir, first, last)
    shutil.rmtree(unavailable["scanDir"])

    pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert pending["scanCount"] == 3
    assert pending["unavailableScans"] == 1
    assert pending["skippedPairs"] == 1
    assert pending["batches"] == []

    forced = run_workbench(
        state_dir, "list-unmatched-scan-pairs", "--repository", str(repository), "--force"
    )
    assert forced["scanCount"] == 3
    assert forced["unavailableScans"] == 1
    assert forced["skippedPairs"] == 0
    assert len(forced["batches"]) == 1
    assert forced["batches"][0]["afterScanId"] == last["scanId"]
    assert forced["batches"][0]["beforeScans"][0]["scanId"] == first["scanId"]


def test_semantic_scan_comparison_caches_matches_and_exposes_related_findings(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(
        state_dir,
        root,
        repository,
        identity_anchor="archive-extraction-missing-destination-containment",
    )
    baseline = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert baseline["matchingCached"] is False
    assert baseline["summary"]["new"] == 1
    assert baseline["summary"]["resolved"] == 1
    unmatched = run_workbench(state_dir, "get-scan", "--scan-id", before["scanId"])["scan"][
        "findings"
    ][0]
    assert "knownSince" not in unmatched
    assert "knownScanIds" not in unmatched
    previous = baseline["matchingInputs"]["before"][0]
    current = baseline["matchingInputs"]["after"][0]
    assert previous["codeEvidence"][0]["code"] == "destination.write_bytes(entry.read())"
    assert current["rootCause"]["summary"]
    sealed_findings = Path(after["scanDir"]) / "findings.json"
    sealed_manifest = Path(after["scanDir"]) / "scan-manifest.json"
    original_findings = sealed_findings.read_bytes()
    original_manifest = sealed_manifest.read_bytes()

    saved = save_scan_matches(
        state_dir,
        before,
        after,
        confirmed_match(
            previous["occurrenceId"],
            current["occurrenceId"],
            "Both describe the same missing archive containment control.",
        ),
    )
    assert saved["summary"] == {
        "new": 0,
        "persisting": 1,
        "resolved": 0,
        "reopened": 0,
        "unknown": 0,
    }
    assert saved["findings"][0]["beforeOccurrenceId"] == previous["occurrenceId"]
    assert saved["findings"][0]["afterOccurrenceId"] == current["occurrenceId"]
    assert "archive containment" in saved["findings"][0]["matchReason"]
    assert "matchingInputs" not in saved
    assert sealed_findings.read_bytes() == original_findings
    assert sealed_manifest.read_bytes() == original_manifest

    cached = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert cached["matchingCached"] is True
    assert cached["matchingInputs"]["before"][0]["occurrenceId"] == previous["occurrenceId"]

    before_finding = run_workbench(state_dir, "get-scan", "--scan-id", before["scanId"])["scan"][
        "findings"
    ][0]
    after_finding = run_workbench(state_dir, "get-scan", "--scan-id", after["scanId"])["scan"][
        "findings"
    ][0]
    assert before_finding["matches"] == [
        {
            "findingId": current["findingId"],
            "occurrenceId": current["occurrenceId"],
            "reason": "Both describe the same missing archive containment control.",
            "scanId": after["scanId"],
            "title": current["title"],
        }
    ]
    assert after_finding["matches"][0]["occurrenceId"] == previous["occurrenceId"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        known_since = connection.execute(
            "SELECT MIN(started_at) FROM scans WHERE id IN (?, ?)",
            (before["scanId"], after["scanId"]),
        ).fetchone()[0]
    assert before_finding["knownSince"] == known_since
    assert after_finding["knownSince"] == known_since
    assert before_finding["knownScanIds"] == [before["scanId"], after["scanId"]]
    assert after_finding["knownScanIds"] == [before["scanId"], after["scanId"]]

    latest = create_cli_scan(state_dir, root, repository)
    latest_finding = compare_scan_pair(state_dir, after, latest, "--include-matching-inputs")[
        "matchingInputs"
    ]["after"][0]
    save_scan_matches(
        state_dir,
        after,
        latest,
        confirmed_match(current["occurrenceId"], latest_finding["occurrenceId"]),
    )
    for scan in (before, after, latest):
        finding = run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"][
            "findings"
        ][0]
        assert finding["knownScanIds"] == [before["scanId"], latest["scanId"]]
        assert finding["knownSince"] == known_since

    save_scan_matches(
        state_dir,
        before,
        latest,
        confirmed_match(previous["occurrenceId"], latest_finding["occurrenceId"]),
    )
    latest_finding = run_workbench(state_dir, "get-scan", "--scan-id", latest["scanId"])["scan"][
        "findings"
    ][0]
    assert latest_finding["knownScanIds"] == [before["scanId"], latest["scanId"]]
    assert latest_finding["knownSince"] == known_since


def test_semantic_scan_matching_backfills_legacy_finding_details(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository)
    database = state_dir / "workbench.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE finding_occurrences SET details_json = '{}' WHERE scan_id IN (?, ?)",
            (before["scanId"], after["scanId"]),
        )

    compare_scan_pair(state_dir, before, after)
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE details_json = '{}'"
        ).fetchone() == (2,)

    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]

    for finding in (inputs["before"][0], inputs["after"][0]):
        assert finding["rootCause"]["summary"]
        assert finding["codeEvidence"][0]["code"] == "destination.write_bytes(entry.read())"


def test_semantic_scan_comparison_supports_one_to_many_without_copying_triage(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(
        state_dir,
        root,
        repository,
        extra_anchors=("archive-extraction-second-reachable-write",),
    )
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]
    current = inputs["after"]
    assert len(current) == 2
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.executemany(
            "UPDATE finding_occurrences SET severity = ? WHERE id = ?",
            (("low", current[0]["occurrenceId"]), ("critical", current[1]["occurrenceId"])),
        )
    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        previous["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "The reported paths are already contained.",
    )

    saved = save_scan_matches(
        state_dir,
        before,
        after,
        confirmed_match(
            previous["occurrenceId"],
            [finding["occurrenceId"] for finding in current],
            "A single containment fix closes both reported paths.",
        ),
    )
    assert saved["summary"]["persisting"] == 1
    assert saved["summary"]["new"] == 0
    assert saved["findings"][0]["severity"] == "critical"
    assert saved["findings"][0]["title"] == current[1]["title"]
    assert saved["findings"][0]["beforeOccurrenceId"] == previous["occurrenceId"]
    assert set(saved["findings"][0]["afterOccurrenceIds"]) == {
        finding["occurrenceId"] for finding in current
    }
    prior = run_workbench(state_dir, "get-scan", "--scan-id", before["scanId"])["scan"]["findings"][
        0
    ]
    assert len(prior["matches"]) == 2
    assert prior["triage"]["closeReason"] == "false_positive"
    assert prior["triage"]["status"] == "closed"
    later = run_workbench(state_dir, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"]
    assert all(finding["triage"]["status"] == "open" for finding in later)


def test_uncertain_semantic_scan_matches_stay_separate(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository)
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]
    current = inputs["after"][0]
    assert previous["findingId"] == current["findingId"]

    compared = save_scan_matches(
        state_dir,
        before,
        after,
        uncertain=(
            {
                "beforeOccurrenceId": previous["occurrenceId"],
                "afterOccurrenceId": current["occurrenceId"],
                "reason": "The reports may describe independently reachable writes.",
            },
        ),
    )
    assert compared["summary"]["unknown"] == 2
    assert compared["summary"]["persisting"] == 0
    assert all(finding["status"] == "unknown" for finding in compared["findings"])
    assert all("independently reachable" in finding["reason"] for finding in compared["findings"])
    shown = run_workbench(state_dir, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"][
        0
    ]
    assert "matches" not in shown
    assert "knownSince" not in shown
    assert "knownScanIds" not in shown


def test_semantic_scan_comparison_replaces_cached_matches_atomically(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(
        state_dir,
        root,
        repository,
        identity_anchor="archive-extraction-equivalent-root-cause",
    )
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]["occurrenceId"]
    current = inputs["after"][0]["occurrenceId"]
    save_scan_matches(state_dir, before, after, confirmed_match(previous, current))
    compared = save_scan_matches(state_dir, before, after)

    assert compared["summary"]["resolved"] == 1
    assert compared["summary"]["new"] == 1
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM scan_comparison_matches").fetchone() == (0,)
    shown = run_workbench(state_dir, "get-scan", "--scan-id", before["scanId"])["scan"]["findings"][
        0
    ]
    assert "matches" not in shown


def test_semantic_scan_comparison_rejects_cross_target_scans(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    before_repository = tmp_path / "before"
    after_repository = tmp_path / "after"
    before_revision = initialize_git_repository(before_repository)
    after_revision = initialize_git_repository(after_repository)
    for repository, origin in (
        (before_repository, "https://github.com/a/b"),
        (after_repository, "https://github.com/a/other"),
    ):
        subprocess.run(
            ["git", "-C", str(repository), "remote", "add", "origin", origin], check=True
        )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", before_repository, target_revision=before_revision
    )
    after = create_cli_scan(
        state_dir, tmp_path / "after-results", after_repository, target_revision=after_revision
    )

    for command, arguments in (
        ("compare-scans", ("--include-matching-inputs",)),
        ("compare-scans", ("--require-matches",)),
        ("save-scan-comparison", ("--matches-json", '{"matches":[],"uncertain":[]}')),
    ):
        rejected = run_workbench(
            state_dir,
            command,
            "--before-scan-id",
            before["scanId"],
            "--after-scan-id",
            after["scanId"],
            *arguments,
            check=False,
        )
        assert rejected["returncode"] != 0
        assert "same repository target" in rejected["stderr"]


def test_semantic_scan_comparison_accepts_linked_git_worktrees(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    linked_worktree = tmp_path / "linked-worktree"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked_worktree)],
        check=True,
    )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", repository, target_revision=revision
    )
    after = create_cli_scan(
        state_dir, tmp_path / "after-results", linked_worktree, target_revision=revision
    )
    for target in (repository, linked_worktree):
        pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(target))
        assert pending["scanCount"] == 2
        assert pending["batches"][0]["afterScanId"] == after["scanId"]
        assert pending["batches"][0]["beforeScans"][0]["scanId"] == before["scanId"]

    compared = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert compared["summary"]["new"] == 1
    assert compared["summary"]["resolved"] == 1

    saved = save_scan_matches(
        state_dir,
        before,
        after,
        confirmed_match(
            compared["matchingInputs"]["before"][0]["occurrenceId"],
            compared["matchingInputs"]["after"][0]["occurrenceId"],
        ),
    )
    assert saved["summary"]["persisting"] == 1


def test_semantic_scan_comparison_accepts_matching_git_origins(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    before_repository = tmp_path / "before"
    after_repository = tmp_path / "after"
    before_revision = initialize_git_repository(before_repository)
    after_revision = initialize_git_repository(after_repository)
    for repository, origin in (
        (before_repository, "https://user:token@GITHUB.com/example/project.git"),
        (after_repository, "git@github.com:example/project"),
    ):
        subprocess.run(
            ["git", "-C", str(repository), "remote", "add", "origin", origin], check=True
        )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", before_repository, target_revision=before_revision
    )
    after = create_cli_scan(
        state_dir, tmp_path / "after-results", after_repository, target_revision=after_revision
    )
    for target in (before_repository, after_repository):
        pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(target))
        assert pending["scanCount"] == 2
        assert pending["batches"][0]["afterScanId"] == after["scanId"]
        assert pending["batches"][0]["beforeScans"][0]["scanId"] == before["scanId"]

    compared = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert compared["summary"]["new"] == 1
    assert compared["summary"]["resolved"] == 1

    saved = save_scan_matches(state_dir, before, after)
    assert saved["summary"]["new"] == 1


def test_semantic_scan_comparison_rejects_unknown_overlapping_and_uncertain_groups(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository)
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]["occurrenceId"]
    current = inputs["after"][0]["occurrenceId"]
    confirmed = confirmed_match(previous, current)
    uncertain = {
        "beforeOccurrenceId": previous,
        "afterOccurrenceId": current,
        "reason": "Possibly the same root issue.",
    }
    rejected_payloads = (
        {"matches": [{**confirmed, "afterOccurrenceIds": ["occ_unknown"]}], "uncertain": []},
        {"matches": [confirmed, confirmed], "uncertain": []},
        {"matches": [confirmed], "uncertain": [uncertain]},
        {"matches": [], "uncertain": [uncertain, uncertain]},
    )
    for payload in rejected_payloads:
        rejected = run_workbench(
            state_dir,
            "save-scan-comparison",
            "--before-scan-id",
            before["scanId"],
            "--after-scan-id",
            after["scanId"],
            "--matches-json",
            json.dumps(payload),
            check=False,
        )
        assert rejected["returncode"] != 0

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone() == (0,)


def test_cli_scan_comparison_requires_complete_matching_path_coverage(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "tests").mkdir()
    root = tmp_path / "results"
    original = create_cli_scan(state_dir, root, repository, paths=["src"])
    partial = create_cli_scan(
        state_dir, root, repository, finding=False, completeness="partial", paths=["src"]
    )
    other_scope = create_cli_scan(state_dir, root, repository, finding=False, paths=["tests"])
    deep = create_cli_scan(state_dir, root, repository, mode="deep")
    explicit_root = create_cli_scan(state_dir, root, repository, paths=["."])
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", deep["scanId"])["scan"]["progress"][
            "status"
        ]
        == "complete"
    )
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", explicit_root["scanId"])["scan"][
            "progress"
        ]["status"]
        == "complete"
    )

    for later in (partial, other_scope):
        compared = run_workbench(
            state_dir,
            "compare-scans",
            "--before-scan-id",
            original["scanId"],
            "--after-scan-id",
            later["scanId"],
        )
        assert compared["summary"]["unknown"] == 1
        assert compared["summary"]["resolved"] == 0


def test_cli_scan_reruns_reject_other_repository_parents(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    parent = create_cli_scan(state_dir, tmp_path / "results", repository)
    other = tmp_path / "other"
    other.mkdir()
    scan_dir = tmp_path / "other-results"
    scan_dir.mkdir(mode=0o700)
    rejected = run_workbench(
        state_dir,
        "register-cli-scan",
        "--scan-dir",
        str(scan_dir),
        "--repository",
        str(other),
        "--recipe-json",
        json.dumps(
            {
                "config": {},
                "mode": "standard",
                "repository": str(other),
                "target": {"kind": "repository", "paths": []},
            }
        ),
        "--parent-scan-id",
        parent["scanId"],
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "same repository as its parent" in rejected["stderr"]


def test_cli_diff_launch_accepts_equal_refs_and_distinct_working_tree_base(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    base = initialize_git_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "--allow-empty", "-qm", "head"], check=True
    )
    head = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()

    for kind, base_revision in (("refs", head), ("working_tree", base)):
        launched = create_cli_scan(
            state_dir,
            tmp_path / kind,
            repository,
            complete=False,
            target={"kind": kind, "paths": [], "base": base_revision, "head": head},
        )
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            assert connection.execute(
                "SELECT diff_target_kind, diff_base_revision, diff_head_revision "
                "FROM scans WHERE id = ?",
                (launched["scanId"],),
            ).fetchone() == (
                "range" if kind == "refs" else "working_tree",
                base_revision,
                head,
            )
