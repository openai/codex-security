from __future__ import annotations

import copy
import json
import shutil
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest
from test_workbench_db import HEAD_CHANGED_WARNING
from test_workbench_deep_scan import begin_target_scan
from test_workbench_prompt_only_scan import start_headless_standard_scan, start_prompt_only_scan
from workbench_test_support import (
    fail_scan,
    get_scan,
    initialize_git_repository,
    mark_deep_coordinator_succeeded,
    resume_deep_scan,
    run_workbench,
    scan_command,
    set_triage,
    stable_target_id,
    write_completed_contract,
)

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
FINALIZER = SCRIPT.with_name("finalize_scan_contract.py")


@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("upgrade", [False, True])
def test_rename_persists_without_changing_scan_results(
    tmp_path: Path, complete: bool, upgrade: bool
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "scans", repository, complete=complete)
    before = run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]
    if upgrade:
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute("ALTER TABLE scans DROP COLUMN name")
            connection.execute("DELETE FROM schema_migrations WHERE version = 42")

    renamed = run_workbench(
        state_dir, "rename-scan", "--scan-id", scan["scanId"], "--name=  Release audit  "
    )

    assert renamed == {"scanId": scan["scanId"], "name": "Release audit"}
    after = run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert after == {**before, "name": "Release audit"}
    listed = run_workbench(state_dir, "list-scans", "--query", "release audit")["scans"]
    assert [(item["scanId"], item["name"]) for item in listed] == [
        (scan["scanId"], "Release audit")
    ]


def test_rename_rejects_blank_names(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "scans", repository, complete=False)

    blank = run_workbench(
        state_dir, "rename-scan", "--scan-id", scan["scanId"], "--name=  ", check=False
    )
    assert blank["returncode"] != 0
    assert "Scan name cannot be empty" in blank["stderr"]
    assert run_workbench(state_dir, "get-scan", "--scan-id", scan["scanId"])["scan"]["name"] is None


@pytest.mark.parametrize(
    ("name", "query"),
    [("Évaluation", "évaluation"), ("Straße", "STRASSE"), ("Проверка", "проверка")],
)
def test_scan_name_search_ignores_unicode_case(tmp_path: Path, name: str, query: str) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "scans", repository, complete=False)
    run_workbench(state_dir, "rename-scan", "--scan-id", scan["scanId"], f"--name={name}")

    listed = run_workbench(state_dir, "list-scans", "--query", query)["scans"]

    assert [(item["scanId"], item["name"]) for item in listed] == [(scan["scanId"], name)]


def test_scan_history_search_casefolds_displayed_fields(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "Straße"
    (repository / "Ä").mkdir(parents=True)
    (repository / "Ä" / "source.py").write_text("pass\n")
    scan = start_prompt_only_scan(
        state_dir,
        repository,
        tmp_path / "scans",
        extra_args=("--scope=Ä", "--target-summary=Überblick"),
    )["scan"]
    for query in ("Straße", "STRASSE", "Ä", "ä", "Überblick", "ÜBERBLICK"):
        listed = run_workbench(state_dir, "list-scans", "--query", query)["scans"]
        assert [item["scanId"] for item in listed] == [scan["scanId"]]
    assert run_workbench(state_dir, "list-scans", "--query", "unrelated")["scans"] == []


def test_rename_does_not_reorder_scan_history(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    older = create_cli_scan(state_dir, tmp_path / "scans", repository)
    newer = create_cli_scan(state_dir, tmp_path / "scans", repository)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        for scan, timestamp in (
            (older, "2026-08-01T00:00:00Z"),
            (newer, "2026-08-02T00:00:00Z"),
        ):
            connection.execute(
                "UPDATE scans SET started_at = ?, updated_at = ? WHERE id = ?",
                (timestamp, timestamp, scan["scanId"]),
            )
            connection.execute(
                "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                (timestamp, scan["scanId"]),
            )
    before = run_workbench(state_dir, "list-scans")["scans"]
    assert [scan["scanId"] for scan in before] == [newer["scanId"], older["scanId"]]

    run_workbench(state_dir, "rename-scan", "--scan-id", older["scanId"], "--name=Release audit")

    after = run_workbench(state_dir, "list-scans")["scans"]
    assert after == [before[0], {**before[1], "name": "Release audit"}]


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
        resume_deep_scan(state_dir, launched["scanId"], "thread-scan-history")
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
    fail_scan(state_dir, failed["scanId"], "interrupted")

    assert str(uuid.UUID(first["scanId"])) == first["scanId"]
    assert first["targetId"] == stable_target_id(repository)
    assert first["scanDir"].startswith(str(root))
    detail = get_scan(state_dir, rerun["scanId"])
    assert detail["parentScanId"] == first["scanId"]
    assert detail["recipe"]["target"]["paths"] == ["src", "tests"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT parent_scan_id FROM scans WHERE id = ?", (rerun["scanId"],)
        ).fetchone() == (first["scanId"],)
    assert scan_command(state_dir, "get-scan-recipe", first["scanId"])["recipe"]["config"] == {
        "model": "gpt-5.6-sol",
        "model_reasoning_effort": "high",
    }

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
    initial = get_scan(state_dir, scan["scanId"])["scan"]
    assert initial["threadIds"] == []
    assert initial["executionThreadIds"] == []

    result = scan_command(state_dir, "set-scan-thread", scan["scanId"], "--thread-id", "thread-1")

    assert result == {"scanId": scan["scanId"], "threadId": "thread-1"}
    detail = get_scan(state_dir, scan["scanId"])
    assert detail["scan"]["continuationThreadId"] == "thread-1"
    assert detail["scan"]["threadIds"] == ["thread-1"]
    assert detail["scan"]["executionThreadIds"] == ["thread-1"]


def test_get_scan_keeps_desktop_standard_owners_out_of_execution_roots(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    for start_scan in (start_prompt_only_scan, start_headless_standard_scan):
        repository = tmp_path / start_scan.__name__
        repository.mkdir()
        started = start_scan(
            state_dir, repository, tmp_path / "results", thread_id="desktop-owner"
        )["scan"]
        detail = get_scan(state_dir, started["scanId"])["scan"]
        assert detail["threadIds"] == ["desktop-owner"]
        assert detail["executionThreadIds"] == []
        if start_scan is start_headless_standard_scan:
            assert detail["continuationThreadId"] == "desktop-owner"


def test_get_scan_includes_desktop_deep_worker_threads_without_continuation(tmp_path: Path) -> None:
    state_dir, codex_home = tmp_path / "state", tmp_path / "codex-home"
    repository, other_repository = tmp_path / "repository", tmp_path / "other-repository"
    repository.mkdir()
    other_repository.mkdir()
    scan = begin_target_scan(
        state_dir, codex_home, repository, tmp_path / "results", thread_id="desktop-owner"
    )["deepScan"]
    other = begin_target_scan(
        state_dir, codex_home, other_repository, tmp_path / "results", thread_id="other-owner"
    )["deepScan"]
    workers = [
        (scan["scanId"], "setup", "succeeded", "setup-worker"),
        (scan["scanId"], "discovery", "failed", "failed-worker"),
        (scan["scanId"], "discovery", "canceled", "canceled-worker"),
        (scan["scanId"], "dedup", "running", "dedup-worker"),
        (scan["scanId"], "discovery", "running", "shared-worker"),
        (scan["scanId"], "discovery", "succeeded", "shared-worker"),
        (scan["scanId"], "discovery", "running", "desktop-workspace"),
        (scan["scanId"], "discovery", "queued", None),
        (other["scanId"], "discovery", "failed", "other-worker"),
    ]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE workspaces SET thread_id = 'desktop-workspace' "
            "WHERE id = (SELECT workspace_id FROM scans WHERE id = ?)",
            (scan["scanId"],),
        )
        connection.executemany(
            """
            INSERT INTO deep_scan_workers (
                id, scan_id, kind, status, sdk_thread_id, prompt_path, artifact_dir,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    str(uuid.uuid4()),
                    scan_id,
                    kind,
                    status,
                    thread_id,
                    str(tmp_path / "prompt.md"),
                    str(tmp_path / "artifacts"),
                    scan["createdAt"],
                    scan["createdAt"],
                )
                for scan_id, kind, status, thread_id in workers
            ],
        )

    detail = get_scan(state_dir, scan["scanId"])["scan"]
    assert detail["continuationThreadId"] is None
    assert detail["threadIds"] == [
        "desktop-owner",
        "desktop-workspace",
        "canceled-worker",
        "dedup-worker",
        "failed-worker",
        "setup-worker",
        "shared-worker",
    ]
    assert detail["executionThreadIds"] == [
        "canceled-worker",
        "dedup-worker",
        "desktop-workspace",
        "failed-worker",
        "setup-worker",
        "shared-worker",
    ]

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET continuation_thread_id = 'desktop-headless' WHERE id = ?",
            (scan["scanId"],),
        )
    continued = get_scan(state_dir, scan["scanId"])["scan"]
    assert continued["threadIds"] == ["desktop-headless", *detail["threadIds"]]
    assert continued["executionThreadIds"] == detail["executionThreadIds"]


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

    completed = scan_command(state_dir, "complete-scan", launched["scanId"])

    assert completed["scan"]["progress"]["status"] == "complete"
    assert completed["scan"]["targetRevision"] == revision
    assert completed["scan"]["warnings"] == [HEAD_CHANGED_WARNING]
    assert "41  source line 41" in completed["scan"]["findings"][0]["sourceExcerpt"]
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["target"]["revision"] == revision
    history = run_workbench(state_dir, "list-scans", "--repository", str(repository))
    assert history["scans"][0]["warnings"] == completed["scan"]["warnings"]


@pytest.mark.parametrize("context_reporting", ["bounded", "unknown_upper", "legacy"])
def test_cli_scan_history_persists_per_scan_cost(tmp_path: Path, context_reporting: str) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    cost = {
        "model": "gpt-5.6-sol",
        "inputTokens": 1250,
        "cachedInputTokens": 200,
        "cacheWriteInputTokens": 0,
        "outputTokens": 30,
        "estimatedUsd": 0.00488,
        "cacheWriteInputTokensReported": False,
        "pricing": {
            "source": "https://developers.openai.com/api/docs/pricing",
            "asOf": "2026-09-09" if context_reporting == "legacy" else "2026-09-14",
            "serviceTier": "standard",
            "context": "short",
            "usdPerMillionTokens": {"input": 4, "cacheRead": 0.4, "cacheWrite": 5, "output": 20},
        },
    }
    if context_reporting != "legacy":
        cost["estimatedUsdRange"] = {
            "min": 0.00488,
            "max": 0.01156 if context_reporting == "bounded" else None,
            "context": "unknown",
        }
    if context_reporting == "bounded":
        cost["pricing"]["longContextUsdPerMillionTokens"] = {
            "input": 8,
            "cacheRead": 0.8,
            "cacheWrite": 10,
            "output": 30,
        }
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, cost=cost)

    listed = run_workbench(state_dir, "list-scans", "--repository", str(repository))
    assert listed["scans"][0]["cost"] == cost
    assert get_scan(state_dir, scan["scanId"])["scan"]["cost"] == cost
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

    completed = scan_command(
        state_dir, "complete-scan", scan["scanId"], "--cost-json", json.dumps(cost)
    )

    assert completed["scan"]["cost"] == cost
    assert completed["scan"]["usage"]["inputTokens"] == 5_000
    assert get_scan(state_dir, scan["scanId"])["scan"]["cost"] == cost


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

    failed = fail_scan(
        state_dir,
        scan["scanId"],
        "Scan stopped: cost limit exceeded.",
        "--cost-json",
        json.dumps(cost),
    )

    assert failed["scan"]["cost"] == cost
    assert failed["scan"]["progress"]["status"] == "failed"
    assert run_workbench(state_dir, "list-scans")["scans"][0]["cost"] == cost
    assert get_scan(state_dir, scan["scanId"])["scan"]["cost"] == cost


def test_scan_failure_rejects_invalid_cost_without_stopping_the_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, complete=False)

    rejected = fail_scan(
        state_dir, scan["scanId"], "Scan stopped.", "--cost-json", "{}", check=False
    )

    assert rejected["returncode"] != 0
    assert "Scan cost" in rejected["stderr"]
    assert get_scan(state_dir, scan["scanId"])["scan"]["progress"]["status"] == "running"


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
        rejected = scan_command(
            state_dir, "complete-scan", scan["scanId"], "--cost-json", value, check=False
        )
        assert rejected["returncode"] != 0
        assert "Scan cost" in rejected["stderr"]

    assert "cost" not in get_scan(state_dir, scan["scanId"])["scan"]


def test_scan_history_resolves_unique_prefixes_and_rejects_ambiguity(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    scan = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(state_dir, root, repository)
    prefix = scan["scanId"][:8]
    after_prefix = after["scanId"][:8]

    assert get_scan(state_dir, prefix)["scan"]["scanId"] == scan["scanId"]
    assert scan_command(state_dir, "get-scan-recipe", prefix)["scanId"] == scan["scanId"]
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
        ambiguous_scan_id = f"{prefix}-ffff-4000-8000-000000000000"
        timestamp = "2026-07-24T00:00:00Z"
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
                ambiguous_scan_id,
                workspace_id,
                "/tmp/target",
                "fixture-revision",
                ".",
                "standard",
                f"/tmp/scans/{ambiguous_scan_id}",
                "complete",
                "reporting",
                "delivered",
                None,
                timestamp,
                timestamp,
                timestamp,
                timestamp,
                None,
                None,
            ),
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
    assert get_scan(state_dir, scan["scanId"])["scan"]["scanId"] == scan["scanId"]


def test_scan_list_shares_worktree_history_without_including_clones(tmp_path: Path) -> None:
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

    for target in (repository, worktree):
        scans = run_workbench(state_dir, "list-scans", "--repository", str(target))["scans"]
        assert [scan["scanId"] for scan in scans] == [
            worktree_scan["scanId"],
            original_scan["scanId"],
        ]

    for offset, expected in enumerate((worktree_scan, original_scan)):
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
        assert page["nextOffset"] == (offset + 1 if offset < 1 else None)

    queried = run_workbench(
        state_dir, "list-scans", "--repository", str(repository), "--query", "clone"
    )["scans"]
    assert queried == []
    clone_history = run_workbench(state_dir, "list-scans", "--repository", str(clone))["scans"]
    assert [scan["scanId"] for scan in clone_history] == [clone_scan["scanId"]]

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
    set_triage(state_dir, occurrence, "closed", "--close-reason", "already_fixed")
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
        assert connection.execute("SELECT COUNT(*) FROM scan_comparison_matches").fetchone() == (0,)
        known_since = connection.execute("SELECT MIN(started_at) FROM scans").fetchone()[0]

    before_finding, after_finding = (
        get_scan(state_dir, scan["scanId"])["scan"]["findings"][0] for scan in (before, after)
    )
    assert before_finding["findingId"] == after_finding["findingId"]
    for finding, other in ((before_finding, after_finding), (after_finding, before_finding)):
        assert [match["occurrenceId"] for match in finding["matches"]] == [other["occurrenceId"]]
        assert finding["knownSince"] == known_since
        assert finding["knownScanIds"] == [before["scanId"], after["scanId"]]

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
    assert compared["summary"]["persisting"] == 1
    assert compared["summary"]["new"] == compared["summary"]["resolved"] == 0
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
    unmatched = get_scan(state_dir, before["scanId"])["scan"]["findings"][0]
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

    before_finding = get_scan(state_dir, before["scanId"])["scan"]["findings"][0]
    after_finding = get_scan(state_dir, after["scanId"])["scan"]["findings"][0]
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
        finding = get_scan(state_dir, scan["scanId"])["scan"]["findings"][0]
        assert finding["knownScanIds"] == [before["scanId"], latest["scanId"]]
        assert finding["knownSince"] == known_since

    save_scan_matches(
        state_dir,
        before,
        latest,
        confirmed_match(previous["occurrenceId"], latest_finding["occurrenceId"]),
    )
    latest_finding = get_scan(state_dir, latest["scanId"])["scan"]["findings"][0]
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
    set_triage(
        state_dir,
        previous["occurrenceId"],
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
    prior = get_scan(state_dir, before["scanId"])["scan"]["findings"][0]
    assert len(prior["matches"]) == 2
    assert prior["triage"]["closeReason"] == "false_positive"
    assert prior["triage"]["status"] == "closed"
    later = get_scan(state_dir, after["scanId"])["scan"]["findings"]
    assert all(finding["triage"]["status"] == "open" for finding in later)


def test_uncertain_semantic_scan_matches_stay_separate(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository)
    after = create_cli_scan(
        state_dir, root, repository, identity_anchor="independent-archive-entry-write"
    )
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]
    current = inputs["after"][0]
    assert previous["findingId"] != current["findingId"]

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
    shown = get_scan(state_dir, after["scanId"])["scan"]["findings"][0]
    assert "matches" not in shown
    assert "knownSince" not in shown
    assert "knownScanIds" not in shown


@pytest.mark.parametrize("reverse", (False, True))
def test_semantic_scan_comparison_replaces_cached_matches_atomically(
    tmp_path: Path, reverse: bool
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
        identity_anchor="archive-extraction-equivalent-root-cause",
    )
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]["occurrenceId"]
    current = inputs["after"][0]["occurrenceId"]
    if reverse:
        save_scan_matches(state_dir, after, before, confirmed_match(current, previous))
    else:
        save_scan_matches(state_dir, before, after, confirmed_match(previous, current))
    compared = save_scan_matches(state_dir, before, after)

    assert compared["summary"]["resolved"] == 1
    assert compared["summary"]["new"] == 1
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM scan_comparison_matches").fetchone() == (0,)
    shown = get_scan(state_dir, before["scanId"])["scan"]["findings"][0]
    assert "matches" not in shown
    assert len(run_workbench(state_dir, "list-global-findings")["findings"]) == 2


@pytest.mark.parametrize("indirect", (False, True))
def test_replacing_reverse_comparison_preserves_other_pairs_and_triage(
    tmp_path: Path, indirect: bool
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scans = [
        create_cli_scan(state, tmp_path / "results", repository, identity_anchor=f"root-{index}")
        for index in range(4)
    ]
    occurrences = [get_scan(state, scan["scanId"])["scan"]["findings"][0] for scan in scans]

    def match(before: int, after: int) -> None:
        save_scan_matches(
            state,
            scans[before],
            scans[after],
            confirmed_match(
                occurrences[before]["occurrenceId"], occurrences[after]["occurrenceId"]
            ),
        )

    match(1, 0)
    match(2, 3)
    if indirect:
        match(0, 2)
        match(2, 1)
    set_triage(
        state,
        occurrences[0]["occurrenceId"],
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Accepted synthetic risk.",
    )
    artifacts = {
        path: path.read_bytes()
        for scan in scans
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
        for path in (Path(scan["scanDir"]) / name,)
    }
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        comparisons = connection.execute("SELECT * FROM scan_comparisons ORDER BY 1, 2").fetchall()
        links = connection.execute("SELECT * FROM scan_comparison_matches ORDER BY 1, 2").fetchall()
        triage = connection.execute(
            "SELECT * FROM finding_triage ORDER BY occurrence_id"
        ).fetchall()
        stored_occurrences = connection.execute(
            "SELECT * FROM finding_occurrences ORDER BY id"
        ).fetchall()
    old_pair = (scans[1]["scanId"], scans[0]["scanId"])

    save_scan_matches(state, scans[0], scans[1])

    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        remaining = connection.execute("SELECT * FROM scan_comparisons ORDER BY 1, 2").fetchall()
        new_pair = (scans[0]["scanId"], scans[1]["scanId"])
        assert [row for row in remaining if row[:2] != new_pair] == [
            row for row in comparisons if row[:2] != old_pair
        ]
        assert len([row for row in remaining if row[:2] == new_pair]) == 1
        assert connection.execute(
            "SELECT * FROM scan_comparison_matches ORDER BY 1, 2"
        ).fetchall() == [row for row in links if row[:2] != old_pair]
        assert (
            connection.execute("SELECT * FROM finding_triage ORDER BY occurrence_id").fetchall()
            == triage
        )
        assert (
            connection.execute("SELECT * FROM finding_occurrences ORDER BY id").fetchall()
            == stored_occurrences
        )
    findings = run_workbench(state, "list-global-findings")["findings"]
    groups = {frozenset(finding["knownScanIds"]) for finding in findings}
    assert groups == (
        {frozenset(scan["scanId"] for scan in scans)}
        if indirect
        else {
            frozenset([scans[0]["scanId"]]),
            frozenset([scans[1]["scanId"]]),
            frozenset([scans[2]["scanId"], scans[3]["scanId"]]),
        }
    )
    assert all(path.read_bytes() == content for path, content in artifacts.items())


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
        assert pending["scanCount"] == 1
        assert pending["batches"] == []

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
    assert get_scan(state_dir, deep["scanId"])["scan"]["progress"]["status"] == "complete"
    assert get_scan(state_dir, explicit_root["scanId"])["scan"]["progress"]["status"] == "complete"

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


def test_history_repair_matches_legacy_generation_in_owned_checkout(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    first = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    second = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation = NULL WHERE id = ?", (first["scanId"],)
        )
    pending = run_workbench(state, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert len(pending["batches"]) == 1
    assert pending["batches"][0]["afterScanId"] == second["scanId"]
    assert pending["batches"][0]["beforeScans"][0]["scanId"] == first["scanId"]


@pytest.mark.parametrize("remove_checkout", (False, True))
def test_history_repair_keeps_triage_across_legacy_match(
    tmp_path: Path, remove_checkout: bool
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    first = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-prior-anchor",
    )
    second = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-current-anchor",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation = NULL WHERE id = ?", (first["scanId"],)
        )
    inputs = compare_scan_pair(state, first, second, "--include-matching-inputs")["matchingInputs"]
    prior = inputs["before"][0]["occurrenceId"]
    current = inputs["after"][0]["occurrenceId"]
    save_scan_matches(state, first, second, confirmed_match(prior, current))
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        prior,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "The synthetic finding is already prevented by its checked guard.",
    )
    current = create_cli_scan(
        state, tmp_path / "results", repository, target_revision=revision, finding=False
    )
    feedback = run_workbench(state, "get-scan-feedback", "--scan-id", current["scanId"])
    assert len(feedback["falsePositives"]) == 1
    assert (
        feedback["falsePositives"][0]["reason"]
        == "The synthetic finding is already prevented by its checked guard."
    )
    if remove_checkout:
        repository.rename(tmp_path / "archived-checkout")
    rows = run_workbench(state, "list-global-findings", "--repository", str(repository))["findings"]
    assert len(rows) == 1
    assert rows[0]["status"] == "closed"
    assert rows[0]["occurrenceCount"] == 2
    assert len(rows[0]["matchedFindingIds"]) == 2
    assert run_workbench(state, "list-repositories")["repositories"][0]["openFindingsCount"] == 0


def test_history_repair_uses_completion_horizon_for_focused_matching(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    first = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-first-anchor",
    )
    second = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-second-anchor",
    )
    inputs = compare_scan_pair(state, first, second, "--include-matching-inputs")["matchingInputs"]
    save_scan_matches(
        state,
        first,
        second,
        confirmed_match(inputs["before"][0]["occurrenceId"], inputs["after"][0]["occurrenceId"]),
    )
    focused = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-focused-anchor",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2026-01-01T00:00:00Z' WHERE id = ?",
            (focused["scanId"],),
        )
    pending = run_workbench(
        state,
        "list-unmatched-scan-pairs",
        "--repository",
        str(repository),
        "--after-scan-id",
        focused["scanId"],
    )
    assert len(pending["batches"]) == 1
    groups = pending["batches"][0].get("knownFindingGroups", [])
    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_history_repair_rebinds_only_unscanned_workspace(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    workspace = str(uuid.uuid4())
    created = run_workbench(
        state, "create-workspace", "--workspace-id", workspace, "--target-path", str(repository)
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        old = connection.execute(
            "SELECT id, repository_identity FROM security_targets WHERE current_path = ?",
            (str(repository),),
        ).fetchone()
    (repository / ".git").rename(tmp_path / "previous-git")
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace,
        "--target-path",
        str(repository),
        "--scope",
        ".",
        "--mode",
        "deep",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        new = connection.execute(
            "SELECT id, repository_identity FROM security_targets WHERE current_path = ?",
            (str(repository),),
        ).fetchone()
    assert old is not None and new is not None
    assert new[0] == old[0]
    assert new[1] != old[1]
    assert created["targetMetadata"]["isGit"] is True


def test_history_repair_counts_only_each_worktrees_legacy_findings(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    linked = tmp_path / "linked"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)], check=True
    )
    legacy = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation = NULL WHERE id = ?", (legacy["scanId"],)
        )
    create_cli_scan(state, tmp_path / "results", linked, target_revision=revision, finding=False)
    counts = {
        row["targetPath"]: row["openFindingsCount"]
        for row in run_workbench(state, "list-repositories")["repositories"]
    }
    assert (
        counts[str(repository)]
        == len(
            run_workbench(state, "list-global-findings", "--repository", str(repository))[
                "findings"
            ]
        )
        == 1
    )
    assert (
        counts[str(linked)]
        == len(
            run_workbench(state, "list-global-findings", "--repository", str(linked))["findings"]
        )
        == 0
    )


def test_history_repair_rebinds_unscanned_directory(tmp_path: Path) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    workspace = str(uuid.uuid4())
    run_workbench(
        state, "create-workspace", "--workspace-id", workspace, "--target-path", str(repository)
    )
    (repository / ".git").rename(tmp_path / "previous-git")
    run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace,
        "--target-path",
        str(repository),
        "--scope",
        ".",
        "--mode",
        "standard",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT repository_identity FROM security_targets WHERE current_path = ?",
                (str(repository),),
            ).fetchone()[0]
            is None
        )
    create_cli_scan(state, tmp_path / "results", repository)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-07-01T00:00:00Z",
        "2026-07-01T00:00:00z",
        "2026-07-01t00:00:00z",
        "2026-07-01T00:00:00+00:00",
        "2026-06-30T19:00:00-05:00",
    ],
)
def test_history_timestamp_preserves_utc_completion_order(workbench_api, timestamp):
    target_state = sys.modules["workbench_target_state"]
    assert target_state._timestamp_ns(timestamp) == 1782864000000000000


@pytest.mark.parametrize(
    ("digits", "prefix"),
    [(digits, "") for digits in [1, 2, 3, 4, 5, 6, 7, 10, 40, 5000]] + [(7, "123456")],
)
def test_history_timestamp_preserves_fractional_order_and_ownership(workbench_api, digits, prefix):
    target_state = sys.modules["workbench_target_state"]
    history = sys.modules["workbench_scan_history"]
    fraction = prefix.ljust(digits - 1, "0")
    earlier = f"1970-01-01T00:00:00.{fraction}1z"
    later = f"1970-01-01T01:00:00.{fraction}2+01:00"
    # Persisted rows can have been finalized by a newer Python runtime.
    for field in ("completed_at", "started_at"):
        scans = [{"id": "b", field: earlier}, {"id": "a", field: later}]
        assert sorted(scans, key=history._scan_completion_order) == scans
    timestamp = target_state._timestamp_ns(earlier)
    assert timestamp is not None
    birth = int((fraction + "1")[:9].ljust(9, "0"))
    assert birth <= timestamp < birth + 1
    scan = {"started_at": earlier, "created_at": earlier}
    for birth_time, expected in ((birth, True), (birth + 1, False)):
        identity = target_state.GitRepositoryIdentity("repository", ".", "common", 1, 2, birth_time)
        assert target_state._repository_predates_history(identity, [scan]) is expected


@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        "invalid",
        "2026-07-01T00:00:00",
        "2026-07-01.1+00:00",
        "1970-01-01T00:00:00.1Z\n",
        "1970-01-01T00:00:00.1234567+00:00\n",
        "1970-01-01T00:00:00.١23456Z",
    ],
)
def test_history_timestamp_keeps_unavailable_completion_order(workbench_api, timestamp):
    target_state = sys.modules["workbench_target_state"]
    assert target_state._timestamp_ns(timestamp) is None


@pytest.mark.parametrize("matched", (False, True))
@pytest.mark.parametrize("legacy_representative", (False, True))
def test_matched_repository_confirmation_uses_all_saved_repository_buckets(
    tmp_path: Path, matched: bool, legacy_representative: bool
) -> None:
    state = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    before = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-legacy-anchor",
    )
    after = create_cli_scan(
        state,
        tmp_path / "results",
        repository,
        target_revision=revision,
        identity_anchor="synthetic-current-anchor",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET repository_generation = NULL WHERE id = ?", (before["scanId"],)
        )
        # Preserve the two possible imported report orders independently of completion order.
        for scan, timestamp in (
            (before, "2026-09-02T00:00:00Z" if legacy_representative else "2026-09-01T00:00:00Z"),
            (after, "2026-09-01T00:00:00Z" if legacy_representative else "2026-09-02T00:00:00Z"),
        ):
            connection.execute(
                "UPDATE finding_occurrences SET created_at = ? WHERE scan_id = ?",
                (timestamp, scan["scanId"]),
            )
    if matched:
        inputs = compare_scan_pair(state, before, after, "--include-matching-inputs")[
            "matchingInputs"
        ]
        save_scan_matches(
            state,
            before,
            after,
            confirmed_match(
                inputs["before"][0]["occurrenceId"], inputs["after"][0]["occurrenceId"]
            ),
        )
    create_cli_scan(
        state, tmp_path / "results", repository, target_revision=revision, finding=False
    )
    global_findings = run_workbench(state, "list-global-findings")["findings"]
    legacy = next(
        finding for finding in global_findings if before["scanId"] in finding["knownScanIds"]
    )
    assert legacy["confirmedInLatestScan"] is (not matched)
    if matched:
        assert len(global_findings) == 1
        assert set(legacy["knownScanIds"]) == {before["scanId"], after["scanId"]}
        scoped = run_workbench(state, "list-global-findings", "--repository", str(repository))[
            "findings"
        ]
        assert len(scoped) == 1
        assert scoped[0]["confirmedInLatestScan"] is False


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_portable_identity_allows_git_initialization_after_plain_directory_history(
    tmp_path: Path, mode: str
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "README.md").write_text("fixture\n")
    state = tmp_path / "state"
    before = create_cli_scan(state, tmp_path / "results", repository, mode=mode)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT target_revision FROM scans WHERE id = ?", (before["scanId"],)
            ).fetchone()[0]
            == "unversioned"
        )
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "add", "."],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "Initialize repository",
        ],
        cwd=repository,
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    after = create_cli_scan(
        state, tmp_path / "results", repository, mode=mode, target_revision=revision
    )
    assert compare_scan_pair(state, before, after)["afterScanId"] == after["scanId"]


@pytest.mark.parametrize("same_origin", (True, False))
def test_portable_identity_explicit_clone_comparison_without_birth_timestamps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, same_origin: bool
) -> None:
    import argparse

    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_scan_history as history
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://example.test/synthetic/project.git"],
        cwd=repository,
        check=True,
    )
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(repository), str(clone)], check=True)
    subprocess.run(
        [
            "git",
            "remote",
            "set-url",
            "origin",
            "https://example.test/synthetic/project.git"
            if same_origin
            else "https://example.test/synthetic/other.git",
        ],
        cwd=clone,
        check=True,
    )
    state = tmp_path / "state"
    before = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    after = create_cli_scan(state, tmp_path / "results", clone, target_revision=revision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE scans SET repository_generation = NULL")
        connection.execute("UPDATE security_targets SET repository_identity = NULL")
        monkeypatch.setattr(target_state, "_repository_birth_time_ns", lambda *_: None)
        args = argparse.Namespace(before_scan_id=before["scanId"], after_scan_id=after["scanId"])

        def compare():
            return history.compare_scans(
                connection,
                args,
                require_scan=lambda db, id: db.execute(
                    "SELECT * FROM scans WHERE id = ?", (id,)
                ).fetchone(),
                read_coverage=lambda row: json.loads(
                    (Path(row["scan_dir"]) / "coverage.json").read_text()
                ),
            )

        if same_origin:
            assert compare()["afterScanId"] == after["scanId"]
        else:
            with pytest.raises(SystemExit, match="same repository"):
                compare()


@pytest.mark.parametrize(
    "platform,ending,literal_cr",
    (
        ("win32", b"\r\n", False),
        ("win32", b"\n", False),
        ("linux", b"\n", False),
        ("linux", b"\n", True),
    ),
)
def test_portable_identity_decodes_git_line_protocol_without_changing_path_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, ending: bytes, literal_cr: bool
) -> None:
    import os

    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_target_state as target_state

    monkeypatch.setattr(target_state.sys, "platform", platform)
    expected = tmp_path / ("path\r" if literal_cr else "path")
    assert target_state._path_from_git_bytes(os.fsencode(expected) + ending, tmp_path) == expected
    assert (
        target_state._path_from_git_bytes(os.fsencode(expected), tmp_path, strip_line_feed=False)
        == expected
    )


@pytest.mark.parametrize("reopen", (False, True))
def test_portable_identity_history_lookup_uses_indexes(tmp_path: Path, reopen: bool) -> None:
    state = tmp_path / "state"
    run_workbench(state, "list-repositories")
    if reopen:
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute("DROP INDEX IF EXISTS scans_by_target_path")
        run_workbench(state, "list-repositories")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        plan = [
            row[3]
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT target_device, target_inode, started_at, created_at FROM scans WHERE target_id = ? OR target_path = ?",
                ("synthetic-target", "synthetic-path"),
            )
        ]
        assert not any(line.startswith("SCAN scans") for line in plan), plan
        assert any("target_id=?" in line for line in plan), plan
        assert any("target_path=?" in line for line in plan), plan


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_legacy_aliases_restore_mixed_plain_and_git_history(tmp_path: Path, mode: str) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "README.md").write_text("fixture\n")
    state = tmp_path / "state"
    before = create_cli_scan(state, tmp_path / "results", repository, mode=mode)
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "add", "."],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-qm",
            "Initialize repository",
        ],
        cwd=repository,
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True
    ).strip()
    after = create_cli_scan(
        state, tmp_path / "results", repository, mode=mode, target_revision=revision
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET repository_generation = NULL")
        connection.execute("UPDATE security_targets SET repository_identity = NULL")
    current = create_cli_scan(
        state, tmp_path / "results", repository, mode=mode, target_revision=revision
    )
    assert compare_scan_pair(state, after, current)["afterScanId"] == current["scanId"]
    assert before["scanId"] != current["scanId"]


@pytest.mark.parametrize("missing_birth", ("before", "after"))
@pytest.mark.parametrize("same_origin", (True, False))
def test_legacy_aliases_explicit_comparison_with_mixed_birth_support(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_birth: str, same_origin: bool
) -> None:
    import argparse

    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_scan_history as history
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://example.test/synthetic/project.git"],
        cwd=repository,
        check=True,
    )
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(repository), str(clone)], check=True)
    subprocess.run(
        [
            "git",
            "remote",
            "set-url",
            "origin",
            "https://example.test/synthetic/project.git"
            if same_origin
            else "https://example.test/synthetic/other.git",
        ],
        cwd=clone,
        check=True,
    )
    state = tmp_path / "state"
    before = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    after = create_cli_scan(state, tmp_path / "results", clone, target_revision=revision)
    missing = before if missing_birth == "before" else after
    missing_path = repository if missing_birth == "before" else clone
    original_birth = target_state._repository_birth_time_ns
    monkeypatch.setattr(
        target_state,
        "_repository_birth_time_ns",
        lambda path, metadata: (
            None if Path(path) == missing_path / ".git" else original_birth(path, metadata)
        ),
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE scans SET repository_generation = NULL WHERE id = ?", (missing["scanId"],)
        )
        connection.execute(
            "UPDATE security_targets SET repository_identity = NULL WHERE current_path = ?",
            (str(missing_path),),
        )
        args = argparse.Namespace(before_scan_id=before["scanId"], after_scan_id=after["scanId"])

        def compare():
            return history.compare_scans(
                connection,
                args,
                require_scan=lambda db, id: db.execute(
                    "SELECT * FROM scans WHERE id = ?", (id,)
                ).fetchone(),
                read_coverage=lambda row: json.loads(
                    (Path(row["scan_dir"]) / "coverage.json").read_text()
                ),
            )

        if same_origin:
            assert compare()["afterScanId"] == after["scanId"]
        else:
            with pytest.raises(SystemExit, match="same repository"):
                compare()


@pytest.mark.parametrize("other_checkout", ("linked", "clone", "different-scope"))
def test_originless_linked_comparison_without_birth_timestamps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, other_checkout: str
) -> None:
    import argparse

    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_scan_history as history
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    (repository / "src").mkdir()
    linked = tmp_path / "linked"
    if other_checkout == "clone":
        subprocess.run(["git", "clone", "-q", str(repository), str(linked)], check=True)
        subprocess.run(["git", "remote", "remove", "origin"], cwd=linked, check=True)
    else:
        subprocess.run(
            ["git", "worktree", "add", "-q", "-b", "fixture-linked", str(linked)],
            cwd=repository,
            check=True,
        )
    (linked / "src").mkdir(exist_ok=True)
    state = tmp_path / "state"
    before_target = repository / "src" if other_checkout == "different-scope" else repository
    before = create_cli_scan(state, tmp_path / "results", before_target, target_revision=revision)
    after = create_cli_scan(state, tmp_path / "results", linked, target_revision=revision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE scans SET repository_generation = NULL")
        connection.execute("UPDATE security_targets SET repository_identity = NULL")
        connection.commit()
        monkeypatch.setattr(target_state, "_repository_birth_time_ns", lambda *_: None)
        args = argparse.Namespace(before_scan_id=before["scanId"], after_scan_id=after["scanId"])
        require_scan = lambda db, id: db.execute(
            "SELECT * FROM scans WHERE id = ?", (id,)
        ).fetchone()
        read_coverage = lambda row: json.loads(
            (Path(row["scan_dir"]) / "coverage.json").read_text()
        )
        if other_checkout != "linked":
            with pytest.raises(SystemExit, match="same repository"):
                history.compare_scans(
                    connection, args, require_scan=require_scan, read_coverage=read_coverage
                )
            return
        result = history.compare_scans(
            connection, args, require_scan=require_scan, read_coverage=read_coverage
        )
        assert result["afterScanId"] == after["scanId"]
        before_id = connection.execute(
            "SELECT id FROM finding_occurrences WHERE scan_id = ?", (before["scanId"],)
        ).fetchone()[0]
        after_id = connection.execute(
            "SELECT id FROM finding_occurrences WHERE scan_id = ?", (after["scanId"],)
        ).fetchone()[0]
        args.matches_json = json.dumps(
            {"matches": [confirmed_match(before_id, after_id)], "uncertain": []}
        )
        saved = history.save_scan_comparison(
            connection,
            args,
            now=lambda: "2026-10-07T00:00:00Z",
            require_scan=require_scan,
            read_coverage=read_coverage,
        )
        assert saved["afterScanId"] == after["scanId"]


@pytest.mark.parametrize("scope", [".", "component"])
def test_repository_identity_preserves_directory_aliases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scope: str
) -> None:
    import os

    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / "component").mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(repository, target_is_directory=True)
    selected = alias / scope
    actual_realpath = os.path.realpath

    def preserve_alias(path, *args, **kwargs):
        result = actual_realpath(path, *args, **kwargs)
        return str(selected) if str(path) == str(selected) else result

    # Case-insensitive filesystems can retain an alias's spelling. Keep real
    # directory identity and Git operations while controlling that spelling.
    monkeypatch.setattr(os.path, "realpath", preserve_alias)
    expected = target_state.repository_identity(repository / scope)
    assert expected is not None
    assert target_state.repository_identity(selected) == expected
    assert target_state.repository_relative_path(selected) == scope


def change_repository_metadata(
    monkeypatch: pytest.MonkeyPatch, repository: Path, change: str
) -> None:
    from types import SimpleNamespace

    import workbench_target_state as target_state

    original_stat = Path.stat
    original_statvfs = getattr(target_state.os, "statvfs", None)
    original_birth = target_state._repository_birth_time_ns
    objects = repository / ".git" / "objects"

    class ChangedMetadata:
        def __init__(self, metadata: Any, name: str) -> None:
            self.metadata, self.name = metadata, name

        def __getattr__(self, name: str) -> Any:
            value = getattr(self.metadata, name)
            return value + 1 if name == self.name else value

    def metadata(path: Path, *args: Any, **kwargs: Any) -> Any:
        result = original_stat(path, *args, **kwargs)
        if change in ("device", "legacy-device") and (
            path == repository or repository in path.parents
        ):
            return ChangedMetadata(result, "st_dev")
        if change == "inode" and path == objects:
            return ChangedMetadata(result, "st_ino")
        return result

    def filesystem(path: Path) -> Any:
        result = original_statvfs(path) if original_statvfs else SimpleNamespace(f_fsid=1)
        return (
            ChangedMetadata(result, "f_fsid")
            if change in ("filesystem", "common-filesystem")
            and Path(path) == (objects if change == "filesystem" else repository / ".git")
            else result
        )

    def birth(path: str, value: Any) -> int | None:
        result = original_birth(path, value)
        return (
            result + 1
            if result is not None and change == "birth" and Path(path) == objects
            else result
        )

    monkeypatch.setattr(Path, "stat", metadata)
    monkeypatch.setattr(target_state.os, "statvfs", filesystem, raising=False)
    monkeypatch.setattr(target_state, "_repository_birth_time_ns", birth)


@pytest.mark.parametrize(
    "change",
    (
        "device",
        "legacy-device",
        "stored-legacy-device",
        "foreign-strong-device",
        "filesystem",
        "common-filesystem",
        "inode",
        "birth",
    ),
)
def test_repository_history_distinguishes_linux_remount_from_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    import argparse

    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_scan_history as history
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    state = tmp_path / "state"
    scan = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        if change == "legacy-device":
            connection.execute("UPDATE security_targets SET repository_identity=NULL")
            connection.execute("UPDATE scans SET repository_generation=NULL")
        if change == "stored-legacy-device":
            identity = target_state._repository_identity_details(repository)
            assert identity is not None
            connection.execute(
                "UPDATE security_targets SET repository_identity=?", (identity.legacy_value,)
            )
        before = dict(connection.execute("SELECT * FROM scans").fetchone())
        args = argparse.Namespace(
            repository=str(repository),
            scan_root=None,
            target_id=None,
            mode=None,
            status=None,
            query=None,
            limit=None,
            offset=0,
        )
        assert [row["scanId"] for row in history.list_scans(connection, args)["scans"]] == [
            scan["scanId"]
        ]
        change_repository_metadata(
            monkeypatch,
            repository,
            "device" if change in ("stored-legacy-device", "foreign-strong-device") else change,
        )
        if change == "foreign-strong-device":
            connection.execute(
                "UPDATE security_targets SET repository_identity=?",
                (
                    target_state._identity_digest(
                        "synthetic foreign binding", "repository_v3_sha256_"
                    ),
                ),
            )
        binding = connection.execute("SELECT repository_identity FROM security_targets").fetchone()[
            0
        ]
        changes = connection.total_changes
        preserved = (
            change in ("device", "legacy-device", "stored-legacy-device")
            and sys.platform == "linux"
            or change in ("filesystem", "common-filesystem")
            and sys.platform != "linux"
        )
        assert [row["scanId"] for row in history.list_scans(connection, args)["scans"]] == (
            [scan["scanId"]] if preserved else []
        )
        if preserved:
            assert (
                target_state.ensure_security_target(connection, str(repository))
                == before["target_id"]
            )
        else:
            with pytest.raises(SystemExit, match="no longer matches"):
                target_state.ensure_security_target(connection, str(repository))
        assert dict(connection.execute("SELECT * FROM scans").fetchone()) == before
        assert connection.total_changes == changes
        assert (
            connection.execute("SELECT repository_identity FROM security_targets").fetchone()[0]
            == binding
        )


@pytest.mark.parametrize("remounted_before_upgrade", (False, True))
@pytest.mark.parametrize("stored_binding", (False, True))
def test_repository_generation_upgrade_requires_the_original_v2_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    remounted_before_upgrade: bool,
    stored_binding: bool,
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_db as workbench
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    state = tmp_path / "state"
    create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    identity = target_state._repository_identity_details(repository)
    assert identity is not None
    previous = identity.previous_value or identity.value
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE security_targets SET repository_identity=?",
            (previous if stored_binding else None,),
        )
        connection.execute("UPDATE scans SET repository_generation=?", (previous,))
        connection.execute("DELETE FROM schema_migrations WHERE version=49")
        before = dict(connection.execute("SELECT * FROM scans").fetchone())
        if remounted_before_upgrade:
            change_repository_metadata(monkeypatch, repository, "device")
        workbench.apply_migrations(connection)
        expected = previous if remounted_before_upgrade else identity.value
        assert connection.execute("SELECT repository_identity FROM security_targets").fetchone()[
            0
        ] == (expected if stored_binding else None)
        assert dict(connection.execute("SELECT * FROM scans").fetchone()) == {
            **before,
            "repository_generation": expected,
        }
        if remounted_before_upgrade:
            with pytest.raises(SystemExit, match="no longer matches"):
                target_state.ensure_security_target(connection, str(repository))
        else:
            assert (
                target_state.ensure_security_target(connection, str(repository))
                == before["target_id"]
            )


@pytest.mark.parametrize("historical_scan", (False, True))
@pytest.mark.parametrize("binding", ("authenticated", "unmatched", "remounted"))
def test_repository_generation_migration_preserves_null_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, historical_scan: bool, binding: str
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_db as workbench
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    state = tmp_path / "state"
    if historical_scan:
        create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    else:
        state.mkdir()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        workbench.apply_migrations(connection)
        target_id = target_state.ensure_security_target(connection, str(repository))
        identity = target_state._repository_identity_details(repository)
        assert identity is not None
        previous = identity.previous_value or identity.value
        if binding == "unmatched":
            previous = "repository_sha256_" + "0" * 64
        connection.execute("UPDATE security_targets SET repository_identity=?", (previous,))
        connection.execute("UPDATE scans SET repository_generation=NULL")
        connection.execute("DELETE FROM schema_migrations WHERE version=49")
        before = [dict(row) for row in connection.execute("SELECT * FROM scans")]
        if binding == "authenticated":
            scope = target_state.RepositoryIdentityCache(connection).scope(target_id)
            assert all(scope.contains(row) for row in before)
        if binding == "remounted":
            change_repository_metadata(monkeypatch, repository, "device")
        workbench.apply_migrations(connection)
        expected = identity.value if binding == "authenticated" else previous
        assert (
            connection.execute("SELECT repository_identity FROM security_targets").fetchone()[0]
            == expected
        )
        assert [dict(row) for row in connection.execute("SELECT * FROM scans")] == before
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 49
        # A completed migration, including an unverifiable binding, does not probe
        # local repositories again on a database reopen.
        with monkeypatch.context() as no_probes:

            def unexpected_probe(*args, **kwargs):
                raise AssertionError("A completed migration reprobed repository identity")

            no_probes.setattr(target_state, "_repository_identity_details", unexpected_probe)
            workbench.apply_migrations(connection)
        if binding == "authenticated":
            registration = target_state.register_security_target(connection, str(repository))
            assert registration.target_id == target_id
            assert registration.repository_generation == identity.value
            if sys.platform == "linux":
                change_repository_metadata(monkeypatch, repository, "device")
            scope = target_state.RepositoryIdentityCache(connection).scope(target_id)
            assert scope.available
            assert all(scope.contains(row) for row in before)
        elif historical_scan:
            with pytest.raises(SystemExit, match="no longer matches"):
                target_state.ensure_security_target(connection, str(repository))
        # Unscanned targets retain the existing registration rebind behavior.
        else:
            assert target_state.ensure_security_target(connection, str(repository)) == target_id


def test_repository_generation_migration_is_atomic_and_preserves_shared_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_db as workbench
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)], check=True
    )
    state = tmp_path / "state"
    first = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    second = create_cli_scan(state, tmp_path / "results", linked, target_revision=revision)
    legacy = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    identity = target_state._repository_identity_details(repository)
    assert identity is not None
    previous = identity.previous_value or identity.value
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("UPDATE security_targets SET repository_identity=?", (previous,))
        connection.execute("UPDATE scans SET repository_generation=?", (previous,))
        connection.execute(
            "UPDATE scans SET repository_generation=NULL WHERE id=?", (legacy["scanId"],)
        )
        connection.execute("DELETE FROM schema_migrations WHERE version=49")
        connection.commit()
        before = [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")]
        dump = list(connection.iterdump())
        target_updates = []

        def deny_generation_update(operation, table, column, *_):
            if (
                operation == sqlite3.SQLITE_UPDATE
                and table == "security_targets"
                and column == "repository_identity"
            ):
                target_updates.append(True)
            return (
                sqlite3.SQLITE_DENY
                if operation == sqlite3.SQLITE_UPDATE
                and table == "scans"
                and column == "repository_generation"
                else sqlite3.SQLITE_OK
            )

        # Only Linux converts the v2 format; other platforms still record the
        # semantic migration without changing their existing generations.
        if sys.platform == "linux":
            connection.set_authorizer(deny_generation_update)
            with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
                workbench.apply_migrations(connection)
            connection.set_authorizer(lambda *_: sqlite3.SQLITE_OK)
            assert target_updates
            assert list(connection.iterdump()) == dump
        # One authenticated checkout can update its shared generation even if a
        # linked checkout is temporarily absent; no NULL-generation scan is joined.
        linked.rename(tmp_path / "offline")
        workbench.apply_migrations(connection)
        assert {
            row[0] for row in connection.execute("SELECT repository_identity FROM security_targets")
        } == {identity.value}
        assert [dict(row) for row in connection.execute("SELECT * FROM scans ORDER BY id")] == [
            {
                **row,
                "repository_generation": None if row["id"] == legacy["scanId"] else identity.value,
            }
            for row in before
        ]
        scope = target_state.RepositoryIdentityCache(connection).scope_for_path(str(repository))
        assert all(
            scope.contains(
                connection.execute("SELECT * FROM scans WHERE id=?", (scan["scanId"],)).fetchone()
            )
            for scan in (first, second, legacy)
        )


@pytest.mark.parametrize("old_version", (41, 42))
def test_repository_generation_migration_keeps_released_null_history_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old_version: int
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_db as workbench
    import workbench_schema as schema
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    state = tmp_path / "state"
    scan = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    with (
        sqlite3.connect(state / "workbench.sqlite3") as source,
        sqlite3.connect(":memory:") as connection,
    ):
        source.row_factory = connection.row_factory = sqlite3.Row
        schema.apply_migrations(
            connection,
            tuple(item for item in schema.MIGRATIONS if item[0] <= old_version),
            workbench.now,
            lambda _: None,
        )
        for table in ("security_targets", "workspaces", "scans"):
            columns = [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]
            for row in source.execute(f"SELECT * FROM {table}"):
                connection.execute(
                    f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})",
                    tuple(row[name] for name in columns),
                )
        before = dict(connection.execute("SELECT * FROM scans").fetchone())
        workbench.apply_migrations(connection)
        after = dict(connection.execute("SELECT * FROM scans").fetchone())
        assert {name: after[name] for name in before} == before
        assert after["repository_generation"] is None
        assert after["completion_sequence"] == 1
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 49
        scope = target_state.RepositoryIdentityCache(connection).scope_for_path(str(repository))
        assert scope.available and scope.contains(after)
        assert after["id"] == scan["scanId"]


@pytest.mark.parametrize(
    "alias_binding", ("unsaved", "stale", "current", "legacy", "unbound-owner")
)
def test_repository_generation_returns_after_offline_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias_binding: str
) -> None:
    monkeypatch.syspath_prepend(str(SCRIPT.parent))
    import workbench_db as workbench
    import workbench_target_state as target_state

    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    linked = tmp_path / "linked"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)],
        check=True,
    )
    state = tmp_path / "state"
    scan = create_cli_scan(state, tmp_path / "results", repository, target_revision=revision)
    if alias_binding == "legacy":
        create_cli_scan(state, tmp_path / "results", linked, target_revision=revision)
    identity = target_state._repository_identity_details(repository)
    assert identity is not None
    previous = identity.previous_value or identity.value
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        if alias_binding in ("stale", "current"):
            target_state.ensure_security_target(connection, str(linked))
        connection.execute(
            "UPDATE security_targets SET repository_identity=? WHERE current_path=?",
            (previous, str(repository)),
        )
        connection.execute("UPDATE scans SET repository_generation=?", (previous,))
        if alias_binding == "legacy":
            connection.execute(
                "UPDATE security_targets SET repository_identity=NULL WHERE current_path=?",
                (str(linked),),
            )
            connection.execute(
                "UPDATE scans SET repository_generation=NULL, target_device=NULL, target_inode=NULL WHERE target_path=?",
                (str(linked),),
            )
        elif alias_binding == "stale":
            connection.execute(
                "UPDATE security_targets SET repository_identity=? WHERE current_path=?",
                ("repository_sha256_" + "0" * 64, str(linked)),
            )
        if alias_binding == "unbound-owner":
            connection.execute(
                "UPDATE security_targets SET repository_identity=NULL WHERE current_path=?",
                (str(repository),),
            )
        connection.execute("DELETE FROM schema_migrations WHERE version=49")
        offline = tmp_path / "offline"
        repository.rename(offline)
        workbench.apply_migrations(connection)
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 49
        assert (
            connection.execute(
                "SELECT repository_generation FROM scans WHERE id=?", (scan["scanId"],)
            ).fetchone()[0]
            == previous
        )
        offline.rename(repository)
        workbench.apply_migrations(connection)
        saved = connection.execute("SELECT * FROM scans WHERE id=?", (scan["scanId"],)).fetchone()
        cache = target_state.RepositoryIdentityCache(connection)
        assert cache.scope_for_scan(saved).contains(saved)
        assert cache.scope_for_path(str(repository)).contains(saved)
        if alias_binding != "stale":
            assert cache.scope_for_path(str(linked)).contains(saved)
        with connection:
            registration = target_state.register_security_target(connection, str(linked))
        expected = previous if alias_binding == "legacy" else identity.value
        assert registration.repository_generation == expected
        new_scan = create_cli_scan(state, tmp_path / "results", linked, target_revision=revision)
        assert (
            connection.execute(
                "SELECT repository_generation FROM scans WHERE id=?", (new_scan["scanId"],)
            ).fetchone()[0]
            == expected
        )
        assert {
            row[0]
            for row in connection.execute(
                "SELECT repository_generation FROM scans WHERE repository_generation IS NOT NULL"
            )
        } == {expected}
        # An owner that can authenticate the complete binding converts all pending
        # scans together; a NULL-generation historical scan remains local.
        with connection:
            target_state.register_security_target(connection, str(repository))
        assert {
            row[0] for row in connection.execute("SELECT repository_identity FROM security_targets")
        } == (
            {identity.value, None}
            if alias_binding in ("legacy", "unbound-owner")
            else {identity.value}
        )
        assert {
            row[0] for row in connection.execute("SELECT repository_generation FROM scans")
        } == ({identity.value, None} if alias_binding == "legacy" else {identity.value})
        if sys.platform == "linux":
            change_repository_metadata(monkeypatch, repository, "device")
        updated = connection.execute("SELECT * FROM scans WHERE id=?", (scan["scanId"],)).fetchone()
        target_state.require_scan_checkout_owner(connection, updated)
