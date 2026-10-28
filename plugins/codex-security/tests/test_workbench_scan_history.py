from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import uuid
from argparse import Namespace
from contextlib import closing
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
    load_script,
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
    name = "Évaluation Größe Проверка"
    run_workbench(state_dir, "rename-scan", "--scan-id", scan["scanId"], f"--name={name}")
    for query in ("STRASSE", "ä", "ÜBERBLICK", "évaluation", "GRÖSSE", "проверка"):
        listed = run_workbench(state_dir, "list-scans", "--query", query)["scans"]
        assert [(item["scanId"], item["name"]) for item in listed] == [(scan["scanId"], name)]
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
    related: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    return run_workbench(
        state_dir,
        "save-scan-comparison",
        "--before-scan-id",
        before["scanId"],
        "--after-scan-id",
        after["scanId"],
        "--matches-json",
        json.dumps({"matches": matches, "uncertain": uncertain, "related": related}),
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
    follow_up: bool = False,
    extra_anchors: tuple[str, ...] = (),
    finding: bool = True,
    identity_anchor: str = "archive-entry-write-without-containment",
    identity_instance: str | None = None,
    mode: str = "standard",
    parent_scan_id: str | None = None,
    paths: list[str] | None = None,
    cost: dict[str, Any] | None = None,
    relative_path: str = "src/extract.py",
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
        relative_path=relative_path,
        coverage_mode=coverage_mode,
        inventory_strategy="scoped_path" if paths else "repository",
        target_kind="git_revision" if target_revision is not None else "directory_snapshot",
        target_revision=target_revision,
        snapshot_digest=snapshot_digest,
    )
    if not finding or extra_anchors or identity_instance is not None:
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        if identity_instance is not None:
            findings["findings"][0]["identity"]["instance"] = identity_instance
        if not finding:
            findings["findings"] = []
        else:
            for index, anchor in enumerate(extra_anchors, start=1):
                additional = copy.deepcopy(findings["findings"][0])
                additional["identity"]["anchor"] = anchor
                additional["title"] += f" ({index})"
                findings["findings"].append(additional)
        findings_path.write_text(json.dumps(findings))
    if follow_up:
        coverage_path = scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
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


@pytest.mark.parametrize("artifact", ["findings.json", "coverage.json", "scan-manifest.json"])
@pytest.mark.parametrize("mutation", ["remove", "modify"])
def test_get_scan_reads_pinned_coverage_independently_of_unrelated_artifacts(
    tmp_path: Path, artifact: str, mutation: str
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, finding=True)
    scan_dir = Path(scan["scanDir"])
    before = get_scan(state_dir, scan["scanId"])["scan"]
    assert before["coverage"]["includePaths"] == ["."]
    artifact_path = scan_dir / artifact
    if mutation == "remove":
        artifact_path.unlink()
    else:
        artifact_path.write_bytes(artifact_path.read_bytes() + b"\n")

    after = get_scan(state_dir, scan["scanId"])["scan"]
    assert after["progress"]["status"] == "complete"
    assert after["findings"] == before["findings"]
    if artifact == "findings.json":
        assert after["coverage"] == before["coverage"]
    else:
        assert "coverage" not in after


@pytest.mark.parametrize("finding", [False, True])
@pytest.mark.parametrize("follow_up", [False, True])
def test_get_scan_reads_legacy_sealed_history_coverage_without_writes(
    tmp_path: Path, finding: bool, follow_up: bool
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(
        state_dir, tmp_path / "results", repository, finding=finding, follow_up=follow_up
    )
    scan_dir = Path(scan["scanDir"])
    artifacts = {path: path.read_bytes() for path in scan_dir.rglob("*") if path.is_file()}
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM finding_occurrences WHERE scan_id = ? AND details_json = '{}'",
            (scan["scanId"],),
        ).fetchone() == (0,)
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan["scanId"],)
        )

    assert get_scan(state_dir, scan["scanId"])["scan"]["coverage"] == {
        "mode": "repository",
        "includePaths": ["."],
        "excludePaths": [],
        "explicitExclusions": [],
    }
    assert {path: path.read_bytes() for path in scan_dir.rglob("*") if path.is_file()} == artifacts
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan["scanId"],)
        ).fetchone() == (None,)


@pytest.mark.parametrize(
    "corruption",
    ["coverage", "findings", "missing-coverage", "missing-manifest", "unsealed", "owner", "mode"],
)
def test_get_scan_rejects_unverifiable_legacy_sealed_history_coverage(
    tmp_path: Path, corruption: str
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    scan = create_cli_scan(state_dir, tmp_path / "results", repository, finding=False)
    scan_dir = Path(scan["scanDir"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = NULL WHERE id = ?", (scan["scanId"],)
        )
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if corruption in {"coverage", "findings"}:
        path = scan_dir / f"{corruption}.json"
        path.write_bytes(path.read_bytes() + b"\n")
    elif corruption.startswith("missing-"):
        (
            scan_dir
            / ("coverage.json" if corruption == "missing-coverage" else "scan-manifest.json")
        ).unlink()
    elif corruption == "unsealed":
        del manifest["scan"]["sealedAt"]
        del manifest["scan"]["artifacts"]
        manifest_path.write_text(json.dumps(manifest))
    elif corruption == "owner":
        manifest["scan"]["target"]["targetId"] = "unrelated-target"
        manifest_path.write_text(json.dumps(manifest))
    else:
        coverage_path = scan_dir / "coverage.json"
        coverage = json.loads(coverage_path.read_text())
        coverage["mode"] = "deep_repository"
        coverage_path.write_text(json.dumps(coverage))
        for artifact in manifest["scan"]["artifacts"]:
            if artifact["path"] == "coverage.json":
                artifact["sha256"] = hashlib.sha256(coverage_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
    artifacts = {path: path.read_bytes() for path in scan_dir.rglob("*") if path.is_file()}

    assert "coverage" not in get_scan(state_dir, scan["scanId"])["scan"]
    assert {path: path.read_bytes() for path in scan_dir.rglob("*") if path.is_file()} == artifacts
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan["scanId"],)
        ).fetchone() == (None,)


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
    assert json.loads(stored[0]) == {"cost": cost, "usage": listed["scans"][0]["usage"]}
    assert listed["scans"][0]["usage"]["coverage"] == "unavailable"


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
    assert persisted["summary"]["persisting"] == 1
    occurrence = persisted["findings"][0]["beforeOccurrenceId"]
    set_triage(state_dir, occurrence, "closed", "--close-reason", "already_fixed")
    reopened = compare_scan_pair(state_dir, before, after)
    assert reopened["summary"]["reopened"] == 1
    assert reopened["findings"][0]["triage"] == {"closeReason": None, "status": "open"}

    resolved = compare_scan_pair(state_dir, after, fixed)
    assert resolved["summary"]["not_observed"] == 1
    after_occurrence = persisted["findings"][0]["afterOccurrenceId"]
    set_triage(state_dir, after_occurrence, "closed", "--close-reason", "already_fixed")
    assert compare_scan_pair(state_dir, after, fixed)["summary"]["resolved"] == 1
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM findings").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM finding_occurrences").fetchone() == (2,)


def create_ordered_history(root: Path, anchors: tuple[str, ...]):
    repository = root / "repository"
    repository.mkdir()
    state_dir = root / "state"
    scans = sorted(
        (
            create_cli_scan(state_dir, root / "results", repository, identity_anchor=anchor)
            for anchor in anchors
        ),
        key=lambda scan: scan["scanId"],
    )
    return state_dir / "workbench.sqlite3", repository, scans


@pytest.fixture(scope="module")
def recurring_history(tmp_path_factory: pytest.TempPathFactory):
    return create_ordered_history(tmp_path_factory.mktemp("recurring-scans"), ("recurring",) * 2)


@pytest.fixture(scope="module")
def matched_history(tmp_path_factory: pytest.TempPathFactory):
    database, _repository, scans = create_ordered_history(
        tmp_path_factory.mktemp("matched-scans"), tuple(f"synthetic-{index}" for index in range(4))
    )
    findings = [get_scan(database.parent, scan["scanId"])["scan"]["findings"][0] for scan in scans]
    for left, right in ((0, 1), (1, 3)):
        save_scan_matches(
            database.parent,
            scans[left],
            scans[right],
            confirmed_match(findings[left]["occurrenceId"], findings[right]["occurrenceId"]),
        )
    return database, scans, [sorted(finding["findingId"] for finding in findings[:2])]


def copy_history_state(database: Path, tmp_path: Path) -> Path:
    # Each case changes its own timestamps or matches. The sealed scan directories are read-only.
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    with (
        closing(sqlite3.connect(database)) as source,
        closing(sqlite3.connect(state_dir / "workbench.sqlite3")) as destination,
    ):
        source.backup(destination)
    return state_dir


@pytest.mark.parametrize(
    ("timestamps", "expected_order"),
    [
        (("2026-08-01T00:00:00Z", "2026-08-01T01:00:00+02:00"), (1, 0)),
        (("2026-08-01T00:00:00.000200Z", "2026-08-01T01:00:00.000100+01:00"), (1, 0)),
        (("2026-08-01T01:00:00+01:00", "2026-08-01T00:00:00Z"), (0, 1)),
    ],
    ids=["mixed-offsets", "microseconds", "equal-instants"],
)
def test_finding_occurrence_history_uses_start_instants(
    tmp_path: Path, recurring_history, timestamps: tuple[str, str], expected_order: tuple[int, int]
) -> None:
    database, _repository, scans = recurring_history
    state_dir = copy_history_state(database, tmp_path)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.executemany(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            [(timestamp, scan["scanId"]) for scan, timestamp in zip(scans, timestamps)],
        )

    for scan in scans:
        finding = get_scan(state_dir, scan["scanId"])["scan"]["findings"][0]
        assert finding["knownSince"] == timestamps[expected_order[0]]
        assert finding["knownScanIds"] == [scans[index]["scanId"] for index in expected_order]


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


@pytest.mark.parametrize("identity_instance", [None, "archive-entry"])
def test_scan_comparison_matches_equivalent_findings_across_standard_and_deep_scans(
    tmp_path: Path,
    identity_instance: str | None,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "extract.py").write_text("destination.write_bytes(entry.read())\n")
    root = tmp_path / "results"
    standard = create_cli_scan(state_dir, root, repository, identity_instance=identity_instance)
    deep = create_cli_scan(
        state_dir,
        root,
        repository,
        mode="deep",
        identity_anchor="archive-extraction-missing-destination-containment",
        identity_instance=identity_instance,
    )

    baseline = compare_scan_pair(state_dir, standard, deep, "--include-matching-inputs")
    inputs = baseline["matchingInputs"]
    assert inputs["before"][0]["findingId"] != inputs["after"][0]["findingId"]
    assert baseline["summary"] == {
        "new": 0,
        "persisting": 1,
        "resolved": 0,
        "not_observed": 0,
        "reopened": 0,
        "unknown": 0,
    }
    assert baseline["findings"][0]["beforeOccurrenceId"] == inputs["before"][0]["occurrenceId"]
    assert baseline["findings"][0]["afterOccurrenceId"] == inputs["after"][0]["occurrenceId"]
    assert "identical locations" in baseline["findings"][0]["matchReason"]

    uncertain = save_scan_matches(
        state_dir,
        standard,
        deep,
        uncertain=(
            {
                "beforeOccurrenceId": inputs["before"][0]["occurrenceId"],
                "afterOccurrenceId": inputs["after"][0]["occurrenceId"],
                "reason": "The scan modes describe the control differently.",
            },
        ),
    )
    assert uncertain["summary"]["persisting"] == 1
    assert uncertain["summary"]["unknown"] == 0


def create_scan_with_finding_locations(
    state_dir: Path, root: Path, repository: Path, findings: list[tuple[str, str]]
) -> dict[str, Any]:
    scan = create_cli_scan(state_dir, root, repository, complete=False)
    scan_dir = Path(scan["scanDir"])
    write_completed_contract(scan_dir, scan["scanId"], repository)
    findings_path = scan_dir / "findings.json"
    document = json.loads(findings_path.read_text())
    template = document["findings"][0]
    document["findings"] = []
    for anchor, path in findings:
        finding = copy.deepcopy(template)
        finding["identity"]["anchor"] = anchor
        for location in finding["locations"]:
            location["path"] = path
        document["findings"].append(finding)
    findings_path.write_text(json.dumps(document))
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)
    run_workbench(state_dir, "complete-scan", "--scan-id", scan["scanId"])
    return scan


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("through_history", [False, True])
def test_equivalent_locations_preserve_confirmed_groups(
    tmp_path: Path, reverse: bool, through_history: bool
) -> None:
    state_dir = tmp_path / "state"
    root = tmp_path / "results"
    repository = tmp_path / "repository"
    repository.mkdir()
    before = create_scan_with_finding_locations(
        state_dir, root, repository, [("original-control", "src/extract.py")]
    )
    after = create_scan_with_finding_locations(
        state_dir,
        root,
        repository,
        [("moved-control", "src/helper.py"), ("independent-control", "src/extract.py")],
    )
    if reverse:
        before, after = after, before
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    by_anchor = {
        finding["identity"]["anchor"]: finding["occurrenceId"]
        for side in inputs.values()
        for finding in side
    }
    previous, current = by_anchor["original-control"], by_anchor["moved-control"]
    if reverse:
        previous, current = current, previous
    if through_history:
        middle = create_cli_scan(
            state_dir,
            root,
            repository,
            identity_anchor="historical-control",
            relative_path="src/history.py",
        )
        middle_id = compare_scan_pair(state_dir, before, middle, "--include-matching-inputs")[
            "matchingInputs"
        ]["after"][0]["occurrenceId"]
        save_scan_matches(state_dir, before, middle, confirmed_match(previous, middle_id))
        save_scan_matches(state_dir, middle, after, confirmed_match(middle_id, current))
        compared = compare_scan_pair(state_dir, before, after)
    else:
        compared = save_scan_matches(state_dir, before, after, confirmed_match(previous, current))
    assert compared["summary"] == {
        "new": 0 if reverse else 1,
        "persisting": 1,
        "resolved": 0,
        "not_observed": 1 if reverse else 0,
        "reopened": 0,
        "unknown": 0,
    }
    persisting = next(
        finding for finding in compared["findings"] if finding["status"] == "persisting"
    )
    assert persisting["beforeOccurrenceId"] == previous
    assert persisting["afterOccurrenceId"] == current
    assert compare_scan_pair(state_dir, before, after) == compared


@pytest.mark.parametrize(
    ("alias_shape", "history"),
    [("none", None), ("endpoints", None), ("chain", None), ("branch", None)]
    + [
        (shape, direction)
        for shape in ("none", "chain", "branch")
        for direction in ("forward", "reverse")
    ],
)
def test_equivalent_locations_preserve_related_findings(
    tmp_path: Path, alias_shape: str, history: str | None
) -> None:
    state_dir = tmp_path / "state"
    root = tmp_path / "results"
    repository = tmp_path / "repository"
    repository.mkdir()
    before_specs = [("member-control", "src/extract.py")]
    after_specs = [("symlink-control", "src/extract.py")]
    alias_groups = []
    related_anchors = ("member-control", "symlink-control")
    if alias_shape == "endpoints":
        before_specs.append(("member-alias", "src/member.py"))
        after_specs.append(("symlink-alias", "src/symlink.py"))
        alias_groups = [
            ("before", [anchor for anchor, _ in before_specs]),
            ("after", [anchor for anchor, _ in after_specs]),
        ]
        related_anchors = ("member-alias", "symlink-alias")
    elif alias_shape == "branch":
        before_specs.append(("member-alias", "src/member.py"))
        after_specs.append(("independent-member", "src/member.py"))
        alias_groups = [("before", [anchor for anchor, _ in before_specs])]
    elif alias_shape == "chain":
        # Three location links could bridge the related endpoints through two alias groups.
        before_specs.extend(
            [("middle-before-one", "src/middle.py"), ("middle-before-two", "src/symlink.py")]
        )
        after_specs = [
            ("middle-after-one", "src/extract.py"),
            ("middle-after-two", "src/middle.py"),
            ("symlink-control", "src/symlink.py"),
        ]
        alias_groups = [
            ("before", ["middle-before-one", "middle-before-two"]),
            ("after", ["middle-after-one", "middle-after-two"]),
        ]
    before_specs.append(("independent-before", "src/independent.py"))
    after_specs.append(("independent-after", "src/independent.py"))
    before = create_scan_with_finding_locations(state_dir, root, repository, before_specs)
    related_scan = (
        create_cli_scan(
            state_dir,
            root,
            repository,
            identity_anchor="historical-distinct-root",
            relative_path="src/related-history.py",
        )
        if history
        else None
    )
    after = create_scan_with_finding_locations(state_dir, root, repository, after_specs)
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    by_anchor = {
        finding["identity"]["anchor"]: finding["occurrenceId"]
        for side in inputs.values()
        for finding in side
    }
    for side, anchors in alias_groups:
        scan = before if side == "before" else after
        historical = create_cli_scan(
            state_dir,
            root,
            repository,
            identity_anchor=f"historical-{side}",
            relative_path="src/history.py",
        )
        historical_id = compare_scan_pair(state_dir, scan, historical, "--include-matching-inputs")[
            "matchingInputs"
        ]["after"][0]["occurrenceId"]
        save_scan_matches(
            state_dir,
            scan,
            historical,
            confirmed_match([by_anchor[anchor] for anchor in anchors], historical_id),
        )
    related = {
        "beforeOccurrenceId": by_anchor[related_anchors[0]],
        "afterOccurrenceId": by_anchor[related_anchors[1]],
        "reason": "Member-name validation and existing-symlink traversal need different fixes.",
    }
    if related_scan is None:
        compared = save_scan_matches(state_dir, before, after, related=(related,))
    else:
        historical_id = compare_scan_pair(
            state_dir, before, related_scan, "--include-matching-inputs"
        )["matchingInputs"]["after"][0]["occurrenceId"]
        if history == "reverse":
            save_scan_matches(
                state_dir,
                related_scan,
                before,
                related=(
                    {
                        **related,
                        "beforeOccurrenceId": historical_id,
                        "afterOccurrenceId": related["beforeOccurrenceId"],
                    },
                ),
            )
        else:
            save_scan_matches(
                state_dir,
                before,
                related_scan,
                related=(
                    {
                        **related,
                        "afterOccurrenceId": historical_id,
                    },
                ),
            )
        save_scan_matches(
            state_dir,
            related_scan,
            after,
            confirmed_match(historical_id, related["afterOccurrenceId"]),
        )
        if history == "reverse":
            before, after = after, before
        compared = compare_scan_pair(state_dir, before, after)
    assert compared["summary"] == {
        "new": (0 if history == "reverse" else 1)
        if alias_shape == "branch"
        else (2 if alias_shape == "chain" else 1),
        "persisting": 2 if alias_shape == "branch" else 1,
        "resolved": 0,
        "not_observed": (1 if history == "reverse" else 0)
        if alias_shape == "branch"
        else (2 if alias_shape == "chain" else 1),
        "reopened": 0,
        "unknown": 0,
    }
    independent = [by_anchor["independent-before"], by_anchor["independent-after"]]
    if history == "reverse":
        independent.reverse()
    persisting = next(
        item for item in compared["findings"] if item.get("beforeOccurrenceId") == independent[0]
    )
    assert persisting["status"] == "persisting"
    assert persisting["afterOccurrenceId"] == independent[1]
    if alias_shape == "branch":
        group_side, member_side = (
            ("after", "before") if history == "reverse" else ("before", "after")
        )
        shared = next(item for item in compared["findings"] if f"{group_side}OccurrenceIds" in item)
        assert shared["status"] == "persisting"
        assert set(shared[f"{group_side}OccurrenceIds"]) == {
            by_anchor["member-control"],
            by_anchor["member-alias"],
        }
        assert shared[f"{member_side}OccurrenceId"] == by_anchor["independent-member"]
    if history is None:
        assert len(compared["related"]) == 1
        assert all(compared["related"][0][key] == value for key, value in related.items())
    else:
        assert "related" not in compared
    assert compare_scan_pair(state_dir, before, after) == compared


@pytest.mark.parametrize(
    ("before_instance", "after_instance"),
    [("first-entry", "second-entry"), ("first-entry", None), (None, "second-entry")],
)
def test_scan_comparison_keeps_different_instances_at_the_same_location_separate(
    tmp_path: Path, before_instance: str | None, after_instance: str | None
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    root = tmp_path / "results"
    before = create_cli_scan(state_dir, root, repository, identity_instance=before_instance)
    after = create_cli_scan(
        state_dir, root, repository, mode="deep", identity_instance=after_instance
    )

    compared = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    inputs = compared["matchingInputs"]
    assert len(inputs["before"]) == len(inputs["after"]) == 1
    assert inputs["before"][0]["findingId"] != inputs["after"][0]["findingId"]
    assert compared["summary"] == {
        "new": 1,
        "persisting": 0,
        "resolved": 0,
        "not_observed": 1,
        "reopened": 0,
        "unknown": 0,
    }


def test_scan_comparison_keeps_changed_content_and_ambiguous_locations_for_semantic_matching(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "extract.py").write_text("original\n")
    root = tmp_path / "results"
    original = create_cli_scan(state_dir, root, repository)
    (repository / "extract.py").write_text("changed\n")
    changed = create_cli_scan(
        state_dir, root, repository, identity_anchor="renamed-archive-entry-write"
    )
    compared = compare_scan_pair(state_dir, original, changed)
    assert compared["summary"]["new"] == 1
    assert compared["summary"]["not_observed"] == 1

    siblings = create_cli_scan(
        state_dir,
        root,
        repository,
        identity_anchor="sibling-archive-entry-write",
        extra_anchors=("second-sibling-archive-entry-write",),
    )
    ambiguous = compare_scan_pair(state_dir, changed, siblings)
    assert ambiguous["summary"]["new"] == 2
    assert ambiguous["summary"]["not_observed"] == 1


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


def test_list_unmatched_scan_pairs_skips_incompatible_replaced_repositories(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "remote", "add", "origin", "https://example.test/first.git"],
        check=True,
    )
    results = tmp_path / "results"
    create_cli_scan(state_dir, results, repository, target_revision=revision)
    saved_repository = tmp_path / "saved-repository"
    repository.rename(saved_repository)
    subprocess.run(["git", "clone", "-q", str(saved_repository), str(repository)], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "set-url",
            "origin",
            "https://example.test/second.git",
        ],
        check=True,
    )
    before, after = (
        create_cli_scan(state_dir, results, repository, target_revision=revision) for _ in range(2)
    )

    pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert pending["scanCount"] == 3
    assert pending["unavailableScans"] == 0
    assert pending["skippedPairs"] == 0
    assert [batch["afterScanId"] for batch in pending["batches"]] == [after["scanId"]]
    assert [scan["scanId"] for scan in pending["batches"][0]["beforeScans"]] == [before["scanId"]]

    save_scan_matches(state_dir, before, after)
    cached = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert cached == {**pending, "batches": [], "skippedPairs": 1}
    forced = run_workbench(
        state_dir, "list-unmatched-scan-pairs", "--repository", str(repository), "--force"
    )
    assert forced == pending


@pytest.mark.parametrize(
    ("before_started", "after_started"),
    [
        ("2026-01-02T00:15:00+02:00", "2026-01-01T21:00:00-02:00"),
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.000001Z"),
        ("2026-01-01t02:00:00.000000+02:00", "2026-01-01T00:00:00Z"),
    ],
)
def test_automatic_matching_orders_instants_and_preserves_directed_cache(
    tmp_path: Path, recurring_history, before_started: str, after_started: str
) -> None:
    database, repository, (before, after) = recurring_history
    state_dir = copy_history_state(database, tmp_path)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.executemany(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            [(before_started, before["scanId"]), (after_started, after["scanId"])],
        )
    save_scan_matches(state_dir, after, before)

    pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert pending["skippedPairs"] == 0
    assert [batch["afterScanId"] for batch in pending["batches"]] == [after["scanId"]]
    assert [scan["scanId"] for scan in pending["batches"][0]["beforeScans"]] == [before["scanId"]]

    save_scan_matches(state_dir, before, after)
    cached = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert cached["batches"] == []
    assert cached["skippedPairs"] == 1
    forced = run_workbench(
        state_dir, "list-unmatched-scan-pairs", "--repository", str(repository), "--force"
    )
    assert forced == pending


def test_automatic_matching_keeps_unavailable_history_without_future_links(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    repository.mkdir()
    earlier, unavailable, current, future = (
        create_cli_scan(
            state_dir, tmp_path / "results", repository, identity_anchor=f"archive-check-{index}"
        )
        for index in range(4)
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.executemany(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            [
                ("2026-01-01T00:00:00Z", earlier["scanId"]),
                ("2026-01-01T03:00:00+02:00", unavailable["scanId"]),
                ("2026-01-01T02:00:00Z", current["scanId"]),
                ("2026-01-01T00:30:00-03:00", future["scanId"]),
            ],
        )
    findings = [
        get_scan(state_dir, scan["scanId"])["scan"]["findings"][0]
        for scan in (unavailable, current, future)
    ]
    for before, after, before_finding, after_finding in (
        (unavailable, current, findings[0], findings[1]),
        (current, future, findings[1], findings[2]),
    ):
        save_scan_matches(
            state_dir,
            before,
            after,
            confirmed_match(before_finding["occurrenceId"], after_finding["occurrenceId"]),
        )
    shutil.rmtree(unavailable["scanDir"])

    pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    assert (pending["scanCount"], pending["unavailableScans"], pending["skippedPairs"]) == (4, 1, 1)
    assert [batch["afterScanId"] for batch in pending["batches"]] == [
        current["scanId"],
        future["scanId"],
    ]
    assert [scan["scanId"] for scan in pending["batches"][0]["beforeScans"]] == [earlier["scanId"]]
    assert pending["batches"][0]["knownFindingGroups"] == [
        sorted(finding["findingId"] for finding in findings[:2])
    ]
    assert pending["batches"][1]["knownFindingGroups"] == [
        sorted(finding["findingId"] for finding in findings)
    ]

    forced = run_workbench(
        state_dir, "list-unmatched-scan-pairs", "--repository", str(repository), "--force"
    )
    assert (forced["scanCount"], forced["unavailableScans"], forced["skippedPairs"]) == (4, 1, 0)
    assert all("knownFindingGroups" not in batch for batch in forced["batches"])


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
        relative_path="src/rewrite.py",
    )
    baseline = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert baseline["matchingCached"] is False
    assert baseline["summary"]["new"] == 1
    assert baseline["summary"]["not_observed"] == 1
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
        "not_observed": 0,
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


@pytest.mark.parametrize(
    "timestamps",
    [
        (
            "2026-08-01T03:00:00+02:00",
            "2026-08-01T01:15:00Z",
            "2026-08-01T01:30:00Z",
            "2026-08-01T00:45:00-01:00",
        ),
        (
            "2026-08-01T01:00:00Z",
            "2026-08-01T01:00:00.000001Z",
            "2026-08-01T01:00:00.000002Z",
            "2026-08-01T01:00:00.000003Z",
        ),
        (
            "2026-08-01t03:00:00.000000+02:00",
            "2026-08-01T01:00:00Z",
            "2026-08-01T01:00:00.0Z",
            "2026-08-01T01:00:00.000Z",
        ),
    ],
    ids=["offsets", "microseconds", "equal-instants"],
)
def test_explicit_comparison_uses_chronological_matching_cutoff(
    tmp_path: Path, matched_history, monkeypatch: pytest.MonkeyPatch, timestamps: tuple[str, ...]
) -> None:
    database, scans, expected = matched_history
    state_dir = copy_history_state(database, tmp_path)
    middle, after, future = scans[1:]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.executemany(
            "UPDATE scans SET started_at = ? WHERE id = ?",
            [(timestamp, scan["scanId"]) for timestamp, scan in zip(timestamps, scans)],
        )
        original = list(connection.iterdump())
    for before_scan, after_scan in ((middle, after), (after, middle)):
        compared = compare_scan_pair(
            state_dir, before_scan, after_scan, "--include-matching-inputs"
        )
        assert (compared["beforeScanId"], compared["afterScanId"]) == (
            before_scan["scanId"],
            after_scan["scanId"],
        )
        assert compared["matchingInputs"]["knownFindingGroups"] == expected

    history = load_script("workbench_scan_history")

    def unexpected_git_lookup(*_args: Any, **_kwargs: Any) -> str:
        raise AssertionError("Future scans must not trigger repository discovery")

    monkeypatch.setitem(history.git_output.__globals__, "git_command", unexpected_git_lookup)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert list(connection.iterdump()) == original
        connection.row_factory = sqlite3.Row
        connection.execute(
            "UPDATE scans SET target_id = NULL, target_path = ? WHERE id = ?",
            (str(tmp_path / "future-repository"), future["scanId"]),
        )
        compared = history.compare_scans(
            connection,
            Namespace(before_scan_id=middle["scanId"], after_scan_id=after["scanId"]),
            require_scan=lambda db, scan_id: db.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone(),
            read_coverage=lambda _: {},
            include_matching_inputs=True,
        )
    assert compared["matchingInputs"]["knownFindingGroups"] == expected


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
        state_dir,
        root,
        repository,
        identity_anchor="independent-archive-entry-write",
        relative_path="src/rewrite.py",
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
        relative_path="src/rewrite.py",
    )
    inputs = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")[
        "matchingInputs"
    ]
    previous = inputs["before"][0]["occurrenceId"]
    current = inputs["after"][0]["occurrenceId"]
    save_scan_matches(state_dir, before, after, confirmed_match(previous, current))
    compared = save_scan_matches(state_dir, before, after)

    assert compared["summary"]["not_observed"] == 1
    assert compared["summary"]["new"] == 1
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM scan_comparison_matches").fetchone() == (0,)
    shown = get_scan(state_dir, before["scanId"])["scan"]["findings"][0]
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


@pytest.mark.parametrize(
    ("before_origin", "after_origin", "same_repository"),
    [
        ("alice@example.test:project.git", "bob@example.test:project.git", False),
        ("alice@example.test:project.git", "alice@EXAMPLE.test:project", True),
        ("Alice@example.test:project.git", "alice@example.test:project.git", False),
        ("alice@example.test:project.git", "alice@example.test:/project.git", False),
        ("ssh://alice@example.test/~/project.git", "ssh://bob@example.test/~/project.git", False),
        ("alice@example.test:/project.git", "bob@example.test:/project.git", True),
        ("ssh://alice@example.test/project.git", "bob@example.test:/project.git", True),
        ("alice@example.test:~owner/project.git", "bob@example.test:~owner/project.git", True),
        ("git@github.com:example/project.git", "https://github.com/example/project", True),
        ("git@gitlab.com:example/project.git", "https://gitlab.com/example/project", True),
        ("git@bitbucket.org:example/project.git", "https://bitbucket.org/example/project", True),
        ("git@example.test:project.git", "https://example.test/project.git", False),
        ("git@github.com:example/project.git", "alice@github.com:example/project.git", False),
        (
            "git@gitlab.com:example/project.git",
            "ssh://git@gitlab.com:2222/example/project.git",
            False,
        ),
    ],
)
def test_scan_comparison_preserves_ssh_repository_identity(
    tmp_path: Path, before_origin: str, after_origin: str, same_repository: bool
) -> None:
    state_dir = tmp_path / "state"
    before_repository = tmp_path / "before"
    after_repository = tmp_path / "after"
    initialize_git_repository(before_repository)
    (before_repository / "src").mkdir()
    (before_repository / "src" / "extract.py").write_text("destination.write_bytes(entry.read())\n")
    subprocess.run(["git", "-C", str(before_repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(before_repository), "commit", "-qm", "Add reviewed source"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(before_repository), "rev-parse", "HEAD"], text=True
    ).strip()
    subprocess.run(
        ["git", "clone", "-q", str(before_repository), str(after_repository)], check=True
    )
    subprocess.run(
        ["git", "-C", str(before_repository), "remote", "add", "origin", before_origin], check=True
    )
    subprocess.run(
        ["git", "-C", str(after_repository), "remote", "set-url", "origin", after_origin],
        check=True,
    )
    before = create_cli_scan(
        state_dir,
        tmp_path / "before-results",
        before_repository,
        target_revision=revision,
        identity_anchor="before-origin-fixture",
    )
    after = create_cli_scan(
        state_dir,
        tmp_path / "after-results",
        after_repository,
        target_revision=revision,
        identity_anchor="after-origin-fixture",
    )
    listed = run_workbench(state_dir, "list-scans", "--repository", str(after_repository))
    assert len(listed["scans"]) == (2 if same_repository else 1)
    if same_repository:
        compared = compare_scan_pair(state_dir, before, after)
        assert compared["summary"]["persisting"] == 1
        saved = save_scan_matches(state_dir, before, after)
        assert saved["summary"]["persisting"] == 1
        assert compare_scan_pair(state_dir, before, after, "--require-matches") == saved
    else:
        for command, arguments in (
            ("compare-scans", ()),
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
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            assert connection.execute("SELECT COUNT(*) FROM scan_comparisons").fetchone() == (0,)


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
    assert compared["summary"]["persisting"] == 1
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 0
    assert "identical locations" in compared["findings"][0]["matchReason"]

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


def replace_history_repository(repository: Path, origin: str) -> None:
    previous_identity = (repository / ".git").stat()
    retained = repository.with_name("retained-repository")
    repository.rename(retained)
    subprocess.run(["git", "clone", "-q", str(retained), str(repository)], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "remote", "set-url", "origin", origin], check=True
    )
    current_identity = (repository / ".git").stat()
    # Keep the old directory alive so inode reuse cannot make the fixture ambiguous.
    assert (previous_identity.st_dev, previous_identity.st_ino) != (
        current_identity.st_dev,
        current_identity.st_ino,
    )


HISTORY_ORIGIN = "https://example.test/original.git"


@pytest.fixture
def git_finding_history(tmp_path: Path):
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    origin = HISTORY_ORIGIN
    subprocess.run(["git", "-C", str(repository), "remote", "add", "origin", origin], check=True)

    def scan(anchor: str, location: str) -> dict[str, Any]:
        return create_cli_scan(
            state_dir,
            tmp_path / "scans",
            repository,
            target_revision=revision,
            identity_anchor=anchor,
            relative_path=location,
        )

    return state_dir, repository, scan


@pytest.mark.parametrize(
    ("change", "confirmed"),
    [
        ("replacement", True),
        ("same-repository", True),
        ("same-origin-clone", True),
        ("remote-edit", True),
        ("replacement", False),
        ("legacy", True),
    ],
)
def test_finding_history_scopes_saved_aliases_to_repository_identity(
    git_finding_history, monkeypatch: pytest.MonkeyPatch, change: str, confirmed: bool
) -> None:
    state_dir, repository, scan = git_finding_history
    old = [scan("control-a", "src/old-a.py"), scan("control-b", "src/old-b.py")]
    old_findings = [get_scan(state_dir, item["scanId"])["scan"]["findings"][0] for item in old]
    if confirmed:
        save_scan_matches(
            state_dir,
            *old,
            confirmed_match(old_findings[0]["occurrenceId"], old_findings[1]["occurrenceId"]),
        )
    set_triage(
        state_dir,
        old_findings[0]["occurrenceId"],
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic triage fixture.",
    )
    if change in {"replacement", "same-origin-clone"}:
        replace_history_repository(
            repository,
            "https://example.test/replacement.git" if change == "replacement" else HISTORY_ORIGIN,
        )
    elif change == "remote-edit":
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "remote",
                "set-url",
                "origin",
                "https://example.test/changed.git",
            ],
            check=True,
        )
    current = [scan("control-a", "src/new-a.py"), scan("control-b", "src/new-b.py")]
    if change == "legacy":
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute("UPDATE scans SET target_git_identity_json = NULL")
    eligible = change != "replacement"
    direct = compare_scan_pair(state_dir, old[0], current[0], check=False)
    assert (direct["returncode"] == 0) == eligible
    if not eligible:
        assert "same repository target" in direct["stderr"]
    shown = [get_scan(state_dir, item["scanId"])["scan"]["findings"][0] for item in current]
    assert [item["findingId"] for item in shown] == [item["findingId"] for item in old_findings]
    assert shown[0]["findingId"] != shown[1]["findingId"]
    assert all(item["triage"]["status"] == "open" for item in shown)
    old_ids = {item["scanId"] for item in old}
    for finding in shown:
        historical_ids = {item["scanId"] for item in finding.get("matches", [])}
        assert bool(historical_ids & old_ids) == eligible
        assert bool(set(finding.get("knownScanIds", [])) & old_ids) == eligible
        if not eligible:
            assert "matches" not in finding
            assert "knownSince" not in finding
            assert "knownScanIds" not in finding
    compared = compare_scan_pair(state_dir, *current, "--include-matching-inputs")
    assert compared["summary"]["persisting"] == int(eligible and confirmed)
    groups = [sorted(item["findingId"] for item in old_findings)] if eligible and confirmed else []
    assert compared["matchingInputs"].get("knownFindingGroups", []) == groups
    plan = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(repository))
    batch = next(item for item in plan["batches"] if item["afterScanId"] == current[1]["scanId"])
    assert batch.get("knownFindingGroups", []) == groups
    assert set(batch.get("excludedScanIds", [])) == (set() if eligible else old_ids)
    if not eligible:
        assert [item["scanId"] for item in batch["beforeScans"]] == [current[0]["scanId"]]
    if change == "legacy":
        workbench = load_script("workbench_db")

        def unexpected_git_lookup(*_args: Any, **_kwargs: Any) -> str:
            raise AssertionError("Saved legacy groups must not require repository discovery")

        monkeypatch.setitem(
            workbench.scan_history.git_output.__globals__, "git_command", unexpected_git_lookup
        )
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.row_factory = sqlite3.Row
            assert (
                workbench.scan_history.list_unmatched_scan_pairs(
                    connection,
                    Namespace(repository=str(repository), force=False),
                    backfill_finding_details=workbench.backfill_legacy_finding_details,
                    read_coverage=workbench.coverage_for_comparison,
                )
                == plan
            )


@pytest.mark.parametrize(
    ("replacement", "related", "mixed_neighbor"),
    [(True, True, False), (False, True, False), (True, False, False), (False, True, True)],
)
def test_finding_history_scopes_related_location_veto_to_repository_identity(
    git_finding_history, replacement: bool, related: bool, mixed_neighbor: bool
) -> None:
    state_dir, repository, scan = git_finding_history
    old = [scan("control-a", "src/old-a.py")]
    if mixed_neighbor:
        replace_history_repository(repository, "https://example.test/original.git")
    old.append(scan("control-b", "src/old-b.py"))
    if related:
        findings = [get_scan(state_dir, item["scanId"])["scan"]["findings"][0] for item in old]
        save_scan_matches(
            state_dir,
            *old,
            related=(
                {
                    "beforeOccurrenceId": findings[0]["occurrenceId"],
                    "afterOccurrenceId": findings[1]["occurrenceId"],
                    "reason": "Different root causes.",
                },
            ),
        )
    if mixed_neighbor:
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "remote",
                "set-url",
                "origin",
                "https://example.test/changed.git",
            ],
            check=True,
        )
    elif replacement:
        replace_history_repository(repository, "https://example.test/replacement.git")
    current = [scan("control-a", "src/current.py"), scan("control-b", "src/current.py")]
    direct = compare_scan_pair(state_dir, old[0], current[0], check=False)
    assert (direct["returncode"] == 0) == (not replacement and not mixed_neighbor)
    if mixed_neighbor:
        assert compare_scan_pair(state_dir, old[1], current[1], check=False)["returncode"] == 0
    compared = compare_scan_pair(state_dir, *current)
    expected = int(replacement or mixed_neighbor or not related)
    assert compared["summary"]["persisting"] == expected
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 1 - expected


@pytest.mark.parametrize("replacement", [True, False])
def test_finding_history_scopes_transitive_aliases_to_repository_identity(
    git_finding_history, replacement: bool
) -> None:
    state_dir, repository, scan = git_finding_history
    old = [scan("control-a", "src/old-a.py"), scan("control-bridge", "src/old-x.py")]
    old_findings = [get_scan(state_dir, item["scanId"])["scan"]["findings"][0] for item in old]
    save_scan_matches(
        state_dir,
        *old,
        confirmed_match(old_findings[0]["occurrenceId"], old_findings[1]["occurrenceId"]),
    )
    if replacement:
        replace_history_repository(repository, "https://example.test/replacement.git")
    current = [
        scan("control-a", "src/current-a.py"),
        scan("control-bridge", "src/current-x.py"),
        scan("control-b", "src/current-b.py"),
    ]
    findings = [get_scan(state_dir, item["scanId"])["scan"]["findings"][0] for item in current]
    save_scan_matches(
        state_dir,
        current[1],
        current[2],
        confirmed_match(findings[1]["occurrenceId"], findings[2]["occurrenceId"]),
    )
    direct = compare_scan_pair(state_dir, old[0], current[0], check=False)
    assert (direct["returncode"] == 0) == (not replacement)
    compared = compare_scan_pair(state_dir, current[0], current[2], "--include-matching-inputs")
    assert compared["summary"]["persisting"] == int(not replacement)
    groups = compared["matchingInputs"]["knownFindingGroups"]
    expected_findings = findings[1:] if replacement else findings
    assert groups == [sorted(item["findingId"] for item in expected_findings)]
    first = get_scan(state_dir, current[0]["scanId"])["scan"]["findings"][0]
    bridge = get_scan(state_dir, current[1]["scanId"])["scan"]["findings"][0]
    if replacement:
        assert "matches" not in first
        assert {item["scanId"] for item in bridge["matches"]} == {current[2]["scanId"]}
    else:
        assert current[2]["scanId"] in {item["scanId"] for item in first["matches"]}


@pytest.mark.parametrize(
    "change",
    [
        "different-origin",
        "retained-directory",
        "same-origin",
        "remote-edit",
        "recreated-subdirectory",
    ],
)
def test_scan_comparison_checks_saved_identity_when_target_path_is_reused(
    tmp_path: Path, change: str
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    target = repository
    if change == "recreated-subdirectory":
        target = repository / "selected"
        (target / "src").mkdir(parents=True)
        (target / "src" / "extract.py").write_text("destination.write_bytes(entry.read())\n")
        subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "commit", "-qm", "Add nested target fixture"],
            check=True,
        )
        revision = subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip()
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/first.git",
        ],
        check=True,
    )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", target, target_revision=revision
    )
    git_inode = (repository / ".git").stat().st_ino
    if change == "recreated-subdirectory":
        saved_target = tmp_path / "saved-target"
        target.rename(saved_target)
        shutil.copytree(saved_target, target)
    elif change != "remote-edit":
        saved_repository = tmp_path / "saved-repository"
        if change == "retained-directory":
            saved_repository.mkdir()
            for child in repository.iterdir():
                child.rename(saved_repository / child.name)
        else:
            repository.rename(saved_repository)
        subprocess.run(["git", "clone", "-q", str(saved_repository), str(repository)], check=True)
    origin = "first" if change == "same-origin" else "second"
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "set-url",
            "origin",
            f"git@github.com:example/{origin}",
        ],
        check=True,
    )
    after = create_cli_scan(
        state_dir,
        tmp_path / "after-results",
        target,
        target_revision=revision,
        identity_anchor="replacement-repository-control",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        saved = [
            connection.execute("SELECT * FROM scans WHERE id = ?", (scan["scanId"],)).fetchone()
            for scan in (before, after)
        ]
    for field in (
        "target_id",
        "target_path",
        "target_revision",
        "target_snapshot_digest",
        "target_git_prefix",
    ):
        assert saved[0][field] == saved[1][field]
    identities = [json.loads(scan["target_git_identity_json"]) for scan in saved]
    assert identities[0]["commonDirectory"] == identities[1]["commonDirectory"]
    assert (identities[0]["origin"] == identities[1]["origin"]) == (change == "same-origin")
    assert (saved[0]["target_inode"] == saved[1]["target_inode"]) == (
        change in {"remote-edit", "retained-directory"}
    )
    assert ((repository / ".git").stat().st_ino == git_inode) == (
        change in {"remote-edit", "recreated-subdirectory"}
    )

    if change in {"different-origin", "retained-directory"}:
        compared = compare_scan_pair(state_dir, before, after, check=False)
        assert compared["returncode"] != 0, compared
        assert "same repository target" in compared["stderr"]
    else:
        compared = compare_scan_pair(state_dir, before, after)
        assert compared["summary"]["persisting"] == 1


def test_scan_comparison_keeps_distinct_repositories_after_target_replacement(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    before_repository = tmp_path / "before"
    after_repository = tmp_path / "after"
    revision = initialize_git_repository(before_repository)
    subprocess.run(
        ["git", "clone", "-q", str(before_repository), str(after_repository)], check=True
    )
    subprocess.run(["git", "-C", str(after_repository), "remote", "remove", "origin"], check=True)
    for repository, origin in (
        (before_repository, "https://github.com/example/first.git"),
        (after_repository, "https://github.com/example/second.git"),
    ):
        subprocess.run(
            ["git", "-C", str(repository), "remote", "add", "origin", origin], check=True
        )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", before_repository, target_revision=revision
    )
    after = create_cli_scan(
        state_dir,
        tmp_path / "after-results",
        after_repository,
        target_revision=revision,
        identity_anchor="separate-repository-control",
    )
    rejected = compare_scan_pair(state_dir, before, after, check=False)
    assert rejected["returncode"] != 0
    assert "same repository target" in rejected["stderr"]

    before_repository.rename(tmp_path / "before-saved")
    if os.name == "nt":
        subprocess.run(
            f'cmd /d /s /c "mklink /J "{before_repository}" "{after_repository}""',
            check=True,
        )
    else:
        before_repository.symlink_to(after_repository, target_is_directory=True)
    rejected = compare_scan_pair(state_dir, before, after, check=False)
    assert rejected["returncode"] != 0
    assert "same repository target" in rejected["stderr"]


@pytest.mark.parametrize("checkout_kind", ["worktree", "clone"])
def test_scan_comparison_keeps_saved_repository_identity(
    tmp_path: Path, checkout_kind: str
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    other = tmp_path / "other"
    revision = initialize_git_repository(repository)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/shared.git",
        ],
        check=True,
    )
    if checkout_kind == "worktree":
        subprocess.run(
            ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(other)],
            check=True,
        )
    else:
        subprocess.run(["git", "clone", "-q", str(repository), str(other)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(other),
                "remote",
                "set-url",
                "origin",
                "git@github.com:example/shared",
            ],
            check=True,
        )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", repository, target_revision=revision
    )
    after = create_cli_scan(
        state_dir,
        tmp_path / "after-results",
        other,
        target_revision=revision,
        identity_anchor="corresponding-repository-control",
    )
    assert compare_scan_pair(state_dir, before, after)["summary"]["persisting"] == 1

    repository.rename(tmp_path / "repository-saved")
    initialize_git_repository(repository)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/unrelated.git",
        ],
        check=True,
    )
    compared = compare_scan_pair(state_dir, before, after)
    assert compared["summary"]["persisting"] == 1
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 0


@pytest.mark.parametrize("legacy_identity", ["missing-snapshot", "missing-directory-identity"])
def test_legacy_git_identity_preserves_saved_matches_without_inference(
    tmp_path: Path, legacy_identity: str
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", repository, target_revision=revision
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        if legacy_identity == "missing-snapshot":
            connection.execute("ALTER TABLE scans DROP COLUMN target_git_identity_json")
            connection.execute(
                "DELETE FROM schema_migrations WHERE name = 'save scan Git repository identities'"
            )
        else:
            identity = json.loads(
                connection.execute(
                    "SELECT target_git_identity_json FROM scans WHERE id = ?", (before["scanId"],)
                ).fetchone()[0]
            )
            identity.pop("commonDirectoryIdentity")
            connection.execute(
                "UPDATE scans SET target_git_identity_json = ? WHERE id = ?",
                (json.dumps(identity), before["scanId"]),
            )
    after = create_cli_scan(
        state_dir,
        tmp_path / "after-results",
        repository,
        target_revision=revision,
        identity_anchor="legacy-repository-control",
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        old_identity = connection.execute(
            "SELECT target_git_identity_json FROM scans WHERE id = ?", (before["scanId"],)
        ).fetchone()[0]
        if legacy_identity == "missing-snapshot":
            assert old_identity is None
        else:
            assert "commonDirectoryIdentity" not in json.loads(old_identity)
        saved_identity = connection.execute(
            "SELECT target_git_identity_json FROM scans WHERE id = ?", (after["scanId"],)
        ).fetchone()[0]
        assert json.loads(saved_identity)["commonDirectory"] == str(repository / ".git")
        assert json.loads(saved_identity)["commonDirectoryIdentity"] is not None
    compared = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert compared["summary"]["persisting"] == 0
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 1
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
    assert get_scan(state_dir, before["scanId"])["scan"]["scanId"] == before["scanId"]


@pytest.mark.parametrize("checkout_kind", ["same", "worktree", "clone"])
def test_equivalent_locations_require_same_git_target_prefix(
    tmp_path: Path, checkout_kind: str
) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    for name in ("first", "second"):
        source = repository / name / "src"
        source.mkdir(parents=True)
        (source / "extract.py").write_text("destination.write_bytes(entry.read())\n")
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Add target fixtures"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    other = repository
    if checkout_kind != "same":
        other = tmp_path / "other-checkout"
        if checkout_kind == "worktree":
            subprocess.run(
                ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(other)],
                check=True,
            )
        else:
            subprocess.run(["git", "clone", "-q", str(repository), str(other)], check=True)
            for checkout in (repository, other):
                subprocess.run(
                    ["git", "-C", str(checkout), "remote", "remove", "origin"],
                    check=False,
                    capture_output=True,
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(checkout),
                        "remote",
                        "add",
                        "origin",
                        "https://github.com/example/project.git",
                    ],
                    check=True,
                )
    before = create_cli_scan(
        state_dir, tmp_path / "before-results", repository / "first", target_revision=revision
    )
    after = create_cli_scan(
        state_dir,
        tmp_path / "after-results",
        other / "second",
        target_revision=revision,
        identity_anchor="other-control",
    )
    compared = compare_scan_pair(state_dir, before, after)
    assert compared["summary"]["persisting"] == 0
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 1
    corresponding = create_cli_scan(
        state_dir,
        tmp_path / "corresponding-results",
        other / "first",
        target_revision=revision,
        identity_anchor="renamed-control",
    )
    compared = compare_scan_pair(state_dir, before, corresponding)
    assert compared["summary"]["persisting"] == 1
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 0

    # Saved positions must not change when a former target becomes a directory link.
    original_target = repository / "first"
    original_target.rename(repository / "first-saved")
    if os.name == "nt":
        subprocess.run(
            f'cmd /d /s /c "mklink /J "{original_target}" "{repository / "second"}""',
            check=True,
        )
    else:
        original_target.symlink_to(repository / "second", target_is_directory=True)
    compared = compare_scan_pair(state_dir, before, after)
    assert compared["summary"]["persisting"] == 0
    assert compared["summary"]["new"] == compared["summary"]["not_observed"] == 1
    assert compare_scan_pair(state_dir, before, corresponding)["summary"]["persisting"] == 1

    if checkout_kind == "same":
        # Legacy rows cannot reconstruct a trustworthy scan-time position.
        with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
            connection.execute("UPDATE scans SET target_git_prefix = NULL")
        compared = compare_scan_pair(state_dir, before, corresponding, "--include-matching-inputs")
        assert compared["summary"]["persisting"] == 0
        saved = save_scan_matches(
            state_dir,
            before,
            corresponding,
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
    initialize_git_repository(after_repository)
    (after_repository / "CHANGES.md").write_text("fixture update\n")
    subprocess.run(["git", "-C", str(after_repository), "add", "CHANGES.md"], check=True)
    subprocess.run(
        ["git", "-C", str(after_repository), "commit", "-qm", "Add fixture update"], check=True
    )
    after_revision = subprocess.run(
        ["git", "-C", str(after_repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
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
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        for (identity_json,) in connection.execute("SELECT target_git_identity_json FROM scans"):
            assert json.loads(identity_json)["origin"] == ["github.com", "example/project"]
    for target in (before_repository, after_repository):
        pending = run_workbench(state_dir, "list-unmatched-scan-pairs", "--repository", str(target))
        assert pending["scanCount"] == 2
        assert pending["batches"][0]["afterScanId"] == after["scanId"]
        assert pending["batches"][0]["beforeScans"][0]["scanId"] == before["scanId"]

    compared = compare_scan_pair(state_dir, before, after, "--include-matching-inputs")
    assert compared["summary"]["new"] == 1
    assert compared["summary"]["not_observed"] == 1

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


def test_cli_scan_comparison_distinguishes_absence_from_out_of_scope(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "tests").mkdir()
    root = tmp_path / "results"
    original = create_cli_scan(state_dir, root, repository, paths=["src"])
    partial = create_cli_scan(
        state_dir, root, repository, finding=False, follow_up=True, paths=["src"]
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
        expected = "not_observed" if later is partial else "unknown"
        assert compared["summary"][expected] == 1
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
