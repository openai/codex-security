from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
import uuid
from pathlib import Path

import pytest
from workbench_test_support import initialize_git_repository, recipe, run_workbench


def native_scan(tmp_path: Path, kind: str, *, continuation: bool = True) -> tuple:
    state, target = tmp_path / "state", tmp_path / "target"
    base = initialize_git_repository(target)
    subprocess.run(
        ["git", "commit", "--allow-empty", "-qm", "Next revision"], cwd=target, check=True
    )
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip()
    if kind == "working_tree":
        base = head
    workspace = str(uuid.uuid4())
    run_workbench(
        state,
        "create-workspace",
        "--workspace-id",
        workspace,
        "--target-path",
        str(target),
        "--thread-id",
        "original-thread",
    )
    diff = (
        ()
        if kind == "standard"
        else (
            "--diff-target-kind",
            kind,
            "--diff-base-revision",
            base,
            "--diff-head-revision",
            head,
        )
    )
    run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "standard" if kind == "standard" else "diff",
        *diff,
    )
    scan = run_workbench(state, "start-scan", "--workspace-id", workspace)["results"]
    claim = str(uuid.uuid4())
    run_workbench(
        state, "claim-handoff-delivery", "--scan-id", scan["scanId"], "--claim-token", claim
    )
    owner = "continuation-thread" if continuation else "original-thread"
    if continuation:
        run_workbench(
            state,
            "attach-scan-continuation-thread",
            "--scan-id",
            scan["scanId"],
            "--claim-token",
            claim,
            "--thread-id",
            owner,
        )
    run_workbench(
        state,
        "mark-handoff-delivered",
        "--scan-id",
        scan["scanId"],
        "--claim-token",
        claim,
        "--thread-id",
        owner,
    )
    saved_recipe = recipe(target)
    if kind != "standard":
        saved_recipe["target"] = {
            "kind": "working_tree" if kind == "working_tree" else "refs",
            "paths": [],
            "base": base,
            "head": head,
        }
    registration = {
        "scanId": scan["scanId"],
        "threadId": owner,
        "claimToken": claim,
        "recipe": saved_recipe,
    }
    return state, target, scan, registration


def bind(state, target, scan, registration, *, check=True):
    return run_workbench(
        state,
        "register-cli-scan",
        "--scan-dir",
        scan["scanDir"],
        "--repository",
        str(target),
        "--registration-json-stdin",
        input_text=json.dumps(registration),
        check=check,
    )


@pytest.mark.parametrize("kind", ["standard", "range", "commit", "working_tree"])
def test_native_registration_preserves_continuation_owner(tmp_path: Path, kind: str) -> None:
    state, target, scan, registration = native_scan(tmp_path, kind)
    bound = bind(state, target, scan, registration)
    assert bound["scanId"] == scan["scanId"]
    assert bound["threadId"] is None
    assert bound["recipe"] == registration["recipe"]
    run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "execution-thread",
        "--claim-token",
        registration["claimToken"],
    )
    rebound = bind(state, target, scan, registration)
    assert rebound["threadId"] == "execution-thread"
    for owner in ("original-thread", "execution-thread"):
        rejected = bind(state, target, scan, {**registration, "threadId": owner}, check=False)
        assert "belongs to another Codex thread" in rejected["stderr"]
    rejected = bind(
        state, target, scan, {**registration, "claimToken": str(uuid.uuid4())}, check=False
    )
    assert "owned by another continuation" in rejected["stderr"]


@pytest.mark.parametrize("kind", ["standard", "range", "commit", "working_tree"])
@pytest.mark.parametrize("continuation", [False, True])
def test_native_owner_can_update_context_after_registration(
    tmp_path: Path, kind: str, continuation: bool
) -> None:
    state, target, scan, registration = native_scan(tmp_path, kind, continuation=continuation)

    def update(thread_id, claim_token, context, *, check=True):
        return run_workbench(
            state,
            "update-scan-context",
            "--scan-id",
            scan["scanId"],
            "--thread-id",
            thread_id,
            "--claim-token",
            claim_token,
            "--user-context",
            context,
            check=check,
        )

    owner = registration["threadId"]
    claim = registration["claimToken"]
    assert update(owner, claim, "Before binding")["scan"]["userContext"] == "Before binding"
    bind(state, target, scan, registration)
    assert update(owner, claim, "After binding")["scan"]["userContext"] == "After binding"
    run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "execution-thread",
        "--claim-token",
        claim,
    )
    assert update(owner, claim, "While executing")["scan"]["userContext"] == "While executing"
    for thread_id in ("another-thread", "execution-thread"):
        rejected = update(thread_id, claim, "Rejected update", check=False)
        assert "does not belong to the current Codex thread" in rejected["stderr"]
    rejected = update(owner, str(uuid.uuid4()), "Stale claim", check=False)
    assert "owned by another continuation" in rejected["stderr"]
    assert (
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["userContext"]
        == "While executing"
    )


@pytest.mark.parametrize("kind", ["range", "working_tree"])
@pytest.mark.parametrize("changed", ["kind", "base", "head"])
def test_native_registration_rejects_changed_diff(tmp_path: Path, kind: str, changed: str) -> None:
    state, target, scan, registration = native_scan(tmp_path, kind, continuation=False)
    modified = copy.deepcopy(registration)
    selected = modified["recipe"]["target"]
    if changed == "kind":
        selected[changed] = "refs" if kind == "working_tree" else "working_tree"
    else:
        selected[changed] = subprocess.check_output(
            [
                "git",
                "rev-parse",
                "HEAD^" if changed == "head" or kind == "working_tree" else "HEAD",
            ],
            cwd=target,
            text=True,
        ).strip()
    rejected = bind(state, target, scan, modified, check=False)
    assert rejected["returncode"] != 0
    assert "preserve the original scope" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT recipe_json FROM scans WHERE id = ?", (scan["scanId"],)
            ).fetchone()[0]
            is None
        )
    assert (
        bind(state, target, scan, registration)["recipe"]["target"]
        == registration["recipe"]["target"]
    )


@pytest.mark.parametrize("kind", ["standard", "range", "working_tree"])
@pytest.mark.parametrize("action", ["fail-scan", "cancel-scan"])
def test_stopped_scan_retains_late_execution_thread(tmp_path: Path, kind: str, action: str) -> None:
    state, target, scan, registration = native_scan(tmp_path, kind, continuation=False)
    bind(state, target, scan, registration)
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(
            (
                "--claim-token",
                registration["claimToken"],
                "--message",
                "Synthetic startup interruption.",
            )
            if action == "fail-scan"
            else ()
        ),
    )
    before = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert before["continuationThreadId"] is None
    run_workbench(
        state,
        "set-scan-thread",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        "late-execution",
        "--claim-token",
        registration["claimToken"],
    )
    after = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert after["progress"]["status"] == before["progress"]["status"]
    assert after["continuationThreadId"] is None
    assert "late-execution" in after["threadIds"]
    assert after["executionThreadIds"] == ["late-execution"]
