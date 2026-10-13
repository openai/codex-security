from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from workbench_test_support import (
    composition_payload,
    recipe,
    run_workbench,
    write_completed_contract,
)

CHECKPOINT = "artifacts/deep-scan/checkpoint.json"
OWNER = "thread-deep-scan"


def begin_target_scan(state, home, target, root, *, thread_id=OWNER, user_context=None):
    return run_workbench(
        state,
        "begin-deep-scan",
        "--target-path",
        str(target),
        "--scan-root",
        str(root),
        "--thread-id",
        thread_id,
        "--user-context-stdin",
        input_text=user_context or "",
        environment={"CODEX_HOME": str(home)},
    )


def save_composition(state, target, scan, *, context=None, snapshot=True, terminal=False):
    directory = Path(scan["scanDir"])
    claim = scan["handoffClaimToken"]
    run_workbench(
        state,
        "register-cli-scan",
        "--repository",
        str(target),
        "--scan-dir",
        str(directory),
        "--registration-json-stdin",
        input_text=json.dumps(
            {
                "scanId": scan["scanId"],
                "threadId": OWNER,
                "claimToken": claim,
                "recipe": recipe(target, "deep"),
            }
        ),
    )
    aggregate = None
    if terminal:
        write_completed_contract(
            directory,
            scan["scanId"],
            target,
            relative_path="app.py",
            coverage_mode="deep_repository",
        )
        aggregate = {
            "scanId": scan["scanId"],
            "findings": json.loads((directory / "findings.json").read_text())["findings"],
            "coverage": json.loads((directory / "coverage.json").read_text()),
        }
    value = {
        "version": 3,
        "startedAt": "2026-01-01T00:00:00Z",
        "passes": [],
        "mergedScanIds": [],
        "aggregate": aggregate,
        "noNewStreak": 0,
        "consecutiveErrors": 0,
    }
    if snapshot:
        value["discoveryUserContext"] = context
    if terminal:
        value["terminalReason"] = "saturated"
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan["scanId"],
        "--artifact-path",
        CHECKPOINT,
        "--claim-token",
        claim,
        input_text=composition_payload(directory, value),
    )
    return directory / CHECKPOINT


def complete(state, scan):
    run_workbench(
        state,
        "complete-scan",
        "--scan-id",
        scan["scanId"],
        "--claim-token",
        scan["handoffClaimToken"],
    )


def update_context(state, scan, context):
    return run_workbench(
        state,
        "update-scan-context",
        "--scan-id",
        scan["scanId"],
        "--thread-id",
        OWNER,
        "--claim-token",
        scan["handoffClaimToken"],
        "--user-context-stdin",
        input_text=context or "",
    )


@pytest.fixture
def native_target(tmp_path):
    state, home = tmp_path / "state", tmp_path / "codex-home"
    target, root = tmp_path / "target", tmp_path / "scans"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    return state, home, target, root


CONTEXT_CHANGES = (
    ("Review authentication only.", "Review SQL injection only."),
    ("Review authentication only.", None),
    (None, "Review SQL injection only."),
)


@pytest.mark.parametrize(("first_context", "next_context"), CONTEXT_CHANGES)
def test_target_request_does_not_reuse_different_user_context(
    native_target, first_context, next_context
):
    state, home, target, root = native_target
    first = begin_target_scan(state, home, target, root, user_context=first_context)["scan"]
    save_composition(state, target, first, context=first_context, terminal=True)
    complete(state, first)
    requested = begin_target_scan(
        state, home, target, root, thread_id="thread-new-request", user_context=next_context
    )
    assert requested["startDisposition"] == "created"
    assert requested["scan"]["scanId"] != first["scanId"]
    assert requested["scan"]["userContext"] == next_context
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert dict(connection.execute("SELECT id, user_context FROM scans")) == {
            first["scanId"]: first_context,
            requested["scan"]["scanId"]: next_context,
        }


@pytest.mark.parametrize(("original_context", "edited_context"), CONTEXT_CHANGES)
@pytest.mark.parametrize("request_original", (False, True))
def test_terminal_owner_reuse_matches_original_request_after_context_edit(
    native_target, original_context, edited_context, request_original
):
    state, home, target, root = native_target
    first = begin_target_scan(state, home, target, root, user_context=original_context)["scan"]
    checkpoint = save_composition(state, target, first, context=original_context, terminal=True)
    assert update_context(state, first, edited_context)["scan"]["userContext"] == edited_context
    complete(state, first)
    before = checkpoint.read_bytes()
    requested = begin_target_scan(
        state,
        home,
        target,
        root,
        user_context=original_context if request_original else edited_context,
    )
    assert requested["startDisposition"] == ("joined" if request_original else "created")
    assert (requested["scan"]["scanId"] == first["scanId"]) is request_original
    assert requested["scan"]["userContext"] == edited_context
    assert checkpoint.read_bytes() == before
    assert json.loads(before)["discoveryUserContext"] == original_context
    assert (
        run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["userContext"]
        == edited_context
    )


@pytest.mark.parametrize("original_context", (None, "Review authentication only."))
def test_context_snapshot_survives_owner_join_and_explicit_resume(native_target, original_context):
    state, home, target, root = native_target
    first = begin_target_scan(state, home, target, root, user_context=original_context)["scan"]
    checkpoint = save_composition(state, target, first, context=original_context)
    before = checkpoint.read_bytes()
    updated = "Use updated context in later phases."
    update_context(state, first, updated)
    for requested in (
        begin_target_scan(state, home, target, root, user_context="New request"),
        run_workbench(
            state,
            "begin-deep-scan",
            "--scan-id",
            first["scanId"],
            "--thread-id",
            OWNER,
            "--claim-token",
            first["handoffClaimToken"],
        ),
    ):
        assert requested["startDisposition"] == "joined"
        assert requested["scan"]["scanId"] == first["scanId"]
        assert requested["scan"]["userContext"] == updated
        assert checkpoint.read_bytes() == before
        assert json.loads(before)["discoveryUserContext"] == original_context


@pytest.mark.parametrize("resume_existing", (False, True))
def test_native_composition_does_not_depend_on_retired_worker_tables(
    native_target, resume_existing
):
    state, home, target, root = native_target
    first = begin_target_scan(state, home, target, root, user_context="Original context.")["scan"]
    checkpoint = save_composition(state, target, first, context="Original context.")
    before = checkpoint.read_bytes()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        for table in ("deep_scan_dedup_inputs", "deep_scan_workers", "deep_scan_runs"):
            connection.execute(f"DROP TABLE {table}")
    if resume_existing:
        started = run_workbench(
            state,
            "begin-deep-scan",
            "--scan-id",
            first["scanId"],
            "--thread-id",
            OWNER,
            "--claim-token",
            first["handoffClaimToken"],
        )
    else:
        started = begin_target_scan(
            state, home, target, root, thread_id="thread-new-request", user_context="New context."
        )
    assert started["startDisposition"] == ("joined" if resume_existing else "created")
    assert (started["scan"]["scanId"] == first["scanId"]) is resume_existing
    assert started["scan"]["userContext"] == (
        "Original context." if resume_existing else "New context."
    )
    assert checkpoint.read_bytes() == before


@pytest.mark.parametrize("snapshot", (False, True))
@pytest.mark.parametrize("original_context", (None, "Review authentication only."))
def test_owner_join_preserves_older_composition_context_metadata(
    native_target, original_context, snapshot
):
    state, home, target, root = native_target
    first = begin_target_scan(state, home, target, root, user_context=original_context)["scan"]
    checkpoint = save_composition(state, target, first, context=original_context, snapshot=snapshot)
    before = checkpoint.read_bytes()
    update_context(state, first, "Edited display context.")
    resumed = run_workbench(
        state,
        "begin-deep-scan",
        "--scan-id",
        first["scanId"],
        "--thread-id",
        OWNER,
        "--claim-token",
        first["handoffClaimToken"],
    )
    assert resumed["startDisposition"] == "joined"
    assert resumed["scan"]["userContext"] == "Edited display context."
    assert checkpoint.read_bytes() == before
    assert ("discoveryUserContext" in json.loads(before)) is snapshot
    requested = begin_target_scan(
        state, home, target, root, thread_id="thread-new-request", user_context=original_context
    )
    assert requested["startDisposition"] == "created"
    assert requested["scan"]["scanId"] != first["scanId"]
    assert checkpoint.read_bytes() == before
