from __future__ import annotations

import argparse
import os
import runpy
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier, Event, local
from unittest import mock

import pytest
from test_workbench_db import (
    SCRIPT,
    create_saved_workspace,
    initialize_git_repository,
    run_workbench,
)
from workbench_test_support import get_scan, scan_command, start_scan_command, update_progress


def start_prompt_only_scan(
    state_dir: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-prompt-only-scan",
    mode: str = "standard",
    extra_args: tuple[str, ...] = (),
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "start-prompt-only-scan",
        "--thread-id",
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        mode,
        "--target-summary",
        "Prompt-only scan",
        "--user-context",
        "Inspect authentication boundaries",
        "--scan-root",
        str(scan_root),
        *extra_args,
    )


def start_headless_standard_scan(
    state_dir: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-headless-standard-scan",
    user_context: str = "Inspect authentication boundaries",
) -> dict[str, object]:
    return run_workbench(
        state_dir,
        "start-headless-standard-scan",
        "--thread-id",
        thread_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--target-summary",
        "Headless standard scan",
        "--user-context",
        user_context,
        "--scan-root",
        str(scan_root),
    )


def prompt_scan_arguments(target: Path, root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        thread_id="thread-fixture",
        target_path=str(target),
        scope=".",
        mode="standard",
        diff_target_kind=None,
        diff_base_revision=None,
        diff_head_revision=None,
        diff_content_digest=None,
        user_context=None,
        user_context_stdin=False,
        target_summary=None,
        scan_root=str(root / "scans"),
        model=None,
        reasoning_effort=None,
    )


def test_headless_standard_scan_starts_without_setup_opt_out(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")

    started = start_headless_standard_scan(state_dir, target, tmp_path / "scans")
    scan = started["scan"]
    workspace = started["workspace"]
    assert started["startDisposition"] == "created"
    assert scan["mode"] == "standard"
    assert scan["progress"]["status"] == "running"
    assert scan["progress"]["phase"] == "preflight"
    assert scan["handoffStatus"] == "delivered"
    assert scan["continuationThreadId"] == "thread-headless-standard-scan"
    assert str(uuid.UUID(str(scan["handoffClaimToken"]))) == scan["handoffClaimToken"]
    assert workspace["setup"] == {"submitted": True}
    assert workspace["results"]["scanId"] == scan["scanId"]


def test_headless_standard_scan_preserves_url_user_context(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    user_context = (
        "Repository: https://github.com/example/security-review\n"
        "OAuth issuer: https://accounts.example.test"
    )

    started = start_headless_standard_scan(
        state_dir,
        target,
        tmp_path / "scans",
        user_context=user_context,
    )

    assert started["scan"]["userContext"] == user_context
    assert started["workspace"]["userContext"] == user_context


def test_headless_standard_scan_joins_only_the_owning_thread(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    scan_root = tmp_path / "scans"

    first = start_headless_standard_scan(state_dir, target, scan_root)
    joined = start_headless_standard_scan(state_dir, target, scan_root)
    other = start_headless_standard_scan(
        state_dir, target, scan_root, thread_id="thread-headless-other"
    )

    assert first["startDisposition"] == "created"
    assert joined["startDisposition"] == "joined"
    assert joined["scan"]["scanId"] == first["scan"]["scanId"]
    assert joined["scan"]["handoffClaimToken"] == first["scan"]["handoffClaimToken"]
    assert other["startDisposition"] == "created"
    assert other["scan"]["scanId"] != first["scan"]["scanId"]
    assert other["scan"]["handoffClaimToken"] != first["scan"]["handoffClaimToken"]


def test_headless_standard_scan_serializes_concurrent_starts(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    run_workbench(state_dir, "database-info")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: start_headless_standard_scan(state_dir, target, tmp_path / "scans"),
                range(2),
            )
        )

    assert {result["startDisposition"] for result in results} == {"created", "joined"}
    assert len({result["scan"]["scanId"] for result in results}) == 1


def test_prompt_only_scan_starts_without_persisted_opt_out(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"
    started = start_prompt_only_scan(state_dir, target, scan_root)
    assert started["startDisposition"] == "created"


def test_prompt_only_scan_creates_submitted_delivered_scan(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("print('fixture')\n")
    started = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    assert started["startDisposition"] == "created"
    scan = started["scan"]
    workspace = started["workspace"]
    assert scan["scanId"]
    assert scan["mode"] == "standard"
    assert scan["progress"]["status"] == "running"
    assert scan["handoffStatus"] == "delivered"
    assert workspace["id"]
    assert workspace["setup"] == {"submitted": True}
    assert workspace["results"]["scanId"] == scan["scanId"]


def test_prompt_only_standard_phase_uses_latest_persisted_scan_context(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()

    started = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    scan_id = str(started["scan"]["scanId"])
    updated_context = "Prioritize password-reset token validation."
    updated = scan_command(
        state_dir,
        "update-scan-context",
        scan_id,
        "--thread-id",
        "thread-prompt-only-scan",
        "--user-context",
        updated_context,
    )
    assert updated["scan"]["userContext"] == updated_context

    next_phase = update_progress(state_dir, scan_id, "--phase", "discovery")
    assert next_phase["scan"]["progress"]["phase"] == "discovery"
    assert next_phase["scan"]["userContext"] == updated_context


@pytest.mark.parametrize("headless_standard", [False, True])
@pytest.mark.parametrize("target_changes", [False, True])
@pytest.mark.parametrize("existing_scan", [False, True])
def test_prompt_scan_revalidates_target_after_concurrent_database_write(
    tmp_path: Path, target_changes: bool, existing_scan: bool, headless_standard: bool
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "fixture.py"
    source.write_text("original\n")
    saved = create_saved_workspace(state_dir, target)
    namespace = runpy.run_path(str(SCRIPT), run_name="prompt_scan_lock_test")
    start = namespace["_start_prompt_driven_scan"]
    globals_ = start.__globals__
    identity = globals_["scan_target_identity"]
    calls = 0
    args = prompt_scan_arguments(target, tmp_path)

    def inspect_identity(*args, **kwargs):
        nonlocal calls
        calls += 1
        # Unrelated progress commits during every hash must not prevent startup.
        with sqlite3.connect(state_dir / "workbench.sqlite3", timeout=0) as other:
            other.execute("BEGIN IMMEDIATE")
            other.execute(
                "UPDATE workspaces SET target_summary = ? WHERE id = ?",
                (f"Concurrent setup update {calls}", saved["id"]),
            )
            if calls == 2:
                if existing_scan:
                    other.execute("UPDATE scans SET status = 'failed'")
                if target_changes:
                    source.write_text("changed during hashing\n")
        return identity(*args, **kwargs)

    with (
        mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(state_dir)}),
    ):
        connection = globals_["connect"]()
        connection.execute("PRAGMA busy_timeout = 1375")
        if existing_scan:
            start(connection, args, headless_standard=headless_standard)
        try:
            with mock.patch.dict(globals_, {"scan_target_identity": inspect_identity}):
                if target_changes:
                    with pytest.raises(SystemExit, match="target changed"):
                        start(connection, args, headless_standard=headless_standard)
                else:
                    assert start(connection, args, headless_standard=headless_standard)[
                        "startDisposition"
                    ] == ("created")
                count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                assert count == int(existing_scan) + (0 if target_changes else 1)
            assert not connection.in_transaction
            assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 1375
        finally:
            connection.close()
    assert calls == 2


@pytest.mark.parametrize("target_changes", [False, True])
@pytest.mark.parametrize("writer_arrival", ["before_hash", "during_hash"])
def test_prompt_scan_revalidates_target_after_database_lock_wait(
    tmp_path: Path, target_changes: bool, writer_arrival: str
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "fixture.py"
    source.write_text("original\n")
    namespace = runpy.run_path(str(SCRIPT), run_name="prompt_scan_lock_test")
    start = namespace["_start_prompt_driven_scan"]
    globals_ = start.__globals__
    identity = globals_["scan_target_identity"]
    calls = 0
    args = prompt_scan_arguments(target, tmp_path)

    acquiring = Event()

    def inspect_identity(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            # Initial hashing does not need the database writer lock.
            with sqlite3.connect(state_dir / "workbench.sqlite3", timeout=0) as other:
                other.execute("BEGIN IMMEDIATE")
        result = identity(*args, **kwargs)
        if calls == 2 and writer_arrival == "during_hash":
            blocker.execute("BEGIN IMMEDIATE")
            if target_changes:
                source.write_text("changed before writer admission\n")
        return result

    with mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(state_dir)}):
        connection = globals_["connect"]()
        blocker = sqlite3.connect(state_dir / "workbench.sqlite3", check_same_thread=False)

        class ContendedConnection:
            def __getattr__(self, name):
                return getattr(connection, name)

            def execute(self, sql, *parameters):
                if (
                    writer_arrival == "before_hash"
                    and sql == "BEGIN IMMEDIATE"
                    and not acquiring.is_set()
                ):
                    blocker.execute("BEGIN IMMEDIATE")
                    acquiring.set()
                try:
                    return connection.execute(sql, *parameters)
                except sqlite3.OperationalError:
                    if writer_arrival == "during_hash" and blocker.in_transaction:
                        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 0
                        blocker.commit()
                    raise

        def release_writer():
            assert acquiring.wait(timeout=10)
            if target_changes:
                source.write_text("changed during lock acquisition\n")
            blocker.commit()

        try:
            with (
                ThreadPoolExecutor(max_workers=1) as pool,
                mock.patch.dict(globals_, {"scan_target_identity": inspect_identity}),
            ):
                released = pool.submit(release_writer) if writer_arrival == "before_hash" else None
                if target_changes:
                    with pytest.raises(SystemExit, match="target changed"):
                        start(ContendedConnection(), args, headless_standard=False)
                else:
                    assert (
                        start(ContendedConnection(), args, headless_standard=False)[
                            "startDisposition"
                        ]
                        == "created"
                    )
                if released is not None:
                    released.result()
            count = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            assert count == (0 if target_changes else 1)
            assert not connection.in_transaction
            assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        finally:
            acquiring.set()
            blocker.close()
            connection.close()
    assert calls == (2 if writer_arrival == "before_hash" else 3)


@pytest.mark.parametrize("headless_standard", [False, True])
def test_concurrent_prompt_scan_starts_join_the_winner(
    tmp_path: Path, headless_standard: bool
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "fixture.py").write_text("original\n")
    create_saved_workspace(state_dir, target)
    namespace = runpy.run_path(str(SCRIPT), run_name="prompt_scan_concurrent_test")
    start = namespace["_start_prompt_driven_scan"]
    globals_ = start.__globals__
    identity = globals_["scan_target_identity"]
    ready = Barrier(2)
    caller = local()
    args = prompt_scan_arguments(target, tmp_path)

    def synchronized_identity(*args, **kwargs):
        caller.calls = getattr(caller, "calls", 0) + 1
        result = identity(*args, **kwargs)
        if caller.calls == 2:
            ready.wait(timeout=10)
        return result

    def begin():
        connection = globals_["connect"]()
        try:
            return start(connection, args, headless_standard=headless_standard)
        finally:
            connection.close()

    with (
        mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(state_dir)}),
        mock.patch.dict(globals_, {"scan_target_identity": synchronized_identity}),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        futures = [pool.submit(begin) for _ in range(2)]
        results = [future.result(timeout=20) for future in futures]
    assert sorted(result["startDisposition"] for result in results) == ["created", "joined"]
    assert results[0]["scan"]["scanId"] == results[1]["scan"]["scanId"]
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_setup_scan_reuses_checked_target_metadata(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    saved = create_saved_workspace(state_dir, target)
    namespace = runpy.run_path(str(SCRIPT), run_name="setup_scan_target_identity_test")
    start = namespace["start_scan"]
    start_globals = start.__globals__
    real_scan_target_identity = start_globals["scan_target_identity"]
    observed_metadata: list[os.stat_result | None] = []

    def record_target_identity(
        target_path: Path,
        diff_target: dict[str, str] | None,
        *,
        metadata: os.stat_result | None = None,
    ) -> tuple[str, str | None, int | str, int | str]:
        observed_metadata.append(metadata)
        if metadata is None:
            return real_scan_target_identity(target_path, diff_target)
        return real_scan_target_identity(target_path, diff_target, metadata=metadata)

    args = argparse.Namespace(
        model=None,
        reasoning_effort=None,
        scan_root=str(tmp_path / "scans"),
        workspace_id=str(saved["id"]),
    )
    with (
        mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(state_dir)}),
        mock.patch.dict(
            start_globals,
            {"scan_target_identity": record_target_identity},
        ),
        closing(start_globals["connect"]()) as connection,
    ):
        started = start(connection, args)

    assert len(observed_metadata) == 1
    metadata = observed_metadata[0]
    assert metadata is not None
    scan_id = str(started["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        identity = connection.execute(
            "SELECT target_device, target_inode FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    identity_helpers = runpy.run_path(str(SCRIPT.with_name("filesystem_identity.py")))
    serialize_identity = identity_helpers["serialize_filesystem_identity"]
    assert identity == (
        serialize_identity(metadata.st_dev),
        serialize_identity(metadata.st_ino),
    )


def test_prompt_only_scan_does_not_join_setup_owned_scans(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    scan_root = tmp_path / "scans"
    saved = create_saved_workspace(
        state_dir,
        target,
        thread_id="thread-prompt-only-scan",
    )
    pending = start_scan_command(state_dir, str(saved["id"]), "--scan-root", str(scan_root))
    assert pending["results"]["handoffStatus"] == "pending"
    prompt_only = start_prompt_only_scan(state_dir, target, scan_root)
    assert prompt_only["startDisposition"] == "created"
    assert prompt_only["scan"]["handoffStatus"] == "delivered"
    assert prompt_only["scan"]["scanId"] != pending["results"]["scanId"]


def test_prompt_only_diff_scan_validates_and_persists_canonical_diff_identity(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    head = initialize_git_repository(target)
    (target / "README.md").write_text("changed fixture\n")
    started = start_prompt_only_scan(
        state_dir,
        target,
        tmp_path / "scans",
        thread_id="thread-diff",
        mode="diff",
        extra_args=("--diff-target-kind", "working_tree"),
    )
    assert started["scan"]["diffTarget"]["kind"] == "working_tree"
    assert started["scan"]["diffTarget"]["baseRevision"] == head
    assert started["scan"]["diffTarget"]["headRevision"] == head
    assert started["workspace"]["diffTarget"] == started["scan"]["diffTarget"]


@pytest.mark.parametrize("change_target", [False, True])
def test_prompt_registration_keeps_existing_scans_readable(
    tmp_path: Path, change_target: bool
) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    source = target / "fixture.py"
    source.write_text("original\n")
    existing = start_prompt_only_scan(state_dir, target, tmp_path / "scans")
    scan_id = existing["scan"]["scanId"]
    namespace = runpy.run_path(str(SCRIPT), run_name="prompt_registration_readers")
    start = namespace["_start_prompt_driven_scan"]
    real_identity = start.__globals__["scan_target_identity"]
    hashing = Event()
    resume = Event()
    calls = 0

    def pause_second_hash(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            hashing.set()
            assert resume.wait(20)
        return real_identity(*args, **kwargs)

    def register():
        with closing(namespace["connect"]()) as connection:
            return start(
                connection,
                argparse.Namespace(
                    thread_id="thread-prompt-only-scan",
                    target_path=str(target),
                    scope=".",
                    mode="standard",
                    diff_target_kind=None,
                    diff_base_revision=None,
                    diff_head_revision=None,
                    diff_content_digest=None,
                    user_context="Inspect authentication boundaries",
                    user_context_file=None,
                    target_summary="Prompt-only scan",
                    scan_root=str(tmp_path / "scans"),
                    model=None,
                    reasoning_effort=None,
                ),
                headless_standard=False,
            )

    def read_scans():
        read = get_scan(state_dir, str(scan_id))
        listed = run_workbench(state_dir, "list-scans")
        assert read["scan"]["scanId"] == scan_id
        assert any(scan["scanId"] == scan_id for scan in listed["scans"])

    with (
        mock.patch.dict(os.environ, {"CODEX_SECURITY_STATE_DIR": str(state_dir)}),
        mock.patch.dict(start.__globals__, {"scan_target_identity": pause_second_hash}),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        registration = pool.submit(register)
        try:
            assert hashing.wait(10)
            pool.submit(read_scans).result(timeout=10)
            if change_target:
                source.write_text("changed during registration\n")
        finally:
            resume.set()
        if change_target:
            with pytest.raises(SystemExit, match="target changed while the scan was starting"):
                registration.result(timeout=10)
        else:
            assert registration.result(timeout=10)["startDisposition"] == "joined"
    assert calls == 2
