from __future__ import annotations

import argparse
import json
import os
import runpy
import sqlite3
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import pytest
from test_workbench_db import (
    SCRIPT,
    create_saved_workspace,
    initialize_git_repository,
    run_workbench,
    write_completed_contract,
)


def start_prompt_only_scan(
    state_dir: Path,
    target: Path,
    scan_root: Path,
    *,
    thread_id: str = "thread-prompt-only-scan",
    mode: str = "standard",
    target_summary: str = "Prompt-only scan",
    user_context: str = "Inspect authentication boundaries",
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
        target_summary,
        "--user-context",
        user_context,
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
    scope: str = ".",
    target_summary: str = "Headless standard scan",
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
        scope,
        "--target-summary",
        target_summary,
        "--user-context",
        user_context,
        "--scan-root",
        str(scan_root),
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
    updated = run_workbench(
        state_dir,
        "update-scan-context",
        "--scan-id",
        scan_id,
        "--thread-id",
        "thread-prompt-only-scan",
        "--user-context",
        updated_context,
    )
    assert updated["scan"]["userContext"] == updated_context

    next_phase = run_workbench(
        state_dir,
        "update-progress",
        "--scan-id",
        scan_id,
        "--phase",
        "discovery",
    )
    assert next_phase["scan"]["progress"]["phase"] == "discovery"
    assert next_phase["scan"]["userContext"] == updated_context


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
    ):
        connection = start_globals["connect"]()
        try:
            started = start(connection, args)
        finally:
            connection.close()

    assert len(observed_metadata) == 1
    metadata = observed_metadata[0]
    assert metadata is not None
    scan_id = str(started["results"]["scanId"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        identity = connection.execute(
            "SELECT target_device, target_inode FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    serialize_identity = start_globals["serialize_filesystem_identity"]
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
    pending = run_workbench(
        state_dir,
        "start-scan",
        "--workspace-id",
        str(saved["id"]),
        "--scan-root",
        str(scan_root),
    )
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


def test_headless_directory_set_controls_identity_and_coverage(tmp_path: Path) -> None:
    target = tmp_path / "target"
    initialize_git_repository(target)
    for directory in ("service", "service/nested", "library", "dependency"):
        (target / directory).mkdir()
        (target / directory / "code.py").write_text("pass\n")
    state = tmp_path / "state"

    def start(paths: list[str]) -> dict[str, object]:
        return run_workbench(
            state,
            "start-headless-standard-scan",
            "--thread-id",
            "directory-scan",
            "--target-path",
            str(target),
            "--include-paths-json",
            json.dumps(paths),
            "--scan-root",
            str(tmp_path / "scans"),
        )

    first = start(["service", "library"])
    assert first["scan"]["executionThreadIds"] == []
    joined = start(["./library/", "service/nested", "service", "service"])
    other = start(["dependency", "library"])
    assert joined["startDisposition"] == "joined"
    assert first["scan"]["scanId"] == joined["scan"]["scanId"]
    assert other["scan"]["scanId"] != first["scan"]["scanId"]
    assert first["scan"]["contract"]["scope"]["requiredIncludePaths"] == ["library", "service"]
    assert first["scan"]["progress"]["coverage"]["filesTotal"] == 3
    rejoined = start(["service", "library"])
    assert rejoined["startDisposition"] == "joined"
    assert rejoined["scan"]["scanId"] == first["scan"]["scanId"]
    history = run_workbench(state, "list-scans", "--query", "service")["scans"]
    assert [scan["scanId"] for scan in history] == [first["scan"]["scanId"]]
    assert history[0]["scope"] == "."
    assert history[0]["includePaths"] == ["library", "service"]


def test_headless_directory_set_preserves_nested_git_file_counts(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    scan_root = tmp_path / "scans"
    standalone_counts = []
    for directory in ("service", "library"):
        repository = target / directory
        initialize_git_repository(repository)
        (repository / ".gitignore").write_text("ignored.py\n")
        (repository / "untracked.py").write_text("pass\n")
        (repository / "ignored.py").write_text("pass\n")
        (repository / ".git" / "fixture-metadata").write_text("fixture\n")
        standalone = start_headless_standard_scan(
            state, repository, scan_root, thread_id=f"standalone-{directory}"
        )
        standalone_counts.append(standalone["scan"]["progress"]["coverage"]["filesTotal"])
    (target / "other").mkdir()
    (target / "other" / "code.py").write_text("pass\n")
    (target / "root.py").write_text("pass\n")

    combined = run_workbench(
        state,
        "start-headless-standard-scan",
        "--thread-id",
        "combined-directories",
        "--target-path",
        str(target),
        "--include-paths-json",
        '["service", "library"]',
        "--scan-root",
        str(scan_root),
    )["scan"]

    assert standalone_counts == [3, 3]
    assert combined["contract"]["scope"]["requiredIncludePaths"] == ["library", "service"]
    assert combined["progress"]["coverage"]["filesTotal"] == sum(standalone_counts)


@pytest.mark.parametrize(
    ("command", "first_selection"),
    [
        ("start-headless-standard-scan", "--scope"),
        ("start-headless-standard-scan", "--include-paths-json"),
        ("start-prompt-only-scan", "--scope"),
    ],
)
@pytest.mark.parametrize(
    "directory",
    [
        "café",
        "name-\x7f",
        pytest.param(
            "1:module", marks=pytest.mark.skipif(os.name == "nt", reason="POSIX directory name")
        ),
    ],
)
def test_prompt_driven_scans_join_literal_directory_selection(
    tmp_path: Path, command: str, first_selection: str, directory: str
) -> None:
    target = tmp_path / "target"
    (target / directory).mkdir(parents=True)
    (target / directory / "code.py").write_text("pass\n")

    def start(selection: str) -> dict[str, object]:
        return run_workbench(
            tmp_path / "state",
            command,
            "--thread-id",
            "unicode-directory-scan",
            "--target-path",
            str(target),
            selection,
            f" {directory} " if selection == "--scope" else json.dumps([directory]),
            "--scan-root",
            str(tmp_path / "scans"),
            *(("--mode", "standard") if command == "start-prompt-only-scan" else ()),
        )

    first = start(first_selection)
    selections = (
        ["--scope"] if command == "start-prompt-only-scan" else ["--scope", "--include-paths-json"]
    )
    for selection in selections:
        joined = start(selection)
        assert joined["startDisposition"] == "joined"
        assert joined["scan"]["scanId"] == first["scan"]["scanId"]
    history = run_workbench(tmp_path / "state", "list-scans", "--query", directory)["scans"]
    assert [scan["scanId"] for scan in history] == [first["scan"]["scanId"]]
    assert history[0]["scope"] == directory
    assert history[0]["includePaths"] == [directory]


@pytest.mark.parametrize(
    "selected",
    [
        ["app/[id]", "library"],
        ["library", "name-\x7f"],
        pytest.param(
            ["1:module", "library"],
            marks=pytest.mark.skipif(os.name == "nt", reason="POSIX directory name"),
        ),
        pytest.param(
            [" leading", "trailing "],
            marks=pytest.mark.skipif(os.name == "nt", reason="POSIX trailing-space directory"),
        ),
    ],
)
def test_headless_directory_set_survives_completion(tmp_path: Path, selected: list[str]) -> None:
    target = tmp_path / "target"
    for directory in (*selected, "dependency"):
        (target / directory).mkdir(parents=True)
        (target / directory / "code.py").write_text("pass\n")
    state = tmp_path / "state"
    started = run_workbench(
        state,
        "start-headless-standard-scan",
        "--thread-id",
        "directory-scan",
        "--target-path",
        str(target),
        "--include-paths-json",
        json.dumps([f"./{directory}/" for directory in selected]),
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan = started["scan"]
    scan_id = str(scan["scanId"])
    scan_dir = Path(str(scan["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    manifest_path = scan_dir / "scan-manifest.json"
    draft = json.loads(manifest_path.read_text())
    del draft["scan"]["scope"]
    manifest_path.write_text(json.dumps(draft))
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))

    completed = run_workbench(
        state,
        "complete-scan",
        "--scan-id",
        scan_id,
        "--claim-token",
        str(scan["handoffClaimToken"]),
    )["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["contract"]["scope"]["requiredIncludePaths"] == selected
    manifest = json.loads(manifest_path.read_text())
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert manifest["scan"]["scope"] == {
        "includePaths": selected,
        "excludePaths": [],
    }
    assert coverage["mode"] == "scoped_path"
    assert coverage["includePaths"] == selected
    assert coverage["excludePaths"] == []


@pytest.mark.skipif(sys.platform != "linux", reason="Linux non-UTF-8 directory name")
def test_headless_directory_selection_rejects_non_utf8_before_creating_scan(tmp_path: Path) -> None:
    target = tmp_path / "target"
    for directory in ("service", "bad-\udcff"):
        (target / directory).mkdir(parents=True)
        (target / directory / "code.py").write_text("pass\n")
    state = tmp_path / "state"
    run_workbench(state, "database-info")
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        before = list(connection.iterdump())

    scan_root = tmp_path / "scans"
    rejected = run_workbench(
        state,
        "start-headless-standard-scan",
        "--thread-id",
        "invalid-selection-scan",
        "--target-path",
        str(target),
        "--include-paths-json",
        json.dumps(["service", "bad-\udcff"]),
        "--scan-root",
        str(scan_root),
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "UTF-8 directory paths" in rejected["stderr"]
    assert not scan_root.exists()
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert list(connection.iterdump()) == before


def test_headless_whole_repository_selection_joins_legacy_scope(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "service").mkdir(parents=True)
    (target / "service" / "code.py").write_text("pass\n")
    (target / "root.py").write_text("pass\n")
    scan_ids = []
    for selection in (
        (),
        ("--include-paths-json", '["."]'),
        ("--include-paths-json", '["service", ".", "service"]'),
        ("--scope", "."),
    ):
        started = run_workbench(
            tmp_path / "state",
            "start-headless-standard-scan",
            "--thread-id",
            "whole-repository-scan",
            "--target-path",
            str(target),
            "--scan-root",
            str(tmp_path / "scans"),
            *selection,
        )
        assert started["scan"]["contract"]["scope"]["requiredIncludePaths"] == ["."]
        assert started["scan"]["progress"]["coverage"]["filesTotal"] == 2
        scan_ids.append(started["scan"]["scanId"])
    assert len(set(scan_ids)) == 1


@pytest.mark.parametrize(
    ("selection", "selected"),
    [
        (("--scope", "service"), ["service"]),
        (("--include-paths-json", '[" leading"]'), [" leading"]),
    ],
)
def test_workspace_restart_preserves_single_directory_selection(
    tmp_path: Path, selection: tuple[str, ...], selected: list[str]
) -> None:
    target = tmp_path / "target"
    for directory in ("service", " leading", "other"):
        (target / directory).mkdir(parents=True)
        (target / directory / "code.py").write_text("pass\n")
    state = tmp_path / "state"
    started = run_workbench(
        state,
        "start-headless-standard-scan",
        "--thread-id",
        "restart-scan",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
        *selection,
    )
    run_workbench(
        state,
        "cancel-scan",
        "--scan-id",
        str(started["scan"]["scanId"]),
        "--thread-id",
        "restart-scan",
    )
    restarted = run_workbench(
        state,
        "start-scan",
        "--workspace-id",
        str(started["workspace"]["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
    )["results"]
    assert restarted["scanId"] != started["scan"]["scanId"]
    assert restarted["contract"]["scope"]["requiredIncludePaths"] == selected
    assert restarted["progress"]["coverage"]["filesTotal"] == 1


def test_workspace_restart_revalidates_saved_directory_selection(tmp_path: Path) -> None:
    target = tmp_path / "target"
    for directory in ("service", "library", "other"):
        (target / directory).mkdir(parents=True)
        (target / directory / "code.py").write_text("pass\n")
    state = tmp_path / "state"
    started = run_workbench(
        state,
        "start-headless-standard-scan",
        "--thread-id",
        "restart-scan",
        "--target-path",
        str(target),
        "--include-paths-json",
        '["service", "library"]',
        "--scan-root",
        str(tmp_path / "scans"),
    )
    scan_id = str(started["scan"]["scanId"])
    run_workbench(state, "cancel-scan", "--scan-id", scan_id, "--thread-id", "restart-scan")
    (target / "service").rename(target / "moved")
    rejected = run_workbench(
        state,
        "start-scan",
        "--workspace-id",
        str(started["workspace"]["id"]),
        "--scan-root",
        str(tmp_path / "scans"),
        check=False,
    )
    assert rejected["returncode"] != 0
    assert "existing directory" in rejected["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT id FROM scans").fetchall() == [(scan_id,)]
        assert connection.execute("SELECT active_scan_id FROM workspaces").fetchall() == [
            (scan_id,)
        ]


@pytest.mark.parametrize(
    ("selection", "error"),
    [
        (("--include-paths-json", "{"), "must be a JSON array"),
        (("--include-paths-json", "[]"), "must be a nonempty JSON array"),
        (("--include-paths-json", '["a:module"]'), "literal repository-relative"),
        (("--include-paths-json", '["./a:module/"]'), "literal repository-relative"),
        (("--include-paths-json", '["./ /"]'), "literal repository-relative"),
        (("--include-paths-json", '[".", ".."]'), "literal repository-relative"),
        (("--include-paths-json", '[".", "missing"]'), "existing directory"),
        (("--scope", ".", "--include-paths-json", '["."]'), "not allowed with argument"),
    ],
)
def test_headless_directory_selection_rejects_invalid_arguments(
    tmp_path: Path, selection: tuple[str, ...], error: str
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    rejected = run_workbench(
        tmp_path / "state",
        "start-headless-standard-scan",
        "--thread-id",
        "invalid-selection-scan",
        "--target-path",
        str(target),
        *selection,
        check=False,
    )
    assert rejected["returncode"] != 0
    assert error in rejected["stderr"]
