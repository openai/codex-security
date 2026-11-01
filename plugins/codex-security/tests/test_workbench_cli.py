from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from workbench_test_support import SCRIPT, run_workbench

WORKSPACE_ID = "00000000-0000-4000-8000-000000000001"
SCAN_ID = "00000000-0000-4000-8000-000000000002"
CREATE_WORKSPACE = ["create-workspace", "--workspace-id", WORKSPACE_ID]
STDIN_FLAGS = [
    ["--user-context-stdin"],
    ["--user-context-s"],
    ["--user-context-stdin", "--user-context-stdin"],
    ["--user-context-s", "--user-context-stdin"],
]


@pytest.mark.parametrize("flags", STDIN_FLAGS)
@pytest.mark.parametrize("payload", [b"", "  first\r\nsecond\rcafé  ".encode()])
def test_context_stdin_is_resolved_once(workbench_api, monkeypatch, flags, payload):
    stdin = Mock(buffer=Mock(read=Mock(return_value=payload)))
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "argv", ["workbench_db.py", *CREATE_WORKSPACE, *flags])

    args = workbench_api["parse_args"]("workbench")

    assert args.user_context == payload.decode("utf-8")
    assert args.user_context_stdin is False
    for _ in range(2):
        assert workbench_api["user_context_argument"](args) == (args.user_context.strip() or None)
    stdin.buffer.read.assert_called_once_with()
    stdin.read.assert_not_called()


@pytest.mark.parametrize(
    "flags",
    [
        ["--user-context", "inline", "--user-context-stdin"],
        ["--user-context=inline", "--user-context-stdin"],
        ["--user-context-stdin", "--user-context=inline"],
        ["--user-context=", "--user-context-s"],
        ["--user-context=inline", "--user-context-s", "--user-context-stdin"],
    ],
)
def test_context_conflicts_do_not_read_stdin(workbench_api, monkeypatch, capsys, flags):
    stdin = Mock()
    monkeypatch.setattr(sys, "stdin", stdin)
    command = ["update-scan-context", "--scan-id", SCAN_ID, "--workspace-id", WORKSPACE_ID]
    monkeypatch.setattr(sys, "argv", ["workbench_db.py", *command, *flags])

    with pytest.raises(SystemExit) as error:
        workbench_api["parse_args"]("workbench")

    assert error.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
    stdin.buffer.read.assert_not_called()
    stdin.read.assert_not_called()


@pytest.mark.parametrize("option, exit_code", [("--help", 0), ("--unknown", 2)])
def test_context_stdin_is_not_read_before_argument_parsing(
    workbench_api, monkeypatch, option, exit_code
):
    stdin = Mock()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(
        sys, "argv", ["workbench_db.py", *CREATE_WORKSPACE, "--user-context-stdin", option]
    )

    with pytest.raises(SystemExit) as error:
        workbench_api["parse_args"]("workbench")

    assert error.value.code == exit_code
    stdin.buffer.read.assert_not_called()


# Exercise both workspace setup and Deep Scan creation before either can allocate state.
# The parser-only cases above also check that conflicting options leave stdin untouched.
@pytest.mark.parametrize(
    "command",
    [CREATE_WORKSPACE, ["begin-deep-scan", "--thread-id", "thread-context", "--target-path", "."]],
    ids=lambda args: args[0],
)
@pytest.mark.parametrize(
    "flags, payload, diagnostic",
    [
        (["--user-context-stdin"], b"\xff", b"UnicodeDecodeError"),
        (["--user-context-s"], b"\xff", b"UnicodeDecodeError"),
        (["--user-context=inline", "--user-context-stdin"], b"stdin", b"not allowed with argument"),
    ],
)
def test_invalid_context_does_not_allocate_database(tmp_path, command, flags, payload, diagnostic):
    state_dir = tmp_path / "state"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *command, *flags],
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
        input=payload,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert diagnostic in result.stderr
    assert not state_dir.exists()


def test_context_read_failure_precedes_database_connection(workbench_api, monkeypatch):
    stdin = Mock(buffer=Mock(read=Mock(side_effect=ValueError("read of closed file"))))
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "argv", ["workbench_db.py", *CREATE_WORKSPACE, "--user-context-s"])
    connect = Mock()
    monkeypatch.setitem(workbench_api["main"].__globals__, "connect", connect)

    with pytest.raises(ValueError, match="closed file"):
        workbench_api["main"]()

    connect.assert_not_called()


@pytest.mark.parametrize(
    "command",
    ["start-prompt-only-scan", "start-headless-standard-scan", "begin-deep-scan"],
)
def test_scan_context_stdin_preserves_newlines(tmp_path: Path, command: str) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "example.py").write_text("print('example')\n")
    context = "first\r\nsecond\rcafé"

    result = run_workbench(
        tmp_path / "state",
        command,
        "--thread-id",
        "thread-context",
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--scan-root",
        str(tmp_path / "scans"),
        "--user-context-s",
        "--user-context-stdin",
        *(["--mode", "standard"] if command == "start-prompt-only-scan" else []),
        input_text=context,
        environment={"CODEX_HOME": str(tmp_path / "codex-home")},
    )

    assert result["deepScan" if command == "begin-deep-scan" else "scan"]["userContext"] == context


def test_workspace_context_stdin_survives_save_and_update(tmp_path: Path) -> None:
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "example.py").write_text("print('example')\n")
    for command, extra, context in [
        ("create-workspace", [], "created\r\ncontext"),
        (
            "save-workspace",
            ["--target-path", str(target), "--scope", ".", "--mode", "standard"],
            "saved\rcontext",
        ),
    ]:
        workspace = run_workbench(
            state,
            command,
            "--workspace-id",
            WORKSPACE_ID,
            *extra,
            "--user-context-s",
            input_text=context,
        )
        assert workspace["userContext"] == context
    started = run_workbench(
        state,
        "start-scan",
        "--workspace-id",
        WORKSPACE_ID,
        "--scan-root",
        str(tmp_path / "scans"),
    )
    context = "updated\r\ncontext"
    scan = run_workbench(
        state,
        "update-scan-context",
        "--scan-id",
        started["results"]["scanId"],
        "--workspace-id",
        WORKSPACE_ID,
        "--user-context-s",
        input_text=context,
    )
    assert scan["scan"]["userContext"] == context


def test_invalid_context_cannot_mutate_joined_deep_scan(tmp_path: Path) -> None:
    state = tmp_path / "state"
    target = tmp_path / "target"
    target.mkdir()
    (target / "example.py").write_text("print('example')\n")
    environment = {"CODEX_HOME": str(tmp_path / "codex-home")}
    command = [
        "begin-deep-scan",
        "--thread-id",
        "thread-context",
        "--target-path",
        str(target),
        "--scan-root",
        str(tmp_path / "scans"),
    ]
    run_workbench(state, *command, "--model", "original-model", environment=environment)

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            *command,
            "--user-context-s",
            "--model",
            "changed-model",
        ],
        input=b"\xff",
        env={**os.environ, **environment, "CODEX_SECURITY_STATE_DIR": str(state)},
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert b"UnicodeDecodeError" in result.stderr
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT model FROM scans").fetchall() == [("original-model",)]
