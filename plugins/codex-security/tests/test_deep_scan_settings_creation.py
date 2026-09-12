"""Original settings survive real creation/claim process death and competing starts."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from workbench_test_support import (
    SCRIPT,
    create_saved_workspace,
    run_workbench,
    start_delivered_scan,
)

# Run the real workbench, pausing only at a requested transaction boundary.
# The parse hook also runs against the parent source, where the settings input
# was ignored, so its regression fails on missing durable bytes.
BOUNDARY_PROCESS = """
import json, runpy, sys
from pathlib import Path
boundary = sys.argv.pop(1)
script = sys.argv.pop(1)
main = runpy.run_path(script)['main']
namespace = main.__globals__
deep = namespace['deep_scan']
parse = namespace['parse_args']
def parse_with_settings(*args, **kwargs):
    result = parse(*args, **kwargs)
    payload = json.loads(sys.stdin.readline())
    result.execution_settings = payload['executionSettings']
    result.user_context = payload.get('userContext')
    result.user_context_stdin = False
    return result
namespace['parse_args'] = parse_with_settings
def pause(scan):
    print(json.dumps({'scanId': scan['id'], 'scanDir': scan['scan_dir']}), flush=True)
    sys.stdin.readline()
write = deep.write_scan_local_bytes
def write_settings(scan_dir, relative_path, payload, **kwargs):
    if boundary == 'before-write' and relative_path.endswith('/execution-settings.json'):
        pause({'id': None, 'scan_dir': str(scan_dir)})
    return write(scan_dir, relative_path, payload, **kwargs)
deep.write_scan_local_bytes = write_settings
ensure = deep.ensure_deep_scan_run
def ensure_run(connection, scan, *args):
    result = ensure(connection, scan, *args)
    if boundary == 'before-commit':
        pause(scan)
    return result
deep.ensure_deep_scan_run = ensure_run
begin = deep.begin_deep_scan
def begin_run(connection, args):
    result = begin(connection, args)
    if boundary == 'after-commit':
        pause({'id': result['deepScan']['scanId'], 'scan_dir': result['deepScan']['scanDir']})
    return result
deep.begin_deep_scan = begin_run
claim = deep.claim_deep_scan_coordinator
def claim_run(connection, args):
    result = claim(connection, args)
    if boundary == 'after-claim':
        pause({'id': result['deepScan']['scanId'], 'scan_dir': result['deepScan']['scanDir']})
    return result
deep.claim_deep_scan_coordinator = claim_run
main()
"""


def settings(root: Path, name: str) -> dict[str, object]:
    return {
        "codexPath": str(root / name / "codex"),
        "codexHome": str(root / name / "home"),
        "model": f"{name}-model",
        "reasoningEffort": "high",
        "reasoningSummary": "concise",
        "parentSandbox": {"filesystemDenies": [str(root / name / "denied")]},
    }


def start_process(
    root: Path,
    selected: dict[str, object] | None,
    *args: str,
    boundary: str = "none",
) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [sys.executable, "-c", BOUNDARY_PROCESS, boundary, str(SCRIPT), *args],
        env={
            **os.environ,
            "CODEX_SECURITY_STATE_DIR": str(root / "state"),
            "CODEX_HOME": str(root / "current-home"),
        },
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin is not None
    process.stdin.write(json.dumps({"executionSettings": selected}) + "\n")
    process.stdin.flush()
    return process


def finish(process: subprocess.Popen[str]) -> dict[str, object]:
    stdout, stderr = process.communicate(timeout=30)
    assert process.returncode == 0, stderr
    return json.loads(stdout)


def begin_args(root: Path, *, name: str = "target") -> list[str]:
    (root / name).mkdir(exist_ok=True)
    return [
        "begin-deep-scan",
        "--thread-id",
        "original-thread",
        "--target-path",
        str(root / name),
        "--scan-root",
        str(root / "scans"),
    ]


def snapshot(scan_dir: str) -> Path:
    return Path(scan_dir) / "artifacts" / "deep_discovery" / "execution-settings.json"


@pytest.mark.parametrize(
    "boundary", ["before-write", "before-commit", "after-commit", "after-claim"]
)
def test_process_death_keeps_original_settings_or_no_recoverable_run(
    tmp_path: Path, boundary: str
) -> None:
    original = settings(tmp_path, "original")
    args = begin_args(tmp_path)
    if boundary == "after-claim":
        begun = finish(start_process(tmp_path, original, *args))["deepScan"]
        args = [
            "claim-deep-scan-coordinator",
            "--scan-id",
            begun["scanId"],
            "--thread-id",
            "original-thread",
        ]
    process = start_process(tmp_path, original, *args, boundary=boundary)
    try:
        assert process.stdout is not None
        paused = json.loads(process.stdout.readline())
        path = snapshot(paused["scanDir"])
        with sqlite3.connect(tmp_path / "state" / "workbench.sqlite3") as connection:
            rows = connection.execute("SELECT scan_id FROM deep_scan_runs").fetchall()
        if boundary in {"before-write", "before-commit"}:
            assert rows == [], "uncommitted settings must not leave a recoverable run"
        else:
            assert rows == [(paused["scanId"],)]
        if boundary != "before-write":
            assert json.loads(path.read_bytes())["settings"] == original
    finally:
        process.kill()
        process.communicate(timeout=30)
    with sqlite3.connect(tmp_path / "state" / "workbench.sqlite3") as connection:
        remaining = connection.execute("SELECT scan_id FROM deep_scan_runs").fetchall()
    if boundary in {"before-write", "before-commit"}:
        assert remaining == []
        return
    before = path.read_bytes()
    with sqlite3.connect(tmp_path / "state" / "workbench.sqlite3") as connection:
        connection.execute("UPDATE deep_scan_runs SET updated_at = '2000-01-01T00:00:00Z'")
    run_workbench(
        tmp_path / "state",
        "claim-deep-scan-coordinator",
        "--scan-id",
        paused["scanId"],
        "--thread-id",
        "original-thread",
    )
    joined = finish(start_process(tmp_path, settings(tmp_path, "later"), *begin_args(tmp_path)))
    assert joined["startDisposition"] == "joined"
    assert path.read_bytes() == before


def test_competing_creation_and_observer_cannot_replace_original_settings(tmp_path: Path) -> None:
    first = start_process(
        tmp_path, settings(tmp_path, "original"), *begin_args(tmp_path), boundary="before-commit"
    )
    second = None
    try:
        assert first.stdout is not None
        paused = json.loads(first.stdout.readline())
        path = snapshot(paused["scanDir"])
        before = path.read_bytes()
        second = start_process(tmp_path, settings(tmp_path, "later"), *begin_args(tmp_path))
        # Release the creation lock with the original process still alive. The
        # contender must observe the committed run, not rewrite the settings.
        created = finish(first)
        joined = finish(second)
        assert created["startDisposition"] == "created"
        assert joined["startDisposition"] == "joined"
        assert joined["deepScan"]["scanId"] == paused["scanId"]
        assert path.read_bytes() == before
        observer = finish(start_process(tmp_path, None, *begin_args(tmp_path)))
        assert observer["startDisposition"] == "joined"
        assert path.read_bytes() == before
        other = finish(
            start_process(
                tmp_path, settings(tmp_path, "other"), *begin_args(tmp_path, name="other-target")
            )
        )
        assert json.loads(snapshot(other["deepScan"]["scanDir"]).read_bytes())[
            "settings"
        ] == settings(tmp_path, "other")
    finally:
        for process in (first, second):
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=30)


def test_internal_settings_input_preserves_public_user_context_and_shape(tmp_path: Path) -> None:
    context = "Review the parser.\nKeep this second line."
    process = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy, sys; script = sys.argv.pop(1); "
                "runpy.run_path(script)['main'](with_execution_settings=True)"
            ),
            str(SCRIPT),
            *begin_args(tmp_path),
        ],
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(tmp_path / "state")},
        input=json.dumps(
            {"executionSettings": settings(tmp_path, "original"), "userContext": context}
        ),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["deepScan"]["userContext"] == context
    assert "executionSettings" not in result["deepScan"]
    assert json.loads(snapshot(result["deepScan"]["scanDir"]).read_bytes())["settings"] == settings(
        tmp_path, "original"
    )


def test_managed_creation_retry_preserves_saved_settings_before_commit(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    workspace = create_saved_workspace(state, target, thread_id="original-thread", mode="deep")
    started = start_delivered_scan(
        state,
        "--workspace-id",
        workspace["id"],
        "--scan-root",
        str(tmp_path / "scans"),
        "--model",
        "original-model",
        "--reasoning-effort",
        "high",
    )
    scan = started["results"]
    args = ["begin-deep-scan", "--scan-id", scan["scanId"], "--thread-id", "original-thread"]
    original = settings(tmp_path, "original")
    process = start_process(tmp_path, original, *args, boundary="before-commit")
    try:
        assert process.stdout is not None
        paused = json.loads(process.stdout.readline())
        path = snapshot(paused["scanDir"])
        before = path.read_bytes()
    finally:
        process.kill()
        process.communicate(timeout=30)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM deep_scan_runs").fetchone() == (0,)
    recovered = finish(
        start_process(
            tmp_path,
            settings(tmp_path, "later"),
            *args,
            "--model",
            "later-model",
            "--reasoning-effort",
            "low",
        )
    )
    assert recovered["startDisposition"] == "created"
    assert path.read_bytes() == before
    assert json.loads(before)["settings"] == original
    assert recovered["deepScan"]["model"] == "original-model"
    assert recovered["deepScan"]["reasoningEffort"] == "high"
