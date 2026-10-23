from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import SCRIPT, empty_target_scan, register, write_completed_contract

pytestmark = pytest.mark.cross_platform


READER = """
import json
import sys
from contextlib import contextmanager

sys.path.insert(0, sys.argv[1])
import workbench_db as db

original_lock = db.scan_completion_lock
original_context = db.scan_context
announced = False

@contextmanager
def observed_lock(scan_id):
    global announced
    if not announced:
        announced = True
        print(json.dumps({"event": "lock-attempt", "scanId": scan_id}), flush=True)
    with original_lock(scan_id):
        yield

def observed_context(*args, **kwargs):
    result = original_context(*args, **kwargs)
    if not announced:
        print(json.dumps({"event": "unlocked-result", "status": result["scan"]["progress"]["status"]}), flush=True)
    return result

db.scan_completion_lock = observed_lock
db.scan_context = observed_context
sys.argv = ["workbench_db.py", "get-scan", "--scan-id", sys.argv[2]]
db.main()
"""


@pytest.mark.parametrize("terminal", ["complete", "canceled"])
@pytest.mark.parametrize("abbreviated", [False, True], ids=["full-id", "prefix"])
def test_get_scan_waits_for_publication_without_blocking_other_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workbench_api,
    terminal: str,
    abbreviated: bool,
) -> None:
    state, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    other_target = tmp_path / "other-target"
    other_target.mkdir()
    other = register(state, other_target, tmp_path / "other-scan")
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    selected = scan_id[:8] if abbreviated else scan_id
    reader = None
    boundary_thread = None
    try:
        with closing(workbench_api["connect"]()) as connection:
            assert not connection.in_transaction
            with workbench_api["scan_completion_lock"](scan_id):
                reader = subprocess.Popen(
                    [sys.executable, "-c", READER, str(SCRIPT.parent), selected],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    env=os.environ.copy(),
                )
                assert reader.stdout is not None
                boundary: queue.Queue[str] = queue.Queue()
                boundary_thread = threading.Thread(
                    target=lambda: boundary.put(reader.stdout.readline()), daemon=True
                )
                boundary_thread.start()
                event = json.loads(boundary.get(timeout=30))
                assert event == {"event": "lock-attempt", "scanId": scan_id}
                assert reader.poll() is None

                independent = subprocess.run(
                    [sys.executable, str(SCRIPT), "get-scan", "--scan-id", other["scanId"]],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    check=True,
                    timeout=30,
                    env=os.environ.copy(),
                )
                independent_scan = json.loads(independent.stdout)["scan"]
                assert independent_scan["scanId"] == other["scanId"]
                assert independent_scan["progress"]["status"] == "running"

                if terminal == "complete":
                    workbench_api["complete_scan"](
                        connection,
                        SimpleNamespace(scan_id=scan_id, cost_json=None, claim_token=None),
                    )
                else:
                    workbench_api["saved_results"].cancel_scan(
                        workbench_api["_WORKBENCH_DB_CONTEXT"],
                        connection,
                        SimpleNamespace(scan_id=scan_id, thread_id=None, defer_publication=True),
                    )
                assert not connection.in_transaction
                # The real writer has returned, but our outer publication lock remains held.
                assert reader.poll() is None

        stdout, stderr = reader.communicate(timeout=30)
        assert reader.returncode == 0, stderr
        observed = json.loads(stdout)["scan"]
        assert observed["scanId"] == scan_id
        assert observed["progress"]["status"] == terminal
        with closing(workbench_api["connect"]()) as connection:
            stored = workbench_api["require_scan"](connection, scan_id)
            assert stored["status"] == ("complete" if terminal == "complete" else "failed")
            assert (stored["canceled_at"] is not None) == (terminal == "canceled")
            if terminal == "complete":
                assert stored["seal_manifest_digest"].startswith("sha256:")
    finally:
        if reader is not None:
            if reader.poll() is None:
                reader.kill()
            reader.communicate(timeout=30)
        if boundary_thread is not None:
            boundary_thread.join(timeout=30)
            assert not boundary_thread.is_alive()
