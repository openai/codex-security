from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from test_saved_deferred_identity import recover, save_worker, saved_draft
from test_workbench_standard_deep_results import accepted_standard_worker, deep_scan_fixture
from workbench_test_support import run_workbench, write_checkpoint

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_saved_results as saved


@pytest.mark.parametrize(
    ("reason", "identity"),
    [
        pytest.param("\ud800", "deferred-7b02db7069064f21", id="high-surrogate"),
        pytest.param("\udfff", "deferred-042d3e8a3549a045", id="low-surrogate"),
        pytest.param("\U0001f600", "deferred-6403b70908c737af", id="emoji"),
        pytest.param("\\ud800", "deferred-6e08d26c2848d312", id="literal-escape"),
        pytest.param("é", "deferred-397a18fac04fedaa", id="accent"),
        pytest.param("A\U0001f600Z", "deferred-93fabecbc432e3f8", id="embedded-emoji"),
    ],
)
def test_recovery_matches_unicode_ids_from_the_public_writer(
    tmp_path: Path, reason: str, identity: str
) -> None:
    pending = {"reason": reason, "paths": ["src/example.py"]}
    closed = saved_draft(
        "identity-scan",
        closures=[{"id": identity, "reason": "Review completed."}],
        complete=True,
    )
    worker = save_worker(
        tmp_path,
        saved,
        "reviewer",
        [saved_draft("identity-scan", deferred=[pending])],
        closed,
    )
    result = recover(tmp_path, saved, [worker])
    assert {row["id"] for row in result[2]["deferred"]} == {"scan-stopped"}
    replay = recover(tmp_path, saved, [worker], result[0]["scan"]["preservedSources"])
    assert replay[2] == result[2]


@pytest.mark.parametrize(
    ("reason", "identity"),
    [
        pytest.param("\ud800", "deferred-7b02db7069064f21", id="high-surrogate"),
        pytest.param("\udfff", "deferred-042d3e8a3549a045", id="low-surrogate"),
    ],
)
def test_stopped_publication_recovers_after_unicode_review_is_closed(
    tmp_path: Path, reason: str, identity: str
) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    pending = saved_draft(scan_id, deferred=[{"reason": reason, "paths": ["src/example.py"]}])
    checkpoint = write_checkpoint(result.parent / "checkpoints", pending)
    os.utime(checkpoint, ns=(100, 100))
    closed = saved_draft(
        scan_id,
        closures=[{"id": identity, "reason": "Review completed."}],
        complete=True,
    )
    result.write_text(json.dumps(closed), encoding="utf-8")
    os.utime(result, ns=(200, 200))
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        "--deep-status",
        "failed",
        environment=environment,
    )
    coverage = json.loads((scan_dir / "coverage.json").read_text(encoding="utf-8"))
    assert {row["id"] for row in coverage["deferred"]} == {"scan-stopped"}
    manifest = (scan_dir / "scan-manifest.json").read_bytes()
    recovered = run_workbench(
        state, "recover-scan-results", "--scan-id", scan_id, environment=environment
    )
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    assert (scan_dir / "scan-manifest.json").read_bytes() == manifest
