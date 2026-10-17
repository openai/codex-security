from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(
    ("timing", "successor"),
    [
        ("tied", "succeeded"),
        ("earlier", "succeeded"),
        ("later", "succeeded"),
        ("later", "running"),
        ("later", "failed"),
        ("legacy", "succeeded"),
        ("legacy-tied", "succeeded"),
        ("legacy-earlier", "succeeded"),
    ],
)
def test_final_selection_follows_committed_reducer_chain(
    workbench_api, workbench_db, tmp_path, monkeypatch, timing, successor
):
    target, scan_dir, home = (tmp_path / name for name in ("target", "scan", "home"))
    target.mkdir()
    scan_dir.mkdir(mode=0o700)
    (target / "app.py").write_text("value = 1\n")
    (home / "codex-security").mkdir(parents=True)
    (home / "codex-security/config.toml").write_text(
        "[deep_scan]\nworkers=1\nsubagents=0\nmax_discovery_runs=4\nstop_after_no_new=5\n"
    )
    monkeypatch.setenv("CODEX_HOME", str(home))
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(tmp_path / "state"))
    clock = ["2030-01-01T00:00:01Z"]
    deep = workbench_api["deep_scan"]
    monkeypatch.setattr(
        deep,
        "_dependencies",
        SimpleNamespace(
            **{
                **workbench_api,
                "now": lambda: clock[0],
                "preserve_stopped_results": workbench_api[
                    "preserve_stopped_results_after_transition"
                ],
            }
        ),
    )

    def args(command, *words, **overrides):
        monkeypatch.setattr(sys, "argv", ["workbench_db", command, *map(str, words)])
        parsed = workbench_api["parse_args"]("test")
        vars(parsed).update(overrides)
        return parsed

    registered = workbench_api["register_cli_scan"](
        workbench_db,
        args(
            "register-cli-scan",
            "--scan-dir",
            scan_dir,
            "--repository",
            target,
            "--recipe-json",
            json.dumps(
                {
                    "config": {},
                    "mode": "deep",
                    "repository": str(target),
                    "target": {"kind": "repository", "paths": []},
                }
            ),
        ),
    )
    scan_id = registered["scanId"]
    deep.begin_deep_scan(
        workbench_db,
        args(
            "begin-deep-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "synthetic-owner",
            execution_settings={
                "codexPath": sys.executable,
                "codexHome": str(home),
                "parentSandbox": {"filesystemDenies": []},
            },
        ),
    )
    coverage = {
        "completeness": "complete",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [],
    }

    def worker(number, inputs=None, status="succeeded"):
        kind = "discovery" if inputs is None else "dedup"
        prefix = "10000000" if inputs is None else "ffffffff" if number == 1 else "00000000"
        worker_id = f"{prefix}-0000-4000-8000-{number:012d}"
        directory = scan_dir / "workers" / f"{kind}-{number}"
        directory.mkdir(parents=True)
        prompt, result = directory / "prompt.md", directory / "result.json"
        prompt.write_text("Synthetic review")
        common = [
            "--scan-id",
            scan_id,
            "--worker-id",
            worker_id,
            "--prompt-path",
            prompt,
            "--artifact-dir",
            directory,
        ]
        if inputs is not None:
            deep.claim_deep_scan_dedup(
                workbench_db,
                args(
                    "claim-deep-scan-dedup",
                    *common,
                    *(value for item in inputs for value in ("--input-worker-id", item)),
                ),
            )
        common += ["--kind", kind, "--attempt", "1"]
        deep.upsert_deep_scan_worker(
            workbench_db, args("upsert-deep-scan-worker", *common, "--status", "running")
        )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "complete": True,
                    "findings": [],
                    "coverage" if inputs is None else "sourceCoverage": {
                        **coverage,
                        "completeness": "partial",
                        "deferred": [{"reason": f"Review gap from {kind} {number}."}],
                    },
                }
            )
        )
        if inputs is not None and status == "succeeded":
            deep.commit_deep_scan_dedup(
                workbench_db,
                args(
                    "commit-deep-scan-dedup",
                    "--scan-id",
                    scan_id,
                    "--worker-id",
                    worker_id,
                    "--result-manifest-path",
                    result,
                    "--new-findings-count",
                    "1",
                ),
            )
        elif status != "running":
            deep.upsert_deep_scan_worker(
                workbench_db,
                args(
                    "upsert-deep-scan-worker",
                    *common,
                    "--status",
                    status,
                    "--result-manifest-path",
                    result,
                ),
            )
        return worker_id

    first = worker(1, [worker(1), worker(2)])
    clock[0] = {
        "earlier": "2030-01-01T00:00:00Z",
        "tied": clock[0],
        "legacy-tied": clock[0],
    }.get(timing, "2030-01-01T00:00:02Z")
    second = worker(2, [worker(3)], successor)
    assert (
        workbench_db.execute(
            "SELECT previous_worker_id FROM deep_scan_merge_claims WHERE worker_id = ?", (second,)
        ).fetchone()[0]
        == first
    )
    if timing.startswith("legacy"):
        # Exercise the legacy no-claim fallback with controlled metadata.
        with workbench_db:
            workbench_db.execute("DELETE FROM deep_scan_merge_claims")
    expected_worker = first
    if successor == "succeeded":
        second_reference = workbench_db.execute(
            "SELECT accepted_result_path, accepted_result_sha256 FROM deep_scan_attempts "
            "WHERE worker_id = ?",
            (second,),
        ).fetchone()
        if timing == "later":
            clock[0] = "2030-01-01T00:00:03Z"
        elif timing == "legacy-earlier":
            clock[0] = "2030-01-01T00:00:00Z"
        expected_worker = worker(3, [worker(4)])
        claim = workbench_db.execute(
            "SELECT * FROM deep_scan_merge_claims WHERE worker_id = ?", (expected_worker,)
        ).fetchone()
        assert claim["previous_worker_id"] == second
        assert claim["previous_result_path"] == second_reference["accepted_result_path"]
        assert claim["previous_result_sha256"] == second_reference["accepted_result_sha256"]
    accepted = workbench_db.execute(
        "SELECT accepted_result_path, accepted_result_sha256 FROM deep_scan_attempts WHERE worker_id = ?",
        (expected_worker,),
    ).fetchone()
    run, scan = deep.require_running_deep_scan(workbench_db, scan_id)

    def observe_budget_draft(document, unmerged):
        assert document == json.loads(Path(accepted["accepted_result_path"]).read_bytes())
        assert len(unmerged) == (0 if successor == "succeeded" else 1)
        raise RuntimeError("observed budget draft boundary")

    # Exercise budget auto-selection before committing a normal final selection.
    with pytest.raises(RuntimeError, match="observed budget draft boundary"):
        deep.prepare_budget_exhausted_deep_scan(
            workbench_db, scan, scan_dir, "Synthetic budget stop", observe_budget_draft
        )
    finish = args(
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        scan_dir / "scan-manifest.json",
        select_finalization=True,
        finalization_result_path=accepted["accepted_result_path"],
    )
    if successor == "succeeded":
        previous = workbench_db.execute(
            "SELECT accepted_result_path FROM deep_scan_attempts WHERE worker_id = ?", (first,)
        ).fetchone()[0]
        stale = SimpleNamespace(**{**vars(finish), "finalization_result_path": previous})
        with pytest.raises(SystemExit, match="committed accepted reducer"):
            deep.selected_deep_scan_finalization(workbench_db, run, scan, stale, [], False)
        selection = deep.finish_deep_scan_locked(workbench_db, finish, scan_id)["deepScan"][
            "finalizationInput"
        ]
        replay = deep.finish_deep_scan_locked(workbench_db, stale, scan_id)["deepScan"][
            "finalizationInput"
        ]
        assert replay == selection
    else:
        # A pending or failed successor cannot replace the last committed input
        # selected for budget publication, which does not await model work.
        selection = deep.selected_deep_scan_finalization(workbench_db, run, scan, finish, [], False)
    assert (
        selection["resultPath"]
        == Path(accepted["accepted_result_path"]).relative_to(scan_dir).as_posix()
    )
    assert selection["resultSha256"] == accepted["accepted_result_sha256"]
