from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.mark.parametrize("termination", ["failed", "interrupted", "canceled"])
def test_stopped_deep_scan_ignores_late_worker_checkpoints_without_reducer(
    tmp_path: Path,
    termination: str,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [
                {
                    "candidateId": "pending-query",
                    "reason": "Query validation remains pending.",
                    "paths": ["app.py"],
                }
            ],
        },
    }
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    # The latest incomplete attempt need not be parseable for a saved checkpoint to survive.
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )
    environment = {"CODEX_HOME": str(codex_home)}
    if termination == "canceled":
        run_workbench(
            state_dir,
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment=environment,
        )
    else:
        run_workbench(
            state_dir,
            "fail-deep-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Worker stopped.",
            "--deep-status",
            termination,
            environment=environment,
        )

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id[:12])["scan"]
    assert stopped["progress"]["status"] == ("canceled" if termination == "canceled" else "failed")
    assert stopped["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert any(item.get("candidateId") == "pending-query" for item in coverage["deferred"])
    assert result_path.read_text() == "{incomplete"
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == termination
    )
    first_seal = (scan_dir / "scan-manifest.json").read_bytes()
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    archived = result_path.parent / "attempts" / "attempt-01" / "checkpoints"
    write_checkpoint(archived, late)
    wrong_owner = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "not-the-owner",
        check=False,
    )
    assert wrong_owner["returncode"] != 0
    assert (scan_dir / "scan-manifest.json").read_bytes() == first_seal
    refreshed = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment=environment,
    )["scan"]
    expected_count = 1
    assert refreshed["findingCount"] == expected_count
    assert len({finding["occurrenceId"] for finding in refreshed["findings"]}) == expected_count
    assert refreshed["findings"][0]["locations"][0]["startLine"] != 91
    seal = (scan_dir / "scan-manifest.json").read_bytes()
    assert seal == first_seal
    assert (
        run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]["findingCount"]
        == expected_count
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == seal


def test_reopened_workspace_ignores_late_stopped_scan_checkpoints(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        "--deep-status",
        "failed",
        environment={"CODEX_HOME": str(codex_home)},
    )
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    write_checkpoint(result_path.parent / "attempts" / "attempt-01" / "checkpoints", late)
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        workspace_id = connection.execute(
            "SELECT workspace_id FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]

    reopened = run_workbench(
        state_dir,
        "get-workspace",
        "--workspace-id",
        workspace_id,
        environment={"CODEX_HOME": str(codex_home)},
    )
    assert reopened["results"]["findingCount"] == 1
    assert json.loads((scan_dir / "findings.json").read_text())["findings"]


@pytest.mark.parametrize(
    ("command", "collection", "count_field"),
    [
        ("list-scans", "scans", "findingCount"),
        ("list-global-findings", "findings", None),
        ("list-repositories", "repositories", "openFindingsCount"),
    ],
)
def test_aggregate_queries_ignore_late_stopped_scan_checkpoints(
    tmp_path: Path,
    command: str,
    collection: str,
    count_field: str | None,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        "--deep-status",
        "failed",
        environment={"CODEX_HOME": str(codex_home)},
    )
    late = copy.deepcopy(checkpoint)
    late["findings"][0]["identity"]["anchor"] = "late-independent-finding"
    write_checkpoint(result_path.parent / "attempts" / "attempt-01" / "checkpoints", late)

    rows = run_workbench(state_dir, command, environment={"CODEX_HOME": str(codex_home)})[
        collection
    ]

    if command == "list-global-findings":
        assert len([row for row in rows if row["scanId"] == scan_id]) == 1
    else:
        assert count_field is not None
        row = next(
            row
            for row in rows
            if row.get("scanId") == scan_id or row.get("targetPath") == str(target)
        )
        assert row[count_field] == 1


def test_unreadable_only_checkpoint_records_recovery_warning(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    result_path.write_text("{not-json")

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        "--deep-status",
        "failed",
        environment={"CODEX_HOME": str(codex_home)},
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert any("Preserved unreadable checkpoint" in warning for warning in failed["warnings"])


def test_malformed_current_finding_does_not_override_worker_rejection(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = "rejected-candidate"
    checkpoint = json.loads(result_path.read_text())
    checkpoint["complete"] = False
    checkpoint["findings"] = [copy.deepcopy(finding)]
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    finding["summary"] = ""
    current = json.loads(result_path.read_text())
    current["findings"] = [finding]
    current["coverage"]["surfaces"] = [
        {
            "label": "Rejected candidate",
            "candidateId": "rejected-candidate",
            "disposition": "rejected",
            "notes": "The completed worker rejected this checkpointed candidate.",
        }
    ]
    result_path.write_text(json.dumps(current))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after rejecting a malformed current finding.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert failed["findingCount"] == 0
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"][0]["disposition"] == "rejected"
    assert len(coverage["surfaces"][0]["previousFindings"]) == 1


def test_stopped_recovery_accepts_trailing_slash_scope(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(
        contract_dir,
        scan_id,
        target,
        include_paths=["src/"],
        relative_path="src/app.py",
        coverage_mode="scoped_path",
        inventory_strategy="scoped_path",
    )
    checkpoint = json.loads(result_path.read_text())
    checkpoint["complete"] = False
    checkpoint["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    checkpoint["coverage"] = json.loads((contract_dir / "coverage.json").read_text())
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET scope = 'src/' WHERE id = ?", (scan_id,))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    assert failed["findingCount"] == 1
    assert failed["findings"][0]["locations"][0]["path"] == "src/app.py"


def test_canceled_scan_retries_failed_publication_from_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [finding],
        "coverage": {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        },
    }
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_canceled_publication.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    canceled = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )
    assert canceled.returncode == 0, canceled.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        row = connection.execute(
            "SELECT retained_source_digests_json, completion_warnings_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
    assert row[0]
    assert "injected publication failure" in row[1]

    late = copy.deepcopy(checkpoint)
    late["findings"][0]["locations"][0]["startLine"] = 91
    late["findings"][0]["locations"][0]["endLine"] = 92
    archived = result_path.parent / "attempts" / "attempt-01" / "checkpoints"
    write_checkpoint(archived, late)

    preserved = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )["scan"]
    assert preserved["findingCount"] == 1
    assert preserved["findings"][0]["locations"][0]["startLine"] != 91
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == "canceled"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        warnings = json.loads(
            connection.execute(
                "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
        )
    assert not any("result publication needs follow-up" in warning for warning in warnings)


@pytest.mark.parametrize("deep_status", ["failed", "interrupted"])
def test_existing_non_canceled_output_recovers_structured_publication_failure(
    tmp_path: Path,
    deep_status: str,
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    original = "Saved result publication failed: genuine worker failure"
    publication = "Saved result publication failed: stale publication timeout"
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--deep-status",
        deep_status,
        "--message",
        original,
        environment=environment,
    )

    if deep_status == "failed":
        run_workbench(
            state_dir,
            "record-deep-scan-publication-failure",
            "--scan-id",
            scan_id,
            "--message",
            publication,
            environment=environment,
        )
        after_race = run_workbench(
            state_dir,
            "get-deep-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment=environment,
        )["deepScan"]
        assert after_race["error"] == original

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET publication_error_message = ? WHERE scan_id = ?",
            (publication, scan_id),
        )
    before_recovery = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment=environment,
    )["deepScan"]
    assert publication in before_recovery["error"]
    assert original in before_recovery["error"]

    run_workbench(
        state_dir,
        "get-scan",
        "--scan-id",
        scan_id,
        environment=environment,
    )
    recovered = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment=environment,
    )["deepScan"]
    assert recovered["error"] == original
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT publication_error_message FROM deep_scan_runs WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()[0]
            is None
        )


def test_canceled_scan_reports_noop_coordinator_publication(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    result_path.write_text("{incomplete")

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_before_canceled_sources_are_frozen.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_before_sources_are_frozen(*args, **kwargs):\n"
        "    raise OSError('injected early publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_before_sources_are_frozen\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    canceled = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )
    assert canceled.returncode == 0, canceled.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
            is None
        )

    preserved = run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
        check=False,
    )
    assert preserved["returncode"] != 0
    assert "could not be published or verified" in preserved["stderr"]


def test_canceled_scan_reseals_prepared_completion_with_frozen_sources(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    relative_result_path = result_path.relative_to(scan_dir).as_posix()
    manifest["scan"]["preservedSources"] = {
        relative_result_path: hashlib.sha256(
            json.dumps(
                result,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    }
    manifest_path.write_text(json.dumps(manifest))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at "
            "WHERE scan_id = ?",
            (str(manifest_path), scan_id),
        )
    run_workbench(state_dir, "prepare-scan-completion", "--scan-id", scan_id)
    assert json.loads(manifest_path.read_text())["scan"]["status"] == "completed"

    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_prepared_canceled_publication.py"
    wrapper.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n"
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n"
        "raise SystemExit(workbench_db.main())\n"
    )
    canceled = subprocess.run(
        [
            sys.executable,
            str(wrapper),
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
        ],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )
    assert canceled.returncode == 0, canceled.stderr
    assert json.loads(manifest_path.read_text())["scan"]["status"] == "completed"

    run_workbench(
        state_dir,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )

    assert json.loads(manifest_path.read_text())["scan"]["status"] == "canceled"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]


def test_stopped_deep_scan_recovers_when_parent_manifest_has_no_scan(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    result = json.loads(result_path.read_text())
    result["findings"] = [finding]
    result_path.write_text(json.dumps(result))
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_text(json.dumps({"documentType": "broken-parent"}))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        "--deep-status",
        "failed",
        environment={"CODEX_HOME": str(codex_home)},
    )

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["findingCount"] == 1
    assert any("has no scan object" in warning for warning in stopped["warnings"])
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["status"] == ("failed")


def deep_scan_fixture(
    tmp_path: Path, *, budget: bool = False, workers: int = 1
) -> tuple[Path, Path, Path, Path, str]:
    state_dir = tmp_path / "state"
    codex_home = tmp_path / "codex-home"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("value = request.args['value']\n")
    config_path = codex_home / "codex-security" / "config.toml"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(f"[deep_scan]\nworkers = {workers}\nmax_discovery_runs = {workers}\n")
    environment = {"CODEX_HOME": str(codex_home)}

    if budget:
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir(mode=0o700)
        registered = run_workbench(
            state_dir,
            "register-cli-scan",
            "--scan-dir",
            str(scan_dir),
            "--repository",
            str(target),
            "--recipe-json",
            json.dumps(
                {
                    "config": {},
                    "mode": "deep",
                    "repository": str(target),
                    "target": {"kind": "repository", "paths": []},
                    "maxCostUsd": 0.005,
                }
            ),
        )
        scan_id = str(registered["scanId"])
        run_workbench(
            state_dir,
            "begin-deep-scan",
            "--thread-id",
            "standard-worker-thread",
            "--scan-id",
            scan_id,
            environment=environment,
        )
    else:
        begun = run_workbench(
            state_dir,
            "begin-deep-scan",
            "--thread-id",
            "standard-worker-thread",
            "--target-path",
            str(target),
            "--scope",
            ".",
            "--scan-root",
            str(tmp_path / "scans"),
            "--available-parallelism",
            "16",
            environment=environment,
        )["deepScan"]
        scan_id = str(begun["scanId"])
        scan_dir = Path(str(begun["scanDir"]))

    return state_dir, codex_home, target, scan_dir, scan_id


def worker_paths(scan_dir: Path, name: str) -> tuple[Path, Path, Path]:
    artifact_dir = scan_dir / "artifacts" / "deep_discovery" / name
    artifact_dir.mkdir(parents=True)
    prompt_path = artifact_dir / "prompt.md"
    prompt_path.write_text(f"Prompt for {name}\n")
    return prompt_path, artifact_dir, artifact_dir / "result.json"


def accepted_standard_worker(
    state_dir: Path,
    codex_home: Path,
    scan_dir: Path,
    scan_id: str,
    *,
    name: str = "standard-worker",
) -> tuple[str, Path]:
    worker_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, name)
    base_args = (
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        worker_id,
        "--kind",
        "discovery",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "1",
    )
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(state_dir, *base_args, "--status", "running", environment=environment)
    result_path.write_text(
        json.dumps(
            {
                "scanId": scan_id,
                "findings": [],
                "coverage": {
                    "completeness": "complete",
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                },
                "threatModel": {"summary": "The ordinary Standard worker threat model."},
            }
        )
    )
    run_workbench(
        state_dir,
        *base_args,
        "--status",
        "succeeded",
        "--result-manifest-path",
        str(result_path),
        environment=environment,
    )
    return worker_id, result_path


def committed_standard_reducer(
    state_dir: Path,
    codex_home: Path,
    scan_dir: Path,
    scan_id: str,
    discovery_worker_id: str,
    discovery_result: Path,
    *,
    additional_worker_ids: tuple[str, ...] = (),
) -> tuple[str, Path, dict[str, object]]:
    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, result_path = worker_paths(scan_dir, "standard-reducer")
    environment = {"CODEX_HOME": str(codex_home)}
    input_worker_args = [
        argument
        for worker_id in (discovery_worker_id, *additional_worker_ids)
        for argument in ("--input-worker-id", worker_id)
    ]
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        *input_worker_args,
        environment=environment,
    )
    run_workbench(
        state_dir,
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--kind",
        "dedup",
        "--status",
        "running",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "1",
        environment=environment,
    )
    result_path.write_text(discovery_result.read_text())
    committed = run_workbench(
        state_dir,
        "commit-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--result-manifest-path",
        str(result_path),
        "--new-findings-count",
        "0",
        environment=environment,
    )["deepScan"]
    return reducer_id, result_path, committed


def test_failure_preserves_last_committed_reducer_without_parent_draft(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    draft = json.loads(result_path.read_text())
    draft["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(draft))
    _, reducer_path, _ = committed_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, result_path
    )
    reduced = json.loads(reducer_path.read_text())
    reduced["findings"][0]["summary"] = (
        "The reducer retained additional independently reviewed evidence."
    )
    reducer_path.write_text(json.dumps(reduced))
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Later reducer failed.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 1
    assert failed["findings"][0]["summary"] == reduced["findings"][0]["summary"]


def test_stopped_rejection_recovers_malformed_parent_surfaces(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "rejected-candidate"}
    finding["provenance"]["candidateId"] = "rejected-candidate"
    finding["provenance"]["workerId"] = worker_id
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": [finding]}))
    malformed_coverage = json.loads((contract_dir / "coverage.json").read_text())
    malformed_coverage["surfaces"] = None
    (scan_dir / "coverage.json").write_text(json.dumps(malformed_coverage))
    (scan_dir / "scan-manifest.json").write_bytes(
        (contract_dir / "scan-manifest.json").read_bytes()
    )
    current = json.loads(result_path.read_text())
    checkpoint = copy.deepcopy(current)
    checkpoint["complete"] = False
    checkpoint["findings"] = [copy.deepcopy(finding)]
    write_checkpoint(result_path.parent / "checkpoints", checkpoint)
    current["coverage"]["surfaces"] = [
        {
            "label": "Rejected candidate",
            "candidateId": "rejected-candidate",
            "disposition": "rejected",
            "notes": "The completed worker rejected this checkpointed candidate.",
        }
    ]
    result_path.write_text(json.dumps(current))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after rejecting a checkpointed candidate.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert isinstance(coverage["surfaces"], list)


def test_stopped_scan_rebinds_prepared_completion_seal(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
    (scan_dir / "findings.json").write_bytes((contract_dir / "findings.json").read_bytes())
    (scan_dir / "coverage.json").write_bytes((contract_dir / "coverage.json").read_bytes())
    (scan_dir / "scan-manifest.json").write_bytes(
        (contract_dir / "scan-manifest.json").read_bytes()
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET status = 'succeeded', phase = 'terminal', "
            "terminal_reason = 'saturated', manifest_path = ?, completed_at = updated_at "
            "WHERE scan_id = ?",
            (str(scan_dir / "scan-manifest.json"), scan_id),
        )
    run_workbench(state_dir, "prepare-scan-completion", "--scan-id", scan_id)
    prepared_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert prepared_manifest["scan"]["status"] == "completed"

    run_workbench(
        state_dir,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Completion was not accepted.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    failed_manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert failed_manifest["scan"]["status"] == "failed"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        seal_digest = connection.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    assert seal_digest


@pytest.mark.parametrize(
    "command",
    [
        ("request-finding-remediation",),
        ("request-finding-remediation-action", "--expected-version", "1", "--action", "apply"),
        ("claim-finding-remediation-resend",),
        ("mark-finding-remediation-delivered",),
        ("release-finding-remediation-claim",),
        ("cancel-finding-remediation-request",),
        ("set-finding-remediation", "--expected-version", "1", "--state", "failed"),
    ],
)
def test_stopped_findings_cannot_enter_remediation(
    tmp_path: Path, command: tuple[str, ...]
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    result = json.loads(result_path.read_text())
    result["findings"] = json.loads((contract_dir / "findings.json").read_text())["findings"]
    result_path.write_text(json.dumps(result))
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped with a provisional finding.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["remediationAvailable"] is False
    assert failed["remediationUnavailableReason"] == (
        "Remediation is available only for successfully completed scans."
    )
    occurrence_id = failed["findings"][0]["occurrenceId"]

    blocked = run_workbench(
        state_dir,
        *command,
        "--occurrence-id",
        occurrence_id,
        "--request-id",
        str(uuid.uuid4()),
        "--action-token",
        str(uuid.uuid4()),
        check=False,
    )

    assert blocked["returncode"] != 0
    assert "successfully completed scans" in blocked["stderr"]


def test_complete_worker_supersedes_obsolete_checkpoint_coverage(tmp_path: Path) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    checkpoint = {
        "scanId": scan_id,
        "complete": False,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [
                {
                    "id": "obsolete-surface",
                    "label": "Obsolete review",
                    "disposition": "needs_follow_up",
                    "receiptRefs": [],
                }
            ],
            "explicitExclusions": [],
            "deferred": [{"id": "obsolete-work", "reason": "This was later completed."}],
        },
    }
    checkpoints = result_path.parent / "checkpoints"
    checkpoints.mkdir()
    (checkpoints / ("0" * 64 + ".json")).write_text(json.dumps(checkpoint))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after the worker completed.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert not any(item.get("id") == "obsolete-surface" for item in coverage["surfaces"])
    assert not any(item.get("id") == "obsolete-work" for item in coverage["deferred"])


def test_complete_partial_parent_supersedes_obsolete_checkpoint_questions(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    coverage_path = scan_dir / "coverage.json"
    final_coverage = json.loads(coverage_path.read_text())
    final_coverage["completeness"] = "partial"
    final_coverage["openQuestions"] = []
    coverage_path.write_text(json.dumps(final_coverage))
    write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
                "openQuestions": ["This question was answered by the final parent draft."],
            },
        },
    )

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after the final partial parent draft.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    recovered = json.loads(coverage_path.read_text())
    assert recovered.get("openQuestions", []) == []


def test_canceled_reducer_checkpoint_supersedes_discovery_result(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    baseline = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    baseline["extensions"] = {"candidateId": "candidate-reducer"}
    baseline["provenance"]["candidateId"] = "candidate-reducer"
    discovery = json.loads(worker_result.read_text())
    discovery["findings"] = [baseline]
    discovery["coverage"]["surfaces"] = [
        {
            "id": "reducer-surface",
            "label": "Reducer-reviewed route",
            "disposition": "reported",
            "notes": "Discovery evidence only.",
            "receiptRefs": [],
        }
    ]
    worker_result.write_text(json.dumps(discovery))

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, reducer_result = worker_paths(scan_dir, "canceled-reducer")
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--input-worker-id",
        worker_id,
        environment=environment,
    )
    run_workbench(
        state_dir,
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--kind",
        "dedup",
        "--status",
        "running",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "1",
        environment=environment,
    )
    reduced = copy.deepcopy(discovery)
    reduced["findings"][0]["summary"] = "The reducer retained stronger merged evidence."
    reduced["coverage"]["surfaces"][0]["notes"] = "Reducer-validated merged evidence."
    reducer_result.write_text(json.dumps(reduced))
    checkpoints = reducer_result.parent / "checkpoints"
    checkpoints.mkdir()
    (checkpoints / ("a" * 64 + ".json")).write_text(json.dumps(reduced))
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'canceled', completed_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), reducer_id),
        )

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Canceled after reducer validation.",
        environment=environment,
    )

    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert findings[0]["summary"] == reduced["findings"][0]["summary"]
    assert coverage["surfaces"][0]["notes"] == "Reducer-validated merged evidence."


def test_archived_reducer_checkpoint_supersedes_discovery_result(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    discovery = json.loads(worker_result.read_text())
    discovery["findings"] = [finding]
    worker_result.write_text(json.dumps(discovery))

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, reducer_result = worker_paths(scan_dir, "archived-reducer")
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--input-worker-id",
        worker_id,
        environment=environment,
    )
    run_workbench(
        state_dir,
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--kind",
        "dedup",
        "--status",
        "running",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "2",
        environment=environment,
    )
    reduced = copy.deepcopy(discovery)
    reduced["findings"][0]["summary"] = "The archived reducer retained the newest evidence."
    archived = artifact_dir / "attempts" / "attempt-01"
    archived.mkdir(parents=True)
    (archived / "result.json").write_text(json.dumps(reduced))
    write_checkpoint(archived / "checkpoints", reduced)
    reducer_result.write_text("{incomplete current reducer")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'canceled', completed_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), reducer_id),
        )

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Canceled after archiving a validated reducer attempt.",
        environment=environment,
    )

    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert findings[0]["summary"] == reduced["findings"][0]["summary"]


def test_recovery_selects_strongest_same_finding_checkpoint(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    weak = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    weak["severity"]["level"] = "low"
    weak["confidence"]["level"] = "low"
    weak["summary"] = "Earlier weak checkpoint evidence."
    strong = copy.deepcopy(weak)
    strong["severity"]["level"] = "high"
    strong["confidence"]["level"] = "high"
    strong["summary"] = "Later strong checkpoint evidence."
    checkpoint_dir = result_path.parent / "checkpoints"
    checkpoint_dir.mkdir()
    for name, finding in (("0" * 64, weak), ("f" * 64, strong)):
        (checkpoint_dir / f"{name}.json").write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "complete": False,
                    "findings": [finding],
                    "coverage": {
                        "completeness": "partial",
                        "surfaces": [],
                        "explicitExclusions": [],
                        "deferred": [],
                    },
                }
            )
        )
    result_path.write_text("{incomplete")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_workers SET status = 'running' WHERE id = ?", (worker_id,)
        )

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped between checkpoints.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["severity"]["level"] == "high"
    assert retained["confidence"]["level"] == "high"
    assert retained["summary"] == "Later strong checkpoint evidence."
    assert any(
        finding.get("summary") == "Earlier weak checkpoint evidence."
        for finding in retained["provenance"]["previousFindings"]
    )


def test_failed_reducer_preserves_later_successful_worker_findings(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=3)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    baseline = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    environment = {"CODEX_HOME": str(codex_home)}

    first_worker_id, first_result = accepted_standard_worker(
        state_dir, codex_home, scan_dir, scan_id, name="first-worker"
    )
    first_document = json.loads(first_result.read_text())
    first_document["findings"] = [baseline]
    first_result.write_text(json.dumps(first_document))
    empty_worker_id, _ = accepted_standard_worker(
        state_dir, codex_home, scan_dir, scan_id, name="empty-worker"
    )
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        first_worker_id,
        first_result,
        additional_worker_ids=(empty_worker_id,),
    )

    second_worker_id, second_result = accepted_standard_worker(
        state_dir, codex_home, scan_dir, scan_id, name="later-worker"
    )
    later = copy.deepcopy(baseline)
    later["identity"]["anchor"] = "later-successful-worker-finding"
    later["title"] = "Later successful worker finding"
    later["summary"] = "This finding completed after the last successful reduction."
    second_document = json.loads(second_result.read_text())
    second_document["findings"] = [later]
    second_result.write_text(json.dumps(second_document))

    reducer_id = str(uuid.uuid4())
    prompt_path, artifact_dir, _ = worker_paths(scan_dir, "failed-reducer")
    run_workbench(
        state_dir,
        "claim-deep-scan-dedup",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--input-worker-id",
        second_worker_id,
        environment=environment,
    )
    base_args = (
        "upsert-deep-scan-worker",
        "--scan-id",
        scan_id,
        "--worker-id",
        reducer_id,
        "--kind",
        "dedup",
        "--prompt-path",
        str(prompt_path),
        "--artifact-dir",
        str(artifact_dir),
        "--attempt",
        "1",
    )
    run_workbench(state_dir, *base_args, "--status", "running", environment=environment)
    run_workbench(
        state_dir,
        *base_args,
        "--status",
        "failed",
        "--error-message",
        "Synthetic reducer process failure.",
        environment=environment,
    )

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Later reducers failed.",
        environment=environment,
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["progress"]["status"] == "failed"
    assert failed["findingCount"] == 2
    assert {finding["identity"]["anchor"] for finding in failed["findings"]} == {
        baseline["identity"]["anchor"],
        later["identity"]["anchor"],
    }
    assert json.loads((scan_dir / "coverage.json").read_text())["completeness"] == ("partial")


def test_recovery_does_not_promote_already_retained_historical_finding(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    historical = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    historical["extensions"] = {"candidateId": "candidate-refined-location"}
    historical["provenance"]["candidateId"] = "candidate-refined-location"
    historical["locations"][0]["startLine"] = 1
    historical["locations"][0]["endLine"] = 2
    historical["severity"]["level"] = "critical"
    historical["confidence"]["level"] = "high"
    historical.pop("identity")
    checkpoint_historical = copy.deepcopy(historical)
    historical["provenance"]["originalCandidates"] = [
        {"candidateId": "candidate-refined-location", "title": historical["title"]}
    ]

    current = copy.deepcopy(historical)
    current["identity"] = {"anchor": "refined-location-finding"}
    current["locations"][0]["startLine"] = 2
    current["severity"]["level"] = "medium"
    current["confidence"]["level"] = "medium"
    current["provenance"]["previousFindings"] = [copy.deepcopy(historical)]
    source_finding = copy.deepcopy(current)
    source_finding["provenance"].pop("sourceFindings", None)
    current["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": source_finding}]

    worker_document = json.loads(worker_result.read_text())
    worker_document["findings"] = [current]
    worker_result.write_text(json.dumps(worker_document))
    checkpoint = copy.deepcopy(worker_document)
    checkpoint["complete"] = False
    checkpoint["findings"] = [checkpoint_historical]
    write_checkpoint(worker_result.parent / "checkpoints", checkpoint)
    committed_standard_reducer(state_dir, codex_home, scan_dir, scan_id, worker_id, worker_result)

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after the canonical result was retained.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["locations"][0]["startLine"] == 2
    assert retained["severity"]["level"] == "medium"
    assert retained["confidence"]["level"] == "medium"
    assert retained["provenance"]["previousFindings"] == [historical]


def test_recovery_retains_same_worker_checkpoint_version_as_history(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    checkpoint_finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    checkpoint_finding["extensions"] = {"candidateId": "candidate-refined-location"}
    checkpoint_finding["provenance"]["candidateId"] = "candidate-refined-location"
    checkpoint_finding["locations"][0]["startLine"] = 1
    checkpoint_finding["locations"][0]["endLine"] = 2
    checkpoint_finding.pop("identity")
    checkpoint_finding["provenance"]["previousFindings"] = [
        None,
        "malformed checkpoint history",
    ]

    current = copy.deepcopy(checkpoint_finding)
    current["locations"][0]["startLine"] = 2
    current["provenance"]["previousFindings"] = [17]
    source_finding = copy.deepcopy(current)
    source_finding["provenance"].pop("sourceFindings", None)
    current["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": source_finding}]

    worker_document = json.loads(worker_result.read_text())
    worker_document["findings"] = [current]
    worker_result.write_text(json.dumps(worker_document))
    checkpoint = copy.deepcopy(worker_document)
    checkpoint["complete"] = False
    checkpoint["findings"] = [checkpoint_finding]
    write_checkpoint(worker_result.parent / "checkpoints", checkpoint)
    committed_standard_reducer(state_dir, codex_home, scan_dir, scan_id, worker_id, worker_result)

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after the canonical result was retained.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    assert retained["locations"][0]["startLine"] == 2
    assert retained["identity"] == {"anchor": "candidate-refined-location"}
    expected_checkpoint = copy.deepcopy(checkpoint_finding)
    expected_checkpoint["provenance"].pop("previousFindings")
    assert retained["provenance"]["previousFindings"] == [expected_checkpoint]


def test_independent_worker_candidate_ids_do_not_share_rejection(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["extensions"] = {"candidateId": "candidate-1"}
    environment = {"CODEX_HOME": str(codex_home)}
    for ordinal, name in enumerate(("rejecting", "reporting"), 1):
        prompt, output, result = worker_paths(scan_dir, name)
        run_workbench(
            state_dir,
            "upsert-deep-scan-worker",
            "--scan-id",
            scan_id,
            "--worker-id",
            f"00000000-0000-4000-8000-{ordinal:012}",
            "--kind",
            "discovery",
            "--status",
            "running",
            "--prompt-path",
            str(prompt),
            "--artifact-dir",
            str(output),
            "--attempt",
            "1",
            environment=environment,
        )
        result.write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "findings": [finding] if name == "reporting" else [],
                    "coverage": {
                        "completeness": "complete",
                        "surfaces": []
                        if name == "reporting"
                        else [
                            {
                                "label": "Safe route",
                                "candidateId": "candidate-1",
                                "disposition": "rejected",
                                "notes": "This route enforces containment.",
                            }
                        ],
                        "explicitExclusions": [],
                        "deferred": [],
                    },
                }
            )
        )
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped.",
        environment=environment,
    )
    failed = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert failed["findingCount"] == 1
    canonical_findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert canonical_findings[0]["extensions"]["candidateId"] == "candidate-1"
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    rejected = next(item for item in coverage["surfaces"] if item["disposition"] == "rejected")
    assert "previousFindings" not in rejected


def test_standard_worker_results_commit_and_recover_without_discovery_ledgers(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    reducer_id, reducer_result, committed = committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )

    assert committed["canonicalArtifacts"] is None
    assert committed["completionSequence"] == 1
    workers = {worker["id"]: worker for worker in committed["workers"]}
    assert workers[worker_id]["mergeState"] == "merged"
    assert workers[worker_id]["resultManifestPath"] == str(worker_result)
    assert workers[reducer_id]["resultManifestPath"] == str(reducer_result)
    assert not (scan_dir / "artifacts" / "02_discovery").exists()

    recovered = run_workbench(
        state_dir,
        "get-deep-scan",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]
    assert recovered["canonicalArtifacts"] is None
    assert recovered["workers"] == committed["workers"]


def test_standard_worker_results_finish_with_only_canonical_parent_manifest(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    manifest_path = scan_dir / "scan-manifest.json"

    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest_path),
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]

    assert finished["status"] == "succeeded"
    assert finished["manifestPath"] == str(manifest_path)
    assert finished["canonicalArtifacts"] is None
    assert not (scan_dir / "artifacts" / "02_discovery").exists()


@pytest.mark.parametrize(
    "incidental_artifacts",
    ("inventory", "ledger", "both", "inventory_symlink", "ledger_symlink"),
)
def test_standard_worker_results_ignore_incidental_legacy_discovery_artifacts(
    tmp_path: Path, incidental_artifacts: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    discovery_dir = scan_dir / "artifacts" / "02_discovery"
    discovery_dir.mkdir(parents=True)
    inventory = discovery_dir / "in_scope_files.txt"
    ledger = discovery_dir / "candidate_ledger.jsonl"
    outside = tmp_path / "outside-discovery-artifact"
    outside.write_text("unrelated legacy artifact\n")

    if incidental_artifacts in {"inventory", "both"}:
        inventory.write_text("unrelated.py\n")
    elif incidental_artifacts == "inventory_symlink":
        inventory.symlink_to(outside)
    if incidental_artifacts in {"ledger", "both"}:
        ledger.write_text("unrelated legacy candidate\n")
    elif incidental_artifacts == "ledger_symlink":
        ledger.symlink_to(outside)

    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    _, _, committed = committed_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, worker_result
    )
    assert committed["canonicalArtifacts"] is None

    def recovered() -> dict[str, object]:
        return run_workbench(
            state_dir,
            "get-deep-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment={"CODEX_HOME": str(codex_home)},
        )["deepScan"]

    assert recovered()["canonicalArtifacts"] is None
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(scan_dir / "scan-manifest.json"),
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]
    assert finished["status"] == "succeeded"
    assert finished["canonicalArtifacts"] is None
    assert recovered()["canonicalArtifacts"] is None
    assert outside.read_text() == "unrelated legacy artifact\n"
    if incidental_artifacts.endswith("_symlink"):
        assert (inventory if incidental_artifacts.startswith("inventory") else ledger).is_symlink()


def test_standard_worker_deadline_can_finish_without_any_completed_worker(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["completeness"] = "partial"
    coverage["surfaces"] = []
    coverage["deferred"] = [
        {
            "reason": "The configured discovery time limit elapsed before any source review completed."
        }
    ]
    coverage_path.write_text(json.dumps(coverage))
    manifest_path = scan_dir / "scan-manifest.json"
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?",
            ((datetime.now(timezone.utc) - timedelta(hours=97)).isoformat(), scan_id),
        )

    finished = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest_path),
        environment={"CODEX_HOME": str(codex_home)},
    )["deepScan"]

    assert finished["status"] == "succeeded"
    assert finished["completionSequence"] == 0
    assert finished["canonicalArtifacts"] is None
    assert not (scan_dir / "artifacts" / "02_discovery").exists()


def test_standard_worker_finish_preserves_running_state_when_parent_draft_is_incomplete(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    (scan_dir / "findings.json").unlink()

    rejected = run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(scan_dir / "scan-manifest.json"),
        environment={"CODEX_HOME": str(codex_home)},
        check=False,
    )

    assert "Canonical parent findings.json must be an existing path" in str(rejected["stderr"])
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT status, manifest_path FROM deep_scan_runs WHERE scan_id = ?", (scan_id,)
        ).fetchone() == ("running", None)


def test_budget_exhaustion_preserves_validated_standard_results_without_candidate_ledgers(
    tmp_path: Path,
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, budget=True)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    manifest_path = scan_dir / "scan-manifest.json"
    run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(manifest_path),
        environment={"CODEX_HOME": str(codex_home)},
    )
    warning = "Scan stopped: estimated cost $0.00625 exceeded the $0.005 cost limit."

    completed = run_workbench(
        state_dir,
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(
            {
                "model": "gpt-5.6-sol",
                "inputTokens": 1250,
                "cachedInputTokens": 200,
                "cacheWriteInputTokens": 0,
                "outputTokens": 30,
                "estimatedUsd": 0.00625,
            }
        ),
        "--message",
        warning,
    )["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert "Unsafe archive extraction" in completed["findings"][0]["title"]
    assert completed["warnings"] == [warning]
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert coverage["deferred"] == [
        {
            "id": "scan-cost-limit",
            "reason": "Validation was deferred because the scan reached its cost limit.",
        }
    ]
    sarif = json.loads((scan_dir / "exports/results.sarif").read_text())
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True
    assert not (scan_dir / "artifacts" / "02_discovery").exists()


def test_budget_exhaustion_rejects_incomplete_standard_result_draft(tmp_path: Path) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, budget=True)
    worker_id, worker_result = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    committed_standard_reducer(
        state_dir,
        codex_home,
        scan_dir,
        scan_id,
        worker_id,
        worker_result,
    )
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    run_workbench(
        state_dir,
        "finish-deep-scan",
        "--scan-id",
        scan_id,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        str(scan_dir / "scan-manifest.json"),
        environment={"CODEX_HOME": str(codex_home)},
    )
    (scan_dir / "findings.json").unlink()

    rejected = run_workbench(
        state_dir,
        "complete-budget-exhausted-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(
            {
                "model": "gpt-5.6-sol",
                "inputTokens": 1250,
                "cachedInputTokens": 200,
                "cacheWriteInputTokens": 0,
                "outputTokens": 30,
                "estimatedUsd": 0.00625,
            }
        ),
        check=False,
    )

    assert "incomplete canonical scan draft" in str(rejected["stderr"])
