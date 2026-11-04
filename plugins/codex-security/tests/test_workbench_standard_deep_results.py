from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import (
    empty_target_scan,
    get_scan,
    scan_command,
    write_checkpoint,
    write_completed_contract,
)


@pytest.mark.parametrize(
    ("questions", "checkpoint_questions", "expected"),
    [
        pytest.param(
            ["Q1", "Q2", "Q3"],
            None,
            [{"question": "Q1"}, {"question": "Q2"}, {"question": "Q3"}],
            id="string-questions",
        ),
        pytest.param(
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            id="identical-follow-up",
        ),
        pytest.param(
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."}],
            [{"question": "Which tests remain?", "followUpPrompt": "Run the Windows tests."}],
            [
                {"question": "Which tests remain?", "followUpPrompt": "Run the Linux tests."},
                {"question": "Which tests remain?", "followUpPrompt": "Run the Windows tests."},
            ],
            id="distinct-follow-ups",
        ),
    ],
)
def test_merge_saved_results_deduplicates_open_questions(
    tmp_path: Path,
    questions: list[str | dict[str, str]],
    checkpoint_questions: list[dict[str, str]] | None,
    expected: list[dict[str, str]],
    workbench_api,
) -> None:
    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "test-scan-open-questions"

    manifest = {
        "scan": {
            "id": scan_id,
            "target": {"kind": "git_revision", "repository": "test", "revision": "head"},
            "scope": {"includePaths": ["."], "excludePaths": []},
            "status": "in_progress",
            "complete": False,
        }
    }
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    (scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    (scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
                "openQuestions": questions,
            }
        )
    )
    if checkpoint_questions is not None:
        write_checkpoint(
            scan_dir / "checkpoints",
            {
                "scanId": scan_id,
                "complete": False,
                "findings": [],
                "coverage": {
                    "surfaces": [],
                    "explicitExclusions": [],
                    "deferred": [],
                    "openQuestions": checkpoint_questions,
                },
            },
        )

    binding = {
        "status": "in_progress",
        "allowedTargetKinds": ["git_revision"],
        "target": {"kind": "git_revision", "repository": "test", "revision": "head"},
        "scope": {"includePaths": ["."], "excludePaths": []},
        "coverageMode": "repository",
    }

    result = workbench_api["saved_results"].merge_saved_results(
        scan_dir, scan_id, binding, [], stopped=False, reason=""
    )
    assert result is not None
    _, _, coverage = result
    assert coverage.get("openQuestions") == expected


@pytest.mark.parametrize("checkpoint_count", [0, 4, 20])
@pytest.mark.parametrize("finding_count", [1, 3])
def test_parent_validation_does_not_scale_with_superseded_checkpoints(
    tmp_path: Path, workbench_api, checkpoint_count: int, finding_count: int
) -> None:
    saved_results = workbench_api["saved_results"]
    target = tmp_path / "target"
    target.mkdir()
    scan_dir = tmp_path / "scan"
    scan_dir.mkdir()
    scan_id = "parent-validation"
    write_completed_contract(scan_dir, scan_id, target)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    findings = json.loads((scan_dir / "findings.json").read_text())
    findings["findings"] = [copy.deepcopy(findings["findings"][0]) for _ in range(finding_count)]
    for index, finding in enumerate(findings["findings"]):
        finding["identity"] = {"anchor": f"finding-{index}"}
    (scan_dir / "findings.json").write_text(json.dumps(findings))
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    for index in range(checkpoint_count):
        earlier = copy.deepcopy(findings["findings"][0])
        earlier["summary"] = f"Superseded observation {index}."
        write_checkpoint(
            scan_dir / "checkpoints",
            {"scanId": scan_id, "findings": [earlier], "coverage": coverage},
        )
    # A committed parent head records that the older checkpoints were reconciled.
    committed = scan_dir / "artifacts/scan-draft.json"
    committed.parent.mkdir(exist_ok=True)
    committed.write_text(
        json.dumps({"manifest": {"scan": manifest}, "findings": findings, "coverage": coverage})
    )
    binding = {
        "status": "completed",
        "allowedTargetKinds": [manifest["target"]["kind"]],
        "target": manifest["target"],
        "scope": manifest["scope"],
        "coverageMode": "repository",
    }
    with (
        mock.patch.object(
            saved_results, "_read_json", wraps=saved_results._read_json
        ) as read_schema,
        mock.patch.object(
            saved_results,
            "_recover_unsealed_findings",
            wraps=saved_results._recover_unsealed_findings,
        ) as recover,
    ):
        result = saved_results.merge_saved_results(
            scan_dir, scan_id, binding, [], stopped=False, reason=""
        )
    assert result is not None
    assert result[1]["findings"] == findings["findings"]
    assert read_schema.call_count == 2
    # Unchanged findings share validation across parent, checkpoints, and final output.
    assert recover.call_count == finding_count


def deep_scan_fixture(tmp_path: Path):
    """Create an active composed Deep Scan without the retired worker scheduler."""
    from workbench_test_support import checkpoint, register

    target, state, directory = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    scan = register(state, target, directory, mode="deep")
    checkpoint(state, scan)
    return state, tmp_path / "codex-home", target, directory, scan["scanId"]


def run_workbench_with_fault(script_path, state_dir, codex_home, setup, *args):
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    script_path.write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\n"
        "import workbench_saved_results\n" + setup + "raise SystemExit(workbench_db.main())\n"
    )
    return subprocess.run(
        [sys.executable, str(script_path), *args],
        capture_output=True,
        env={
            **os.environ,
            "CODEX_HOME": str(codex_home),
            "CODEX_SECURITY_STATE_DIR": str(state_dir),
        },
        text=True,
    )


def test_canonical_finding_validation_survives_frozen_publication_retry(tmp_path: Path) -> None:
    state_dir, target, scan_id, scan_dir = empty_target_scan(tmp_path)
    write_completed_contract(scan_dir, scan_id, target)
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["severity"]["level"] = "informational"
    stronger = copy.deepcopy(finding)
    stronger["severity"]["level"] = "critical"
    malformed_identity = copy.deepcopy(finding)
    malformed_identity["identity"] = {"anchor": []}
    findings["findings"].extend([stronger, malformed_identity])
    findings_path.write_text(json.dumps(findings))
    original = findings_path.read_bytes()

    failed = run_workbench_with_fault(
        tmp_path / "fail_canonical_publication.py",
        state_dir,
        tmp_path / "codex-home",
        "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n",
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Finding repair was interrupted.",
    )
    assert failed.returncode == 0, failed.stderr
    assert findings_path.read_bytes() == original
    assert get_scan(state_dir, scan_id)["scan"]["resultsRecoveryNeeded"] is True
    frozen = {path: path.read_bytes() for path in (scan_dir / "checkpoints").glob("*.json")}
    assert frozen

    recovered = scan_command(state_dir, "recover-scan-results", scan_id)["scan"]

    assert recovered["resultsRecoveryNeeded"] is False
    assert recovered["findingCount"] == 1
    finding = json.loads(findings_path.read_text())["findings"][0]
    assert finding["severity"]["level"] == "critical"
    assert any(
        previous["severity"]["level"] == "informational"
        for previous in finding["provenance"]["previousFindings"]
    )
    assert any("duplicate logical finding" in warning for warning in recovered["warnings"])
    assert any("identity" in warning for warning in recovered["warnings"])
    assert all(path.read_bytes() == content for path, content in frozen.items())


def test_stopped_scan_recovers_latest_numbered_iteration_after_upgrade(
    historical_publication_scan,
) -> None:
    scan = historical_publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    results = []
    # Tied completion timestamps and reversed worker IDs must defer to the iteration number.
    originals = sorted([scan.add_worker(), scan.add_worker()], reverse=True)
    for number, original in enumerate(originals, 1):
        directory = original.parent.with_name(f"dedup-{number:04d}")
        original.parent.rename(directory)
        result = directory / "result.json"
        with scan.connection:
            scan.connection.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', artifact_dir = ?, "
                "result_manifest_path = ? WHERE id = ?",
                (str(directory), str(result), original.parent.name),
            )
        results.append(result)
    first, latest = results
    earlier = {"scanId": scan.scan_id, "findings": []}
    first.write_text(json.dumps(earlier))
    write_checkpoint(first.parent / "checkpoints", earlier)
    finding = copy.deepcopy(scan.findings[0])
    finding["provenance"]["deepScanRepairGroups"] = [
        {"order": 0, "sources": ["review-1:candidate-1"]}
    ]
    model = {"summary": "The most recent scan found another trust boundary."}
    latest.write_text(
        json.dumps({"scanId": scan.scan_id, "findings": [finding], "threatModel": model})
    )

    scan.fail()
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["threatModel"] == model
    retained = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(retained) == 1
    assert retained[0]["summary"] == finding["summary"]
    assert "deepScanRepairGroups" not in retained[0]["provenance"]
    assert json.loads(latest.read_text())["findings"] == [finding]
