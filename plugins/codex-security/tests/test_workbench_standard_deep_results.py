from __future__ import annotations

import copy
import json
from pathlib import Path
from unittest import mock

import pytest
from workbench_test_support import write_checkpoint, write_completed_contract


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
                "completeness": "partial",
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
                    "completeness": "partial",
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
