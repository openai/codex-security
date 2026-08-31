from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any

import pytest
from workbench_test_support import (
    create_saved_workspace,
    run_workbench,
    stable_target_id,
    start_delivered_scan,
    write_completed_contract,
)


def _create_workspace(state_dir: Path, target: Path) -> str:
    source = target / "src" / "extract.py"
    source.parent.mkdir(parents=True)
    source.write_text("safe fixture\n" * 50)
    return str(create_saved_workspace(state_dir, target)["id"])


def _start_scan(state_dir: Path, workspace_id: str, scan_root: Path) -> dict[str, Any]:
    return start_delivered_scan(
        state_dir,
        "--workspace-id",
        workspace_id,
        "--scan-root",
        str(scan_root),
    )["results"]


def _complete_scan(
    state_dir: Path,
    workspace_id: str,
    scan_root: Path,
    target: Path,
    *,
    anchors: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    started = _start_scan(state_dir, workspace_id, scan_root)
    scan_id = str(started["scanId"])
    scan_dir = Path(str(started["scanDir"]))
    write_completed_contract(scan_dir, scan_id, target)
    if anchors is not None:
        findings_path = scan_dir / "findings.json"
        document = json.loads(findings_path.read_text())
        finding = document["findings"][0]
        document["findings"] = [
            {
                **finding,
                "identity": {"anchor": anchor},
                "title": f"{finding['title']} ({anchor})",
            }
            for anchor in anchors
        ]
        findings_path.write_text(json.dumps(document))
    return run_workbench(state_dir, "complete-scan", "--scan-id", scan_id)["scan"]


def _close_finding(
    state_dir: Path,
    occurrence_id: str,
    close_reason: str,
    note: str | None = None,
) -> dict[str, Any]:
    arguments = [
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        close_reason,
    ]
    if note is not None:
        arguments.extend(("--note", note))
    return run_workbench(state_dir, *arguments)["scan"]


def _feedback(state_dir: Path, scan_id: str) -> dict[str, Any]:
    return run_workbench(state_dir, "get-scan-feedback", "--scan-id", scan_id)


@pytest.mark.parametrize("mode", ("standard", "deep"))
def test_native_scan_materializes_false_positive_feedback(tmp_path: Path, mode: str) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    workspace_id = _create_workspace(state_dir, target)
    completed = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    _close_finding(
        state_dir,
        str(completed["findings"][0]["occurrenceId"]),
        "false_positive",
        "The archive path is normalized before the write.",
    )
    if mode == "deep":
        workspace_id = str(create_saved_workspace(state_dir, target, mode=mode)["id"])

    started = _start_scan(state_dir, workspace_id, tmp_path / "scans")
    feedback_path = (
        Path(str(started["scanDir"])) / "artifacts" / "01_context" / "false_positive_feedback.json"
    )

    assert (
        json.loads(feedback_path.read_text())
        == _feedback(state_dir, str(started["scanId"]))["falsePositives"]
    )
    assert feedback_path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("note", (None, "  \t  "))
def test_false_positive_triage_requires_a_reason(tmp_path: Path, note: str | None) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    workspace_id = _create_workspace(state_dir, target)
    completed = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    occurrence_id = str(completed["findings"][0]["occurrenceId"])

    rejected = run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        *(() if note is None else ("--note", note)),
        check=False,
    )

    assert rejected["returncode"] != 0
    assert "Explain why this finding is a false positive." in str(rejected["stderr"])
    scan = run_workbench(state_dir, "get-scan", "--scan-id", str(completed["scanId"]))["scan"]
    assert scan["findings"][0]["triage"] == {"status": "open"}


def test_feedback_excludes_the_current_scan(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    workspace_id = _create_workspace(state_dir, target)
    completed = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    assert not (
        Path(str(completed["scanDir"]))
        / "artifacts"
        / "01_context"
        / "false_positive_feedback.json"
    ).exists()
    _close_finding(
        state_dir,
        str(completed["findings"][0]["occurrenceId"]),
        "false_positive",
        "The current scan must not provide its own feedback.",
    )

    assert _feedback(state_dir, str(completed["scanId"])) == {
        "falsePositives": [],
        "scanId": completed["scanId"],
        "targetId": stable_target_id(target),
    }


def test_feedback_is_scoped_to_explained_false_positives(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    other_target = tmp_path / "other-repository"
    workspace_id = _create_workspace(state_dir, target)
    other_workspace_id = _create_workspace(state_dir, other_target)
    previous = _complete_scan(
        state_dir,
        workspace_id,
        tmp_path / "scans",
        target,
        anchors=("false-positive", "already-fixed", "accepted-risk", "no-reason"),
    )
    occurrences = {
        finding["identity"]["anchor"]: str(finding["occurrenceId"])
        for finding in previous["findings"]
    }
    _close_finding(
        state_dir,
        occurrences["false-positive"],
        "false_positive",
        "Archive entries are normalized before the write.",
    )
    _close_finding(state_dir, occurrences["already-fixed"], "already_fixed")
    _close_finding(state_dir, occurrences["accepted-risk"], "wont_fix", "Accepted risk")
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            """
            INSERT INTO finding_triage (
                occurrence_id, status, close_reason, note, updated_at
            ) VALUES (?, 'closed', 'false_positive', NULL, ?)
            """,
            (occurrences["no-reason"], "2026-07-26T12:00:00Z"),
        )

    other = _complete_scan(state_dir, other_workspace_id, tmp_path / "scans", other_target)
    _close_finding(
        state_dir,
        str(other["findings"][0]["occurrenceId"]),
        "false_positive",
        "This finding belongs to another repository.",
    )
    current = _start_scan(state_dir, workspace_id, tmp_path / "scans")

    feedback = _feedback(state_dir, str(current["scanId"]))

    assert feedback["scanId"] == current["scanId"]
    assert feedback["targetId"] == stable_target_id(target)
    assert len(feedback["falsePositives"]) == 1
    assert feedback["falsePositives"][0]["identity"]["anchor"] == "false-positive"
    assert feedback["falsePositives"][0]["reason"] == (
        "Archive entries are normalized before the write."
    )
    assert feedback["falsePositives"][0]["sourceScanId"] == previous["scanId"]


def test_latest_decision_controls_false_positive_feedback(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    workspace_id = _create_workspace(state_dir, target)
    first = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    _close_finding(
        state_dir,
        str(first["findings"][0]["occurrenceId"]),
        "false_positive",
        "Original reviewer rationale.",
    )
    second = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    occurrence_id = str(second["findings"][0]["occurrenceId"])

    assert _feedback(state_dir, str(second["scanId"]))["falsePositives"][0]["reason"] == (
        "Original reviewer rationale."
    )

    closed = _close_finding(
        state_dir,
        occurrence_id,
        "false_positive",
        "The latest reviewer checked the current control.",
    )
    current = _start_scan(state_dir, workspace_id, tmp_path / "scans")
    scan_id = str(current["scanId"])
    feedback = _feedback(state_dir, scan_id)

    assert len(feedback["falsePositives"]) == 1
    assert feedback["falsePositives"][0]["reason"] == (
        "The latest reviewer checked the current control."
    )
    assert feedback["falsePositives"][0]["sourceScanId"] == second["scanId"]
    assert (
        feedback["falsePositives"][0]["updatedAt"] == (closed["findings"][0]["triage"]["updatedAt"])
    )

    run_workbench(
        state_dir,
        "set-finding-triage",
        "--occurrence-id",
        occurrence_id,
        "--status",
        "open",
    )
    assert _feedback(state_dir, scan_id)["falsePositives"] == []

    _close_finding(state_dir, occurrence_id, "wont_fix", "Accepted risk.")
    assert _feedback(state_dir, scan_id)["falsePositives"] == []

    _close_finding(
        state_dir,
        occurrence_id,
        "false_positive",
        "The latest reviewer restored the dismissal.",
    )
    assert _feedback(state_dir, scan_id)["falsePositives"][0]["reason"] == (
        "The latest reviewer restored the dismissal."
    )


def test_default_open_finding_overrides_an_older_false_positive(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    workspace_id = _create_workspace(state_dir, target)
    first = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    _close_finding(
        state_dir,
        str(first["findings"][0]["occurrenceId"]),
        "false_positive",
        "The original route checked the session.",
    )
    reopened = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target)
    assert reopened["findings"][0]["triage"]["status"] == "open"
    current = _start_scan(state_dir, workspace_id, tmp_path / "scans")

    assert _feedback(state_dir, str(current["scanId"]))["falsePositives"] == []


def test_feedback_returns_only_the_50_latest_decisions(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    target = tmp_path / "repository"
    workspace_id = _create_workspace(state_dir, target)
    anchors = tuple(f"false-positive-{index:03d}" for index in range(55))
    previous = _complete_scan(state_dir, workspace_id, tmp_path / "scans", target, anchors=anchors)

    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        rows = connection.execute(
            """
            SELECT occurrences.id, findings.identity_anchor
            FROM finding_occurrences AS occurrences
            JOIN findings ON findings.id = occurrences.finding_id
            WHERE occurrences.scan_id = ?
            ORDER BY findings.identity_anchor
            """,
            (previous["scanId"],),
        ).fetchall()
        for index, (occurrence_id, _) in enumerate(rows):
            timestamp = f"2026-07-26T12:00:{index:02d}Z"
            connection.execute(
                """
                INSERT INTO finding_triage (
                    occurrence_id, status, close_reason, note, updated_at
                ) VALUES (?, 'closed', 'false_positive', ?, ?)
                """,
                (occurrence_id, f"Counterexample {index}", timestamp),
            )
            connection.execute(
                """
                INSERT INTO finding_decisions (
                    id, occurrence_id, status, close_reason, note, created_at
                ) VALUES (?, ?, 'closed', 'false_positive', ?, ?)
                """,
                (str(uuid.uuid4()), occurrence_id, f"Counterexample {index}", timestamp),
            )

    current = _start_scan(state_dir, workspace_id, tmp_path / "scans")
    feedback = _feedback(state_dir, str(current["scanId"]))

    assert len(feedback["falsePositives"]) == 50
    assert [finding["identity"]["anchor"] for finding in feedback["falsePositives"]] == [
        f"false-positive-{index:03d}" for index in range(54, 4, -1)
    ]
