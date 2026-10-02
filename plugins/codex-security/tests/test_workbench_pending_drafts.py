from __future__ import annotations

import argparse
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import checkpoint, register, run_workbench, write_completed_contract


@pytest.fixture
def pending_scan(tmp_path, workbench_api, monkeypatch, request):
    scenario = getattr(request, "param", "standard")
    mode = "standard" if scenario == "standard" else "deep"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode=mode)
    directory = Path(scan["scanDir"])
    child_title = None
    if scenario == "deep_child":
        child_dir = directory / "artifacts/deep-scan/passes/pass-1"
        child = register(state, target, child_dir, parent=scan["scanId"], role="deep_pass")
        write_completed_contract(
            child_dir,
            child["scanId"],
            target,
            relative_path="app.py",
            identity_anchor="unmerged-child",
        )
        child_findings = json.loads((child_dir / "findings.json").read_text())
        child_title = "Unmerged child evidence"
        child_findings["findings"][0]["title"] = child_title
        (child_dir / "findings.json").write_text(json.dumps(child_findings))
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        checkpoint(
            state,
            scan,
            terminal="capped",
            passes=[
                {
                    "directory": child_dir.relative_to(directory).as_posix(),
                    "scanId": child["scanId"],
                }
            ],
        )
    elif mode == "deep":
        checkpoint(state, scan, terminal="saturated")
    write_completed_contract(
        directory,
        scan["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository" if mode == "deep" else "repository",
    )
    documents = {
        key: json.loads((directory / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["manifest"]["scan"]["complete"] = True
    expected = copy.deepcopy(documents["findings"]["findings"][0])
    empty = copy.deepcopy(documents)
    empty["findings"]["findings"] = []
    saved = workbench_api["saved_results"]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    args = argparse.Namespace(
        scan_id=scan["scanId"],
        claim_token=None,
        draft_path=None,
        checkpoint_path=None,
        expected_draft_digest=None,
    )
    with workbench_api["connect"]() as connection:

        def publish(draft, *, staged=False):
            payload = {
                "documents": draft,
                "checkpoint": {
                    "scanId": scan["scanId"],
                    "complete": True,
                    "findings": draft["findings"]["findings"],
                    "coverage": draft["coverage"],
                },
            }
            publish_args = copy.copy(args)
            if staged:
                (directory / "drafts").mkdir(exist_ok=True)
                draft_path = directory / "drafts" / f"{scan['scanId']}.json"
                checkpoint_path = draft_path.with_suffix(".checkpoint.json")
                draft_path.write_text(json.dumps(draft))
                checkpoint_path.write_text(json.dumps(payload["checkpoint"]))
                publish_args.draft_path = str(draft_path)
                publish_args.checkpoint_path = str(checkpoint_path)
            monkeypatch.setattr(saved.sys, "stdin", io.StringIO(json.dumps(payload)))
            saved.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], connection, publish_args)

        yield SimpleNamespace(
            publish=publish,
            saved=saved,
            documents=documents,
            empty=empty,
            expected=expected,
            directory=directory,
            state=state,
            scan_id=scan["scanId"],
            child_title=child_title,
        )


def test_later_commits_retire_accepted_markers_after_cleanup_interruption(
    pending_scan, monkeypatch
):
    fixture = pending_scan
    saved, directory = fixture.saved, fixture.directory
    remove = saved._remove_scan_local_file_if_exists
    rejected = copy.deepcopy(fixture.empty)
    rejected["coverage"]["surfaces"][0]["disposition"] = "rejected"

    def fail_cleanup(root, relative):
        if relative.startswith("checkpoints/pending/"):
            raise OSError("Synthetic checkpoint cleanup interruption")
        return remove(root, relative)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_remove_scan_local_file_if_exists", fail_cleanup)
        fixture.publish(fixture.documents)
        assert (
            json.loads((directory / "findings.json").read_text())["findings"][0]["title"]
            == fixture.expected["title"]
        )
        accepted = json.loads((directory / "artifacts/scan-draft.json").read_text())
        acknowledged = accepted["reconciledCheckpointIds"]
        assert len(acknowledged) == 1
        for _ in range(2):
            fixture.publish(rejected)
            committed = json.loads((directory / "artifacts/scan-draft.json").read_text())
            assert acknowledged[0] in committed["reconciledCheckpointIds"]
            assert saved._pending_result_paths(directory) == []
            assert json.loads((directory / "findings.json").read_text())["findings"] == []
    evidence = (directory / "checkpoints" / acknowledged[0]).read_bytes()
    assert (directory / "checkpoints/pending" / acknowledged[0]).exists()
    # An explicit rejection in a later accepted draft must not be reopened by the marker.
    fixture.publish(rejected)
    assert not (directory / "checkpoints/pending" / acknowledged[0]).exists()
    fixture.publish(rejected)
    run_workbench(fixture.state, "prepare-scan-completion", "--scan-id", fixture.scan_id)
    assert json.loads((directory / "findings.json").read_text())["findings"] == []
    assert (
        json.loads((directory / "coverage.json").read_text())["surfaces"][0]["disposition"]
        == "rejected"
    )
    assert fixture.expected["title"] not in (directory / "report.md").read_text()
    assert (directory / "checkpoints" / acknowledged[0]).read_bytes() == evidence
    assert list((directory / "checkpoints/pending").glob("*.json")) == []


@pytest.mark.parametrize("pending_scan", ["standard", "deep"], indirect=True)
@pytest.mark.parametrize(
    ("document", "invalid"),
    [
        (None, "{malformed"),
        (None, "{}"),
        ("manifest", None),
        ("findings", []),
        ("coverage", "invalid"),
    ],
    ids=["invalid_json", "missing_documents", "null_manifest", "array_findings", "scalar_coverage"],
)
def test_cancel_recovers_immutable_checkpoint_when_committed_head_is_malformed(
    pending_scan, document, invalid
):
    fixture = pending_scan
    directory = fixture.directory
    fixture.publish(fixture.documents)
    checkpoints = {
        path.name: path.read_bytes() for path in (directory / "checkpoints").glob("*.json")
    }
    # Accepted evidence must survive even when no pending index remains.
    (directory / "checkpoints/pending").rmdir()
    contents = (
        json.dumps({**fixture.documents, document: invalid}) if document is not None else invalid
    )
    (directory / "artifacts/scan-draft.json").write_text(contents)
    findings_path = directory / "findings.json"
    current = json.loads(findings_path.read_text())
    current["findings"] = []
    findings_path.write_text(json.dumps(current))
    run_workbench(fixture.state, "cancel-scan", "--scan-id", fixture.scan_id)
    findings = json.loads(findings_path.read_text())["findings"]
    assert [finding["title"] for finding in findings] == [fixture.expected["title"]]
    assert findings[0]["codeEvidence"] == fixture.expected["codeEvidence"]
    assert json.loads((directory / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    assert fixture.expected["title"] in (directory / "report.md").read_text()
    assert all(
        (directory / "checkpoints" / name).read_bytes() == contents
        for name, contents in checkpoints.items()
    )


@pytest.mark.parametrize("pending_scan", ["standard", "deep"], indirect=True)
def test_stopped_scan_does_not_reopen_acknowledged_findings(pending_scan, monkeypatch):
    fixture = pending_scan
    fixture.publish(fixture.documents)
    original_exports = {
        name: (fixture.directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    removed = copy.deepcopy(fixture.empty)
    removed["coverage"]["surfaces"][0]["disposition"] = "no_issue_found"
    write = fixture.saved.write_scan_local_bytes

    def fail_export(root, relative, contents, **kwargs):
        if relative == "findings.json":
            raise OSError("Synthetic export interruption")
        return write(root, relative, contents, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(fixture.saved, "write_scan_local_bytes", fail_export)
        with pytest.raises(OSError, match="export interruption"):
            fixture.publish(removed)
    assert all(
        (fixture.directory / name).read_bytes() == data for name, data in original_exports.items()
    )
    run_workbench(
        fixture.state, "fail-scan", "--scan-id", fixture.scan_id, "--message", "Synthetic stop"
    )
    assert json.loads((fixture.directory / "findings.json").read_text())["findings"] == []
    run_workbench(fixture.state, "recover-scan-results", "--scan-id", fixture.scan_id)
    assert json.loads((fixture.directory / "findings.json").read_text())["findings"] == []


def test_pending_review_on_an_already_resolved_surface_survives_completion(
    pending_scan, monkeypatch
):
    fixture = pending_scan
    resolved = copy.deepcopy(fixture.empty)
    resolved["coverage"]["surfaces"][0]["disposition"] = "no_issue_found"
    fixture.publish(resolved)
    pending = copy.deepcopy(resolved)
    pending["manifest"]["scan"]["complete"] = False
    pending["coverage"]["completeness"] = "partial"
    pending["coverage"]["deferred"] = [
        {
            "id": "independent-review",
            "reason": "Review additional evidence",
            "surfaceIds": [resolved["coverage"]["surfaces"][0]["id"]],
        }
    ]
    write = fixture.saved.write_scan_local_bytes

    def fail_commit(root, relative, contents, **kwargs):
        if relative == "artifacts/scan-draft.json":
            raise OSError("Synthetic commit interruption")
        return write(root, relative, contents, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(fixture.saved, "write_scan_local_bytes", fail_commit)
        with pytest.raises(OSError, match="commit interruption"):
            fixture.publish(pending)
    run_workbench(fixture.state, "prepare-scan-completion", "--scan-id", fixture.scan_id)
    coverage = json.loads((fixture.directory / "coverage.json").read_text())
    assert coverage["deferred"] == pending["coverage"]["deferred"]
    assert coverage["completeness"] == "partial"


@pytest.mark.parametrize("staged", [False, True, "legacy"])
def test_checkpoint_copy_failure_retains_pending_evidence(pending_scan, monkeypatch, staged):
    fixture = pending_scan
    fixture.publish(fixture.empty)
    write = fixture.saved.write_scan_local_bytes

    def fail_history_copy(root, relative, contents, **kwargs):
        if relative.startswith("checkpoints/") and not relative.startswith("checkpoints/pending/"):
            raise OSError("Synthetic history copy interruption")
        return write(root, relative, contents, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(fixture.saved, "write_scan_local_bytes", fail_history_copy)
        with pytest.raises(OSError, match="history copy interruption"):
            fixture.publish(fixture.documents, staged=staged)
    markers = list((fixture.directory / "checkpoints/pending").glob("*.json"))
    assert len(markers) == 1
    evidence = markers[0].read_bytes()
    assert fixture.expected["title"] in evidence.decode()
    if staged == "legacy":
        staged_path = next((fixture.directory / "drafts").glob("*.checkpoint.json"))
        markers[0].write_text(staged_path.relative_to(fixture.directory).as_posix())
    run_workbench(
        fixture.state, "fail-scan", "--scan-id", fixture.scan_id, "--message", "Synthetic stop"
    )
    findings = json.loads((fixture.directory / "findings.json").read_text())["findings"]
    assert [finding["title"] for finding in findings] == [fixture.expected["title"]]
    if staged != "legacy":
        assert markers[0].read_bytes() == evidence
    assert (fixture.directory / "checkpoints" / markers[0].name).read_bytes() == evidence
