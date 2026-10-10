from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path

import pytest
from workbench_test_support import (
    begin_legacy_scan,
    checkpoint,
    register,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)


def test_retired_execution_rejected_without_mutating_artifacts(
    tmp_path, workbench_api, monkeypatch
):
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    created = begin_legacy_scan(
        state, tmp_path / "home", target, tmp_path / "scans", thread_id="owner"
    )
    scan = created["deepScan"]
    directory = Path(scan["scanDir"])
    sentinel = directory / "saved-evidence.txt"
    sentinel.write_text("Historical evidence")
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with workbench_api["connect"]() as connection:
        row = workbench_api["require_scan"](connection, scan["scanId"])
        with pytest.raises(SystemExit, match="original version"):
            workbench_api["saved_results"].require_current_deep_scan(
                workbench_api["_WORKBENCH_DB_CONTEXT"], connection, row
            )
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = 'historical-seal' WHERE id = ?",
            (scan["scanId"],),
        )
        row = workbench_api["require_scan"](connection, scan["scanId"])
        workbench_api["saved_results"].require_current_deep_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"], connection, row
        )
    assert sentinel.read_text() == "Historical evidence"


def test_committed_draft_survives_partial_export_and_blocks_stale_writer(
    tmp_path, workbench_api, monkeypatch
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    registered = register(state, target, tmp_path / "scan")
    directory = Path(registered["scanDir"])
    write_completed_contract(directory, registered["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((directory / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["findings"]["findings"][0]["title"] = "Accepted current draft"
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    module = workbench_api["saved_results"]
    write = module.write_scan_local_bytes

    def fail_export(root, relative, contents, **kwargs):
        if relative == "coverage.json":
            raise OSError("Synthetic export interruption")
        return write(root, relative, contents, **kwargs)

    args = argparse.Namespace(
        scan_id=registered["scanId"],
        claim_token=None,
        draft_path=None,
        checkpoint_path=None,
        expected_draft_digest=None,
    )
    with workbench_api["connect"]() as connection:
        monkeypatch.setattr(module.sys, "stdin", io.StringIO(json.dumps({"documents": documents})))
        monkeypatch.setattr(module, "write_scan_local_bytes", fail_export)
        with pytest.raises(OSError, match="export interruption"):
            module.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], connection, args)
        committed = (directory / "artifacts/scan-draft.json").read_bytes()
        observed_digest = module._scan_draft_digest(directory)
        _, recovered = module._read_saved_parent_result(directory, registered["scanId"])
        assert recovered["findings"][0]["title"] == "Accepted current draft"
        monkeypatch.setattr(module, "write_scan_local_bytes", write)
        monkeypatch.setattr(module.sys, "stdin", io.StringIO(json.dumps({"documents": documents})))
        args.expected_draft_digest = "stale"
        with pytest.raises(SystemExit, match="scan_draft_conflict"):
            module.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], connection, args)
        assert (directory / "artifacts/scan-draft.json").read_bytes() == committed
        monkeypatch.setattr(module.sys, "stdin", io.StringIO(json.dumps({"documents": documents})))
        args.expected_draft_digest = observed_digest
        module.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], connection, args)
    blocked = run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        registered["scanId"],
        "--artifact-path",
        "artifacts/scan-draft.json",
        input_text="{}",
        check=False,
    )
    assert blocked["returncode"] != 0
    assert "typed scan tools" in blocked["stderr"]


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("existing_exports", [False, True])
def test_completion_uses_committed_documents_after_interrupted_export(
    tmp_path, workbench_api, monkeypatch, mode, complete, existing_exports
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode=mode)
    directory = Path(scan["scanDir"])
    if mode == "deep":
        checkpoint(state, scan, terminal="saturated")
    write_completed_contract(
        directory,
        scan["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository" if mode == "deep" else "repository",
    )
    manifest_path = directory / "scan-manifest.json"
    documents = {
        key: json.loads((directory / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["manifest"]["scan"]["complete"] = not complete
    manifest_path.write_text(json.dumps(documents["manifest"]))
    artifact_names = ("scan-manifest.json", "findings.json", "coverage.json")
    if not existing_exports:
        for name in artifact_names:
            (directory / name).unlink()
    documents["manifest"]["scan"]["complete"] = complete
    documents["findings"]["findings"][0]["summary"] = "Latest committed finding."
    documents["coverage"]["surfaces"][0]["label"] = "Latest committed surface"
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes

    def fail_export(root, relative, contents, **kwargs):
        if relative == ("coverage.json" if existing_exports else "findings.json"):
            raise OSError("Synthetic export interruption")
        return write(root, relative, contents, **kwargs)

    with workbench_api["connect"]() as connection:
        with monkeypatch.context() as patch:
            patch.setattr(saved.sys, "stdin", io.StringIO(json.dumps({"documents": documents})))
            patch.setattr(saved, "write_scan_local_bytes", fail_export)
            with pytest.raises(OSError, match="export interruption"):
                saved.write_scan_draft(
                    workbench_api["_WORKBENCH_DB_CONTEXT"],
                    connection,
                    argparse.Namespace(
                        scan_id=scan["scanId"],
                        claim_token=None,
                        draft_path=None,
                        checkpoint_path=None,
                        expected_draft_digest=None,
                    ),
                )
    committed = directory / "artifacts/scan-draft.json"
    committed_bytes = committed.read_bytes()
    if existing_exports:
        assert json.loads(manifest_path.read_text())["scan"]["complete"] is not complete
    protected = {
        name: (directory / name).read_bytes()
        for name in artifact_names
        if (directory / name).exists()
    }
    assert bool(protected) is existing_exports
    if not complete:
        rejected = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"], check=False)
        assert rejected["returncode"] != 0
        assert "latest saved scan draft is incomplete" in rejected["stderr"]
        assert (
            run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["progress"][
                "status"
            ]
            == "running"
        )
        assert {name for name in artifact_names if (directory / name).exists()} == set(protected)
        assert all((directory / name).read_bytes() == value for name, value in protected.items())
    else:
        run_workbench(state, "prepare-scan-completion", "--scan-id", scan["scanId"])
        manifest = json.loads(manifest_path.read_text())["scan"]
        assert manifest["complete"] is True
        assert manifest["sealedAt"]
        assert json.loads((directory / "coverage.json").read_text())["surfaces"][0]["label"] == (
            "Latest committed surface"
        )
        assert committed.read_bytes() == committed_bytes
        # Sealed canonical results take precedence over a stale unsealed snapshot.
        committed.write_text(json.dumps({"manifest": {"scan": {"complete": False}}}))
        sealed = {name: (directory / name).read_bytes() for name in artifact_names}
        completed = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])["scan"]
        assert completed["progress"]["status"] == "complete"
        assert completed["findingCount"] == 1
        assert completed["findings"][0]["summary"] == "Latest committed finding."
        assert all((directory / name).read_bytes() == value for name, value in sealed.items())
    if not complete:
        assert committed.read_bytes() == committed_bytes


def test_deep_completion_keeps_strict_validation_for_committed_findings(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    directory = Path(scan["scanDir"])
    checkpoint(state, scan, terminal="saturated")
    write_completed_contract(
        directory,
        scan["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository",
    )
    documents = {
        key: json.loads((directory / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    del documents["findings"]["findings"][0]["severity"]
    run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        input_text=json.dumps({"documents": documents}),
    )
    result = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"], check=False)
    assert result["returncode"] != 0
    assert "severity" in result["stderr"]
    scan = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert scan["progress"]["status"] == "failed"
    manifest = json.loads((directory / "scan-manifest.json").read_text())["scan"]
    assert manifest["status"] == "failed"


def test_flat_source_materialization_retains_originals_and_accepted_revisions(workbench_api):
    original = {"identity": {"anchor": "first"}, "remediation": "First repair"}
    revision = {"identity": {"anchor": "accepted"}, "remediation": "Second repair"}
    draft = {
        "findings": [{"provenance": {"sourceFindingIds": ["source"], "revisionIds": ["revision"]}}],
        "sourceFindings": {"source": original},
        "revisions": {"revision": revision},
    }
    materialized = workbench_api["saved_results"].materialize_sources(draft)
    assert materialized == {
        "findings": [
            {
                "provenance": {
                    "sourceFindingIds": ["source"],
                    "sourceFindings": [{"id": "source", "finding": original}],
                    "previousFindings": [revision],
                }
            }
        ]
    }
    assert "sourceFindings" in draft


@pytest.mark.parametrize(
    ("resolution_source", "mode", "reopened"),
    [
        ("committed", "deep", False),
        ("canonical", "standard", False),
        ("canonical", "standard", True),
        ("interrupted_export", "standard", True),
    ],
)
def test_cancellation_reconciles_current_surface_resolution_and_late_checkpoint_evidence(
    tmp_path, workbench_api, monkeypatch, resolution_source, mode, reopened
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode=mode)
    directory = Path(scan["scanDir"])
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
    late_findings = documents["findings"]["findings"]
    documents["findings"]["findings"] = []
    documents["manifest"]["scan"]["complete"] = False
    coverage = documents["coverage"]
    coverage["completeness"] = "partial"
    coverage["surfaces"] = [
        {
            "id": "reviewed-surface",
            "label": "Reviewed surface",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
    ]
    coverage["deferred"] = [
        {"id": "resolved-work", "reason": "Review surface", "surfaceIds": ["reviewed-surface"]}
    ]
    pending = coverage["deferred"]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    saved = workbench_api["saved_results"]
    args = argparse.Namespace(
        scan_id=scan["scanId"],
        claim_token=None,
        draft_path=None,
        checkpoint_path=None,
        expected_draft_digest=None,
    )
    with workbench_api["connect"]() as connection:

        def publish():
            payload = {
                "documents": documents,
                "checkpoint": {
                    "scanId": scan["scanId"],
                    "complete": False,
                    "findings": [],
                    "coverage": coverage,
                },
            }
            monkeypatch.setattr(saved.sys, "stdin", io.StringIO(json.dumps(payload)))
            saved.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], connection, args)

        if reopened:
            coverage["surfaces"][0]["disposition"] = "no_issue_found"
            coverage["deferred"] = []
        publish()
        coverage["surfaces"][0]["disposition"] = "needs_follow_up" if reopened else "no_issue_found"
        coverage["deferred"] = pending if reopened else []
        if reopened:
            coverage["surfaces"][0]["notes"] = "Review reopened after another observation."
        if resolution_source == "interrupted_export":
            write = saved.write_scan_local_bytes

            def fail_export(root, relative, contents, **kwargs):
                if relative == "coverage.json":
                    raise OSError("Synthetic export interruption")
                return write(root, relative, contents, **kwargs)

            with monkeypatch.context() as patch:
                patch.setattr(saved, "write_scan_local_bytes", fail_export)
                with pytest.raises(OSError, match="export interruption"):
                    publish()
            manifest = json.loads((directory / "scan-manifest.json").read_text())
            assert manifest["scan"]["completedAt"] != documents["manifest"]["scan"]["completedAt"]
        elif resolution_source == "canonical":
            (directory / "coverage.json").write_text(json.dumps(coverage))
        else:
            publish()
    committed = (directory / "artifacts/scan-draft.json").read_bytes()
    late_coverage = {
        **coverage,
        "surfaces": [
            {
                "id": "pending-surface",
                "label": "Unrelated pending surface",
                "disposition": "needs_follow_up",
                "receiptRefs": [],
            }
        ],
        "deferred": [
            {"id": "pending-work", "reason": "Unrelated review", "surfaceIds": ["pending-surface"]},
            {
                "id": "new-candidate",
                "reason": "New evidence on the reviewed surface",
                "surfaceIds": ["reviewed-surface"],
                "candidate": {"summary": "Later candidate evidence"},
            },
        ],
    }
    late_checkpoint = write_checkpoint(
        directory / "checkpoints",
        {
            "scanId": scan["scanId"],
            "complete": False,
            "findings": late_findings,
            "coverage": late_coverage,
        },
    )
    late_bytes = late_checkpoint.read_bytes()
    (directory / "checkpoints/pending" / late_checkpoint.name).write_bytes(late_bytes)
    run_workbench(state, "cancel-scan", "--scan-id", scan["scanId"])
    published = json.loads((directory / "coverage.json").read_text())
    assert published["surfaces"] == coverage["surfaces"] + late_coverage["surfaces"]
    expected_deferred = {"pending-work", "new-candidate", "scan-stopped"}
    if reopened:
        expected_deferred.add("resolved-work")
        assert "Review reopened after another observation." in (directory / "report.md").read_text()
    assert {row["id"] for row in published["deferred"]} == expected_deferred
    assert late_coverage["deferred"][1] in published["deferred"]
    findings = json.loads((directory / "findings.json").read_text())["findings"]
    assert [finding["title"] for finding in findings] == [late_findings[0]["title"]]
    assert findings[0]["codeEvidence"] == late_findings[0]["codeEvidence"]
    assert (directory / "artifacts/scan-draft.json").read_bytes() == committed
    assert late_checkpoint.read_bytes() == late_bytes
    manifest = json.loads((directory / "scan-manifest.json").read_text())["scan"]
    assert f"checkpoints/{late_checkpoint.name}" in manifest["preservedSources"]


@pytest.mark.parametrize(
    ("command", "resolution", "complete"),
    [
        ("fail-scan", "reported", False),
        ("cancel-scan", "reported", False),
        ("fail-scan", "committed_rejection", False),
        ("cancel-scan", "committed_rejection", False),
        ("cancel-scan", "reported", True),
        ("fail-scan", "committed_rejection", None),
        ("cancel-scan", "invalid", False),
        ("cancel-scan", "stale", False),
        ("cancel-scan", "rejected", False),
        ("fail-scan", "not_applicable", False),
        ("cancel-scan", "invalid_rejection", False),
        ("cancel-scan", "reported_after_rejection", False),
        ("fail-scan", "rejected_after_report", False),
        ("cancel-scan", "invalid_after_rejection", False),
        ("cancel-scan", "stale_after_rejection", False),
    ],
)
def test_stopped_scan_retains_canonical_results_written_after_committed_draft(
    tmp_path,
    workbench_api,
    monkeypatch,
    command,
    resolution,
    complete,
    timestamp="unchanged",
    interrupted_at="findings.json",
    legacy_export=False,
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan")
    directory = Path(scan["scanDir"])
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((directory / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    rejected = resolution == "committed_rejection" or resolution.endswith("after_rejection")
    current_rejection = resolution in {
        "rejected",
        "not_applicable",
        "invalid_rejection",
        "rejected_after_report",
    }
    documents["findings"]["findings"][0]["provenance"]["candidateId"] = "candidate"
    original = json.loads(json.dumps(documents["findings"]["findings"][0]))
    original["remediation"] = "Original repair evidence."
    candidate = {"summary": "Original candidate evidence."}
    if resolution in {"invalid", "invalid_after_rejection"}:
        documents["findings"]["findings"][0].pop("title")
    if current_rejection:
        documents["findings"]["findings"] = []
    later_findings = json.dumps(documents["findings"])
    documents["coverage"]["completeness"] = "partial"
    documents["coverage"]["surfaces"][0].update(
        {"candidateId": "candidate", "disposition": "rejected" if rejected else "needs_follow_up"}
    )
    if rejected:
        documents["coverage"]["surfaces"][0].update({"candidate": candidate, "finding": original})
    if complete is True:
        documents["coverage"]["surfaces"][0].pop("candidateId")
    if not rejected:
        documents["coverage"]["deferred"] = [
            {
                "id": "pending-candidate",
                "candidateId": "candidate",
                "reason": "Candidate needs validation.",
                "candidate": candidate,
                "finding": original,
            },
            {
                "id": "pending-surface-review",
                "reason": "Surface needs validation.",
                "surfaceIds": [documents["coverage"]["surfaces"][0]["id"]],
            },
        ]
    documents["findings"]["findings"] = []
    if resolution == "rejected_after_report":
        documents["findings"]["findings"] = [original]
        documents["coverage"]["surfaces"][0]["disposition"] = "reported"
        documents["coverage"]["deferred"] = []
    if complete is None:
        documents["manifest"]["scan"].pop("complete", None)
    else:
        documents["manifest"]["scan"]["complete"] = complete
    historical = json.loads(json.dumps(documents["coverage"]))
    historical["deferred"] = [{"id": "older-work", "reason": "Earlier deferred review."}]
    write_checkpoint(
        directory / "checkpoints",
        {"scanId": scan["scanId"], "complete": False, "findings": [], "coverage": historical},
    )
    run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        input_text=json.dumps({"documents": documents}),
    )
    committed = (directory / "artifacts/scan-draft.json").read_bytes()
    (directory / "findings.json").write_text(later_findings)
    later_coverage = json.loads((directory / "coverage.json").read_text())
    later_coverage["completeness"] = "partial"
    if resolution != "committed_rejection":
        later_coverage["surfaces"][0]["candidateId"] = "candidate"
        later_coverage["surfaces"][0]["disposition"] = (
            "not_applicable"
            if resolution == "not_applicable"
            else "rejected"
            if current_rejection
            else "reported"
        )
        if rejected:
            later_coverage["surfaces"][0].pop("candidate", None)
            later_coverage["surfaces"][0].pop("finding", None)
        if resolution == "invalid_rejection":
            later_coverage["surfaces"][0].pop("label")
        later_coverage["deferred"] = []
    later_coverage["surfaces"].append(
        {
            "id": "later-surface",
            "label": "Newly observed surface",
            "candidateId": "later-candidate",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        }
    )
    later_coverage["deferred"].append(
        {"id": "later-work", "candidateId": "later-candidate", "reason": "New deferred review."}
    )
    if resolution == "committed_rejection":
        later_coverage["deferred"].append(
            {"id": "resolved-work", "candidateId": "candidate", "reason": "Already rejected."}
        )
    later_coverage["openQuestions"] = [{"question": "Which control governs the new surface?"}]
    (directory / "coverage.json").write_text(json.dumps(later_coverage))
    manifest_path = directory / "scan-manifest.json"
    later_manifest = json.loads(manifest_path.read_text())
    if timestamp == "changed":
        later_manifest["scan"]["completedAt"] = "2030-01-01T00:00:00Z"
    elif timestamp == "omitted":
        later_manifest["scan"].pop("completedAt", None)
    if timestamp != "unchanged":
        manifest_path.write_text(json.dumps(later_manifest))
    if resolution in {"stale", "stale_after_rejection"}:
        # A later commit may leave a mixture of old and current exports.
        monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
        saved = workbench_api["saved_results"]
        write = saved.write_scan_local_bytes

        def fail_export(root, relative, contents, **kwargs):
            if relative == interrupted_at:
                raise OSError("Synthetic export interruption")
            return write(root, relative, contents, **kwargs)

        with monkeypatch.context() as patch, workbench_api["connect"]() as connection:
            patch.setattr(saved, "write_scan_local_bytes", fail_export)
            patch.setattr(saved.sys, "stdin", io.StringIO(json.dumps({"documents": documents})))
            with pytest.raises(OSError, match="export interruption"):
                saved.write_scan_draft(
                    workbench_api["_WORKBENCH_DB_CONTEXT"],
                    connection,
                    argparse.Namespace(
                        scan_id=scan["scanId"],
                        claim_token=None,
                        draft_path=None,
                        checkpoint_path=None,
                        expected_draft_digest=None,
                    ),
                )
        committed = (directory / "artifacts/scan-draft.json").read_bytes()
    if legacy_export:
        legacy = json.loads(committed)
        legacy.pop("canonicalExport")
        committed = json.dumps(legacy).encode()
        (directory / "artifacts/scan-draft.json").write_bytes(committed)
    run_workbench(
        state,
        command,
        "--scan-id",
        scan["scanId"],
        *(["--message", "Synthetic interruption"] if command == "fail-scan" else []),
    )
    published = json.loads((directory / "findings.json").read_text())["findings"]
    if resolution in {"stale", "stale_after_rejection"}:
        assert published == []
        assert (directory / "artifacts/scan-draft.json").read_bytes() == committed
        coverage = json.loads((directory / "coverage.json").read_text())
        assert "later-work" not in {item["id"] for item in coverage["deferred"]}
        return
    retained_rejection = resolution in {
        "committed_rejection",
        "invalid_after_rejection",
        "stale_after_rejection",
    }
    assert [finding["title"] for finding in published] == (
        []
        if retained_rejection or current_rejection or resolution == "invalid"
        else [original["title"]]
    )
    manifest = json.loads((directory / "scan-manifest.json").read_text())
    assert any(
        json.loads((directory / source).read_text())["findings"]
        == json.loads(later_findings)["findings"]
        for source in manifest["scan"]["preservedSources"]
    )
    assert (directory / "artifacts/scan-draft.json").read_bytes() == committed

    coverage = json.loads((directory / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    assert later_coverage["surfaces"][-1] in coverage["surfaces"]
    assert later_coverage["openQuestions"][0] in coverage["openQuestions"]
    deferred_ids = {item["id"] for item in coverage["deferred"]}
    assert "later-work" in deferred_ids
    assert "resolved-work" not in deferred_ids
    unresolved = resolution in {"invalid", "stale", "invalid_rejection"}
    assert ("pending-candidate" in deferred_ids) is unresolved
    assert ("pending-surface-review" in deferred_ids) is unresolved
    assert (
        any(
            row.get("candidateId") == "candidate" and row["disposition"] == "needs_follow_up"
            for row in coverage["surfaces"]
        )
        is unresolved
    )
    if resolution in {"reported", "reported_after_rejection"}:
        assert published[0]["provenance"]["originalCandidates"] == [candidate]
        assert original in published[0]["provenance"]["previousFindings"]
    elif current_rejection and not unresolved:
        rejected_surface = next(
            row for row in coverage["surfaces"] if row.get("candidateId") == "candidate"
        )
        assert rejected_surface["disposition"] == (
            "not_applicable" if resolution == "not_applicable" else "rejected"
        )
        if resolution == "rejected_after_report":
            assert original in rejected_surface["previousFindings"]
        else:
            assert rejected_surface["candidate"] == candidate
            assert rejected_surface["finding"] == original
    if resolution.endswith("after_rejection") or resolution == "rejected_after_report":
        assert [
            row["disposition"]
            for row in coverage["surfaces"]
            if row.get("candidateId") == "candidate"
        ] == ["reported" if resolution == "reported_after_rejection" else "rejected"]
    assert ("older-work" in deferred_ids) is (complete is False)
    report = (directory / "report.md").read_text()
    assert "New deferred review." in report
    assert "Which control governs the new surface?" in report
    assert ("Candidate needs validation." in report) is unresolved


@pytest.mark.parametrize(
    ("canonical_time", "pending_time", "expected", "retry"),
    [
        (300, None, "canonical", None),
        (100, None, "committed", None),
        (300, 400, "pending", None),
        (300, 100, "canonical", None),
        (300, None, "canonical", "publication"),
        (300, 400, "pending", "publication"),
        (300, None, "committed", "frozen-model"),
    ],
)
def test_stopped_scan_preserves_newest_model_and_frozen_retry_selection(
    tmp_path, workbench_api, monkeypatch, canonical_time, pending_time, expected, retry
):
    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    scan = register(state, target, tmp_path / "scan")
    directory = Path(scan["scanDir"])
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    filenames = {
        "manifest": "scan-manifest.json",
        "findings": "findings.json",
        "coverage": "coverage.json",
    }
    documents = {
        key: json.loads((directory / filename).read_text()) for key, filename in filenames.items()
    }
    models = {
        name: {"summary": f"The {name} threat model."}
        for name in ("committed", "canonical", "pending")
    }
    documents["manifest"]["scan"].update(threatModel=models["committed"], complete=False)
    run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        input_text=json.dumps({"documents": documents}),
    )
    committed = directory / "artifacts/scan-draft.json"
    committed_bytes = committed.read_bytes()
    os.utime(committed, ns=(200, 200))
    for filename in filenames.values():
        os.utime(directory / filename, ns=(100, 100))
    manifest_path = directory / "scan-manifest.json"
    canonical = json.loads(manifest_path.read_text())
    canonical["scan"]["threatModel"] = models["canonical"]
    manifest_path.write_text(json.dumps(canonical))
    os.utime(manifest_path, ns=(canonical_time, canonical_time))
    if pending_time is not None:
        pending = write_checkpoint(
            directory / "checkpoints/pending",
            {
                "scanId": scan["scanId"],
                "complete": False,
                "findings": [],
                "coverage": documents["coverage"],
                "threatModel": models["pending"],
            },
        )
        os.utime(pending, ns=(pending_time, pending_time))

    if retry is None:
        run_workbench(
            state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic interruption"
        )
    else:
        monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
        saved = workbench_api["saved_results"]

        def fail_publication(*args, **kwargs):
            raise OSError("Synthetic publication interruption")

        with monkeypatch.context() as patch, workbench_api["connect"]() as connection:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
            saved.fail_scan(
                workbench_api["_WORKBENCH_DB_CONTEXT"],
                connection,
                argparse.Namespace(
                    scan_id=scan["scanId"],
                    claim_token=None,
                    cost_json=None,
                    message="Synthetic interruption",
                ),
            )
            row = workbench_api["require_scan"](connection, scan["scanId"])
            assert row["seal_manifest_digest"] is None
            sources = json.loads(row["retained_source_digests_json"])
            if retry == "frozen-model":
                selected = next(
                    relative
                    for relative in sources
                    if json.loads((directory / relative).read_text()).get("threatModel")
                    == models["committed"]
                )
                with connection:
                    connection.execute(
                        "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
                        (
                            json.dumps({"sources": sources, "threatModelSource": selected}),
                            scan["scanId"],
                        ),
                    )
        # Retries use the captured order even if later writes reverse file timestamps.
        for relative in sources:
            path = directory / relative
            model = json.loads(path.read_text()).get("threatModel")
            modified = 900 if model == models["committed"] else 1
            os.utime(path, ns=(modified, modified))
        canonical["scan"]["threatModel"] = {"summary": "Unaccepted later model."}
        manifest_path.write_text(json.dumps(canonical))
        run_workbench(state, "preserve-scan-results", "--scan-id", scan["scanId"])

    published = json.loads(manifest_path.read_text())["scan"]
    assert published["sealedAt"]
    assert published["threatModel"] == models[expected]
    threat_model = (directory / "threatmodel.md").read_text()
    assert models[expected]["summary"] in threat_model
    assert f"Snapshot: {published['target']['snapshotDigest']}" in threat_model
    assert committed.read_bytes() == committed_bytes
    sealed = manifest_path.read_bytes()
    run_workbench(state, "preserve-scan-results", "--scan-id", scan["scanId"])
    assert manifest_path.read_bytes() == sealed


@pytest.mark.parametrize("command", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("timestamp", ["changed", "omitted"])
def test_stopped_scan_retains_authored_results_with_new_completion_timestamp(
    tmp_path, workbench_api, monkeypatch, command, timestamp
):
    test_stopped_scan_retains_canonical_results_written_after_committed_draft(
        tmp_path, workbench_api, monkeypatch, command, "reported", False, timestamp=timestamp
    )


@pytest.mark.parametrize("command", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("interrupted_at", ["findings.json", "coverage.json", "scan-manifest.json"])
def test_stopped_scan_does_not_reopen_committed_rejection_after_interrupted_export(
    tmp_path, workbench_api, monkeypatch, command, interrupted_at
):
    test_stopped_scan_retains_canonical_results_written_after_committed_draft(
        tmp_path,
        workbench_api,
        monkeypatch,
        command,
        "stale_after_rejection",
        False,
        interrupted_at=interrupted_at,
    )


@pytest.mark.parametrize("resolution", ["reported", "stale_after_rejection"])
def test_stopped_scan_preserves_legacy_export_selection(
    tmp_path, workbench_api, monkeypatch, resolution
):
    test_stopped_scan_retains_canonical_results_written_after_committed_draft(
        tmp_path,
        workbench_api,
        monkeypatch,
        "cancel-scan",
        resolution,
        False,
        legacy_export=True,
    )


@pytest.mark.parametrize("distinct_instances", [False, True])
def test_checkpoint_recovery_retains_refinement_and_distinct_instances(
    tmp_path, distinct_instances
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan")
    directory = Path(scan["scanDir"])
    write_completed_contract(directory, scan["scanId"], target, relative_path="app.py")
    findings = json.loads((directory / "findings.json").read_text())["findings"]
    original = json.loads(json.dumps(findings[0]))
    if distinct_instances:
        findings[0]["identity"]["instance"] = "first"
        original["identity"]["instance"] = "second"
        findings.append(original)
    else:
        findings[0]["locations"][0]["startLine"] = 24
        findings[0]["provenance"]["previousFindings"] = [original]
    write_checkpoint(
        directory / "checkpoints",
        {
            "scanId": scan["scanId"],
            "complete": False,
            "findings": findings,
            "coverage": json.loads((directory / "coverage.json").read_text()),
        },
    )
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (directory / name).unlink()
    saved = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop"
    )["scan"]
    actual = json.loads((directory / "findings.json").read_text())["findings"]
    assert saved["findingCount"] == len(actual) == (2 if distinct_instances else 1)
    if distinct_instances:
        assert {finding["identity"]["instance"] for finding in actual} == {"first", "second"}
    else:
        assert actual[0]["provenance"]["previousFindings"] == [original]


def test_current_aggregate_hydrates_immutable_sources_only_when_requested(
    tmp_path, workbench_api, monkeypatch
):
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    directory = Path(scan["scanDir"])
    source = {"identity": {"anchor": "original"}, "remediation": "Original repair"}
    source_id = "synthetic-child:0"
    revision = {"identity": {"anchor": "accepted"}}
    revision_id = hashlib.sha256(json.dumps(revision).encode()).hexdigest()
    documents = {
        f"sources/{hashlib.sha256(source_id.encode()).hexdigest()}": source,
        f"revisions/{revision_id}": revision,
        "aggregates/current": {
            "findings": [],
            "sourceFindingIds": [source_id],
            "revisionIds": [revision_id],
        },
        "checkpoint": {
            "version": 3,
            "aggregatePath": "artifacts/deep-scan/aggregates/current.json",
        },
    }
    for relative, document in documents.items():
        path = directory / f"artifacts/deep-scan/{relative}.json"
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(json.dumps(document))
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    row = {"id": scan["scanId"], "scan_dir": str(directory)}
    read = workbench_api["load_composition"].__globals__["read_composition_checkpoint"]
    assert read(row)["aggregate"] == {
        "findings": [],
        "sourceFindings": {source_id: source},
        "revisions": {revision_id: revision},
    }
    assert "aggregate" not in read(row, load_aggregate=False)


def test_old_live_checkpoint_is_readable_but_cannot_resume(tmp_path, workbench_api, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    checkpoint = Path(scan["scanDir"]) / "artifacts/deep-scan/checkpoint.json"
    checkpoint.parent.mkdir(parents=True, mode=0o700)
    contents = json.dumps({"version": 2, "passes": [], "mergedScanIds": [], "aggregate": None})
    checkpoint.write_text(contents)
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    read = workbench_api["load_composition"].__globals__["read_composition_checkpoint"]
    assert (
        read({"id": scan["scanId"], "scan_dir": scan["scanDir"]}, load_aggregate=False)["version"]
        == 2
    )
    assert "compositionCheckpoint" not in run_workbench(
        state, "get-scan", "--scan-id", scan["scanId"]
    )
    result = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"], check=False)
    assert result["returncode"] != 0
    assert "original version" in result["stderr"]
    assert checkpoint.read_text() == contents


@pytest.mark.parametrize("sealed", [False, True])
def test_old_checkpoint_completion_requires_sealed_results(
    tmp_path, workbench_api, monkeypatch, sealed
):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode="deep")
    directory = Path(scan["scanDir"])
    write_completed_contract(
        directory, scan["scanId"], target, relative_path="app.py", coverage_mode="deep_repository"
    )
    manifest_path = directory / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["artifacts"] = []
    manifest_path.write_text(json.dumps(manifest))
    checkpoint = directory / "artifacts/deep-scan/checkpoint.json"
    checkpoint.parent.mkdir(parents=True, mode=0o700)
    checkpoint.write_text(
        json.dumps(
            {
                "version": 2,
                "passes": [],
                "mergedScanIds": [],
                "terminalReason": "capped",
                "aggregate": None,
            }
        )
    )
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with workbench_api["connect"]() as connection:
        row = workbench_api["require_scan"](connection, scan["scanId"])
        connection.execute(
            "UPDATE scans SET deep_scan_owner_thread_id = 'native-owner' WHERE id = ?",
            (scan["scanId"],),
        )
        original_recipe = json.loads(row["recipe_json"])
        if sealed:
            # Recreate the old publisher stopping after sealing, before SQLite completion.
            binding = workbench_api["workbench_completion_binding"](row, row["started_at"])
            binding["producer"]["version"] = "historical-fixture"
            workbench_api["finalize_scan"](directory, completion_binding=binding)
        else:
            saved_recipe = {**json.loads(row["recipe_json"]), "maxCostUsd": 0.001}
            connection.execute(
                "UPDATE scans SET recipe_json = ? WHERE id = ?",
                (json.dumps(saved_recipe), scan["scanId"]),
            )
    protected = {
        name: (directory / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json")
    }
    checkpoint_bytes = checkpoint.read_bytes()
    for arguments, payload in (
        (
            ("begin-deep-scan", "--scan-id", scan["scanId"], "--thread-id", "native-owner"),
            None,
        ),
        (
            (
                "register-cli-scan",
                "--repository",
                str(target),
                "--scan-dir",
                str(directory),
                "--registration-json-stdin",
            ),
            json.dumps(
                {"scanId": scan["scanId"], "threadId": "native-owner", "recipe": original_recipe}
            ),
        ),
    ):
        if sealed:
            coverage_path = directory / "coverage.json"
            coverage_path.write_bytes(protected["coverage.json"] + b"\n")
            rejected = run_workbench(state, *arguments, input_text=payload, check=False)
            assert rejected["returncode"] != 0
            assert "Cannot resume sealed scan" in rejected["stderr"]
            coverage_path.write_bytes(protected["coverage.json"])
        result = run_workbench(state, *arguments, input_text=payload, check=False)
        if sealed:
            assert result["returncode"] == 0, result["stderr"]
        else:
            assert result["returncode"] != 0
            assert "original version" in result["stderr"]
    if sealed:
        resumed = run_workbench(state, "get-cli-scan-resume", "--scan-id", scan["scanId"])
        assert resumed["sealedProducerVersion"] == "historical-fixture"
        result = run_workbench(state, "complete-scan", "--scan-id", scan["scanId"], check=False)
        assert result["returncode"] == 0, result["stderr"]
        completed = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
        assert completed["progress"]["status"] == "complete"
        assert completed["findingCount"] == 1
    else:
        cost = {
            "model": "synthetic-model",
            "inputTokens": 10,
            "cachedInputTokens": 0,
            "cacheWriteInputTokens": 0,
            "outputTokens": 5,
            "estimatedUsd": 0.002,
        }
        for command in ("complete-scan", "complete-budget-exhausted-scan"):
            rejected = run_workbench(
                state,
                command,
                "--scan-id",
                scan["scanId"],
                "--cost-json",
                json.dumps(cost),
                check=False,
            )
            assert rejected["returncode"] != 0
            assert "original version" in rejected["stderr"]
        assert (
            run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["progress"][
                "status"
            ]
            == "running"
        )
    assert checkpoint.read_bytes() == checkpoint_bytes
    assert all((directory / name).read_bytes() == contents for name, contents in protected.items())
