from __future__ import annotations

import copy
import hashlib
import json
import uuid
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import (
    composition_payload,
    register,
    run_workbench,
    write_completed_contract,
)


def select_checkpoint(directory: Path, checkpoint: Path) -> None:
    """Publish a proposed semantic snapshot without altering a stopped scan's seal."""
    draft = json.loads(checkpoint.read_text())
    manifest_path = directory / "scan-manifest.json"
    manifest = (
        json.loads(manifest_path.read_text())
        if manifest_path.exists()
        else {"scan": {"id": draft["scanId"]}}
    )
    scan = manifest["scan"]
    for key in ("sealedAt", "artifacts", "preservedSources"):
        scan.pop(key, None)
    for key in ("complete", "threatModel", "scope"):
        if key in draft:
            scan[key] = copy.deepcopy(draft[key])
    document = {
        "manifest": manifest,
        "findings": {"scanId": draft["scanId"], "findings": draft["findings"]},
        "coverage": draft["coverage"],
        "reconciledCheckpointIds": [checkpoint.name],
    }
    committed = directory / "artifacts/scan-draft.json"
    committed.parent.mkdir(parents=True, exist_ok=True)
    committed.write_text(json.dumps(document))


@pytest.mark.parametrize("field", ["id", "candidateId"])
@pytest.mark.parametrize("invalid_id", [["review"], {"task": "review"}], ids=["list", "object"])
def test_stopped_scan_recovers_checkpoint_with_non_string_coverage_id(
    tmp_path: Path, invalid_id: object, field: str
) -> None:
    from workbench_test_support import saved_draft, write_checkpoint

    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan["scanId"], target, relative_path="app.py")
    findings = json.loads((contract_dir / "findings.json").read_text())["findings"]
    valid_work = {"id": "valid-review", "reason": "Other review remains."}
    malformed_work = {"id": "malformed-review", "reason": "Review remains.", field: invalid_id}
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints",
        saved_draft(scan["scanId"], findings=findings, deferred=[valid_work, malformed_work]),
    )
    checkpoint_bytes = checkpoint.read_bytes()

    stopped = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic interruption"
    )["scan"]

    assert stopped["progress"]["status"] == "failed"
    assert stopped["findingCount"] == 1
    assert stopped["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert valid_work in coverage["deferred"]
    if field == "id":
        assert any(
            "Skipped malformed deferred coverage item" in warning for warning in stopped["warnings"]
        )
        assert malformed_work not in coverage["deferred"]
    else:
        # A string task ID still identifies generic work without a usable candidate ID.
        assert malformed_work in coverage["deferred"]
    assert checkpoint.read_bytes() == checkpoint_bytes
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize("instance", ["saved", "null"])
def test_stopped_parent_retains_absent_and_explicit_child_instances(
    tmp_path: Path, action: str, instance: str
) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    findings = json.loads((child_dir / "findings.json").read_text())
    sibling = copy.deepcopy(findings["findings"][0])
    sibling["identity"]["instance"] = instance
    sibling["title"] = "Distinct synthetic instance"
    findings["findings"].append(sibling)
    (child_dir / "findings.json").write_text(json.dumps(findings))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    original = (child_dir / "findings.json").read_bytes()
    assert len(json.loads(original)["findings"]) == 2
    run_workbench(
        state,
        action,
        "--scan-id",
        parent["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
    assert len(retained) == 2
    assert len({row["findingId"] for row in retained}) == 2
    assert {row["provenance"]["sourceFindings"][0]["finding"]["title"] for row in retained} == {
        row["title"] for row in json.loads(original)["findings"]
    }
    assert (child_dir / "findings.json").read_bytes() == original


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize("saved_checkpoint", [False, True])
def test_stopped_parent_preserves_work_with_malformed_child_manifest(
    tmp_path: Path, action: str, saved_checkpoint: bool
) -> None:
    from workbench_test_support import saved_draft, write_checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    write_completed_contract(parent_dir, parent["scanId"], target, relative_path="app.py")
    expected = {"Synthetic accepted parent finding", "Synthetic completed child finding"}
    parent_findings = json.loads((parent_dir / "findings.json").read_text())
    parent_findings["findings"][0]["title"] = "Synthetic accepted parent finding"
    (parent_dir / "findings.json").write_text(json.dumps(parent_findings))
    children = []
    for index in range(2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index + 1}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        write_completed_contract(directory, child["scanId"], target, relative_path="app.py")
        findings = json.loads((directory / "findings.json").read_text())
        findings["findings"][0]["title"] = (
            "Synthetic completed child finding" if index == 0 else "Synthetic checkpoint finding"
        )
        (directory / "findings.json").write_text(json.dumps(findings))
        if index == 0:
            run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        else:
            if saved_checkpoint:
                write_checkpoint(
                    directory / "checkpoints",
                    saved_draft(child["scanId"], complete=True, findings=findings["findings"]),
                )
                expected.add("Synthetic checkpoint finding")
            (directory / "scan-manifest.json").write_text(json.dumps({"scan": None}))
        children.append(directory)
    original = {path: path.read_bytes() for path in children[0].rglob("*.json")}
    for path in (children[1] / "checkpoints").glob("*.json"):
        original[path] = path.read_bytes()
    if not saved_checkpoint:
        manifest = children[1] / "scan-manifest.json"
        original[manifest] = manifest.read_bytes()
    run_workbench(
        state,
        action,
        "--scan-id",
        parent["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert stopped["progress"]["status"] == ("canceled" if action == "cancel-scan" else "failed")
    assert stopped["reportAvailable"] is True
    findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
    assert {finding["title"] for finding in findings} == expected
    coverage = json.loads((parent_dir / "coverage.json").read_text())
    assert coverage["completeness"] == "partial"
    for path, contents in original.items():
        assert path.read_bytes() == contents


def test_draft_without_raw_checkpoint_survives_projection_publication_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        (scan_dir / name).unlink()
    (scan_dir / "checkpoints/pending").mkdir(parents=True)
    (scan_dir / "drafts").mkdir()
    stage = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    stage.write_text(json.dumps(documents))
    args = SimpleNamespace(
        scan_id=scan["scanId"],
        claim_token=None,
        draft_path=str(stage),
        checkpoint_path=None,
        expected_draft_digest=None,
    )
    original_write = results.write_scan_local_bytes

    def interrupt_head(directory, relative, contents):
        if relative == "findings.json":
            raise OSError("Synthetic head publication failure")
        return original_write(directory, relative, contents)

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "write_scan_local_bytes", interrupt_head)
        with pytest.raises(OSError, match="Synthetic head publication failure"):
            results.write_scan_draft(db._WORKBENCH_DB_CONTEXT, connection, args)
    assert (scan_dir / "artifacts/scan-draft.json").exists()
    run_workbench(state, "cancel-scan", "--scan-id", scan["scanId"])
    recovered = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert [row["title"] for row in recovered] == [
        row["title"] for row in documents["findings"]["findings"]
    ]


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize("accepted_model", [False, True])
def test_stopped_parent_recovers_child_model_without_replacing_accepted_model(
    tmp_path: Path, action: str, accepted_model: bool
) -> None:
    from workbench_test_support import checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    manifest_path = child_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    child_model = {"format": "markdown", "content": "# Saved child model\n"}
    manifest["scan"]["threatModel"] = child_model
    manifest_path.write_text(json.dumps(manifest))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    original = manifest_path.read_bytes()
    expected_model = {**child_model, "origin": "recovered"}
    if accepted_model:
        saved = checkpoint(state, parent)
        expected_model = {"format": "markdown", "content": "# Accepted parent model\n"}
        saved["aggregate"] = {"findings": [], "coverage": {}, "threatModel": expected_model}
        run_workbench(
            state,
            "save-scan-artifact",
            "--scan-id",
            parent["scanId"],
            "--artifact-path",
            "artifacts/deep-scan/checkpoint.json",
            input_text=composition_payload(parent_dir, saved),
        )
    run_workbench(
        state,
        action,
        "--scan-id",
        parent["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    retained = json.loads((parent_dir / "scan-manifest.json").read_text())["scan"]
    assert retained["threatModel"] == expected_model
    assert (parent_dir / "threatmodel.md").read_text().startswith(expected_model["content"])
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert stopped["threatModelAvailable"] is True
    assert stopped["threatModelProvenance"]["provisional"] is True
    assert manifest_path.read_bytes() == original


def test_preserve_retry_keeps_child_recovery_warning_until_child_is_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    original = (child_dir / "findings.json").read_bytes()

    def unreadable_child(*args, **kwargs):
        raise OSError("Synthetic child read failure")

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "_stopped_child_draft", unreadable_child)
        results.fail_scan(
            db._WORKBENCH_DB_CONTEXT,
            connection,
            SimpleNamespace(
                scan_id=parent["scanId"],
                claim_token=None,
                cost_json=None,
                message="Synthetic interruption",
            ),
        )
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert stopped["findingCount"] == 0
    assert any("Synthetic child read failure" in warning for warning in stopped["warnings"])
    for _ in range(2):
        preserved = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert preserved["findingCount"] == 0
        assert preserved["warnings"] == stopped["warnings"]
        assert preserved["resultsRecoveryNeeded"] is True
    recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert recovered["findingCount"] == 1
    assert not any("Synthetic child read failure" in warning for warning in recovered["warnings"])
    assert recovered["resultsRecoveryNeeded"] is False
    assert (child_dir / "findings.json").read_bytes() == original


@pytest.mark.parametrize("initial_evidence", [False, True])
def test_explicit_recovery_reads_child_evidence_saved_after_parent_publication(
    tmp_path: Path,
    initial_evidence: bool,
) -> None:
    from workbench_test_support import checkpoint, saved_draft, write_checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    write_completed_contract(parent_dir, parent["scanId"], target, relative_path="app.py")
    findings_path = parent_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"][0]["title"] = "Synthetic accepted parent finding"
    findings_path.write_text(json.dumps(findings))
    late_finding = copy.deepcopy(findings["findings"][0])
    late_finding["title"] = "Synthetic late child finding"
    late_finding["identity"]["anchor"] = "late-child-finding"
    late_finding["severity"] = {"level": "high"}
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    saved = checkpoint(state, parent)
    if initial_evidence:
        initial = copy.deepcopy(late_finding)
        initial["severity"] = {"level": "low"}
        write_checkpoint(
            child_dir / "checkpoints",
            saved_draft(child["scanId"], complete=True, findings=[initial]),
        )
    run_workbench(
        state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic interruption"
    )
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption"
    )["scan"]
    assert stopped["findingCount"] == (2 if initial_evidence else 1)
    assert stopped["resultsRecoveryNeeded"] is False
    assert stopped["warnings"] == []
    original = {path: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    child_checkpoint = write_checkpoint(
        child_dir / "checkpoints",
        saved_draft(child["scanId"], complete=True, findings=[late_finding]),
    )
    original[child_checkpoint] = child_checkpoint.read_bytes()
    if not initial_evidence:
        unsealed = {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in parent_dir.rglob("*.json")
        }
        current = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
        assert current["resultsRecoveryNeeded"] is True
        assert unsealed == {
            path: (path.read_bytes(), path.stat().st_mtime_ns)
            for path in parent_dir.rglob("*.json")
        }
    recovered_child = run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])[
        "scan"
    ]
    assert recovered_child["findingCount"] == 1
    original.update({path: path.read_bytes() for path in child_dir.glob("*.json")})
    saved["mergedScanIds"] = [child["scanId"]]
    saved["aggregate"] = {"findings": [], "coverage": {}}
    (parent_dir / "artifacts/deep-scan/checkpoint.json").write_text(
        composition_payload(parent_dir, saved)
    )
    files = {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in parent_dir.rglob("*.json")
    }
    current = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert current["resultsRecoveryNeeded"] is True
    assert files == {
        path: (path.read_bytes(), path.stat().st_mtime_ns) for path in parent_dir.rglob("*.json")
    }
    for _ in range(2):
        preserved = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert preserved["findingCount"] == (2 if initial_evidence else 1)
        assert preserved["resultsRecoveryNeeded"] is True
        assert preserved["warnings"] == []
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["findingCount"] == 2
        assert recovered["resultsRecoveryNeeded"] is False
        retained = json.loads(findings_path.read_text())["findings"]
        assert {row["title"] for row in retained} == {
            "Synthetic accepted parent finding",
            "Synthetic late child finding",
        }
        updated = next(row for row in retained if row["title"] == "Synthetic late child finding")
        assert updated["severity"]["level"] == "high"
        assert "Synthetic late child finding" in (parent_dir / "report.md").read_text()
        assert recovered["warnings"] == []
        for path, contents in original.items():
            assert path.read_bytes() == contents


@pytest.mark.parametrize("change", ["surface", "closure"])
@pytest.mark.parametrize("publication_failure", [False, True])
def test_parent_recovery_reconciles_updated_child_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, publication_failure: bool
) -> None:
    from workbench_test_support import checkpoint, saved_draft, write_checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    surface = {
        "id": "shared-surface",
        "label": "Synthetic reviewed surface",
        "candidateId": "shared-candidate",
        "disposition": "rejected",
    }
    task = {"id": "shared-task", "reason": "Independent synthetic review."}
    questions = [
        "Synthetic parent question.",
        {
            "question": "Synthetic object question.",
            "followUpPrompt": "Check the synthetic boundary.",
        },
    ]
    expected_questions = [
        {"question": questions[0]},
        questions[1],
        {"question": "Synthetic child 1 question."},
        {"question": "Synthetic child 2 question."},
    ]
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        draft = saved_draft(child["scanId"], complete=True, surfaces=[surface], deferred=[task])
        draft["coverage"]["inventoryStrategy"] = "repository"
        draft["coverage"]["openQuestions"] = [f"Synthetic child {index} question."]
        original = write_checkpoint(directory / "checkpoints", draft)
        select_checkpoint(directory, original)
        run_workbench(
            state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic interruption"
        )
        children.append((child, directory, draft))
    saved = checkpoint(state, parent)
    saved["aggregate"] = saved_draft(parent["scanId"], surfaces=[surface], deferred=[task])
    saved["aggregate"]["coverage"]["openQuestions"] = questions
    (parent_dir / "artifacts/deep-scan/checkpoint.json").write_text(
        composition_payload(parent_dir, saved)
    )
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption"
    )["scan"]
    assert stopped["resultsRecoveryNeeded"] is False
    observed_questions = json.loads((parent_dir / "coverage.json").read_text())["openQuestions"]
    for index, (child, _, _) in enumerate(children):
        identity = observed_questions[index + 2]["id"]
        assert identity.startswith(f"{child['scanId']}/")
        expected_questions[index + 2]["id"] = identity
    assert observed_questions == expected_questions
    unchanged = {path: path.read_bytes() for path in parent_dir.rglob("*") if path.is_file()}
    for command in ("get-scan", "recover-scan-results"):
        observed = run_workbench(state, command, "--scan-id", parent["scanId"])["scan"]
        assert observed["resultsRecoveryNeeded"] is False
        assert unchanged == {
            path: path.read_bytes() for path in parent_dir.rglob("*") if path.is_file()
        }

    child, directory, draft = children[0]
    draft = copy.deepcopy(draft)
    if change == "surface":
        draft["coverage"]["surfaces"][0]["disposition"] = "not_applicable"
    else:
        draft["coverage"]["deferred"] = []
        draft["coverage"]["resolvedDeferred"] = [
            {"id": task["id"], "reason": "Synthetic review finished."}
        ]
    latest = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, latest)
    run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
    child_coverage = json.loads((directory / "coverage.json").read_text())
    assert child_coverage["openQuestions"] == [{"question": "Synthetic child 1 question."}]
    assert child_coverage["surfaces"][0]["disposition"] == (
        "not_applicable" if change == "surface" else "rejected"
    )
    assert any(row["id"] == task["id"] for row in child_coverage["deferred"]) is (
        change == "surface"
    )
    original = {
        path: path.read_bytes()
        for _, child_dir, _ in children
        for path in child_dir.rglob("*")
        if path.is_file()
    }
    original.update(
        {path: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    )
    assert (
        run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"][
            "resultsRecoveryNeeded"
        ]
        is True
    )
    preserved = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert preserved["resultsRecoveryNeeded"] is True
    expected_surface = f"{child['scanId']}/{surface['id']}"
    expected_task = f"{child['scanId']}/{task['id']}"
    sibling = children[1][0]["scanId"]
    if publication_failure:
        monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
        import workbench_db as db
        import workbench_saved_results as results

        outputs = {
            path: path.read_bytes()
            for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
            if (path := parent_dir / name).exists()
        }

        def interrupt_publication(*args, **kwargs):
            raise OSError("Synthetic updated child coverage publication failure")

        monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
        with closing(db.connect()) as connection, monkeypatch.context() as patch:
            patch.setattr(results, "_write_prepared_scan_finalization", interrupt_publication)
            with pytest.raises(OSError, match="Synthetic updated child coverage publication"):
                results.recover_scan_results(
                    db, connection, SimpleNamespace(scan_id=parent["scanId"])
                )
        for path, contents in outputs.items():
            assert path.read_bytes() == contents
        for path, contents in original.items():
            assert path.read_bytes() == contents
        frozen = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert frozen["resultsRecoveryNeeded"] is True
        for path, contents in outputs.items():
            assert path.read_bytes() == contents
    published = None
    for _ in range(3):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        assert coverage["openQuestions"] == expected_questions
        assert [(row["id"], row["disposition"]) for row in coverage["surfaces"]] == [
            (surface["id"], "rejected"),
            (expected_surface, "not_applicable" if change == "surface" else "rejected"),
            (f"{sibling}/{surface['id']}", "rejected"),
        ]
        assert any(row["id"] == expected_task for row in coverage["deferred"]) is (
            change == "surface"
        )
        assert any(row["id"] == f"{sibling}/{task['id']}" for row in coverage["deferred"])
        assert task in coverage["deferred"]
        assert not coverage.get("resolvedDeferred")
        if published is not None:
            assert coverage == published
        published = coverage
        for path, contents in original.items():
            assert path.read_bytes() == contents

    # A subsequent child observation can reopen its own work without touching
    # the accepted parent or sibling rows that used the same local identifiers.
    draft["coverage"]["deferred"] = [{**task, "reason": "Synthetic review reopened."}]
    draft["coverage"].pop("resolvedDeferred", None)
    draft["coverage"]["surfaces"][0]["disposition"] = "rejected"
    reopened = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, reopened)
    run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        assert coverage["openQuestions"] == expected_questions
        assert len(coverage["surfaces"]) == 3
        assert {row["disposition"] for row in coverage["surfaces"]} == {"rejected"}
        assert {"id": expected_task, "reason": "Synthetic review reopened."} in coverage["deferred"]
        assert task in coverage["deferred"]
        assert {**task, "id": f"{sibling}/{task['id']}"} in coverage["deferred"]


def test_parent_recovery_reselects_earlier_child_coverage(tmp_path: Path) -> None:
    from workbench_test_support import saved_draft, write_checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    for index, disposition in enumerate(
        ("rejected", "not_applicable", "rejected", "not_applicable")
    ):
        draft = saved_draft(
            child["scanId"],
            complete=True,
            surfaces=[
                {
                    "id": "surface",
                    "label": "Synthetic reviewed surface",
                    "candidateId": "candidate",
                    "disposition": disposition,
                }
            ],
        )
        draft["coverage"]["inventoryStrategy"] = "repository"
        checkpoint = write_checkpoint(child_dir / "checkpoints", draft)
        select_checkpoint(child_dir, checkpoint)
        if index == 0:
            for scan in (child, parent):
                run_workbench(
                    state,
                    "fail-scan",
                    "--scan-id",
                    scan["scanId"],
                    "--message",
                    "Synthetic interruption",
                )
        else:
            run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
        child_coverage = json.loads((child_dir / "coverage.json").read_text())
        assert child_coverage["surfaces"][0]["disposition"] == disposition
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        assert coverage["surfaces"][0]["disposition"] == disposition
        published = {path: path.read_bytes() for path in parent_dir.rglob("*") if path.is_file()}
        for command in ("preserve-scan-results", "recover-scan-results"):
            replay = run_workbench(state, command, "--scan-id", parent["scanId"])["scan"]
            assert replay["resultsRecoveryNeeded"] is False
            assert published == {
                path: path.read_bytes() for path in parent_dir.rglob("*") if path.is_file()
            }


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize("surviving_finding", [False, True])
def test_parent_recovery_reconciles_withdrawn_child_findings(
    tmp_path: Path, disposition: str, surviving_finding: bool
) -> None:
    from workbench_test_support import checkpoint, saved_draft, write_checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    write_completed_contract(parent_dir, parent["scanId"], target, relative_path="app.py")
    parent_finding = json.loads((parent_dir / "findings.json").read_text())["findings"][0]
    parent_finding["title"] = "Synthetic accepted parent finding"
    parent_finding.setdefault("provenance", {})["candidateId"] = "shared-candidate"
    (parent_dir / "findings.json").write_text(json.dumps({"findings": [parent_finding]}))
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        finding = copy.deepcopy(parent_finding)
        finding["title"] = f"Synthetic child finding {index}"
        finding["identity"]["anchor"] = f"child-{index}"
        findings = [finding]
        if surviving_finding and index == 1:
            survivor = copy.deepcopy(finding)
            survivor["title"] = "Synthetic surviving child finding"
            survivor["identity"]["anchor"] = "surviving-child"
            survivor["provenance"]["candidateId"] = "surviving-candidate"
            findings.append(survivor)
        write_checkpoint(
            directory / "checkpoints",
            saved_draft(
                child["scanId"],
                complete=False,
                findings=findings,
                deferred=[
                    {
                        "id": "review-candidate",
                        "candidateId": "shared-candidate",
                        "reason": "Candidate review remains pending.",
                    }
                ],
            ),
        )
        run_workbench(
            state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic interruption"
        )
        children.append((child, directory))
    checkpoint(state, parent)
    stopped = run_workbench(
        state,
        "fail-scan",
        "--scan-id",
        parent["scanId"],
        "--message",
        "Synthetic interruption",
    )["scan"]
    assert stopped["findingCount"] == 3 + surviving_finding
    original = {path: path.read_bytes() for path in parent_dir.rglob("checkpoints/*.json")}
    child, directory = children[0]
    rejected_draft = saved_draft(
        child["scanId"],
        complete=True,
        surfaces=[
            {
                "id": "child-decision",
                "label": "Synthetic child decision",
                "candidateId": "shared-candidate",
                "disposition": disposition,
            }
        ],
    )
    if surviving_finding:
        rejected_draft["findings"] = [survivor]
    rejected_draft["coverage"] = {
        **json.loads((directory / "coverage.json").read_text()),
        **rejected_draft["coverage"],
    }
    rejected = write_checkpoint(directory / "checkpoints", rejected_draft)
    original[rejected] = rejected.read_bytes()
    select_checkpoint(directory, rejected)
    recovered_child = run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])[
        "scan"
    ]
    assert recovered_child["findingCount"] == int(surviving_finding)
    original.update(
        {path: path.read_bytes() for _, child_dir in children for path in child_dir.glob("*.json")}
    )
    preserved = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert preserved["findingCount"] == 3 + surviving_finding
    assert preserved["resultsRecoveryNeeded"] is True
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["findingCount"] == 2 + surviving_finding
        assert recovered["resultsRecoveryNeeded"] is False
        findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
        assert {finding["title"] for finding in findings} == {
            "Synthetic accepted parent finding",
            "Synthetic child finding 2",
            *(["Synthetic surviving child finding"] if surviving_finding else []),
        }
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        decision = next(
            row
            for row in coverage["surfaces"]
            if row.get("sourceCandidateId") == "shared-candidate"
            and row.get("disposition") == disposition
        )
        history = decision["previousFindings"]
        assert any(
            finding["title"] == "Synthetic child finding 1"
            and finding["provenance"].get("sourceFindings")
            and finding["provenance"]["sourceFindings"][0]["finding"]["title"]
            == "Synthetic child finding 1"
            for finding in history
        )
        assert (
            f"| Reportable DSS findings | {2 + surviving_finding} |"
            in (parent_dir / "report.md").read_text()
        )
        assert recovered["warnings"] == []
        for path, contents in original.items():
            assert path.read_bytes() == contents
    # A later reported outcome remains active even when rejection history survives.
    reported_draft = copy.deepcopy(rejected_draft)
    finding = copy.deepcopy(parent_finding)
    finding["title"] = "Synthetic child finding 1"
    finding["identity"]["anchor"] = "child-1"
    reported_draft["findings"] = [finding, *([survivor] if surviving_finding else [])]
    reported = write_checkpoint(directory / "checkpoints", reported_draft)
    original[reported] = reported.read_bytes()
    select_checkpoint(directory, reported)
    rereported_child = run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])[
        "scan"
    ]
    assert rereported_child["findingCount"] == 1 + surviving_finding
    original.update({path: path.read_bytes() for path in directory.glob("*.json")})
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["findingCount"] == 3 + surviving_finding
        assert recovered["resultsRecoveryNeeded"] is False
        assert (
            f"| Reportable DSS findings | {3 + surviving_finding} |"
            in (parent_dir / "report.md").read_text()
        )
        for path, contents in original.items():
            assert path.read_bytes() == contents


@pytest.mark.parametrize("question_id", [False, True, None])
@pytest.mark.parametrize("change", ["resolve", "edit"])
def test_parent_recovery_refreshes_child_questions_without_replaying_previous_rows(
    tmp_path: Path, question_id: bool | None, change: str
) -> None:
    from workbench_test_support import checkpoint, saved_draft, write_checkpoint

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    parent_question = {"question": "Synthetic parent question."}
    children = []
    for index in (1, 2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        draft = saved_draft(child["scanId"], complete=True)
        draft["coverage"]["inventoryStrategy"] = "repository"
        draft["coverage"]["openQuestions"] = [
            {
                "question": f"Synthetic child {index} question.",
                **(
                    {"id": "question"}
                    if question_id
                    else {"id": None}
                    if question_id is None
                    else {}
                ),
            }
        ]
        original = write_checkpoint(directory / "checkpoints", draft)
        select_checkpoint(directory, original)
        run_workbench(
            state, "fail-scan", "--scan-id", child["scanId"], "--message", "Synthetic interruption"
        )
        children.append((child, directory, draft))
    saved = checkpoint(state, parent)
    saved["aggregate"] = saved_draft(parent["scanId"])
    saved["aggregate"]["coverage"]["openQuestions"] = [parent_question]
    (parent_dir / "artifacts/deep-scan/checkpoint.json").write_text(
        composition_payload(parent_dir, saved)
    )
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption"
    )["scan"]
    assert stopped["resultsRecoveryNeeded"] is False
    original_questions = json.loads((parent_dir / "coverage.json").read_text())["openQuestions"]
    assert {row["question"] for row in original_questions} == {
        parent_question["question"],
        "Synthetic child 1 question.",
        "Synthetic child 2 question.",
    }
    child, directory, draft = children[0]
    updated_questions = (
        []
        if change == "resolve"
        else [
            {
                **draft["coverage"]["openQuestions"][0],
                "question": "Synthetic updated child question.",
                "followUpPrompt": "Check the remaining synthetic boundary.",
            }
        ]
    )
    draft["coverage"]["openQuestions"] = updated_questions
    latest = write_checkpoint(directory / "checkpoints", draft)
    select_checkpoint(directory, latest)
    run_workbench(state, "recover-scan-results", "--scan-id", child["scanId"])
    assert (
        json.loads((directory / "coverage.json").read_text())["openQuestions"] == updated_questions
    )
    unchanged = {
        path: path.read_bytes()
        for _, child_dir, _ in children
        for path in child_dir.rglob("*")
        if path.is_file()
    }
    assert (
        run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"][
            "resultsRecoveryNeeded"
        ]
        is True
    )
    published = None
    for _ in range(3):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["warnings"] == []
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        rows = coverage["openQuestions"]
        assert {row["question"] for row in rows} == {
            parent_question["question"],
            "Synthetic child 2 question.",
            *(["Synthetic updated child question."] if change == "edit" else []),
        }
        for child, _, child_draft in children:
            for question in child_draft["coverage"]["openQuestions"]:
                assert any(
                    row["question"] == question["question"]
                    and isinstance(row.get("id"), str)
                    and row["id"].startswith(f"{child['scanId']}/")
                    for row in rows
                )
        assert parent_question in rows
        assert (
            next(
                row
                for row in original_questions
                if row["question"] == "Synthetic child 2 question."
            )
            in rows
        )
        if change == "edit":
            assert (
                next(row for row in rows if row["question"] == "Synthetic updated child question.")[
                    "followUpPrompt"
                ]
                == "Check the remaining synthetic boundary."
            )
        if published is not None:
            assert coverage == published
        published = coverage
        for path, contents in unchanged.items():
            assert path.read_bytes() == contents


def test_recovery_publishes_readable_children_while_other_children_remain_unreadable(
    tmp_path: Path,
) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    children = []
    for index in range(2):
        directory = parent_dir / f"artifacts/deep-scan/passes/pass-{index + 1}"
        child = register(state, target, directory, parent=parent["scanId"], role="deep_pass")
        write_completed_contract(directory, child["scanId"], target, relative_path="app.py")
        findings_path = directory / "findings.json"
        findings = json.loads(findings_path.read_text())
        findings["findings"][0]["title"] = f"Synthetic child finding {index + 1}"
        findings_path.write_text(json.dumps(findings))
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        children.append((directory, findings_path.read_bytes()))
        findings_path.unlink()
    stopped = run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic interruption"
    )["scan"]
    assert stopped["findingCount"] == 0
    assert stopped["resultsRecoveryNeeded"] is True
    initial_history = {
        path: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")
    }

    (children[0][0] / "findings.json").write_bytes(children[0][1])
    preserved = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert preserved["findingCount"] == 0
    assert preserved["warnings"] == stopped["warnings"]
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["findingCount"] == 1
        assert recovered["resultsRecoveryNeeded"] is True
        assert any(
            "Independent scan recovery failed:" in warning for warning in recovered["warnings"]
        )
        coverage = json.loads((parent_dir / "coverage.json").read_text())
        assert any(
            "pass-2" in row["reason"] and "Recovery failed:" in row["reason"]
            for row in coverage["deferred"]
        )
        findings = json.loads((parent_dir / "findings.json").read_text())["findings"]
        assert [row["title"] for row in findings] == ["Synthetic child finding 1"]
        assert "Synthetic child finding 1" in (parent_dir / "report.md").read_text()
        assert (children[0][0] / "findings.json").read_bytes() == children[0][1]
    frozen = {path: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    for path, contents in initial_history.items():
        assert frozen[path] == contents
    (children[1][0] / "findings.json").write_bytes(children[1][1])
    preserved = run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert preserved["findingCount"] == 1
    assert preserved["warnings"] == recovered["warnings"]
    assert preserved["resultsRecoveryNeeded"] is True
    complete = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])["scan"]
    assert complete["findingCount"] == 2
    assert complete["resultsRecoveryNeeded"] is False
    assert not any(
        "Independent scan recovery failed:" in warning for warning in complete["warnings"]
    )
    for directory, contents in children:
        assert (directory / "findings.json").read_bytes() == contents
    for path, contents in frozen.items():
        assert path.read_bytes() == contents


@pytest.mark.parametrize(
    "consumer",
    [
        "standard-complete",
        "standard-missing-stage",
        "standard-changed-stage",
        "legacy-fail",
        "legacy-recover",
    ],
)
def test_parent_readers_recover_checkpoint_after_history_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, consumer: str
) -> None:
    from test_workbench_standard_deep_results import deep_scan_fixture
    from workbench_test_support import saved_draft

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    if consumer.startswith("standard-"):
        target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
        target.mkdir()
        (target / "app.py").write_text("\n" * 50)
        scan_id = register(state, target, scan_dir)["scanId"]
    else:
        state, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    write_completed_contract(scan_dir, scan_id, target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    stage = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    stage.parent.mkdir()
    stage.write_text(json.dumps(documents))
    run_workbench(state, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(stage))
    additional = copy.deepcopy(documents["findings"]["findings"][0])
    additional["identity"]["anchor"] = "staged-finding"
    additional["title"] = "Finding saved before interrupted publication"
    incoming = copy.deepcopy(documents)
    incoming["findings"]["findings"].append(additional)
    stage.write_text(json.dumps(incoming))
    checkpoint = stage.with_suffix(".checkpoint.json")
    payload = json.dumps(saved_draft(scan_id, complete=True, findings=[additional])).encode()
    checkpoint.write_bytes(payload)
    name = hashlib.sha256(payload).hexdigest() + ".json"
    original_write = results.write_scan_local_bytes

    def interrupt_history(directory, relative, contents):
        if relative == f"checkpoints/{name}":
            raise OSError("Synthetic history publication failure")
        return original_write(directory, relative, contents)

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "write_scan_local_bytes", interrupt_history)
        with pytest.raises(OSError, match="Synthetic history publication failure"):
            results.write_scan_draft(
                db._WORKBENCH_DB_CONTEXT,
                connection,
                SimpleNamespace(
                    scan_id=scan_id,
                    claim_token=None,
                    draft_path=str(stage),
                    checkpoint_path=str(checkpoint),
                    expected_draft_digest=None,
                ),
            )
    assert not (scan_dir / "checkpoints" / name).exists()
    assert (scan_dir / "checkpoints/pending" / name).read_bytes() == payload
    assert checkpoint.read_bytes() == payload
    if consumer == "standard-missing-stage":
        checkpoint.unlink()
    elif consumer in {"standard-changed-stage", "legacy-recover"}:
        checkpoint.write_bytes(payload + b"\n")
    if consumer.startswith("standard-"):
        run_workbench(state, "complete-scan", "--scan-id", scan_id)
    else:
        run_workbench(
            state,
            "fail-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Synthetic interruption",
            environment={"CODEX_HOME": str(codex_home)},
        )
    # The published marker owns its immutable bytes even if the staging file changes.
    retained = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert len(retained) == 2
    assert {row["title"] for row in retained} == {
        row["title"] for row in incoming["findings"]["findings"]
    }
    if consumer == "standard-missing-stage":
        assert not checkpoint.exists()
    else:
        assert checkpoint.read_bytes() == (
            payload + b"\n" if consumer in {"standard-changed-stage", "legacy-recover"} else payload
        )


@pytest.mark.parametrize("change", ["frozen-bytes", "new-checkpoint", "selected-head"])
@pytest.mark.parametrize("freeze_format", ["digests", "model"])
def test_parent_recovery_honors_unsealed_child_frozen_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, freeze_format: str
) -> None:
    import sqlite3

    from workbench_test_support import saved_draft, write_checkpoint

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target, relative_path="app.py")
    finding = json.loads((child_dir / "findings.json").read_text())["findings"][0]
    model = {"summary": "The accepted child model."}
    draft = saved_draft(child["scanId"], findings=[finding], complete=True)
    draft["threatModel"] = model
    draft["coverage"] = json.loads((child_dir / "coverage.json").read_text())
    original = write_checkpoint(child_dir / "checkpoints", draft)
    select_checkpoint(child_dir, original)

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic child publication interruption")

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "_write_prepared_scan_finalization", fail_publication)
        results.fail_scan(
            db._WORKBENCH_DB_CONTEXT,
            connection,
            SimpleNamespace(
                scan_id=child["scanId"],
                claim_token=None,
                cost_json=None,
                message="Synthetic child stop",
            ),
        )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        seal, frozen = connection.execute(
            "SELECT seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
            (child["scanId"],),
        ).fetchone()
    assert seal is None
    assert frozen is not None
    if freeze_format == "model":
        sources = json.loads(frozen)
        selected = original.relative_to(child_dir).as_posix()
        assert selected in sources
        frozen = json.dumps({"sources": sources, "threatModelSource": selected})
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            connection.execute(
                "UPDATE scans SET retained_source_digests_json = ? WHERE id = ?",
                (frozen, child["scanId"]),
            )
    changed = copy.deepcopy(draft)
    changed["findings"][0]["title"] = "Later unaccepted child finding"
    changed["threatModel"] = {"summary": "The later child model."}
    if change == "frozen-bytes":
        original.write_text(json.dumps(changed))
    else:
        later = write_checkpoint(child_dir / "checkpoints", changed)
        if change == "selected-head":
            select_checkpoint(child_dir, later)

    run_workbench(
        state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic parent stop"
    )
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(
            "SELECT seal_manifest_digest, retained_source_digests_json FROM scans WHERE id = ?",
            (child["scanId"],),
        ).fetchone() == (None, frozen)
    if change == "frozen-bytes":
        assert stopped["findingCount"] == 0
        assert any(
            "Frozen stopped-scan checkpoint set is incomplete" in warning
            for warning in stopped["warnings"]
        )
        retry = run_workbench(
            state, "preserve-scan-results", "--scan-id", child["scanId"], check=False
        )
        assert retry["returncode"] != 0
        assert "Frozen stopped-scan checkpoint set is incomplete" in retry["stderr"]
    else:
        retained = json.loads((parent_dir / "findings.json").read_text())["findings"]
        assert [row["title"] for row in retained] == [finding["title"]]
        parent_model = json.loads((parent_dir / "scan-manifest.json").read_text())["scan"][
            "threatModel"
        ]
        assert parent_model == {**model, "origin": "recovered"}
        saved_bytes = {path: path.read_bytes() for path in parent_dir.rglob("*") if path.is_file()}
        assert stopped["resultsRecoveryNeeded"] is False
        for command in ("get-scan", "recover-scan-results", "get-scan"):
            observed = run_workbench(state, command, "--scan-id", parent["scanId"])["scan"]
            assert observed["resultsRecoveryNeeded"] is False
            assert {
                path: path.read_bytes() for path in parent_dir.rglob("*") if path.is_file()
            } == saved_bytes
        run_workbench(state, "preserve-scan-results", "--scan-id", child["scanId"])
        assert (
            json.loads((child_dir / "scan-manifest.json").read_text())["scan"]["threatModel"]
            == model
        )


def test_acknowledging_staged_checkpoint_retains_surface_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    from workbench_test_support import saved_draft

    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    task = {"id": "review", "reason": "Review remains.", "surfaceIds": ["api"]}
    surface = {"id": "api", "label": "API", "disposition": "needs_follow_up", "receiptRefs": []}
    pending = saved_draft(scan["scanId"], deferred=[task], surfaces=[surface])
    documents["manifest"]["scan"]["complete"] = False
    documents["findings"]["findings"] = []
    documents["coverage"].update(pending["coverage"])
    stage = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    stage.parent.mkdir()
    stage.write_text(json.dumps(documents))
    checkpoint = stage.with_suffix(".checkpoint.json")
    contents = json.dumps(pending).encode()
    checkpoint.write_bytes(contents)
    name = hashlib.sha256(contents).hexdigest() + ".json"
    original_write = results.write_scan_local_bytes

    def interrupt_history(directory, relative, payload):
        if relative == f"checkpoints/{name}":
            raise OSError("Synthetic checkpoint history failure")
        return original_write(directory, relative, payload)

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "write_scan_local_bytes", interrupt_history)
        with pytest.raises(OSError, match="Synthetic checkpoint history failure"):
            results.write_scan_draft(
                db._WORKBENCH_DB_CONTEXT,
                connection,
                SimpleNamespace(
                    scan_id=scan["scanId"],
                    claim_token=None,
                    draft_path=str(stage),
                    checkpoint_path=str(checkpoint),
                    expected_draft_digest=None,
                ),
            )
    marker = scan_dir / "checkpoints/pending" / name
    assert marker.exists()
    assert not (scan_dir / "checkpoints" / name).exists()
    observed = marker.stat().st_mtime_ns
    closed = copy.deepcopy(documents)
    closed["manifest"]["scan"]["complete"] = True
    closed["coverage"].update(
        {
            "completeness": "complete",
            "deferred": [],
            "resolvedDeferred": [{"id": task["id"], "reason": "Review completed."}],
            "surfaces": [{**surface, "disposition": "no_issue_found"}],
        }
    )
    closed["reconciledCheckpointIds"] = [name]
    accepted = stage.parent / f"{uuid.uuid4()}.json"
    accepted.write_text(json.dumps(closed))
    run_workbench(
        state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(accepted)
    )
    assert not marker.exists()
    assert checkpoint.read_bytes() == contents
    plugin = Path(__file__).resolve().parents[1]
    sdk = plugin.parents[1] / "sdk/typescript"
    context = {
        "root": str(scan_dir),
        "repoRoot": str(target),
        "scanId": scan["scanId"],
        "layout": "scan",
        "mode": "standard",
        "scope": ".",
        "status": "running",
        "targetRevision": scan["targetRevision"],
        "targetContract": scan["contract"],
    }
    process = subprocess.run(
        [
            "node",
            "--input-type=module",
            "-e",
            (
                "import {createRequire} from 'node:module'; "
                "const {build}=createRequire(process.argv[1])('esbuild'); "
                "const bundle=await build({entryPoints:[process.argv[2]],nodePaths:[process.argv[3]],"
                "bundle:true,format:'esm',platform:'node',write:false}); "
                "const api=await import('data:text/javascript;base64,'+Buffer.from(bundle.outputFiles[0].contents).toString('base64')); "
                "const result=await api.recordCodexSecurityScanDraft(JSON.parse(process.argv[4]),JSON.parse(process.argv[5]),async()=>{}); "
                "console.log(JSON.stringify(result.coverage));"
            ),
            str(sdk / "package.json"),
            str(plugin / "mcp-app/src/artifact-scan-draft.ts"),
            str(sdk / "node_modules"),
            json.dumps(context),
            json.dumps(saved_draft(scan["scanId"], deferred=[task])),
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    reopened = json.loads(process.stdout)
    assert reopened["deferred"] == [task]
    assert reopened["surfaces"] == [surface]
    history = scan_dir / "checkpoints" / name
    assert history.read_bytes() == contents
    assert history.stat().st_mtime_ns == observed
    assert checkpoint.read_bytes() == contents


def test_parent_recovery_refreshes_repaired_empty_child_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, state = tmp_path / "target", tmp_path / "state"
    target.mkdir()
    parent = register(state, target, tmp_path / "parent", mode="deep")
    parent_dir = Path(parent["scanDir"])
    child_dir = parent_dir / "artifacts/deep-scan/passes/pass-1"
    child = register(state, target, child_dir, parent=parent["scanId"], role="deep_pass")
    write_completed_contract(child_dir, child["scanId"], target)
    findings_path = child_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = child_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"] = []
    coverage_path.write_text(json.dumps(coverage))
    run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
    evidence = {path: path.read_bytes() for path in child_dir.rglob("*") if path.is_file()}
    findings_path.unlink()
    run_workbench(state, "fail-scan", "--scan-id", parent["scanId"], "--message", "Synthetic stop")
    stopped = run_workbench(state, "get-scan", "--scan-id", parent["scanId"])["scan"]
    assert stopped["resultsRecoveryNeeded"] is True
    assert "Recovery failed:" in (parent_dir / "report.md").read_text()
    history = {path: path.read_bytes() for path in (parent_dir / "checkpoints").glob("*.json")}
    findings_path.write_bytes(evidence[findings_path])
    published = {path: path.read_bytes() for path in parent_dir.iterdir() if path.is_file()}
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import workbench_db as db
    import workbench_saved_results as results

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic repaired-note publication interruption")

    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    with closing(db.connect()) as connection, monkeypatch.context() as patch:
        patch.setattr(results, "_write_prepared_scan_finalization", fail_publication)
        with pytest.raises(OSError, match="Synthetic repaired-note publication interruption"):
            results.recover_scan_results(db, connection, SimpleNamespace(scan_id=parent["scanId"]))
    assert {path: path.read_bytes() for path in parent_dir.iterdir() if path.is_file()} == published
    run_workbench(state, "preserve-scan-results", "--scan-id", parent["scanId"])
    assert "Recovery failed:" in (parent_dir / "report.md").read_text()
    for _ in range(2):
        recovered = run_workbench(state, "recover-scan-results", "--scan-id", parent["scanId"])[
            "scan"
        ]
        assert recovered["resultsRecoveryNeeded"] is False
        assert recovered["findingCount"] == 0
        assert not any(
            "Independent scan recovery failed:" in warning for warning in recovered["warnings"]
        )
        deferred = json.loads((parent_dir / "coverage.json").read_text())["deferred"]
        note = next(row for row in deferred if row["id"] == f"unmerged-{child['scanId']}")
        assert "Saved work:" in note["reason"]
        assert "Recovery failed:" not in note["reason"]
        assert "Recovery failed:" not in (parent_dir / "report.md").read_text()
        for path, contents in {**history, **evidence}.items():
            assert path.read_bytes() == contents


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize(
    "surface_ids", [None, 7, ["shared-surface"]], ids=["null", "scalar", "valid"]
)
def test_stopped_recovery_retains_findings_with_ambiguous_task_surface_metadata(
    tmp_path: Path, action: str, surface_ids: object
) -> None:
    from workbench_test_support import saved_draft, write_checkpoint

    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan["scanId"], target, relative_path="app.py")
    findings = json.loads((contract / "findings.json").read_text())["findings"]
    valid_work = {"id": "independent-review", "reason": "Independent review remains."}
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints",
        saved_draft(
            scan["scanId"],
            findings=findings,
            deferred=[
                {"id": "shared-task", "reason": "First saved review.", "surfaceIds": surface_ids},
                {"id": "shared-task", "reason": "Distinct saved review."},
                valid_work,
            ],
        ),
    )
    original = checkpoint.read_bytes()
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    stopped = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert stopped["findingCount"] == 1
    assert stopped["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert valid_work in coverage["deferred"]
    assert any(row["reason"] == "Distinct saved review." for row in coverage["deferred"])
    assert checkpoint.read_bytes() == original
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize("deferred", [None, []], ids=["null", "valid"])
def test_stopped_recovery_retains_valid_findings_with_pending_null_deferred(
    tmp_path: Path, action: str, deferred: object
) -> None:
    from workbench_test_support import saved_draft, write_checkpoint

    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    pending = saved_draft(scan["scanId"], findings=[finding])
    pending["coverage"]["deferred"] = deferred
    checkpoint = write_checkpoint(scan_dir / "checkpoints/pending", pending)
    original = checkpoint.read_bytes()
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    stopped = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert stopped["findingCount"] == 1
    assert stopped["resultsRecoveryNeeded"] is False
    retained = scan_dir / "checkpoints" / checkpoint.name
    assert retained.read_bytes() == original
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("action", ["cancel-scan", "fail-scan"])
@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize(
    "surface_id",
    [["malformed-surface"], {"surface": "malformed"}, "valid-surface"],
    ids=["array", "object", "string-control"],
)
def test_stopped_scan_recovers_unhashable_terminal_surface_id(
    tmp_path: Path, action: str, disposition: str, surface_id: object
) -> None:
    from workbench_test_support import saved_draft, write_checkpoint

    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    surface = {
        "id": surface_id,
        "candidateId": "independent-terminal",
        "label": "Saved terminal review",
        "disposition": disposition,
        "receiptRefs": [],
    }
    coverage_path = scan_dir / "coverage.json"
    file_authored_coverage = json.loads(coverage_path.read_text())
    file_authored_coverage["surfaces"].append(surface)
    coverage_path.write_text(json.dumps(file_authored_coverage))
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints", saved_draft(scan["scanId"], findings=findings)
    )
    original = checkpoint.read_bytes()
    run_workbench(
        state,
        action,
        "--scan-id",
        scan["scanId"],
        *(("--message", "Synthetic interruption") if action == "fail-scan" else ()),
    )
    stopped = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]
    assert stopped["progress"]["status"] == ("canceled" if action == "cancel-scan" else "failed")
    assert stopped["findingCount"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    if isinstance(surface_id, str):
        assert surface in coverage["surfaces"]
    else:
        assert surface not in coverage["surfaces"]
        assert any(
            "Skipped malformed coverage surface" in warning for warning in stopped["warnings"]
        )
    assert checkpoint.read_bytes() == original
    assert (scan_dir / "report.md").is_file()
