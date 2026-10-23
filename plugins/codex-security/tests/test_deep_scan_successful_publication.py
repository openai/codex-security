from __future__ import annotations

import copy
import json
import os
import shutil
import uuid
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import (
    mark_deep_aggregate_ready,
    saved_draft,
    write_checkpoint,
    write_completed_contract,
)


@pytest.fixture
def publication_scan(workbench_api, workbench_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))

    def create(*, mode="deep", scope=".", paths=None):
        target = tmp_path / "target"
        target.mkdir()
        (target / "subdir").mkdir()
        (target / "subdir" / "extract.py").write_text("# Synthetic scan target\n")
        if paths is not None:
            for directory in [*paths, "unrelated"]:
                if not (target / directory).is_file():
                    (target / directory).mkdir(exist_ok=True)
                    (target / directory / "extract.py").write_text("# Synthetic scoped target\n")
        include_paths = paths if paths is not None else [scope]
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir(mode=0o700)
        registered = workbench_api["register_cli_scan"](
            workbench_db,
            Namespace(
                repository=str(target),
                scan_dir=str(scan_dir),
                recipe_json=json.dumps(
                    {
                        "config": {},
                        "mode": mode,
                        "repository": str(target),
                        "target": {
                            "kind": "paths" if paths is not None or scope != "." else "repository",
                            "paths": include_paths if paths is not None or scope != "." else [],
                        },
                    }
                ),
                registration_json_stdin=False,
                recipe_json_stdin=False,
                parent_scan_id=None,
                archive_existing=False,
                archived_scan_dir=None,
            ),
        )
        scan_id = registered["scanId"]
        if mode == "deep":
            mark_deep_aggregate_ready(tmp_path / "state", scan_id, scan_dir)
        coverage_mode = (
            "scoped_path"
            if paths is not None or scope != "."
            else "deep_repository"
            if mode == "deep"
            else "repository"
        )
        write_completed_contract(
            scan_dir,
            scan_id,
            target,
            include_paths=include_paths,
            relative_path="subdir/extract.py",
            coverage_mode=coverage_mode,
            inventory_strategy="scoped_path" if scope != "." else "repository",
        )
        manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
        findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        if mode == "deep":
            coverage.update(surfaces=[], explicitExclusions=[], deferred=[])
        else:
            coverage["openQuestions"] = [{"question": "Which deployment controls apply?"}]
        for field in ("documentType", "schemaVersion", "scanId"):
            coverage.pop(field)
        # Use the same draft format as the writer, before finalization adds metadata.
        manifest = {"scan": {key: manifest["scan"][key] for key in ("target", "scope")}}
        findings[0]["severity"]["changeConditions"] = "Reassess if the upload route is removed."
        findings[0]["provenance"]["sourceFindings"] = [
            {"id": "review-1:candidate-1", "finding": {"summary": "Retained original wording."}}
        ]
        for name, value in (
            ("scan-manifest.json", manifest),
            ("findings.json", {"findings": findings}),
            ("coverage.json", coverage),
        ):
            (scan_dir / name).write_text(json.dumps(value))
        return SimpleNamespace(
            scan_id=scan_id,
            scan_dir=scan_dir,
            findings=findings,
            coverage=coverage,
        )

    return create


def complete(workbench_api, connection, scan, *, prepare_only=False):
    return workbench_api["complete_scan"](
        connection,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None),
        prepare_only=prepare_only,
    )["scan"]


def assert_published_aggregate(scan):
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    for finding in findings:
        for field in ("findingId", "occurrenceId", "fingerprints"):
            value = finding.pop(field)
            assert value
    assert findings == scan.findings
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    for field in ("documentType", "schemaVersion", "scanId"):
        coverage.pop(field)
    assert coverage == scan.coverage
    assert (scan.scan_dir / "report.md").is_file()


@pytest.mark.parametrize("mode", ["standard", "deep", "deep-nested"])
@pytest.mark.parametrize("linked_writeup", [False, True], ids=["inline", "linked"])
def test_publication_renders_each_source_remediation(
    workbench_api, workbench_db, publication_scan, mode, linked_writeup
):
    scan = publication_scan(mode="deep" if mode == "deep-nested" else mode)
    finding = scan.findings[0]
    first = copy.deepcopy(finding)
    first["provenance"] = {"source": "local_plugin"}
    first["remediation"] = "Check the destination before writing the archive entry."
    first["remediationTests"] = ["Reject an archive entry outside the destination."]
    second = copy.deepcopy(first)
    second["remediation"] = "Reject symbolic links before opening the destination."
    second["remediationTests"] = ["Reject a symbolic link inside the destination."]
    second["preventiveControls"] = ["Use a directory-relative file handle."]
    third = copy.deepcopy(second)
    third["remediationTests"].append("Reject a dangling symbolic link.")
    third["preventiveControls"].append("Resolve links relative to the destination directory.")
    fourth = copy.deepcopy(first)
    fourth["remediation"] = "Create the output file exclusively."
    fourth["remediationTests"] = ["Preserve an existing destination file."]
    sources = [first, second, third, fourth]
    finding["remediation"] = first["remediation"]
    finding["remediationTests"] = first["remediationTests"]
    if mode == "deep-nested":
        nested = copy.deepcopy(second)
        nested["provenance"]["previousFindings"] = [third]
        nested["provenance"]["sourceFindings"] = [{"id": "review-4:0", "finding": fourth}]
        finding["provenance"]["sourceFindings"] = [
            {"id": "review-1:0", "finding": first},
            {"id": "review-2:0", "finding": nested},
        ]
    else:
        finding["provenance"]["sourceFindings"] = [
            {"id": f"review-{index}:0", "finding": source}
            for index, source in enumerate(sources, 1)
        ]
    if linked_writeup:
        finding["writeup"] = {"reportPath": "findings/archive/archive.md"}
        writeup = scan.scan_dir / "findings" / "archive" / "archive.md"
        writeup.parent.mkdir(parents=True)
        writeup.write_text("# Archive extraction\n\nRepresentative source writeup.\n")
        writeup_bytes = writeup.read_bytes()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))

    completed = complete(workbench_api, workbench_db, scan)

    assert completed["progress"]["status"] == "complete"
    assert_published_aggregate(scan)
    report = (scan.scan_dir / "report.md").read_text()
    if linked_writeup:
        assert "findings/archive/archive.md" in report
        assert writeup.read_bytes() == writeup_bytes
    for source in sources:
        assert report.count(source["remediation"]) == 1
        for test in source["remediationTests"]:
            assert report.count(test) == 1
        for control in source.get("preventiveControls", []):
            assert report.count(control) == 1
    positions = [report.index(text) for text in dict.fromkeys(s["remediation"] for s in sources)]
    assert positions == sorted(positions)


@pytest.mark.parametrize("scope", [".", "subdir"], ids=["repository", "scoped"])
def test_deep_publication_keeps_configured_scope(
    workbench_api, workbench_db, publication_scan, scope
):
    scan = publication_scan(scope=scope)
    completed = complete(workbench_api, workbench_db, scan)

    assert completed["progress"]["status"] == "complete"
    assert_published_aggregate(scan)
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["mode"] == ("deep_repository" if scope == "." else "scoped_path")
    assert coverage["includePaths"] == [scope]
    assert coverage["excludePaths"] == []
    report = (scan.scan_dir / "report.md").read_text()
    assert f"- Included paths: {scope}" in report
    assert "- Excluded paths: none" in report
    assert "## Reviewed Surfaces" not in report


def test_deep_prepare_and_complete_preserve_the_same_aggregate(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    prepared = complete(workbench_api, workbench_db, scan, prepare_only=True)
    assert prepared["progress"]["status"] == "running"
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    published = {name: (scan.scan_dir / name).read_bytes() for name in names}

    complete(workbench_api, workbench_db, scan, prepare_only=True)
    complete(workbench_api, workbench_db, scan)
    repeated = complete(workbench_api, workbench_db, scan)

    assert repeated["progress"]["status"] == "complete"
    assert {name: (scan.scan_dir / name).read_bytes() for name in names} == published
    assert_published_aggregate(scan)


@pytest.mark.parametrize("mode", ["standard", "deep"])
@pytest.mark.parametrize(("scope", "has_parent"), [(".", True), ("subdir", False)])
def test_stopped_scan_salvages_saved_parent_checkpoints(
    workbench_api, workbench_db, publication_scan, mode, scope, has_parent
):
    scan = publication_scan(mode=mode, scope=scope)
    if not has_parent:
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    later_finding = copy.deepcopy(scan.findings[0])
    later_finding["identity"]["anchor"] = "later-checkpoint-finding"
    later_finding["summary"] = "Finding saved after the last completed aggregate."
    saved = {
        "scanId": scan.scan_id,
        "complete": False,
        "findings": [later_finding],
        "coverage": scan.coverage,
    }
    checkpoint = write_checkpoint(scan.scan_dir / "checkpoints", saved)
    checkpoint_bytes = checkpoint.read_bytes()

    stopped = workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Scan interrupted."
        ),
    )["scan"]

    assert stopped["progress"]["status"] == "failed"
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert manifest["scan"]["status"] == "failed"
    assert "completeness" not in coverage
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    expected_summaries = {later_finding["summary"]}
    if has_parent:
        expected_summaries.add(scan.findings[0]["summary"])
    assert {finding["summary"] for finding in findings} == expected_summaries

    artifact_names = ("scan-manifest.json", "findings.json", "coverage.json")
    published = {name: (scan.scan_dir / name).read_bytes() for name in artifact_names}
    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == len(expected_summaries)
    assert {name: (scan.scan_dir / name).read_bytes() for name in artifact_names} == published
    assert checkpoint.read_bytes() == checkpoint_bytes


def test_stopped_deep_scan_preserves_checkpoint_without_coverage(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    invalid_finding = copy.deepcopy(scan.findings[0])
    invalid_finding["identity"]["anchor"] = "checkpoint-without-coverage"
    invalid_finding["summary"] = "Finding from a checkpoint missing required coverage."
    saved = {
        "scanId": scan.scan_id,
        "complete": False,
        "findings": [invalid_finding],
    }
    source_path = write_checkpoint(scan.scan_dir / "checkpoints", saved)
    source_bytes = source_path.read_bytes()
    source_relative = source_path.relative_to(scan.scan_dir).as_posix()

    stopped = workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Scan interrupted."
        ),
    )["scan"]

    assert stopped["progress"]["status"] == "failed"
    assert stopped["resultsRecoveryNeeded"] is False
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert [finding["summary"] for finding in findings] == [scan.findings[0]["summary"]]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    frozen = json.loads(
        workbench_db.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert manifest["scan"]["preservedSources"] == frozen
    assert source_relative not in frozen
    artifact_names = ("scan-manifest.json", "findings.json", "coverage.json")
    published = {name: (scan.scan_dir / name).read_bytes() for name in artifact_names}

    recovered = workbench_api["saved_results"].recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]

    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False
    assert {name: (scan.scan_dir / name).read_bytes() for name in artifact_names} == published
    assert source_path.read_bytes() == source_bytes


def test_standard_publication_preserves_deliberately_partial_coverage(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan(mode="standard")
    scan.coverage["deferred"] = [{"id": "remaining-review", "reason": "Another surface remains."}]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))

    complete(workbench_api, workbench_db, scan)

    assert_published_aggregate(scan)


@pytest.mark.parametrize("scope", ["subdir", "subdir/extract.py"])
def test_scoped_deep_completion_filters_old_parent(
    workbench_api, workbench_db, publication_scan, scope
):
    scan = publication_scan(paths=[scope, "background jobs"])
    findings = []
    for index, directory in enumerate(
        ["subdir", "background jobs", "unrelated", "subdir/extract.py"]
    ):
        finding = copy.deepcopy(scan.findings[0])
        finding["identity"]["anchor"] = f"scope-{index}"
        finding["title"] = f"Scope finding {directory}"
        finding["locations"] = [{"path": f"{directory}/extract.py", "startLine": 1}]
        for key in ("findingId", "occurrenceId", "fingerprints"):
            finding.pop(key, None)
        findings.append(finding)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": findings}))
    completed = complete(workbench_api, workbench_db, scan)
    assert completed["progress"]["status"] == "complete"
    paths = [
        row["locations"][0]["path"]
        for row in json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    ]
    assert paths == ["subdir/extract.py", "background jobs/extract.py"] + (
        [] if scope == "subdir/extract.py" else ["subdir/extract.py/extract.py"]
    )
    assert "Scope finding unrelated" not in (scan.scan_dir / "report.md").read_text()
    indexed = workbench_db.execute(
        "SELECT details_json FROM findings",
    ).fetchall()
    assert sorted(json.loads(row[0])["locations"][0]["path"] for row in indexed) == sorted(paths)


def test_resumed_sealed_out_of_scope_deep_scan_is_not_rewritten(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan(paths=["subdir", "background jobs"])
    scan.findings[0]["locations"] = [{"path": "unrelated/extract.py", "startLine": 1}]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    row = workbench_api["require_scan"](workbench_db, scan.scan_id)
    # Simulate the historical finalizer that sealed before scoping its output.
    workbench_api["finalize_scan"](
        scan.scan_dir,
        completion_binding=workbench_api["workbench_completion_binding"](
            row, workbench_api["now"]()
        ),
    )
    names = ["scan-manifest.json", "findings.json", "coverage.json", "report.md"]
    original = {name: (scan.scan_dir / name).read_bytes() for name in names}
    with pytest.raises(SystemExit, match="sealed Deep scan contains findings outside"):
        complete(workbench_api, workbench_db, scan)
    assert {name: (scan.scan_dir / name).read_bytes() for name in names} == original
    # Historical sealed reads are retained; this change is not a migration.
    workbench_api["finalize_scan"](scan.scan_dir)
    assert {name: (scan.scan_dir / name).read_bytes() for name in names} == original


def test_deep_scope_filter_does_not_hide_unsafe_finding_locations(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan(paths=["subdir", "background jobs"])
    scan.findings[0]["locations"] = [{"path": "../outside.py", "startLine": 1}]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    with pytest.raises(SystemExit, match="path"):
        complete(workbench_api, workbench_db, scan)
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"].get("status") != "completed"


@pytest.mark.parametrize("stopped", [False, True])
@pytest.mark.parametrize("scope", ["./subdir/", "./subdir/extract.py"])
def test_deep_publication_preserves_original_scope_kinds_after_checkout_changes(
    workbench_api, workbench_db, publication_scan, scope, stopped
):
    scan = publication_scan(paths=[scope, "background jobs"])
    row = workbench_api["require_scan"](workbench_db, scan.scan_id)
    file_paths = [scope] if scope.endswith(".py") else []
    assert workbench_api["requested_scan_file_paths"](row) == file_paths
    assert workbench_api["scan_contract"](row)["scope"]["filePaths"] == file_paths
    descendant = copy.deepcopy(scan.findings[0])
    descendant["identity"]["anchor"] = "descendant"
    descendant["locations"] = [{"path": "subdir/extract.py/generated", "startLine": 1}]
    for key in ("findingId", "occurrenceId", "fingerprints"):
        descendant.pop(key, None)
    findings = [*scan.findings, descendant]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": findings}))
    checkpoint = write_checkpoint(
        scan.scan_dir / "checkpoints",
        saved_draft(scan.scan_id, findings=findings, complete=True),
    )
    accepted = [(checkpoint, checkpoint.read_bytes())]
    target_path = Path(row["target_path"]) / scope
    if file_paths:
        target_path.unlink()
        target_path.mkdir()
    else:
        shutil.rmtree(target_path)
        target_path.write_text("new checkout file\n")
    if stopped:
        workbench_api["saved_results"].fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="interrupted"
            ),
        )
    else:
        assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"
    expected_paths = ["subdir/extract.py"] + ([] if file_paths else ["subdir/extract.py/generated"])
    assert [
        item["locations"][0]["path"]
        for item in json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    ] == expected_paths
    for result, contents in accepted:
        assert result.read_bytes() == contents
    # Reading a sealed report keeps the original projection even after the checkout changes.
    sealed = (scan.scan_dir / "findings.json").read_bytes()
    workbench_api["finalize_scan"](scan.scan_dir)
    assert (scan.scan_dir / "findings.json").read_bytes() == sealed


def test_legacy_deep_scope_does_not_reclassify_a_changed_checkout(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan(paths=["subdir"])
    row = workbench_api["require_scan"](workbench_db, scan.scan_id)
    recipe = json.loads(row["recipe_json"])
    recipe.pop("scopeFilePaths", None)
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET recipe_json = ? WHERE id = ?", (json.dumps(recipe), scan.scan_id)
        )
    row = workbench_api["require_scan"](workbench_db, scan.scan_id)
    target = Path(row["target_path"]) / "subdir"
    shutil.rmtree(target)
    target.write_text("new checkout file\n")
    assert complete(workbench_api, workbench_db, scan)["progress"]["status"] == "complete"
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1


@pytest.mark.parametrize(
    "scope, location",
    [
        ("subdir", "unrelated/extract.py"),
        ("./subdir/extract.py", "subdir/extract.py/generated"),
    ],
)
def test_stopped_deep_projection_filters_the_canonical_parent(
    workbench_api, workbench_db, publication_scan, scope, location
):
    scan = publication_scan(paths=[scope, "background jobs"])
    scan.findings[0]["locations"] = [{"path": location, "startLine": 1}]
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    stopped = workbench_api["saved_results"].fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Scan interrupted."
        ),
    )["scan"]
    assert stopped["progress"]["status"] == "failed"
    assert stopped["findingCount"] == 0
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == []


@pytest.mark.parametrize("operation", ["fail", "cancel"])
def test_stopped_standard_scan_does_not_reopen_reported_outside_candidate(
    workbench_api, workbench_db, publication_scan, operation
):
    scan = publication_scan(mode="standard", paths=["subdir"])
    finding = copy.deepcopy(scan.findings[0])
    finding["locations"] = [{"path": "unrelated/extract.py", "startLine": 1}]
    finding["provenance"]["candidateId"] = "candidate-x"
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    manifest_path = scan.scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["complete"] = False
    manifest_path.write_text(json.dumps(manifest))
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    pending = write_checkpoint(
        scan.scan_dir / "checkpoints",
        saved_draft(
            scan.scan_id,
            deferred=[{"candidateId": "candidate-x", "reason": "Validation pending."}],
        ),
    )
    os.utime(pending, ns=(50, 50))
    evidence = pending.read_bytes()
    saved = workbench_api["saved_results"]
    args = Namespace(
        scan_id=scan.scan_id,
        claim_token=None,
        thread_id=None,
        cost_json=None,
        message="Synthetic interruption.",
    )
    getattr(saved, f"{operation}_scan")(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args)
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["locations"] == finding["locations"]
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert not any(row.get("candidateId") == "candidate-x" for row in coverage["deferred"])
    published = (scan.scan_dir / "coverage.json").read_bytes()
    getattr(saved, f"{operation}_scan")(workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, args)
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
    assert pending.read_bytes() == evidence


@pytest.mark.cross_platform
@pytest.mark.parametrize("scope", [".", "subdir"])
@pytest.mark.parametrize("missing_parent", [False, True])
def test_deep_completion_preserves_findings_with_missing_optional_writeups(
    workbench_api, workbench_db, publication_scan, scope, missing_parent
):
    scan = publication_scan(scope=scope)
    valid_path = "findings/valid/valid.md"
    valid_file = scan.scan_dir / valid_path
    valid_file.parent.mkdir(parents=True)
    valid_file.write_text("# Retained writeup\n")
    scan.findings[0]["writeup"] = {"reportPath": valid_path}
    missing = copy.deepcopy(scan.findings[0])
    missing["identity"]["anchor"] = "missing-writeup"
    missing["summary"] = "A separate finding whose optional writeup was not transferred."
    missing_path = "findings/missing/missing.md"
    if not missing_parent:
        (scan.scan_dir / missing_path).parent.mkdir()
    missing["writeup"] = {"reportPath": missing_path}
    scan.findings.append(missing)
    if scope != ".":
        excluded = copy.deepcopy(missing)
        excluded["identity"]["anchor"] = "excluded-writeup"
        excluded["locations"] = [{"path": "unrelated/extract.py", "startLine": 1}]
        excluded["writeup"] = {"reportPath": "findings/excluded/excluded.md"}
        scan.findings.insert(0, excluded)
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    original_files = {valid_file: valid_file.read_bytes()}
    for kind in ("discovery", "dedup"):
        result = add_worker(workbench_db, scan)
        result.write_text(
            json.dumps(saved_draft(scan.scan_id, findings=scan.findings, complete=True))
        )
        checkpoint = write_checkpoint(result.parent / "checkpoints", json.loads(result.read_text()))
        original_files.update({path: path.read_bytes() for path in (result, checkpoint)})
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = ?, merge_state = 'none' "
                "WHERE result_manifest_path = ?",
                (kind, str(result)),
            )

    # Preparing and then completing also exercises replay of the sealed parent.
    prepared = complete(workbench_api, workbench_db, scan, prepare_only=True)
    completed = complete(workbench_api, workbench_db, scan)

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 2
    assert len(completed["warnings"]) == 1
    assert completed["warnings"] == prepared["warnings"]
    assert completed["warnings"][0].startswith("Skipped missing writeup for finding 2:")
    assert "findings[1].writeup.reportPath" in completed["warnings"][0]
    if scope != ".":
        scan.findings.pop(0)
    missing.pop("writeup")
    assert_published_aggregate(scan)
    assert {path: path.read_bytes() for path in original_files} == original_files
    report = (scan.scan_dir / "report.md").read_text()
    assert valid_path in report
    assert missing_path not in report
    assert missing["summary"] in report
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["status"] == "completed"
    assert manifest["scan"]["sealedAt"]


@pytest.mark.cross_platform
@pytest.mark.parametrize("invalid", ["unsafe-path", "directory"])
def test_deep_scope_filter_does_not_hide_invalid_writeups(
    workbench_api, workbench_db, publication_scan, invalid
):
    scan = publication_scan(scope="subdir")
    finding = scan.findings[0]
    finding["locations"] = [{"path": "unrelated/extract.py", "startLine": 1}]
    report_path = "findings/invalid/invalid.md"
    if invalid == "unsafe-path":
        report_path = "../invalid.md"
    else:
        (scan.scan_dir / report_path).mkdir(parents=True)
    finding["writeup"] = {"reportPath": report_path}
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))

    with pytest.raises(SystemExit, match="reportPath|regular non-symlink file"):
        complete(workbench_api, workbench_db, scan)
    assert (
        workbench_db.execute("SELECT status FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()[0]
        != "complete"
    )


@pytest.mark.cross_platform
@pytest.mark.parametrize("invalid", ["finding", "coverage"])
def test_missing_deep_writeup_does_not_enable_general_recovery(
    workbench_api, workbench_db, publication_scan, invalid
):
    scan = publication_scan()
    scan.findings[0]["writeup"] = {"reportPath": "findings/missing/missing.md"}
    if invalid == "finding":
        scan.findings[0]["severity"]["level"] = "invalid"
    else:
        scan.coverage["surfaces"] = "invalid"
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": scan.findings}))
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))

    with pytest.raises(SystemExit, match="severity|surfaces"):
        complete(workbench_api, workbench_db, scan)
    assert (
        workbench_db.execute("SELECT status FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()[0]
        != "complete"
    )


def test_standard_publication_preserves_deferred_work(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan(mode="standard")
    scan.coverage["deferred"] = [{"id": "remaining-review", "reason": "Another surface remains."}]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))

    complete(workbench_api, workbench_db, scan)

    assert_published_aggregate(scan)


def test_already_sealed_legacy_capped_scan_remains_immutable(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    complete(workbench_api, workbench_db, scan)
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    sealed = {name: (scan.scan_dir / name).read_bytes() for name in names}
    # Historical completed scans have a coordinator receipt and no composition checkpoint.
    (scan.scan_dir / "artifacts/deep-scan/checkpoint.json").unlink()
    add_worker(workbench_db, scan, status="failed")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET terminal_reason = 'capped' WHERE scan_id = ?",
            (scan.scan_id,),
        )
    repeated = complete(workbench_api, workbench_db, scan)
    assert repeated["progress"]["status"] == "complete"
    assert {name: (scan.scan_dir / name).read_bytes() for name in names} == sealed


def add_worker(connection, scan, *, status="succeeded") -> Path:
    timestamp = connection.execute(
        "SELECT started_at FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    worker_id = str(uuid.uuid4())
    output = scan.scan_dir / "workers" / worker_id
    output.mkdir(parents=True)
    result = output / "result.json"
    with connection:
        # Retain historical worker artifacts alongside the current composition fixture.
        connection.execute(
            "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
            "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
            "created_at, updated_at) SELECT id, 1, 'deep-security-scan/v1', 'succeeded', "
            "'terminal', 1, 1, 1, 1, started_at, updated_at FROM scans WHERE id = ? "
            "ON CONFLICT(scan_id) DO NOTHING",
            (scan.scan_id,),
        )
        connection.execute(
            "INSERT INTO deep_scan_workers (id, scan_id, kind, status, merge_state, "
            "prompt_path, artifact_dir, result_manifest_path, attempt, created_at, "
            "updated_at, completed_at) VALUES (?, ?, 'discovery', ?, ?, ?, ?, ?, 1, ?, ?, ?)",
            (
                worker_id,
                scan.scan_id,
                status,
                "merged" if status == "succeeded" else "none",
                str(output / "prompt.md"),
                str(output),
                str(result),
                timestamp,
                timestamp,
                timestamp,
            ),
        )
    return result
