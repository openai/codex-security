from __future__ import annotations

import copy
import json
import uuid
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import write_checkpoint, write_completed_contract


@pytest.fixture
def publication_scan(workbench_api, workbench_db, tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex-home"))
    deep = workbench_api["deep_scan"]
    monkeypatch.setattr(
        deep,
        "_dependencies",
        deep.DeepScanDependencies(
            **{
                name: workbench_api[
                    "preserve_stopped_results_after_transition"
                    if name == "preserve_stopped_results"
                    else name
                ]
                for name in deep.DeepScanDependencies.__dataclass_fields__
            }
        ),
    )

    def create(*, mode="deep", scope="."):
        target = tmp_path / "target"
        target.mkdir()
        (target / "subdir").mkdir()
        (target / "subdir" / "extract.py").write_text("# Synthetic scan target\n")
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
                            "kind": "repository" if scope == "." else "paths",
                            "paths": [] if scope == "." else [scope],
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
        timestamp = workbench_db.execute(
            "SELECT started_at FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
        if mode == "deep":
            # Start with a finished Deep result so these tests only need to save it.
            with workbench_db:
                workbench_db.execute(
                    "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
                    "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
                    "manifest_path, terminal_reason, created_at, updated_at, completed_at) "
                    "VALUES (?, 1, 'publication-test', 'succeeded', 'terminal', 1, 0, 1, 1, "
                    "?, 'saturated', ?, ?, ?)",
                    (
                        scan_id,
                        str(scan_dir / "scan-manifest.json"),
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
        coverage_mode = (
            "scoped_path" if scope != "." else "deep_repository" if mode == "deep" else "repository"
        )
        write_completed_contract(
            scan_dir,
            scan_id,
            target,
            include_paths=[scope],
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
            timestamp=timestamp,
            findings=findings,
            coverage=coverage,
        )

    return create


def add_worker(connection, scan, *, status="succeeded") -> Path:
    worker_id = str(uuid.uuid4())
    output = scan.scan_dir / "workers" / worker_id
    output.mkdir(parents=True)
    result = output / "result.json"
    with connection:
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
                scan.timestamp,
                scan.timestamp,
                scan.timestamp,
            ),
        )
    return result


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
            assert finding.pop(field)
    assert findings == scan.findings
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    for field in ("documentType", "schemaVersion", "scanId"):
        coverage.pop(field)
    assert coverage == scan.coverage
    assert (scan.scan_dir / "report.md").is_file()


@pytest.mark.parametrize("scope", [".", "subdir"], ids=["repository", "scoped"])
def test_deep_publication_keeps_configured_scope_without_worker_observations(
    workbench_api, workbench_db, publication_scan, scope
):
    scan = publication_scan(scope=scope)
    result = add_worker(workbench_db, scan)
    worker_coverage = {
        "completeness": "partial",
        "surfaces": [
            {
                "id": "worker-surface",
                "label": "Worker review",
                "disposition": "needs_follow_up",
                "receiptRefs": [],
            }
        ],
        "explicitExclusions": [{"pattern": "docs/", "reason": "Worker-local exclusion."}],
        "deferred": [{"id": "worker-follow-up", "reason": "Review this path again."}],
        "openQuestions": [{"question": "Which deployment controls apply?"}],
    }
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": worker_coverage,
            }
        )
    )
    source_bytes = result.read_bytes()

    completed = complete(workbench_api, workbench_db, scan)

    assert completed["progress"]["status"] == "complete"
    assert_published_aggregate(scan)
    assert result.read_bytes() == source_bytes
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["mode"] == ("deep_repository" if scope == "." else "scoped_path")
    assert coverage["includePaths"] == [scope]
    assert coverage["excludePaths"] == []
    report = (scan.scan_dir / "report.md").read_text()
    assert f"- Included paths: {scope}" in report
    assert "- Excluded paths: none" in report
    assert "## Reviewed Surfaces" not in report
    assert "Which deployment controls apply?" not in report


def test_deep_publication_ignores_empty_canceled_checkpoint(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan, status="canceled")
    checkpoint = write_checkpoint(
        result.parent / "checkpoints",
        {
            "scanId": scan.scan_id,
            "complete": False,
            "findings": [],
            "coverage": {
                "completeness": "partial",
                "surfaces": [],
                "explicitExclusions": [],
                "deferred": [],
            },
        },
    )
    source_bytes = checkpoint.read_bytes()

    complete(workbench_api, workbench_db, scan)

    assert_published_aggregate(scan)
    assert checkpoint.read_bytes() == source_bytes
    assert not result.exists()


@pytest.mark.parametrize("old_result", ["unreadable", "removed"])
def test_deep_publication_does_not_require_old_worker_files(
    workbench_api, workbench_db, publication_scan, old_result
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    result.write_text("{old worker output is unavailable")
    if old_result == "removed":
        result.unlink()

    completed = complete(workbench_api, workbench_db, scan)

    assert completed["warnings"] == []
    assert_published_aggregate(scan)
    if old_result == "removed":
        assert not result.exists()
    else:
        assert result.read_text() == "{old worker output is unavailable"


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


@pytest.mark.parametrize(
    ("source", "scope", "has_parent"),
    [
        ("standard-worker-checkpoint", ".", True),
        ("deep-reducer-checkpoint", ".", True),
        ("deep-reducer-archived-checkpoint", ".", True),
        ("deep-reducer-result", ".", True),
        ("deep-reducer-result", "subdir", False),
    ],
    ids=[
        "standard-worker-checkpoint",
        "deep-reducer-checkpoint",
        "deep-reducer-archived-checkpoint",
        "deep-reducer-result",
        "scoped-reducer-without-parent",
    ],
)
def test_stopped_deep_scan_still_salvages_saved_findings(
    workbench_api, workbench_db, publication_scan, source, scope, has_parent
):
    scan = publication_scan(scope=scope)
    if not has_parent:
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan.scan_dir / name).unlink()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'reducing', "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    result = add_worker(
        workbench_db, scan, status="succeeded" if source == "deep-reducer-result" else "running"
    )
    if source.startswith("deep-reducer"):
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
                (result.parent.name,),
            )
    later_finding = copy.deepcopy(scan.findings[0])
    later_finding["identity"]["anchor"] = "later-checkpoint-finding"
    later_finding["summary"] = "Finding saved after the last completed aggregate."
    saved = {
        "scanId": scan.scan_id,
        "complete": source == "deep-reducer-result",
        "findings": [later_finding],
    }
    if source == "standard-worker-checkpoint":
        saved["coverage"] = {
            "completeness": "partial",
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        }
    if source == "deep-reducer-result":
        checkpoint = None
        result.write_text(json.dumps(saved))
    else:
        checkpoint_root = (
            result.parent / "attempts" / "attempt-01"
            if source == "deep-reducer-archived-checkpoint"
            else result.parent
        )
        checkpoint = write_checkpoint(checkpoint_root / "checkpoints", saved)
        result.write_text("{interrupted worker output")
    result_bytes = result.read_bytes()

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Scan interrupted."
        ),
    )["scan"]

    assert stopped["progress"]["status"] == "failed"
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert manifest["scan"]["status"] == "failed"
    assert coverage["completeness"] == "partial"
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    expected_summaries = {later_finding["summary"]}
    if has_parent:
        expected_summaries.add(scan.findings[0]["summary"])
    assert {finding["summary"] for finding in findings} == expected_summaries

    artifact_names = ("scan-manifest.json", "findings.json", "coverage.json")
    published = {name: (scan.scan_dir / name).read_bytes() for name in artifact_names}
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == len(expected_summaries)
    assert {name: (scan.scan_dir / name).read_bytes() for name in artifact_names} == published
    if checkpoint is not None:
        assert json.loads(checkpoint.read_text()) == saved
    assert result.read_bytes() == result_bytes


@pytest.mark.parametrize("source", ["result", "checkpoint", "parent-checkpoint"])
def test_stopped_deep_scan_ignores_non_reducer_sources_without_coverage(
    workbench_api, workbench_db, publication_scan, source
):
    scan = publication_scan()
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    invalid_finding = copy.deepcopy(scan.findings[0])
    invalid_finding["identity"]["anchor"] = "non-reducer-without-coverage"
    invalid_finding["summary"] = "Finding from a non-reducer artifact missing required coverage."
    saved = {
        "scanId": scan.scan_id,
        "complete": source == "result",
        "findings": [invalid_finding],
    }
    if source == "parent-checkpoint":
        source_path = write_checkpoint(scan.scan_dir / "checkpoints", saved)
    else:
        result = add_worker(
            workbench_db, scan, status="succeeded" if source == "result" else "running"
        )
        if source == "result":
            result.write_text(json.dumps(saved))
            source_path = result
        else:
            source_path = write_checkpoint(result.parent / "checkpoints", saved)
    source_bytes = source_path.read_bytes()
    source_relative = source_path.relative_to(scan.scan_dir).as_posix()

    stopped = workbench_api["fail_scan"](
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

    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]

    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False
    assert {name: (scan.scan_dir / name).read_bytes() for name in artifact_names} == published
    assert source_path.read_bytes() == source_bytes


def test_standard_publication_preserves_deliberately_partial_coverage(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan(mode="standard")
    scan.coverage["completeness"] = "partial"
    scan.coverage["deferred"] = [{"id": "remaining-review", "reason": "Another surface remains."}]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))

    complete(workbench_api, workbench_db, scan)

    assert_published_aggregate(scan)
