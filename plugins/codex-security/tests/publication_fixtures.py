"""Build recorded workbench scans and worker artifacts for publication and crash-recovery tests."""

from __future__ import annotations

import json
import uuid
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import (
    mark_deep_aggregate_ready,
    write_completed_contract,
)


class PublicationScan(SimpleNamespace):
    """Drive publication and recovery against one test scan and its persisted worker records."""

    def worker_draft(self, findings=(), **coverage_updates):
        """Build a completed worker result using this scan's coverage as the starting point."""
        return {
            "scanId": self.scan_id,
            "complete": True,
            "findings": list(findings),
            "coverage": {**self.coverage, **coverage_updates},
        }

    def add_worker(self, connection=None, *, status="succeeded") -> Path:
        """Register a discovery worker and return the path where the test can write its result manifest."""
        worker_id = str(uuid.uuid4())
        output = self.scan_dir / "workers" / worker_id
        output.mkdir(parents=True)
        result = output / "result.json"
        connection = self.connection if connection is None else connection
        with connection:
            # Retain historical worker artifacts alongside the current composition fixture.
            connection.execute(
                "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
                "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
                "created_at, updated_at) SELECT id, 1, 'deep-security-scan/v1', 'succeeded', "
                "'terminal', 1, 1, 1, 1, started_at, updated_at FROM scans WHERE id = ? "
                "ON CONFLICT(scan_id) DO NOTHING",
                (self.scan_id,),
            )
            connection.execute(
                "INSERT INTO deep_scan_workers (id, scan_id, kind, status, merge_state, "
                "prompt_path, artifact_dir, result_manifest_path, attempt, created_at, "
                "updated_at, completed_at) VALUES (?, ?, 'discovery', ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (
                    worker_id,
                    self.scan_id,
                    status,
                    "merged" if status == "succeeded" else "none",
                    str(output / "prompt.md"),
                    str(output),
                    str(result),
                    self.timestamp,
                    self.timestamp,
                    self.timestamp,
                ),
            )
        return result

    def complete(self, connection=None, *, prepare_only=False):
        return self.api["complete_scan"](
            self.connection if connection is None else connection,
            Namespace(scan_id=self.scan_id, claim_token=None, cost_json=None),
            prepare_only=prepare_only,
        )["scan"]

    def fail(self, message="Stopped."):
        return self.api["saved_results"].fail_scan(
            self.api["_WORKBENCH_DB_CONTEXT"],
            self.connection,
            Namespace(scan_id=self.scan_id, claim_token=None, cost_json=None, message=message),
        )["scan"]

    def preserve(self, connection=None):
        return self.api["saved_results"].preserve_scan_results(
            self.api["_WORKBENCH_DB_CONTEXT"],
            self.connection if connection is None else connection,
            Namespace(
                scan_id=self.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
            ),
        )["scan"]

    def recover(self):
        return self.api["saved_results"].recover_scan_results(
            self.api["_WORKBENCH_DB_CONTEXT"], self.connection, Namespace(scan_id=self.scan_id)
        )["scan"]


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
        timestamp = workbench_db.execute(
            "SELECT started_at FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
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
        return PublicationScan(
            api=workbench_api,
            connection=workbench_db,
            scan_id=scan_id,
            scan_dir=scan_dir,
            timestamp=timestamp,
            findings=findings,
            coverage=coverage,
        )

    return create


def assert_published_aggregate(scan):
    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    for finding in findings:
        for field in ("findingId", "occurrenceId", "fingerprints"):
            value = finding.pop(field)
            assert value
    assert findings == scan.findings
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    if "coverageRef" in manifest["scan"]:
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        for field in ("documentType", "schemaVersion", "scanId"):
            coverage.pop(field)
        assert coverage == scan.coverage
    else:
        assert manifest["scan"]["review"] == {
            "excludedPaths": [item["pattern"] for item in scan.coverage["explicitExclusions"]],
        }
        assert not (scan.scan_dir / "coverage.json").exists()
    assert (scan.scan_dir / "report.md").is_file()
