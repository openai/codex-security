"""Build recorded workbench scans and worker artifacts for publication and crash-recovery tests."""

from __future__ import annotations

import copy
import json
import sqlite3
import uuid
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace

import pytest
from deep_deadline_crash import interrupt_finish_before_commit
from workbench_test_support import read_review_state, write_completed_contract


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

    def canceled_discovery_output(self, connection=None, *, attempt=1):
        connection = self.connection if connection is None else connection
        result = self.add_worker(connection, status="canceled")
        worker_id = result.parent.name
        output = self.scan_dir / "artifacts" / "deep_discovery" / "workers" / worker_id / "output"
        output.parent.mkdir(parents=True)
        result.parent.rename(output)
        with connection:
            connection.execute(
                "UPDATE deep_scan_workers SET artifact_dir = ?, prompt_path = ?, "
                "result_manifest_path = NULL, attempt = ? WHERE id = ?",
                (str(output), str(output.parent / "prompt.md"), attempt, worker_id),
            )
        return worker_id, output

    def finish(self, connection=None, *, terminal_reason="saturated", generation=None):
        return self.api["deep_scan"].finish_deep_scan(
            self.connection if connection is None else connection,
            Namespace(
                scan_id=self.scan_id,
                terminal_reason=terminal_reason,
                coordinator_generation=generation,
                manifest_path=str(self.scan_dir / "scan-manifest.json"),
                staged_manifest_path=None,
                omitted_worker_id=[],
            ),
        )["deepScan"]

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
    deep = workbench_api["deep_scan"]
    monkeypatch.setattr(
        deep,
        "_dependencies",
        SimpleNamespace(
            **workbench_api,
            preserve_stopped_results=workbench_api["preserve_stopped_results_after_transition"],
        ),
    )

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
            # Start with a finished Deep result so these tests only need to save it.
            with workbench_db:
                workbench_db.execute(
                    "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
                    "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
                    "manifest_path, terminal_reason, created_at, updated_at, completed_at) "
                    "VALUES (?, 1, 'deep-security-scan/v1', 'succeeded', 'terminal', 1, 0, 1, 1, "
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


@pytest.fixture
def saturated_scan(publication_scan):
    scan = publication_scan()
    completed_result = scan.add_worker()
    completed_result.write_text(json.dumps(scan.worker_draft(scan.findings)))
    reducer_result = scan.add_worker()
    reducer_result.write_bytes(completed_result.read_bytes())
    with scan.connection:
        scan.connection.execute(
            "UPDATE deep_scan_workers SET completion_sequence = 1 WHERE id = ?",
            (completed_result.parent.name,),
        )
        scan.connection.execute(
            "UPDATE deep_scan_workers SET kind = 'dedup', merge_state = 'none' WHERE id = ?",
            (reducer_result.parent.name,),
        )
        scan.connection.execute(
            "INSERT INTO deep_scan_dedup_inputs "
            "(scan_id, dedup_worker_id, discovery_worker_id, input_order) VALUES (?, ?, ?, 0)",
            (scan.scan_id, reducer_result.parent.name, completed_result.parent.name),
        )
        scan.connection.execute(
            "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
            "consecutive_no_new = stop_after_no_new, completion_sequence = 1, "
            "max_discovery_runs = 3, discovery_runs_dispatched = 1, "
            "manifest_path = NULL, terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
            (scan.scan_id,),
        )
    scan.completed_worker_id = completed_result.parent.name
    scan.reducer_id = reducer_result.parent.name
    return scan


@pytest.fixture
def deadline_scan(saturated_scan):
    with saturated_scan.connection:
        saturated_scan.connection.execute(
            "UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00+00:00' WHERE scan_id = ?",
            (saturated_scan.scan_id,),
        )
    return saturated_scan


@pytest.fixture
def finish_after_crashes(deadline_scan, tmp_path):
    def run():
        scan = deadline_scan
        database = tmp_path / "crash-recovery.db"
        with sqlite3.connect(database) as connection:
            scan.connection.backup(connection)

        publications = []
        for hash_seed in (1, 17, 83):
            interrupt_finish_before_commit(database, scan, hash_seed)
            publications.append(read_review_state(scan.connection, scan.scan_dir))
            with sqlite3.connect(database) as connection:
                status = connection.execute(
                    "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
                ).fetchone()[0]
                assert status == "running"
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            scan.finish(connection, terminal_reason="capped")
            completed = scan.complete(connection)
        coverage = read_review_state(scan.connection, scan.scan_dir)
        assert completed["progress"]["status"] == "complete"
        assert all(publication == coverage for publication in publications)
        return completed, coverage

    return run


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


def worker_finding(scan, anchor):
    finding = copy.deepcopy(scan.findings[0])
    finding["identity"] = {"anchor": anchor}
    finding["title"] = anchor
    finding["provenance"] = {"source": "local_plugin"}
    return finding
