from __future__ import annotations

import copy
import json
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_deep_coverage_recovery import worker
from test_workbench_standard_deep_results import write_saved_parent
from workbench_test_support import saved_binding, saved_draft, write_checkpoint

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finalize_scan_contract as finalizer
import workbench_saved_results as saved


def publication_context(tmp_path, scan_id):
    binding = {
        **saved_binding("deep_repository", repository="synthetic", status="completed"),
        "scanId": scan_id,
        "startedAt": "2026-01-01T00:00:00Z",
        "completedAt": "2026-01-01T00:01:00Z",
        "producer": {"name": "codex-security", "version": "0.0.0"},
    }
    binding["target"].update(
        revision="a" * 40, targetId="synthetic", displayName="Synthetic fixture"
    )
    db = SimpleNamespace(
        require_canonical_scan_directory=finalizer._require_scan_directory,
        now=lambda: binding["completedAt"],
        workbench_completion_binding=lambda *_args: copy.deepcopy(binding),
        expected_coverage_mode=lambda _scan: "deep_repository",
        requested_finding_scope=lambda _scan: None,
    )
    scan = {"id": scan_id, "scan_dir": str(tmp_path), "completion_warnings_json": "[]"}
    return binding, db, scan


def test_deadline_rollback_removes_new_parent_observation_without_a_selected_head(tmp_path):
    scan_id = "00000000-0000-4000-8000-000000000001"
    parent = saved_draft(
        scan_id, deferred=[{"id": "review", "reason": "Review remains."}], complete=True
    )
    write_saved_parent(tmp_path, parent, 100)
    _, db, scan = publication_context(tmp_path, scan_id)
    original = {
        path.relative_to(tmp_path): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    class Connection:
        def execute(self, sql, _args):
            if sql.startswith("UPDATE"):
                raise RuntimeError("Synthetic publication failure")
            return SimpleNamespace(fetchall=list)

    with pytest.raises(RuntimeError, match="Synthetic publication failure"):
        saved.preserve_deep_deadline_draft(db, Connection(), scan)

    restored = {
        path.relative_to(tmp_path): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    assert restored == original


@pytest.mark.parametrize("local_failure", [False, True], ids=["caller-rollback", "local-failure"])
def test_deadline_rollback_does_not_reintroduce_a_later_rejected_worker_finding(
    tmp_path, local_failure
):
    scan_id = "00000000-0000-4000-8000-000000000001"
    finding = {
        "ruleId": "synthetic.input",
        "identity": {"anchor": "fixture"},
        "title": "Synthetic candidate",
        "summary": "A synthetic source-backed result.",
        "severity": {"level": "low"},
        "confidence": {"level": "high", "rationale": "Synthetic fixture evidence."},
        "taxonomy": {"category": "other", "cwe": []},
        "locations": [{"path": "fixture.py", "startLine": 1}],
        "remediation": "Apply the synthetic correction.",
        "provenance": {"source": "local_plugin", "candidateId": "candidate-one"},
    }
    draft = saved_draft(scan_id, findings=[finding])
    source = worker(tmp_path, "reviewer", draft)
    output = Path(source["artifact_dir"])
    worker_checkpoint = write_checkpoint(output / "checkpoints", draft)
    worker_bytes = worker_checkpoint.read_bytes()
    previous = write_checkpoint(tmp_path / "checkpoints", saved_draft(scan_id))
    previous_bytes = previous.read_bytes()
    head = tmp_path / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": previous.name}))
    original_head = head.read_bytes()
    binding, db, scan = publication_context(tmp_path, scan_id)

    class Connection:
        def execute(self, sql, _args):
            if sql.startswith("UPDATE") and local_failure:
                raise RuntimeError("Synthetic publication failure")
            return SimpleNamespace(fetchall=lambda: [source])

    if local_failure:
        with pytest.raises(RuntimeError, match="Synthetic publication failure"):
            saved.preserve_deep_deadline_draft(db, Connection(), scan)
    else:
        publication = saved.preserve_deep_deadline_draft(db, Connection(), scan)
        # The caller uses this same restoration path when its transaction fails.
        saved._restore_published_outputs(*publication)

    rejected = saved_draft(
        scan_id,
        complete=True,
        surfaces=[
            {
                "id": "candidate-one",
                "candidateId": "candidate-one",
                "label": "Reviewed candidate",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ],
    )
    (output / "result.json").write_text(json.dumps(rejected))
    warnings = []
    recovered = saved.merge_saved_results(
        tmp_path,
        scan_id,
        binding,
        [source],
        warnings,
        stopped=True,
        reason="Synthetic stop after rejection.",
        project_worker_coverage=True,
    )
    assert recovered is not None
    assert recovered[1]["findings"] == []
    assert worker_checkpoint.read_bytes() == worker_bytes
    assert previous.read_bytes() == previous_bytes
    assert head.read_bytes() == original_head
    assert list((tmp_path / "checkpoints").iterdir()) == [previous]


@pytest.mark.parametrize("local_failure", [False, True], ids=["caller-rollback", "local-failure"])
@pytest.mark.parametrize("newer_source", ["canonical", "unselected-checkpoint"])
def test_deadline_rollback_preserves_parent_observation_order(
    tmp_path, local_failure, newer_source
):
    scan_id = "00000000-0000-4000-8000-000000000001"
    pending = saved_draft(
        scan_id, deferred=[{"id": "review", "reason": "Review remains."}], complete=True
    )
    closed = saved_draft(
        scan_id, closures=[{"id": "review", "reason": "Review completed."}], complete=True
    )
    older, newer = (pending, closed) if newer_source == "canonical" else (closed, pending)
    older["threatModel"] = {"summary": "The earlier model."}
    newer["threatModel"] = {"summary": "The current model."}
    selected = write_checkpoint(tmp_path / "checkpoints", older)
    os.utime(selected, ns=(100, 100))
    head = tmp_path / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(100, 100))
    canonical = newer if newer_source == "canonical" else older
    modified = 200 if newer_source == "canonical" else 100
    write_saved_parent(tmp_path, canonical, modified)
    manifest_path = tmp_path / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["threatModel"] = canonical["threatModel"]
    manifest_path.write_text(json.dumps(manifest))
    for name in ("scan-manifest.json", "findings.json", "coverage.json"):
        os.utime(tmp_path / name, ns=(modified, modified))
    if newer_source == "unselected-checkpoint":
        unselected = write_checkpoint(tmp_path / "checkpoints", newer)
        os.utime(unselected, ns=(200, 200))
    binding, db, scan = publication_context(tmp_path, scan_id)

    class Connection:
        def execute(self, sql, _args):
            if sql.startswith("UPDATE") and local_failure:
                raise RuntimeError("Synthetic publication failure")
            return SimpleNamespace(fetchall=list)

    def recover(directory):
        result = saved.merge_saved_results(
            directory, scan_id, binding, [], [], stopped=True, reason="Synthetic interruption."
        )
        assert result is not None
        return result

    def pending_ids(result):
        return {row.get("id") for row in result[2]["deferred"] if row.get("id") == "review"}

    baseline = tmp_path.with_name(tmp_path.name + "-baseline")
    shutil.copytree(tmp_path, baseline)
    before = recover(baseline)
    assert pending_ids(before) == ({"review"} if newer_source == "unselected-checkpoint" else set())
    assert before[0]["scan"]["threatModel"] == canonical["threatModel"]
    original = {
        path: (path.read_bytes(), path.stat().st_mtime_ns)
        for path in [
            head,
            manifest_path,
            tmp_path / "findings.json",
            tmp_path / "coverage.json",
            *(tmp_path / "checkpoints").glob("*.json"),
        ]
    }
    if local_failure:
        with pytest.raises(RuntimeError, match="Synthetic publication failure"):
            saved.preserve_deep_deadline_draft(db, Connection(), scan)
    else:
        publication = saved.preserve_deep_deadline_draft(db, Connection(), scan)
        saved._restore_published_outputs(*publication)

    restored = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in original}
    after = recover(tmp_path)
    assert pending_ids(after) == pending_ids(before)
    assert after[0]["scan"]["threatModel"] == before[0]["scan"]["threatModel"]
    assert restored == original
