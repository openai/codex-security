from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest
from test_workbench_checkpoint_heads import drafts, select
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    deep_scan_fixture,
    standard_finding,
)
from workbench_test_support import (
    cancel_scan,
    fail_deep_scan,
    get_scan,
    preserve_scan_results,
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    scan_command,
    write_checkpoint,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import workbench_db
import workbench_saved_results as saved
from workbench import saved_sources


def call_workbench(monkeypatch, state, codex_home, *args):
    with open(os.devnull) as stdin, monkeypatch.context() as patch:
        patch.setenv("CODEX_HOME", str(codex_home))
        patch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
        patch.setattr(sys, "stdin", stdin)
        patch.setattr(sys, "argv", ["workbench_db", *args])
        workbench_db.main()


@pytest.mark.parametrize("termination", ["canceled", "failed", "interrupted"])
@pytest.mark.parametrize("latest_pending", [True, False])
@pytest.mark.parametrize("failure_stage", ["publication", "source-order", "head-and-source-order"])
def test_failed_publication_keeps_order_after_identical_result_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    latest_pending: bool,
    failure_stage: str,
    termination: str,
) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    pending, closed = drafts(scan_id)
    old, latest = (closed, pending) if latest_pending else (pending, closed)
    result.write_text(json.dumps(old))
    os.utime(result, ns=(100, 100))
    checkpoint = write_checkpoint(result.parent / "checkpoints", latest)
    os.utime(checkpoint, ns=(200, 200))
    select(result.parent, checkpoint, 200)

    def fail_publication(*args, **kwargs):
        raise OSError("injected publication failure")

    write = saved_sources.write_scan_local_bytes

    def fail_snapshot(root, relative, contents):
        if relative.startswith("source-order/") or (
            failure_stage == "head-and-source-order" and "/checkpoint-heads/" in relative
        ):
            raise OSError("injected snapshot failure")
        return write(root, relative, contents)

    with monkeypatch.context() as patch:
        if failure_stage == "publication":
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        else:
            patch.setattr(saved_sources, "write_scan_local_bytes", fail_snapshot)
        call_workbench(
            patch,
            state,
            codex_home,
            "cancel-scan" if termination == "canceled" else "fail-deep-scan",
            "--scan-id",
            scan_id,
            *(
                ["--deep-status", termination, "--message", "Worker stopped."]
                if termination != "canceled"
                else []
            ),
        )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        frozen = json.loads(
            connection.execute(
                "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
        )
    sources = frozen.get("sources", frozen)
    assert result.relative_to(scan_dir).as_posix() in sources

    if failure_stage != "publication":
        with monkeypatch.context() as patch:
            patch.setattr(saved_sources, "write_scan_local_bytes", fail_snapshot)
            with pytest.raises((saved.ContractError, OSError), match="snapshot failure"):
                call_workbench(
                    patch,
                    state,
                    codex_home,
                    "preserve-scan-results",
                    "--scan-id",
                    scan_id,
                    "--thread-id",
                    "standard-worker-thread",
                )
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            assert (
                json.loads(
                    connection.execute(
                        "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
                    ).fetchone()[0]
                )
                == frozen
            )

    result.write_bytes(result.read_bytes())
    os.utime(result, ns=(300, 300))
    call_workbench(
        monkeypatch,
        state,
        codex_home,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
    )
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    pending_rows = [row for row in coverage["deferred"] if row.get("reason") == "Review remains."]
    assert pending_rows == (
        [
            {
                **pending["coverage"]["deferred"][0],
                "id": f"{worker_id}-attempt-1-deferred-1",
                "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
            }
        ]
        if latest_pending
        else []
    )
    published_sources = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
        "preservedSources"
    ]
    times = saved._frozen_source_times(scan_dir, scan_id, published_sources)
    for path, digest in sources.items():
        if Path(path).name == "checkpoint-head.json":
            assert saved._read_saved_result(scan_dir, path, scan_id)[1] == digest
            assert path not in published_sources
            captured = saved._capture_saved_source(scan_dir, path, scan_id, write=False)
            for snapshot, (expected, observed) in captured.items():
                assert published_sources[snapshot] == expected
                if Path(snapshot).parent.name == "checkpoint-heads":
                    assert times[snapshot] == observed == frozen["sourceTimes"][path]
        else:
            assert published_sources[path] == digest


@pytest.mark.parametrize("explicit_recovery", [False, True])
@pytest.mark.parametrize("layout", ["parent", "worker"])
def test_head_capture_includes_checkpoint_published_after_enumeration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, explicit_recovery: bool, layout: str
) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    pending, closed = drafts(scan_id)
    result.write_text(json.dumps(closed))
    os.utime(result, ns=(100, 100))
    output = scan_dir if layout == "parent" else result.parent
    original = write_checkpoint(output / "checkpoints", closed)
    os.utime(original, ns=(100, 100))
    select(output, original, 100)
    if explicit_recovery:
        fail_deep_scan(state, codex_home, scan_id, deep_status="failed")
        result.write_bytes(result.read_bytes())
        os.utime(result, ns=(300, 300))
    directory = (output / "checkpoints").relative_to(scan_dir).as_posix()
    children = saved_sources._children
    published = []

    def publish_after_listing(root, relative):
        names = children(root, relative)
        if relative == directory and not published:
            checkpoint = write_checkpoint(output / "checkpoints", pending)
            os.utime(checkpoint, ns=(200, 200))
            select(output, checkpoint, 200)
            published.append(checkpoint)
        return names

    monkeypatch.setattr(saved_sources, "_children", publish_after_listing)
    call_workbench(
        monkeypatch,
        state,
        codex_home,
        "recover-scan-results" if explicit_recovery else "cancel-scan",
        "--scan-id",
        scan_id,
    )
    assert len(published) == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    expected = pending["coverage"]["deferred"][0]
    if layout == "worker":
        expected = {
            **expected,
            "id": f"{worker_id}-attempt-1-deferred-1",
            "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
        }
    assert [row for row in coverage["deferred"] if row.get("reason") == "Review remains."] == [
        expected
    ]
    sources = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"]
    assert published[0].relative_to(scan_dir).as_posix() in sources
    assert any("/checkpoint-heads/" in f"/{path}" for path in sources)
    call_workbench(
        monkeypatch,
        state,
        codex_home,
        "preserve-scan-results",
        "--scan-id",
        scan_id,
        "--thread-id",
        "standard-worker-thread",
    )
    assert json.loads((scan_dir / "coverage.json").read_text()) == coverage


@pytest.mark.parametrize("rewritten", ["result", "checkpoint"])
def test_frozen_times_cover_sources_without_checkpoint_heads(
    tmp_path: Path, rewritten: str
) -> None:
    scan_id = "source-order"
    pending, closed = drafts(scan_id)
    output = tmp_path / "worker"
    output.mkdir()
    result = output / "result.json"
    result.write_text(json.dumps(closed))
    os.utime(result, ns=(100, 100))
    checkpoint = write_checkpoint(output / "checkpoints", pending)
    os.utime(checkpoint, ns=(200, 200))
    workers = [saved_discovery_worker(output, "worker", 1)]
    binding = saved_binding("deep_repository", repository="synthetic")

    def merge(frozen=None):
        return saved.merge_saved_results(
            tmp_path,
            scan_id,
            binding,
            workers,
            [],
            stopped=True,
            reason="interrupted",
            frozen_source_digests=frozen,
        )

    first = merge()
    frozen = first[0]["scan"]["preservedSources"]
    assert pending["coverage"]["deferred"][0] in first[2]["deferred"]
    path, observed = (result, 300) if rewritten == "result" else (checkpoint, 50)
    path.write_bytes(path.read_bytes())
    os.utime(path, ns=(observed, observed))
    assert merge(frozen)[2] == first[2]
    record_path = next(path for path in frozen if path.startswith("source-order/"))
    record = json.loads((tmp_path / record_path).read_text())
    record["sources"][result.relative_to(tmp_path).as_posix()]["observedAtNs"] = "400"
    (tmp_path / record_path).write_text(json.dumps(record))
    with pytest.raises(
        saved.ContractError, match="Frozen stopped-scan checkpoint set is incomplete"
    ):
        merge(frozen)


def test_order_metadata_is_not_new_evidence(tmp_path: Path) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    fail_deep_scan(state, codex_home, scan_id, deep_status="failed")
    manifest = (scan_dir / "scan-manifest.json").read_bytes()
    orphan = scan_dir / "source-order" / ("0" * 64 + ".json")
    orphan.write_text(json.dumps({"scanId": scan_id, "sources": {}}))
    assert get_scan(state, scan_id)["scan"]["resultsRecoveryNeeded"] is False
    scan_command(
        state, "recover-scan-results", scan_id, environment={"CODEX_HOME": str(codex_home)}
    )
    assert (scan_dir / "scan-manifest.json").read_bytes() == manifest


@pytest.mark.parametrize("head_time", [100, 200, 500], ids=["older", "tied", "newer"])
def test_restored_head_uses_its_captured_observation(tmp_path: Path, head_time: int) -> None:
    scan_id = "restored-observation"
    finding = standard_finding(tmp_path, scan_id, tmp_path)
    finding.setdefault("extensions", {})["candidateId"] = "candidate-a"
    reported = saved_draft(
        scan_id,
        findings=[finding],
        complete=True,
        surfaces=[
            {
                "id": "candidate-a",
                "candidateId": "candidate-a",
                "label": "Candidate",
                "disposition": "reported",
                "receiptRefs": [],
            }
        ],
    )
    rejected = saved_draft(
        scan_id,
        surfaces=[
            {
                "id": "candidate-a",
                "candidateId": "candidate-a",
                "label": "Candidate",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ],
        complete=True,
    )
    output = tmp_path / "worker"
    output.mkdir()
    checkpoints = [
        write_checkpoint(output / "checkpoints", draft) for draft in (rejected, reported)
    ]
    for checkpoint, observed in zip(checkpoints, (300, 400)):
        os.utime(checkpoint, ns=(50, 50))
        select(output, checkpoint, observed)
        saved._capture_saved_source(tmp_path, "worker/checkpoint-head.json", scan_id)
    result = output / "result.json"
    result.write_text(json.dumps(reported))
    os.utime(result, ns=(200, 200))
    select(output, checkpoints[0], head_time)
    original = {path: path.read_bytes() for path in (result, *checkpoints)}
    workers = [saved_discovery_worker(output)]
    binding = saved_binding("deep_repository", repository="synthetic")
    binding["target"]["targetId"] = "synthetic-target"
    first = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    for _ in range(2):
        assert len(first[1]["findings"]) == int(head_time < 200)
        first = saved.merge_saved_results(
            tmp_path,
            scan_id,
            binding,
            workers,
            [],
            stopped=True,
            reason="interrupted",
            frozen_source_digests=first[0]["scan"]["preservedSources"],
            checkpoint_heads=first[0]["scan"]["preservedCheckpointHeads"],
        )
    assert all(path.read_bytes() == contents for path, contents in original.items())


@pytest.mark.parametrize("termination", ["failed", "interrupted", "canceled"])
def test_first_stop_freezes_sources_before_report_preparation(
    tmp_path: Path, termination: str
) -> None:
    state, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    finding = standard_finding(tmp_path, scan_id, target)
    finding.setdefault("extensions", {})["candidateId"] = "candidate-a"
    reported = saved_draft(
        scan_id,
        findings=[finding],
        complete=True,
        surfaces=[
            {
                "id": "candidate-a",
                "candidateId": "candidate-a",
                "label": "Candidate",
                "disposition": "reported",
                "receiptRefs": [],
            }
        ],
    )
    result.write_text(json.dumps(reported))
    os.utime(result, ns=(100, 100))
    checkpoint = write_checkpoint(result.parent / "checkpoints", reported)
    select(result.parent, checkpoint, 100)
    report = scan_dir / "report.md"
    report.mkdir()
    environment = {"CODEX_HOME": str(codex_home)}
    if termination == "canceled":
        cancel_scan(state, scan_id, "standard-worker-thread", environment=environment)
    else:
        fail_deep_scan(state, codex_home, scan_id, deep_status=termination)
    stopped = get_scan(state, scan_id)["scan"]
    assert any("report.md: expected a regular file" in warning for warning in stopped["warnings"])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        frozen = connection.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    assert frozen is not None
    report.rmdir()
    rejection = saved_draft(
        scan_id,
        surfaces=[
            {
                "id": "candidate-a",
                "candidateId": "candidate-a",
                "label": "Candidate",
                "disposition": "rejected",
                "receiptRefs": [],
            }
        ],
        complete=True,
    )
    latest = write_checkpoint(result.parent / "checkpoints", rejection)
    select(result.parent, latest, 300)
    preserved = preserve_scan_results(
        state, scan_id, "standard-worker-thread", environment=environment
    )["scan"]
    assert preserved["findingCount"] == 1
    assert preserved["resultsRecoveryNeeded"] is (termination != "canceled")
    published = (scan_dir / "scan-manifest.json").read_bytes()
    preserve_scan_results(state, scan_id, "standard-worker-thread", environment=environment)
    assert (scan_dir / "scan-manifest.json").read_bytes() == published
    assert result.read_text() == json.dumps(reported)


def test_invalid_explicit_recovery_does_not_replace_first_selection(tmp_path: Path) -> None:
    state, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result = accepted_standard_worker(state, codex_home, scan_dir, scan_id)
    initial = json.loads(result.read_text())
    os.utime(result, ns=(100, 100))
    checkpoint = write_checkpoint(result.parent / "checkpoints", initial)
    select(result.parent, checkpoint, 100)
    fail_deep_scan(state, codex_home, scan_id, deep_status="failed")
    artifacts = {
        name: (scan_dir / name).read_bytes()
        for name in ("scan-manifest.json", "findings.json", "coverage.json", "report.md")
    }
    query = (
        "SELECT seal_manifest_digest, retained_source_digests_json, retained_checkpoint_heads_json "
        "FROM scans WHERE id = ?"
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        original = connection.execute(query, (scan_id,)).fetchone()
    original_checkpoint = checkpoint.read_bytes()
    checkpoint.write_text(json.dumps({**initial, "scanId": "other-scan"}))
    valid = {**initial, "complete": True, "threatModel": {"summary": "Completed review."}}
    later = write_checkpoint(result.parent / "checkpoints", valid)
    select(result.parent, later, 200)
    environment = {"CODEX_HOME": str(codex_home)}
    failed = scan_command(
        state, "recover-scan-results", scan_id, environment=environment, check=False
    )
    assert failed["returncode"] != 0
    assert "Frozen stopped-scan checkpoint set is incomplete" in failed["stderr"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert connection.execute(query, (scan_id,)).fetchone() == original
    assert all((scan_dir / name).read_bytes() == contents for name, contents in artifacts.items())
    checkpoint.write_bytes(original_checkpoint)
    scan_command(state, "recover-scan-results", scan_id, environment=environment)
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["threatModel"]["summary"] == "Completed review."
