from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_deep_scan_stop_conditions import canceled_discovery_output, complete, finish
from test_deep_scan_stop_conditions import deadline_scan as deadline_scan
from test_deep_scan_stop_conditions import publication_scan as publication_scan
from test_deep_scan_stop_conditions import saturated_scan as saturated_scan
from workbench_test_support import (
    replay_saved_results,
    saved_binding,
    saved_discovery_worker,
    saved_draft,
    write_checkpoint,
)


def surface(label, identity="entry", disposition="needs_follow_up"):
    return {"id": identity, "label": label, "disposition": disposition, "receiptRefs": []}


def pending(identity, reason, surface_id="entry"):
    return {"id": identity, "reason": reason, "surfaceIds": [surface_id]}


def interrupt_in_fresh_python(database, scan, hash_seed):
    script = Path(__file__).resolve().parents[1] / "scripts" / "workbench_db.py"
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            """
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(sys.argv[1]).parents[1] / "tests"))
from test_deep_scan_deadline_recovery import interrupt_finish_before_commit

api = runpy.run_path(sys.argv[1], run_name="surface_link_recovery_test")
api["deep_scan"]._dependencies = SimpleNamespace(
    **api, preserve_stopped_results=api["preserve_stopped_results_after_transition"]
)
scan = SimpleNamespace(scan_id=sys.argv[3], scan_dir=Path(sys.argv[4]))
interrupt_finish_before_commit(api, Path(sys.argv[2]), scan)
""",
            str(script),
            str(database),
            scan.scan_id,
            str(scan.scan_dir),
        ],
        cwd=Path(__file__).parent,
        env={**os.environ, "PYTHONHASHSEED": str(hash_seed)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize("parent_collision", [False, True])
def test_deadline_surface_links_follow_sources_across_repeated_crashes(
    workbench_api, workbench_db, deadline_scan, tmp_path, parent_collision
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan, attempt=2)
    archived = output.parent / "attempts" / "attempt-01"
    shared = pending("shared-review", "Review all retained observations.")
    checkpoints = []
    for index, (source, label) in enumerate(
        [(archived, "download"), (output, "upload"), (output, "export")], start=1
    ):
        # Each is a valid raw input checkpoint saved before the writer merges history.
        checkpoint = write_checkpoint(
            source / "checkpoints",
            saved_draft(
                scan.scan_id,
                surfaces=[surface(label)],
                deferred=[pending(f"{label}-review", f"Review {label}."), shared],
            ),
        )
        os.utime(checkpoint, ns=(index * 100, index * 100))
        checkpoints.append(checkpoint)
    canonical_id = f"{worker_id}/entry" if parent_collision else "parent-entry"
    canonical_surface = surface("Canonical parent", canonical_id)
    canonical_pending = pending("parent-review", "Parent review remains.", canonical_id)
    scan.coverage.update(surfaces=[canonical_surface], deferred=[canonical_pending])
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    originals = {path: path.read_bytes() for path in checkpoints}
    database = tmp_path / "surface-links.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for hash_seed in (1, 17, 83):
        interrupt_in_fresh_python(database, scan, hash_seed)
        publications.append(json.loads((scan.scan_dir / "coverage.json").read_text()))
        with sqlite3.connect(database) as connection:
            assert (
                connection.execute(
                    "SELECT status FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
                ).fetchone()[0]
                == "running"
            )
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        completed = complete(workbench_api, connection, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert completed["progress"]["status"] == "complete"
    assert all(publication == coverage for publication in publications)
    assert canonical_surface in coverage["surfaces"]
    assert canonical_pending in coverage["deferred"]
    surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert {row["label"] for row in surfaces} == {"download", "upload", "export"}
    assert len(surfaces) == len({row["id"] for row in surfaces}) == 3
    tasks = [row for row in coverage["deferred"] if row.get("workerId") == worker_id]
    for row in surfaces:
        task = next(item for item in tasks if item["reason"] == f"Review {row['label']}.")
        assert task["surfaceIds"] == [row["id"]]
    shared_tasks = [row for row in tasks if row["reason"] == shared["reason"]]
    assert len(shared_tasks) == 1
    assert shared_tasks[0]["surfaceIds"] == [row["id"] for row in surfaces]
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.parametrize("with_reduction", [False, True], ids=["zero-accepted", "reduced"])
def test_deadline_retains_all_targets_of_one_legacy_surface_id(
    workbench_api, workbench_db, publication_scan, request, with_reduction
):
    scan = request.getfixturevalue("deadline_scan") if with_reduction else publication_scan()
    if not with_reduction:
        with workbench_db:
            workbench_db.execute(
                "UPDATE deep_scan_runs SET status = 'running', phase = 'discovery', "
                "created_at = '2000-01-01T00:00:00+00:00', manifest_path = NULL, "
                "terminal_reason = NULL, completed_at = NULL WHERE scan_id = ?",
                (scan.scan_id,),
            )
    _, output = canceled_discovery_output(workbench_db, scan)
    checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(
            scan.scan_id,
            surfaces=[surface("download"), surface("upload")],
            deferred=[pending("review", "Review both legacy observations.")],
        ),
    )
    original = checkpoint.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    complete(workbench_api, workbench_db, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    surfaces = [row for row in coverage["surfaces"] if row["label"] in {"download", "upload"}]
    assert len(surfaces) == len({row["id"] for row in surfaces}) == 2
    task = next(
        row for row in coverage["deferred"] if row["reason"] == "Review both legacy observations."
    )
    assert task["surfaceIds"] == [row["id"] for row in surfaces]
    assert checkpoint.read_bytes() == original


def test_deadline_deferred_only_checkpoint_keeps_prior_surface_link(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    earlier = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, surfaces=[surface("Earlier review", "prior")]),
    )
    current = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, deferred=[pending("review", "Review prior surface.", "prior")]),
    )
    os.utime(earlier, ns=(100, 100))
    os.utime(current, ns=(200, 200))
    originals = {path: path.read_bytes() for path in (earlier, current)}

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    complete(workbench_api, workbench_db, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    retained = next(row for row in coverage["surfaces"] if row["label"] == "Earlier review")
    task = next(row for row in coverage["deferred"] if row["reason"] == "Review prior surface.")
    assert task["surfaceIds"] == [retained["id"]] == [f"{worker_id}/prior"]
    assert {path: path.read_bytes() for path in originals} == originals


def test_deadline_reopened_generic_surface_copy_retains_its_link(
    workbench_api, workbench_db, deadline_scan
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    canonical = surface("Canonical parent", f"{worker_id}/entry")
    scan.coverage["surfaces"] = [canonical]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    drafts = [
        saved_draft(
            scan.scan_id,
            surfaces=[surface("Worker review")],
            deferred=[pending("review", "Initial review pending.")],
        ),
        saved_draft(
            scan.scan_id,
            complete=True,
            surfaces=[surface("Worker review", disposition="no_issue_found")],
            closures=[{"id": "review", "reason": "Initial review completed."}],
        ),
        saved_draft(
            scan.scan_id,
            surfaces=[surface("Worker review")],
            deferred=[pending("review", "Review reopened.")],
        ),
    ]
    originals = {}
    for index, draft in enumerate(drafts, start=1):
        checkpoint = write_checkpoint(output / "checkpoints", draft)
        os.utime(checkpoint, ns=(index * 100, index * 100))
        originals[checkpoint] = checkpoint.read_bytes()
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    originals[head] = head.read_bytes()

    finish(workbench_api, workbench_db, scan, terminal_reason="capped")
    complete(workbench_api, workbench_db, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    retained = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert len(retained) == 1
    assert retained[0]["disposition"] == "needs_follow_up"
    task = next(row for row in coverage["deferred"] if row["reason"] == "Review reopened.")
    assert task["surfaceIds"] == [retained[0]["id"]]
    assert canonical in coverage["surfaces"]
    assert {path: path.read_bytes() for path in originals} == originals


def test_stopped_recovery_preserves_source_link_union(workbench_api, tmp_path):
    saved = workbench_api["saved_results"]
    scan_id = "surface-links"
    binding = saved_binding("deep_repository")
    output = tmp_path / "worker" / "output"
    archived = output.parent / "attempts" / "attempt-01"
    shared = pending("review", "Review retained observations.")
    originals = {}
    for source, label in ((archived, "download"), (output, "upload")):
        checkpoint = write_checkpoint(
            source / "checkpoints",
            saved_draft(scan_id, surfaces=[surface(label)], deferred=[shared]),
        )
        originals[checkpoint] = checkpoint.read_bytes()
    workers = [saved_discovery_worker(output, "worker", 2)]

    documents = saved.merge_saved_results(
        tmp_path, scan_id, binding, workers, [], stopped=True, reason="interrupted"
    )
    replay = replay_saved_results(saved, documents, tmp_path, scan_id, binding, workers)

    assert replay[2] == documents[2]
    coverage = documents[2]
    assert {row["label"] for row in coverage["surfaces"]} == {"download", "upload"}
    tasks = [row for row in coverage["deferred"] if row["reason"] == shared["reason"]]
    assert len(tasks) == 1
    assert tasks[0]["surfaceIds"] == [row["id"] for row in coverage["surfaces"]]
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize("changed_task", [False, True], ids=["copied-task", "updated-task"])
def test_deadline_retains_equal_task_origins_from_selected_worker_result(
    workbench_api, workbench_db, deadline_scan, tmp_path, changed_task
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan, attempt=2)
    archived = output.parent / "attempts" / "attempt-01"
    previous_task = pending("download-review", "Download review pending.")
    archived_draft = saved_draft(
        scan.scan_id, surfaces=[surface("download")], deferred=[previous_task]
    )
    checkpoint = write_checkpoint(archived / "checkpoints", archived_draft)
    os.utime(checkpoint, ns=(100, 100))
    archived_head = archived / "checkpoint-head.json"
    archived_head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    os.utime(archived_head, ns=(110, 110))
    archived_result = archived / "result.json"
    archived_result.write_bytes(checkpoint.read_bytes())
    os.utime(archived_result, ns=(120, 120))
    current_task = pending("upload-review", "Upload review pending.")
    retained_task = (
        pending("download-review", "Download review updated.") if changed_task else previous_task
    )
    incoming = saved_draft(
        scan.scan_id,
        surfaces=[surface("upload")],
        deferred=[current_task, retained_task] if changed_task else [current_task],
    )
    raw_checkpoint = write_checkpoint(output / "checkpoints", incoming)
    os.utime(raw_checkpoint, ns=(200, 200))
    # The writer preserves the old pending task while publishing its latest surface.
    merged = saved_draft(
        scan.scan_id, surfaces=[surface("upload")], deferred=[current_task, retained_task]
    )
    selected = write_checkpoint(output / "checkpoints", merged)
    os.utime(selected, ns=(210, 210))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(220, 220))
    result = output / "result.json"
    result.write_bytes(selected.read_bytes())
    os.utime(result, ns=(230, 230))
    originals = {path: path.read_bytes() for path in output.parent.rglob("*") if path.is_file()}
    database = tmp_path / "selected-result.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for hash_seed in (1, 17, 83):
        interrupt_in_fresh_python(database, scan, hash_seed)
        publications.append(json.loads((scan.scan_dir / "coverage.json").read_text()))
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        complete(workbench_api, connection, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert all(publication == coverage for publication in publications)
    surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert {row["label"] for row in surfaces} == {"download", "upload"}
    upload = next(row for row in surfaces if row["label"] == "upload")
    tasks = [row for row in coverage["deferred"] if row.get("workerId") == worker_id]
    assert len(tasks) == 2
    current = next(row for row in tasks if row["reason"] == current_task["reason"])
    retained = next(row for row in tasks if row["reason"] == retained_task["reason"])
    assert current["surfaceIds"] == [upload["id"]]
    assert retained["surfaceIds"] == (
        [upload["id"]] if changed_task else [row["id"] for row in surfaces]
    )
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize(
    "selected_result", [False, True], ids=["raw-checkpoint", "selected-result"]
)
def test_deadline_dropped_legacy_surface_does_not_rebind_its_pending_task(
    workbench_api, workbench_db, deadline_scan, tmp_path, selected_result
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan, attempt=2)
    archived = output.parent / "attempts" / "attempt-01"
    download_task = pending("download-review", "Download review pending.")
    archived_checkpoint = write_checkpoint(
        archived / "checkpoints",
        saved_draft(scan.scan_id, surfaces=[surface("download")], deferred=[download_task]),
    )
    os.utime(archived_checkpoint, ns=(100, 100))
    archived_result = archived / "result.json"
    archived_result.write_bytes(archived_checkpoint.read_bytes())
    os.utime(archived_result, ns=(110, 110))
    upload_task = pending("upload-review", "Upload review pending.")
    # Historical artifacts can contain labels rejected during finalization.
    malformed_surface = surface("\u0085")
    raw_checkpoint = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, surfaces=[malformed_surface], deferred=[upload_task]),
    )
    os.utime(raw_checkpoint, ns=(200, 200))
    if selected_result:
        selected = write_checkpoint(
            output / "checkpoints",
            saved_draft(
                scan.scan_id,
                surfaces=[malformed_surface],
                deferred=[upload_task, download_task],
            ),
        )
        os.utime(selected, ns=(210, 210))
        head = output / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": selected.name}))
        os.utime(head, ns=(220, 220))
        result = output / "result.json"
        result.write_bytes(selected.read_bytes())
        os.utime(result, ns=(230, 230))
    originals = {path: path.read_bytes() for path in output.parent.rglob("*") if path.is_file()}
    database = tmp_path / "dropped-surface.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for hash_seed in (1, 17, 83):
        interrupt_in_fresh_python(database, scan, hash_seed)
        publications.append(json.loads((scan.scan_dir / "coverage.json").read_text()))
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        completed = complete(workbench_api, connection, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert completed["progress"]["status"] == "complete"
    assert all(publication == coverage for publication in publications)
    surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert len(surfaces) == 1 and surfaces[0]["label"] == "download"
    tasks = [row for row in coverage["deferred"] if row.get("workerId") == worker_id]
    retained_upload = next(row for row in tasks if row["reason"] == upload_task["reason"])
    retained_download = next(row for row in tasks if row["reason"] == download_task["reason"])
    assert retained_upload["surfaceIds"] == []
    assert retained_download["surfaceIds"] == [surfaces[0]["id"]]
    assert any(
        raw_checkpoint.relative_to(scan.scan_dir).as_posix() in warning
        and "coverage.surfaces[0].label: expected a non-empty string" in warning
        for warning in completed["warnings"]
    )
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize(
    "history",
    ["parent-collision", "current-checkpoints", "retry-checkpoints", "coalesced-history"],
)
def test_deadline_inherited_surface_links_follow_historical_observations(
    workbench_api, workbench_db, deadline_scan, tmp_path, history
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(
        workbench_db, scan, attempt=2 if history == "retry-checkpoints" else 1
    )
    archived = output.parent / "attempts" / "attempt-01"
    first_output = archived if history == "retry-checkpoints" else output
    earlier = write_checkpoint(
        first_output / "checkpoints",
        saved_draft(scan.scan_id, surfaces=[surface("Earlier observation")]),
    )
    os.utime(earlier, ns=(100, 100))
    expected_labels = {"Earlier observation"}
    if history != "parent-collision":
        newer = write_checkpoint(
            output / "checkpoints",
            saved_draft(scan.scan_id, surfaces=[surface("Newer observation")]),
        )
        os.utime(newer, ns=(200, 200))
        expected_labels.add("Newer observation")
    inherited_task = pending("history-review", "Review the inherited surface.")
    unknown_task = pending("unknown-review", "Review an unresolved reference.", "not-declared")
    deferred_only = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, deferred=[inherited_task, unknown_task]),
    )
    os.utime(deferred_only, ns=(300, 300))
    if history == "coalesced-history":
        # The merged checkpoint copies a task whose earlier raw source inherited history.
        selected = write_checkpoint(
            output / "checkpoints",
            saved_draft(
                scan.scan_id,
                surfaces=[surface("Newer observation")],
                deferred=[inherited_task, unknown_task],
            ),
        )
        os.utime(selected, ns=(400, 400))
        head = output / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": selected.name}))
        os.utime(head, ns=(410, 410))
    if history == "current-checkpoints":
        # An interrupted later write cannot identify an earlier task's target.
        future = write_checkpoint(
            output / "checkpoints",
            saved_draft(scan.scan_id, surfaces=[surface("Later observation")]),
        )
        os.utime(future, ns=(400, 400))
    canonical_id = f"{worker_id}/entry" if history == "parent-collision" else "parent-entry"
    canonical_surface = surface("Canonical parent", canonical_id)
    canonical_task = pending("parent-review", "Parent review remains.", canonical_id)
    scan.coverage.update(surfaces=[canonical_surface], deferred=[canonical_task])
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    originals = {path: path.read_bytes() for path in output.parent.rglob("*") if path.is_file()}
    database = tmp_path / "historical-links.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for hash_seed in (1, 17, 83):
        interrupt_in_fresh_python(database, scan, hash_seed)
        publications.append(json.loads((scan.scan_dir / "coverage.json").read_text()))
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        completed = complete(workbench_api, connection, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert completed["progress"]["status"] == "complete"
    assert all(publication == coverage for publication in publications)
    assert canonical_surface in coverage["surfaces"]
    assert canonical_task in coverage["deferred"]
    worker_surfaces = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    historical = [row for row in worker_surfaces if row["label"] in expected_labels]
    assert {row["label"] for row in historical} == expected_labels
    assert len(historical) == len(expected_labels)
    if history == "current-checkpoints":
        assert any(row["label"] == "Later observation" for row in worker_surfaces)
    tasks = [row for row in coverage["deferred"] if row.get("workerId") == worker_id]
    inherited = next(row for row in tasks if row["reason"] == inherited_task["reason"])
    unknown = next(row for row in tasks if row["reason"] == unknown_task["reason"])
    assert inherited["surfaceIds"] == [row["id"] for row in historical]
    assert unknown["surfaceIds"] == [f"{worker_id}/not-declared"]
    assert {path: path.read_bytes() for path in originals} == originals


@pytest.mark.skipif(
    not hasattr(os, "fork"), reason="Crash boundary uses a forked workbench process."
)
@pytest.mark.parametrize(
    ("changed_surface_id", "legacy_duplicate_id"),
    [(False, False), (True, False), (True, True)],
    ids=["same-id", "changed-id", "legacy-duplicate-id"],
)
def test_deadline_candidate_supersession_preserves_independent_surface_links(
    workbench_api, workbench_db, deadline_scan, tmp_path, changed_surface_id, legacy_duplicate_id
):
    scan = deadline_scan
    worker_id, output = canceled_discovery_output(workbench_db, scan)
    canonical_id = f"{worker_id}/entry"
    canonical_surface = surface("Canonical parent", canonical_id)
    canonical_task = pending("parent-review", "Parent review remains.", canonical_id)
    scan.coverage.update(surfaces=[canonical_surface], deferred=[canonical_task])
    (scan.scan_dir / "coverage.json").write_text(json.dumps(scan.coverage))
    independent = pending("independent-review", "Review another caller.")
    candidate_surface = {**surface("Candidate review"), "candidateId": "candidate"}
    earlier_surfaces = [candidate_surface]
    if legacy_duplicate_id:
        # Legacy artifacts may reuse an ID for a candidate and an independent observation.
        earlier_surfaces.append(surface("Independent observation"))
    earlier = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, surfaces=earlier_surfaces, deferred=[independent]),
    )
    os.utime(earlier, ns=(100, 100))
    outcome_id = "outcome" if changed_surface_id else "entry"
    outcome = {
        **surface("Candidate reviewed", outcome_id, "rejected"),
        "candidateId": "candidate",
    }
    raw_checkpoint = write_checkpoint(
        output / "checkpoints", saved_draft(scan.scan_id, complete=True, surfaces=[outcome])
    )
    os.utime(raw_checkpoint, ns=(200, 200))
    # The selected merged checkpoint retains independent work before result publication.
    selected = write_checkpoint(
        output / "checkpoints",
        saved_draft(scan.scan_id, complete=True, surfaces=[outcome], deferred=[independent]),
    )
    os.utime(selected, ns=(210, 210))
    head = output / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": selected.name}))
    os.utime(head, ns=(220, 220))
    originals = {path: path.read_bytes() for path in output.rglob("*") if path.is_file()}
    database = tmp_path / "candidate-links.db"
    with sqlite3.connect(database) as connection:
        workbench_db.backup(connection)

    publications = []
    for hash_seed in (1, 17, 83):
        interrupt_in_fresh_python(database, scan, hash_seed)
        publications.append(json.loads((scan.scan_dir / "coverage.json").read_text()))
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        finish(workbench_api, connection, scan, terminal_reason="capped")
        completed = complete(workbench_api, connection, scan)

    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert completed["progress"]["status"] == "complete"
    assert all(publication == coverage for publication in publications)
    assert canonical_surface in coverage["surfaces"]
    assert canonical_task in coverage["deferred"]
    retained = [row for row in coverage["surfaces"] if row.get("workerId") == worker_id]
    assert len(retained) == (2 if legacy_duplicate_id else 1)
    outcome = next(row for row in retained if row["label"] == "Candidate reviewed")
    assert outcome["disposition"] == "rejected"
    if legacy_duplicate_id:
        observation = next(row for row in retained if row["label"] == "Independent observation")
        assert observation["disposition"] == "needs_follow_up"
    assert all(row["id"] != canonical_id for row in retained)
    tasks = [row for row in coverage["deferred"] if row.get("workerId") == worker_id]
    assert len(tasks) == 1 and tasks[0]["reason"] == independent["reason"]
    assert tasks[0]["surfaceIds"] == [row["id"] for row in retained]
    assert {path: path.read_bytes() for path in originals} == originals
