from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from argparse import Namespace

import pytest
from test_accepted_publication_references import accept_reducer
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_db import BUDGET_COST


@pytest.fixture
def workbench_db(workbench_schema, tmp_path):
    with sqlite3.connect(tmp_path / "real-workbench.sqlite3") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        workbench_schema.backup(connection)
        yield connection


@pytest.mark.parametrize(
    "replacement", ["none", "findings-only", "coherent-pair", "coherent-unsealed"]
)
def test_sealed_budget_replay_keeps_accepted_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, replacement
):
    scan = publication_scan()
    _, accepted, _ = accept_reducer(workbench_db, scan)
    accepted_bytes = accepted.read_bytes()
    accepted_title = json.loads(accepted_bytes)["findings"][0]["title"]
    with workbench_db:
        recipe = json.loads(workbench_db.execute("SELECT recipe_json FROM scans").fetchone()[0])
        recipe["maxCostUsd"] = 0.005
        workbench_db.execute("UPDATE scans SET recipe_json = ?", (json.dumps(recipe),))
        workbench_db.execute(
            "UPDATE deep_scan_runs SET status = 'running', workflow_version = 'deep-security-scan/v2'"
        )
    budget = workbench_api["complete_budget_exhausted_scan"]
    complete = budget.__globals__["complete_scan_locked"]
    args = Namespace(
        scan_id=scan.scan_id, cost_json=json.dumps(BUDGET_COST), message="Synthetic budget stop."
    )
    with monkeypatch.context() as patch:
        patch.setitem(
            budget.__globals__,
            "complete_scan_locked",
            lambda *a, **kw: complete(*a, **kw, prepare_only=True),
        )
        budget(workbench_db, args)
    manifest_path = scan.scan_dir / "scan-manifest.json"
    assert json.loads(manifest_path.read_text())["scan"]["sealedAt"]
    assert workbench_db.execute("SELECT status FROM scans").fetchone()[0] == "running"
    selected_before = json.loads(
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
    )
    assert selected_before["publicationSha256"]
    saved = workbench_api["saved_results"]
    actual_check = saved.require_selected_publication
    injected = []
    writer = """
import hashlib, json, sys
from pathlib import Path
root, mode = Path(sys.argv[1]), sys.argv[2]
p = root / 'findings.json'
findings = json.loads(p.read_bytes())
findings['findings'][0]['title'] = 'Synthetic replacement after accepted seal'
p.write_text(json.dumps(findings))
if mode in {'coherent-pair', 'coherent-unsealed'}:
    m = root / 'scan-manifest.json'
    manifest = json.loads(m.read_bytes())
    for artifact in manifest['scan']['artifacts']:
        if artifact['path'] == 'findings.json':
            artifact['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
    if mode == 'coherent-unsealed':
        manifest['scan'].pop('sealedAt', None)
        manifest['scan'].pop('artifacts', None)
    m.write_text(json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + chr(10))
"""

    def check_then_write(*a, **kw):
        value = actual_check(*a, **kw)
        if replacement != "none" and not injected:
            subprocess.run(
                [sys.executable, "-I", "-B", "-c", writer, str(scan.scan_dir), replacement],
                check=True,
            )
            injected.append(True)
        return value

    monkeypatch.setattr(saved, "require_selected_publication", check_then_write)
    error = None
    try:
        budget(workbench_db, args)
    except SystemExit as exc:
        error = str(exc)
    selected_after = json.loads(
        workbench_db.execute("SELECT finalization_input_json FROM deep_scan_runs").fetchone()[0]
    )
    status = workbench_db.execute("SELECT status FROM scans").fetchone()[0]
    final_title = json.loads((scan.scan_dir / "findings.json").read_bytes())["findings"][0]["title"]
    rows = [dict(r) for r in workbench_db.execute("SELECT * FROM finding_occurrences")]
    indexed_replacement = any(
        "Synthetic replacement after accepted seal" in json.dumps(r) for r in rows
    )
    assert accepted.read_bytes() == accepted_bytes
    if replacement != "none":
        assert error is not None
        assert status == "running"
        assert not rows
        assert selected_after["publicationSha256"] == selected_before["publicationSha256"]
    else:
        assert error is None
        assert status == "complete"
        assert final_title == accepted_title
        assert not indexed_replacement
        assert selected_after["publicationSha256"] == selected_before["publicationSha256"]
