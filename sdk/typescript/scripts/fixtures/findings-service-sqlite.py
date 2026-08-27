"""Assert persisted findings and embeddings in the smoke-test container."""

import json
import shutil
import sqlite3
import sys
from pathlib import Path

imported_ids = json.loads(sys.argv[1])
expected_ids = sorted(imported_ids)
scan = json.loads(Path("_bundled_plugin/examples/completed-scan/scan-manifest.json").read_text())["scan"]
with sqlite3.connect("/state/workbench.sqlite3") as db:
    assert db.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] > 0
    finding_ids = [row[0] for row in db.execute("SELECT id FROM findings ORDER BY id")]
    assert finding_ids == expected_ids, (finding_ids, expected_ids)
    embeddings = db.execute(
        "SELECT finding_id, model, vector_json FROM finding_embeddings ORDER BY finding_id"
    ).fetchall()
    assert [row[0] for row in embeddings] == expected_ids
    for finding_id, model, vector_json in embeddings:
        vector = json.loads(vector_json)
        assert model == "text-embedding-3-large", (finding_id, model)
        assert len(vector) == 1536, (finding_id, len(vector))
    associations = db.execute(
        "SELECT repository_id, finding_id FROM finding_repositories ORDER BY repository_id, finding_id"
    ).fetchall()
    assert associations == sorted(
        [(scan["target"]["targetId"], finding_id) for finding_id in imported_ids[:3]]
        + [("synthetic-other", imported_ids[3])]
    )

    if "--expect-groups" in sys.argv:
        assert db.execute("SELECT COUNT(*) FROM finding_dedupe_groups").fetchone()[0] == 1
        members = db.execute(
            "SELECT finding_id FROM finding_dedupe_group_members ORDER BY finding_id"
        ).fetchall()
        assert [row[0] for row in members] == sorted(imported_ids[:3])
        workflows = db.execute("SELECT dedupe_status, results_json FROM finding_workflows").fetchall()
        assert len(workflows) == 2
        for status, results_json in workflows:
            results = json.loads(results_json)
            assert status == "completed"
            assert results["dedupe"]["duplicateGroups"] == [imported_ids[:3]]
            assert "dedupePendingWrite" not in results
        reviews = db.execute("SELECT binding_json, result_json FROM finding_workflow_reviews").fetchall()
        models = set()
        decisions = set()
        for binding_json, result_json in reviews:
            binding = json.loads(binding_json)
            result = json.loads(result_json)
            models.add(binding["model"])
            assert binding["source"]["content"]
            assert binding["promptDigest"] and binding["contractDigest"]
            for decision in result.get("decisions", [result]):
                decisions.add(decision["decision"])
                if decision["decision"] == "SAME":
                    assert decision["mergedFinding"]["findingId"] == decision["canonicalFindingId"]
                    assert decision["mergedFinding"]["extensions"]["mergedOriginals"]
        assert models == {"gpt-5.6-luna", "gpt-5.6-sol"}
        assert decisions == {"SAME", "DISTINCT"}

    if "--prepare-scan" in sys.argv:
        source_dir = Path("/state/smoke-source")
        source_dir.mkdir(exist_ok=True)
        scan_dir = Path("/state/smoke-scan")
        shutil.copytree("_bundled_plugin/examples/completed-scan", scan_dir, dirs_exist_ok=True)
        scan_dir.chmod(0o700)
        timestamp = scan["completedAt"]
        db.execute(
            "INSERT OR IGNORE INTO workspaces (id, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000001', ?, ?)",
            (timestamp, timestamp),
        )
        db.execute(
            "INSERT OR IGNORE INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, '00000000-0000-4000-8000-000000000001', ?, 'revision', '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?, ?)",
            (scan["id"], str(source_dir), str(scan_dir), timestamp, timestamp, timestamp, timestamp),
        )
        db.execute(
            "INSERT OR IGNORE INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
            (scan["id"], timestamp),
        )

print(f"Verified {len(expected_ids)} stored findings and embeddings.")
