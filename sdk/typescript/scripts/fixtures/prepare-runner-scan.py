"""Prepare a synthetic saved scan in the runner, separate from service storage."""

import json
import shutil
import sys
from pathlib import Path

package = Path("/usr/local/lib/node_modules/@openai/codex-security")
sys.path.insert(0, str(package / "_bundled_plugin/scripts"))
from workbench_db import connect

scan = json.loads((package / "_bundled_plugin/examples/completed-scan/scan-manifest.json").read_text())["scan"]
Path("/state/runner-marker").write_text("synthetic runner state\n")
with connect() as db:
    source_dir = Path("/output/repository")
    source_dir.mkdir(exist_ok=True)
    scan_dir = Path("/output/smoke-scan")
    shutil.copytree(package / "_bundled_plugin/examples/completed-scan", scan_dir, dirs_exist_ok=True)
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
