// Prepare a synthetic saved scan in the runner, separate from service storage.
import { execFileSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { ScanManifest } from "../../src/models.js";

const packageRoot = "/usr/local/lib/node_modules/@openai/codex-security";
const exampleDir = join(packageRoot, "_bundled_plugin/examples/completed-scan");
const { scan } = JSON.parse(
  readFileSync(join(exampleDir, "scan-manifest.json"), "utf8"),
) as ScanManifest;
writeFileSync("/state/runner-marker", "synthetic runner state\n");
// Keep database initialization and migrations in the existing workbench.
const { databasePath } = JSON.parse(
  execFileSync(
    "python3",
    [
      "-I",
      "-B",
      join(packageRoot, "_bundled_plugin/scripts/workbench_db.py"),
      "database-info",
    ],
    { encoding: "utf8" },
  ),
) as { databasePath: string };
const db = new DatabaseSync(databasePath);
try {
  db.exec("PRAGMA busy_timeout = 5000");
  const sourceDir = "/output/repository";
  mkdirSync(sourceDir, { recursive: true });
  const scanDir = "/output/smoke-scan";
  cpSync(exampleDir, scanDir, { recursive: true });
  chmodSync(scanDir, 0o700);
  const timestamp = scan.completedAt!;
  db.exec("BEGIN");
  db.prepare(
    "INSERT OR IGNORE INTO workspaces (id, created_at, updated_at) VALUES ('00000000-0000-4000-8000-000000000001', ?, ?)",
  ).run(timestamp, timestamp);
  db.prepare(
    "INSERT OR IGNORE INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, completed_at, created_at, updated_at) VALUES (?, '00000000-0000-4000-8000-000000000001', ?, 'revision', '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?, ?)",
  ).run(
    scan.id,
    sourceDir,
    scanDir,
    timestamp,
    timestamp,
    timestamp,
    timestamp,
  );
  db.prepare(
    "INSERT OR IGNORE INTO scan_progress (scan_id, updated_at) VALUES (?, ?)",
  ).run(scan.id, timestamp);
  db.exec("COMMIT");
} finally {
  db.close();
}
