import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, test } from "bun:test";
import { resolvePluginPython } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("matches scan-root filters including Windows path aliases", async () => {
  const python = await resolvePluginPython();

  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-scan-root-case-")),
  );
  const scanRoot = join(root, "Scan History");
  mkdirSync(scanRoot);
  try {
    const probe = [
      "import argparse, json, sqlite3, sys",
      "sys.path.insert(0, sys.argv[1])",
      "from workbench_db import apply_migrations",
      "import workbench_scan_history as history",
      "connection = sqlite3.connect(':memory:')",
      "connection.row_factory = sqlite3.Row",
      "connection.execute('PRAGMA foreign_keys = ON')",
      "apply_migrations(connection)",
      "connection.execute('INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)', ('workspace', '1', '1'))",
      "for scan_id, scan_dir in [('scan', sys.argv[2] + '/scan'), ('sibling', sys.argv[2] + ' Other/scan')]:",
      "    connection.execute('INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan_id, 'workspace', 'repository', 'revision', '.', 'standard', scan_dir, 'complete', 'reporting', '1', '1', '1'))",
      "    connection.execute('INSERT INTO scan_progress (scan_id, scope_file_count, review_items_completed, review_items_total, updated_at) VALUES (?, 1, 1, 1, ?)', (scan_id, '1'))",
      "args = argparse.Namespace(repository=None, scan_root=sys.argv[3], target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
      "print(json.dumps(history.list_scans(connection, args)))",
    ].join("\n");
    const result = await promisify(execFile)(
      python,
      [
        "-I",
        "-B",
        "-c",
        probe,
        join(PLUGIN_ROOT, "scripts"),
        scanRoot,
        process.platform === "win32" ? scanRoot.toUpperCase() : scanRoot,
      ],
      { encoding: "utf8", timeout: 10_000, windowsHide: true },
    );

    expect(result.stderr).toBe("");
    expect(JSON.parse(result.stdout)).toMatchObject({
      scans: [{ scanId: "scan" }],
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
