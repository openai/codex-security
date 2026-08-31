import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { expect, test } from "bun:test";
import { resolvePluginPython } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test.skipIf(process.platform !== "win32")(
  "matches scan-root filters across Windows path aliases",
  async () => {
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
        "import workbench_scan_history as history",
        "connection = sqlite3.connect(':memory:')",
        "connection.row_factory = sqlite3.Row",
        "connection.executescript('''",
        "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT, completed_at TEXT, continuation_thread_id TEXT, cost_json TEXT, handoff_status TEXT, mode TEXT, model TEXT, parent_scan_id TEXT, phase TEXT, recipe_json TEXT, reasoning_effort TEXT, scan_dir TEXT, scope TEXT, target_revision TEXT, target_summary TEXT, updated_at TEXT, canceled_at TEXT, completion_warnings_json TEXT);",
        "CREATE TABLE scan_progress (scan_id TEXT, reportable_findings_count INTEGER, scope_file_count INTEGER, review_items_completed INTEGER, review_items_total INTEGER, updated_at TEXT);",
        "CREATE TABLE finding_occurrences (scan_id TEXT);",
        "''')",
        "connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, NULL, ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL, ?)', ('scan', 'repository', 'complete', '1', 'standard_repository', 'complete', sys.argv[2] + '/scan', '.', '1', '[]'))",
        "connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, NULL, ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL, ?)', ('sibling', 'repository', 'complete', '1', 'standard_repository', 'complete', sys.argv[2] + ' Other/scan', '.', '1', '[]'))",
        "connection.execute('INSERT INTO scan_progress VALUES (?, 0, 1, 1, 1, ?)', ('scan', '1'))",
        "args = argparse.Namespace(repository=None, scan_root=sys.argv[2].upper(), target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
        "print(json.dumps(history.list_scans(connection, args)))",
      ].join("\n");
      const result = await promisify(execFile)(
        python,
        ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts"), scanRoot],
        { encoding: "utf8", timeout: 10_000, windowsHide: true },
      );

      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toMatchObject({
        scans: [{ scanId: "scan" }],
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
