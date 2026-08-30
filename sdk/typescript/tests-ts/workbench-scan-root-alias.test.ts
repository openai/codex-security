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
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import workbench_scan_history as history",
        "from windows_paths import extended_path",
        "connection = sqlite3.connect(':memory:')",
        "connection.row_factory = sqlite3.Row",
        "connection.executescript('''",
        "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT, completed_at TEXT, continuation_thread_id TEXT, cost_json TEXT, handoff_status TEXT, mode TEXT, model TEXT, parent_scan_id TEXT, phase TEXT, recipe_json TEXT, reasoning_effort TEXT, scan_dir TEXT, scope TEXT, target_revision TEXT, target_summary TEXT, updated_at TEXT, canceled_at TEXT, completion_warnings_json TEXT);",
        "CREATE TABLE scan_progress (scan_id TEXT, reportable_findings_count INTEGER, scope_file_count INTEGER, review_items_completed INTEGER, review_items_total INTEGER, updated_at TEXT);",
        "CREATE TABLE finding_occurrences (scan_id TEXT);",
        "''')",
        "connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, NULL, ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL, ?)', ('scan', 'repository', 'complete', '1', 'standard_repository', 'complete', sys.argv[2] + '/scan', '.', '1', '[]'))",
        "connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, NULL, ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL, ?)', ('legacy', 'repository', 'complete', '1', 'standard_repository', 'complete', str(extended_path(Path(sys.argv[2]) / 'legacy')), '.', '1', '[]'))",
        "connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?, NULL, NULL, NULL, NULL, ?, NULL, NULL, ?, NULL, NULL, ?, ?, NULL, NULL, ?, NULL, ?)', ('sibling', 'repository', 'complete', '1', 'standard_repository', 'complete', sys.argv[2] + ' Other/scan', '.', '1', '[]'))",
        "connection.executemany('INSERT INTO scan_progress VALUES (?, 0, 1, 1, 1, ?)', [(name, '1') for name in ['scan', 'legacy', 'sibling']])",
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
        scans: [{ scanId: "legacy" }, { scanId: "scan" }],
      });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);

test.skipIf(process.platform !== "win32")(
  "archives a scan when only its previous sibling needs extended paths",
  async () => {
    const python = await resolvePluginPython();
    const root = realpathSync(mkdtempSync(join(tmpdir(), "codex-archive-")));
    try {
      const probe = [
        "import argparse, json, sqlite3, sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "from windows_paths import filesystem_path, WINDOWS_DIRECTORY_PATH_LIMIT",
        "from workbench_scan_start import archive_scan",
        "root = Path(sys.argv[2])",
        "padding = WINDOWS_DIRECTORY_PATH_LIMIT - 1 - len('\\\\scan') - len(str(root).encode('utf-16-le')) // 2 - 1",
        "assert padding > 0, 'temporary root leaves no room for the path-length boundary'",
        "parent = root / ('p' * padding)",
        "scan_dir = parent / 'scan'",
        "archived_dir = parent / ('scan.previous-' + 'a' * 32)",
        "scan_dir.mkdir(parents=True)",
        "filesystem_path(archived_dir).mkdir()",
        "assert filesystem_path(scan_dir) == scan_dir",
        "assert filesystem_path(archived_dir) != archived_dir",
        "connection = sqlite3.connect(':memory:')",
        "connection.row_factory = sqlite3.Row",
        "connection.executescript('CREATE TABLE scans (id TEXT, status TEXT, scan_dir TEXT, updated_at TEXT); CREATE TABLE scan_artifacts (scan_id TEXT, kind TEXT, path TEXT);')",
        "connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?)', ('scan', 'complete', str(scan_dir), 'before'))",
        "connection.execute('INSERT INTO scan_artifacts VALUES (?, ?, ?)', ('scan', 'findings', str(filesystem_path(scan_dir / 'findings.json'))))",
        "args = argparse.Namespace(archive_existing=True, archived_scan_dir=str(archived_dir))",
        "archive_scan(connection, args, scan_dir, 'after', lambda path: filesystem_path(path).resolve(strict=True))",
        "assert connection.execute('SELECT scan_dir FROM scans').fetchone()[0] == str(archived_dir)",
        "assert connection.execute('SELECT path FROM scan_artifacts').fetchone()[0] == str(archived_dir / 'findings.json')",
        "print(json.dumps({'archived': True}))",
      ].join("\n");
      const result = await promisify(execFile)(
        python,
        ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts"), root],
        { encoding: "utf8", timeout: 10_000, windowsHide: true },
      );
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toEqual({ archived: true });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
