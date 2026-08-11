import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("loads matching findings once and compares missing findings honestly", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import argparse, json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT, target_revision TEXT, target_snapshot_digest TEXT, mode TEXT, scope TEXT, model TEXT, reasoning_effort TEXT, recipe_json TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "for index in range(3):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?)', (scan, sys.argv[2], 'complete', str(index), 'revision', 'standard' if index == 0 else 'deep', '.' if index == 0 else 'src', 'old-model' if index == 0 else 'new-model', 'medium' if index == 0 else 'high', json.dumps({'pluginVersion': '0.1.8' if index == 0 else '0.1.9', 'config': {'goals': index == 0}})))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "queries = []",
    "connection.set_trace_callback(queries.append)",
    "backfilled = []",
    "result = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda _connection, scan: backfilled.append(scan['id']), read_coverage=lambda _scan: {})",
    "finding_queries = sum('FROM finding_occurrences AS occurrences' in query for query in queries)",
    "connection.execute(\"DELETE FROM finding_occurrences WHERE scan_id != 'scan-0'\")",
    "connection.execute(\"INSERT INTO finding_locations VALUES ('scan-0', 'src/login.ts', 'root_control', 0)\")",
    "coverage = lambda scan: {'completeness': 'partial' if scan['id'] == 'scan-0' else 'complete', 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
    "scenarios = (",
    "    ('unchanged_revision', 'revision', 'revision', None, None),",
    "    ('unchanged_snapshot', 'revision', 'revision', 'snapshot-a', 'snapshot-a'),",
    "    ('unchanged_unversioned', 'unversioned', 'unversioned', 'snapshot-a', 'snapshot-a'),",
    "    ('unconfirmed_snapshot', 'revision', 'revision', None, 'snapshot-b'),",
    "    ('changed_revision', 'revision', 'changed', None, None),",
    "    ('changed_snapshot', 'revision', 'revision', 'snapshot-a', 'snapshot-b'),",
    "    ('changed_unversioned', 'unversioned', 'unversioned', 'snapshot-a', 'snapshot-b'),",
    ")",
    "comparisons = {}",
    "def compare():",
    "    return history.compare_scans(connection, argparse.Namespace(before_scan_id='scan-0', after_scan_id='scan-1'), require_scan=lambda db, scan: db.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone(), read_coverage=coverage)",
    "for name, before_revision, after_revision, before_snapshot, after_snapshot in scenarios:",
    "    connection.execute(\"UPDATE scans SET target_revision = ?, target_snapshot_digest = ? WHERE id = 'scan-0'\", (before_revision, before_snapshot))",
    "    connection.execute(\"UPDATE scans SET target_revision = ?, target_snapshot_digest = ? WHERE id = 'scan-1'\", (after_revision, after_snapshot))",
    "    comparisons[name] = compare()",
    "for occurrence, finding, scan in (('before-merged', 'merged-finding', 'scan-0'), ('after-renamed', 'replacement-finding', 'scan-1')):",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (occurrence, finding, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "    connection.execute('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', (occurrence, 'src/login.ts', 'root_control', 0))",
    "matches = {'matches': [{'beforeOccurrenceIds': ['scan-0', 'before-merged'], 'afterOccurrenceIds': ['after-renamed'], 'reason': 'Same root cause.'}], 'uncertain': []}",
    "connection.execute('INSERT INTO scan_comparisons VALUES (?, ?, ?)', ('scan-0', 'scan-1', json.dumps(matches)))",
    "comparisons['renamed_and_merged'] = compare()",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': finding_queries, 'comparisons': comparisons}))",
  ].join("\n");

  const result = spawnSync(
    python,
    [
      "-I",
      "-B",
      "-c",
      probe,
      join(PLUGIN_ROOT, "scripts"),
      join(tmpdir(), "codex-security-matching-fixture"),
    ],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toMatchObject({
    backfilled: ["scan-0", "scan-1", "scan-2"],
    findingQueries: 3,
    result: {
      scanCount: 3,
      batches: [
        { afterScanId: "scan-1", beforeScans: [{ scanId: "scan-0" }] },
        {
          afterScanId: "scan-2",
          beforeScans: [{ scanId: "scan-0" }, { scanId: "scan-1" }],
        },
      ],
    },
    comparisons: {
      unchanged_revision: {
        coverage: {
          beforeCompleteness: "partial",
          afterCompleteness: "complete",
        },
        changes: {
          pluginVersion: { before: "0.1.8", after: "0.1.9" },
          model: { before: "old-model", after: "new-model" },
          reasoningEffort: { before: "medium", after: "high" },
          config: { before: { goals: true }, after: { goals: false } },
          mode: { before: "standard", after: "deep" },
          scope: { before: ".", after: "src" },
          coverage: { before: "partial", after: "complete" },
        },
        findings: [
          expect.objectContaining({
            status: "unknown",
            reason:
              "The finding was not rediscovered, and no source change was recorded.",
          }),
        ],
        summary: { resolved: 0, unknown: 1 },
      },
      unchanged_snapshot: { summary: { resolved: 0, unknown: 1 } },
      unchanged_unversioned: { summary: { resolved: 0, unknown: 1 } },
      unconfirmed_snapshot: { summary: { resolved: 0, unknown: 1 } },
      changed_revision: { summary: { resolved: 1, unknown: 0 } },
      changed_snapshot: { summary: { resolved: 1, unknown: 0 } },
      changed_unversioned: { summary: { resolved: 1, unknown: 0 } },
      renamed_and_merged: {
        findings: [
          expect.objectContaining({
            status: "persisting",
            findingId: "replacement-finding",
            beforeFindingIds: ["merged-finding", "scan-0"],
            afterFindingIds: ["replacement-finding"],
          }),
        ],
      },
    },
  });
});
