import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("loads each scan's matching findings once across historical batches", async () => {
  const python = await resolvePluginPython();

  const probe = [
    "import argparse, json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "for index in range(3):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?)', (scan, sys.argv[2], 'complete', str(index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "queries = []",
    "connection.set_trace_callback(queries.append)",
    "backfilled = []",
    "result = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda _connection, scan: backfilled.append(scan['id']), read_coverage=lambda _scan: {})",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': sum('FROM finding_occurrences AS occurrences' in query for query in queries)}))",
  ].join("\n");

  const result = await runCodexCommand(
    { command: python },
    [
      "-I",
      "-B",
      "-",
      join(PLUGIN_ROOT, "scripts"),
      join(tmpdir(), "codex-security-matching-fixture"),
    ],
    process.env,
    probe,
    AbortSignal.timeout(10_000),
  );

  expect(result.exitCode, result.stderr).toBe(0);
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
  });
});

test("loads oversized comparison matches from stdin", async () => {
  const python = await resolvePluginPython();

  const probe = [
    "import argparse, io, json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT, created_at TEXT, updated_at TEXT);",
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT);",
    "''')",
    "scans = {'before': {'id': 'before', 'status': 'complete', 'target_id': 'target', 'target_path': '/repo'}, 'after': {'id': 'after', 'status': 'complete', 'target_id': 'target', 'target_path': '/repo'}}",
    "findings = {'before': {'old': {'id': 'old'}}, 'after': {'new': {'id': 'new'}}}",
    "history._scan_findings = lambda _connection, scan_id: findings[scan_id]",
    "history.compare_scans = lambda *_args, **_kwargs: {'saved': True}",
    "payload = sys.stdin.read()",
    "sys.stdin = io.StringIO(payload)",
    "result = history.save_scan_comparison(connection, argparse.Namespace(before_scan_id='before', after_scan_id='after', matches_json=None, matches_json_stdin=True), now=lambda: 'now', require_scan=lambda _connection, scan_id: scans[scan_id], read_coverage=lambda _scan: {})",
    "print(json.dumps(result))",
  ].join("\n");
  const payload = JSON.stringify({
    matches: [
      {
        beforeOccurrenceIds: ["old"],
        afterOccurrenceIds: ["new"],
        reason: "x".repeat(64 * 1024),
      },
    ],
    uncertain: [],
  });

  const result = await runCodexCommand(
    { command: python },
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    process.env,
    payload,
    AbortSignal.timeout(10_000),
  );

  expect(result.exitCode, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual({ saved: true });
});
