import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("loads each scan's matching findings once across historical batches", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import argparse, json, sqlite3, sys",
    "from pathlib import Path",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "repository = str(Path(sys.argv[2]).resolve())",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, started_at TEXT, completed_at TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('target', repository))",
    "for index in range(3):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)', (scan, repository, 'target', 'complete', f'2026-08-01T0{index}:00:00Z', f'2026-08-01T0{index + 3}:00:00Z'))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "queries = []",
    "connection.set_trace_callback(queries.append)",
    "backfilled = []",
    "result = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=False), backfill_finding_details=lambda _connection, scan: backfilled.append(scan['id']), read_coverage=lambda _scan: {})",
    "finding_queries = sum('FROM finding_occurrences AS occurrences' in query for query in queries)",
    "def planned(focus=None):",
    "    value = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=False, after_scan_id=focus), backfill_finding_details=lambda *_: None, read_coverage=lambda _: {})",
    "    return {'batches': [{'after': batch['afterScanId'], 'before': [scan['scanId'] for scan in batch['beforeScans']]} for batch in value['batches']], 'skipped': value['skippedPairs']}",
    "connection.execute(\"UPDATE scans SET status = 'running', completed_at = NULL WHERE id = 'scan-0'\")",
    "later_completed_first = planned('scan-2')",
    "connection.execute(\"UPDATE scans SET status = 'complete', completed_at = '2026-08-01T06:00:00Z' WHERE id = 'scan-0'\")",
    "earlier_completed_last = planned('scan-0')",
    "excludes_later_completion = planned('scan-2')",
    "def automatic_pairs():",
    "    return [[before, batch['after']] for index in range(3) for batch in planned(f'scan-{index}')['batches'] for before in batch['before']]",
    "completion_pairs = automatic_pairs()",
    "connection.execute(\"INSERT INTO scan_comparisons VALUES ('scan-2', 'scan-0')\")",
    "reverse_cached, chronological = planned('scan-0'), planned()",
    "connection.execute('DELETE FROM scan_comparisons')",
    "connection.execute(\"UPDATE scans SET completed_at = CASE id WHEN 'scan-0' THEN NULL WHEN 'scan-1' THEN '2026-08-01T05:00:00+01:00' ELSE '2026-08-01T04:00:00Z' END\")",
    "legacy = dict(connection.execute(\"SELECT * FROM scans WHERE id = 'scan-0'\").fetchone())",
    "legacy_without_completed = {key: value for key, value in legacy.items() if key != 'completed_at'}",
    "print(json.dumps({'result': result, 'backfilled': backfilled, 'findingQueries': finding_queries, 'laterCompletedFirst': later_completed_first, 'earlierCompletedLast': earlier_completed_last, 'excludesLaterCompletion': excludes_later_completion, 'completionPairs': completion_pairs, 'reverseCached': reverse_cached, 'chronological': chronological, 'tiedPairs': automatic_pairs(), 'legacyFallback': history._scan_completion_order(legacy) == history._scan_completion_order(legacy_without_completed)}))",
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

  expect(result.status, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toMatchObject({
    backfilled: ["scan-0", "scan-1", "scan-2"],
    findingQueries: 3,
    laterCompletedFirst: {
      batches: [{ after: "scan-2", before: ["scan-1"] }],
      skipped: 0,
    },
    earlierCompletedLast: {
      batches: [{ after: "scan-0", before: ["scan-1", "scan-2"] }],
      skipped: 0,
    },
    excludesLaterCompletion: {
      batches: [{ after: "scan-2", before: ["scan-1"] }],
      skipped: 0,
    },
    completionPairs: [
      ["scan-1", "scan-0"],
      ["scan-2", "scan-0"],
      ["scan-1", "scan-2"],
    ],
    tiedPairs: [
      ["scan-0", "scan-1"],
      ["scan-0", "scan-2"],
      ["scan-1", "scan-2"],
    ],
    legacyFallback: true,
    reverseCached: {
      batches: [{ after: "scan-0", before: ["scan-1"] }],
      skipped: 1,
    },
    chronological: {
      batches: [
        { after: "scan-1", before: ["scan-0"] },
        { after: "scan-2", before: ["scan-1"] },
      ],
      skipped: 1,
    },
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
