import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

type ComparisonSettings = {
  revisions?: [string, string];
  snapshots?: [string | null, string | null];
  models?: [string | null, string | null];
  efforts?: [string | null, string | null];
  recipes?: [Record<string, unknown> | null, Record<string, unknown> | null];
  coverage?: [string, string];
  matchedFindingId?: string;
};

function compareScans(
  settings: ComparisonSettings = {},
): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");

  const fixture = {
    revisions: settings.revisions ?? ["revision", "revision"],
    snapshots: settings.snapshots ?? [null, null],
    models: settings.models ?? [null, null],
    efforts: settings.efforts ?? [null, null],
    recipes: settings.recipes ?? [null, null],
    coverage: settings.coverage ?? ["complete", "complete"],
    matchedFindingId: settings.matchedFindingId ?? null,
  };
  const probe = [
    "import argparse, json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "fixture = json.loads(sys.argv[2])",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, status TEXT, target_revision TEXT, target_snapshot_digest TEXT, mode TEXT, scope TEXT, model TEXT, reasoning_effort TEXT, recipe_json TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "for index, scan in enumerate(('before', 'after')):",
    "    recipe = fixture['recipes'][index]",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan, '/repository', 'target', 'complete', fixture['revisions'][index], fixture['snapshots'][index], 'standard', '.', fixture['models'][index], fixture['efforts'][index], json.dumps(recipe) if recipe is not None else None))",
    "connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', ('before-finding', 'finding', 'before', '{}', 'fix', 'high', 'summary', 'Missing access control'))",
    "connection.execute('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', ('before-finding', 'src/login.ts', 'root_control', 0))",
    "if fixture['matchedFindingId'] is not None:",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', ('after-finding', fixture['matchedFindingId'], 'after', '{}', 'fix', 'high', 'summary', 'Missing access control'))",
    "    connection.execute('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', ('after-finding', 'src/login.ts', 'root_control', 0))",
    "    matches = {'matches': [{'beforeOccurrenceIds': ['before-finding'], 'afterOccurrenceIds': ['after-finding'], 'reason': 'Same root cause.'}], 'uncertain': []}",
    "    connection.execute('INSERT INTO scan_comparisons VALUES (?, ?, ?)', ('before', 'after', json.dumps(matches)))",
    "def read_coverage(scan):",
    "    return {'completeness': fixture['coverage'][scan['id'] == 'after'], 'includePaths': ['.'], 'excludePaths': [], 'explicitExclusions': []}",
    "result = history.compare_scans(connection, argparse.Namespace(before_scan_id='before', after_scan_id='after'), require_scan=lambda db, scan: db.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone(), read_coverage=read_coverage)",
    "print(json.dumps(result))",
  ].join("\n");

  const result = spawnSync(
    python,
    [
      "-I",
      "-B",
      "-c",
      probe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify(fixture),
    ],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

test.each([
  ["unchanged Git revision", ["commit-a", "commit-a"], [null, null]],
  [
    "unchanged dirty working tree",
    ["commit-a", "commit-a"],
    ["snapshot-a", "snapshot-a"],
  ],
  [
    "unchanged unversioned directory",
    ["unversioned", "unversioned"],
    ["snapshot-a", "snapshot-a"],
  ],
  [
    "unconfirmed working-tree change",
    ["commit-a", "commit-a"],
    [null, "snapshot-a"],
  ],
] as const)(
  "does not resolve a missing finding on an %s",
  (_case, revisions, snapshots) => {
    const result = compareScans({
      revisions: [...revisions],
      snapshots: [...snapshots],
    });

    expect(result["summary"]).toMatchObject({ resolved: 0, unknown: 1 });
    expect(result["findings"]).toEqual([
      expect.objectContaining({
        status: "unknown",
        reason:
          "The finding was not rediscovered, and no source change was recorded.",
      }),
    ]);
  },
);

test.each([
  ["new Git revision", ["commit-a", "commit-b"], [null, null]],
  [
    "changed dirty working tree",
    ["commit-a", "commit-a"],
    ["snapshot-a", "snapshot-b"],
  ],
  [
    "changed unversioned directory",
    ["unversioned", "unversioned"],
    ["snapshot-a", "snapshot-b"],
  ],
] as const)(
  "resolves a missing finding after a %s",
  (_case, revisions, snapshots) => {
    const result = compareScans({
      revisions: [...revisions],
      snapshots: [...snapshots],
    });

    expect(result["summary"]).toMatchObject({ resolved: 1, unknown: 0 });
    expect(result["findings"]).toEqual([
      expect.objectContaining({ status: "resolved" }),
    ]);
  },
);

test("shows changed scanner settings and scan coverage", () => {
  const before = {
    pluginVersion: "0.1.8",
    config: { features: { goals: true } },
  };
  const after = {
    pluginVersion: "0.1.9",
    config: { features: { goals: false } },
  };
  const result = compareScans({
    models: ["gpt-5.6-luna", "gpt-5.6-sol"],
    efforts: ["medium", "high"],
    recipes: [before, after],
    coverage: ["partial", "complete"],
  });

  expect(result["coverage"]).toEqual({
    beforeCompleteness: "partial",
    afterCompleteness: "complete",
  });
  expect(result["changes"]).toEqual({
    pluginVersion: { before: "0.1.8", after: "0.1.9" },
    model: { before: "gpt-5.6-luna", after: "gpt-5.6-sol" },
    reasoningEffort: { before: "medium", after: "high" },
    config: { before: before.config, after: after.config },
    coverage: { before: "partial", after: "complete" },
  });
});

test("shows changed finding identities for the same root cause", () => {
  const result = compareScans({ matchedFindingId: "replacement-finding" });

  expect(result["findings"]).toEqual([
    expect.objectContaining({
      status: "persisting",
      findingId: "replacement-finding",
      beforeFindingIds: ["finding"],
      afterFindingIds: ["replacement-finding"],
    }),
  ]);
});

test("loads each scan's matching findings once across historical batches", () => {
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
  });
});
