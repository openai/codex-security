import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

async function runPythonProbe(
  program: string,
  ...args: string[]
): Promise<Record<string, unknown>> {
  const python = await resolvePluginPython();
  const result = await runCodexCommand(
    { command: python },
    ["-I", "-X", "utf8", "-B", "-", join(PLUGIN_ROOT, "scripts"), ...args],
    process.env,
    program,
    AbortSignal.timeout(10_000),
  );
  expect(result.exitCode, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout) as Record<string, unknown>;
}

test("keeps inline and stdin comparison transports compatible", async () => {
  const python = await resolvePluginPython();
  const probe = [
    "import json, sys",
    "sys.path.insert(0, sys.argv.pop(1))",
    "from workbench_cli import parse_args",
    "args = parse_args('Synthetic comparison transport')",
    "print(json.dumps({'matchesJson': args.matches_json, 'matchesJsonStdin': args.matches_json_stdin}))",
  ].join("\n");
  const args = [
    "-I",
    "-B",
    "-c",
    probe,
    join(PLUGIN_ROOT, "scripts"),
    "save-scan-comparison",
    "--before-scan-id",
    "before",
    "--after-scan-id",
    "after",
  ];
  const payload = JSON.stringify({
    matches: [
      {
        beforeOccurrenceIds: ["before"],
        afterOccurrenceIds: ["after"],
        confidence: "high",
        reason: "Synthetic comparison 🙂",
      },
    ],
    uncertain: [],
  });
  for (const transport of [
    {
      args: ["--matches-json", payload],
      expected: { matchesJson: payload, matchesJsonStdin: false },
    },
    {
      args: ["--matches-json-stdin"],
      expected: { matchesJson: null, matchesJsonStdin: true },
    },
  ]) {
    const result = await runCodexCommand(
      { command: python },
      [...args, ...transport.args],
      process.env,
      undefined,
      AbortSignal.timeout(10_000),
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(transport.expected);
  }
  const conflicting = await runCodexCommand(
    { command: python },
    [...args, "--matches-json", payload, "--matches-json-stdin"],
    process.env,
    payload,
    AbortSignal.timeout(10_000),
  );
  expect(conflicting.exitCode).toBe(2);
  expect(conflicting.stderr).toContain("not allowed with argument");
});

test("keeps unrelated legacy repositories out of matching inputs", async () => {
  const observed = await runPythonProbe(
    `
import argparse, json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript('''
CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, started_at TEXT);
CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);
''')
for index, (scan, repository) in enumerate([
    ('unrelated-before', 'unrelated'), ('unrelated-after', 'unrelated'),
    ('before', 'selected'), ('after', 'selected')
]):
    connection.execute('INSERT INTO scans VALUES (?, NULL, ?, ?, ?)',
                       (scan, str(Path(sys.argv[2]) / repository), 'complete', str(index)))
connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?)', [
    ('unrelated-first', 'unrelated-identity-a', 'unrelated-before'),
    ('unrelated-second', 'unrelated-identity-b', 'unrelated-after')
])
connection.execute('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)',
                   ('unrelated-before', 'unrelated-after', 'unrelated-first', 'unrelated-second'))
comparison = history.compare_scans(
    connection, argparse.Namespace(before_scan_id='before', after_scan_id='after'),
    require_scan=lambda db, scan: db.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone(),
    read_coverage=lambda _: {'completeness': 'complete'}, include_matching_inputs=True)
print(json.dumps(comparison['matchingInputs']))
`,
    join(tmpdir(), "codex-security-legacy-repositories"),
  );
  expect(observed).toEqual({ before: [], after: [] });
});

test("validates related pairs by confirmed group without replacing saved results", async () => {
  const probe = `
import argparse, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript('''
PRAGMA foreign_keys = ON;
CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT, target_id TEXT, status TEXT);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT, severity TEXT
);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (
    before_scan_id TEXT, after_scan_id TEXT, result_json TEXT, created_at TEXT, updated_at TEXT,
    PRIMARY KEY(before_scan_id, after_scan_id)
);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT,
    reason TEXT,
    FOREIGN KEY(before_scan_id, after_scan_id)
        REFERENCES scan_comparisons(before_scan_id, after_scan_id) ON DELETE CASCADE
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);
''')
for scan, names in [('before', ('a1', 'a2', 'b', 'c')), ('after', ('x1', 'x2', 'y', 'z'))]:
    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?)', (scan, sys.argv[2], 'target', 'complete'))
    for name in names:
        connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?)', (name, name, scan, name, 'high'))
        connection.execute('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', (name, 'src/example.py', 'root_control', 0))
connection.commit()
def pair(before, after):
    return {'beforeOccurrenceId': before, 'afterOccurrenceId': after, 'reason': 'Separate synthetic controls.'}
def group(before, after):
    return {'beforeOccurrenceIds': before, 'afterOccurrenceIds': after,
            'confidence': 'high', 'reason': 'The same synthetic control.'}
payload = {'matches': [group(['a1', 'a2'], ['x1', 'x2']), group(['b'], ['y'])],
           'uncertain': [], 'related': [pair('a2', 'y'), pair('c', 'z')]}
def save(value):
    return history.save_scan_comparison(
        connection, argparse.Namespace(before_scan_id='before', after_scan_id='after', matches_json=json.dumps(value)),
        now=lambda: '2026-01-01T00:00:00Z',
        require_scan=lambda db, scan: db.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone(),
        read_coverage=lambda _: {'completeness': 'complete', 'includePaths': ['src'],
                                 'excludePaths': [], 'explicitExclusions': []})
def snapshot():
    return (connection.execute('SELECT result_json FROM scan_comparisons').fetchone()[0],
            [tuple(row) for row in connection.execute('SELECT * FROM scan_comparison_matches ORDER BY before_occurrence_id, after_occurrence_id')])
accepted = save(payload)
original = snapshot()
invalid = [
    {**payload, 'related': [pair('a2', 'x2')]},
    {**payload, 'related': [pair('b', 'y')]},
    {**payload, 'related': [pair('a2', 'y'), pair('a2', 'y')]},
    {**payload, 'related': [pair('outside', 'z')]},
    {**payload, 'uncertain': [pair('c', 'z')]},
    {**payload, 'uncertain': [pair('a1', 'z')]},
    {**payload, 'uncertain': [pair('c', 'y')]},
    {**payload, 'matches': [payload['matches'][0], group(['b', 'a1'], ['y'])]},
]
for value in invalid:
    try:
        save(value)
    except SystemExit:
        pass
    else:
        raise AssertionError('Invalid comparison was accepted')
    assert snapshot() == original
print(json.dumps({'summary': accepted['summary'],
                  'related': [(item['beforeOccurrenceId'], item['afterOccurrenceId']) for item in accepted['related']],
                  'savedPairs': len(original[1])}))
`;
  expect(
    await runPythonProbe(
      probe,
      join(tmpdir(), "codex-security-validation-fixture"),
    ),
  ).toEqual({
    summary: { new: 1, persisting: 2, reopened: 0, resolved: 1, unknown: 0 },
    related: [
      ["a2", "y"],
      ["c", "z"],
    ],
    savedPairs: 5,
  });
});

test("upgrades existing history with indexed identity and reverse comparison lookups", async () => {
  const probe = `
import json, sqlite3, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from finalize_scan_contract import _derived_finding_identity_rows
from workbench_schema import MIGRATIONS, apply_migrations
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.execute('PRAGMA foreign_keys = ON')
timestamp = '2026-01-01T00:00:00Z'
def migrate(migrations):
    apply_migrations(connection, migrations, lambda: timestamp, lambda _: None)
migrate(tuple(item for item in MIGRATIONS if item[0] < 31))
connection.execute('INSERT INTO security_targets VALUES (?, ?, ?, ?, ?)', ('target', sys.argv[2], 'Synthetic target', timestamp, timestamp))
connection.execute('INSERT INTO workspaces (id, target_id, created_at, updated_at) VALUES (?, ?, ?, ?)', ('workspace', 'target', timestamp, timestamp))
connection.executemany('''INSERT INTO scans (
    id, workspace_id, target_id, target_path, target_revision, scope, mode, scan_dir,
    status, phase, started_at, created_at, updated_at
) VALUES (?, 'workspace', 'target', ?, 'unversioned', '.', 'standard', ?, 'complete', 'reporting', ?, ?, ?)''', (
    (f'scan-{index:03d}', sys.argv[2], str(Path(sys.argv[2]) / f'scan-{index:03d}'), timestamp, timestamp, timestamp)
    for index in range(200)
))
connection.executemany('INSERT INTO scan_comparisons VALUES (?, ?, ?, ?, ?)', (
    (f'scan-{before:03d}', f'scan-{after:03d}', json.dumps({'matches': [], 'uncertain': []}), timestamp, timestamp)
    for after in range(200) for before in range(after)
))
def rows():
    return [tuple(row) for row in connection.execute('SELECT * FROM scan_comparisons ORDER BY before_scan_id, after_scan_id')]
original = rows()
migrate(MIGRATIONS)
migrate(MIGRATIONS)
query = '''SELECT before_scan_id, after_scan_id, result_json FROM scan_comparisons
    WHERE before_scan_id = ? OR after_scan_id = ? ORDER BY before_scan_id, after_scan_id'''
plan = [row['detail'] for row in connection.execute('EXPLAIN QUERY PLAN ' + query, ('scan-100', 'scan-100'))]
identity_plan = [row['detail'] for row in connection.execute(
    'EXPLAIN QUERY PLAN SELECT id FROM finding_occurrences WHERE finding_id = ?', ('synthetic-finding',))]
indexes = {
    name: [row['name'] for row in connection.execute(f'PRAGMA index_info({name})')]
    for name in ('finding_occurrences_by_finding', 'scan_comparisons_by_after_scan')
}
def identity(target, scan):
    finding = {'ruleId': 'synthetic-control', 'identity': {'anchor': 'synthetic-control'}}
    return _derived_finding_identity_rows(
        {'scan': {'id': scan, 'target': {'targetId': target}}},
        {'scanId': scan, 'findings': [finding]})[0][2:4]
first_identity = identity('target', 'first')
recurring_identity = identity('target', 'second')
other_identity = identity('another-target', 'third')
print(json.dumps({'unchanged': rows() == original, 'comparisons': len(original),
                  'plan': plan, 'identityPlan': identity_plan, 'indexes': indexes,
                  'stableIdentity': first_identity[0] == recurring_identity[0],
                  'distinctOccurrences': first_identity[1] != recurring_identity[1],
                  'targetScopedIdentity': first_identity[0] != other_identity[0],
                  'foreignKeyErrors': len(connection.execute('PRAGMA foreign_key_check').fetchall())}))
`;
  const observed = (await runPythonProbe(
    probe,
    join(tmpdir(), "codex-security-index-fixture"),
  )) as {
    plan: string[];
    identityPlan: string[];
  };
  expect(observed).toMatchObject({
    unchanged: true,
    comparisons: 19_900,
    foreignKeyErrors: 0,
    stableIdentity: true,
    distinctOccurrences: true,
    targetScopedIdentity: true,
    indexes: {
      finding_occurrences_by_finding: ["finding_id", "id"],
      scan_comparisons_by_after_scan: ["after_scan_id", "before_scan_id"],
    },
  });
  expect(observed.plan.some((step) => step.includes("before_scan_id=?"))).toBe(
    true,
  );
  expect(observed.plan.some((step) => step.includes("after_scan_id=?"))).toBe(
    true,
  );
  expect(
    observed.plan.some((step) => step.startsWith("SCAN scan_comparisons")),
  ).toBe(false);
  expect(
    observed.identityPlan.some((step) =>
      step.includes("finding_occurrences_by_finding"),
    ),
  ).toBe(true);
});

test("loads each scan once and scopes saved links to uncached history", async () => {
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
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);",
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
    "finding_queries = sum('FROM finding_occurrences AS occurrences' in query for query in queries)",
    "connection.executemany('INSERT INTO scan_comparisons VALUES (?, ?)', [('scan-0', 'scan-1'), ('scan-0', 'scan-2'), ('scan-1', 'scan-2')])",
    "queries.clear()",
    "cached = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda *_: None, read_coverage=lambda _scan: {})",
    "cached_link_queries = sum('FROM scan_comparison_matches' in query for query in queries)",
    "for name in ('foreign-a', 'foreign-b'):",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (name, name, name, '{}', 'fix', 'high', 'summary', 'title'))",
    "connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)', [('scan-0', 'scan-1', 'scan-0', 'scan-1'), ('foreign-a', 'foreign-b', 'foreign-a', 'foreign-b')])",
    "queries.clear()",
    "scoped = history._saved_finding_links(connection, {'scan-0', 'scan-1'})",
    "link_queries = [query for query in queries if 'FROM scan_comparison_matches' in query]",
    "for index in (3, 4):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, NULL, ?, ?)', (scan, sys.argv[2], 'complete', str(index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, f'scan-{index - 3}', scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "def coverage(scan):",
    "    if scan['id'] in {'scan-0', 'scan-1', 'scan-2'}:",
    "        raise SystemExit('Synthetic unavailable artifacts')",
    "    return {}",
    "unavailable = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=False), backfill_finding_details=lambda *_: None, read_coverage=coverage)",
    "forced = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=sys.argv[2], force=True), backfill_finding_details=lambda *_: None, read_coverage=coverage)",
    "connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)', [('scan-1', 'scan-2', 'scan-1', 'scan-2'), ('scan-2', 'scan-0', 'scan-2', 'scan-0'), ('scan-0', 'foreign-a', 'scan-0', 'foreign-a'), ('foreign-a', 'scan-1', 'foreign-a', 'scan-1')])",
    "limited = hasattr(connection, 'setlimit')",
    "if limited:",
    "    old_limit = connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 2)",
    "queries.clear()",
    "batched = history._saved_finding_links(connection, {'scan-2', 'scan-0', 'scan-1'})",
    "batched_queries = len(queries)",
    "if limited:",
    "    connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, old_limit)",
    "queries.clear()",
    "empty = history._saved_finding_links(connection, set())",
    "print(json.dumps({",
    "    'result': result, 'backfilled': backfilled, 'findingQueries': finding_queries,",
    "    'cached': cached, 'cachedLinkQueries': cached_link_queries,",
    "    'scopedLinks': [dict(row) for row in scoped], 'scopedQueryCount': len(link_queries),",
    "    'unscopedQueries': sum('WHERE matches.before_scan_id' not in query for query in link_queries),",
    "    'unavailable': unavailable, 'forcedKnownGroups': [batch.get('knownFindingGroups') for batch in forced['batches']],",
    "    'batchedLinks': [[row['before_scan_id'], row['after_scan_id']] for row in batched],",
    "    'batchedQueryCount': batched_queries, 'expectedBatchedQueryCount': 2 if limited else 1,",
    "    'emptyLinks': empty, 'emptyQueryCount': len(queries),",
    "}))",
  ].join("\n");

  const observed = await runPythonProbe(
    probe,
    join(tmpdir(), "codex-security-matching-fixture"),
  );
  expect(observed).toMatchObject({
    backfilled: ["scan-0", "scan-1", "scan-2"],
    findingQueries: 3,
    cached: { batches: [], skippedPairs: 3 },
    cachedLinkQueries: 0,
    scopedLinks: [{ before_finding_id: "scan-0", after_finding_id: "scan-1" }],
    scopedQueryCount: 1,
    unscopedQueries: 0,
    batchedLinks: [
      ["scan-0", "scan-1"],
      ["scan-1", "scan-2"],
      ["scan-2", "scan-0"],
    ],
    emptyLinks: [],
    emptyQueryCount: 0,
    unavailable: {
      scanCount: 5,
      unavailableScans: 3,
      batches: [
        {
          afterScanId: "scan-4",
          beforeScans: [{ scanId: "scan-3" }],
          knownFindingGroups: [["scan-0", "scan-1"]],
        },
      ],
    },
    forcedKnownGroups: [null],
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
  expect(observed["batchedQueryCount"]).toBe(
    observed["expectedBatchedQueryCount"],
  );
});

test("reconciles cached statuses without losing grouped coverage or uncertainty", async () => {
  const probe = `
import argparse, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript('''
CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT, target_id TEXT, status TEXT);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT, severity TEXT
);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (
    before_scan_id TEXT, after_scan_id TEXT, result_json TEXT,
    PRIMARY KEY(before_scan_id, after_scan_id)
);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);
''')
for scan in ('before', 'after', 'later', 'latest'):
    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?)', (scan, sys.argv[2], 'target', 'complete'))
for scan, names in [('before', ('a1', 'a2')), ('after', ('b1', 'b2')),
                    ('later', ('c1', 'c2')), ('latest', ('d1',))]:
    for name in names:
        severity = 'low' if name.endswith('1') else 'high'
        path = 'src/excluded.py' if name == 'a1' else 'src/covered.py'
        connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?)', (name, name, scan, name, severity))
        connection.execute('INSERT INTO finding_locations VALUES (?, ?, ?, ?)', (name, path, 'root_control', 0))
def link(before, after):
    connection.execute('''INSERT INTO scan_comparison_matches
        SELECT previous.scan_id, current.scan_id, previous.id, current.id
        FROM finding_occurrences AS previous, finding_occurrences AS current
        WHERE previous.id = ? AND current.id = ?''', (before, after))
for before, after in [('a1', 'c1'), ('a2', 'c1'), ('b1', 'c2'), ('b2', 'c2')]:
    link(before, after)
payload = {
    'matches': [],
    'uncertain': [{'beforeOccurrenceId': 'a1', 'afterOccurrenceId': 'b1', 'reason': 'Synthetic uncertainty.'}],
    'related': [{'beforeOccurrenceId': 'a2', 'afterOccurrenceId': 'b2', 'reason': 'Separate synthetic controls.'}]
}
def cache():
    connection.execute('INSERT OR REPLACE INTO scan_comparisons VALUES (?, ?, ?)', ('before', 'after', json.dumps(payload)))
coverage = {'completeness': 'complete', 'includePaths': ['src'],
            'excludePaths': ['src/excluded.py'], 'explicitExclusions': []}
def compare():
    return history.compare_scans(
        connection, argparse.Namespace(before_scan_id='before', after_scan_id='after'),
        require_scan=lambda db, scan: db.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone(),
        read_coverage=lambda _: coverage, require_matches=True)
cache()
uncertain = compare()
payload['uncertain'] = []
cache()
excluded = compare()
coverage['excludePaths'] = []
resolved = compare()
connection.execute('INSERT INTO finding_triage VALUES (?, ?, ?)', ('a1', 'closed', 'already_fixed'))
link('c1', 'd1')
link('c2', 'd1')
linked = compare()
unchanged = json.loads(connection.execute('SELECT result_json FROM scan_comparisons').fetchone()[0]) == payload
connection.execute("DELETE FROM scan_comparison_matches WHERE after_scan_id = 'latest'")
restored = compare()
print(json.dumps({'uncertain': uncertain, 'excluded': excluded, 'resolved': resolved,
                  'linked': linked, 'unchanged': unchanged, 'restored': restored}))
`;
  const observed = await runPythonProbe(
    probe,
    join(tmpdir(), "codex-security-comparison-fixture"),
  );
  expect(observed).toMatchObject({
    uncertain: {
      summary: { new: 0, resolved: 0, unknown: 2 },
      findings: [
        {
          findingId: "a2",
          beforeOccurrenceIds: ["a1", "a2"],
          severity: "high",
          status: "unknown",
          reason: "Synthetic uncertainty.",
        },
        {
          findingId: "b2",
          afterOccurrenceIds: ["b1", "b2"],
          status: "unknown",
          reason: "Synthetic uncertainty.",
        },
      ],
    },
    excluded: { summary: { new: 1, resolved: 0, unknown: 1 } },
    resolved: { summary: { new: 1, resolved: 1, unknown: 0 } },
    linked: {
      summary: { new: 0, persisting: 0, reopened: 1, resolved: 0, unknown: 0 },
      findings: [
        {
          beforeOccurrenceIds: ["a1", "a2"],
          afterOccurrenceIds: ["b1", "b2"],
          matchReason: expect.any(String),
          status: "reopened",
        },
      ],
    },
    unchanged: true,
  });
  expect(observed["linked"]).not.toHaveProperty("related");
  expect(observed["restored"]).toEqual(observed["resolved"]);
});

test("loads displayed relations in bulk and follows current confirmed identities", async () => {
  const probe = `
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript('''
CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT);
CREATE INDEX scans_by_target ON scans(target_id, id);
CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT,
    UNIQUE(scan_id, finding_id)
);
CREATE INDEX occurrences_by_finding ON finding_occurrences(finding_id, id);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT
);
CREATE INDEX matches_before ON scan_comparison_matches(before_occurrence_id);
CREATE INDEX matches_after ON scan_comparison_matches(after_occurrence_id);
''')
connection.executemany('INSERT INTO scans VALUES (?, ?)', [
    ('one', 'target'), ('two', 'target'), ('three', 'clone'),
    ('four', 'clone'), ('foreign-one', 'unrelated-target'),
    ('foreign-two', 'unrelated-target')
])
connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', (
    (f'{side}-{index}', f'{side}-identity-{index}', scan, f'Synthetic {side} {index}')
    for index in range(10_000)
    for side, scan in [('left', 'one'), ('right', 'two')]
))
payload = json.dumps({'matches': [], 'uncertain': [], 'related': [
    {'beforeOccurrenceId': f'left-{index}', 'afterOccurrenceId': f'right-{index}',
     'reason': 'Separate synthetic controls.'}
    for index in range(10_000)
]})
connection.execute('INSERT INTO scan_comparisons VALUES (?, ?, ?)', ('one', 'two', payload))
queries = []
connection.set_trace_callback(queries.append)
scoped = history.finding_relations(connection, 'one', ['left-0'])
scoped_queries = len(queries)
queries.clear()
empty = history.finding_relations(connection, 'one', [])
empty_queries = len(queries)
connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', [
    ('recurring-left', 'left-identity-0', 'four', 'Recurring control'),
    ('bridge', 'bridge-identity', 'three', 'Renamed control'),
    ('foreign-a', 'foreign-identity-a', 'foreign-one', 'Unrelated A'),
    ('foreign-b', 'foreign-identity-b', 'foreign-two', 'Unrelated B')
])
connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)', [
    ('four', 'three', 'recurring-left', 'bridge'),
    ('two', 'three', 'right-0', 'bridge'),
    ('foreign-one', 'foreign-two', 'foreign-a', 'foreign-b')
])
aliases = history._confirmed_finding_aliases(connection, ['left-0'])
forward = history.finding_relations(connection, 'one', ['left-0'])
reverse = history.finding_relations(connection, 'two', ['right-0'])
remaining = history.finding_relations(connection, 'one', ['left-1'])
unchanged = connection.execute('SELECT result_json FROM scan_comparisons').fetchone()[0] == payload
connection.execute('DELETE FROM scan_comparison_matches WHERE before_occurrence_id = ?', ('right-0',))
restored = history.finding_relations(connection, 'one', ['left-0']) == scoped

limited = hasattr(connection, 'setlimit')
if limited:
    old_limit = connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 8)
queries.clear()
batched = history.finding_relations(connection, 'one', [f'left-{index}' for index in range(1, 11)])
batched_queries = len(queries)
if limited:
    connection.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, old_limit)

class LegacyConnection:
    def execute(self, *args):
        return connection.execute(*args)

queries.clear()
legacy_rows = list(history._rows_for_ids(
    LegacyConnection(), 'SELECT id FROM finding_occurrences WHERE id IN ({placeholders})',
    (f'left-{index}' for index in range(1001))
))
print(json.dumps({
    'scoped': scoped, 'scopedQueries': scoped_queries, 'empty': empty,
    'emptyQueries': empty_queries, 'aliases': sorted(aliases), 'forward': forward,
    'reverse': reverse, 'remaining': sorted(remaining), 'unchanged': unchanged,
    'restoredAfterUnlink': restored,
    'batchedCount': len(batched), 'batchedQueries': batched_queries,
    'expectedBatchedQueries': 6 if limited else 3,
    'legacyCount': len(legacy_rows), 'legacyQueries': len(queries)
}))
`;
  const observed = await runPythonProbe(probe);
  expect(observed).toMatchObject({
    scoped: {
      "left-0": [{ occurrenceId: "right-0", scanId: "two" }],
    },
    scopedQueries: 3,
    empty: {},
    emptyQueries: 0,
    aliases: ["bridge-identity", "left-identity-0", "right-identity-0"],
    forward: {},
    reverse: {},
    remaining: ["left-1"],
    unchanged: true,
    restoredAfterUnlink: true,
    batchedCount: 10,
    legacyCount: 1001,
    legacyQueries: 2,
  });
  expect(observed["batchedQueries"]).toBe(observed["expectedBatchedQueries"]);
});

test("includes recurring stable identities in confirmed finding history", async () => {
  const observed = await runPythonProbe(`
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_scan_history import finding_matches
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
connection.executescript('''
CREATE TABLE scans (id TEXT PRIMARY KEY, started_at TEXT);
CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT, title TEXT);
CREATE TABLE scan_comparison_matches (
    before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT
);
''')
scans = [('a', 'a'), ('b', 'b'), ('c', 'c'), ('a-repeat', 'a'), ('c-repeat', 'c'), ('unlinked', 'unlinked')]
for index, (scan, finding) in enumerate(scans):
    connection.execute('INSERT INTO scans VALUES (?, ?)', (scan, str(index)))
    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', (scan, finding, scan, scan))
connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?, ?)', [
    ('a', 'b', 'a', 'b', 'First confirmed link.'),
    ('b', 'c', 'b', 'c', 'Second confirmed link.')
])
def collect_history():
    result = {}
    for index, (scan, finding) in enumerate(scans):
        matches, first, bounds = finding_matches(connection, scan, scan, str(index))
        result[scan] = {'linked': [match['occurrenceId'] for match in matches], 'first': first, 'bounds': bounds}
        for match in matches:
            assert match['reason']
            if scan == 'a' and match['occurrenceId'] == 'b':
                assert match['reason'] == 'First confirmed link.'
    return result
with_links = collect_history()
connection.execute('DELETE FROM scan_comparison_matches')
print(json.dumps({'withLinks': with_links, 'withoutLinks': collect_history()}))
`);
  expect(observed).toEqual({
    withLinks: {
      a: {
        linked: ["a-repeat", "b", "c", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      b: {
        linked: ["a", "a-repeat", "c", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      c: {
        linked: ["a", "a-repeat", "b", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      "a-repeat": {
        linked: ["a", "b", "c", "c-repeat"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      "c-repeat": {
        linked: ["a", "a-repeat", "b", "c"],
        first: "0",
        bounds: ["a", "c-repeat"],
      },
      unlinked: { linked: [], first: "5", bounds: ["unlinked"] },
    },
    withoutLinks: {
      a: { linked: ["a-repeat"], first: "0", bounds: ["a", "a-repeat"] },
      "a-repeat": { linked: ["a"], first: "0", bounds: ["a", "a-repeat"] },
      b: { linked: [], first: "1", bounds: ["b"] },
      c: { linked: ["c-repeat"], first: "2", bounds: ["c", "c-repeat"] },
      "c-repeat": { linked: ["c"], first: "2", bounds: ["c", "c-repeat"] },
      unlinked: { linked: [], first: "5", bounds: ["unlinked"] },
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
        confidence: "high",
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
