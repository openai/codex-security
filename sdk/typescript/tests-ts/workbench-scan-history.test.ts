import { spawnSync } from "node:child_process";
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

test("keeps unrelated registered repositories out of matching inputs", async () => {
  const observed = await runPythonProbe(
    `
import argparse, json, os, sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
from filesystem_identity import serialize_filesystem_identity
def fixture_triage(db, scan):
    return {row["id"]: {"status": row["triage_status"], "closeReason": row["close_reason"]}
            for row in history._scan_findings(db, scan["id"]).values()}
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
directory = tempfile.TemporaryDirectory(prefix='codex-security-history-fixture-')
repository = os.path.realpath(directory.name)
metadata = os.stat(repository)
identity = (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino))
connection.executescript('''
CREATE TABLE security_targets (id TEXT, current_path TEXT);
CREATE TABLE scans (id TEXT PRIMARY KEY, target_id TEXT, target_path TEXT, status TEXT, started_at TEXT, target_device INTEGER, target_inode INTEGER);
CREATE TABLE finding_occurrences (id TEXT PRIMARY KEY, finding_id TEXT, scan_id TEXT);
CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);
CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);
''')
for target in ('selected', 'unrelated'):
    path = Path(repository) / target
    path.mkdir()
    connection.execute('INSERT INTO security_targets VALUES (?, ?)', (target, str(path)))
for index, (scan, target) in enumerate([
    ('unrelated-before', 'unrelated'), ('unrelated-after', 'unrelated'),
    ('before', 'selected'), ('after', 'selected')
]):
    path = Path(repository) / target
    metadata = path.stat()
    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (scan, target, str(path), 'complete', str(index), serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino)))
connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?)', [
    ('unrelated-first', 'unrelated-identity-a', 'unrelated-before'),
    ('unrelated-second', 'unrelated-identity-b', 'unrelated-after')
])
connection.execute('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)',
                   ('unrelated-before', 'unrelated-after', 'unrelated-first', 'unrelated-second'))
comparison = history.compare_scans(
    connection, argparse.Namespace(before_scan_id='before', after_scan_id='after'),
    require_scan=lambda db, scan: db.execute('SELECT * FROM scans WHERE id = ?', (scan,)).fetchone(),
    finding_triage=fixture_triage, read_coverage=lambda _: {'completeness': 'complete'}, include_matching_inputs=True)
print(json.dumps(comparison['matchingInputs']))
`,
    join(tmpdir(), "codex-security-legacy-repositories"),
  );
  expect(observed).toEqual({ before: [], after: [] });
});

test("validates related pairs by confirmed group without replacing saved results", async () => {
  const probe = `
import argparse, json, os, sqlite3, sys, tempfile
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
from filesystem_identity import serialize_filesystem_identity
def fixture_triage(db, scan):
    return {row["id"]: {"status": row["triage_status"], "closeReason": row["close_reason"]}
            for row in history._scan_findings(db, scan["id"]).values()}
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
directory = tempfile.TemporaryDirectory(prefix='codex-security-history-fixture-')
repository = os.path.realpath(directory.name)
metadata = os.stat(repository)
identity = (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino))
connection.executescript('''
PRAGMA foreign_keys = ON;
CREATE TABLE security_targets (id TEXT, current_path TEXT);
CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT, target_id TEXT, status TEXT, target_device INTEGER, target_inode INTEGER);
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
connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('target', repository))
for scan, names in [('before', ('a1', 'a2', 'b', 'c')), ('after', ('x1', 'x2', 'y', 'z'))]:
    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)', (scan, repository, 'target', 'complete', *identity))
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
        finding_triage=fixture_triage, read_coverage=lambda _: {'completeness': 'complete', 'includePaths': ['src'],
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

test("loads each scan once after clock rollback and scopes saved links to uncached history", async () => {
  const probe = [
    "import argparse, json, os, sqlite3, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "directory = tempfile.TemporaryDirectory(prefix='codex-security-matching-fixture-')",
    "repository = os.path.realpath(directory.name)",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT, status TEXT, started_at TEXT);",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "''')",
    "metadata = os.stat(repository)",
    "identity = (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino))",
    "connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('owned-target', repository))",
    "for index in range(3):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, repository, 'owned-target', *identity, 'unversioned', 'complete', str(2 - index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "queries = []",
    "connection.set_trace_callback(queries.append)",
    "backfilled = []",
    "result = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=False), backfill_finding_details=lambda _connection, scan: backfilled.append(scan['id']), read_coverage=lambda _scan: {})",
    "finding_queries = sum('FROM finding_occurrences AS occurrences' in query for query in queries)",
    "connection.executemany('INSERT INTO scan_comparisons VALUES (?, ?)', [('scan-0', 'scan-1'), ('scan-0', 'scan-2'), ('scan-1', 'scan-2')])",
    "queries.clear()",
    "cached = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=False), backfill_finding_details=lambda *_: None, read_coverage=lambda _scan: {})",
    "cached_link_queries = sum('FROM scan_comparison_matches' in query for query in queries)",
    "for name in ('foreign-a', 'foreign-b'):",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (name, name, name, '{}', 'fix', 'high', 'summary', 'title'))",
    "connection.executemany('INSERT INTO scan_comparison_matches VALUES (?, ?, ?, ?)', [('scan-0', 'scan-1', 'scan-0', 'scan-1'), ('foreign-a', 'foreign-b', 'foreign-a', 'foreign-b')])",
    "queries.clear()",
    "scoped = history._saved_finding_links(connection, {'scan-0', 'scan-1'})",
    "link_queries = [query for query in queries if 'FROM scan_comparison_matches' in query]",
    "for index in (3, 4):",
    "    scan = f'scan-{index}'",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, repository, 'owned-target', *identity, 'unversioned', 'complete', str(index)))",
    "    connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, f'scan-{index - 3}', scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "def coverage(scan):",
    "    if scan['id'] in {'scan-0', 'scan-1', 'scan-2'}:",
    "        raise SystemExit('Synthetic unavailable artifacts')",
    "    return {}",
    "unavailable = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=False), backfill_finding_details=lambda *_: None, read_coverage=coverage)",
    "forced = history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=repository, force=True), backfill_finding_details=lambda *_: None, read_coverage=coverage)",
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
import argparse, json, os, sqlite3, sys, tempfile
sys.path.insert(0, sys.argv[1])
import workbench_scan_history as history
from filesystem_identity import serialize_filesystem_identity
def fixture_triage(db, scan):
    return {row["id"]: {"status": row["triage_status"], "closeReason": row["close_reason"]}
            for row in history._scan_findings(db, scan["id"]).values()}
connection = sqlite3.connect(':memory:')
connection.row_factory = sqlite3.Row
directory = tempfile.TemporaryDirectory(prefix='codex-security-history-fixture-')
repository = os.path.realpath(directory.name)
metadata = os.stat(repository)
identity = (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino))
connection.executescript('''
CREATE TABLE security_targets (id TEXT, current_path TEXT);
CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT, target_id TEXT, status TEXT, target_device INTEGER, target_inode INTEGER);
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
connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('target', repository))
for scan in ('before', 'after', 'later', 'latest'):
    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)', (scan, repository, 'target', 'complete', *identity))
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
        finding_triage=fixture_triage, read_coverage=lambda _: coverage, require_matches=True)
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
from workbench_scan_history import finding_matches, _confirmed_finding_aliases
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
        aliases = _confirmed_finding_aliases(connection, (scan,))
        identity = aliases.get(finding, finding)
        occurrence_ids = {row["id"] for row in connection.execute("SELECT id, finding_id FROM finding_occurrences") if aliases.get(row["finding_id"], row["finding_id"]) == identity}
        matches, first, bounds = finding_matches(connection, scan, occurrence_ids)
        bounds = [bounds[0], bounds[-1]] if len(bounds) > 1 else bounds
        result[scan] = {'linked': sorted(match['occurrenceId'] for match in matches), 'first': first, 'bounds': bounds}
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

test("never matches independently registered sibling repository targets", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import argparse, json, os, pathlib, sqlite3, subprocess, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "with tempfile.TemporaryDirectory() as temporary:",
    "    repository = pathlib.Path(temporary).resolve() / 'repository'",
    "    subprocess.run(['git', 'init', '-q', str(repository)], check=True)",
    "    left, right = repository / 'left', repository / 'right'",
    "    left.mkdir(); right.mkdir()",
    "    connection = sqlite3.connect(':memory:')",
    "    connection.row_factory = sqlite3.Row",
    "    connection.executescript('''",
    "        CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "        CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT, status TEXT, started_at TEXT);",
    "        CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT);",
    "        CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT);",
    "        CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, details_json TEXT, remediation TEXT, severity TEXT, summary TEXT, title TEXT);",
    "        CREATE TABLE finding_triage (occurrence_id TEXT, status TEXT, close_reason TEXT);",
    "        CREATE TABLE finding_locations (occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);",
    "    ''')",
    "    for target, path in [('left-target', left), ('right-target', right)]:",
    "        connection.execute('INSERT INTO security_targets VALUES (?, ?)', (target, str(path)))",
    "    for scan, target, path in [('left-old', 'left-target', left), ('right', 'right-target', right), ('left-new', 'left-target', left)]:",
    "        metadata = path.stat()",
    "        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, str(path), target, serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), 'revision', 'complete', '2026-01-01'))",
    "        connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
    "    results = [history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=str(repository), force=force), backfill_finding_details=lambda *_args: None, read_coverage=lambda _scan: {}) for force in (False, True)]",
    "    print(json.dumps(results))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status, result.stderr).toBe(0);
  for (const matching of JSON.parse(result.stdout)) {
    expect(matching).toMatchObject({
      scanCount: 3,
      batches: [
        {
          afterScanId: "left-new",
          beforeScans: [{ scanId: "left-old" }],
        },
      ],
    });
  }
});

test("lists completed scans in insertion order after clock rollback", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "import workbench_schema as schema",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "schema.apply_migrations(connection, schema.MIGRATIONS, lambda: '2026-01-01', lambda _connection: None)",
    "connection.execute(\"INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', '2026-01-01', '2026-01-01')\")",
    "for scan, status, started in [('older', 'complete', '2026-02-01'), ('newer', 'complete', '2026-01-01'), ('running', 'running', '2025-12-01')]:",
    "    connection.execute('INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan, 'workspace', '/repository', 'revision', '.', 'standard', '/scans/' + scan, status, 'reporting', started, started, started))",
    "    connection.execute('INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)', (scan, started))",
    "print(json.dumps([scan['scanId'] for scan in history.list_scans(connection)['scans']]))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual(["running", "newer", "older"]);
});

test("orders finding-detail history by scan insertion after clock rollback", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, sqlite3, sys",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE scans (id TEXT, started_at TEXT);",
    "CREATE TABLE finding_occurrences (id TEXT, finding_id TEXT, scan_id TEXT, title TEXT);",
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT);",
    "''')",
    "connection.executemany('INSERT INTO scans VALUES (?, ?)', [('older-scan', '2026-02-01'), ('newer-scan', '2026-01-01')])",
    "connection.executemany('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?)', [('older-occurrence', 'finding', 'older-scan', 'Older'), ('newer-occurrence', 'finding', 'newer-scan', 'Newer')])",
    "connection.execute(\"INSERT INTO scan_comparison_matches VALUES ('older-scan', 'newer-scan', 'older-occurrence', 'newer-occurrence', 'Same finding')\")",
    "matches, known_since, scan_ids = history.finding_matches(connection, 'newer-occurrence', {'older-occurrence', 'newer-occurrence'})",
    "print(json.dumps({'knownSince': known_since, 'knownScanIds': scan_ids, 'matches': matches}))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toMatchObject({
    knownSince: "2026-02-01",
    knownScanIds: ["older-scan", "newer-scan"],
  });
});

test("compares registered scan history after its checkout moves", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, os, pathlib, sqlite3, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "with tempfile.TemporaryDirectory() as temporary:",
    "    old = pathlib.Path(temporary) / 'old-checkout'",
    "    old.mkdir()",
    "    identity = os.stat(old)",
    "    moved = pathlib.Path(temporary) / 'moved-checkout'",
    "    old.rename(moved)",
    "    connection = sqlite3.connect(':memory:')",
    "    connection.row_factory = sqlite3.Row",
    "    connection.execute('CREATE TABLE security_targets (id TEXT, current_path TEXT)')",
    "    connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('owned-target', str(moved)))",
    "    rows = [connection.execute('SELECT ? AS target_id, ? AS target_path, ? AS target_device, ? AS target_inode', ('owned-target', str(path), serialize_filesystem_identity(identity.st_dev), serialize_filesystem_identity(identity.st_ino))).fetchone() for path in (old, moved)]",
    "    print(json.dumps(history._same_registered_repository(connection, *rows)))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8" },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toBe(true);
});

test("finds registered ancestors beyond isolated targetless child scans", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import argparse, json, os, pathlib, sqlite3, subprocess, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "import workbench_schema as schema",
    "from filesystem_identity import serialize_filesystem_identity",
    "temporary = tempfile.TemporaryDirectory()",
    "temporary_root = pathlib.Path(temporary.name).resolve()",
    "child = pathlib.Path(sys.argv[1]).resolve()",
    "intermediate = child.parent",
    "owner = intermediate.parent",
    "sibling = owner / 'src'",
    "git_root = temporary_root / 'git-repository'",
    "subprocess.run(['git', 'init', '-q', str(git_root)], check=True)",
    "git_parent = git_root / 'legacy'",
    "git_child = git_parent / 'nested'",
    "git_child.mkdir(parents=True)",
    "directory_parent = temporary_root / 'directory'",
    "directory_child = directory_parent / 'nested'",
    "directory_child.mkdir(parents=True)",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "schema.apply_migrations(connection, schema.MIGRATIONS, lambda: '2026-01-01', lambda _connection: None)",
    "connection.execute(\"INSERT INTO workspaces (id, created_at, updated_at) VALUES ('workspace', '2026-01-01', '2026-01-01')\")",
    "for target_id, path in [('registered-owner', owner), ('independent-sibling', sibling)]:",
    "    connection.execute('INSERT INTO security_targets (id, current_path, display_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', (target_id, str(path), target_id, '2026-01-01', '2026-01-01'))",
    "def identity(path):",
    "    metadata = path.stat()",
    "    return (serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino))",
    "scans = [",
    "    ('recycled-owner', 'registered-owner', owner, identity(owner)),",
    "    ('previous-owner', 'registered-owner', owner, (-1, -1)),",
    "    ('current-owner', 'registered-owner', owner, identity(owner)),",
    "    ('sibling-scan', 'independent-sibling', sibling, identity(sibling)),",
    "    ('legacy-intermediate', None, intermediate, (None, None)),",
    "    ('legacy-child', None, child, (None, None)),",
    "    ('legacy-git-parent', None, git_parent, (None, None)),",
    "    ('legacy-git-child', None, git_child, (None, None)),",
    "    ('legacy-directory-parent', None, directory_parent, (None, None)),",
    "    ('legacy-directory-child', None, directory_child, (None, None)),",
    "]",
    "for scan, target_id, path, filesystem in scans:",
    "    connection.execute('INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at, target_id, target_device, target_inode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan, 'workspace', str(path), 'revision', '.', 'standard', '/scans/' + scan, 'complete', 'reporting', '2026-01-01', '2026-01-01', '2026-01-01', target_id, *filesystem))",
    "    connection.execute('INSERT INTO scan_progress (scan_id, updated_at) VALUES (?, ?)', (scan, '2026-01-01'))",
    "def listed(path):",
    "    args = argparse.Namespace(repository=str(path), scan_root=None, target_id=None, mode=None, status=None, query=None, limit=None, offset=0)",
    "    return [scan['scanId'] for scan in history.list_scans(connection, args)['scans']]",
    "result = {'direct': listed(intermediate), 'nested': listed(child), 'standaloneGit': listed(git_child), 'standaloneDirectory': listed(directory_child)}",
    "temporary.cleanup()",
    "print(json.dumps(result))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );

  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    direct: ["current-owner"],
    nested: ["current-owner"],
    standaloneGit: ["legacy-git-child"],
    standaloneDirectory: ["legacy-directory-child"],
  });
});

test("includes linked worktrees and recognizes separately verified clones", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = [
    "import json, os, pathlib, sqlite3, subprocess, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "from filesystem_identity import serialize_filesystem_identity",
    "with tempfile.TemporaryDirectory() as temporary:",
    "    root = pathlib.Path(temporary).resolve() / 'repository'",
    "    linked = pathlib.Path(temporary).resolve() / 'linked-worktree'",
    "    clone = pathlib.Path(temporary).resolve() / 'repository-clone'",
    "    unregistered = pathlib.Path(temporary).resolve() / 'unregistered-clone'",
    "    subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True)",
    "    (root / 'source.py').write_text('print(1)\\n')",
    "    subprocess.run(['git', '-C', str(root), 'add', 'source.py'], check=True)",
    "    subprocess.run(['git', '-C', str(root), '-c', 'user.name=Inventory Test', '-c', 'user.email=inventory@example.test', 'commit', '-qm', 'initial'], check=True)",
    "    subprocess.run(['git', '-C', str(root), 'worktree', 'add', '-q', '-b', 'linked', str(linked)], check=True)",
    "    subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', 'https://github.com/example/project.git'], check=True)",
    "    subprocess.run(['git', 'clone', '-q', str(root), str(clone)], check=True)",
    "    subprocess.run(['git', '-C', str(clone), 'remote', 'set-url', 'origin', 'git@github.com:example/project.git'], check=True)",
    "    subprocess.run(['git', 'clone', '-q', str(root), str(unregistered)], check=True)",
    "    subprocess.run(['git', '-C', str(unregistered), 'remote', 'set-url', 'origin', 'git@github.com:example/project.git'], check=True)",
    "    nested = root / 'src'",
    "    nested.mkdir()",
    "    connection = sqlite3.connect(':memory:')",
    "    connection.row_factory = sqlite3.Row",
    "    connection.executescript('CREATE TABLE security_targets (id TEXT, current_path TEXT); CREATE TABLE scans (id TEXT, target_id TEXT, target_path TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT, started_at TEXT);')",
    "    for target_id, target in [('main', root), ('linked', linked), ('clone', clone)]:",
    "        metadata = target.stat()",
    "        connection.execute('INSERT INTO security_targets VALUES (?, ?)', (target_id, str(target)))",
    "        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)', (target_id, target_id, str(target), serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), 'revision', '2026-01-01'))",
    "    connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)', ('local-legacy', None, str(nested), None, None, 'revision', '2026-01-02'))",
    "    _, _, target_ids, _ = history.repository_scan_scope(connection, nested)",
    "    scans = [connection.execute('SELECT * FROM scans WHERE id = ?', (target_id,)).fetchone() for target_id in ('main', 'clone')]",
    "    untrusted = connection.execute(\"SELECT '' AS target_id, ? AS target_path\", (str(unregistered),)).fetchone()",
    "    _, _, unregistered_targets, _ = history.repository_scan_scope(connection, unregistered)",
    "    print(json.dumps({'targets': sorted(target_ids), 'clone': history._same_repository(*scans, require_ownership=True), 'untrusted': history._same_repository(scans[0], untrusted), 'unregistered': unregistered_targets}))",
  ].join("\n");

  const result = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8" },
  );

  expect(result.status).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual({
    targets: ["clone", "linked", "main"],
    clone: true,
    untrusted: false,
    unregistered: [],
  });
});

test("loads oversized comparison matches from stdin", async () => {
  const python = await resolvePluginPython();

  const probe = [
    "import argparse, io, json, pathlib, sqlite3, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "import workbench_scan_history as history",
    "connection = sqlite3.connect(':memory:')",
    "connection.row_factory = sqlite3.Row",
    "connection.executescript('''",
    "CREATE TABLE scan_comparisons (before_scan_id TEXT, after_scan_id TEXT, result_json TEXT, created_at TEXT, updated_at TEXT);",
    "CREATE TABLE scan_comparison_matches (before_scan_id TEXT, after_scan_id TEXT, before_occurrence_id TEXT, after_occurrence_id TEXT, reason TEXT);",
    "CREATE TABLE security_targets (id TEXT, current_path TEXT);",
    "''')",
    "temporary = tempfile.TemporaryDirectory()",
    "repository = pathlib.Path(temporary.name).resolve()",
    "metadata = repository.stat()",
    "connection.execute('INSERT INTO security_targets VALUES (?, ?)', ('target', str(repository)))",
    "connection.commit()",
    "scans = {name: {'id': name, 'status': 'complete', 'target_id': 'target', 'target_path': str(repository), 'target_device': metadata.st_dev, 'target_inode': metadata.st_ino} for name in ('before', 'after')}",
    "findings = {'before': {'old': {'id': 'old'}}, 'after': {'new': {'id': 'new'}}}",
    "history._scan_findings = lambda _connection, scan_id: findings[scan_id]",
    "history.compare_scans = lambda *_args, **_kwargs: {'saved': True}",
    "payload = sys.stdin.read()",
    "sys.stdin = io.StringIO(payload)",
    "result = history.save_scan_comparison(connection, argparse.Namespace(before_scan_id='before', after_scan_id='after', matches_json=None, matches_json_stdin=True), now=lambda: 'now', require_scan=lambda _connection, scan_id: scans[scan_id], read_coverage=lambda _scan: {}, finding_triage=lambda _connection, _scan: {})",
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
