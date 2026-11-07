import { join } from "node:path";
import { expect, onTestFinished, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

function testProbe(name: string, run: (signal: AbortSignal) => Promise<void>) {
  test.serial(name, () => {
    const controller = new AbortController();
    onTestFinished(() => controller.abort());
    return run(controller.signal).catch((error) => {
      // Bun already reported the timeout if teardown aborted the probe.
      if (!controller.signal.aborted) throw error;
    });
  });
}

async function runPythonProbe(
  program: string,
  signal: AbortSignal,
): Promise<unknown> {
  const python = await resolvePluginPython({ signal });
  const result = await runCodexCommand(
    { command: python },
    ["-I", "-X", "utf8", "-B", "-", join(PLUGIN_ROOT, "scripts")],
    process.env,
    program,
    signal,
  );
  expect(result.exitCode, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  return JSON.parse(result.stdout);
}

testProbe("accepts comparison matches inline or over stdin", async (signal) => {
  const python = await resolvePluginPython({ signal });
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
      signal,
    );
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(transport.expected);
  }
  const conflicting = await runCodexCommand(
    { command: python },
    [...args, "--matches-json", payload, "--matches-json-stdin"],
    process.env,
    payload,
    signal,
  );
  expect(conflicting.exitCode).toBe(2);
  expect(conflicting.stderr).toContain("not allowed with argument");
});

testProbe(
  "never matches independently registered sibling repository targets",
  async (signal) => {
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
      "        CREATE TABLE scans (id TEXT, target_path TEXT, target_id TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT, mode TEXT, target_snapshot_digest TEXT, status TEXT, started_at TEXT);",
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
      "        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (scan, str(path), target, serialize_filesystem_identity(metadata.st_dev), serialize_filesystem_identity(metadata.st_ino), 'revision', 'standard', 'digest', 'complete', '2026-01-01'))",
      "        connection.execute('INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (scan, scan, scan, '{}', 'fix', 'high', 'summary', 'title'))",
      "    results = [history.list_unmatched_scan_pairs(connection, argparse.Namespace(repository=str(repository), force=force), backfill_finding_details=lambda *_args: None, read_coverage=lambda _scan: {}) for force in (False, True)]",
      "    print(json.dumps({'results': results}))",
    ].join("\n");

    const observed = (await runPythonProbe(probe, signal)) as Record<
      string,
      unknown
    >;
    for (const matching of observed["results"] as unknown[]) {
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
  },
);

testProbe(
  "lists completed scans in insertion order after clock rollback",
  async (signal) => {
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
      "print(json.dumps({'scanIds': [scan['scanId'] for scan in history.list_scans(connection)['scans']]}))",
    ].join("\n");

    expect(await runPythonProbe(probe, signal)).toEqual({
      scanIds: ["running", "newer", "older"],
    });
  },
);

testProbe(
  "orders finding-detail history by scan insertion after clock rollback",
  async (signal) => {
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

    expect(await runPythonProbe(probe, signal)).toMatchObject({
      knownSince: "2026-02-01",
      knownScanIds: ["older-scan", "newer-scan"],
    });
  },
);

testProbe(
  "compares registered scan history after its checkout moves",
  async (signal) => {
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

    expect(await runPythonProbe(probe, signal)).toBe(true);
  },
);

testProbe(
  "finds registered ancestors beyond isolated targetless child scans",
  async (signal) => {
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

    expect(await runPythonProbe(probe, signal)).toEqual({
      direct: ["current-owner"],
      nested: ["current-owner"],
      standaloneGit: ["legacy-git-child"],
      standaloneDirectory: ["legacy-directory-child"],
    });
  },
);

testProbe(
  "includes linked worktrees and recognizes separately verified clones",
  async (signal) => {
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

    expect(await runPythonProbe(probe, signal)).toEqual({
      targets: ["clone", "linked", "main"],
      clone: true,
      untrusted: false,
      unregistered: [],
    });
  },
);

testProbe("loads oversized comparison matches from stdin", async (signal) => {
  const python = await resolvePluginPython({ signal });

  const probe = [
    "import argparse, io, json, pathlib, sqlite3, sys, tempfile",
    "sys.path.insert(0, sys.argv[1])",
    "from filesystem_identity import serialize_filesystem_identity",
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
    "scans = {name: {'id': name, 'status': 'complete', 'target_id': 'target', 'target_path': str(repository), 'target_device': serialize_filesystem_identity(metadata.st_dev), 'target_inode': serialize_filesystem_identity(metadata.st_ino)} for name in ('before', 'after')}",
    "findings = {'before': {'old': {'id': 'old'}}, 'after': {'new': {'id': 'new'}}}",
    "history._scan_findings = lambda _connection, scan_id: findings[scan_id]",
    "history.compare_scans = lambda *_args, **_kwargs: {'saved': True}",
    "payload = sys.stdin.read()",
    "sys.stdin = io.StringIO(payload)",
    "result = history.save_scan_comparison(connection, argparse.Namespace(before_scan_id='before', after_scan_id='after', matches_json=None, matches_json_stdin=True), now=lambda: 'now', require_scan=lambda _connection, scan_id: scans[scan_id], read_coverage=lambda _scan: {}, finding_triage=lambda _connection, _scan, _through_scan: {})",
    "print(json.dumps(result))",
  ].join("\n");
  const payload = JSON.stringify({
    matches: [
      {
        beforeOccurrenceIds: ["old"],
        afterOccurrenceIds: ["new"],
        confidence: "high",
        reason: "x".repeat(64 * 1024) + "🙂",
      },
    ],
    uncertain: [],
  });

  const result = await runCodexCommand(
    { command: python },
    ["-I", "-X", "utf8", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    process.env,
    payload,
    signal,
  );

  expect(result.exitCode, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual({ saved: true });
});
