import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

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

test("loads oversized comparison matches from stdin", async () => {
  const python = await resolvePluginPython();

  const probe = [
    "import argparse, sqlite3, sys",
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
    "history.compare_scans = lambda *_args, **_kwargs: {}",
    "history.save_scan_comparison(connection, argparse.Namespace(before_scan_id='before', after_scan_id='after', matches_json=None, matches_json_stdin=True), now=lambda: 'now', require_scan=lambda _connection, scan_id: scans[scan_id], read_coverage=lambda _scan: {})",
    "print(connection.execute('SELECT result_json FROM scan_comparisons').fetchone()[0])",
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
    AbortSignal.timeout(10_000),
  );

  expect(result.exitCode, result.stderr).toBe(0);
  expect(result.stderr).toBe("");
  expect(JSON.parse(result.stdout)).toEqual(JSON.parse(payload));
});
