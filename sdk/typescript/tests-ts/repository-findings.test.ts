import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("combines repository findings without reviving dismissed aliases", async () => {
  const python = await resolvePluginPython();

  const probe = `
import argparse, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_native_indexes as indexes

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.executescript("""
CREATE TABLE security_targets(id TEXT, current_path TEXT, display_name TEXT);
CREATE TABLE scans(id TEXT, target_id TEXT, scope TEXT, updated_at TEXT, status TEXT, started_at TEXT, target_path TEXT, seal_manifest_digest TEXT, scan_dir TEXT, target_device INTEGER, target_inode INTEGER, target_revision TEXT);
CREATE TABLE finding_occurrences(id TEXT, finding_id TEXT, severity TEXT, created_at TEXT, scan_id TEXT, title TEXT, summary TEXT);
CREATE TABLE finding_triage(occurrence_id TEXT PRIMARY KEY, status TEXT, updated_at TEXT, close_reason TEXT);
CREATE TABLE finding_decisions(occurrence_id TEXT);
CREATE TABLE finding_locations(occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparison_matches(before_occurrence_id TEXT, after_occurrence_id TEXT);
CREATE TABLE scan_comparisons(before_scan_id TEXT, after_scan_id TEXT, result_json TEXT);
INSERT INTO security_targets VALUES('first', '/first', 'First'), ('second', '/second', 'Second');
""")
def add_scan(scan_id, target, day):
    timestamp = f"2026-01-{day:02d}T00:00:00Z"
    connection.execute("INSERT INTO scans (id, target_id, scope, updated_at, status, started_at, target_path) VALUES (?, ?, ?, ?, ?, ?, ?)", (scan_id, target, "repository", timestamp, "complete", timestamp, "/" + target))

def add_finding(occurrence, finding, scan):
    started = connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan,)).fetchone()[0]
    connection.execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)", (occurrence, finding, "high", started, scan, finding, "Summary"))
    connection.execute("INSERT INTO finding_locations VALUES (?, ?, ?, ?)", (occurrence, "src/auth.py", "root_control", 0))

def add_decision(occurrence, status, timestamp, close_reason):
    connection.execute("INSERT INTO finding_triage VALUES (?, ?, ?, ?) ON CONFLICT(occurrence_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at, close_reason = excluded.close_reason", (occurrence, status, timestamp, close_reason))
    connection.execute("INSERT INTO finding_decisions VALUES (?)", (occurrence,))

for scan_id, target, day in [("old", "first", 1), ("same", "first", 2), ("renamed", "first", 3), ("latest", "first", 4), ("other", "second", 4)]:
    add_scan(scan_id, target, day)
for occurrence, finding, scan in [("old-occurrence", "dismissed", "old"), ("same-occurrence", "dismissed", "same"), ("renamed-occurrence", "renamed", "renamed"), ("latest-occurrence", "renamed-again", "latest"), ("historical-occurrence", "historical", "old"), ("other-occurrence", "dismissed", "other")]:
    add_finding(occurrence, finding, scan)
connection.executemany("INSERT INTO scan_comparison_matches VALUES (?, ?)", [("same-occurrence", "renamed-occurrence"), ("renamed-occurrence", "latest-occurrence"), ("latest-occurrence", "other-occurrence")])
add_decision("latest-occurrence", "closed", "2026-01-01T12:00:00Z", "false_positive")

def findings(target, status="open"):
    arguments = argparse.Namespace(limit=20, offset=0, query=None, severity=None, status=status, target_id=target)
    return indexes.list_global_findings(connection, arguments, read_coverage=lambda _scan: {"completeness": "partial"})["findings"]

result = {"dismissed": findings("first"), "other": findings("second"), "closed": findings("first", None)}
add_decision("latest-occurrence", "open", "2025-12-31T00:00:00Z", None)
result["reopened"] = findings("first")
add_scan("clean", "first", 7)
result["not_revalidated"] = findings("first")
add_decision("old-occurrence", "closed", "2026-01-08T00:00:00Z", "wont_fix")
result["wont_fix"] = findings("first")
add_decision("old-occurrence", "closed", "2026-01-09T00:00:00Z", "already_fixed")
add_scan("rediscovered", "first", 10)
add_finding("rediscovered-occurrence", "renamed-again", "rediscovered")
result["rediscovered"] = findings("first")
add_scan("tied", "first", 11)
add_finding("z-occurrence", "z-finding", "tied")
add_finding("a-occurrence", "a-finding", "tied")
connection.execute("UPDATE finding_occurrences SET severity = 'critical' WHERE id = 'historical-occurrence'")
result["ordered"] = findings("first")
print(json.dumps(result))
`;

  const execution = await runCodexCommand(
    { command: python },
    ["-I", "-B", "-", join(PLUGIN_ROOT, "scripts")],
    process.env,
    probe,
    AbortSignal.timeout(10_000),
  );
  expect(execution.exitCode, execution.stderr).toBe(0);

  const result = JSON.parse(execution.stdout) as Record<
    string,
    Array<Record<string, unknown>>
  >;
  expect(result).toMatchObject({
    dismissed: [
      {
        findingId: "historical",
        confirmedInLatestScan: false,
        knownScanIds: ["old"],
      },
    ],
    other: [{ findingId: "dismissed", targetId: "second", status: "open" }],
    closed: [
      { findingId: "historical", status: "open" },
      { findingId: "renamed-again", status: "closed" },
    ],
    wont_fix: [{ findingId: "historical" }],
  });
  expect(result["reopened"]?.[0]).toMatchObject({
    findingId: "renamed-again",
    status: "open",
    confirmedInLatestScan: true,
    knownSince: "2026-01-01T00:00:00Z",
    knownScanIds: ["old", "same", "renamed", "latest"],
    matchedFindingIds: ["dismissed", "renamed", "renamed-again"],
    occurrenceCount: 4,
  });
  expect(result["not_revalidated"]?.[0]).toMatchObject({
    findingId: "renamed-again",
    status: "open",
    confirmedInLatestScan: false,
  });
  expect(result["rediscovered"]?.[0]).toMatchObject({
    findingId: "renamed-again",
    status: "open",
    confirmedInLatestScan: true,
    occurrenceCount: 5,
  });
  expect(result["ordered"]?.map((finding) => finding["findingId"])).toEqual([
    "historical",
    "a-finding",
    "z-finding",
    "renamed-again",
  ]);
});
