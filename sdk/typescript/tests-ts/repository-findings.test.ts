import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("combines repository findings without reviving dismissed aliases", () => {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  if (python === null) throw new Error("A Python interpreter is required.");

  const probe = `
import argparse, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_native_indexes as indexes

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.executescript("""
CREATE TABLE security_targets(id TEXT, current_path TEXT, display_name TEXT);
CREATE TABLE scans(id TEXT, target_id TEXT, scope TEXT, updated_at TEXT, status TEXT, started_at TEXT);
CREATE TABLE finding_occurrences(id TEXT, finding_id TEXT, severity TEXT, created_at TEXT, scan_id TEXT, title TEXT, summary TEXT);
CREATE TABLE finding_triage(occurrence_id TEXT, status TEXT, updated_at TEXT, close_reason TEXT);
CREATE TABLE finding_locations(occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparison_matches(before_occurrence_id TEXT, after_occurrence_id TEXT);
INSERT INTO security_targets VALUES('first', '/first', 'First'), ('second', '/second', 'Second');
""")
indexes.scan_history.list_scans = lambda db: {"scans": [{"scanId": row["id"], "targetId": row["target_id"]} for row in db.execute("SELECT id, target_id FROM scans")]}

def add_scan(scan_id, target, day):
    timestamp = f"2026-01-{day:02d}T00:00:00Z"
    connection.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)", (scan_id, target, "repository", timestamp, "complete", timestamp))

def add_finding(occurrence, finding, scan, title):
    started = connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan,)).fetchone()[0]
    connection.execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)", (occurrence, finding, "high", started, scan, title, "Summary"))
    connection.execute("INSERT INTO finding_locations VALUES (?, ?, ?, ?)", (occurrence, "src/auth.py", "root_control", 0))

for scan_id, target, day in [("old", "first", 1), ("same", "first", 2), ("renamed", "first", 3), ("latest", "first", 4), ("other", "second", 4)]:
    add_scan(scan_id, target, day)
for occurrence, finding, scan, title in [("old-occurrence", "dismissed", "old", "Dismissed"), ("same-occurrence", "dismissed", "same", "Same identity"), ("renamed-occurrence", "renamed", "renamed", "Renamed"), ("latest-occurrence", "renamed-again", "latest", "Latest alias"), ("historical-occurrence", "historical", "old", "Earlier open issue"), ("other-occurrence", "dismissed", "other", "Other repository")]:
    add_finding(occurrence, finding, scan, title)
connection.executemany("INSERT INTO scan_comparison_matches VALUES (?, ?)", [("same-occurrence", "renamed-occurrence"), ("renamed-occurrence", "latest-occurrence"), ("latest-occurrence", "other-occurrence")])
connection.execute("INSERT INTO finding_triage VALUES (?, ?, ?, ?)", ("old-occurrence", "closed", "2026-01-01T12:00:00Z", "false_positive"))

def findings(target, status="open"):
    arguments = argparse.Namespace(limit=20, offset=0, query=None, severity=None, status=status, target_id=target)
    return indexes.list_global_findings(connection, arguments)["findings"]

result = {"dismissed": findings("first"), "other": findings("second"), "closed": findings("first", None), "dismissed_repositories": indexes.list_repositories(connection)["repositories"]}
connection.execute("INSERT INTO finding_triage VALUES (?, ?, ?, ?)", ("latest-occurrence", "open", "2026-01-06T00:00:00Z", None))
result["reopened"] = findings("first")
result["reopened_repositories"] = indexes.list_repositories(connection)["repositories"]
add_scan("clean", "first", 7)
result["not_revalidated"] = findings("first")
connection.execute("UPDATE finding_triage SET close_reason = ?, updated_at = ? WHERE occurrence_id = ?", ("wont_fix", "2026-01-08T00:00:00Z", "old-occurrence"))
result["wont_fix"] = findings("first")
connection.execute("UPDATE finding_triage SET close_reason = ?, updated_at = ? WHERE occurrence_id = ?", ("already_fixed", "2026-01-09T00:00:00Z", "old-occurrence"))
add_scan("rediscovered", "first", 10)
add_finding("rediscovered-occurrence", "renamed-again", "rediscovered", "Rediscovered")
result["rediscovered"] = findings("first")
add_scan("tied", "first", 11)
add_finding("z-occurrence", "z-finding", "tied", "Z finding")
add_finding("a-occurrence", "a-finding", "tied", "A finding")
connection.execute("UPDATE finding_occurrences SET severity = 'critical' WHERE id = 'historical-occurrence'")
result["ordered"] = findings("first")
print(json.dumps(result))
`;

  const execution = spawnSync(
    python,
    ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts")],
    { encoding: "utf8", timeout: 10_000 },
  );
  expect(execution.status, execution.stderr).toBe(0);

  const result = JSON.parse(execution.stdout) as Record<
    string,
    Array<Record<string, unknown>>
  >;
  expect(result["dismissed"]).toMatchObject([
    {
      findingId: "historical",
      confirmedInLatestScan: false,
      knownScanIds: ["old"],
    },
  ]);
  expect(result["other"]).toMatchObject([
    { findingId: "dismissed", targetId: "second", status: "open" },
  ]);
  expect(result["dismissed_repositories"]).toContainEqual(
    expect.objectContaining({ targetId: "first", openFindingsCount: 1 }),
  );
  expect(result["closed"]).toMatchObject([
    { findingId: "historical", status: "open" },
    { findingId: "renamed-again", status: "closed" },
  ]);
  expect(result["reopened"]).toContainEqual(
    expect.objectContaining({
      findingId: "renamed-again",
      status: "open",
      confirmedInLatestScan: true,
      knownSince: "2026-01-01T00:00:00Z",
      knownScanIds: ["old", "same", "renamed", "latest"],
      matchedFindingIds: ["dismissed", "renamed", "renamed-again"],
      occurrenceCount: 4,
    }),
  );
  expect(result["reopened_repositories"]).toContainEqual(
    expect.objectContaining({ targetId: "first", openFindingsCount: 2 }),
  );
  expect(result["not_revalidated"]).toContainEqual(
    expect.objectContaining({
      findingId: "renamed-again",
      status: "open",
      confirmedInLatestScan: false,
    }),
  );
  expect(result["wont_fix"]).toMatchObject([{ findingId: "historical" }]);
  expect(result["rediscovered"]).toContainEqual(
    expect.objectContaining({
      findingId: "renamed-again",
      status: "open",
      confirmedInLatestScan: true,
      occurrenceCount: 5,
    }),
  );
  expect(result["ordered"]?.map((finding) => finding["findingId"])).toEqual([
    "historical",
    "a-finding",
    "z-finding",
    "renamed-again",
  ]);
});
