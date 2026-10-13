import { workbenchFixture } from "./support/workbench-fixture.js";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { resolvePluginPython, runCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("combines repository findings without reviving dismissed aliases", async () => {
  const python = await resolvePluginPython();

  const probe = `
import argparse, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
${workbenchFixture}
import workbench_native_indexes as indexes

connection = migrated_connection()
seed_many(connection, 'security_targets', ('id', 'current_path', 'display_name'), [('first', '/first', 'First'), ('second', '/second', 'Second')])
def add_scan(scan_id, target, day):
    timestamp = f"2026-01-{day:02d}T00:00:00Z"
    seed(connection, 'scans', ('id', 'target_id', 'scope', 'updated_at', 'status', 'started_at'), (scan_id, target, "repository", timestamp, "complete", timestamp))

def add_finding(occurrence, finding, scan):
    started = connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan,)).fetchone()[0]
    seed(connection, 'finding_occurrences', ('id', 'finding_id', 'severity', 'created_at', 'scan_id', 'title', 'summary'), (occurrence, finding, "high", started, scan, finding, "Summary"))
    seed(connection, 'finding_locations', ('occurrence_id', 'relative_path', 'role', 'sort_order'), (occurrence, "src/auth.py", "root_control", 0))

for scan_id, target, day in [("old", "first", 1), ("same", "first", 2), ("renamed", "first", 3), ("latest", "first", 4), ("other", "second", 4)]:
    add_scan(scan_id, target, day)
for occurrence, finding, scan in [("old-occurrence", "dismissed", "old"), ("same-occurrence", "dismissed", "same"), ("renamed-occurrence", "renamed", "renamed"), ("latest-occurrence", "renamed-again", "latest"), ("historical-occurrence", "historical", "old"), ("other-occurrence", "dismissed", "other")]:
    add_finding(occurrence, finding, scan)
seed_many(connection, 'scan_comparison_matches', ('before_occurrence_id', 'after_occurrence_id'), [("same-occurrence", "renamed-occurrence"), ("renamed-occurrence", "latest-occurrence"), ("latest-occurrence", "other-occurrence")])
seed(connection, 'finding_triage', ('occurrence_id', 'status', 'updated_at', 'close_reason'), ("old-occurrence", "closed", "2026-01-01T12:00:00Z", "false_positive"))

def findings(target, status="open"):
    arguments = argparse.Namespace(limit=20, offset=0, query=None, severity=None, status=status, target_id=target)
    return indexes.list_global_findings(connection, arguments)["findings"]

result = {"dismissed": findings("first"), "other": findings("second"), "closed": findings("first", None)}
seed(connection, 'finding_triage', ('occurrence_id', 'status', 'updated_at', 'close_reason'), ("latest-occurrence", "open", "2026-01-06T00:00:00Z", None))
result["reopened"] = findings("first")
add_scan("clean", "first", 7)
result["not_revalidated"] = findings("first")
connection.execute("UPDATE finding_triage SET close_reason = ?, updated_at = ? WHERE occurrence_id = ?", ("wont_fix", "2026-01-08T00:00:00Z", "old-occurrence"))
result["wont_fix"] = findings("first")
connection.execute("UPDATE finding_triage SET close_reason = ?, updated_at = ? WHERE occurrence_id = ?", ("already_fixed", "2026-01-09T00:00:00Z", "old-occurrence"))
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
