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
CREATE TABLE scans(id TEXT, target_id TEXT, scope TEXT, updated_at TEXT, status TEXT, started_at TEXT);
CREATE TABLE finding_occurrences(id TEXT, finding_id TEXT, severity TEXT, created_at TEXT, scan_id TEXT, title TEXT, summary TEXT);
CREATE TABLE finding_triage(occurrence_id TEXT, status TEXT, updated_at TEXT, close_reason TEXT);
CREATE TABLE finding_locations(occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparison_matches(before_occurrence_id TEXT, after_occurrence_id TEXT);
INSERT INTO security_targets VALUES('first', '/first', 'First'), ('second', '/second', 'Second');
""")
def add_scan(scan_id, target, day):
    timestamp = f"2026-01-{day:02d}T00:00:00Z"
    connection.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)", (scan_id, target, "repository", timestamp, "complete", timestamp))

def add_finding(occurrence, finding, scan):
    started = connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan,)).fetchone()[0]
    connection.execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)", (occurrence, finding, "high", started, scan, finding, "Summary"))
    connection.execute("INSERT INTO finding_locations VALUES (?, ?, ?, ?)", (occurrence, "src/auth.py", "root_control", 0))

for scan_id, target, day in [("old", "first", 1), ("same", "first", 2), ("renamed", "first", 3), ("latest", "first", 4), ("other", "second", 4)]:
    add_scan(scan_id, target, day)
for occurrence, finding, scan in [("old-occurrence", "dismissed", "old"), ("same-occurrence", "dismissed", "same"), ("renamed-occurrence", "renamed", "renamed"), ("latest-occurrence", "renamed-again", "latest"), ("historical-occurrence", "historical", "old"), ("other-occurrence", "dismissed", "other")]:
    add_finding(occurrence, finding, scan)
connection.executemany("INSERT INTO scan_comparison_matches VALUES (?, ?)", [("same-occurrence", "renamed-occurrence"), ("renamed-occurrence", "latest-occurrence"), ("latest-occurrence", "other-occurrence")])
connection.execute("INSERT INTO finding_triage VALUES (?, ?, ?, ?)", ("old-occurrence", "closed", "2026-01-01T12:00:00Z", "false_positive"))

def findings(target, status="open"):
    arguments = argparse.Namespace(limit=20, offset=0, query=None, severity=None, status=status, target_id=target)
    return indexes.list_global_findings(connection, arguments)["findings"]

result = {"dismissed": findings("first"), "other": findings("second"), "closed": findings("first", None)}
connection.execute("INSERT INTO finding_triage VALUES (?, ?, ?, ?)", ("latest-occurrence", "open", "2026-01-06T00:00:00Z", None))
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

test("shares findings only between explicitly identified repository and scope aliases", async () => {
  const python = (Bun.which("python3") ?? Bun.which("python"))!;
  const probe = `
import argparse, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_native_indexes as indexes
import workbench_target_state as state

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.executescript("""
CREATE TABLE security_targets(id TEXT, current_path TEXT, display_name TEXT, repository_identity TEXT, origin TEXT);
CREATE TABLE scans(id TEXT, target_id TEXT, target_path TEXT, repository_generation TEXT, scope TEXT, updated_at TEXT, status TEXT, started_at TEXT);
CREATE TABLE finding_occurrences(id TEXT, finding_id TEXT, severity TEXT, created_at TEXT, scan_id TEXT, title TEXT, summary TEXT);
CREATE TABLE finding_triage(occurrence_id TEXT, status TEXT, updated_at TEXT, close_reason TEXT);
CREATE TABLE finding_locations(occurrence_id TEXT, relative_path TEXT, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparison_matches(before_occurrence_id TEXT, after_occurrence_id TEXT);
""")
origin = "https://example.invalid/synthetic/repository"
connection.executemany("INSERT INTO security_targets VALUES (?, ?, ?, ?, ?)", [
    ("primary", "/primary", "Primary", "common-git-directory::.", origin),
    ("linked", "/linked", "Linked", "common-git-directory::.", origin),
    ("empty-alias", "/empty-alias", "Empty alias", "common-git-directory::.", origin),
    ("same-origin-clone", "/clone", "Clone", "independent-git-directory::.", origin),
    ("different-scope", "/primary/packages/api", "Scoped", "common-git-directory::packages/api", origin),
    ("unknown-first", "/unknown-first", "Unknown first", None, origin),
    ("unknown-second", "/unknown-second", "Unknown second", None, origin),
])
refused = set()
def inspect(database, target_id, path, stored, **kwargs):
    repository = state.GitRepositoryIdentity(stored, ".", "synthetic", 1, 2, 3) if stored else None
    return state.RepositoryTargetState(
        target_id, path, stored, resolved_path=path, repository=repository,
        ownership_matches=target_id not in refused, strict_owner_matches=True,
        has_historical_scans=True,
    )
state._inspect_repository_target = inspect
indexes.Path.is_dir = lambda path: True

def add_scan(scan_id, target, day):
    timestamp = f"2026-02-{day:02d}T00:00:00Z"
    saved = connection.execute("SELECT current_path, repository_identity FROM security_targets WHERE id = ?", (target,)).fetchone()
    connection.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (scan_id, target, saved["current_path"], saved["repository_identity"], "repository", timestamp, "complete", timestamp))

def add_finding(occurrence, finding, scan, severity="high"):
    started = connection.execute("SELECT started_at FROM scans WHERE id = ?", (scan,)).fetchone()[0]
    connection.execute("INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)", (occurrence, finding, severity, started, scan, finding, "Summary"))
    connection.execute("INSERT INTO finding_locations VALUES (?, ?, ?, ?)", (occurrence, "src/auth.py", "root_control", 0))

for scan_id, target, day in [
    ("primary-old", "primary", 1),
    ("empty-alias-scan", "empty-alias", 1),
    ("linked-reviewed", "linked", 2),
    ("primary-open", "primary", 3),
    ("linked-latest", "linked", 4),
    ("clone-scan", "same-origin-clone", 5),
    ("scope-scan", "different-scope", 6),
    ("unknown-first-scan", "unknown-first", 7),
    ("unknown-second-scan", "unknown-second", 8),
]:
    add_scan(scan_id, target, day)

for occurrence, finding, scan in [
    ("dismissed-primary", "dismissed-original", "primary-old"),
    ("dismissed-linked", "dismissed-renamed", "linked-reviewed"),
    ("fixed-primary", "fixed-original", "primary-old"),
    ("fixed-linked", "fixed-rediscovered", "linked-reviewed"),
    ("wont-fix-primary", "wont-fix-original", "primary-old"),
    ("wont-fix-linked", "wont-fix-renamed", "linked-reviewed"),
    ("open-primary", "primary-only", "primary-open"),
    ("same-id-primary", "same-id", "primary-open"),
    ("open-linked", "linked-only", "linked-latest"),
    ("same-id-linked", "same-id", "linked-latest"),
    ("clone-occurrence", "clone-only", "clone-scan"),
    ("scope-occurrence", "scope-only", "scope-scan"),
    ("unknown-first-occurrence", "unknown-first-only", "unknown-first-scan"),
    ("unknown-second-occurrence", "unknown-second-only", "unknown-second-scan"),
]:
    add_finding(occurrence, finding, scan)

connection.executemany("INSERT INTO scan_comparison_matches VALUES (?, ?)", [
    ("dismissed-primary", "dismissed-linked"),
    ("fixed-primary", "fixed-linked"),
    ("wont-fix-primary", "wont-fix-linked"),
    ("open-linked", "clone-occurrence"),
    ("open-linked", "scope-occurrence"),
    ("unknown-first-occurrence", "unknown-second-occurrence"),
])
connection.executemany("INSERT INTO finding_triage VALUES (?, ?, ?, ?)", [
    ("dismissed-primary", "closed", "2026-02-01T12:00:00Z", "false_positive"),
    ("fixed-primary", "closed", "2026-02-01T12:00:00Z", "already_fixed"),
    ("wont-fix-primary", "closed", "2026-02-01T12:00:00Z", "wont_fix"),
])

def findings(target, status="open", limit=20, offset=0):
    arguments = argparse.Namespace(limit=limit, offset=offset, query=None, severity=None, status=status, target_id=target)
    return indexes.list_global_findings(connection, arguments)

indexes.scan_history.list_scans = lambda database: {
    "scans": [
        {"scanId": scan["id"], "targetId": scan["target_id"]}
        for scan in database.execute("SELECT id, target_id FROM scans")
    ]
}
repository_arguments = argparse.Namespace(
    query=None, target_id=None, status="open_findings", limit=None, offset=0
)
result = {
    "primary": findings("primary"),
    "linked": findings("linked"),
    "closed": findings("primary", "closed"),
    "all": findings("primary", None),
    "clone": findings("same-origin-clone"),
    "differentScope": findings("different-scope"),
    "unknownFirst": findings("unknown-first"),
    "unknownSecond": findings("unknown-second"),
    "firstPage": findings("primary", limit=2),
    "secondPage": findings("primary", limit=2, offset=2),
    "thirdPage": findings("primary", limit=2, offset=4),
    "repositories": indexes.list_repositories(connection),
    "openRepositories": indexes.list_repositories(connection, repository_arguments),
}
connection.execute(
    "UPDATE finding_occurrences SET created_at = ? WHERE id = ?",
    ("2026-02-05T00:00:00Z", "same-id-primary"),
)
result["overlappingCompletions"] = findings("primary", None)
connection.execute(
    "UPDATE finding_occurrences SET created_at = ? WHERE id = ?",
    ("2026-02-03T00:00:00Z", "same-id-primary"),
)
connection.execute(
    "INSERT INTO finding_triage VALUES (?, ?, ?, ?)",
    ("same-id-primary", "closed", "2026-02-05T00:00:00Z", "false_positive"),
)
result["sameIdDismissed"] = findings("primary")
result["sameIdClosed"] = findings("linked", "closed")
connection.execute(
    "INSERT INTO finding_triage VALUES (?, ?, ?, ?)",
    ("same-id-linked", "open", "2026-02-06T00:00:00Z", None),
)
result["sameIdReopened"] = findings("primary")
refused.add("primary")
result["reusedPath"] = findings("primary")
result["deletedAlias"] = findings("linked")
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
    {
      findings: Array<Record<string, unknown>>;
      nextOffset: number | null;
      repositories?: Array<Record<string, unknown>>;
    }
  >;
  const primary = result["primary"]!.findings;
  expect(result["linked"]!.findings).toEqual(primary);
  expect(
    result["overlappingCompletions"]!.findings.find(
      (finding) => finding["findingId"] === "same-id",
    ),
  ).toMatchObject({
    scanId: "primary-open",
    confirmedInLatestScan: true,
    knownScanIds: ["primary-open", "linked-latest"],
  });
  expect(primary.map((finding) => finding["findingId"])).toEqual([
    "linked-only",
    "same-id",
    "primary-only",
    "fixed-rediscovered",
  ]);
  expect(
    primary.filter((finding) => finding["findingId"] === "same-id"),
  ).toMatchObject([
    {
      targetId: "linked",
      occurrenceCount: 2,
      knownScanIds: ["primary-open", "linked-latest"],
      matchedFindingIds: ["same-id"],
    },
  ]);
  expect(
    primary.find((finding) => finding["findingId"] === "linked-only"),
  ).toMatchObject({
    confirmedInLatestScan: true,
    matchedFindingIds: ["linked-only"],
  });
  expect(
    primary.find((finding) => finding["findingId"] === "primary-only"),
  ).toMatchObject({ confirmedInLatestScan: false });
  expect(
    primary.find((finding) => finding["findingId"] === "fixed-rediscovered"),
  ).toMatchObject({
    status: "open",
    knownScanIds: ["primary-old", "linked-reviewed"],
    matchedFindingIds: ["fixed-original", "fixed-rediscovered"],
    occurrenceCount: 2,
  });
  expect(result["closed"]!.findings).toMatchObject([
    {
      findingId: "dismissed-renamed",
      status: "closed",
      matchedFindingIds: ["dismissed-original", "dismissed-renamed"],
    },
    {
      findingId: "wont-fix-renamed",
      status: "closed",
      matchedFindingIds: ["wont-fix-original", "wont-fix-renamed"],
    },
  ]);
  expect(result["all"]!.findings).toHaveLength(6);
  expect(result["clone"]!.findings).toMatchObject([
    { findingId: "clone-only", targetId: "same-origin-clone" },
  ]);
  expect(result["differentScope"]!.findings).toMatchObject([
    { findingId: "scope-only", targetId: "different-scope" },
  ]);
  expect(result["unknownFirst"]!.findings).toMatchObject([
    { findingId: "unknown-first-only", targetId: "unknown-first" },
  ]);
  expect(result["unknownSecond"]!.findings).toMatchObject([
    { findingId: "unknown-second-only", targetId: "unknown-second" },
  ]);
  expect(
    Object.fromEntries(
      result["repositories"]!.repositories!.map((repository) => [
        repository["targetId"],
        repository["openFindingsCount"],
      ]),
    ),
  ).toEqual({
    primary: 4,
    linked: 4,
    "empty-alias": 4,
    "same-origin-clone": 1,
    "different-scope": 1,
    "unknown-first": 1,
    "unknown-second": 1,
  });
  expect(
    result["openRepositories"]!.repositories!.map(
      (repository) => repository["targetId"],
    ),
  ).toContain("empty-alias");
  expect(result["firstPage"]!.nextOffset).toBe(2);
  expect(result["secondPage"]!.nextOffset).toBeNull();
  expect(result["thirdPage"]!.nextOffset).toBeNull();
  expect([
    ...result["firstPage"]!.findings,
    ...result["secondPage"]!.findings,
    ...result["thirdPage"]!.findings,
  ]).toEqual(primary);
  expect(
    result["sameIdDismissed"]!.findings.some(
      (finding) => finding["findingId"] === "same-id",
    ),
  ).toBe(false);
  expect(
    result["sameIdClosed"]!.findings.find(
      (finding) => finding["findingId"] === "same-id",
    ),
  ).toMatchObject({ status: "closed", occurrenceCount: 2 });
  expect(
    result["sameIdReopened"]!.findings.find(
      (finding) => finding["findingId"] === "same-id",
    ),
  ).toMatchObject({ status: "open", occurrenceCount: 2 });
  expect(result["reusedPath"]!.findings).toEqual([]);
  expect(result["deletedAlias"]!.findings).toHaveLength(4);
});
