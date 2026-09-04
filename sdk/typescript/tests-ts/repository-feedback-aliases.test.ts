import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("reuses reviewed feedback only across matching persisted repository identities", () => {
  const python = (Bun.which("python3") ?? Bun.which("python"))!;
  const probe = `
import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import workbench_target_state as state
from workbench_feedback import get_scan_feedback

scenario = sys.argv[2]
connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.executescript("""
CREATE TABLE security_targets(id TEXT, current_path TEXT, display_name TEXT, origin TEXT);
CREATE TABLE scans(id TEXT, target_id TEXT, target_path TEXT, repository_generation TEXT, status TEXT, completed_at TEXT, started_at TEXT, updated_at TEXT, scope TEXT);
CREATE TABLE findings(id TEXT PRIMARY KEY, fingerprint TEXT, rule_id TEXT, identity_anchor TEXT, identity_instance TEXT);
CREATE TABLE finding_occurrences(id TEXT, finding_id TEXT, scan_id TEXT, title TEXT, summary TEXT, severity TEXT, created_at TEXT);
CREATE TABLE finding_triage(occurrence_id TEXT, status TEXT, close_reason TEXT, note TEXT, updated_at TEXT);
CREATE TABLE finding_locations(id INTEGER PRIMARY KEY, occurrence_id TEXT, relative_path TEXT, start_line INTEGER, end_line INTEGER, role TEXT, sort_order INTEGER);
CREATE TABLE scan_comparison_matches(before_occurrence_id TEXT, after_occurrence_id TEXT);
""")
if scenario == "identities":
    connection.execute("ALTER TABLE security_targets ADD COLUMN repository_identity TEXT")
refused = set()
def inspect(database, target_id, path, stored, **kwargs):
    repository = state.GitRepositoryIdentity(stored, ".", "synthetic", 1, 2, 3) if stored else None
    return state.RepositoryTargetState(
        target_id, path, stored, resolved_path=path, repository=repository,
        ownership_matches=target_id not in refused, strict_owner_matches=True,
        has_historical_scans=True,
    )
state._inspect_repository_target = inspect

origin = "https://example.invalid/synthetic/repository"
for target, identity in [
    ("primary", "common-git-directory::."),
    ("linked", "common-git-directory::."),
    ("same-origin-clone", "independent-git-directory::."),
    ("different-scope", "common-git-directory::packages/api"),
    ("unknown-first", None),
    ("unknown-second", None),
]:
    connection.execute(
        "INSERT INTO security_targets(id, current_path, display_name, origin) VALUES (?, ?, ?, ?)",
        (target, f"/{target}", target, origin),
    )
    if scenario == "identities":
        connection.execute(
            "UPDATE security_targets SET repository_identity = ? WHERE id = ?",
            (identity, target),
        )

def add_scan(scan_id, target, day, status="complete"):
    timestamp = f"2026-03-{day:02d}T00:00:00Z"
    completed_at = timestamp if status == "complete" else None
    generation = connection.execute("SELECT repository_identity FROM security_targets WHERE id = ?", (target,)).fetchone()[0] if scenario == "identities" else None
    connection.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (scan_id, target, f"/{target}", generation, status, completed_at, timestamp, timestamp, "repository"))

def add_finding(scan_id, finding_id, day, *, status="closed", reason="false_positive", note="Reviewed and safe"):
    occurrence_id = f"{scan_id}:{finding_id}"
    connection.execute(
        "INSERT OR IGNORE INTO findings VALUES (?, ?, ?, ?, ?)",
        (finding_id, f"fingerprint-{finding_id}", "synthetic-rule", f"anchor-{finding_id}", None),
    )
    connection.execute(
        "INSERT INTO finding_occurrences VALUES (?, ?, ?, ?, ?, ?, ?)",
        (occurrence_id, finding_id, scan_id, finding_id, "Synthetic summary", "high", f"2026-03-{day:02d}T00:00:00Z"),
    )
    connection.execute(
        "INSERT INTO finding_locations(occurrence_id, relative_path, start_line, end_line, role, sort_order) VALUES (?, ?, ?, ?, ?, ?)",
        (occurrence_id, "src/auth.py", 3, 4, "root_control", 0),
    )
    connection.execute(
        "INSERT INTO finding_triage VALUES (?, ?, ?, ?, ?)",
        (occurrence_id, status, reason, note, f"2026-03-{day:02d}T12:00:00Z"),
    )

for scan_id, target, day in [
    ("primary-reviewed", "primary", 1),
    ("linked-reviewed", "linked", 2),
    ("linked-reopened", "linked", 3),
    ("clone-reviewed", "same-origin-clone", 4),
    ("scope-reviewed", "different-scope", 5),
    ("unknown-first-reviewed", "unknown-first", 6),
    ("unknown-second-reviewed", "unknown-second", 7),
]:
    add_scan(scan_id, target, day)

add_finding("primary-reviewed", "primary-false-positive", 1)
add_finding("primary-reviewed", "reopened-across-alias", 1)
add_finding("primary-reviewed", "renamed-before-reopening", 1)
add_finding("linked-reviewed", "linked-false-positive", 2)
add_finding("linked-reviewed", "linked-wont-fix", 2, reason="wont_fix")
add_finding("linked-reviewed", "linked-no-note", 2, note="   ")
add_finding("linked-reopened", "reopened-across-alias", 3, status="open", reason=None, note=None)
add_finding("linked-reopened", "renamed-after-reopening", 3, status="open", reason=None, note=None)
connection.execute(
    "INSERT INTO scan_comparison_matches VALUES (?, ?)",
    ("primary-reviewed:renamed-before-reopening", "linked-reopened:renamed-after-reopening"),
)
add_finding("clone-reviewed", "clone-false-positive", 4)
add_finding("scope-reviewed", "scope-false-positive", 5)
add_finding("unknown-first-reviewed", "unknown-first-false-positive", 6)
add_finding("unknown-second-reviewed", "unknown-second-false-positive", 7)
add_scan("linked-incomplete", "linked", 8, status="running")
add_finding("linked-incomplete", "linked-incomplete-false-positive", 8)

for target in ["primary", "linked", "same-origin-clone", "different-scope", "unknown-first", "unknown-second"]:
    add_scan(f"current-{target}", target, 9, status="running")

def feedback(target):
    scan = connection.execute("SELECT * FROM scans WHERE id = ?", (f"current-{target}",)).fetchone()
    return get_scan_feedback(connection, scan)

result = {
    "primary": feedback("primary"),
    "linked": feedback("linked"),
    "clone": feedback("same-origin-clone"),
    "differentScope": feedback("different-scope"),
    "unknownFirst": feedback("unknown-first"),
    "unknownSecond": feedback("unknown-second"),
}
if scenario == "identities":
    refused.add("primary")
    result["reusedPath"] = feedback("primary")
    result["deletedAlias"] = feedback("linked")
print(json.dumps(result))
`;

  const run = (scenario: "identities" | "legacy") => {
    const execution = spawnSync(
      python,
      ["-I", "-B", "-c", probe, join(PLUGIN_ROOT, "scripts"), scenario],
      { encoding: "utf8", timeout: 10_000 },
    );
    expect(execution.status, execution.stderr).toBe(0);
    return JSON.parse(execution.stdout) as Record<
      string,
      {
        scanId: string;
        targetId: string;
        falsePositives: Array<Record<string, unknown>>;
      }
    >;
  };

  const identities = run("identities");
  expect(identities["primary"]).toMatchObject({
    scanId: "current-primary",
    targetId: "primary",
    falsePositives: [
      {
        findingId: "linked-false-positive",
        sourceScanId: "linked-reviewed",
        reason: "Reviewed and safe",
      },
      {
        findingId: "primary-false-positive",
        sourceScanId: "primary-reviewed",
      },
    ],
  });
  expect(identities["linked"]?.falsePositives).toEqual(
    identities["primary"]?.falsePositives,
  );
  expect(identities["clone"]?.falsePositives).toMatchObject([
    { findingId: "clone-false-positive" },
  ]);
  expect(identities["differentScope"]?.falsePositives).toMatchObject([
    { findingId: "scope-false-positive" },
  ]);
  expect(identities["unknownFirst"]?.falsePositives).toMatchObject([
    { findingId: "unknown-first-false-positive" },
  ]);
  expect(identities["unknownSecond"]?.falsePositives).toMatchObject([
    { findingId: "unknown-second-false-positive" },
  ]);
  expect(identities["reusedPath"]?.falsePositives).toEqual([]);
  expect(identities["deletedAlias"]?.falsePositives).toEqual(
    identities["linked"]?.falsePositives,
  );

  const legacy = run("legacy");
  expect(legacy["primary"]?.falsePositives).toMatchObject([
    { findingId: "reopened-across-alias", sourceScanId: "primary-reviewed" },
    {
      findingId: "renamed-before-reopening",
      sourceScanId: "primary-reviewed",
    },
    { findingId: "primary-false-positive", sourceScanId: "primary-reviewed" },
  ]);
  expect(legacy["linked"]?.falsePositives).toMatchObject([
    { findingId: "linked-false-positive", sourceScanId: "linked-reviewed" },
  ]);
});
