import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("repository index includes and filters persisted unscanned targets", () => {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const scripts = join(PLUGIN_ROOT, "scripts");
  const probe = `
import argparse
import json
import sqlite3
import sys
sys.path.insert(0, sys.argv[1])
import workbench_native_indexes as indexes

connection = sqlite3.connect(":memory:")
connection.row_factory = sqlite3.Row
connection.executescript("""
CREATE TABLE security_targets (
  id TEXT PRIMARY KEY,
  current_path TEXT NOT NULL,
  display_name TEXT NOT NULL
);
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  target_id TEXT NOT NULL,
  started_at TEXT NOT NULL
);
""")
connection.executemany(
    "INSERT INTO security_targets VALUES (?, ?, ?)",
    [
        ("target-scanned", "/repo/scanned", "Scanned"),
        ("target-unscanned", "/repo/unscanned", "Unscanned"),
    ],
)
connection.execute(
    "INSERT INTO scans VALUES (?, ?, ?)",
    ("scan-1", "target-scanned", "2026-08-18T00:00:00Z"),
)
connection.commit()

indexes.scan_history.list_scans = lambda _connection: {
    "scans": [{"scanId": "scan-1", "targetId": "target-scanned"}]
}
indexes._indexed_findings = lambda _connection: iter(())

def arguments(status):
    return argparse.Namespace(
        query=None,
        target_id=None,
        status=status,
        offset=0,
        limit=None,
    )

def compact(result):
    return [
        {
            "targetId": row["targetId"],
            "scanCount": row["scanCount"],
            "latestScan": row["latestScan"],
        }
        for row in result["repositories"]
    ]

print(json.dumps({
    "all": compact(indexes.list_repositories(connection)),
    "scanned": compact(indexes.list_repositories(connection, arguments("scanned"))),
    "notScanned": compact(indexes.list_repositories(connection, arguments("not_scanned"))),
}))
`;

  const result = spawnSync(python!, ["-I", "-B", "-c", probe, scripts], {
    encoding: "utf8",
  });
  expect(result.status, result.stderr).toBe(0);
  expect(JSON.parse(result.stdout)).toEqual({
    all: [
      {
        targetId: "target-scanned",
        scanCount: 1,
        latestScan: { scanId: "scan-1", targetId: "target-scanned" },
      },
      {
        targetId: "target-unscanned",
        scanCount: 0,
        latestScan: null,
      },
    ],
    scanned: [
      {
        targetId: "target-scanned",
        scanCount: 1,
        latestScan: { scanId: "scan-1", targetId: "target-scanned" },
      },
    ],
    notScanned: [
      {
        targetId: "target-unscanned",
        scanCount: 0,
        latestScan: null,
      },
    ],
  });
});
