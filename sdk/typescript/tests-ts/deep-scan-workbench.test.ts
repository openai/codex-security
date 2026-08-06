import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const originalClaimToken = "22222222-2222-4222-8222-222222222222";
const replacementClaimToken = "33333333-3333-4333-8333-333333333333";

const deepScanOwnershipProbe = [
  "import argparse, json, sqlite3, sys",
  "sys.path.insert(0, sys.argv[1])",
  "import deep_scan_workbench as deep_scan",
  "case = json.loads(sys.argv[2])",
  "connection = sqlite3.connect(':memory:')",
  "connection.row_factory = sqlite3.Row",
  "connection.executescript('''",
  "CREATE TABLE workspaces (id TEXT PRIMARY KEY, thread_id TEXT, updated_at TEXT);",
  "CREATE TABLE scans (id TEXT PRIMARY KEY, workspace_id TEXT, mode TEXT, status TEXT, recipe_json TEXT, handoff_status TEXT, handoff_claim_token TEXT, deep_scan_owner_thread_id TEXT, updated_at TEXT);",
  "CREATE TABLE deep_scan_runs (scan_id TEXT PRIMARY KEY);",
  "''')",
  "scan_id = '11111111-1111-4111-8111-111111111111'",
  "connection.execute(\"INSERT INTO workspaces VALUES ('workspace', NULL, 'before')\")",
  "connection.execute(\"INSERT INTO scans VALUES (?, 'workspace', 'deep', 'running', '{}', 'delivered', ?, NULL, 'before')\", (scan_id, case['storedToken']))",
  "connection.execute('INSERT INTO deep_scan_runs VALUES (?)', (scan_id,))",
  "connection.commit()",
  "if case.get('mutation') == 'rotate':",
  "    connection.executescript(\"CREATE TRIGGER rotate_claim BEFORE UPDATE OF thread_id ON workspaces BEGIN UPDATE scans SET handoff_claim_token = '33333333-3333-4333-8333-333333333333' WHERE workspace_id = NEW.id; END\")",
  "elif case.get('mutation') == 'withdraw':",
  "    connection.executescript(\"CREATE TRIGGER withdraw_handoff BEFORE UPDATE OF thread_id ON workspaces BEGIN UPDATE scans SET handoff_status = 'pending' WHERE workspace_id = NEW.id; END\")",
  "deep_scan.require_scan = lambda database, value: database.execute('SELECT * FROM scans WHERE id = ?', (value,)).fetchone()",
  "deep_scan.require_workspace = lambda database, value: database.execute('SELECT * FROM workspaces WHERE id = ?', (value,)).fetchone()",
  "deep_scan.now = lambda: 'after'",
  "deep_scan.deep_scan_result = lambda database, value, *, start_disposition=None: {'startDisposition': start_disposition}",
  "try:",
  "    result = deep_scan.begin_deep_scan_for_scan(connection, scan_id, 'requesting-thread', argparse.Namespace(claim_token=case['suppliedToken'], model=None, reasoning_effort=None))",
  "except SystemExit as error:",
  "    accepted, message, result = False, str(error), None",
  "else:",
  "    accepted, message = True, None",
  "scan = connection.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()",
  "workspace = connection.execute(\"SELECT * FROM workspaces WHERE id = 'workspace'\").fetchone()",
  "print(json.dumps({'accepted': accepted, 'error': message, 'result': result, 'scanOwner': scan['deep_scan_owner_thread_id'], 'workspaceOwner': workspace['thread_id'], 'scanUpdatedAt': scan['updated_at'], 'workspaceUpdatedAt': workspace['updated_at'], 'storedToken': scan['handoff_claim_token'], 'handoffStatus': scan['handoff_status']}))",
].join("\n");

interface OwnershipProbe {
  storedToken: string | null;
  suppliedToken: string | null;
  mutation?: "rotate" | "withdraw";
}

function runOwnershipProbe(probe: OwnershipProbe): Record<string, unknown> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  if (python === null) {
    throw new Error("A Python interpreter is required for deep-scan tests.");
  }

  const result = Bun.spawnSync(
    [
      python,
      "-I",
      "-B",
      "-c",
      deepScanOwnershipProbe,
      join(PLUGIN_ROOT, "scripts"),
      JSON.stringify(probe),
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
    string,
    unknown
  >;
}

describe("deep scan workbench ownership", () => {
  test.each([
    ["a malformed continuation token", null, "not-a-valid-token"],
    ["an unexpected token for a legacy delivery", null, originalClaimToken],
    ["a missing continuation token", originalClaimToken, null],
    [
      "a different continuation token",
      originalClaimToken,
      replacementClaimToken,
    ],
  ] as const)(
    "rejects %s without changing persisted ownership",
    (_description, storedToken, suppliedToken) => {
      expect(runOwnershipProbe({ storedToken, suppliedToken })).toMatchObject({
        accepted: false,
        scanOwner: null,
        workspaceOwner: null,
        scanUpdatedAt: "before",
        workspaceUpdatedAt: "before",
        storedToken,
        handoffStatus: "delivered",
      });
    },
  );

  test.each(["rotate", "withdraw"] as const)(
    "rolls back both ownership writes when the handoff changes during %s",
    (mutation) => {
      expect(
        runOwnershipProbe({
          storedToken: originalClaimToken,
          suppliedToken: originalClaimToken,
          mutation,
        }),
      ).toMatchObject({
        accepted: false,
        scanOwner: null,
        workspaceOwner: null,
        scanUpdatedAt: "before",
        workspaceUpdatedAt: "before",
        storedToken: originalClaimToken,
        handoffStatus: "delivered",
      });
    },
  );

  test.each([
    ["a matching continuation token", originalClaimToken],
    ["a recovery continuation token", `recovery_${originalClaimToken}`],
    ["a tokenless legacy delivery", null],
  ] as const)("claims ownership for %s", (_description, token) => {
    expect(
      runOwnershipProbe({ storedToken: token, suppliedToken: token }),
    ).toMatchObject({
      accepted: true,
      result: { startDisposition: "joined" },
      scanOwner: "requesting-thread",
      workspaceOwner: "requesting-thread",
      scanUpdatedAt: "after",
      workspaceUpdatedAt: "after",
      storedToken: token,
      handoffStatus: "delivered",
    });
  });
});
