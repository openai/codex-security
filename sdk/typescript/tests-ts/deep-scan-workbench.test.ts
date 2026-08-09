import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const originalClaimToken = "22222222-2222-4222-8222-222222222222";
const replacementClaimToken = "33333333-3333-4333-8333-333333333333";
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

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

  test("adopts an expired coordinator without repeating completed discovery", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-resume-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const stateDir = join(root, "state");
    const codexHome = join(root, "codex-home");
    await mkdir(repository);
    await writeFile(join(repository, "source.py"), "# source fixture\n");

    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const command = (args: string[], allowFailure = false) => {
      const result = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
          ...args,
        ],
        {
          env: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: stateDir,
            CODEX_HOME: codexHome,
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      const stdout = new TextDecoder().decode(result.stdout);
      const stderr = new TextDecoder().decode(result.stderr);
      if (allowFailure) return { status: result.exitCode, stderr };
      expect(result.exitCode, stderr).toBe(0);
      return JSON.parse(stdout) as Record<string, unknown>;
    };

    const started = command([
      "begin-deep-scan",
      "--thread-id",
      "thread-deep-scan",
      "--target-path",
      repository,
      "--scope",
      ".",
      "--scan-root",
      join(root, "scans"),
      "--available-parallelism",
      "4",
    ]);
    const initial = started["deepScan"] as Record<string, unknown>;
    const scanId = initial["scanId"] as string;
    const scanDir = initial["scanDir"] as string;
    expect(initial["coordinatorGeneration"]).toBe(1);

    const updateDatabase = (statement: string, ...values: string[]) => {
      const result = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          "-c",
          "import sqlite3,sys; connection=sqlite3.connect(sys.argv[1]); connection.execute(sys.argv[2],sys.argv[3:]); connection.commit()",
          join(stateDir, "workbench.sqlite3"),
          statement,
          ...values,
        ],
        { stdout: "pipe", stderr: "pipe" },
      );
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    };
    updateDatabase(
      "UPDATE scans SET handoff_claim_token = ? WHERE id = ?",
      originalClaimToken,
      scanId,
    );
    command([
      "update-progress",
      "--scan-id",
      scanId,
      "--phase",
      "discovery",
      "--claim-token",
      originalClaimToken,
    ]);

    const completedWorkerId = "44444444-4444-4444-8444-444444444444";
    const interruptedWorkerId = "55555555-5555-4555-8555-555555555555";
    for (const workerId of [completedWorkerId, interruptedWorkerId]) {
      const artifactDir = join(
        scanDir,
        "artifacts",
        "deep_discovery",
        workerId,
      );
      const promptPath = join(artifactDir, "prompt.md");
      await mkdir(artifactDir, { recursive: true });
      await writeFile(promptPath, "Review the source.\n");
      const workerArgs = [
        "upsert-deep-scan-worker",
        "--scan-id",
        scanId,
        "--worker-id",
        workerId,
        "--kind",
        "discovery",
        "--prompt-path",
        promptPath,
        "--artifact-dir",
        artifactDir,
        "--attempt",
        "1",
      ];
      command([...workerArgs, "--status", "running"]);
      if (workerId === completedWorkerId) {
        const resultPath = join(artifactDir, "result.json");
        await writeFile(resultPath, "{}\n");
        command([
          ...workerArgs,
          "--status",
          "succeeded",
          "--result-manifest-path",
          resultPath,
        ]);
      }
    }

    updateDatabase(
      "UPDATE deep_scan_runs SET updated_at = ? WHERE scan_id = ?",
      "2000-01-01T00:00:00+00:00",
      scanId,
    );
    const claimArgs = [
      "claim-deep-scan-coordinator",
      "--scan-id",
      scanId,
      "--thread-id",
      "thread-deep-scan",
    ];
    const missingClaim = command(claimArgs, true);
    expect(missingClaim["status"]).not.toBe(0);
    expect(missingClaim["stderr"]).toContain("another continuation");

    const resumed = command([
      ...claimArgs,
      "--claim-token",
      originalClaimToken,
    ]);
    const recovered = resumed["deepScan"] as Record<string, unknown>;
    expect(resumed["coordinatorDisposition"]).toBe("adopted");
    expect(recovered).toMatchObject({
      status: "running",
      phase: "discovery",
      coordinatorGeneration: 2,
      dispatchedCount: 1,
    });
    expect(recovered["workers"]).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: completedWorkerId,
          status: "succeeded",
        }),
        expect.objectContaining({
          id: interruptedWorkerId,
          status: "canceled",
        }),
      ]),
    );

    const observing = command([
      ...claimArgs,
      "--claim-token",
      originalClaimToken,
    ]);
    expect(observing["coordinatorDisposition"]).toBe("observing");

    const staleProgress = command(
      [
        "update-progress",
        "--scan-id",
        scanId,
        "--phase",
        "discovery",
        "--claim-token",
        originalClaimToken,
        "--coordinator-generation",
        "1",
      ],
      true,
    );
    expect(staleProgress["status"]).not.toBe(0);
    expect(staleProgress["stderr"]).toContain("newer generation");
  });
});
