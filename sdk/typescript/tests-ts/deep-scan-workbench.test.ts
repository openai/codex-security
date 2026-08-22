import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { runWorkbench } from "../src/runtime.js";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

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

test("copies a Deep Scan publication when the filesystem rejects hardlinks", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-deep-publication-")),
  );
  temporaryDirectories.push(root);
  const source = join(root, "source.jsonl");
  const destination = join(root, "destination.jsonl");
  await writeFile(source, '{"finding":"synthetic"}\n');
  const python =
    process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();

  const result = Bun.spawnSync(
    [
      python!,
      "-I",
      "-B",
      "-c",
      [
        "import errno, sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import deep_scan_workbench as deep_scan",
        "def reject_hardlink(source, destination):",
        "    raise OSError(errno.ENOTSUP, 'hardlinks are unavailable')",
        "deep_scan.os.link = reject_hardlink",
        "deep_scan.create_publication_copy(Path(sys.argv[2]), Path(sys.argv[3]))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      source,
      destination,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );

  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  expect(await readFile(destination, "utf8")).toBe('{"finding":"synthetic"}\n');
});

test("recovers an interrupted copied Deep Scan publication", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-deep-copy-recovery-")),
  );
  temporaryDirectories.push(root);
  const python =
    process.env["PYTHON"] ?? Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();

  const result = Bun.spawnSync(
    [
      python!,
      "-I",
      "-B",
      "-c",
      [
        "import json, shutil, sqlite3, sys",
        "from pathlib import Path",
        "sys.path.insert(0, sys.argv[1])",
        "import deep_scan_workbench as deep_scan",
        "root = Path(sys.argv[2])",
        "scan_dir = root / 'scan'",
        "ledger = scan_dir / 'artifacts' / '02_discovery' / 'candidate_ledger.jsonl'",
        "snapshot = root / 'worker' / 'canonical' / ledger.name",
        "backup = ledger.with_name(f'.{ledger.name}.fixture.backup')",
        "ledger.parent.mkdir(parents=True)",
        "snapshot.parent.mkdir(parents=True)",
        "ledger.write_text('old ledger\\n', encoding='utf-8')",
        "shutil.copy2(ledger, backup)",
        "snapshot.write_text('new ledger\\n', encoding='utf-8')",
        "shutil.copy2(snapshot, ledger)",
        "connection = sqlite3.connect(':memory:')",
        "connection.row_factory = sqlite3.Row",
        "connection.execute('CREATE TABLE scans (id TEXT PRIMARY KEY, scan_dir TEXT)')",
        "connection.execute('CREATE TABLE deep_scan_workers (scan_id TEXT, kind TEXT, status TEXT, artifact_dir TEXT, updated_at TEXT)')",
        "connection.execute('INSERT INTO scans VALUES (?, ?)', ('scan', str(scan_dir)))",
        "connection.execute('INSERT INTO deep_scan_workers VALUES (?, ?, ?, ?, ?)', ('scan', 'dedup', 'running', str(snapshot.parent.parent), 'now'))",
        "deep_scan.require_scan = lambda database, value: database.execute('SELECT * FROM scans WHERE id = ?', (value,)).fetchone()",
        "deep_scan.recover_candidate_ledger_publication(connection, 'scan')",
        "print(json.dumps({'ledger': ledger.read_text(encoding='utf-8'), 'backup': backup.exists()}))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
      root,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );

  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
    ledger: "old ledger\n",
    backup: false,
  });
});

test.each([
  ["supplied", "  Review café authentication.\r\n\t"],
  ["absent", undefined],
  ["large", "  --café\r\n".repeat(30_000)],
] as const)(
  "preserves %s scan instructions from registration through the Deep worker prompt",
  async (_label, scanPrompt) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-context-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(scanDir, { mode: 0o700 });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const command = (args: string[], input?: string) =>
      runWorkbench(
        {
          python: python!,
          pluginRoot: PLUGIN_ROOT,
          environment: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
            CODEX_HOME: join(root, "codex-home"),
          },
        },
        args,
        input,
      );
    const registration = await command(
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        recipe: {
          config: {
            developer_instructions: "Synthetic context. ".repeat(4_000),
          },
          mode: "deep",
          repository,
          target: { kind: "repository", paths: [] },
        },
        userContext: scanPrompt,
      }),
    );
    const scanId = registration["scanId"] as string;
    const context = await command(["get-scan", "--scan-id", scanId]);
    expect(context["scan"]).toMatchObject({ userContext: scanPrompt ?? null });

    const begun = await command([
      "begin-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      "synthetic-thread",
      "--scan-root",
      join(root, "scans"),
      "--available-parallelism",
      "4",
      "--workflow-version",
      "deep-scan-mcp/v1",
    ]);
    const deepScan = begun["deepScan"] as Record<string, unknown>;

    const templates =
      /\/\/ templates\/deep-scan\/discovery\.md\n([\s\S]*?)\/\/ src\/deep-scan\/worker-runner\.ts/u.exec(
        await loadBundledRuntime(),
      )?.[1];
    expect(templates).toBeDefined();
    const renderDiscoveryPrompt = new Function(
      `${templates}\nreturn renderDiscoveryPrompt;`,
    )() as (input: Record<string, unknown>) => string;
    const prompt = renderDiscoveryPrompt({
      ...deepScan,
      pluginRoot: PLUGIN_ROOT,
      workerLabel: "synthetic-worker",
      subagents: 0,
    });
    const workerContext = JSON.parse(
      /```json\n([\s\S]*?)\n```/u.exec(prompt)![1]!,
    );
    expect(workerContext).toMatchObject({
      scanId,
      userContext: scanPrompt ?? null,
    });
  },
);

describe("deep scan workbench ownership", () => {
  test("starts a Deep Scan with oversized stdin user context", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-context-stdin-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const stateDir = join(root, "state");
    await mkdir(repository);
    await writeFile(join(repository, "source.py"), "# source fixture\n");
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const userContext = "deep security focus".repeat(4_000);

    const result = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
        "begin-deep-scan",
        "--thread-id",
        "deep-context-stdin-owner",
        "--target-path",
        repository,
        "--scope",
        ".",
        "--user-context-stdin",
        "--scan-root",
        join(root, "scans"),
        "--available-parallelism",
        "4",
      ],
      {
        env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateDir },
        stdin: Buffer.from(userContext),
        stdout: "pipe",
        stderr: "pipe",
      },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    const started = JSON.parse(
      new TextDecoder().decode(result.stdout),
    ) as Record<string, Record<string, unknown>>;
    expect(started["deepScan"]?.["userContext"]).toBe(userContext);
  }, 30_000);

  test("rejects completion before an SDK-created Deep Scan finishes", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-completion-guard-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const stateDir = join(root, "state");
    await mkdir(repository);
    await mkdir(scanDir, { mode: 0o700 });
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const command = (args: string[]) =>
      Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
          ...args,
        ],
        {
          env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateDir },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
    const registered = command([
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "deep",
        repository,
        target: { kind: "repository", paths: [] },
      }),
    ]);
    expect(
      registered.exitCode,
      new TextDecoder().decode(registered.stderr),
    ).toBe(0);
    const { scanId } = JSON.parse(
      new TextDecoder().decode(registered.stdout),
    ) as { scanId: string };

    const premature = command(["complete-scan", "--scan-id", scanId]);
    expect(premature.exitCode).not.toBe(0);
    expect(new TextDecoder().decode(premature.stderr)).toContain(
      "orchestration must finish and persist its manifest",
    );
  });

  test.each([
    [undefined, 96],
    [0.5, 0.5],
    [96, 96],
  ] as const)(
    "resolves the configured discovery deadline %s as %s hours",
    async (configuredHours, expectedHours) => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-deep-deadline-config-")),
      );
      temporaryDirectories.push(root);
      const codexHome = join(root, "codex-home");
      const configDirectory = join(codexHome, "codex-security");
      await mkdir(configDirectory, { recursive: true });
      await writeFile(
        join(configDirectory, "config.toml"),
        `[deep_scan]\n${configuredHours === undefined ? "" : `max_time_hours = ${configuredHours}\n`}`,
      );

      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      const result = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "deep_scan_config.py"),
          "--available-parallelism",
          "8",
        ],
        {
          env: { ...process.env, CODEX_HOME: codexHome },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
      expect(JSON.parse(new TextDecoder().decode(result.stdout))).toMatchObject(
        {
          maxTimeHours: expectedHours,
        },
      );
    },
  );

  test("loads an explicitly isolated Deep Scan configuration", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-isolated-config-")),
    );
    temporaryDirectories.push(root);
    const codexHome = join(root, "codex-home");
    const sharedConfig = join(codexHome, "codex-security", "config.toml");
    const isolatedConfig = join(root, "isolated-deep-scan.toml");
    await mkdir(dirname(sharedConfig), { recursive: true });
    await writeFile(sharedConfig, "[deep_scan]\nworkers = 2\n");
    await writeFile(isolatedConfig, "[deep_scan]\nworkers = 7\n");
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();

    const result = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "deep_scan_config.py"),
        "--available-parallelism",
        "8",
      ],
      {
        env: {
          ...process.env,
          CODEX_HOME: codexHome,
          CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: isolatedConfig,
        },
        stdout: "pipe",
        stderr: "pipe",
      },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toMatchObject({
      workers: 7,
    });
  });

  test("rejects invalid discovery deadlines before returning scan configuration", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-invalid-deadline-")),
    );
    temporaryDirectories.push(root);
    const codexHome = join(root, "codex-home");
    const configDirectory = join(codexHome, "codex-security");
    const configPath = join(configDirectory, "config.toml");
    await mkdir(configDirectory, { recursive: true });
    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();

    for (const hours of ["0", "-0.5", "true", '"2"', "nan", "inf", "96.5"]) {
      await writeFile(configPath, `[deep_scan]\nmax_time_hours = ${hours}\n`);
      const result = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          join(PLUGIN_ROOT, "scripts", "deep_scan_config.py"),
          "--available-parallelism",
          "8",
        ],
        {
          env: { ...process.env, CODEX_HOME: codexHome },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      expect(result.exitCode).not.toBe(0);
      expect(new TextDecoder().decode(result.stderr)).toContain(
        "deep_scan.max_time_hours must be a positive finite number no greater than 96",
      );
    }
  });

  test.each([false, true] as const)(
    "backfills and repairs discovery deadline migration when already recorded: %s",
    (migrationRecorded) => {
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      const script = [
        "import json, runpy, sqlite3, sys",
        "from unittest import mock",
        "namespace = runpy.run_path(sys.argv[1], run_name='codex_security_workbench_db')",
        "apply_migrations = namespace['apply_migrations']",
        "connection = sqlite3.connect(':memory:')",
        "connection.row_factory = sqlite3.Row",
        "historical = tuple(item for item in namespace['MIGRATIONS'] if item[0] < 28)",
        "with mock.patch.dict(apply_migrations.__globals__, {'MIGRATIONS': historical}):",
        "    apply_migrations(connection)",
        "timestamp = '2026-07-01T00:00:00Z'",
        "connection.execute('INSERT INTO workspaces (id, created_at, updated_at) VALUES (?, ?, ?)', ('legacy-workspace', timestamp, timestamp))",
        "connection.execute(\"INSERT INTO scans (id, workspace_id, target_path, target_revision, scope, mode, scan_dir, status, phase, started_at, created_at, updated_at) VALUES (?, ?, '/legacy/target', 'legacy-revision', '.', 'deep', '/legacy/scan', 'running', 'discovery', ?, ?, ?)\", ('legacy-scan', 'legacy-workspace', timestamp, timestamp, timestamp))",
        "connection.execute(\"INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, created_at, updated_at) VALUES (?, 1, 'legacy-workflow', 'running', 'discovery', 1, 0, 3, 10, ?, ?)\", ('legacy-scan', timestamp, timestamp))",
        "if sys.argv[2] == 'true':",
        "    connection.execute('INSERT INTO schema_migrations (version, name, applied_at) VALUES (28, ?, ?)', ('persist deep scan discovery time limit', timestamp))",
        "connection.commit()",
        "apply_migrations(connection)",
        "default = connection.execute('SELECT max_time_hours FROM deep_scan_runs').fetchone()[0]",
        "connection.execute('UPDATE deep_scan_runs SET max_time_hours = 2.5')",
        "connection.commit()",
        "apply_migrations(connection)",
        "configured = connection.execute('SELECT max_time_hours FROM deep_scan_runs').fetchone()[0]",
        "migration = connection.execute('SELECT name FROM schema_migrations WHERE version = 28').fetchone()[0]",
        "print(json.dumps({'default': default, 'configured': configured, 'migration': migration}))",
      ].join("\n");
      const result = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          "-c",
          script,
          join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
          String(migrationRecorded),
        ],
        { stdout: "pipe", stderr: "pipe" },
      );
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
      expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
        default: 96,
        configured: 2.5,
        migration: "persist deep scan discovery time limit",
      });
    },
  );

  test.each([
    ["repository", false],
    ["scoped_path", false],
    ["repository", true],
  ] as const)(
    "returns an honest partial %s report with existing deferred work %s when saturated discovery exceeds its cost limit",
    async (inventoryStrategy, existingDeferred) => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-deep-budget-recovery-")),
      );
      temporaryDirectories.push(root);
      const repository = join(root, "repository");
      const scanDir = join(root, "scan");
      const stateDir = join(root, "state");
      await mkdir(join(repository, "src"), { recursive: true });
      await mkdir(join(repository, "shared"), { recursive: true });
      await mkdir(scanDir, { mode: 0o700 });
      await writeFile(
        join(repository, "src", "source.py"),
        "# source fixture\n",
      );
      await writeFile(
        join(repository, "shared", "support.py"),
        "# supporting context\n",
      );
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();

      const command = (args: string[]): Record<string, unknown> => {
        const result = Bun.spawnSync(
          [
            python!,
            "-I",
            "-B",
            join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
            ...args,
          ],
          {
            env: { ...process.env, CODEX_SECURITY_STATE_DIR: stateDir },
            stdout: "pipe",
            stderr: "pipe",
          },
        );
        expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(
          0,
        );
        return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
          string,
          unknown
        >;
      };
      const scoped = inventoryStrategy === "scoped_path";
      const registration = command([
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        scanDir,
        "--recipe-json",
        JSON.stringify({
          config: {},
          mode: "deep",
          repository,
          target: {
            kind: scoped ? "paths" : "repository",
            paths: scoped ? ["src"] : [],
          },
          maxCostUsd: 10,
        }),
      ]);
      const scanId = registration["scanId"] as string;
      const targetId = registration["targetId"] as string;
      command([
        "begin-deep-scan",
        "--scan-id",
        scanId,
        "--thread-id",
        "budget-recovery-thread",
        "--scan-root",
        join(root, "scans"),
        "--available-parallelism",
        "4",
        "--workflow-version",
        "deep-scan-mcp/v1",
      ]);
      const discoveryDir = join(scanDir, "artifacts", "02_discovery");
      await mkdir(discoveryDir, { recursive: true });
      await writeFile(
        join(discoveryDir, "in_scope_files.txt"),
        "src/source.py\n",
      );
      const candidateLocations = [
        { path: "src/source.py", start_line: 1, end_line: 1, role: "sink" },
        ...(scoped
          ? [
              {
                path: "shared/support.py",
                start_line: 1,
                end_line: 1,
                role: "evidence",
              },
            ]
          : []),
      ];
      const candidates = [
        {
          candidate_id: "candidate-001",
          cwe_ids: ["CWE-862"],
          locations: candidateLocations,
          summary: "Possible missing authorization",
          evidence: "The request reaches a protected handler.",
        },
        {
          candidate_id: "candidate-suppressed",
          cwe_ids: ["CWE-862"],
          locations: candidateLocations,
          summary: "Authorization guard already protects the handler",
          evidence: "The request is rejected by the existing policy.",
          validation: { disposition: "suppressed" },
        },
        {
          candidate_id: "candidate-not-applicable",
          cwe_ids: ["CWE-862"],
          locations: candidateLocations,
          summary: "Handler cannot receive external requests",
          evidence: "The handler is only reachable from trusted callers.",
          validation: { disposition: "not_applicable" },
        },
        {
          candidate_id: "candidate-ignored",
          cwe_ids: ["CWE-862"],
          locations: candidateLocations,
          summary: "Attack path does not cross the trust boundary",
          evidence: "An attacker cannot reach the authorization sink.",
          validation: { disposition: "reportable" },
          attack_path: { decision: "ignore" },
        },
        {
          candidate_id: "candidate-deferred",
          cwe_ids: ["CWE-862"],
          locations: candidateLocations,
          summary: "Authorization proof needs runtime evidence",
          evidence: "The runtime permission policy could not be inspected.",
          validation: {
            disposition: "deferred",
            remaining_uncertainty:
              "Runtime policy configuration is unavailable.",
          },
          attack_path: { decision: "ignore" },
        },
      ];
      await writeFile(
        join(discoveryDir, "candidate_ledger.jsonl"),
        `${candidates.map((candidate) => JSON.stringify(candidate)).join("\n")}\n`,
      );
      const terminalManifest = join(scanDir, "coordinator-manifest.json");
      await writeFile(terminalManifest, "{}\n");
      const terminal = Bun.spawnSync(
        [
          python!,
          "-I",
          "-B",
          "-c",
          "import sqlite3,sys; connection=sqlite3.connect(sys.argv[1]); connection.execute(\"UPDATE deep_scan_runs SET status='succeeded', phase='terminal', terminal_reason='saturated', manifest_path=? WHERE scan_id=?\",sys.argv[2:]); connection.commit()",
          join(stateDir, "workbench.sqlite3"),
          terminalManifest,
          scanId,
        ],
        { stdout: "pipe", stderr: "pipe" },
      );
      expect(terminal.exitCode, new TextDecoder().decode(terminal.stderr)).toBe(
        0,
      );
      if (existingDeferred) {
        await Promise.all([
          writeFile(
            join(scanDir, "scan-manifest.json"),
            JSON.stringify({
              scan: {
                target: {
                  kind: "directory_snapshot",
                  targetId,
                  displayName: "repository",
                },
                scope: { limitations: [], validationMode: "incomplete" },
              },
            }),
          ),
          writeFile(
            join(scanDir, "findings.json"),
            JSON.stringify({ findings: [] }),
          ),
          writeFile(
            join(scanDir, "coverage.json"),
            JSON.stringify({
              completeness: "partial",
              inventoryStrategy,
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                {
                  id: "candidate-001",
                  candidateId: "candidate-001",
                  reason:
                    "Existing candidate validation dependency was unavailable.",
                  paths: ["src/source.py"],
                },
                {
                  id: "candidate-deferred",
                  candidateId: "candidate-deferred",
                  reason: "Existing runtime policy could not be inspected.",
                  paths: ["src/source.py"],
                },
              ],
            }),
          ),
        ]);
      }
      const warning =
        "Scan stopped: estimated cost $10.08 exceeded the $10.00 limit.";
      const completed = command([
        "complete-budget-exhausted-scan",
        "--scan-id",
        scanId,
        "--cost-json",
        JSON.stringify({
          model: "gpt-5.6-sol",
          inputTokens: 1_000,
          cachedInputTokens: 0,
          cacheWriteInputTokens: 0,
          outputTokens: 100,
          estimatedUsd: 10.08,
        }),
        "--message",
        warning,
      ]);
      const scan = completed["scan"] as {
        progress: { status: string };
        warnings: string[];
      };
      expect(scan.progress.status).toBe("complete");
      expect(scan.warnings).toContain(warning);
      const findings = JSON.parse(
        await readFile(join(scanDir, "findings.json"), "utf8"),
      ) as { findings: unknown[] };
      expect(findings.findings).toEqual([]);
      const coverage = JSON.parse(
        await readFile(join(scanDir, "coverage.json"), "utf8"),
      ) as {
        completeness: string;
        inventoryStrategy: string;
        includePaths: string[];
        deferred: Array<{
          id: string;
          candidateId?: string;
          reason: string;
          paths?: string[];
        }>;
        surfaces: Array<{ id: string; disposition: string }>;
      };
      expect(coverage).toMatchObject({
        completeness: "partial",
        inventoryStrategy,
        includePaths: scoped ? ["src"] : ["."],
      });
      if (existingDeferred) {
        expect(coverage.deferred).toEqual([
          {
            id: "candidate-001",
            candidateId: "candidate-001",
            reason: "Existing candidate validation dependency was unavailable.",
            paths: ["src/source.py"],
          },
          {
            id: "candidate-deferred",
            candidateId: "candidate-deferred",
            reason: "Existing runtime policy could not be inspected.",
            paths: ["src/source.py"],
          },
          {
            id: "scan-cost-limit",
            reason:
              "Validation was deferred because the scan reached its cost limit.",
          },
        ]);
      } else {
        expect(coverage.deferred).toEqual([
          expect.objectContaining({
            id: "candidate-001",
            reason: expect.stringContaining("Possible missing authorization"),
            paths: scoped
              ? ["src/source.py", "shared/support.py"]
              : ["src/source.py"],
          }),
          expect.objectContaining({
            id: "candidate-deferred",
            reason: expect.stringContaining(
              "Authorization proof needs runtime evidence",
            ),
            paths: scoped
              ? ["src/source.py", "shared/support.py"]
              : ["src/source.py"],
          }),
        ]);
      }
      expect(coverage.surfaces).toEqual(
        expect.arrayContaining([
          ...(existingDeferred
            ? []
            : [
                expect.objectContaining({
                  id: "candidate-candidate-001",
                  disposition: "needs_follow_up",
                }),
              ]),
          expect.objectContaining({
            id: "candidate-candidate-suppressed",
            disposition: "rejected",
          }),
          expect.objectContaining({
            id: "candidate-candidate-not-applicable",
            disposition: "not_applicable",
          }),
          expect.objectContaining({
            id: "candidate-candidate-ignored",
            disposition: "rejected",
          }),
          ...(existingDeferred
            ? []
            : [
                expect.objectContaining({
                  id: "candidate-candidate-deferred",
                  disposition: "needs_follow_up",
                }),
              ]),
        ]),
      );
      const report = await readFile(join(scanDir, "report.md"), "utf8");
      expect(report).toContain(
        "No findings were validated before the scan reached its cost limit.",
      );
      if (existingDeferred) {
        expect(report).toContain(
          "Existing candidate validation dependency was unavailable.",
        );
        expect(report).toContain(
          "Existing runtime policy could not be inspected.",
        );
      } else {
        expect(report).toContain("Possible missing authorization");
        expect(report).toContain("The request reaches a protected handler.");
      }
      expect(report).toContain(
        "Authorization guard already protects the handler",
      );
      expect(report).toContain("Handler cannot receive external requests");
      expect(report).toContain("Attack path does not cross the trust boundary");
      expect(report).not.toContain(
        "No reportable findings survived the canonical discovery, validation",
      );
    },
  );

  test.each([
    [
      "a deferred discovery candidate",
      "Validation was deferred because the scan reached its cost limit: candidate evidence.",
      true,
    ],
    [
      "a cost-limited scan without candidates",
      "Validation was deferred because the scan reached its cost limit.",
      true,
    ],
    [
      "an unrelated retry budget",
      "The retry budget was exhausted while checking the service.",
      false,
    ],
    [
      "an unrelated resource budget",
      "Validation exceeded the container resource budget.",
      false,
    ],
    [
      "an unrelated service cost limit",
      "A dependent service reached its configured cost limit.",
      false,
    ],
    [
      "a similar non-workbench cost limit",
      "Validation was deferred because the scan reached its cost limit elsewhere.",
      false,
    ],
  ] as const)(
    "only describes an exhausted scan cost limit for %s",
    (_description, reason, exhausted) => {
      const python = Bun.which("python3") ?? Bun.which("python");
      expect(python).not.toBeNull();
      const script = [
        "import json, pathlib, runpy, sys",
        "plugin = pathlib.Path(sys.argv[1])",
        "examples = plugin / 'examples' / 'completed-scan'",
        "documents = [json.loads((examples / name).read_text()) for name in ('scan-manifest.json', 'findings.json', 'coverage.json')]",
        "manifest, findings, coverage = documents",
        "findings['findings'] = []",
        "coverage['completeness'] = 'partial'",
        "coverage['deferred'] = [{'id': 'candidate-example', 'reason': sys.argv[2]}]",
        "projection = runpy.run_path(str(plugin / 'scripts' / 'report_projection.py'))",
        "print(projection['build_report_markdown'](manifest, findings, coverage))",
      ].join("\n");
      const result = Bun.spawnSync(
        [python!, "-I", "-B", "-c", script, PLUGIN_ROOT, reason],
        { stdout: "pipe", stderr: "pipe" },
      );
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
      const report = new TextDecoder().decode(result.stdout);
      expect(
        report.includes(
          "No findings were validated before the scan reached its cost limit.",
        ),
      ).toBe(exhausted);
      expect(
        report.includes(
          "No reportable findings survived the canonical discovery, validation, and reportability gates.",
        ),
      ).toBe(!exhausted);
    },
  );

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

  test("completes an expired discovery deadline with no workers as honest partial coverage", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-empty-deadline-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const scanDir = join(root, "scan");
    const stateDir = join(root, "state");
    const codexHome = join(root, "codex-home");
    const configDir = join(codexHome, "codex-security");
    await Promise.all([
      mkdir(repository),
      mkdir(scanDir, { mode: 0o700 }),
      mkdir(configDir, { recursive: true }),
    ]);
    await Promise.all([
      writeFile(join(repository, "source.py"), "# source fixture\n"),
      writeFile(
        join(configDir, "config.toml"),
        "[deep_scan]\nworkers = 1\nmax_discovery_runs = 3\nmax_time_hours = 0.5\n",
      ),
    ]);

    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const command = (args: string[]): Record<string, unknown> => {
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
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
      return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
        string,
        unknown
      >;
    };
    const registration = command([
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "deep",
        repository,
        target: { kind: "repository", paths: [] },
      }),
    ]);
    const scanId = registration["scanId"] as string;
    const targetId = registration["targetId"] as string;
    const begun = command([
      "begin-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      "empty-deadline-thread",
      "--scan-root",
      join(root, "scans"),
      "--available-parallelism",
      "4",
      "--workflow-version",
      "deep-scan-mcp/v1",
    ])["deepScan"] as Record<string, unknown>;
    expect(begun).toMatchObject({
      status: "running",
      completionSequence: 0,
      canonicalArtifacts: null,
      config: { maxTimeHours: 0.5 },
    });

    const discoveryDir = join(scanDir, "artifacts", "02_discovery");
    await mkdir(discoveryDir, { recursive: true });
    const ledgerPath = join(discoveryDir, "candidate_ledger.jsonl");
    const inventoryPath = join(discoveryDir, "in_scope_files.txt");
    const manifestPath = join(scanDir, "coordinator-manifest.json");
    await Promise.all([
      writeFile(ledgerPath, ""),
      writeFile(inventoryPath, "source.py\n"),
      writeFile(manifestPath, "{}\n"),
    ]);
    const expired = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        "-c",
        [
          "import sqlite3, sys",
          "connection = sqlite3.connect(sys.argv[1])",
          "connection.execute('UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?', ('2000-01-01T00:00:00+00:00', sys.argv[2]))",
          "connection.commit()",
        ].join("\n"),
        join(stateDir, "workbench.sqlite3"),
        scanId,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(expired.exitCode, new TextDecoder().decode(expired.stderr)).toBe(0);

    const capped = command([
      "finish-deep-scan",
      "--scan-id",
      scanId,
      "--terminal-reason",
      "capped",
      "--manifest-path",
      manifestPath,
    ])["deepScan"] as Record<string, unknown>;
    expect(capped).toMatchObject({
      status: "succeeded",
      terminalReason: "capped",
      completionSequence: 0,
      workers: [],
      canonicalArtifacts: {
        candidateLedgerPath: ledgerPath,
        inScopeFilesPath: inventoryPath,
      },
    });
    expect(await readFile(ledgerPath, "utf8")).toBe("");

    const reason =
      "The configured discovery time limit elapsed before any source review completed.";
    await Promise.all([
      writeFile(
        join(scanDir, "scan-manifest.json"),
        JSON.stringify({
          scan: {
            target: {
              kind: "directory_snapshot",
              targetId,
              displayName: "repository",
            },
            scope: { limitations: [], validationMode: "incomplete" },
          },
        }),
      ),
      writeFile(
        join(scanDir, "findings.json"),
        JSON.stringify({ findings: [] }),
      ),
      writeFile(
        join(scanDir, "coverage.json"),
        JSON.stringify({
          completeness: "partial",
          inventoryStrategy: "repository",
          surfaces: [],
          explicitExclusions: [],
          deferred: [{ id: "source-review", reason }],
        }),
      ),
    ]);
    const completed = command(["complete-scan", "--scan-id", scanId])[
      "scan"
    ] as {
      progress: { status: string };
      findings: unknown[];
    };
    expect(completed.progress.status).toBe("complete");
    expect(completed.findings).toEqual([]);
    const coverage = JSON.parse(
      await readFile(join(scanDir, "coverage.json"), "utf8"),
    );
    expect(coverage).toMatchObject({
      completeness: "partial",
      mode: "deep_repository",
      deferred: [{ id: "source-review", reason }],
    });
    const report = await readFile(join(scanDir, "report.md"), "utf8");
    expect(report).toContain(
      "No source review completed before the configured time limit. " +
        "No vulnerability conclusion can be drawn.",
    );
    expect(report).not.toContain("No reportable findings survived");
    expect(report).not.toContain("No findings were validated before");
  });

  test("requeues a failed reducer's inputs and preserves findings at the discovery deadline", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-deep-reducer-recovery-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    const stateDir = join(root, "state");
    const codexHome = join(root, "codex-home");
    const configDir = join(codexHome, "codex-security");
    await mkdir(repository);
    await mkdir(configDir, { recursive: true });
    await writeFile(join(repository, "source.py"), "# source fixture\n");
    await writeFile(
      join(configDir, "config.toml"),
      "[deep_scan]\nworkers = 3\nmax_discovery_runs = 6\nmax_time_hours = 0.5\n",
    );

    const python = Bun.which("python3") ?? Bun.which("python");
    expect(python).not.toBeNull();
    const command = (args: string[]): Record<string, unknown> => {
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
      expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
      return JSON.parse(new TextDecoder().decode(result.stdout)) as Record<
        string,
        unknown
      >;
    };
    const state = (result: Record<string, unknown>) =>
      result["deepScan"] as Record<string, unknown>;
    const initial = state(
      command([
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
      ]),
    );
    const scanId = initial["scanId"] as string;
    const scanDir = initial["scanDir"] as string;
    expect(initial["config"]).toMatchObject({
      maxDiscoveryRuns: 6,
      maxTimeHours: 0.5,
    });
    const discoveryDir = join(scanDir, "artifacts", "02_discovery");
    const ledgerPath = join(discoveryDir, "candidate_ledger.jsonl");
    const existingFinding = '{"candidate":"previously committed"}\n';
    await mkdir(discoveryDir, { recursive: true });
    await writeFile(join(discoveryDir, "in_scope_files.txt"), "source.py\n");
    await writeFile(ledgerPath, existingFinding);

    const workerPaths = async (workerId: string) => {
      const artifactDir = join(
        scanDir,
        "artifacts",
        "deep_discovery",
        workerId,
      );
      const promptPath = join(artifactDir, "prompt.md");
      const resultPath = join(artifactDir, "result.json");
      await mkdir(artifactDir, { recursive: true });
      await writeFile(promptPath, "Review the source.\n");
      return { artifactDir, promptPath, resultPath };
    };
    const discoveryIds = [
      "10000000-0000-4000-8000-000000000001",
      "10000000-0000-4000-8000-000000000002",
      "10000000-0000-4000-8000-000000000003",
      "10000000-0000-4000-8000-000000000004",
      "10000000-0000-4000-8000-000000000005",
    ];
    for (const workerId of discoveryIds) {
      const paths = await workerPaths(workerId);
      const args = [
        "upsert-deep-scan-worker",
        "--scan-id",
        scanId,
        "--worker-id",
        workerId,
        "--kind",
        "discovery",
        "--prompt-path",
        paths.promptPath,
        "--artifact-dir",
        paths.artifactDir,
        "--attempt",
        "1",
      ];
      command([...args, "--status", "running"]);
      await writeFile(paths.resultPath, "{}\n");
      command([
        ...args,
        "--status",
        "succeeded",
        "--result-manifest-path",
        paths.resultPath,
      ]);
    }

    const startReducer = async (workerId: string, inputIds: string[]) => {
      const paths = await workerPaths(workerId);
      command([
        "claim-deep-scan-dedup",
        "--scan-id",
        scanId,
        "--worker-id",
        workerId,
        "--prompt-path",
        paths.promptPath,
        "--artifact-dir",
        paths.artifactDir,
        ...inputIds.flatMap((inputId) => ["--input-worker-id", inputId]),
      ]);
      const args = [
        "upsert-deep-scan-worker",
        "--scan-id",
        scanId,
        "--worker-id",
        workerId,
        "--kind",
        "dedup",
        "--prompt-path",
        paths.promptPath,
        "--artifact-dir",
        paths.artifactDir,
        "--attempt",
        "1",
      ];
      command([...args, "--status", "running"]);
      return { args, ...paths };
    };
    const commitReducer = async (
      workerId: string,
      resultPath: string,
      newFindingsCount: number,
    ) => {
      await writeFile(resultPath, "{}\n");
      return state(
        command([
          "commit-deep-scan-dedup",
          "--scan-id",
          scanId,
          "--worker-id",
          workerId,
          "--result-manifest-path",
          resultPath,
          "--new-findings-count",
          String(newFindingsCount),
        ]),
      );
    };
    const previousReducerId = "20000000-0000-4000-8000-000000000001";
    const previous = await startReducer(
      previousReducerId,
      discoveryIds.slice(0, 2),
    );
    await commitReducer(previousReducerId, previous.resultPath, 1);

    const failedReducerId = "20000000-0000-4000-8000-000000000002";
    const claimedInputs = discoveryIds.slice(2, 4);
    const failedReducer = await startReducer(failedReducerId, claimedInputs);
    const failureArgs = [
      ...failedReducer.args,
      "--status",
      "failed",
      "--error-message",
      "reducer exhausted its attempts",
    ];
    const failed = state(command(failureArgs));
    const workersById = (result: Record<string, unknown>) =>
      new Map(
        (result["workers"] as Record<string, unknown>[]).map((worker) => [
          worker["id"] as string,
          worker,
        ]),
      );
    const failedWorkers = workersById(failed);
    expect(failed).toMatchObject({
      status: "running",
      phase: "discovery",
      dispatchedCount: 5,
      consecutiveErrors: 0,
    });
    for (const workerId of discoveryIds.slice(0, 2)) {
      expect(failedWorkers.get(workerId)).toMatchObject({
        status: "succeeded",
        mergeState: "merged",
      });
    }
    for (const workerId of discoveryIds.slice(2)) {
      expect(failedWorkers.get(workerId)).toMatchObject({
        status: "succeeded",
        mergeState: "buffered",
      });
    }
    expect(failedWorkers.get(failedReducerId)).toMatchObject({
      status: "failed",
      error: "reducer exhausted its attempts",
    });
    expect(await readFile(ledgerPath, "utf8")).toBe(existingFinding);

    const replacementReducerId = "20000000-0000-4000-8000-000000000003";
    const replacementInputs = discoveryIds.slice(2);
    const replacement = await startReducer(
      replacementReducerId,
      replacementInputs,
    );
    const replayed = state(command(failureArgs));
    expect(replayed["phase"]).toBe("reducing");
    for (const workerId of replacementInputs) {
      expect(workersById(replayed).get(workerId)?.["mergeState"]).toBe(
        "merging",
      );
    }

    const committed = await commitReducer(
      replacementReducerId,
      replacement.resultPath,
      0,
    );
    for (const workerId of discoveryIds) {
      expect(workersById(committed).get(workerId)?.["mergeState"]).toBe(
        "merged",
      );
    }
    expect(workersById(committed).get(failedReducerId)?.["status"]).toBe(
      "failed",
    );
    expect(await readFile(ledgerPath, "utf8")).toBe(existingFinding);

    const manifestPath = join(scanDir, "coordinator-manifest.json");
    await writeFile(manifestPath, "{}\n");
    const premature = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        join(PLUGIN_ROOT, "scripts", "workbench_db.py"),
        "finish-deep-scan",
        "--scan-id",
        scanId,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        manifestPath,
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
    expect(premature.exitCode).not.toBe(0);
    expect(new TextDecoder().decode(premature.stderr)).toContain(
      "before reaching its configured maximum",
    );
    expect(await readFile(ledgerPath, "utf8")).toBe(existingFinding);

    const expire = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        "-c",
        [
          "import sqlite3, sys",
          "connection = sqlite3.connect(sys.argv[1])",
          "connection.execute('UPDATE deep_scan_runs SET created_at = ? WHERE scan_id = ?', ('2000-01-01T00:00:00+00:00', sys.argv[2]))",
          "connection.commit()",
        ].join("\n"),
        join(stateDir, "workbench.sqlite3"),
        scanId,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    expect(expire.exitCode, new TextDecoder().decode(expire.stderr)).toBe(0);

    const completed = state(
      command([
        "finish-deep-scan",
        "--scan-id",
        scanId,
        "--terminal-reason",
        "capped",
        "--manifest-path",
        manifestPath,
      ]),
    );
    expect(completed).toMatchObject({
      status: "succeeded",
      terminalReason: "capped",
      consecutiveErrors: 0,
    });
    expect(await readFile(ledgerPath, "utf8")).toBe(existingFinding);
  });
});
