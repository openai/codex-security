import { createCliTest } from "./support/cli-run.js";
import { workbenchCommand } from "./support/workbench-command.js";
import { runWorkbenchFixtureCommands } from "./support/workbench-fixtures.js";
import { gitText, runCommand } from "./support/shell.js";
import { git as fixtureGit } from "./git-fixture.js";
import { readJsonLines } from "./support/json.js";
import { randomUUID } from "node:crypto";
import { stripVTControlCharacters } from "node:util";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { main } from "../src/cli.js";
import { scanPreflightCodexConfig, type ScanOptions } from "../src/api.js";
import { ScanCostTracker } from "../src/cost.js";
import type { JsonObject } from "../src/config.js";
import { runWorkbench } from "../src/runtime.js";
import { workbenchArgs } from "../src/workbench-arguments.js";
import { readKnowledgeBaseSnapshot } from "../src/knowledge-base.js";
import { saveScanKnowledge, scanInputIdentity } from "../src/scan-inputs.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { runPython } from "./support/python-probe.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { completedEvents, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { fail } from "./support/errors.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function interruptedScan(
  mode: "deep" | "standard" = "deep",
  bulk = false,
  settings: Pick<
    ScanOptions,
    | "safetyIdentifier"
    | "postScanPrompt"
    | "auth"
    | "knowledgeBasePaths"
    | "cyberAccessProgram"
  > & { config?: JsonObject } = {},
  resolvedDeep = false,
  modelProvider?: string,
  knowledgeState: "saved" | "legacy" = "saved",
  separateSetupCommands = false,
) {
  const root = await temporaryDirectory();
  const repository = bulk
    ? join(root, "checkouts", "repo")
    : join(root, "repository");
  const scanDir = bulk
    ? join(root, "artifacts", "repo", "attempt-1")
    : join(root, "scan");
  const codexHome = join(root, "state", "codex-home");
  await mkdir(repository, { recursive: true });
  await mkdir(scanDir, { recursive: true, mode: 0o700 });
  await mkdir(join(codexHome, "sessions"), { recursive: true });
  await writeFile(join(repository, "source.py"), "# synthetic source\n");
  const input = join(root, "repositories.csv");
  if (bulk) {
    const git = (...args: string[]) =>
      gitText(["-C", repository, ...args]).trim();
    git("init", "-q");
    git("config", "--local", "core.autocrlf", "false");
    git("add", ".");
    git(
      "-c",
      "user.name=Recovery Test",
      "-c",
      "user.email=recovery@example.test",
      "commit",
      "-qm",
      "initial",
    );
    const source = join(root, "source");
    git("clone", "--quiet", "--no-hardlinks", repository, source);
    const task = {
      id: "repo",
      repository: source,
      revision: git("rev-parse", "HEAD"),
      mode,
    };
    await writeFile(
      input,
      `id,repository,revision,mode\nrepo,${source},${task.revision},${mode}\n`,
    );
    await writeFile(
      join(root, "manifest.json"),
      JSON.stringify(
        {
          version: 2,
          tasks: [task],
          ...(settings.knowledgeBasePaths?.length
            ? {
                knowledgeBaseDigests: {
                  [mode]: workflowDigest(
                    (
                      await readKnowledgeBaseSnapshot(
                        settings.knowledgeBasePaths,
                      )
                    ).documents,
                  ),
                },
              }
            : {}),
        },
        null,
        2,
      ) + "\n",
    );
    await writeFile(
      join(root, "results.jsonl"),
      JSON.stringify({
        ...task,
        status: "failed",
        attempt: 1,
        outputDir: scanDir,
        error: "Occupied attempt",
      }) + "\n",
    );
  }
  const python = Bun.which("python3") ?? Bun.which("python");
  if (python === null) throw new Error("Python is required for this test.");
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: codexHome,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    ...(modelProvider === "amazon-bedrock"
      ? { AWS_PROFILE: "synthetic-bedrock" }
      : {}),
    ...(settings.safetyIdentifier === undefined
      ? {}
      : { OPENAI_API_KEY: "synthetic-resume-key" }),
  };
  const command = workbenchCommand(python, () => environment);
  const knowledgeSnapshot =
    !bulk && knowledgeState === "saved" && settings.knowledgeBasePaths?.length
      ? await readKnowledgeBaseSnapshot(settings.knowledgeBasePaths)
      : undefined;
  const recipe = {
    repository,
    target: { kind: "repository", paths: [] },
    mode,
    config: {
      model: "gpt-5.6-sol",
      approval_policy: "never",
      ...(modelProvider === undefined ? {} : { model_provider: modelProvider }),
    },
    pluginVersion: "0.1.0",
    requiresScanPrompt: true,
    ...settings,
    ...(knowledgeSnapshot === undefined
      ? {}
      : {
          scanInputs: scanInputIdentity(
            "Keep the original scan instructions.",
            knowledgeSnapshot,
          ),
        }),
    ...(mode === "deep"
      ? {
          deepScan: {
            workers: 2,
            maxDiscoveryRuns: 5,
            ...(resolvedDeep
              ? {
                  subagents: 0,
                  stopAfterNoNew: 6,
                  stopAfterConsecutiveErrors: 2,
                  maxTimeHours: 1.5,
                }
              : {}),
          },
          ...(resolvedDeep ? { deepScanResolved: true } : {}),
        }
      : {}),
  };
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
      recipe,
      userContext: "Keep the original scan instructions.",
    }),
  );
  const scanId = registration["scanId"] as string;
  if (knowledgeSnapshot !== undefined)
    await saveScanKnowledge(scanDir, knowledgeSnapshot);
  const threadId = randomUUID();
  const setupCommands = [
    ["set-scan-thread", "--scan-id", scanId, "--thread-id", threadId],
  ];
  const sessionPath = join(codexHome, "sessions", `rollout-${threadId}.jsonl`);
  await writeFile(
    sessionPath,
    JSON.stringify({
      type: "session_meta",
      payload: { id: threadId, cwd: scanDir },
    }) + "\n",
  );
  if (mode === "deep") {
    setupCommands.push([
      "begin-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId,
      "--available-parallelism",
      "4",
      "--workflow-version",
      "deep-scan-mcp/v1",
    ]);
    const workerId = randomUUID();
    const prompt = join(scanDir, "setup-prompt.md");
    await writeFile(prompt, "Saved setup prompt.\n");
    for (const status of ["running", "succeeded"]) {
      setupCommands.push([
        "upsert-deep-scan-worker",
        "--scan-id",
        scanId,
        "--worker-id",
        workerId,
        "--kind",
        "setup",
        "--status",
        status,
        "--prompt-path",
        prompt,
        "--artifact-dir",
        scanDir,
      ]);
    }
  }
  if (separateSetupCommands) {
    for (const args of setupCommands) await command(args);
  } else {
    await runWorkbenchFixtureCommands(python, environment, setupCommands);
  }
  const checkpoint = join(scanDir, "checkpoint.json");
  await writeFile(checkpoint, '{"completed":"setup"}\n');
  return {
    root,
    repository,
    scanDir,
    codexHome,
    python,
    environment,
    command,
    recipe,
    scanId,
    threadId,
    registration,
    sessionPath,
    checkpoint,
    input,
  };
}

test("resume resolves an interrupted scan without changing its ID, recipe, or completed workers", async () => {
  // Retain the separate-process setup contract alongside the batched fixtures.
  const f = await interruptedScan(
    "deep",
    false,
    {},
    false,
    undefined,
    "saved",
    true,
  );
  const before = await f.command([
    "get-deep-scan",
    "--scan-id",
    f.scanId,
    "--thread-id",
    f.threadId,
  ]);
  const resumed = await f.command([
    "get-cli-scan-resume",
    "--scan-id",
    f.scanId,
  ]);
  expect(resumed).toMatchObject({
    ...f.registration,
    recipe: f.recipe,
    threadId: f.threadId,
  });
  expect(
    await f.command([
      "get-deep-scan",
      "--scan-id",
      f.scanId,
      "--thread-id",
      f.threadId,
    ]),
  ).toEqual(before);
  expect(await readFile(f.checkpoint, "utf8")).toBe('{"completed":"setup"}\n');
});

test("bare resume checks changed files with the host Git clean filter", async () => {
  const f = await interruptedScan("deep", true);
  const filter = "codex-test-clean";
  const checkoutBin = join(f.repository, "bin");
  const hostBin = join(f.root, "host-bin");
  const caller = join(f.root, "caller");
  for (const [label, bin] of [
    ["checkout", checkoutBin],
    ["caller", caller],
    ["host", hostBin],
  ] as const) {
    await mkdir(bin);
    await writeFile(
      join(bin, filter),
      `#!/bin/sh\necho ${label} >> .git/clean-calls\ncat\n`,
      { mode: 0o755 },
    );
  }
  gitText([
    "-C",
    f.repository,
    "config",
    "--local",
    "filter.fixture.clean",
    filter,
  ]);
  await writeFile(
    join(f.repository, ".gitattributes"),
    "source.py filter=fixture\n",
  );
  await appendFile(join(f.repository, "source.py"), "# changed\n");
  const result = await runCommand(
    process.execPath,
    [
      join(import.meta.dir, "../src/cli.ts"),
      "scans",
      "resume",
      f.scanId.slice(0, 8),
    ],
    {
      cwd: caller,
      env: {
        ...f.environment,
        PATH: [caller, checkoutBin, hostBin, f.environment.PATH].join(
          delimiter,
        ),
        PYTHON: f.python,
        CODEX_SECURITY_NO_UPDATE_CHECK: "1",
      },
    },
  );
  expect(result.status).toBe(2);
  expect(result.stderr).toContain(
    "original checkout revision or contents changed",
  );
  const calls = await readFile(
    join(f.repository, ".git", "clean-calls"),
    "utf8",
  );
  expect(new Set(calls.trim().split(/\s+/u))).toEqual(new Set(["host"]));
});

test.each([
  "failed",
  "canceled",
  "standard",
  "changed",
  "replaced",
  "wrong-owner",
])(
  "resume refuses %s scans without altering their saved state",
  async (scenario) => {
    const f = await interruptedScan(
      scenario === "standard" ? "standard" : "deep",
    );
    if (scenario === "failed")
      await f.command([
        "fail-scan",
        "--scan-id",
        f.scanId,
        "--message",
        "Synthetic failure",
      ]);
    if (scenario === "canceled")
      await f.command(["cancel-scan", "--scan-id", f.scanId]);
    if (scenario === "changed")
      await writeFile(join(f.repository, "source.py"), "# changed\n");
    if (scenario === "replaced") {
      await rename(f.repository, join(f.root, "original-repository"));
      await mkdir(f.repository);
      await writeFile(join(f.repository, "source.py"), "# synthetic source\n");
    }
    if (scenario === "wrong-owner")
      await f.command([
        "set-scan-thread",
        "--scan-id",
        f.scanId,
        "--thread-id",
        randomUUID(),
      ]);
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    expect(
      await f.command([
        "get-cli-scan-resume",
        "--scan-id",
        f.scanId,
        "--allow-unavailable",
      ]),
    ).toMatchObject({ unavailable: expect.any(String) });
    await expect(
      f.command(["get-cli-scan-resume", "--scan-id", f.scanId]),
    ).rejects.toThrow(
      scenario === "changed"
        ? "revision or contents changed"
        : scenario === "replaced"
          ? "checkout is missing or was replaced"
          : scenario === "wrong-owner"
            ? "original owning CLI session"
            : scenario === "standard"
              ? "Deep Scan with a saved CLI launch recipe"
              : "running scan; completed, failed, and canceled",
    );
    expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
      before,
    );
    expect(await readFile(f.checkpoint, "utf8")).toBe(
      '{"completed":"setup"}\n',
    );
  },
);

test("CLI resumes through native execution with current permissions and preserves interrupted state", async () => {
  const f = await interruptedScan();
  const feedbackPath = join(
    f.scanDir,
    "artifacts",
    "01_context",
    "false_positive_feedback.json",
  );
  const originalFeedback =
    JSON.stringify([{ reason: "Original reviewer rationale." }]) + "\n";
  await mkdir(join(f.scanDir, "artifacts", "01_context"), { recursive: true });
  await writeFile(feedbackPath, originalFeedback, { mode: 0o600 });
  const originalHome = join(f.root, "original-codex-home");
  await appendFile(
    f.sessionPath,
    JSON.stringify({
      type: "turn_context",
      payload: {
        permission_profile: {
          type: "managed",
          file_system: {
            type: "restricted",
            entries: [
              { path: { type: "path", path: originalHome }, access: "deny" },
            ],
          },
        },
      },
    }) + "\n",
  );
  const before = await f.command([
    "get-deep-scan",
    "--scan-id",
    f.scanId,
    "--thread-id",
    f.threadId,
  ]);
  let resumedThread: string | undefined;
  const { stderr, runCli } = createCliTest(main);

  const code = await runCli(["scans", "resume", f.scanId, "--json"], {
    ...dependencies({ environment: f.environment, currentDirectory: f.root }),
    runWorkbench: f.command,
    createSecurity: (config) =>
      new TestClient(config, {
        environment: f.environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(f.codexHome),
          deepScanConfigDirectory: join(f.codexHome, "worker-config"),
          deepScanConfigPath: join(
            f.codexHome,
            "worker-config",
            "deep-scan-config.toml",
          ),
        }),
        resolvePluginPython: async () => f.python,
        runWorkbench: (options, args, input) =>
          args[0] === "get-scan-feedback"
            ? Promise.resolve({
                scanId: f.scanId,
                targetId: f.registration["targetId"]!,
                falsePositives: Array.from({ length: 55 }, (_, index) => ({
                  reason: `New reviewer rationale ${index}`,
                })),
              })
            : runWorkbench(options, args, input),
        runDeepScan: async function* () {
          throw new Error("Resumed scans must refresh native permissions.");
        },
        createCodex: (options) => ({
          startThread: () => fail("Resume must not create a new thread."),
          resumeThread(threadId, threadOptions) {
            resumedThread = threadId;
            expect(threadOptions.workingDirectory).toBe(f.scanDir);
            expect(threadOptions.approvalPolicy).toBe("never");
            expect(options.config).toMatchObject({
              model: f.recipe.config["model"],
              default_permissions: "codex_security_scan",
            });
            const permissions = parseToml(
              options.configOverrides!.join("\n"),
            ) as {
              permissions: {
                codex_security_scan: { filesystem: Record<string, unknown> };
              };
            };
            const filesystem =
              permissions.permissions.codex_security_scan.filesystem;
            expect(filesystem[f.codexHome]).toEqual({ ".": "deny" });
            expect(filesystem[originalHome]).toBeUndefined();
            expect(options.env).toMatchObject({
              CODEX_SECURITY_SCAN_ID: f.scanId,
              CODEX_SECURITY_SCAN_DIR: f.scanDir,
            });
            return {
              id: threadId,
              async runStreamed(prompt) {
                expect(await readFile(feedbackPath, "utf8")).toBe(
                  originalFeedback,
                );
                expect(prompt).toContain(f.scanId);
                expect(prompt).toContain(
                  "Keep the original scan instructions.",
                );
                const joined = await f.command([
                  "begin-deep-scan",
                  "--scan-id",
                  f.scanId,
                  "--thread-id",
                  threadId,
                  "--available-parallelism",
                  "4",
                ]);
                expect(joined["deepScan"]).toMatchObject({
                  scanId: f.scanId,
                });
                throw new Error("Synthetic transport disconnected");
              },
            };
          },
        }),
      }),
  });
  expect(stderr.text()).toContain("Synthetic transport disconnected");
  expect(stderr.text()).toContain(`scans show ${f.scanId}`);
  expect(stderr.text()).toContain(`scans logs ${f.scanId}`);
  expect(code).not.toBe(0);
  expect(resumedThread).toBe(f.threadId);
  expect(
    await f.command([
      "get-deep-scan",
      "--scan-id",
      f.scanId,
      "--thread-id",
      f.threadId,
    ]),
  ).toEqual(before);
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "running" } });
  expect(await readFile(f.checkpoint, "utf8")).toBe('{"completed":"setup"}\n');
  expect(await readFile(feedbackPath, "utf8")).toBe(originalFeedback);
});

test("resumed Bedrock scans retain provider context for the account advisory", async () => {
  const f = await interruptedScan("deep", false, {}, false, "amazon-bedrock");
  const { stderr, runCli } = createCliTest(main);

  const code = await runCli(
    ["scans", "resume", f.scanId, "--json"],
    resumeDependencies(
      f,
      (options) => ({
        startThread() {
          throw new Error("Resume must not create a new thread.");
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          expect(options.env).toMatchObject({
            AWS_PROFILE: "synthetic-bedrock",
          });
          expect(options.apiKey).toBeUndefined();
          return {
            id: threadId,
            async runStreamed(prompt) {
              expect(prompt).toContain(
                "Amazon Bedrock with AWS authentication",
              );
              expect(prompt).toContain(
                "Skip the ChatGPT account Daybreak access advisory",
              );
              throw new Error("Resumed Bedrock prompt captured");
            },
          };
        },
      }),
      { deepScanConfigPath: join(f.codexHome, "deep-scan.toml") },
    ),
  );
  expect(code).not.toBe(0);
  expect(stderr.text()).toContain("Resumed Bedrock prompt captured");
});

function resumeDependencies(
  f: Awaited<ReturnType<typeof interruptedScan>>,
  createCodex: NonNullable<
    ConstructorParameters<typeof TestClient>[1]["createCodex"]
  >,
  runtimeOverrides: Partial<ReturnType<typeof preparedRuntime>> = {},
  workbench = runWorkbench,
) {
  return {
    ...dependencies({ environment: f.environment, currentDirectory: f.root }),
    runWorkbench: f.command,
    createSecurity: (config: ConstructorParameters<typeof TestClient>[0]) =>
      new TestClient(config, {
        environment: f.environment,
        prepareRuntime: async () => {
          const runtime = {
            ...preparedRuntime(f.codexHome),
            ...runtimeOverrides,
          };
          runtime.configPath = join(f.root, "resumed-runtime.toml");
          runtime.environment = Object.fromEntries(
            Object.entries(f.environment).filter(
              (entry): entry is [string, string] => entry[1] !== undefined,
            ),
          );
          runtime.plugin.version = JSON.parse(
            await readFile(
              join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
              "utf8",
            ),
          ).version;
          return runtime;
        },
        resolvePluginPython: async () => f.python,
        runWorkbench: workbench,
        createCodex,
      }),
  };
}

async function finishDiscovery(f: Awaited<ReturnType<typeof interruptedScan>>) {
  // Advance the persisted clock to exercise a coordinator reaching its time cap.
  const expired = runPython(f.python, [
    "-c",
    "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00+00:00' WHERE scan_id = ?\", (sys.argv[2],)); c.commit()",
    join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    f.scanId,
  ]);
  expect(expired.exitCode, new TextDecoder().decode(expired.stderr)).toBe(0);
  await copyCompletedScanFixture(f.scanDir);
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    const path = join(f.scanDir, name);
    const doc = JSON.parse(await readFile(path, "utf8"));
    if (name === "scan-manifest.json") {
      doc.scan.id = f.scanId;
      const contract = f.registration["contract"] as {
        target: { allowedKinds: string[] };
      };
      doc.scan.target = { kind: contract.target.allowedKinds[0] };
      delete doc.scan.sealedAt;
      delete doc.scan.artifacts;
    } else {
      doc.scanId = f.scanId;
      if (name === "findings.json") doc.findings = [];
      else {
        doc.mode = "deep_repository";
        doc.completeness = "partial";
        doc.surfaces = [];
        doc.deferred = [{ id: "time_cap", reason: "Synthetic time cap" }];
      }
    }
    await writeFile(path, JSON.stringify(doc) + "\n");
  }
  await f.command([
    "finish-deep-scan",
    "--scan-id",
    f.scanId,
    "--terminal-reason",
    "capped",
    "--manifest-path",
    join(f.scanDir, "scan-manifest.json"),
  ]);
}

test("resumes the original Deep scan after its parent returns during consolidation", () =>
  parentReturnsDuringConsolidation());
test("resumes the original Deep scan when the process exits after turn.completed", () =>
  parentReturnsDuringConsolidation("signal"));
test("resumes the original Deep scan when Codex reports a closed WebSocket", () =>
  parentReturnsDuringConsolidation("websocket-close"));
test.each([
  [
    "a provider policy rejection",
    "stream disconnected before completion: Network access is disabled by policy",
  ],
  [
    "an invalid network policy",
    '{"error":{"code":"invalid_request_error","message":"Unsupported network policy"}}',
  ],
  [
    "HTTP 422 with timeout wording",
    "unexpected status 422 Unprocessable Entity: Network request timed out",
  ],
])("keeps a parent terminal after %s", (_kind, message) =>
  parentReturnsDuringConsolidation(undefined, message),
);
test("resumes a nested Git target with knowledge in the scanned directory", () =>
  parentReturnsDuringConsolidation("nested-knowledge"));
test("does not offer bare resume with knowledge from a separate checkout", () =>
  parentReturnsDuringConsolidation("external-knowledge"));
test.each(["fail-scan", "get-scan"] as const)(
  "honors an explicit abort after the handoff's %s returns",
  (transition) => parentReturnsDuringConsolidation(transition),
);

test("a peer resume can seal a preserved scan", () =>
  parentReturnsDuringConsolidation("peer-resume"));
test("runs the requested post-scan prompt once after a failed Deep scan", () =>
  parentReturnsDuringConsolidation("post-scan"));
test.each(["--validate", "--patch"] as const)(
  "retains the terminal Deep Scan outcome when the CLI owns %s",
  (action) => parentReturnsDuringConsolidation(action),
);

async function parentReturnsDuringConsolidation(
  transition?:
    | "signal"
    | "websocket-close"
    | "fail-scan"
    | "get-scan"
    | "peer-resume"
    | "nested-knowledge"
    | "external-knowledge"
    | "--validate"
    | "--patch"
    | "post-scan",
  rejection?: string,
) {
  const cancellation = new AbortController();
  const f = await interruptedScan("standard");
  const { root, codexHome, python, environment, command } = f;
  const nested = transition === "nested-knowledge";
  const repository = nested ? join(f.repository, "service") : f.repository;
  const userSkill = { path: join(root, "custom", "SKILL.md"), enabled: false };
  const installedRoot = join(codexHome, "plugins", "cache", "codex-security");
  const extraArgs: string[] = [];
  const cliFollowup = transition === "--validate" || transition === "--patch";
  if (cliFollowup) extraArgs.push(transition);
  if (nested || transition === "external-knowledge") {
    const checkout = nested ? f.repository : await temporaryDirectory();
    fixtureGit(checkout, "init", "-q");
    if (nested) {
      await mkdir(repository);
      await writeFile(join(repository, "source.py"), "# synthetic service\n");
    }
    const document = join(nested ? repository : checkout, "architecture.md");
    await writeFile(document, "Synthetic architecture.\n");
    if (nested) {
      fixtureGit(checkout, "add", ".");
      fixtureGit(checkout, "commit", "--no-gpg-sign", "-qm", "Add service");
    }
    extraArgs.push("--knowledge-base", document);
  }
  const scanDir = join(root, "fresh-deep-scan");
  const threadId = randomUUID();
  const workers = Array.from({ length: 3 }, () => randomUUID());
  const reducer = randomUUID();
  const promptPath = join(scanDir, "worker.md");
  const resultManifestPath = join(scanDir, "worker-result.json");
  const postScanPrompt = "Report only when the scan is terminal.";
  if (transition === "post-scan") {
    const promptFile = join(root, "post-scan.md");
    await writeFile(promptFile, postScanPrompt);
    extraArgs.push("--post-scan-prompt-file", promptFile);
  }
  let scanId = "";
  let parentTurns = 0;
  let resumeTurns = 0;
  const followupStates: string[] = [];
  let registration: JsonObject = {};
  async function* startDiscovery() {
    // Only session identity is known; this fixture has no cumulative token receipt.
    await writeFile(
      join(codexHome, "sessions", "rollout.jsonl"),
      JSON.stringify({
        type: "session_meta",
        payload: { id: threadId, cwd: scanDir },
      }) + "\n",
    );
    await writeFile(promptPath, "Review the synthetic source.\n");
    await writeFile(resultManifestPath, "{}\n");
    const paths = { scanId, promptPath, artifactDir: scanDir };
    const worker = (workerId: string, status: string, kind = "discovery") =>
      workbenchArgs("upsert-deep-scan-worker", {
        ...paths,
        workerId,
        kind,
        status,
        resultManifestPath:
          status === "succeeded" ? resultManifestPath : undefined,
        attempt: kind === "dedup" ? 1 : undefined,
      });
    const run = { scanId, threadId, availableParallelism: 4 };
    const claim = { ...paths, workerId: reducer, inputWorkerId: workers };
    await runWorkbenchFixtureCommands(python, environment, [
      workbenchArgs("begin-deep-scan", run),
      ...workers.flatMap((id) => [
        worker(id, "running"),
        worker(id, "succeeded"),
      ]),
      workbenchArgs("claim-deep-scan-dedup", claim),
      worker(reducer, "running", "dedup"),
    ]);
    const message =
      transition === "websocket-close"
        ? "stream disconnected before completion: websocket closed"
        : rejection;
    if (message) yield { type: "turn.failed" as const, error: { message } };
  }
  async function* parentEvents() {
    yield* completedEvents(threadId, startDiscovery());
    if (transition === "signal")
      throw new Error("Codex Exec exited with signal SIGKILL");
  }
  const createCodex: Parameters<typeof resumeDependencies>[1] = (options) => ({
    startThread: () => ({
      id: threadId,
      async runStreamed(prompt) {
        scanId =
          options.env?.["CODEX_SECURITY_SCAN_ID"] ?? fail("Expected scan ID");
        parentTurns++;
        if (prompt === postScanPrompt) {
          const { scan } = await command(workbenchArgs("get-scan", { scanId }));
          followupStates.push(
            (scan as { progress: { status: string } }).progress.status,
          );
          return { events: completedEvents(threadId) };
        }
        return { events: parentEvents() };
      },
    }),
    resumeThread(id) {
      expect(id).toBe(threadId);
      expect(options.config?.["features"]).toMatchObject({
        multi_agent_v2: {
          enabled: true,
          max_concurrent_threads_per_session: 4,
        },
      });
      expect(options.config?.["skills"]).toMatchObject({
        config: expect.arrayContaining([
          userSkill,
          {
            path: join(installedRoot, "skills", "security-scan", "SKILL.md"),
            enabled: false,
          },
        ]),
      });
      return {
        id,
        async runStreamed() {
          resumeTurns++;
          if (nested) {
            const staged =
              options.env?.["CODEX_SECURITY_KNOWLEDGE_BASE"] ??
              fail("Expected saved knowledge");
            expect(
              await readFile(join(staged, "0-architecture.md.txt"), "utf8"),
            ).toBe("Synthetic architecture.\n");
          }
          await command(
            workbenchArgs("commit-deep-scan-dedup", {
              scanId,
              workerId: reducer,
              resultManifestPath,
              newFindingsCount: 0,
            }),
          );
          await finishDiscovery({ ...f, scanId, scanDir, registration });
          return { events: completedEvents(id) };
        },
      };
    },
  });
  let preserved = false;
  const deps = resumeDependencies(
    f,
    createCodex,
    { plugin: { ...preparedRuntime(codexHome).plugin, installedRoot } },
    async (options, args, input) => {
      if (
        preserved &&
        transition === "peer-resume" &&
        args[0] === "get-scan" &&
        options.signal === undefined
      ) {
        preserved = false;
        await resume();
      }
      const result = await runWorkbench(options, args, input);
      if (result["preserved"] === true) preserved = true;
      if (preserved && args[0] === transition) cancellation.abort();
      return result;
    },
  );
  if (transition === "fail-scan" || transition === "get-scan") {
    await using client = deps.createSecurity({});
    await expect(
      client.run(repository, {
        mode: "deep",
        auth: "chatgpt",
        outputDir: scanDir,
        signal: cancellation.signal,
      }),
    ).rejects.toThrow("interrupted");
    expect(cancellation.signal.aborted).toBe(true);
    expect(await command(workbenchArgs("get-scan", { scanId }))).toMatchObject({
      scan: {
        progress: { status: "failed" },
        handoffCost: { inputTokens: 10, outputTokens: 3 },
      },
    });
    expect(
      await command(workbenchArgs("get-deep-scan", { scanId, threadId })),
    ).toMatchObject({
      deepScan: { status: "failed" },
    });
    const retry = createCliTest(main);
    expect(
      await retry.runCli(["scans", "resume", scanId, "--json"], deps),
    ).toBe(2);
    expect(parentTurns).toBe(1);
    expect(resumeTurns).toBe(0);
    return;
  }
  const first = createCliTest(main);
  const scan = ["scan", repository, "--mode", "deep", "--auth", "chatgpt"];
  using unreadableArchive =
    transition === undefined && rejection === undefined
      ? spyOn(ScanCostTracker.prototype, "refresh").mockRejectedValue(
          new Error("Session archive unavailable"),
        )
      : undefined;
  expect(
    await first.runCli(
      [
        ...scan,
        ...extraArgs,
        "--codex",
        "features.multi_agent_v2.max_concurrent_threads_per_session=4",
        "--codex",
        `skills.config=[{path=${JSON.stringify(userSkill.path)},enabled=false}]`,
        "--output-dir",
        scanDir,
        "--json",
      ],
      deps,
    ),
    first.stderr.text(),
  ).toBe(2);
  unreadableArchive?.mockRestore();
  const message = JSON.parse(first.stdout.text()).message;
  const saved = await command(workbenchArgs("get-scan", { scanId }));
  if (rejection) {
    expect(message).not.toContain("scans resume");
    expect(saved["scan"]).toMatchObject({
      progress: { status: "failed" },
      failureMessage: rejection,
    });
    expect(resumeTurns).toBe(0);
    return;
  }
  if (transition === "post-scan") {
    expect(followupStates).toEqual(["failed"]);
    expect(parentTurns).toBe(2);
    expect(resumeTurns).toBe(0);
  }
  if (
    cliFollowup ||
    transition === "external-knowledge" ||
    transition === "post-scan"
  ) {
    expect(message).toContain("Deep Scan discovery orchestration must finish");
    expect(message).not.toContain("scans resume");
    expect(saved["scan"]).toMatchObject({
      progress: { status: "failed" },
      failureMessage: message,
    });
    if (cliFollowup) {
      expect(first.stderr.text()).toContain(`scans show ${scanId}`);
      expect(first.stderr.text()).not.toMatch(
        /codex-security (?:validate |patch --scan)/u,
      );
      const retry = createCliTest(main);
      expect(await retry.runCli(["scans", "resume", scanId], deps)).toBe(2);
      expect(parentTurns).toBe(1);
      expect(resumeTurns).toBe(0);
    }
    return;
  }
  if (transition === "peer-resume") {
    expect(message).not.toContain("scans resume");
    expect(saved["scan"]).toMatchObject({ progress: { status: "complete" } });
    expect(saved["scan"]).not.toHaveProperty("cost");
    expect(parentTurns).toBe(1);
    expect(resumeTurns).toBe(1);
    return;
  }
  expect({
    message,
    parentTurns,
    scan: saved["scan"],
  }).toMatchObject({
    message: expect.stringContaining("codex-security scans resume " + scanId),
    parentTurns: 1,
    scan: {
      progress: {
        status: "running",
        independentReviews: { completed: 3, consolidating: true },
      },
    },
  });
  await resume();
  expect(resumeTurns).toBe(1);
  expect(parentTurns).toBe(1);

  async function resume() {
    registration = await command(
      workbenchArgs("get-cli-scan-resume", { scanId }),
    );
    expect(registration).toMatchObject({
      scanId,
      threadId,
      recipe: { repository },
    });
    if (nested)
      expect(registration["recipe"]).toMatchObject({
        checkoutRoot: f.repository,
      });
    if (transition === undefined || transition === "signal")
      expect(registration).toMatchObject({
        handoffCost: { inputTokens: 10, outputTokens: 3 },
      });
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(
      await runCli(
        ["scans", "resume", scanId, "--json"],
        resumeDependencies(f, createCodex),
      ),
      stderr.text(),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: scanId } },
      cost: null,
    });
  }
}

test("a resume cannot return a scan total when the parent hands off after attachment", () =>
  verifyConcurrentHandoff("gpt-5.6-sol"));
test("an unpriced model withholds turn-only tokens after a concurrent handoff", () =>
  verifyConcurrentHandoff("unpriced-test-model"));

async function verifyConcurrentHandoff(model: string) {
  const f = await interruptedScan("deep", false, { config: { model } });
  const cli = createCliTest(main);
  const deps = resumeDependencies(f, () => ({
    startThread: () => fail("Expected the original session"),
    resumeThread(id) {
      return {
        id,
        async runStreamed() {
          // The SDK has read the running scan, but its original owner now detaches.
          const handoff = await f.command([
            "fail-scan",
            "--scan-id",
            f.scanId,
            "--message",
            "Parent disconnected",
            "--preserve-deep-owner",
            id,
          ]);
          expect(handoff).toHaveProperty("preserved", true);
          await finishDiscovery(f);
          return { events: completedEvents(id) };
        },
      };
    },
  }));
  const exit = await cli.runCli(
    ["scans", "resume", f.scanId, "--json", "--show-cost"],
    deps,
  );
  expect(exit, cli.stderr.text()).toBe(0);
  expect(cli.stderr.text()).not.toContain("13 total");
  expect(cli.stderr.text()).not.toMatch(/\$[0-9]/);
  expect(
    (await f.command(workbenchArgs("get-scan", { scanId: f.scanId })))["scan"],
  ).not.toHaveProperty("cost");
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    cost: null,
    turn: { usage: null },
  });
}

test.each([false, true])(
  "resumed CLI starts with terminal Deep progress (interactive=%p)",
  async (interactive) => {
    const f = await interruptedScan();
    await finishDiscovery(f);
    const { stderr, runCli } = createCliTest(main, { stderr: interactive });
    const progress = Promise.withResolvers<void>();
    const deps = resumeDependencies(f, () => ({
      startThread: () => fail("Unexpected new session"),
      resumeThread(threadId) {
        expect(threadId).toBe(f.threadId);
        return {
          id: threadId,
          async runStreamed() {
            await progress.promise;
            const text = stripVTControlCharacters(stderr.text()).replace(
              /\s+/gu,
              " ",
            );
            expect(text).toContain("consolidating results");
            expect(text).toContain("Reviews: 0 completed, 0 active, cap 40");
            expect(text).not.toContain("Scan phase: discovery");
            throw new Error("Terminal progress captured");
          },
        };
      },
    }));
    const code = await runCli(["scans", "resume", f.scanId, "--json"], {
      ...deps,
      createSecurity: (config) => {
        const security = deps.createSecurity(config);
        const run = security.run.bind(security);
        security.run = (repository, options = {}) =>
          run(repository, {
            ...options,
            onDeepProgress(update) {
              options.onDeepProgress?.(update);
              progress.resolve();
            },
          });
        return security;
      },
    });
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Terminal progress captured");
  },
);

test.each([
  [false, false],
  [true, false],
  [false, true],
  [true, true],
])(
  "resumed CLI seals the original scan (coordinator finished: %p, bulk: %p)",
  async (alreadyFinished, bulk) => {
    const f = await interruptedScan("deep", bulk);
    if (alreadyFinished) await finishDiscovery(f);
    await appendFile(
      f.sessionPath,
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: 10000, output_tokens: 2000 },
          },
        },
      }) + "\n",
    );
    const { stdout, stderr, runCli } = createCliTest(main);

    const code = await runCli(
      bulk
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json", "--show-cost"],
      resumeDependencies(f, () => ({
        startThread: () => fail("Unexpected new session"),
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              if (!alreadyFinished) await finishDiscovery(f);
              return { events: completedEvents(threadId) };
            },
          };
        },
      })),
    );
    // A valid bounded result succeeds while retaining follow-up notes.
    expect(code, stderr.text()).toBe(0);
    const result = JSON.parse(stdout.text());
    if (bulk) {
      expect(result, stderr.text()).toMatchObject({
        completed: 1,
        failed: 0,
      });
      const receipts = await readJsonLines(result.resultsPath);
      expect(receipts).toHaveLength(2);
      expect(receipts[1]).toMatchObject({
        attempt: 1,
        outputDir: f.scanDir,
        status: "completed",
        cost: { inputTokens: 10000, outputTokens: 2000 },
      });
      // Reconcile a crash after sealing but before the bulk receipt was appended.
      await writeFile(result.resultsPath, JSON.stringify(receipts[0]) + "\n");
      const reconciledOutput = capture();
      expect(
        await main(
          ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
          reconciledOutput.stream,
          stderr.stream,
          {
            ...dependencies({
              onRun: () => fail("A sealed scan needs no Codex invocation"),
            }),
            runWorkbench: f.command,
          },
        ),
      ).toBe(0);
      expect(JSON.parse(reconciledOutput.text())).toMatchObject({
        completed: 1,
        failed: 0,
      });
      const reconciled = await readJsonLines(result.resultsPath);
      expect(reconciled[1]).toMatchObject({
        attempt: 1,
        cost: { inputTokens: 10000, outputTokens: 2000 },
      });
      // A subsequent bulk recovery must skip the reconciled completion.
      const nextOutput = capture();
      expect(
        await main(
          ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
          nextOutput.stream,
          stderr.stream,
          { ...dependencies(), runWorkbench: f.command },
        ),
      ).toBe(0);
      expect(JSON.parse(nextOutput.text())).toMatchObject({
        skipped: 1,
        completed: 1,
        failed: 0,
      });
    } else {
      expect(stderr.text()).toContain("Estimated cost: $");
      expect(result.coverage).not.toHaveProperty("completeness");
      expect(result.manifest.scan.id).toBe(f.scanId);
      expect(result.manifest.scan.sealedAt).toBeString();
      expect(result.cost.inputTokens).toBe(10000);
      expect(result.cost.outputTokens).toBe(2000);
    }
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
    });
    expect(
      (await f.command(["list-scans", "--repository", f.repository]))["scans"],
    ).toHaveLength(1);
    expect(await readFile(f.checkpoint, "utf8")).toBe(
      '{"completed":"setup"}\n',
    );
    await expect(
      f.command(["get-cli-scan-resume", "--scan-id", f.scanId]),
    ).rejects.toThrow("running scan");
  },
);

test.each([
  "single",
  "bulk",
  "unsupported-schema",
  "wrong-producer",
  "changed-findings",
])(
  "resume preserves sealed artifacts across a plugin upgrade (%s)",
  async (scenario) => {
    const f = await interruptedScan("deep", scenario === "bulk");
    await finishDiscovery(f);
    const oldPlugin = join(f.root, "old-plugin");
    for (const path of ["scripts", "schemas", "shared", ".codex-plugin"]) {
      await cp(join(PLUGIN_ROOT, path), join(oldPlugin, path), {
        recursive: true,
      });
    }
    const pluginManifest = join(oldPlugin, ".codex-plugin", "plugin.json");
    const plugin = JSON.parse(await readFile(pluginManifest, "utf8"));
    plugin.version = f.recipe.pluginVersion;
    await writeFile(pluginManifest, JSON.stringify(plugin));
    await runWorkbench(
      { python: f.python, pluginRoot: oldPlugin, environment: f.environment },
      ["prepare-scan-completion", "--scan-id", f.scanId],
    );
    const manifestPath = join(f.scanDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    expect(manifest.scan.producer.version).toBe(f.recipe.pluginVersion);
    if (scenario === "unsupported-schema") manifest.schemaVersion = "999.0";
    if (scenario === "wrong-producer")
      manifest.scan.producer.name = "different-producer";
    if (scenario === "unsupported-schema" || scenario === "wrong-producer") {
      await writeFile(manifestPath, JSON.stringify(manifest));
    }
    if (scenario === "changed-findings") {
      await appendFile(join(f.scanDir, "findings.json"), "\n");
    }
    const artifactNames = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
    ];
    const artifacts = await Promise.all(
      artifactNames.map((name) => readFile(join(f.scanDir, name))),
    );
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    const rejected = !["single", "bulk"].includes(scenario);
    let turns = 0;
    const { stdout, stderr, runCli } = createCliTest(main);

    const code = await runCli(
      scenario === "bulk"
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      resumeDependencies(f, () => ({
        startThread: () => fail("Unexpected new session"),
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              turns++;
              return { events: completedEvents(threadId) };
            },
          };
        },
      })),
    );
    expect(code, stderr.text()).toBe(rejected ? 2 : 0);
    expect(
      await Promise.all(
        artifactNames.map((name) => readFile(join(f.scanDir, name))),
      ),
    ).toEqual(artifacts);
    const after = await f.command(["get-scan", "--scan-id", f.scanId]);
    if (rejected) {
      expect(stderr.text()).toContain("Cannot resume sealed scan");
      expect(turns).toBe(0);
      expect(after).toEqual(before);
    } else {
      expect(after["scan"], stderr.text()).toMatchObject({
        progress: { status: "complete" },
        continuationThreadId: f.threadId,
      });
      if (scenario === "bulk") {
        expect(JSON.parse(stdout.text())).toMatchObject({
          completed: 1,
          failed: 0,
        });
        const receipts = await readJsonLines(join(f.root, "results.jsonl"));
        expect(receipts).toHaveLength(2);
        expect(receipts[1]).toMatchObject({
          attempt: 1,
          outputDir: f.scanDir,
          status: "completed",
        });
      }
    }
  },
);

test.each(["chatgpt", "api-key"] as const)(
  "CLI saves %s authentication and launch settings before execution",
  async (auth) => {
    const safetyIdentifier =
      auth === "chatgpt" ? undefined : "synthetic-original-user";
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "state", "codex-home");
    await mkdir(repository);
    await mkdir(codexHome, { recursive: true });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const promptFile = join(root, "post-scan.md");
    const postScanPrompt = "Keep these original post-scan instructions.\n";
    await writeFile(promptFile, postScanPrompt);
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-launch-key",
    };
    const command = workbenchCommand(python, () => environment);
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      [
        "scan",
        repository,
        "--mode",
        "deep",
        "--output-dir",
        join(root, "scan"),
        "--auth",
        auth,
        ...(safetyIdentifier === undefined
          ? []
          : ["--safety-identifier", safetyIdentifier]),
        "--post-scan-prompt-file",
        promptFile,
        "--json",
      ],
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: () => fail("Synthetic stop after registration"),
          }),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Synthetic stop after registration");
    await writeFile(
      promptFile,
      "Changed instructions that must not replace the saved text.",
    );
    await rm(promptFile);
    const scans = (await command(["list-scans", "--repository", repository]))[
      "scans"
    ] as Array<{ scanId: string }>;
    expect(scans).toHaveLength(1);
    const saved = await command([
      "get-scan-recipe",
      "--scan-id",
      scans[0]!.scanId,
    ]);
    expect(saved["recipe"]).toMatchObject({
      auth,
      ...(safetyIdentifier === undefined ? {} : { safetyIdentifier }),
      postScanPrompt,
    });
    expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
    expect(JSON.stringify(saved)).not.toContain(promptFile);
  },
);

test.each([
  ["chatgpt", false],
  ["api-key", false],
  [undefined, false],
  ["chatgpt", true],
  ["api-key", true],
  [undefined, true],
] as const)(
  "resume restores saved launch settings with %s auth (bulk: %p)",
  async (auth, bulk) => {
    const profile =
      auth === "chatgpt"
        ? "review.v2"
        : auth === "api-key"
          ? "review mode"
          : "分析";
    const selected = {
      model: `synthetic-${auth ?? "auto"}-model`,
      model_reasoning_effort: "high",
      daybreak: auth === "api-key",
      features: { goals: false },
    };
    const settings = {
      config: scanPreflightCodexConfig({
        model: "synthetic-root-model",
        model_reasoning_effort: "low",
        profile,
        profiles: { [profile]: selected },
      }),
      auth,
      cyberAccessProgram: "daybreak_blue" as const,
      safetyIdentifier:
        auth === "chatgpt" ? undefined : "synthetic-original-user",
      postScanPrompt: "Run these exact saved post-scan instructions.\n",
    };
    const f = await interruptedScan("deep", bulk, settings, true);
    f.environment.OPENAI_API_KEY = "synthetic-resume-key";
    const ambientHome = join(f.root, "ambient-codex-home");
    f.environment.CODEX_HOME = ambientHome;
    const ambientDeepConfig = join(
      ambientHome,
      "codex-security",
      "config.toml",
    );
    await mkdir(join(ambientHome, "codex-security"), { recursive: true });
    await writeFile(ambientDeepConfig, "invalid ambient TOML [");
    const prompts: string[] = [];
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      bulk
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      resumeDependencies(f, (options) => {
        expect(options.config).toMatchObject(selected);
        expect(options.env?.["CODEX_SAFETY_IDENTIFIER"]).toBe(
          settings.safetyIdentifier,
        );
        expect(options.apiKey).toBe(
          auth === "chatgpt" ? undefined : "synthetic-resume-key",
        );
        expect(options.env?.["OPENAI_API_KEY"]).toBeUndefined();
        expect(options.env?.["CODEX_API_KEY"]).toBeUndefined();
        expect(options.config?.["features"]).toMatchObject({
          api_key_cyber_access_programs: true,
        });
        return {
          startThread: () => fail("Resume must use the original session."),
          resumeThread(threadId) {
            expect(threadId).toBe(f.threadId);
            return {
              id: threadId,
              async runStreamed(prompt, turnOptions) {
                expect(turnOptions?.cyberAccessProgram).toBe(
                  settings.cyberAccessProgram,
                );
                prompts.push(prompt as string);
                if (prompts.length === 1) {
                  expect(prompt).toContain(
                    "Keep the original scan instructions.",
                  );
                  const deepConfigPath =
                    options.env?.["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"];
                  expect(deepConfigPath).toBe(
                    preparedRuntime(f.codexHome).deepScanConfigPath,
                  );
                  const deep = parseToml(
                    await readFile(deepConfigPath!, "utf8"),
                  );
                  expect(deep).toMatchObject({
                    deep_scan: {
                      workers: 2,
                      subagents: 0,
                      stop_after_no_new: 6,
                      stop_after_consecutive_errors: 2,
                      max_discovery_runs: 5,
                      max_time_hours: 1.5,
                    },
                    worker_runtime: {
                      daybreak: selected.daybreak,
                      features: { goals: false },
                    },
                  });
                  const workerConfigPath =
                    options.env?.["CODEX_SECURITY_CONFIG_PATH"];
                  expect(workerConfigPath).toBe(
                    join(f.root, "resumed-runtime.toml"),
                  );
                  const workerConfig = parseToml(
                    await readFile(workerConfigPath!, "utf8"),
                  );
                  expect(workerConfig).toMatchObject({
                    daybreak: selected.daybreak,
                    codex_security: {
                      cyber_access_program: settings.cyberAccessProgram,
                    },
                    features: {
                      api_key_cyber_access_programs: true,
                    },
                  });
                  const saved = await f.command([
                    "get-scan-recipe",
                    "--scan-id",
                    f.scanId,
                  ]);
                  expect(saved["recipe"]).toMatchObject({
                    cyberAccessProgram: settings.cyberAccessProgram,
                  });
                  await finishDiscovery(f);
                }
                return { events: completedEvents(threadId) };
              },
            };
          },
        };
      }),
    );
    expect(code, stderr.text()).toBe(0);
    expect(prompts, stderr.text()).toHaveLength(2);
    expect(prompts[1]).toBe(settings.postScanPrompt);
    expect(f.environment.OPENAI_API_KEY).toBe("synthetic-resume-key");
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
    });
  },
);

test.each(["unchanged", "edited", "deleted"] as const)(
  "single Deep resume uses saved knowledge when original files are %s",
  async (sourceState) => {
    const documentRoot = await temporaryDirectory();
    const document = join(documentRoot, "architecture.md");
    await writeFile(document, "Original architecture.\n");
    const f = await interruptedScan("deep", false, {
      knowledgeBasePaths: [document],
    });
    const before = await f.command([
      "get-deep-scan",
      "--scan-id",
      f.scanId,
      "--thread-id",
      f.threadId,
    ]);
    if (sourceState === "edited")
      await writeFile(document, "Changed architecture.\n");
    if (sourceState === "deleted") await rm(document);
    const stdout = capture();
    const stderr = capture();
    let resumed = false;
    let staged = "";
    const code = await main(
      ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      resumeDependencies(f, (codex) => ({
        startThread() {
          throw new Error("Expected original session");
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed(prompt) {
              expect(prompt).toContain("Keep the original scan instructions.");
              staged = codex.env!["CODEX_SECURITY_KNOWLEDGE_BASE"]!;
              expect(
                await readFile(join(staged, "0-architecture.md.txt"), "utf8"),
              ).toBe("Original architecture.\n");
              resumed = true;
              throw new Error("synthetic interrupted transport");
            },
          };
        },
      })),
    );
    expect(resumed, stderr.text()).toBe(true);
    expect(code).toBe(2);
    expect(
      await readFile(join(f.scanDir, ".scan-knowledge.json"), "utf8"),
    ).toContain("Original architecture.");
    expect(await readdir(staged).catch(() => null)).toBeNull();
    expect(
      await f.command([
        "get-deep-scan",
        "--scan-id",
        f.scanId,
        "--thread-id",
        f.threadId,
      ]),
    ).toEqual(before);
    expect(
      (await f.command(["get-scan-recipe", "--scan-id", f.scanId]))["recipe"],
    ).toEqual(f.recipe);
  },
);

test.each(["legacy", "missing", "modified"] as const)(
  "single Deep resume preserves saved work when knowledge snapshot is %s",
  async (snapshotState) => {
    const documentRoot = await temporaryDirectory();
    const document = join(documentRoot, "architecture.md");
    await writeFile(document, "Original architecture.");
    const f = await interruptedScan(
      "deep",
      false,
      { knowledgeBasePaths: [document] },
      false,
      undefined,
      snapshotState === "legacy" ? "legacy" : "saved",
    );
    const snapshot = join(f.scanDir, ".scan-knowledge.json");
    if (snapshotState === "missing") await rm(snapshot);
    if (snapshotState === "modified") {
      const value = JSON.parse(await readFile(snapshot, "utf8"));
      value.documents["0-architecture.md.txt"] = "Changed architecture.";
      await writeFile(snapshot, JSON.stringify(value));
    }
    const before = await readFile(f.checkpoint, "utf8");
    const stderr = capture();
    const code = await main(
      ["scans", "resume", f.scanId, "--json"],
      capture().stream,
      stderr.stream,
      resumeDependencies(f, () =>
        fail("Cannot run with missing or changed original context"),
      ),
    );
    expect(code).toBe(2);
    expect(stderr.text()).toMatch(/new scan/i);
    expect(await readFile(f.checkpoint, "utf8")).toBe(before);
    expect(
      (await f.command(["get-cli-scan-resume", "--scan-id", f.scanId]))[
        "recipe"
      ],
    ).toEqual(f.recipe);
  },
);

test("bulk Deep resume stages campaign knowledge after its source is removed", async () => {
  const documentRoot = await temporaryDirectory();
  const document = join(documentRoot, "architecture.md");
  await writeFile(document, "Original architecture.");
  const f = await interruptedScan("deep", true, {
    knowledgeBasePaths: [document],
  });
  const stdout = capture();
  const stderr = capture();
  let resumed = false;
  const code = await main(
    [
      "bulk-scan",
      f.input,
      "--output-dir",
      f.root,
      "--recover",
      "--knowledge-base",
      document,
      "--json",
    ],
    stdout.stream,
    stderr.stream,
    {
      ...resumeDependencies(f, (codex) => ({
        startThread() {
          throw new Error("Expected original session");
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              const directory = codex.env!["CODEX_SECURITY_KNOWLEDGE_BASE"]!;
              expect(await readdir(directory)).toEqual([
                "0-architecture.md.txt",
              ]);
              expect(
                await readFile(
                  join(directory, "0-architecture.md.txt"),
                  "utf8",
                ),
              ).toBe("Original architecture.");
              resumed = true;
              await finishDiscovery(f);
              return { events: completedEvents(threadId) };
            },
          };
        },
      })),
      runWorkbench: async (args, input) => {
        if (args[0] === "get-cli-scan-resume") await rm(document);
        return f.command(args, input);
      },
    },
  );
  expect(resumed, stderr.text()).toBe(true);
  expect(code, stderr.text()).toBe(0);
  expect(JSON.parse(stdout.text())).toMatchObject({
    completed: 1,
    failed: 0,
  });
  expect(
    (await f.command(["get-scan-recipe", "--scan-id", f.scanId]))["recipe"],
  ).toMatchObject({ knowledgeBasePaths: [document] });
});

test("missing session logs do not create another session or fail the original scan", async () => {
  const f = await interruptedScan();
  await rm(f.sessionPath);
  const { stderr, runCli } = createCliTest(main);

  const code = await runCli(
    ["scans", "resume", f.scanId],
    resumeDependencies(f, () =>
      fail("Must not invoke Codex without the original session"),
    ),
  );
  expect(code).not.toBe(0);
  expect(stderr.text()).toContain("original Codex session");
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "running" } });
});

test.each(["failed", "missing-checkout", "missing-session", "standard"])(
  "bulk recovery retries an unavailable %s scan without overwriting its attempt",
  async (scenario) => {
    const f = await interruptedScan(
      scenario === "standard" ? "standard" : "deep",
      true,
    );
    if (scenario === "failed")
      await f.command([
        "fail-scan",
        "--scan-id",
        f.scanId,
        "--message",
        "Synthetic failure",
      ]);
    if (scenario === "missing-checkout")
      await rm(f.repository, { recursive: true });
    if (scenario === "missing-session") await rm(f.sessionPath);
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies({
      environment: f.environment,
      currentDirectory: f.root,
    });
    let attempts = 0;
    expect(
      await runCli(
        ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
        {
          ...deps,
          runWorkbench: f.command,
          createSecurity: (config) => ({
            ...deps.createSecurity(config),
            run: async (repository, options = {}) => {
              attempts++;
              expect(options.resumeScanId).toBeUndefined();
              expect(options.mode).toBe(f.recipe.mode);
              expect(options.outputDir).toBe(
                join(f.root, "artifacts", "repo", "attempt-2"),
              );
              expect(repository).toBe(
                join(f.root, "recovery-checkouts", "repo", "attempt-2"),
              );
              expect(
                (
                  await readFile(join(repository, "source.py"), "utf8")
                ).replaceAll("\r\n", "\n"),
              ).toBe("# synthetic source\n");
              return {
                manifest: { scan: { status: "completed" } },
                coverage: {},
                cost: null,
              } as import("../src/result.js").ScanResult;
            },
          }),
        },
      ),
      stderr.text(),
    ).toBe(0);
    expect(attempts).toBe(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      completed: 1,
      failed: 0,
    });
    expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
      before,
    );
    expect(await readFile(f.checkpoint, "utf8")).toBe(
      '{"completed":"setup"}\n',
    );
  },
);

test("resume requires an explicit scan ID", async () => {
  const { stderr, runCli } = createCliTest(main);

  const code = await runCli(["scans", "resume"], {
    ...dependencies(),
    runWorkbench: async () => fail("Must select a scan explicitly"),
  });
  expect(code).toBe(2);
  expect(stderr.text()).toContain("scanId");
});

test.each([false, true])(
  "unfinished empty artifact list does not pin producer on resume (empty=%p)",
  async (empty) => {
    const f = await interruptedScan("deep");
    await finishDiscovery(f);
    const manifestPath = join(f.scanDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    delete manifest.scan.sealedAt;
    manifest.scan.producer.version = f.recipe.pluginVersion;
    if (empty) manifest.scan.artifacts = [];
    else delete manifest.scan.artifacts;
    await writeFile(manifestPath, JSON.stringify(manifest));
    const resume = await f.command([
      "get-cli-scan-resume",
      "--scan-id",
      f.scanId,
    ]);
    expect(resume["sealedProducerVersion"]).toBeUndefined();
    const { stderr, runCli } = createCliTest(main);
    const code = await runCli(
      ["scans", "resume", f.scanId, "--json"],
      resumeDependencies(f, () => ({
        startThread: () => fail("Unexpected new session"),
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              return { events: completedEvents(threadId) };
            },
          };
        },
      })),
    );
    expect(code, stderr.text()).toBe(0);
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({ progress: { status: "complete" } });
    const sealed = JSON.parse(await readFile(manifestPath, "utf8"));
    const plugin = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".codex-plugin/plugin.json"), "utf8"),
    );
    expect(sealed.scan.producer.version).toBe(plugin.version);
    expect(sealed.scan.artifacts.length).toBeGreaterThan(0);
  },
);
