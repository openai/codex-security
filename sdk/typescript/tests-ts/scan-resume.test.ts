import { publishDraft } from "./support/scan-publication.js";
import { semanticCoverage, semanticFinding } from "./helpers/semantic-scan.js";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { parse as parseToml } from "smol-toml";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost, type ScanCost } from "../src/cost.js";
import {
  DEEP_SCAN_CHECKPOINT,
  ScanCostTrackingError,
  TerminalDeepScanError,
  type DeepScanCheckpoint,
} from "../src/deep-scan.js";
import type { SemanticScan } from "../src/scan-semantics.js";
import { prepareScanArtifactRestorer, runWorkbench } from "../src/runtime.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime as fixtureRuntime,
} from "./support/api-events.js";

const PLUGIN_ROOT = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

function preparedRuntime(codexHome: string) {
  const runtime = fixtureRuntime(codexHome);
  runtime.plugin.pluginRoot = PLUGIN_ROOT;
  runtime.plugin.installedRoot = PLUGIN_ROOT;
  runtime.plugin.marketplaceRoot = PLUGIN_ROOT;
  return runtime;
}

async function interruptedScan(
  mode: "deep" | "standard" = "deep",
  bulk = false,
  settings: Pick<
    ScanOptions,
    | "maxCostUsd"
    | "safetyIdentifier"
    | "postScanPrompt"
    | "auth"
    | "inheritedPermissions"
    | "preserveProviderEnvironment"
  > = {},
  resolvedDeep = false,
  startedMerge = true,
  ordinaryPass: {
    cost?: ScanCost;
    findings?: SemanticScan["findings"];
    coverage?: SemanticScan["coverage"];
  } | null = {},
) {
  const root = await temporaryDirectory();
  const repository = bulk
    ? join(root, "checkouts", "repo")
    : join(root, "repository");
  const scanDir = bulk
    ? join(root, "artifacts", "repo", "attempt-1")
    : join(root, "scan");
  const codexHome = join(root, "state", "codex-home");
  await mkdir(repository, { recursive: true, mode: 0o700 });
  await mkdir(scanDir, { recursive: true, mode: 0o700 });
  await mkdir(join(codexHome, "sessions"), { recursive: true });
  await writeFile(join(repository, "source.py"), "# synthetic source\n");
  const input = join(root, "repositories.csv");
  if (bulk) {
    const git = (...args: string[]) =>
      execFileSync("git", ["-C", repository, ...args], {
        encoding: "utf8",
      }).trim();
    git("init", "-q");
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
      JSON.stringify({ version: 1, tasks: [task] }, null, 2) + "\n",
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
    ...(settings.safetyIdentifier === undefined
      ? {}
      : { OPENAI_API_KEY: "synthetic-resume-key" }),
  };
  const command = (args: readonly string[], input?: string) =>
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
  const recipe = {
    repository,
    target: { kind: "repository", paths: [] },
    mode,
    config: {
      model: "gpt-5.6-sol",
      approval_policy: "never",
      ...(settings.preserveProviderEnvironment
        ? {
            model_provider: "custom",
            model_providers: { custom: { env_key: "OPENAI_API_KEY" } },
          }
        : {}),
    },
    pluginVersion: "0.1.0",
    requiresScanPrompt: true,
    ...settings,
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
  const threadId = randomUUID();
  if (startedMerge)
    await command([
      "set-scan-thread",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId,
    ]);
  const sessionPath = join(codexHome, "sessions", `rollout-${threadId}.jsonl`);
  await writeFile(
    sessionPath,
    JSON.stringify({
      type: "session_meta",
      payload: {
        id: threadId,
        cwd:
          mode === "deep"
            ? join(scanDir, "artifacts/deep-scan/merge")
            : scanDir,
      },
    }) + "\n",
  );
  let childId: string | undefined;
  let childDir: string | undefined;
  if (mode === "deep" && ordinaryPass !== null) {
    childDir = join(scanDir, "artifacts/deep-scan/passes/pass-1");
    await mkdir(childDir, { recursive: true, mode: 0o700 });
    const child = await command(
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        childDir,
        "--parent-scan-id",
        scanId,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        recipe: {
          repository,
          target: recipe.target,
          mode: "standard",
          config: recipe.config,
        },
        parentScanRole: "deep_pass",
      }),
    );
    childId = child["scanId"] as string;
    const aggregate: SemanticScan = {
      scanId,
      findings: ordinaryPass.findings ?? [],
      coverage: ordinaryPass.coverage ?? {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [{ id: "time-cap", reason: "Synthetic time cap" }],
      },
    };
    await publishDraft(command, child, "standard", {
      ...aggregate,
      scanId: childId,
    });
    await command(["prepare-scan-completion", "--scan-id", childId]);
    await command([
      "complete-scan",
      "--scan-id",
      childId,
      ...(ordinaryPass.cost
        ? ["--cost-json", JSON.stringify(ordinaryPass.cost)]
        : []),
    ]);
    const state: DeepScanCheckpoint = {
      version: 2,
      startedAt: "2000-01-01T00:00:00Z",
      passes: [
        { directory: "artifacts/deep-scan/passes/pass-1", scanId: childId },
      ],
      mergedScanIds: startedMerge ? [childId] : [],
      aggregate: startedMerge ? aggregate : null,
      noNewStreak: startedMerge ? 1 : 0,
      consecutiveErrors: 0,
    };
    await command(
      [
        "save-scan-artifact",
        "--scan-id",
        scanId,
        "--artifact-path",
        DEEP_SCAN_CHECKPOINT,
      ],
      JSON.stringify(state),
    );
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
    childId,
    childDir,
  };
}

test("resume preserves its identity, launch recipe, accepted child and checkpoint", async () => {
  const f = await interruptedScan();
  const before = await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT));
  const child = await f.command(["get-scan", "--scan-id", f.childId!]);
  const artifacts = await readFile(join(f.childDir!, "findings.json"));
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
  expect(await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT))).toEqual(before);
  expect(await f.command(["get-scan", "--scan-id", f.childId!])).toEqual(child);
  expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(artifacts);
});

test.each(["failed", "canceled", "changed", "replaced", "wrong-owner"])(
  "resume refuses %s scans without altering their saved state",
  async (scenario) => {
    const f = await interruptedScan();
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
    const ownerArgs =
      scenario === "wrong-owner" ? ["--claim-token", randomUUID()] : [];
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    expect(
      await f.command([
        "get-cli-scan-resume",
        "--scan-id",
        f.scanId,
        "--allow-unavailable",
        ...ownerArgs,
      ]),
    ).toMatchObject({ unavailable: expect.any(String) });
    await expect(
      f.command(["get-cli-scan-resume", "--scan-id", f.scanId, ...ownerArgs]),
    ).rejects.toThrow(
      scenario === "changed"
        ? "revision or contents changed"
        : scenario === "replaced"
          ? "checkout is missing or was replaced"
          : scenario === "wrong-owner"
            ? "original owning CLI session"
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

test("CLI merge failure retains accepted ordinary scans and the original thread", async () => {
  const f = await interruptedScan();
  const checkpoint = JSON.parse(
    await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
  ) as DeepScanCheckpoint;
  checkpoint.mergedScanIds = [];
  checkpoint.aggregate = null;
  await f.command(
    [
      "save-scan-artifact",
      "--scan-id",
      f.scanId,
      "--artifact-path",
      DEEP_SCAN_CHECKPOINT,
    ],
    JSON.stringify(checkpoint),
  );
  const childBefore = await readFile(join(f.childDir!, "findings.json"));
  let resumedThread: string | undefined;
  const stderr = capture();
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    capture().stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: resumeClient(f, (options) => ({
        startThread() {
          throw new Error("Resume must not create a new thread.");
        },
        resumeThread(threadId, threadOptions) {
          resumedThread = threadId;
          expect(threadOptions.workingDirectory).toBe(
            join(f.scanDir, "artifacts/deep-scan/merge"),
          );
          expect(options.env).toMatchObject({
            CODEX_SECURITY_SCAN_ID: f.scanId,
            CODEX_SECURITY_SCAN_DIR: f.scanDir,
          });
          return {
            id: threadId,
            async runStreamed() {
              throw new Error("Synthetic transport disconnected");
            },
          };
        },
      })),
    },
  );
  expect(stderr.text()).toContain("Synthetic transport disconnected");
  expect(code).not.toBe(0);
  expect(resumedThread).toBe(f.threadId);
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "failed" } });
  expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(
    childBefore,
  );
});

function resumeClient(
  f: Awaited<ReturnType<typeof interruptedScan>>,
  createCodex: NonNullable<
    ConstructorParameters<typeof TestClient>[1]["createCodex"]
  >,
  workbench: typeof runWorkbench = runWorkbench,
) {
  return (config: ConstructorParameters<typeof TestClient>[0]) =>
    new TestClient(config, {
      environment: f.environment,
      prepareRuntime: async () => {
        const runtime = preparedRuntime(f.codexHome);
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
      prepareScanArtifactRestorer,
      runWorkbench: workbench,
      createCodex,
    });
}

async function finishDiscovery(f: Awaited<ReturnType<typeof interruptedScan>>) {
  const checkpoint = JSON.parse(
    await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
  ) as DeepScanCheckpoint;
  checkpoint.terminalReason = "capped";
  await f.command(
    [
      "save-scan-artifact",
      "--scan-id",
      f.scanId,
      "--artifact-path",
      DEEP_SCAN_CHECKPOINT,
    ],
    JSON.stringify(checkpoint),
  );
  await publishDraft(f.command, f.registration, "deep", checkpoint.aggregate!);
}

test.each(["failed", "canceled"] as const)(
  "rejecting a %s checkpoint preserves saved accounting and artifacts",
  async (terminalReason) => {
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      output_tokens: 100,
    })!;
    const f = await interruptedScan("deep", false, {}, false, true, { cost });
    const checkpointPath = join(f.scanDir, DEEP_SCAN_CHECKPOINT);
    const checkpoint = JSON.parse(
      await readFile(checkpointPath, "utf8"),
    ) as DeepScanCheckpoint;
    checkpoint.terminalReason = terminalReason;
    await f.command(
      [
        "save-scan-artifact",
        "--scan-id",
        f.scanId,
        "--artifact-path",
        DEEP_SCAN_CHECKPOINT,
      ],
      JSON.stringify(checkpoint),
    );
    await f.command([
      "preserve-scan-results",
      "--scan-id",
      f.scanId,
      "--cost-json",
      JSON.stringify(cost),
    ]);
    const paths = [
      checkpointPath,
      f.checkpoint,
      ...[
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
      ].map((name) => join(f.childDir!, name)),
    ];
    const artifacts = await Promise.all(paths.map((path) => readFile(path)));
    const saved = await f.command(["get-scan", "--scan-id", f.scanId]);
    // Terminal rejection must work without recovering session accounting.
    await rm(f.sessionPath);
    const calls: string[] = [];
    const notifications: string[] = [];
    const client = resumeClient(
      f,
      () => {
        throw new Error("Terminal resume must not create a worker.");
      },
      async (options, args, input) => {
        calls.push(args[0]!);
        return runWorkbench(options, args, input);
      },
    )({ codexOverrides: f.recipe.config });
    try {
      await expect(
        client.run(f.repository, {
          mode: "deep",
          outputDir: f.scanDir,
          resumeScanId: f.scanId,
          maxCostUsd: 0.001,
          onCost() {
            notifications.push("cost");
          },
          onActivity() {
            notifications.push("activity");
          },
          onSessionEvent() {
            notifications.push("session");
          },
          onBudgetApproaching() {
            notifications.push("budget");
          },
        }),
      ).rejects.toBeInstanceOf(TerminalDeepScanError);
      expect(notifications).toEqual([]);
      for (const command of [
        "fail-scan",
        "preserve-scan-results",
        "save-scan-artifact",
        "prepare-scan-completion",
        "list-scans",
      ])
        expect(calls).not.toContain(command);
      expect(await Promise.all(paths.map((path) => readFile(path)))).toEqual(
        artifacts,
      );
      expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
        saved,
      );
    } finally {
      await client.close();
    }
  },
);

test.each([
  [false, false],
  [true, false],
  [false, true],
  [true, true],
])(
  "resumed CLI seals the original scan (aggregate finished: %p, bulk: %p)",
  async (alreadyFinished, bulk) => {
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      output_tokens: 100,
    })!;
    const f = await interruptedScan("deep", bulk, {}, false, true, { cost });
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
    const stdout = capture();
    const stderr = capture();
    const code = await main(
      bulk
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, () => ({
          startThread() {
            throw new Error("Unexpected new session");
          },
          resumeThread(threadId) {
            expect(threadId).toBe(f.threadId);
            return {
              id: threadId,
              async runStreamed() {
                throw new Error(
                  "Accepted capped aggregate needs no additional model turn",
                );
              },
            };
          },
        })),
      },
    );
    // Preserve the CLI's nonzero exit for a valid, sealed partial result.
    expect(code, stderr.text()).toBe(2);
    const result = JSON.parse(stdout.text());
    if (bulk) {
      expect(result, stderr.text()).toMatchObject({ incomplete: 1, failed: 0 });
      const receipts = (await readFile(result.resultsPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(receipts).toHaveLength(2);
      expect(receipts[1]).toMatchObject({
        attempt: 1,
        outputDir: f.scanDir,
        status: "completed_with_incomplete_coverage",
        cost: { inputTokens: 11000, outputTokens: 2100 },
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
              onRun() {
                throw new Error("A sealed scan needs no Codex invocation");
              },
            }),
            runWorkbench: f.command,
          },
        ),
      ).toBe(2);
      expect(JSON.parse(reconciledOutput.text())).toMatchObject({
        incomplete: 1,
        failed: 0,
      });
      const reconciled = (await readFile(result.resultsPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(reconciled[1]).toMatchObject({
        attempt: 1,
        cost: { inputTokens: 11000, outputTokens: 2100 },
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
      ).toBe(2);
      expect(JSON.parse(nextOutput.text())).toMatchObject({
        skipped: 1,
        incomplete: 1,
        failed: 0,
      });
    } else {
      expect(result.coverage.completeness).toBe("partial");
      expect(result.manifest.scan.id).toBe(f.scanId);
      expect(result.manifest.scan.sealedAt).toBeString();
      expect(result.cost.inputTokens).toBe(11000);
      expect(result.cost.outputTokens).toBe(2100);
    }
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
      cost: { inputTokens: 11000, outputTokens: 2100 },
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

test.each([true, false])(
  "resume preserves accepted results when recovered child costs exhaust the budget (saved merge session: %p)",
  async (savedMergeSession) => {
    const cost = (input_tokens: number, output_tokens: number) =>
      estimateScanCost("gpt-5.6-sol", { input_tokens, output_tokens })!;
    const coverage = semanticCoverage({
      completeness: "partial",
      surfaces: [{ label: "Accepted source review", disposition: "reported" }],
      deferred: [{ reason: "Retained review follow-up." }],
    });
    const finding = semanticFinding({
      identity: { anchor: "unsafe-output" },
      locations: [{ path: "source.py", startLine: 1 }],
    });
    const f = await interruptedScan(
      "deep",
      false,
      { maxCostUsd: 0.01 },
      true,
      true,
      { cost: cost(100, 10), findings: [finding], coverage },
    );
    const checkpointPath = join(f.scanDir, DEEP_SCAN_CHECKPOINT);
    const checkpoint = JSON.parse(
      await readFile(checkpointPath, "utf8"),
    ) as DeepScanCheckpoint;
    checkpoint.startedAt = new Date().toISOString();
    const acceptedChild = await readFile(join(f.childDir!, "findings.json"));
    const writeUsage = async (
      threadId: string,
      cwd: string,
      inputTokens: number,
      outputTokens: number,
    ) => {
      await writeFile(
        join(f.codexHome, "sessions", `rollout-${threadId}.jsonl`),
        [
          { type: "session_meta", payload: { id: threadId, cwd } },
          {
            type: "event_msg",
            payload: {
              type: "token_count",
              info: {
                total_token_usage: {
                  input_tokens: inputTokens,
                  output_tokens: outputTokens,
                },
              },
            },
          },
        ]
          .map((event) => JSON.stringify(event))
          .join("\n") + "\n",
      );
    };
    await writeUsage(
      f.threadId,
      join(f.scanDir, "artifacts/deep-scan/merge"),
      10,
      1,
    );
    for (const [index, input, output] of [
      [2, 10_000, 1_000],
      [3, 20_000, 2_000],
    ] as const) {
      const directory = `artifacts/deep-scan/passes/pass-${index}`;
      const scanDir = join(f.scanDir, directory);
      await mkdir(scanDir, { recursive: true, mode: 0o700 });
      const registration = await f.command(
        [
          "register-cli-scan",
          "--repository",
          f.repository,
          "--scan-dir",
          scanDir,
          "--parent-scan-id",
          f.scanId,
          "--registration-json-stdin",
        ],
        JSON.stringify({
          recipe: { ...f.recipe, mode: "standard" },
          parentScanRole: "deep_pass",
        }),
      );
      const scanId = registration["scanId"] as string;
      const threadId = randomUUID();
      await f.command([
        "set-scan-thread",
        "--scan-id",
        scanId,
        "--thread-id",
        threadId,
      ]);
      await writeUsage(threadId, scanDir, input, output);
      checkpoint.passes.push({ directory, scanId });
    }
    await f.command(
      [
        "save-scan-artifact",
        "--scan-id",
        f.scanId,
        "--artifact-path",
        DEEP_SCAN_CHECKPOINT,
      ],
      JSON.stringify(checkpoint),
    );
    await publishDraft(
      f.command,
      f.registration,
      "deep",
      checkpoint.aggregate!,
    );
    let turns = 0;
    const client = resumeClient(
      f,
      () => ({
        startThread() {
          if (savedMergeSession)
            throw new Error("Budget recovery must not start another session.");
          return {
            id: null,
            async runStreamed() {
              turns++;
              throw new Error(
                "Budget recovery must not start another model turn.",
              );
            },
          };
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              turns++;
              throw new Error(
                "Budget recovery must not start another model turn.",
              );
            },
          };
        },
      }),
      async (options, args, input) => {
        const response = await runWorkbench(options, args, input);
        if (!savedMergeSession && args.includes(f.scanId)) {
          if (args[0] === "get-cli-scan-resume") response["threadId"] = null;
          if (args[0] === "get-scan")
            (response["scan"] as JsonObject)["continuationThreadId"] = null;
        }
        return response;
      },
    )({ codexOverrides: f.recipe.config });
    try {
      const pending = client.run(f.repository, {
        mode: "deep",
        outputDir: f.scanDir,
        resumeScanId: f.scanId,
        maxCostUsd: 0.01,
        ...f.recipe.deepScan,
      });
      if (!savedMergeSession) {
        await expect(pending).rejects.toBeInstanceOf(ScanCostTrackingError);
        const saved = (await f.command(["get-scan", "--scan-id", f.scanId]))[
          "scan"
        ] as JsonObject;
        expect(saved).toMatchObject({ progress: { status: "running" } });
        expect(saved["cost"]).toBeUndefined();
        expect(turns).toBe(0);
        expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(
          acceptedChild,
        );
        return;
      }
      const result = await pending;
      const expectedCost = cost(30_110, 3_011);
      expect(turns).toBe(0);
      expect(result.manifest.scan.id).toBe(f.scanId);
      expect(result.manifest.scan.sealedAt).toBeString();
      expect(result.threadId).toBe(f.threadId);
      expect(result.cost).toMatchObject({
        inputTokens: expectedCost.inputTokens,
        outputTokens: expectedCost.outputTokens,
      });
      expect(result.cost!.estimatedUsd).toBeCloseTo(expectedCost.estimatedUsd);
      expect(result.findings.findings).toHaveLength(1);
      expect(result.findings.findings[0]).toMatchObject({
        title: finding.title,
        locations: finding.locations,
      });
      expect(result.coverage).toMatchObject({
        completeness: "partial",
        surfaces: coverage.surfaces,
        deferred: expect.arrayContaining(
          coverage.deferred.map((entry) => expect.objectContaining(entry)),
        ),
      });
      const saved = JSON.parse(await readFile(checkpointPath, "utf8"));
      expect(saved).toMatchObject({
        terminalReason: "capped",
        mergedScanIds: [f.childId],
        aggregate: {
          findings: [finding],
          coverage: {
            ...coverage,
            deferred: expect.arrayContaining(coverage.deferred),
          },
        },
      });
      expect(
        (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
      ).toMatchObject({
        progress: { status: "complete" },
        cost: { inputTokens: 30_110, outputTokens: 3_011 },
      });
      expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(
        acceptedChild,
      );
    } finally {
      await client.close();
    }
  },
);

test.each([
  ["accepted", false, undefined],
  ["accepted", true, undefined],
  ["in-flight", false, undefined],
  ["in-flight", true, undefined],
  ["before-merge", true, undefined],
  ["discovery", true, undefined],
  ["in-flight", false, "unsealed"],
  ["in-flight", true, "unsealed"],
  ["in-flight", false, "sealed"],
  ["in-flight", true, "sealed"],
  ["accepted", false, "sealed"],
  ["accepted", true, "sealed"],
] as const)(
  "resume keeps missing merge accounting unknown (%s, required cost: %p, interruption: %p)",
  async (phase, requiredCost, interruption) => {
    const cost = (input_tokens: number, output_tokens: number) =>
      estimateScanCost("gpt-5.6-sol", { input_tokens, output_tokens })!;
    const finding = semanticFinding({
      identity: { anchor: "retained-review" },
      locations: [{ path: "source.py", startLine: 1 }],
    });
    const priorMerge = phase === "accepted" || phase === "in-flight";
    const f = await interruptedScan(
      "deep",
      false,
      requiredCost && !interruption ? { maxCostUsd: 1 } : {},
      true,
      false,
      phase === "discovery"
        ? null
        : {
            cost: cost(100, 10),
            findings: phase === "accepted" ? [finding] : [],
          },
    );
    const checkpointPath = join(f.scanDir, DEEP_SCAN_CHECKPOINT);
    const checkpoint: DeepScanCheckpoint =
      phase === "discovery"
        ? {
            version: 2,
            startedAt: "2000-01-01T00:00:00Z",
            passes: [],
            mergedScanIds: [],
            aggregate: null,
            noNewStreak: 0,
            consecutiveErrors: 0,
          }
        : JSON.parse(await readFile(checkpointPath, "utf8"));
    if (priorMerge) {
      // Completion is durable before the first merge can start. Its optional
      // session write can fail before either acceptance or a failure is saved.
      checkpoint.passes[0]!.completed = true;
      await appendFile(
        f.sessionPath,
        JSON.stringify({
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: 1000, output_tokens: 100 },
            },
          },
        }) + "\n",
      );
      await f.command([
        "preserve-scan-results",
        "--scan-id",
        f.scanId,
        "--cost-json",
        JSON.stringify(cost(1100, 110)),
      ]);
    }
    if (phase === "accepted") {
      checkpoint.mergedScanIds = [f.childId!];
      checkpoint.aggregate = {
        scanId: f.scanId,
        findings: [finding],
        coverage: semanticCoverage({ completeness: "partial" }),
      };
      checkpoint.terminalReason = "saturated";
      await publishDraft(
        f.command,
        f.registration,
        "deep",
        checkpoint.aggregate,
      );
    }
    await f.command(
      [
        "save-scan-artifact",
        "--scan-id",
        f.scanId,
        "--artifact-path",
        DEEP_SCAN_CHECKPOINT,
      ],
      JSON.stringify(checkpoint),
    );
    let before = await f.command(["get-scan", "--scan-id", f.scanId]);
    let savedCheckpoint = await readFile(checkpointPath);
    const childFindings = f.childDir
      ? await readFile(join(f.childDir, "findings.json"))
      : null;
    let starts = 0;
    let turns = 0;
    let mergeThreadId: string | undefined;
    const abort = new AbortController();
    const client = resumeClient(
      f,
      () => ({
        resumeThread(threadId) {
          expect(threadId).toBe(mergeThreadId!);
          return {
            id: threadId,
            async runStreamed() {
              throw new Error("The accepted merge needs no additional turn.");
            },
          };
        },
        startThread() {
          starts++;
          const thread = {
            id: null as string | null,
            async runStreamed() {
              turns++;
              thread.id = mergeThreadId = randomUUID();
              await writeFile(
                join(f.codexHome, "sessions", `rollout-${thread.id}.jsonl`),
                [
                  {
                    type: "session_meta",
                    payload: {
                      id: thread.id,
                      cwd: join(f.scanDir, "artifacts/deep-scan/merge"),
                    },
                  },
                  {
                    type: "event_msg",
                    payload: {
                      type: "token_count",
                      info: {
                        total_token_usage: {
                          input_tokens: 10,
                          cached_input_tokens: 2,
                          output_tokens: 3,
                        },
                      },
                    },
                  },
                ]
                  .map((event) => JSON.stringify(event))
                  .join("\n") + "\n",
              );
              async function* events() {
                for await (const event of completedEvents(thread.id!)) {
                  if (
                    event.type === "item.completed" &&
                    event.item.type === "agent_message"
                  )
                    yield {
                      ...event,
                      item: {
                        ...event.item,
                        text: JSON.stringify({
                          scanId: f.scanId,
                          findings: [],
                        }),
                      },
                    };
                  else yield event;
                }
              }
              return { events: events() };
            },
          };
          return thread;
        },
      }),
      async (options, args, input) => {
        if (
          interruption &&
          !abort.signal.aborted &&
          args[0] === "prepare-scan-completion"
        ) {
          if (interruption === "sealed")
            await runWorkbench(options, args, input);
          abort.abort(
            new ScanTransportClosedError("Synthetic completion interruption."),
          );
          throw abort.signal.reason;
        }
        return runWorkbench(options, args, input);
      },
    )({ codexOverrides: f.recipe.config });
    try {
      const options: ScanOptions = {
        mode: "deep",
        outputDir: f.scanDir,
        resumeScanId: f.scanId,
        ...f.recipe.deepScan,
      };
      let pending = client.run(f.repository, {
        ...options,
        ...(interruption
          ? { signal: abort.signal }
          : requiredCost
            ? { maxCostUsd: 1 }
            : {}),
      });
      if (interruption) {
        await expect(pending).rejects.toBeInstanceOf(ScanTransportClosedError);
        before = await f.command(["get-scan", "--scan-id", f.scanId]);
        expect(before["scan"]).toMatchObject({
          continuationThreadId: mergeThreadId ?? null,
        });
        savedCheckpoint = await readFile(checkpointPath);
        pending = client.run(f.repository, {
          ...options,
          ...(requiredCost ? { maxCostUsd: 1 } : {}),
        });
      }
      if (requiredCost && priorMerge) {
        await expect(pending).rejects.toBeInstanceOf(ScanCostTrackingError);
        expect(starts).toBe(interruption ? 1 : 0);
        expect(turns).toBe(interruption && phase === "in-flight" ? 1 : 0);
        expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
          before,
        );
        expect(await readFile(checkpointPath)).toEqual(savedCheckpoint);
        if (phase === "accepted")
          expect(
            JSON.parse(await readFile(join(f.scanDir, "findings.json"), "utf8"))
              .findings,
          ).toHaveLength(1);
      } else {
        const result = await pending;
        expect(turns).toBe(
          phase === "accepted" || phase === "discovery" ? 0 : 1,
        );
        expect(result.manifest.scan.sealedAt).toBeString();
        const saved = (await f.command(["get-scan", "--scan-id", f.scanId]))[
          "scan"
        ] as JsonObject;
        expect(saved).toMatchObject({ progress: { status: "complete" } });
        if (phase === "before-merge") {
          expect(result.cost).toMatchObject({
            inputTokens: 110,
            outputTokens: 13,
          });
          expect(saved["cost"]).toMatchObject({
            inputTokens: 110,
            outputTokens: 13,
          });
        } else {
          expect(result.cost).toBeNull();
          expect(saved["cost"]).toBeUndefined();
        }
      }
      if (childFindings !== null)
        expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(
          childFindings,
        );
    } finally {
      await client.close();
    }
  },
);

test("sealed legacy results retain their saved accounting", async () => {
  const f = await interruptedScan(
    "deep",
    false,
    { maxCostUsd: 0.001 },
    true,
    false,
    null,
  );
  const cost = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 10000,
    output_tokens: 2000,
  })!;
  const expectedCost = {
    inputTokens: 10000,
    outputTokens: 2000,
    estimatedUsd: cost.estimatedUsd,
  };
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
  const coverage = semanticCoverage({
    completeness: "partial",
    surfaces: [],
    explicitExclusions: [],
    deferred: [{ reason: "Retained legacy discovery coverage." }],
  });
  const checkpoint: DeepScanCheckpoint = {
    version: 2,
    startedAt: "2000-01-01T00:00:00Z",
    passes: [],
    mergedScanIds: [],
    aggregate: { scanId: f.scanId, findings: [], coverage },
    noNewStreak: 0,
    consecutiveErrors: 0,
    terminalReason: "capped",
    mergeFailures: 1,
    legacy: {
      discoveryRuns: 1,
      coverage,
      originThreadId: f.threadId,
      cost,
    },
  };
  await f.command(
    [
      "save-scan-artifact",
      "--scan-id",
      f.scanId,
      "--artifact-path",
      DEEP_SCAN_CHECKPOINT,
    ],
    JSON.stringify(checkpoint),
  );
  const artifactNames = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
    DEEP_SCAN_CHECKPOINT,
  ];
  await publishDraft(f.command, f.registration, "deep", checkpoint.aggregate!);
  await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
  const artifacts = await Promise.all(
    artifactNames.map((name) => readFile(join(f.scanDir, name))),
  );
  let turns = 0;
  const client = resumeClient(f, () => ({
    startThread() {
      return {
        id: null,
        async runStreamed() {
          turns++;
          throw new Error("Completed legacy discovery needs no model turn.");
        },
      };
    },
    resumeThread() {
      throw new Error("The retired coordinator must not resume.");
    },
  }))({ codexOverrides: f.recipe.config });
  const options: ScanOptions = {
    mode: "deep",
    outputDir: f.scanDir,
    resumeScanId: f.scanId,
    maxCostUsd: 0.001,
    ...f.recipe.deepScan,
  };
  try {
    const result = await client.run(f.repository, options);
    expect(result.manifest.scan.id).toBe(f.scanId);
    expect(result.manifest.scan.sealedAt).toBeString();
    expect(result.threadId).toBe(f.threadId);
    expect(result.coverage.completeness).toBe("partial");
    expect(result.cost).toMatchObject(expectedCost);
    expect(turns).toBe(0);
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      cost: expectedCost,
    });
    expect(
      await Promise.all(
        artifactNames.map((name) => readFile(join(f.scanDir, name))),
      ),
    ).toEqual(artifacts);
  } finally {
    await client.close();
  }
});

test.each([
  "managed",
  "native",
  "wrong-claim",
  "wrong-target",
  "wrong-output",
  "changed-artifact",
] as const)(
  "sealed publication reads without authentication or execution (%s)",
  async (scenario) => {
    const childCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 375,
      output_tokens: 3,
    })!;
    const expectedCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1375,
      output_tokens: 13,
    })!;
    const f = await interruptedScan("deep", false, {}, true, true, {
      cost: childCost,
    });
    await appendFile(
      f.sessionPath,
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: 1000, output_tokens: 10 },
          },
        },
      }) + "\n",
    );
    await finishDiscovery(f);
    await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    const native = scenario !== "managed";
    const owner = "synthetic-native-owner";
    const claim = randomUUID();
    if (native) {
      const nativeHome = join(f.root, "native-home");
      await rename(f.codexHome, nativeHome);
      f.environment.CODEX_HOME = nativeHome;
      execFileSync(f.python, [
        "-c",
        `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("UPDATE scans SET deep_scan_owner_thread_id = ?, handoff_claim_token = ? WHERE id = ?", sys.argv[2:])
`,
        join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
        owner,
        claim,
        f.scanId,
      ]);
    }
    let repository = f.repository;
    let outputDir = f.scanDir;
    if (scenario === "wrong-target") {
      repository = join(f.root, "other-repository");
      await mkdir(repository);
      await writeFile(
        join(repository, "source.py"),
        "# another synthetic source\n",
      );
    }
    if (scenario === "wrong-output") {
      outputDir = join(f.root, "other-output");
      await mkdir(outputDir, { mode: 0o700 });
      await cp(f.scanDir, outputDir, { recursive: true });
    }
    if (scenario === "changed-artifact")
      await appendFile(join(f.scanDir, "findings.json"), "\n");
    const artifactNames = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
      DEEP_SCAN_CHECKPOINT,
    ];
    const artifacts = await Promise.all(
      artifactNames.map((name) => readFile(join(f.scanDir, name))),
    );
    const commands: string[] = [];
    let authentications = 0;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: f.environment,
        ...(native
          ? {
              ambientExecution: {
                command: { command: "synthetic-unused-codex" },
                configuration: {},
                environment: f.environment,
                preserveProviderEnvironment: false,
                pluginRoot: PLUGIN_ROOT,
              },
            }
          : {}),
        prepareRuntime: async () => {
          throw new Error(
            "Saved publication must not prepare a Codex runtime.",
          );
        },
        createCodex: () => {
          throw new Error("Saved publication must not create a model client.");
        },
        resolvePluginPython: async () => f.python,
        runWorkbench: async (options, args, input) => {
          commands.push(args[0]!);
          return runWorkbench(options, args, input);
        },
      },
    );
    try {
      const pending = client.run(repository, {
        mode: "deep",
        outputDir,
        maxCostUsd: 1,
        ...(native
          ? {
              registeredScan: {
                scanId: f.scanId,
                scanDir: outputDir,
                threadId: owner,
                handoffClaimToken:
                  scenario === "wrong-claim" ? randomUUID() : claim,
              },
            }
          : { resumeScanId: f.scanId }),
        onAuthentication() {
          authentications++;
        },
      });
      if (scenario === "managed" || scenario === "native") {
        const result = await pending;
        expect(result.cost).toEqual(expectedCost);
        expect(result.threadId).toBe(f.threadId);
        expect(result.repositoryFindings).toEqual([]);
        expect(commands).toContain("list-global-findings");
        expect(
          commands.filter((command) => command === "complete-scan"),
        ).toHaveLength(1);
      } else {
        await expect(pending).rejects.toThrow(
          scenario === "wrong-claim"
            ? "another continuation"
            : scenario === "changed-artifact"
              ? "Cannot resume sealed scan"
              : "match its target, directory and mode",
        );
        expect(commands).not.toContain("complete-scan");
      }
      expect(authentications).toBe(0);
      expect(commands).not.toContain("get-scan-feedback");
      expect(
        await Promise.all(
          artifactNames.map((name) => readFile(join(f.scanDir, name))),
        ),
      ).toEqual(artifacts);
    } finally {
      await client.close();
    }
  },
);

test.each([
  [null, false, false],
  [undefined, false, false],
  [null, true, false],
  [null, true, true],
  ["v2", true, false],
  ["v2", true, true],
] as const)(
  "sealed resume with a %p checkpoint (tracking failure: %p, cost limit: %p)",
  async (checkpoint, trackingFailure, requiredCost) => {
    const f = await interruptedScan("deep", false, {}, false, true, {
      cost: estimateScanCost("gpt-5.6-sol", {
        input_tokens: 375,
        output_tokens: 3,
      })!,
    });
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1375,
      output_tokens: 13,
    })!;
    const expectedCost = {
      inputTokens: 1375,
      outputTokens: 13,
      estimatedUsd: cost.estimatedUsd,
    };
    await finishDiscovery(f);
    if (checkpoint !== "v2") {
      await rm(join(f.scanDir, DEEP_SCAN_CHECKPOINT));
      execFileSync(f.python, [
        "-c",
        `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    timestamp = connection.execute("SELECT started_at FROM scans WHERE id = ?", (sys.argv[2],)).fetchone()[0]
    connection.execute(
        "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
        "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
        "manifest_path, terminal_reason, created_at, updated_at, completed_at) "
        "VALUES (?, 1, 'publication-test', 'succeeded', 'terminal', 1, 0, 1, 1, "
        "?, 'saturated', ?, ?, ?)",
        (sys.argv[2], sys.argv[3], timestamp, timestamp, timestamp),
    )
`,
        join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
        f.scanId,
        join(f.scanDir, "scan-manifest.json"),
      ]);
    }
    if (trackingFailure)
      await f.command([
        "preserve-scan-results",
        "--scan-id",
        f.scanId,
        "--cost-json",
        JSON.stringify(cost),
      ]);
    await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    const artifactNames = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
      ...(checkpoint === "v2" ? [DEEP_SCAN_CHECKPOINT] : []),
    ];
    const artifacts = await Promise.all(
      artifactNames.map((name) => readFile(join(f.scanDir, name))),
    );
    const savedCheckpoint = (
      await f.command(["get-scan", "--scan-id", f.scanId])
    )["compositionCheckpoint"];
    if (checkpoint === "v2")
      expect(savedCheckpoint).toMatchObject({ version: 2 });
    else expect(savedCheckpoint).toBeNull();
    for (const [threadId, cwd, inputTokens, outputTokens, timestamp] of [
      [f.threadId, f.scanDir, 1000, 10, "2026-07-26T12:00:00.900Z"],
      [
        randomUUID(),
        join(f.scanDir, "artifacts/deep_discovery/workers/worker/output"),
        250,
        2,
        "2026-07-26T12:00:00.900Z",
      ],
      [
        randomUUID(),
        join(f.scanDir, "artifacts"),
        125,
        1,
        "2026-07-26T12:02:00Z",
      ],
    ] as const) {
      await writeFile(
        join(f.codexHome, "sessions", `rollout-${threadId}.jsonl`),
        [
          JSON.stringify({
            type: "session_meta",
            payload: { id: threadId, cwd, timestamp },
          }),
          JSON.stringify({
            type: "event_msg",
            payload: {
              type: "token_count",
              info: {
                total_token_usage: {
                  input_tokens: inputTokens,
                  output_tokens: outputTokens,
                },
              },
            },
          }),
          "",
        ].join("\n"),
      );
    }
    let turns = 0;
    let brokenTracking = false;
    const warnings: string[] = [];
    const commands: string[] = [];
    const client = resumeClient(
      f,
      () => ({
        startThread() {
          throw new Error(
            "The sealed legacy scan already has a saved session.",
          );
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              turns++;
              throw new Error("Sealed legacy discovery needs no model turn.");
            },
          };
        },
      }),
      async (options, args, input) => {
        commands.push(args[0]!);
        const result = await runWorkbench(options, args, input);
        if (args[0] === "get-scan" && checkpoint === undefined)
          delete result["compositionCheckpoint"];
        if (args[0] === "get-scan" && trackingFailure && !brokenTracking) {
          // Session identity was already checked; fail subsequent usage reads.
          brokenTracking = true;
          await rename(
            join(f.codexHome, "sessions"),
            join(f.codexHome, "saved-sessions"),
          );
          await writeFile(join(f.codexHome, "sessions"), "not a directory");
        }
        return result;
      },
    )({ codexOverrides: f.recipe.config });
    try {
      const pending = client.run(f.repository, {
        mode: "deep",
        outputDir: f.scanDir,
        resumeScanId: f.scanId,
        ...f.recipe.deepScan,
        ...(requiredCost ? { maxCostUsd: 1 } : {}),
        onWarning: (warning) => warnings.push(warning),
      });
      if (requiredCost) {
        await expect(pending).rejects.toBeInstanceOf(ScanCostTrackingError);
        expect(commands).not.toContain("complete-scan");
      } else {
        const result = await pending;
        expect(result.threadId).toBe(f.threadId);
        expect(result.cost).toMatchObject(expectedCost);
        if (trackingFailure)
          expect(warnings).toContainEqual(
            expect.stringContaining("Could not track scan activity:"),
          );
        expect(commands).toContain("complete-scan");
      }
      expect(brokenTracking).toBe(trackingFailure);
      expect(turns).toBe(0);
      expect(
        (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
      ).toMatchObject({
        progress: { status: requiredCost ? "running" : "complete" },
        cost: expectedCost,
      });
      expect(
        await Promise.all(
          artifactNames.map((name) => readFile(join(f.scanDir, name))),
        ),
      ).toEqual(artifacts);
    } finally {
      await client.close();
    }
  },
);

test.each([
  [false, false],
  [false, true],
  [true, false],
  [true, true],
] as const)(
  "sealed recovery distinguishes a parent snapshot from a completed total (complete: %p, required cost: %p)",
  async (completed, requiredCost) => {
    const finding = semanticFinding({
      identity: { anchor: "retained-review" },
    });
    const f = await interruptedScan("deep", false, {}, true, true, {
      findings: [finding],
    });
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      output_tokens: 100,
    })!;
    await finishDiscovery(f);
    await f.command([
      "preserve-scan-results",
      "--scan-id",
      f.scanId,
      "--cost-json",
      JSON.stringify(cost),
    ]);
    await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    const names = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
      DEEP_SCAN_CHECKPOINT,
    ];
    const artifacts = await Promise.all(
      names.map((name) => readFile(join(f.scanDir, name))),
    );
    let completions = 0;
    const client = resumeClient(
      f,
      () => ({
        startThread() {
          throw new Error("Sealed recovery needs no new session.");
        },
        resumeThread(threadId) {
          return {
            id: threadId,
            async runStreamed() {
              throw new Error("Sealed recovery needs no model turn.");
            },
          };
        },
      }),
      async (options, args, input) => {
        if (args[0] === "complete-scan") completions++;
        const response = await runWorkbench(options, args, input);
        if (completed && args[0] === "get-cli-scan-resume")
          await f.command([
            "complete-scan",
            "--scan-id",
            f.scanId,
            "--cost-json",
            JSON.stringify(cost),
          ]);
        return response;
      },
    )({ codexOverrides: f.recipe.config });
    try {
      const pending = client.run(f.repository, {
        mode: "deep",
        outputDir: f.scanDir,
        resumeScanId: f.scanId,
        ...f.recipe.deepScan,
        ...(requiredCost ? { maxCostUsd: 1 } : {}),
      });
      if (requiredCost && !completed) {
        await expect(pending).rejects.toBeInstanceOf(ScanCostTrackingError);
        expect(completions).toBe(0);
      } else {
        const result = await pending;
        expect(result.cost).toEqual(completed ? cost : null);
        expect(result.findings.findings).toHaveLength(1);
        expect(result.findings.findings[0]!.title).toBe(finding.title);
        expect(completions).toBe(1);
      }
      const saved = (await f.command(["get-scan", "--scan-id", f.scanId]))[
        "scan"
      ] as JsonObject;
      expect(saved).toMatchObject({
        progress: {
          status: requiredCost && !completed ? "running" : "complete",
        },
      });
      if (completed || requiredCost)
        expect(saved["cost"] as unknown).toEqual(cost);
      else expect(saved["cost"]).toBeUndefined();
      expect(
        await Promise.all(names.map((name) => readFile(join(f.scanDir, name)))),
      ).toEqual(artifacts);
    } finally {
      await client.close();
    }
  },
);

test("bulk recovery merges a sealed child when the parent stopped before its first merge thread", async () => {
  const f = await interruptedScan("deep", true, {}, false, false);
  const before = await readFile(join(f.childDir!, "findings.json"));
  const stderr = capture();
  const stdout = capture();
  let merges = 0;
  const code = await main(
    ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: resumeClient(f, () => ({
        resumeThread() {
          throw new Error("Parent has no saved merge thread yet.");
        },
        startThread(threadOptions) {
          expect(threadOptions.workingDirectory).toBe(
            join(f.scanDir, "artifacts/deep-scan/merge"),
          );
          return {
            id: f.threadId,
            async runStreamed() {
              merges++;
              async function* events() {
                for await (const event of completedEvents(f.threadId)) {
                  if (
                    event.type === "item.completed" &&
                    event.item.type === "agent_message"
                  )
                    yield {
                      ...event,
                      item: {
                        ...event.item,
                        text: JSON.stringify({
                          scanId: f.scanId,
                          findings: [],
                        }),
                      },
                    };
                  else yield event;
                }
              }
              return { events: events() };
            },
          };
        },
      })),
    },
  );
  expect(code, stderr.text()).toBe(2);
  expect(JSON.parse(stdout.text()), stderr.text()).toMatchObject({
    incomplete: 1,
    failed: 0,
  });
  expect(merges).toBe(1);
  expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(before);
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "complete" } });
});

test.each([
  "single",
  "bulk",
  "unsupported-schema",
  "wrong-producer",
  "changed-findings",
])(
  "resume preserves sealed artifacts across a plugin upgrade (%s)",
  async (scenario) => {
    const postScanPrompt = "Finish the original sealed scan follow-up.";
    const childCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 20000,
      output_tokens: 4000,
    })!;
    const f = await interruptedScan(
      "deep",
      scenario === "bulk",
      { postScanPrompt },
      false,
      true,
      { cost: childCost },
    );
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
    await finishDiscovery(f);
    const oldPlugin = join(f.root, "old-plugin");
    for (const path of ["scripts", "schemas", ".codex-plugin"]) {
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
    const followUps: string[] = [];
    const stdout = capture();
    const stderr = capture();
    const code = await main(
      scenario === "bulk"
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, () => ({
          startThread(options) {
            expect(options?.workingDirectory).toBe(f.scanDir);
            return {
              id: "saved-post-scan",
              async runStreamed(prompt) {
                followUps.push(prompt as string);
                return { events: completedEvents("saved-post-scan") };
              },
            };
          },
          resumeThread(threadId) {
            expect(threadId).toBe(f.threadId);
            return {
              id: threadId,
              async runStreamed() {
                turns++;
                throw new Error("Sealed scan needs no model turn");
              },
            };
          },
        })),
      },
    );
    expect(code, stderr.text()).toBe(2);
    expect(
      await Promise.all(
        artifactNames.map((name) => readFile(join(f.scanDir, name))),
      ),
    ).toEqual(artifacts);
    const after = await f.command(["get-scan", "--scan-id", f.scanId]);
    if (rejected) {
      expect(stderr.text()).toContain("Cannot resume sealed scan");
      expect(turns).toBe(0);
      expect(followUps).toEqual([]);
      expect(after).toEqual(before);
    } else {
      expect(after["scan"], stderr.text()).toMatchObject({
        progress: { status: "complete" },
        continuationThreadId: f.threadId,
        cost: { inputTokens: 30000, outputTokens: 6000 },
      });
      expect(turns).toBe(0);
      expect(followUps).toEqual([postScanPrompt]);
      if (scenario === "single")
        expect(JSON.parse(stdout.text())).toMatchObject({
          cost: { inputTokens: 30000, outputTokens: 6000 },
        });
      if (scenario === "bulk") {
        expect(JSON.parse(stdout.text())).toMatchObject({
          incomplete: 1,
          failed: 0,
        });
        const receipts = (await readFile(join(f.root, "results.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(receipts).toHaveLength(2);
        expect(receipts[1]).toMatchObject({
          attempt: 1,
          outputDir: f.scanDir,
          status: "completed_with_incomplete_coverage",
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
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const stdout = capture();
    const stderr = capture();
    const code = await main(
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
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: () => {
              throw new Error("Synthetic stop after registration");
            },
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
  ["chatgpt", false, false],
  ["api-key", false, false],
  [undefined, false, false],
  ["chatgpt", true, false],
  ["api-key", true, false],
  [undefined, true, false],
  [undefined, false, true],
  [undefined, true, true],
] as const)(
  "resume restores saved launch settings with %s auth (bulk: %p, native provider: %p)",
  async (auth, bulk, preserveProviderEnvironment) => {
    const settings = {
      auth,
      ...(preserveProviderEnvironment
        ? { preserveProviderEnvironment: true }
        : {}),
      safetyIdentifier:
        auth === "chatgpt" ? undefined : "synthetic-original-user",
      postScanPrompt: "Run these exact saved post-scan instructions.\n",
      inheritedPermissions: {
        filesystem: {
          [join(tmpdir(), "synthetic-private")]: "deny",
          glob_scan_max_depth: 4,
        },
        network: { enabled: false },
      },
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
    const stdout = capture();
    const stderr = capture();
    const code = await main(
      bulk
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, (options) => {
          const permission = options.configOverrides?.find((value) =>
            value.startsWith("permissions.codex_security_scan="),
          );
          expect(permission).toBeDefined();
          expect(parseToml(permission!)).toMatchObject({
            permissions: { codex_security_scan: settings.inheritedPermissions },
          });
          expect(options.env?.["CODEX_SAFETY_IDENTIFIER"]).toBe(
            settings.safetyIdentifier,
          );
          expect(options.apiKey).toBe(
            preserveProviderEnvironment || auth === "chatgpt"
              ? undefined
              : "synthetic-resume-key",
          );
          expect(options.env?.["OPENAI_API_KEY"]).toBe(
            preserveProviderEnvironment ? "synthetic-resume-key" : undefined,
          );
          expect(options.env?.["CODEX_API_KEY"]).toBeUndefined();
          return {
            startThread() {
              return {
                id: f.threadId,
                async runStreamed(prompt) {
                  prompts.push(prompt as string);
                  return { events: completedEvents(f.threadId) };
                },
              };
            },
            resumeThread(threadId) {
              expect(threadId).toBe(f.threadId);
              return {
                id: threadId,
                async runStreamed() {
                  throw new Error("Completed inputs need no model turn.");
                },
              };
            },
          };
        }),
      },
    );
    expect(code, stderr.text()).toBe(2);
    expect(prompts, stderr.text()).toEqual([settings.postScanPrompt]);
    expect(
      (await f.command(["get-scan-recipe", "--scan-id", f.scanId]))["recipe"],
    ).toMatchObject({
      ...JSON.parse(JSON.stringify(settings)),
      deepScan: {
        subagents: 0,
        stopAfterConsecutiveErrors: 2,
        maxTimeHours: 1.5,
      },
    });
    expect(f.environment.OPENAI_API_KEY).toBe("synthetic-resume-key");
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
    });
  },
);

test("missing session logs do not create another session or fail the original scan", async () => {
  const f = await interruptedScan();
  await rm(f.sessionPath);
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["scans", "resume", f.scanId],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: resumeClient(f, () => {
        throw new Error("Must not invoke Codex without the original session");
      }),
    },
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
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies({
      environment: f.environment,
      currentDirectory: f.root,
    });
    let attempts = 0;
    expect(
      await main(
        ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
        stdout.stream,
        stderr.stream,
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
                coverage: { completeness: "complete" },
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

test("the public resume command remains limited to Deep scans", async () => {
  const f = await interruptedScan("standard");
  const before = await f.command(["get-scan", "--scan-id", f.scanId]);
  let runs = 0;
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    capture().stream,
    capture().stream,
    {
      ...dependencies({
        environment: f.environment,
        currentDirectory: f.root,
        onRun() {
          runs++;
        },
      }),
      runWorkbench: f.command,
    },
  );
  expect(code).toBe(2);
  expect(runs).toBe(0);
  expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(before);
});

test("resume requires an explicit scan ID", async () => {
  const stdout = capture();
  const stderr = capture();
  const code = await main(["scans", "resume"], stdout.stream, stderr.stream, {
    ...dependencies(),
    runWorkbench: async () => {
      throw new Error("Must select a scan explicitly");
    },
  });
  expect(code).toBe(2);
  expect(stderr.text()).toContain("scanId");
});
