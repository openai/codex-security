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
  type DeepScanCheckpoint,
} from "../src/deep-scan.js";
import {
  prepareSemanticScanDraft,
  type SemanticScan,
} from "../src/scan-semantics.js";
import { prepareScanArtifactRestorer, runWorkbench } from "../src/runtime.js";
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
  ordinaryPass: { cost?: ScanCost } | null = {},
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
      }),
    );
    childId = child["scanId"] as string;
    const aggregate: SemanticScan = {
      scanId,
      findings: [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [{ id: "time-cap", reason: "Synthetic time cap" }],
      },
    };
    await writeDraft(command, child, "standard", {
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

async function writeDraft(
  command: (args: readonly string[], input?: string) => Promise<JsonObject>,
  registration: JsonObject,
  mode: "deep" | "standard",
  draft: SemanticScan,
) {
  const directory = registration["scanDir"] as string;
  const documents = prepareSemanticScanDraft(
    {
      targetContract: registration["contract"] as JsonObject,
      mode,
      targetRevision: registration["targetRevision"] as string,
    },
    draft,
  );
  const draftPath = join(directory, "drafts", randomUUID() + ".json");
  const checkpointPath = join(
    directory,
    "drafts",
    randomUUID() + ".checkpoint.json",
  );
  await mkdir(join(directory, "drafts"), { recursive: true, mode: 0o700 });
  await writeFile(draftPath, JSON.stringify(documents));
  await writeFile(checkpointPath, JSON.stringify(draft));
  await command([
    "write-scan-draft",
    "--scan-id",
    registration["scanId"] as string,
    "--draft-path",
    draftPath,
    "--checkpoint-path",
    checkpointPath,
  ]);
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
  await writeDraft(f.command, f.registration, "deep", checkpoint.aggregate!);
}

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

test.each([
  [false, false],
  [true, false],
  [false, true],
])(
  "completed legacy discovery recovers partial results when its saved budget is exhausted (sealed: %p, restore logs: %p)",
  async (sealed, restoreLogs) => {
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
    const coverage = {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [{ reason: "Retained legacy discovery coverage." }],
    };
    const checkpoint: DeepScanCheckpoint = {
      version: 2,
      startedAt: "2000-01-01T00:00:00Z",
      passes: [],
      mergedScanIds: [],
      aggregate: { scanId: f.scanId, findings: [], coverage },
      noNewStreak: 0,
      consecutiveErrors: 0,
      terminalReason: "capped",
      legacy: {
        discoveryRuns: 1,
        coverage,
        originThreadId: f.threadId,
        ...(restoreLogs ? {} : { cost }),
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
    if (sealed) {
      await writeDraft(
        f.command,
        f.registration,
        "deep",
        checkpoint.aggregate!,
      );
      await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    }
    const artifacts = sealed
      ? await Promise.all(
          artifactNames.map((name) => readFile(join(f.scanDir, name))),
        )
      : undefined;
    let starts = 0;
    let turns = 0;
    const client = resumeClient(f, () => ({
      startThread() {
        starts++;
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
      if (restoreLogs) {
        const savedSession = await readFile(f.sessionPath);
        const checkpointPath = join(f.scanDir, DEEP_SCAN_CHECKPOINT);
        const savedCheckpoint = await readFile(checkpointPath);
        const before = await f.command(["get-scan", "--scan-id", f.scanId]);
        await rm(f.sessionPath);
        try {
          await expect(client.run(f.repository, options)).rejects.toThrow(
            "Restore the original Deep Scan session logs",
          );
          expect(starts).toBe(0);
          expect(turns).toBe(0);
          expect(before["scan"]).toMatchObject({
            progress: { status: "running" },
          });
          expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
            before,
          );
          expect(await readFile(checkpointPath)).toEqual(savedCheckpoint);
        } finally {
          await writeFile(f.sessionPath, savedSession);
        }
      }
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
      if (sealed) {
        expect(
          await Promise.all(
            artifactNames.map((name) => readFile(join(f.scanDir, name))),
          ),
        ).toEqual(artifacts!);
      }
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
    const f = await interruptedScan();
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
