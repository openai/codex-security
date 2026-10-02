import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import type { ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost, type ScanCost } from "../src/cost.js";
import {
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
} from "../src/deep-scan.js";
import type { SemanticScan } from "../src/scan-semantics.js";
import { writeSemanticScanDraft } from "../src/scan-publication.js";
import { prepareScanArtifactRestorer, runWorkbench } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { tokenUsageEvent } from "./support/usage-rollout.js";
import {
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
  > & { model?: string } = {},
  resolvedDeep = false,
  startedMerge = true,
  ordinaryPass: {
    cost?: ScanCost;
    findings?: SemanticScan["findings"];
    coverage?: SemanticScan["coverage"];
  } | null = {},
) {
  const { model = "gpt-5.6-sol", ...scanSettings } = settings;
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
      model,
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
    ...scanSettings,
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
      version: 3,
      startedAt: "2000-01-01T00:00:00Z",
      passes: [
        { directory: "artifacts/deep-scan/passes/pass-1", scanId: childId },
      ],
      mergedScanIds: startedMerge ? [childId] : [],
      aggregate: startedMerge ? { ...aggregate, sourceFindings: {} } : null,
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
      JSON.stringify({ ...state, aggregate: undefined, aggregatePath: null }),
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
  await writeSemanticScanDraft(
    {
      contract: {
        targetContract: registration["contract"] as JsonObject,
        mode,
        targetRevision: registration["targetRevision"] as string,
      },
      workbench: command,
    },
    draft,
  );
}

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

test("Deep sealed resume retains session cost until final receipts are produced", async () => {
  const f = await interruptedScan("deep");
  const usage = { input_tokens: 1000, output_tokens: 10 };
  const cost = estimateScanCost("gpt-5.6-sol", usage)!;
  await writeFile(
    f.sessionPath,
    [
      {
        type: "session_meta",
        payload: {
          id: f.threadId,
          cwd: f.scanDir,
          timestamp: new Date().toISOString(),
        },
      },
      tokenUsageEvent(usage),
    ]
      .map((event) => JSON.stringify(event))
      .join("\n") + "\n",
  );
  await writeDraft(f.command, f.registration, "deep", {
    scanId: f.scanId,
    findings: [],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const checkpoint = JSON.parse(
    await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
  );
  await f.command(
    [
      "save-scan-artifact",
      "--scan-id",
      f.scanId,
      "--artifact-path",
      DEEP_SCAN_CHECKPOINT,
    ],
    JSON.stringify({ ...checkpoint, terminalReason: "capped" }),
  );
  await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
  let resumed = 0;
  await using client = resumeClient(f, () => ({
    startThread() {
      throw new Error("The existing Deep session must be resumed.");
    },
    resumeThread(id) {
      expect(id).toBe(f.threadId);
      resumed++;
      return {
        id,
        async runStreamed() {
          return {
            events: (async function* () {
              yield { type: "thread.started", thread_id: id } as const;
              yield { type: "turn.completed", usage } as const;
            })(),
          };
        },
      };
    },
  }))({ codexOverrides: f.recipe.config });
  const result = await client.run(f.repository, {
    mode: "deep",
    outputDir: f.scanDir,
    resumeScanId: f.scanId,
    maxCostUsd: 1,
  });
  expect(resumed).toBe(1);
  expect(result.cost).toEqual(cost);
  expect(result.threadId).toBe(f.threadId);
});

test.each([
  ["dedicated", true],
  ["unpriced", false],
  ["unpriced", true],
  ["other-directory", false],
  ["other-directory", true],
  ["predates-scan", false],
  ["predates-scan", true],
  ["undated", false],
  ["undated", true],
  ["completed", true],
] as const)(
  "sealed Standard recovery attributes only scan-owned sessions (%s, required: %p)",
  async (origin, requireCost) => {
    const f = await interruptedScan(
      "standard",
      false,
      origin === "unpriced" ? { model: "unpriced-synthetic-model" } : {},
    );
    const usage = { input_tokens: 1_000_000, output_tokens: 100 };
    const startedAt = (
      await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
    )["startedAt"] as string;
    await writeFile(
      f.sessionPath,
      [
        {
          type: "session_meta",
          payload: {
            id: f.threadId,
            cwd: origin === "other-directory" ? f.repository : f.scanDir,
            ...(origin === "undated"
              ? {}
              : {
                  timestamp: new Date(
                    Date.parse(startedAt) +
                      (origin === "predates-scan" ? -60_000 : 1),
                  ).toISOString(),
                }),
          },
        },
        tokenUsageEvent(usage),
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );
    await writeDraft(f.command, f.registration, "standard", {
      scanId: f.scanId,
      findings: [],
      coverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    });
    await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    const names = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
    ];
    const artifacts = await Promise.all(
      names.map((name) => readFile(join(f.scanDir, name))),
    );
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    const storedCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    await using client = resumeClient(
      f,
      () => {
        throw new Error("Sealed recovery must not invoke Codex");
      },
      async (options, args, input) => {
        const result = await runWorkbench(options, args, input);
        if (origin === "completed" && args[0] === "get-cli-scan-resume") {
          // Completion can commit after resume reads its registration.
          await f.command([
            "complete-scan",
            "--scan-id",
            f.scanId,
            "--cost-json",
            JSON.stringify(storedCost),
          ]);
          await rm(f.sessionPath);
        }
        return result;
      },
    )({ codexOverrides: f.recipe.config });
    const pending = client.run(f.repository, {
      mode: "standard",
      deepScanPass: true,
      outputDir: f.scanDir,
      resumeScanId: f.scanId,
      requireCost,
    });
    if (requireCost && origin !== "dedicated" && origin !== "completed") {
      await expect(pending).rejects.toThrow("no verified cost receipt");
      expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
        before,
      );
    } else {
      const result = await pending;
      const expectedCost =
        origin === "dedicated"
          ? estimateScanCost("gpt-5.6-sol", usage)
          : origin === "completed"
            ? storedCost
            : null;
      expect(result.cost).toEqual(expectedCost);
      if (origin === "unpriced") {
        expect(result.turnResult.usage).toMatchObject({
          ...usage,
          total_tokens: 1_000_100,
        });
        expect(result.toJSON()).toMatchObject({
          cost: null,
          turn: {
            model: "unpriced-synthetic-model",
            usage: result.turnResult.usage,
          },
        });
      }
      const saved = (await f.command(["get-scan", "--scan-id", f.scanId]))[
        "scan"
      ] as JsonObject;
      expect(saved["progress"]).toMatchObject({ status: "complete" });
      expect<unknown>(saved["cost"] ?? null).toEqual(expectedCost);
    }
    expect(
      await Promise.all(names.map((name) => readFile(join(f.scanDir, name)))),
    ).toEqual(artifacts);
  },
);
