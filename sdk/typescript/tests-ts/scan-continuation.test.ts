import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import type { ThreadEvent } from "@openai/codex-sdk";
import { scanPreflightCodexConfig } from "../src/api.js";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
} from "../src/errors.js";
import { DEFAULT_CODEX_CONFIG } from "../src/config.js";
import {
  estimateScanCost,
  ScanCostTracker,
  type ScanCost,
} from "../src/cost.js";
import { prepareScanArtifactRestorer, runWorkbench } from "../src/runtime.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);
const previousCost = {
  model: "gpt-5.6-sol",
  inputTokens: 1000,
  cachedInputTokens: 0,
  cacheWriteInputTokens: 0,
  outputTokens: 50,
  estimatedUsd: 12.5,
};

async function savedScan(
  options: {
    mode?: "standard" | "deep";
    running?: boolean;
    cost?: boolean;
    savedCost?: ScanCost;
    maxCostUsd?: number;
    custom?: boolean;
    postScanPrompt?: string;
    registerThread?: boolean;
  } = {},
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const codexHome = join(root, "state", "codex-home");
  await mkdir(repository);
  await mkdir(scanDir, { mode: 0o700 });
  await mkdir(join(codexHome, "sessions"), { recursive: true });
  await writeFile(
    join(repository, "reviewed.ts"),
    "export const reviewed = true;\n",
  );
  await writeFile(
    join(repository, "pending.ts"),
    "export const pending = true;\n",
  );
  const python = Bun.which("python3") ?? Bun.which("python");
  if (python === null) throw new Error("Python is required.");
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: codexHome,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const command = (args: readonly string[], input?: string) =>
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
  const recipe = {
    repository,
    target: { kind: "repository", paths: [] },
    mode: options.mode ?? "standard",
    config: {
      ...scanPreflightCodexConfig({
        ...DEFAULT_CODEX_CONFIG,
        approval_policy: "never",
      }),
      approval_policy: "never",
    },
    pluginVersion: "0.1.0",
    ...(options.maxCostUsd === undefined
      ? {}
      : { maxCostUsd: options.maxCostUsd }),
    ...(options.custom ? { validationMode: "custom" } : {}),
    ...(options.postScanPrompt === undefined
      ? {}
      : { postScanPrompt: options.postScanPrompt }),
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
      userContext: "Preserve the original review instructions.",
    }),
  );
  const scanId = registration["scanId"] as string;
  const threadId = randomUUID();
  if (options.registerThread !== false)
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
      payload: { id: threadId, cwd: scanDir },
    }) + "\n",
  );
  const finding = JSON.parse(
    await readFile(
      join(PLUGIN_ROOT, "examples", "completed-scan", "findings.json"),
      "utf8",
    ),
  ).findings[0];
  finding.locations = [{ path: "reviewed.ts", startLine: 1 }];
  const snapshot = {
    scanId,
    complete: false,
    findings: [finding],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      reviewedFiles: ["reviewed.ts"],
    },
  };
  async function checkpoint(
    directory: string,
    id: string,
    value: object,
    customValidationComplete = false,
  ) {
    const contents = JSON.stringify(value) + "\n";
    const path = join(
      directory,
      "checkpoints",
      `${createHash("sha256").update(contents).digest("hex")}.json`,
    );
    await mkdir(join(directory, "checkpoints"), { recursive: true });
    await writeFile(path, contents);
    return command([
      "record-scan-checkpoint",
      "--scan-id",
      id,
      "--checkpoint-path",
      path,
      ...(customValidationComplete ? ["--custom-validation-complete"] : []),
    ]);
  }
  await checkpoint(scanDir, scanId, snapshot);
  if (!options.running)
    await command([
      "fail-scan",
      "--scan-id",
      scanId,
      "--message",
      "Synthetic interrupted scan",
      ...(options.cost === false
        ? []
        : ["--cost-json", JSON.stringify(options.savedCost ?? previousCost)]),
    ]);
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
    sessionPath,
    checkpoint,
  };
}

type Fixture = Awaited<ReturnType<typeof savedScan>>;
async function resume(
  f: Fixture,
  createCodex: NonNullable<
    ConstructorParameters<typeof TestClient>[1]["createCodex"]
  >,
  options: {
    failExport?: boolean;
    failRestorer?: boolean;
    beforeWorkbench?: (args: readonly string[]) => Promise<void>;
  } = {},
) {
  await mkdir(f.codexHome, { recursive: true });
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: (config) =>
        new TestClient(config, {
          environment: f.environment,
          prepareRuntime: async () => {
            const runtime = preparedRuntime(f.codexHome);
            runtime.persistentCredentialHome = true;
            runtime.plugin.version = JSON.parse(
              await readFile(
                join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
                "utf8",
              ),
            ).version;
            return runtime;
          },
          resolvePluginPython: async () => f.python,
          runWorkbench: async (workbenchOptions, args, input) => {
            await options.beforeWorkbench?.(args);
            if (options.failExport && args[0] === "prepare-scan-completion")
              throw new Error("Synthetic local export failure");
            return runWorkbench(workbenchOptions, args, input);
          },
          prepareScanArtifactRestorer: options.failRestorer
            ? async () => {
                throw new Error("Synthetic restorer setup failure");
              }
            : prepareScanArtifactRestorer,
          createCodex,
        }),
    },
  );
  return { code, stdout: stdout.text(), stderr: stderr.text() };
}

async function finishChild(f: Fixture, scanDir: string, scanId: string) {
  const manifest = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  );
  const findings = JSON.parse(
    await readFile(join(scanDir, "findings.json"), "utf8"),
  );
  const coverage = JSON.parse(
    await readFile(join(scanDir, "coverage.json"), "utf8"),
  );
  manifest.scan.complete = true;
  coverage.completeness = "complete";
  coverage.deferred = [];
  coverage.reviewedFiles = ["pending.ts", "reviewed.ts"];
  await f.checkpoint(scanDir, scanId, {
    scanId,
    complete: true,
    findings: findings.findings,
    coverage,
  });
  await writeFile(
    join(scanDir, "scan-manifest.json"),
    JSON.stringify(manifest) + "\n",
  );
  await writeFile(
    join(scanDir, "coverage.json"),
    JSON.stringify(coverage) + "\n",
  );
}

test("Standard continuation preserves the sealed parent and resumes only unfinished source with cumulative cost", async () => {
  const f = await savedScan();
  const parent = await readFile(join(f.scanDir, "scan-manifest.json"), "utf8");
  let childId = "";
  let childDirectory = "";
  let modelCalls = 0;
  const outcome = await resume(f, (options) => ({
    startThread(threadOptions) {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      childDirectory = threadOptions.workingDirectory!;
      expect(childId).not.toBe(f.scanId);
      expect(childDirectory).not.toBe(f.scanDir);
      const threadId = randomUUID();
      return {
        id: threadId,
        async runStreamed(prompt) {
          modelCalls++;
          expect(prompt).toContain(
            "Preserve the original review instructions.",
          );
          expect(prompt).toContain("Review only remainingFiles");
          expect(
            JSON.parse(
              await readFile(
                join(
                  childDirectory,
                  "artifacts",
                  "01_context",
                  `scan-continuation-${childId}.json`,
                ),
                "utf8",
              ),
            ),
          ).toEqual({
            parentScanId: f.scanId,
            reviewedFiles: ["reviewed.ts"],
            remainingFiles: ["pending.ts"],
          });
          const inherited = JSON.parse(
            await readFile(join(childDirectory, "findings.json"), "utf8"),
          );
          expect(inherited.findings).toHaveLength(1);
          await finishChild(f, childDirectory, childId);
          return { events: completedEvents(threadId) };
        },
      };
    },
    resumeThread() {
      throw new Error("A sealed parent cannot be reopened");
    },
  }));
  expect(outcome.code, outcome.stderr).toBe(0);
  expect(modelCalls).toBe(1);
  expect(await readFile(join(f.scanDir, "scan-manifest.json"), "utf8")).toBe(
    parent,
  );
  const result = JSON.parse(outcome.stdout);
  expect(result.findings.findings).toHaveLength(1);
  expect(result.cost.estimatedUsd).toBeGreaterThan(12.5);
  expect(result.cost.inputTokens).toBe(1010);
  expect(
    (await f.command(["get-scan", "--scan-id", childId]))["scan"],
  ).toMatchObject({
    parentScanId: f.scanId,
    progress: { status: "complete" },
    cost: result.cost,
    checkpoint: { remainingFileCount: 0 },
  });
  expect(
    (await f.command(["get-scan", "--scan-id", childId]))["scan"],
  ).not.toHaveProperty("sourceThreadId");
  await expect(
    f.command(["get-cli-scan-resume", "--scan-id", childId]),
  ).rejects.toThrow("already completed");
});

test.each([
  "reported",
  "parent-unreported",
  "current-unreported",
  "different-pricing",
  "missing-pricing",
] as const)(
  "continuation preserves truthful cost metadata (%s)",
  async (scenario) => {
    const parentCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 1000,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      cache_write_input_tokens_reported: scenario !== "parent-unreported",
      output_tokens: 50,
    })!;
    if (scenario === "different-pricing") {
      parentCost.pricing!.usdPerMillionTokens.input *= 2;
      parentCost.estimatedUsd += 0.004;
    } else if (scenario === "missing-pricing") {
      delete parentCost.pricing;
    }
    const f = await savedScan({ savedCost: parentCost });
    let childId = "";
    const currentUsage = {
      input_tokens: 10,
      cached_input_tokens: 2,
      cache_write_input_tokens: 0,
      cache_write_input_tokens_reported: scenario !== "current-unreported",
      output_tokens: 3,
      reasoning_output_tokens: 1,
    };
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed() {
            await finishChild(f, threadOptions.workingDirectory!, childId);
            return {
              events: (async function* () {
                for await (const event of completedEvents(threadId))
                  yield event.type === "turn.completed"
                    ? { ...event, usage: currentUsage }
                    : event;
              })(),
            };
          },
        };
      },
      resumeThread() {
        throw new Error("A sealed parent cannot be reopened");
      },
    }));
    expect(outcome.code, outcome.stderr).toBe(0);
    const result = JSON.parse(outcome.stdout);
    const currentCost = estimateScanCost(result.cost.model, currentUsage)!;
    expect(result.cost.estimatedUsd).toBe(
      parentCost.estimatedUsd + currentCost.estimatedUsd,
    );
    expect(result.cost.cacheWriteInputTokensReported).toBe(
      scenario === "parent-unreported" || scenario === "current-unreported"
        ? false
        : undefined,
    );
    expect(result.cost.pricing).toEqual(
      scenario === "different-pricing" || scenario === "missing-pricing"
        ? undefined
        : currentCost.pricing,
    );
    expect(
      (await f.command(["get-scan", "--scan-id", childId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      cost: result.cost,
    });
  },
);

test.each(["scan-continuation.json", "false_positive_feedback.json"])(
  "continuation preserves inherited %s receipts while writing current context",
  async (filename) => {
    const f = await savedScan({ running: true });
    const receipt = `artifacts/01_context/${filename}`;
    const inherited =
      JSON.stringify({ evidence: "Previous attempt context" }) + "\n";
    await mkdir(join(f.scanDir, "artifacts", "01_context"), {
      recursive: true,
    });
    await writeFile(join(f.scanDir, receipt), inherited);
    const current = (
      await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
    )["checkpoint"] as {
      sources: Array<{ findings: object[]; coverage: object }>;
    };
    await f.checkpoint(f.scanDir, f.scanId, {
      scanId: f.scanId,
      complete: false,
      findings: current.sources[0]!.findings,
      coverage: {
        ...current.sources[0]!.coverage,
        surfaces: [
          {
            id: "saved-context",
            label: "Previously reviewed context",
            disposition: "not_applicable",
            receiptRefs: [receipt],
          },
        ],
      },
    });
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic interruption after saving context",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    const reason = "The current route checks the session before access.";
    if (filename === "false_positive_feedback.json") {
      const reviewedDirectory = join(f.root, "reviewed-scan");
      await mkdir(reviewedDirectory, { mode: 0o700 });
      const registration = await f.command([
        "register-cli-scan",
        "--repository",
        f.repository,
        "--scan-dir",
        reviewedDirectory,
        "--parent-scan-id",
        f.scanId,
        "--recipe-json",
        JSON.stringify(f.recipe),
      ]);
      const reviewedId = registration["scanId"] as string;
      await f.command([
        "continue-scan-checkpoint",
        "--scan-id",
        reviewedId,
        "--parent-scan-id",
        f.scanId,
      ]);
      await finishChild(f, reviewedDirectory, reviewedId);
      const completed = await f.command([
        "complete-scan",
        "--scan-id",
        reviewedId,
      ]);
      const scan = completed["scan"] as {
        findings: Array<{ occurrenceId: string }>;
      };
      await f.command([
        "set-finding-triage",
        "--occurrence-id",
        scan.findings[0]!.occurrenceId,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        reason,
      ]);
    }
    let childDirectory = "";
    let modelCalls = 0;
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        childDirectory = threadOptions.workingDirectory!;
        const scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed(prompt) {
            modelCalls++;
            expect(await readFile(join(childDirectory, receipt), "utf8")).toBe(
              inherited,
            );
            const contextDirectory = join(
              childDirectory,
              "artifacts",
              "01_context",
            );
            const contextFiles = await readdir(contextDirectory);
            let foundCurrent = false;
            for (const name of contextFiles) {
              if (name === filename || !name.endsWith(".json")) continue;
              const document = JSON.parse(
                await readFile(join(contextDirectory, name), "utf8"),
              );
              const matches =
                filename === "scan-continuation.json"
                  ? document.parentScanId === f.scanId
                  : Array.isArray(document) && document[0]?.reason === reason;
              if (matches) {
                foundCurrent = true;
                expect(prompt).toContain(name);
              }
            }
            expect(foundCurrent).toBe(true);
            await finishChild(f, childDirectory, scanId);
            return { events: completedEvents(threadId) };
          },
        };
      },
    }));
    expect(outcome.code, outcome.stderr).toBe(0);
    expect(modelCalls).toBe(1);
    expect(await readFile(join(f.scanDir, receipt), "utf8")).toBe(inherited);
    expect(await readFile(join(childDirectory, receipt), "utf8")).toBe(
      inherited,
    );
  },
);

test("missing Deep native history falls back to a new attempt from semantic checkpoints", async () => {
  const f = await savedScan({ mode: "deep", running: true });
  await rm(f.sessionPath);
  let childId = "";
  const outcome = await resume(f, (options) => ({
    startThread() {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      expect(childId).not.toBe(f.scanId);
      return {
        id: randomUUID(),
        async runStreamed() {
          throw new Error("Synthetic connection failure");
        },
      };
    },
    resumeThread() {
      throw new Error("Unavailable native history must not be resumed");
    },
  }));
  expect(outcome.code).not.toBe(0);
  expect(outcome.stderr).toContain("Synthetic connection failure");
  expect(
    (await f.command(["get-scan", "--scan-id", childId]))["scan"],
  ).toMatchObject({
    parentScanId: f.scanId,
    checkpoint: { reviewedFileCount: 1 },
  });
});

test.each(["initialize", "start-thread", "run-streamed"] as const)(
  "a failed continuation keeps inherited cost only before inference dispatch (%s)",
  async (phase) => {
    const f = await savedScan({ maxCostUsd: 100 });
    let childId = "";
    let modelCalls = 0;
    const failure = new Error("Synthetic continuation setup failure");
    const stopped = await resume(f, (options) => {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      if (phase === "initialize") throw failure;
      return {
        startThread() {
          if (phase === "start-thread") throw failure;
          return {
            id: randomUUID(),
            async runStreamed() {
              modelCalls++;
              throw failure;
            },
          };
        },
      };
    });
    expect(stopped.code).not.toBe(0);
    expect(stopped.stderr).toContain(failure.message);
    expect(childId).not.toBe(f.scanId);
    expect(modelCalls).toBe(phase === "run-streamed" ? 1 : 0);
    const saved = await f.command([
      "get-cli-scan-resume",
      "--scan-id",
      childId,
    ]);
    expect(saved["cost"] ?? null).toEqual(
      phase === "run-streamed" ? null : previousCost,
    );
    expect(saved["inferenceStarted"]).toBe(phase === "run-streamed");

    modelCalls = 0;
    const retried = await resume({ ...f, scanId: childId }, (options) => ({
      startThread(threadOptions) {
        const scanDir = threadOptions.workingDirectory!;
        const scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed() {
            modelCalls++;
            await finishChild(f, scanDir, scanId);
            return { events: completedEvents(threadId) };
          },
        };
      },
    }));
    if (phase === "run-streamed") {
      expect(retried.code).not.toBe(0);
      expect(retried.stderr).toContain("cost is unavailable");
      expect(modelCalls).toBe(0);
    } else {
      expect(retried.code, retried.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      expect(JSON.parse(retried.stdout).cost.estimatedUsd).toBeGreaterThan(
        previousCost.estimatedUsd,
      );
    }
  },
);

test("continuation stops before dispatch when its inference marker cannot be saved", async () => {
  const f = await savedScan({ maxCostUsd: 100 });
  let childId = "";
  let modelCalls = 0;
  const outcome = await resume(
    f,
    () => ({
      startThread() {
        return {
          id: randomUUID(),
          async runStreamed() {
            modelCalls++;
            throw new Error(
              "Inference must not start without its durable marker",
            );
          },
        };
      },
    }),
    {
      beforeWorkbench: async (args) => {
        if (args[0] === "start-scan-inference") {
          childId = args[2]!;
          throw new Error("Synthetic inference marker write failure");
        }
      },
    },
  );
  expect(outcome.code).not.toBe(0);
  expect(outcome.stderr).toContain("Synthetic inference marker write failure");
  expect(modelCalls).toBe(0);
  const saved = await f.command(["get-cli-scan-resume", "--scan-id", childId]);
  expect(saved["inferenceStarted"]).toBe(false);
  expect(saved["cost"]).toEqual(previousCost);
});

test.each([
  "changed source",
  "missing cost",
  "exhausted cost",
  "custom validation",
])("continuation refuses %s before invoking a model", async (scenario) => {
  const f = await savedScan({
    maxCostUsd:
      scenario === "missing cost"
        ? 20
        : scenario === "exhausted cost"
          ? 10
          : undefined,
    cost: scenario !== "missing cost",
    custom: scenario === "custom validation",
  });
  if (scenario === "changed source")
    await writeFile(join(f.repository, "pending.ts"), "changed\n");
  if (scenario === "missing cost") await rm(f.sessionPath);
  let calls = 0;
  const outcome = await resume(f, () => {
    calls++;
    throw new Error("Unexpected model invocation");
  });
  expect(outcome.code).not.toBe(0);
  expect(calls).toBe(0);
  expect(outcome.stderr).toContain(
    scenario === "changed source"
      ? "contents changed"
      : scenario === "missing cost"
        ? "cost is unavailable"
        : scenario === "exhausted cost"
          ? "saved total cost limit"
          : "--validation-prompt-file",
  );
});

test.each([false, true])(
  "historical cost read failures allow continuation only when no saved cap needs it: cap=%j",
  async (capped) => {
    const f = await savedScan({
      cost: false,
      ...(capped ? { maxCostUsd: 100 } : {}),
    });
    const tracker = spyOn(
      ScanCostTracker.prototype,
      "stop",
    ).mockRejectedValueOnce(new Error("Synthetic unreadable sibling rollout"));
    let modelCalls = 0;
    try {
      const outcome = await resume(f, (options) => ({
        startThread(threadOptions) {
          const threadId = randomUUID();
          return {
            id: threadId,
            async runStreamed() {
              modelCalls++;
              await finishChild(
                f,
                threadOptions.workingDirectory!,
                options.env!["CODEX_SECURITY_SCAN_ID"]!,
              );
              return { events: completedEvents(threadId) };
            },
          };
        },
        resumeThread() {
          throw new Error("A sealed parent requires a linked attempt");
        },
      }));
      expect(outcome.stderr).toContain("Previous scan cost is unavailable");
      expect(outcome.stderr).toContain("Synthetic unreadable sibling rollout");
      expect(outcome.code, outcome.stderr).toBe(capped ? 2 : 0);
      expect(modelCalls).toBe(capped ? 0 : 1);
      if (capped) expect(outcome.stderr).toContain("limit cannot be enforced");
      else expect(JSON.parse(outcome.stdout).findings.findings).toHaveLength(1);
    } finally {
      tracker.mockRestore();
    }
  },
);

test.each([false, true])(
  "unavailable native history permits uncapped checkpoint recovery: capped=%j",
  async (capped) => {
    const f = await savedScan({
      cost: false,
      ...(capped ? { maxCostUsd: 100 } : {}),
    });
    await rm(join(f.codexHome, "sessions"), { recursive: true });
    await writeFile(
      join(f.codexHome, "sessions"),
      "Unavailable native history\n",
    );
    let modelCalls = 0;
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed() {
            modelCalls++;
            await finishChild(
              f,
              threadOptions.workingDirectory!,
              options.env!["CODEX_SECURITY_SCAN_ID"]!,
            );
            return { events: completedEvents(threadId) };
          },
        };
      },
    }));
    expect(outcome.code, outcome.stderr).toBe(capped ? 2 : 0);
    expect(modelCalls).toBe(capped ? 0 : 1);
    expect(outcome.stderr).toContain(
      "Previous scan session logs are unavailable",
    );
    if (capped) expect(outcome.stderr).toContain("limit cannot be enforced");
    else expect(JSON.parse(outcome.stdout).findings.findings).toHaveLength(1);
  },
);

test.each([
  { persistedThread: true, nativeLogs: true },
  { persistedThread: false, nativeLogs: true },
  { persistedThread: false, nativeLogs: false },
])(
  "a hard-killed continuation requires bound native spend to enforce its saved cap: %j",
  async ({ persistedThread, nativeLogs }) => {
    const f = await savedScan({ maxCostUsd: 20 });
    const child = join(f.root, "interrupted-child");
    await mkdir(child, { mode: 0o700 });
    const registration = await f.command([
      "register-cli-scan",
      "--repository",
      f.repository,
      "--scan-dir",
      child,
      "--parent-scan-id",
      f.scanId,
      "--recipe-json",
      JSON.stringify(f.recipe),
    ]);
    const childId = registration["scanId"] as string;
    await f.command([
      "continue-scan-checkpoint",
      "--scan-id",
      childId,
      "--parent-scan-id",
      f.scanId,
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    await f.command(["start-scan-inference", "--scan-id", childId]);
    const threadId = randomUUID();
    if (persistedThread)
      await f.command([
        "set-scan-thread",
        "--scan-id",
        childId,
        "--thread-id",
        threadId,
      ]);
    const sessionPath = join(
      f.codexHome,
      "sessions",
      `rollout-${threadId}.jsonl`,
    );
    await writeFile(
      sessionPath,
      JSON.stringify({
        type: "session_meta",
        payload: { id: threadId, cwd: child },
      }) + "\n",
    );
    await appendFile(
      sessionPath,
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
    if (!nativeLogs) await rm(sessionPath);
    let latestId = "";
    let modelCalls = 0;
    const outcome = await resume({ ...f, scanId: childId }, (options) => ({
      startThread(threadOptions) {
        latestId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const newThread = randomUUID();
        return {
          id: newThread,
          async runStreamed() {
            modelCalls++;
            await finishChild(f, threadOptions.workingDirectory!, latestId);
            return { events: completedEvents(newThread) };
          },
        };
      },
    }));
    if (!nativeLogs) {
      expect(outcome.code, outcome.stderr).toBe(2);
      expect(modelCalls).toBe(0);
      expect(outcome.stderr).toContain("cost is unavailable");
      expect(outcome.stderr).toContain("limit cannot be enforced");
      return;
    }
    expect(outcome.code, outcome.stderr).toBe(0);
    expect(modelCalls).toBe(1);
    const result = JSON.parse(outcome.stdout);
    expect(result.cost.estimatedUsd).toBeGreaterThan(12.5);
    expect(result.cost.inputTokens).toBe(11010);
    expect(result.cost.outputTokens).toBe(2053);
  },
);

async function saveCompleteCheckpoint(
  f: Fixture,
  missingReceipt = false,
  customValidationComplete = f.recipe.validationMode === "custom",
) {
  const current = (
    await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
  )["checkpoint"] as {
    sources: Array<{ findings: object[]; coverage: object }>;
  };
  await f.checkpoint(
    f.scanDir,
    f.scanId,
    {
      scanId: f.scanId,
      complete: true,
      ...(f.recipe.validationMode === "custom"
        ? { scope: { validationMode: "custom" } }
        : {}),
      findings: current.sources[0]!.findings,
      coverage: {
        ...current.sources[0]!.coverage,
        completeness: "complete",
        deferred: [],
        reviewedFiles: ["pending.ts", "reviewed.ts"],
        ...(missingReceipt
          ? {
              surfaces: [
                {
                  id: "missing-receipt",
                  candidateId: "candidate-1",
                  label: "Interrupted receipt write",
                  disposition: "rejected",
                  receiptRefs: ["artifacts/review/never-written.json"],
                },
              ],
            }
          : {}),
      },
    },
    customValidationComplete,
  );
}

test.each(["missing", "incomplete"])(
  "custom discovery cannot authorize recovery with %s validation results",
  async (results) => {
    const f = await savedScan({ running: true, custom: true });
    await saveCompleteCheckpoint(f, false, false);
    if (results === "incomplete") {
      await mkdir(join(f.scanDir, "artifacts/custom-validation"), {
        recursive: true,
      });
      await writeFile(
        join(f.scanDir, "artifacts/custom-validation/results.json"),
        JSON.stringify({
          scanId: f.scanId,
          status: "incomplete",
          validations: [],
        }),
      );
    }
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Custom discovery did not return a pending-validation draft",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    let calls = 0;
    const outcome = await resume(f, () => {
      calls++;
      throw new Error("Unvalidated custom findings must not resume");
    });
    expect(outcome.code, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("--validation-prompt-file");
    expect(calls).toBe(0);
  },
);

test.each([false, true])(
  "later model checkpoint cannot reuse custom-validation authority (same bytes: %s)",
  async (sameBytes) => {
    const f = await savedScan({ running: true, custom: true });
    await saveCompleteCheckpoint(f);
    const accepted = (
      await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
    )["checkpoint"] as {
      sources: Array<{
        checkpointPath: string;
        acceptanceId: string;
        customValidationComplete: boolean;
      }>;
    };
    expect(accepted.sources[0]!.customValidationComplete).toBe(true);
    const snapshot = JSON.parse(
      await readFile(
        join(f.scanDir, accepted.sources[0]!.checkpointPath),
        "utf8",
      ),
    );
    expect(snapshot).not.toHaveProperty("customValidationComplete");
    if (!sameBytes) snapshot.findings[0].title = "A later unvalidated finding";
    await f.checkpoint(f.scanDir, f.scanId, snapshot);
    const latest = (
      await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
    )["checkpoint"] as typeof accepted;
    expect(latest.sources[0]!.acceptanceId).not.toBe(
      accepted.sources[0]!.acceptanceId,
    );
    expect(latest.sources[0]!.customValidationComplete).toBe(false);
    let calls = 0;
    const outcome = await resume(f, () => {
      calls++;
      throw new Error(
        "A newer unvalidated checkpoint needs the original instructions",
      );
    });
    expect(outcome.code, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("--validation-prompt-file");
    expect(calls).toBe(0);
  },
);

test.each(["available", "exhausted", "unknown"] as const)(
  "receipt recovery continues in one command only when the saved budget permits (%s)",
  async (budget) => {
    const f = await savedScan({
      running: true,
      maxCostUsd: budget === "exhausted" ? 10 : 100,
    });
    await saveCompleteCheckpoint(f, true);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic interruption before receipt write",
      ...(budget === "unknown"
        ? []
        : ["--cost-json", JSON.stringify(previousCost)]),
    ]);
    if (budget === "unknown") await rm(f.sessionPath);
    let modelCalls = 0;
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        modelCalls++;
        const scanDir = threadOptions.workingDirectory!;
        const scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        const threadId = randomUUID();
        return {
          id: threadId,
          async runStreamed() {
            const coverage = JSON.parse(
              await readFile(join(scanDir, "coverage.json"), "utf8"),
            );
            expect(coverage.completeness).toBe("partial");
            expect(coverage.surfaces[0].disposition).toBe("needs_follow_up");
            const receipt = "artifacts/review/never-written.json";
            await mkdir(join(scanDir, "artifacts", "review"), {
              recursive: true,
            });
            await writeFile(
              join(scanDir, receipt),
              "Completed validation evidence\n",
            );
            coverage.surfaces[0].disposition = "rejected";
            coverage.surfaces[0].receiptRefs = [receipt];
            await writeFile(
              join(scanDir, "coverage.json"),
              JSON.stringify(coverage),
            );
            await finishChild(f, scanDir, scanId);
            return { events: completedEvents(threadId) };
          },
        };
      },
      resumeThread() {
        throw new Error("A stopped parent uses a linked attempt");
      },
    }));
    if (budget === "available") {
      expect(outcome.code, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      expect(JSON.parse(outcome.stdout).cost.estimatedUsd).toBeGreaterThan(
        12.5,
      );
    } else {
      expect(outcome.code).not.toBe(0);
      expect(modelCalls).toBe(0);
      expect(outcome.stderr).toContain(
        budget === "unknown"
          ? "saved total cost limit cannot be enforced"
          : "reached its saved total cost limit",
      );
    }
  },
);

test("a hard-killed checkpoint-only continuation retains its inherited cost", async () => {
  const f = await savedScan({ running: true, maxCostUsd: 10 });
  await saveCompleteCheckpoint(f);
  await f.command([
    "fail-scan",
    "--scan-id",
    f.scanId,
    "--message",
    "Synthetic export failure after completed analysis",
    "--cost-json",
    JSON.stringify(previousCost),
  ]);
  const child = join(f.root, "interrupted-export");
  await mkdir(child, { mode: 0o700 });
  const registration = await f.command([
    "register-cli-scan",
    "--repository",
    f.repository,
    "--scan-dir",
    child,
    "--parent-scan-id",
    f.scanId,
    "--recipe-json",
    JSON.stringify(f.recipe),
  ]);
  const childId = registration["scanId"] as string;
  await f.command([
    "continue-scan-checkpoint",
    "--scan-id",
    childId,
    "--parent-scan-id",
    f.scanId,
    "--cost-json",
    JSON.stringify(previousCost),
  ]);
  // A hard kill leaves the seeded transaction but runs no completion or failure handler.
  const saved = await f.command(["get-cli-scan-resume", "--scan-id", childId]);
  expect(saved["completionReady"]).toBe(true);
  expect(saved["previousCost"]).toEqual(previousCost);
  expect(saved["inferenceStarted"]).toBe(false);
  expect(saved["cost"]).toBeUndefined();
  expect(saved["threadId"]).toBeNull();
  let modelCalls = 0;
  const outcome = await resume({ ...f, scanId: childId }, () => {
    modelCalls++;
    throw new Error("Saved source work needs no model call");
  });
  expect(outcome.code, outcome.stderr).toBe(0);
  expect(modelCalls).toBe(0);
  const result = JSON.parse(outcome.stdout);
  expect(result.cost).toEqual(previousCost);
  expect(
    (await f.command(["get-scan", "--scan-id", result.manifest.scan.id]))[
      "scan"
    ],
  ).toMatchObject({ cost: previousCost });
});

test("failed session registration and export retain locally resumable completed work", async () => {
  const f = await savedScan({ running: true });
  const source = (
    await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
  )["checkpoint"] as {
    sources: Array<{ findings: object[]; coverage: object }>;
  };
  const runtime = preparedRuntime(f.codexHome);
  runtime.persistentCredentialHome = true;
  runtime.plugin.version = JSON.parse(
    await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
  ).version;
  const directory = join(f.root, "initial-attempt");
  const threadId = randomUUID();
  const warnings: string[] = [];
  let scanId = "";
  let modelCalls = 0;
  const client = new TestClient(
    { codexOverrides: f.recipe.config },
    {
      environment: f.environment,
      prepareRuntime: async () => runtime,
      resolvePluginPython: async () => f.python,
      runWorkbench: async (options, args, input) => {
        if (args[0] === "set-scan-thread")
          throw new Error("Synthetic session registration failure");
        if (args[0] === "prepare-scan-completion")
          throw new Error("Synthetic final export failure");
        return runWorkbench(options, args, input);
      },
      createCodex: (options) => ({
        startThread() {
          scanId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
          return {
            id: threadId,
            async runStreamed() {
              modelCalls++;
              await writeFile(
                join(f.codexHome, "sessions", `rollout-${threadId}.jsonl`),
                JSON.stringify({
                  type: "session_meta",
                  payload: { id: threadId, cwd: directory },
                }) + "\n",
              );
              async function* events(): AsyncGenerator<ThreadEvent> {
                yield { type: "thread.started", thread_id: threadId };
                await f.checkpoint(directory, scanId, {
                  scanId,
                  complete: true,
                  findings: source.sources[0]!.findings,
                  coverage: {
                    ...source.sources[0]!.coverage,
                    completeness: "complete",
                    deferred: [],
                    reviewedFiles: ["pending.ts", "reviewed.ts"],
                  },
                });
                yield {
                  type: "turn.completed",
                  usage: {
                    input_tokens: 1000,
                    cached_input_tokens: 0,
                    cache_write_input_tokens: 0,
                    output_tokens: 50,
                    reasoning_output_tokens: 0,
                  },
                };
              }
              return { events: events() };
            },
          };
        },
      }),
    },
  );
  try {
    await expect(
      client.run(f.repository, {
        outputDir: directory,
        maxCostUsd: 100,
        onWarning: (warning) => warnings.push(warning),
      }),
    ).rejects.toThrow("Synthetic final export failure");
  } finally {
    await client.close();
  }
  expect(
    warnings.some((warning) =>
      warning.includes("Synthetic session registration failure"),
    ),
  ).toBe(true);
  const saved = await f.command(["get-cli-scan-resume", "--scan-id", scanId]);
  expect(saved).toMatchObject({
    threadId: null,
    sourceThreadId: null,
    completionReady: true,
  });
  expect(saved["cost"]).toMatchObject({ inputTokens: 1000, outputTokens: 50 });
  const outcome = await resume({ ...f, scanId }, () => {
    modelCalls++;
    throw new Error("Completed analysis must not run again");
  });
  expect(outcome.code, outcome.stderr).toBe(0);
  expect(modelCalls).toBe(1);
  const result = JSON.parse(outcome.stdout);
  expect(result.threadId).toBe(threadId);
  expect(result.cost).toEqual(saved["cost"]);
});

test.each(["missing", "ambiguous"])(
  "completed checkpoint does not repeat inference with %s native identity",
  async (identity) => {
    const f = await savedScan({
      running: true,
      registerThread: false,
      maxCostUsd: 10,
    });
    await saveCompleteCheckpoint(f);
    if (identity === "missing") await rm(f.sessionPath);
    else
      await writeFile(
        join(f.codexHome, "sessions", "rollout-another.jsonl"),
        JSON.stringify({
          type: "session_meta",
          payload: { id: randomUUID(), cwd: f.scanDir },
        }) + "\n",
      );
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export failure",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    let modelCalls = 0;
    const outcome = await resume(f, () => {
      modelCalls++;
      throw new Error("Completed analysis must not run again");
    });
    expect(outcome.code).toBe(2);
    expect(outcome.stderr).toContain(
      "session identity for this completed scan is missing or ambiguous",
    );
    expect(modelCalls).toBe(0);
  },
);

test.each([false, true])(
  "completed checkpoint recovers its native thread after missing registration (custom: %s)",
  async (custom) => {
    const f = await savedScan({
      running: true,
      maxCostUsd: 10,
      custom,
      registerThread: false,
    });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export failure after completed analysis",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    const saved = await f.command([
      "get-cli-scan-resume",
      "--scan-id",
      f.scanId,
    ]);
    expect(saved).toMatchObject({
      threadId: null,
      sourceThreadId: null,
      completionReady: true,
      cost: previousCost,
    });
    let modelCalls = 0;
    const outcome = await resume(f, () => {
      modelCalls++;
      throw new Error("Completed analysis must not run again");
    });
    expect(outcome.code, outcome.stderr).toBe(0);
    expect(modelCalls).toBe(0);
    const result = JSON.parse(outcome.stdout);
    expect(result.threadId).toBe(f.threadId);
    expect(result.cost).toEqual(previousCost);
    expect(result.coverage.completeness).toBe("complete");
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({ continuationThreadId: f.threadId });
  },
);

test.each([false, true])(
  "a complete Standard checkpoint retries final export without another model call or cost (custom: %s)",
  async (custom) => {
    const f = await savedScan({ running: true, maxCostUsd: 10, custom });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export failure after completed analysis",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    // Native logs are unnecessary when analysis and spend are already durable.
    await rm(join(f.codexHome, "sessions"), { recursive: true });
    await writeFile(
      join(f.codexHome, "sessions"),
      "Unavailable native history\n",
    );
    const parent = await readFile(
      join(f.scanDir, "scan-manifest.json"),
      "utf8",
    );
    let modelCalls = 0;
    const noModel = () => {
      modelCalls++;
      throw new Error("No Codex client is needed to finish saved results");
    };
    const failedExport = await resume(f, noModel, { failExport: true });
    expect(failedExport.code).not.toBe(0);
    expect(failedExport.stderr).toContain("Synthetic local export failure");
    const scans = (
      await f.command(["list-scans", "--repository", f.repository])
    )["scans"] as Array<{ scanId: string; parentScanId: string }>;
    const failedChild = scans.find((scan) => scan.parentScanId === f.scanId)!;
    const childContext = await f.command([
      "get-cli-scan-resume",
      "--scan-id",
      failedChild.scanId,
    ]);
    expect(childContext["checkpoint"]).toMatchObject({
      sources: [expect.objectContaining({ customValidationComplete: custom })],
    });
    const outcome = await resume({ ...f, scanId: failedChild.scanId }, noModel);
    expect(outcome.code, outcome.stderr).toBe(0);
    expect(modelCalls).toBe(0);
    expect(outcome.stderr).toContain("without another model call");
    expect(await readFile(join(f.scanDir, "scan-manifest.json"), "utf8")).toBe(
      parent,
    );
    const result = JSON.parse(outcome.stdout);
    expect(result.cost).toEqual(previousCost);
    expect(result.threadId).toBe(f.threadId);
    expect(result.coverage.completeness).toBe("complete");
    expect(result.findings.findings).toHaveLength(1);
  },
);

test.each([false, true])(
  "checkpoint-only completion keeps explicit and latest CLI logs (retried export: %s)",
  async (retryExport) => {
    const f = await savedScan({ maxCostUsd: 10 });
    await saveCompleteCheckpoint(f);
    const event = {
      type: "event_msg",
      payload: { type: "agent_message", message: "Saved source analysis" },
    };
    await appendFile(f.sessionPath, JSON.stringify(event) + "\n");
    const originalLog = await readFile(f.sessionPath, "utf8");
    const noModel = () => {
      throw new Error("Completed source work must not run inference");
    };
    let parentId = f.scanId;
    if (retryExport) {
      const interrupted = await resume(f, noModel, { failExport: true });
      expect(interrupted.code).toBe(2);
      const scans = (
        await f.command(["list-scans", "--repository", f.repository])
      )["scans"] as Array<{ scanId: string; parentScanId: string }>;
      parentId = scans.find((scan) => scan.parentScanId === f.scanId)!.scanId;
    }
    const outcome = await resume({ ...f, scanId: parentId }, noModel);
    expect(outcome.code, outcome.stderr).toBe(0);
    const result = JSON.parse(outcome.stdout);
    const childId = result.manifest.scan.id;
    expect(result.threadId).toBe(f.threadId);
    expect(result.cost).toEqual(previousCost);
    for (const args of [
      ["scans", "logs", childId, "--json"],
      ["scans", "logs", "--json"],
    ]) {
      const stdout = capture();
      const stderr = capture();
      const code = await main(args, stdout.stream, stderr.stream, {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.repository,
        }),
        runWorkbench: f.command,
      });
      expect(code, stderr.text()).toBe(0);
      expect(JSON.parse(stdout.text())).toMatchObject({
        scanId: childId,
        threadId: f.threadId,
        sessions: [{ threadId: f.threadId, path: f.sessionPath }],
        events: [{ threadId: f.threadId }, { threadId: f.threadId, event }],
      });
    }
    expect(
      (await f.command(["get-scan", "--scan-id", childId]))["scan"],
    ).toMatchObject({
      parentScanId: parentId,
      continuationThreadId: null,
      cost: previousCost,
    });
    const database = await f.command(["database-info"]);
    expect(
      execFileSync(
        f.python,
        [
          "-c",
          "import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); print(db.execute('SELECT inference_started FROM scans WHERE id = ?', (sys.argv[2],)).fetchone()[0])",
          database["databasePath"] as string,
          childId,
        ],
        { encoding: "utf8" },
      ).trim(),
    ).toBe("0");
    expect(await readFile(f.sessionPath, "utf8")).toBe(originalLog);
  },
);

test.each(["prepare-scan-completion", "complete-scan"])(
  "checkpoint-only resume reports source changes before %s",
  async (command) => {
    const f = await savedScan({ running: true });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic interruption after completed source review",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    let modelCalls = 0;
    const outcome = await resume(
      f,
      () => {
        modelCalls++;
        throw new Error("Saved source work needs no model call");
      },
      {
        beforeWorkbench: async (args) => {
          if (args[0] === command)
            await writeFile(
              join(f.repository, "pending.ts"),
              "export const pending = false;\n",
            );
        },
      },
    );
    expect(outcome.code, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("Scan target changed during execution");
    expect(modelCalls).toBe(0);
    const result = JSON.parse(outcome.stdout);
    expect(result.cost).toEqual(previousCost);
    expect(result.findings.findings).toHaveLength(1);
    expect(result.coverage.completeness).toBe("complete");
  },
);

test.each([false, true])(
  "completed checkpoint runs only its saved post-scan instructions (custom: %s)",
  async (custom) => {
    const postScanPrompt = "Write the requested follow-up note.";
    const f = await savedScan({
      running: true,
      custom,
      postScanPrompt,
      maxCostUsd: 100,
    });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export interruption",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    const parent = await readFile(
      join(f.scanDir, "scan-manifest.json"),
      "utf8",
    );
    const prompts: string[] = [];
    let childDirectory = "";
    let childId = "";
    const threadId = randomUUID();
    const outcome = await resume(f, (options) => ({
      startThread(threadOptions) {
        childDirectory = threadOptions.workingDirectory!;
        childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
        return {
          id: threadId,
          async runStreamed(prompt) {
            prompts.push(prompt as string);
            expect(prompt).toBe(postScanPrompt);
            expect(
              (await f.command(["get-scan", "--scan-id", childId]))["scan"],
            ).toMatchObject({
              progress: { status: "complete" },
            });
            await writeFile(
              join(childDirectory, "follow-up.txt"),
              "Follow-up complete.\n",
            );
            return { events: completedEvents(threadId) };
          },
        };
      },
      resumeThread() {
        throw new Error("The follow-up must use the child directory");
      },
    }));
    expect(outcome.code, outcome.stderr).toBe(0);
    expect(prompts).toEqual([postScanPrompt]);
    expect(await readFile(join(childDirectory, "follow-up.txt"), "utf8")).toBe(
      "Follow-up complete.\n",
    );
    expect(await readFile(join(f.scanDir, "scan-manifest.json"), "utf8")).toBe(
      parent,
    );
    const result = JSON.parse(outcome.stdout);
    expect(result.findings.findings).toHaveLength(1);
    expect(result.cost.estimatedUsd).toBeGreaterThan(previousCost.estimatedUsd);
    expect(result.cost.inputTokens).toBe(previousCost.inputTokens + 10);
    expect(
      (await f.command(["get-scan", "--scan-id", childId]))["scan"],
    ).toMatchObject({
      continuationThreadId: threadId,
      cost: result.cost,
      progress: { status: "complete" },
    });
  },
);

test("completed checkpoint follow-up persists an approved higher budget", async () => {
  const f = await savedScan({
    running: true,
    postScanPrompt: "Run the saved follow-up.",
    maxCostUsd: 15,
  });
  await saveCompleteCheckpoint(f);
  await f.command([
    "fail-scan",
    "--scan-id",
    f.scanId,
    "--message",
    "Synthetic export interruption",
    "--cost-json",
    JSON.stringify(previousCost),
  ]);
  const runtime = preparedRuntime(f.codexHome);
  runtime.plugin.version = JSON.parse(
    await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
  ).version;
  let tracker: ScanCostTracker;
  const start = ScanCostTracker.prototype.start;
  const startSpy = spyOn(ScanCostTracker.prototype, "start").mockImplementation(
    function (this: ScanCostTracker, id: string) {
      tracker = this;
      start.call(this, id);
    },
  );
  let approve!: () => void;
  const approved = new Promise<void>((resolve) => {
    approve = resolve;
  });
  const controller = new AbortController();
  const requests: number[] = [];
  const commands: string[] = [];
  const artifacts = new Map<string, string>();
  let childId = "";
  let childDirectory = "";
  const threadId = randomUUID();
  const client = new TestClient(
    { codexOverrides: f.recipe.config },
    {
      environment: f.environment,
      prepareRuntime: async () => runtime,
      resolvePluginPython: async () => f.python,
      runWorkbench: async (options, args, input) => {
        commands.push(args[0]!);
        return runWorkbench(options, args, input);
      },
      prepareScanArtifactRestorer,
      createCodex: (options) => ({
        startThread(threadOptions) {
          childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
          childDirectory = threadOptions.workingDirectory!;
          return {
            id: threadId,
            async runStreamed(prompt) {
              expect(prompt).toBe(f.recipe.postScanPrompt!);
              const saved = (
                await f.command(["get-scan", "--scan-id", childId])
              )["scan"];
              expect(saved).toMatchObject({ progress: { status: "complete" } });
              for (const name of [
                "scan-manifest.json",
                "findings.json",
                "coverage.json",
                "report.md",
              ])
                artifacts.set(
                  name,
                  await readFile(join(childDirectory, name), "utf8"),
                );
              async function* events(): AsyncGenerator<ThreadEvent> {
                yield { type: "thread.started", thread_id: threadId };
                tracker.recordUsage({ input_tokens: 1_000, output_tokens: 0 });
                await tracker.refresh();
                const timer = setTimeout(
                  () =>
                    controller.abort(
                      new Error("Budget approval was not applied"),
                    ),
                  15_000,
                );
                try {
                  await Promise.race([
                    approved,
                    new Promise<never>((_resolve, reject) => {
                      controller.signal.addEventListener(
                        "abort",
                        () => reject(controller.signal.reason),
                        { once: true },
                      );
                    }),
                  ]);
                } finally {
                  clearTimeout(timer);
                }
                const usage = {
                  input_tokens: 1_000_000,
                  cached_input_tokens: 0,
                  cache_write_input_tokens: 0,
                  output_tokens: 0,
                  reasoning_output_tokens: 0,
                };
                tracker.recordUsage(usage);
                await tracker.refresh();
                yield { type: "turn.completed", usage };
              }
              return { events: events() };
            },
          };
        },
      }),
    },
  );
  try {
    const result = await client
      .run(f.repository, {
        continuationScanId: f.scanId,
        parentScanId: f.scanId,
        maxCostUsd: f.recipe.maxCostUsd,
        postScanPrompt: f.recipe.postScanPrompt,
        signal: controller.signal,
        onBudgetApproaching: ({ maxCostUsd }) => {
          requests.push(maxCostUsd);
          return 30;
        },
        onCost: (_cost, limit) => {
          if (limit === 30) approve();
        },
      })
      .catch((error: Error) => error);
    expect(requests).toEqual([15]);
    if (result instanceof Error) throw result;
    expect(result.cost!.estimatedUsd).toBeGreaterThan(15);
    expect(result.cost!.estimatedUsd).toBeLessThan(30);
    expect(
      (await f.command(["get-scan-recipe", "--scan-id", childId]))["recipe"],
    ).toMatchObject({ maxCostUsd: 30 });
    expect(
      (await f.command(["get-scan", "--scan-id", childId]))["scan"],
    ).toMatchObject({ progress: { status: "complete" }, cost: result.cost });
    expect(commands).toContain("set-scan-cost-limit");
    expect(commands).not.toContain("fail-scan");
    expect(commands).not.toContain("complete-budget-exhausted-scan");
    for (const [name, contents] of artifacts)
      expect(await readFile(join(childDirectory, name), "utf8")).toBe(contents);
  } finally {
    await client.close();
    startSpy.mockRestore();
  }
});

test("completed checkpoint preserves sealed results when its optional follow-up changes an artifact", async () => {
  const f = await savedScan({
    running: true,
    postScanPrompt: "Write a follow-up.",
    maxCostUsd: 100,
  });
  await saveCompleteCheckpoint(f);
  await f.command([
    "fail-scan",
    "--scan-id",
    f.scanId,
    "--message",
    "Synthetic export interruption",
    "--cost-json",
    JSON.stringify(previousCost),
  ]);
  let childId = "";
  let childDirectory = "";
  let manifest = "";
  let findings = "";
  const threadId = randomUUID();
  const outcome = await resume(f, (options) => ({
    startThread(threadOptions) {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      childDirectory = threadOptions.workingDirectory!;
      return {
        id: threadId,
        async runStreamed(prompt) {
          expect(prompt).toBe(f.recipe.postScanPrompt!);
          manifest = await readFile(
            join(childDirectory, "scan-manifest.json"),
            "utf8",
          );
          findings = await readFile(
            join(childDirectory, "findings.json"),
            "utf8",
          );
          await writeFile(join(childDirectory, "findings.json"), "{}\n");
          return { events: completedEvents(threadId) };
        },
      };
    },
  }));
  expect(outcome.code, outcome.stderr).toBe(0);
  expect(outcome.stderr).toContain("Could not run post-scan instructions:");
  expect(
    await readFile(join(childDirectory, "scan-manifest.json"), "utf8"),
  ).toBe(manifest);
  expect(await readFile(join(childDirectory, "findings.json"), "utf8")).toBe(
    findings,
  );
  expect(
    (await f.command(["get-scan", "--scan-id", childId]))["scan"],
  ).toMatchObject({
    progress: { status: "complete" },
    cost: { inputTokens: previousCost.inputTokens + 10 },
  });
});

test.each(["exhausted", "unknown"] as const)(
  "completed checkpoint refuses a follow-up without a usable saved budget (%s)",
  async (budget) => {
    const f = await savedScan({
      running: true,
      postScanPrompt: "Run the saved follow-up.",
      maxCostUsd: budget === "exhausted" ? 10 : 100,
    });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export interruption",
      ...(budget === "unknown"
        ? []
        : ["--cost-json", JSON.stringify(previousCost)]),
    ]);
    if (budget === "unknown") await rm(f.sessionPath);
    let calls = 0;
    const outcome = await resume(f, () => {
      calls++;
      throw new Error("No budget remains for the follow-up");
    });
    expect(outcome.code).toBe(2);
    expect(calls).toBe(0);
    expect(outcome.stderr).toContain(
      budget === "unknown"
        ? "cost is unavailable"
        : "reached its saved total cost limit",
    );
  },
);

test("completed checkpoint retains follow-up cost when the total reaches its saved limit", async () => {
  const f = await savedScan({
    running: true,
    postScanPrompt: "Run the saved follow-up.",
    maxCostUsd: previousCost.estimatedUsd + 0.000001,
  });
  await saveCompleteCheckpoint(f);
  await f.command([
    "fail-scan",
    "--scan-id",
    f.scanId,
    "--message",
    "Synthetic export interruption",
    "--cost-json",
    JSON.stringify(previousCost),
  ]);
  let childId = "";
  const threadId = randomUUID();
  const outcome = await resume(f, (options) => ({
    startThread() {
      childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
      return {
        id: threadId,
        async runStreamed() {
          return { events: completedEvents(threadId) };
        },
      };
    },
  }));
  expect(outcome.code, outcome.stderr).toBe(2);
  expect(outcome.stderr).toContain("exceeded the");
  const child = (await f.command(["get-scan", "--scan-id", childId]))[
    "scan"
  ] as {
    cost: { estimatedUsd: number; inputTokens: number };
    progress: { status: string };
  };
  expect(child.progress.status).toBe("complete");
  expect(child.cost.estimatedUsd).toBeGreaterThan(f.recipe.maxCostUsd!);
  expect(child.cost.inputTokens).toBe(previousCost.inputTokens + 10);
});

test.each(["budget", "abort", "close"] as const)(
  "completed checkpoint restores sealed artifacts before follow-up cancellation (%s)",
  async (cancellation) => {
    const f = await savedScan({
      running: true,
      postScanPrompt: "Run the saved follow-up.",
      maxCostUsd:
        cancellation === "budget" ? previousCost.estimatedUsd + 0.000001 : 100,
    });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export interruption",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    const runtime = preparedRuntime(f.codexHome);
    runtime.plugin.version = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
    ).version;
    let tracker: ScanCostTracker;
    const start = ScanCostTracker.prototype.start;
    const startSpy = spyOn(
      ScanCostTracker.prototype,
      "start",
    ).mockImplementation(function (this: ScanCostTracker, id: string) {
      tracker = this;
      start.call(this, id);
    });
    const controller = new AbortController();
    const warnings: string[] = [];
    const artifacts = new Map<string, Buffer>();
    const usage = {
      input_tokens: 1000,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 50,
      reasoning_output_tokens: 0,
    };
    let closing: Promise<void> | undefined;
    let childId = "";
    let childDirectory = "";
    const threadId = randomUUID();
    const client = new TestClient(
      { codexOverrides: f.recipe.config },
      {
        environment: f.environment,
        prepareRuntime: async () => runtime,
        resolvePluginPython: async () => f.python,
        runWorkbench,
        prepareScanArtifactRestorer,
        createCodex: (options) => ({
          startThread(threadOptions) {
            childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
            childDirectory = threadOptions.workingDirectory!;
            return {
              id: threadId,
              async runStreamed(prompt) {
                expect(prompt).toBe(f.recipe.postScanPrompt!);
                const manifest = JSON.parse(
                  await readFile(
                    join(childDirectory, "scan-manifest.json"),
                    "utf8",
                  ),
                );
                for (const name of new Set([
                  "scan-manifest.json",
                  "findings.json",
                  "coverage.json",
                  "report.md",
                  ...manifest.scan.artifacts.map(
                    (artifact: { path: string }) => artifact.path,
                  ),
                ]))
                  artifacts.set(
                    name,
                    await readFile(join(childDirectory, name)),
                  );
                async function* events(): AsyncGenerator<ThreadEvent> {
                  yield { type: "thread.started", thread_id: threadId };
                  await writeFile(
                    join(childDirectory, "findings.json"),
                    "{}\n",
                  );
                  await writeFile(
                    join(childDirectory, "report.md"),
                    "Incomplete follow-up\n",
                  );
                  tracker.recordUsage(usage);
                  await tracker.refresh();
                  if (cancellation === "abort")
                    controller.abort(new Error("Stop the follow-up"));
                  if (cancellation === "close") closing = client.close();
                  yield { type: "turn.completed", usage };
                }
                return { events: events() };
              },
            };
          },
        }),
      },
    );
    try {
      const outcome = await client
        .run(f.repository, {
          continuationScanId: f.scanId,
          parentScanId: f.scanId,
          maxCostUsd: f.recipe.maxCostUsd,
          postScanPrompt: f.recipe.postScanPrompt,
          signal: controller.signal,
          onWarning: (warning) => {
            warnings.push(warning);
          },
        })
        .then(
          () => undefined,
          (error: unknown) => error,
        );
      await closing;
      if (cancellation === "budget")
        expect(outcome).toBeInstanceOf(ScanCostLimitExceededError);
      else if (cancellation === "abort")
        expect(outcome).toBeInstanceOf(ScanInterruptedError);
      else expect((outcome as Error).message).toBe("CodexSecurity is closed.");
      expect(artifacts.size).toBeGreaterThan(3);
      for (const [name, contents] of artifacts)
        expect(
          (await readFile(join(childDirectory, name))).equals(contents),
          name,
        ).toBe(true);
      await loadContract(childDirectory, {
        pluginRoot: PLUGIN_ROOT,
        expectedScanId: childId,
      });
      expect(
        (await f.command(["get-scan", "--scan-id", childId]))["scan"],
      ).toMatchObject({
        progress: { status: "complete" },
        cost: {
          inputTokens: previousCost.inputTokens + usage.input_tokens,
          outputTokens: previousCost.outputTokens + usage.output_tokens,
        },
      });
      expect(
        warnings.some((warning) =>
          warning.includes("Could not save post-scan cost"),
        ),
      ).toBe(false);
    } finally {
      await client.close();
      startSpy.mockRestore();
    }
  },
);

test.each(["prepare", "restorer"] as const)(
  "completed checkpoint records no inference before a local %s failure",
  async (phase) => {
    const f = await savedScan({
      running: true,
      postScanPrompt: "Run the saved follow-up.",
      maxCostUsd: 100,
    });
    await saveCompleteCheckpoint(f);
    await f.command([
      "fail-scan",
      "--scan-id",
      f.scanId,
      "--message",
      "Synthetic export interruption",
      "--cost-json",
      JSON.stringify(previousCost),
    ]);
    let childId = "";
    let calls = 0;
    const outcome = await resume(
      f,
      (options) => ({
        startThread() {
          childId = options.env!["CODEX_SECURITY_SCAN_ID"]!;
          return {
            id: randomUUID(),
            async runStreamed() {
              calls++;
              throw new Error("Unpaid setup must not dispatch a follow-up");
            },
          };
        },
      }),
      { failExport: phase === "prepare", failRestorer: phase === "restorer" },
    );
    expect(outcome.code).toBe(phase === "prepare" ? 2 : 0);
    expect(outcome.stderr).toContain(
      phase === "prepare"
        ? "Synthetic local export failure"
        : "Synthetic restorer setup failure",
    );
    expect(calls).toBe(0);
    const database = await f.command(["database-info"]);
    const started = execFileSync(
      f.python,
      [
        "-c",
        "import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); print(db.execute('SELECT inference_started FROM scans WHERE id = ?', (sys.argv[2],)).fetchone()[0])",
        database["databasePath"] as string,
        childId,
      ],
      { encoding: "utf8" },
    );
    expect(started.trim()).toBe("0");
    expect(
      (await f.command(["get-scan", "--scan-id", childId]))["scan"],
    ).toMatchObject({ cost: previousCost });
  },
);
