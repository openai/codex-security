import { randomUUID } from "node:crypto";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, spyOn, test } from "bun:test";
import type { CodexOptions, ThreadOptions } from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import { CodexSecurity, type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import {
  prepareScanArtifactRestorer,
  runWorkbench,
  type WorkbenchCommandOptions,
} from "../src/runtime.js";
import { prepareSemanticScanDraft } from "../src/scan-semantics.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { ScanInterruptedError } from "../src/errors.js";
import {
  DeepScanPublicationError,
  DeepScanRecoveryError,
  ScanCostTrackingError,
} from "../src/deep-scan.js";
import { loadDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";
import { DeepScanProgressTracker } from "../src/deep-progress.js";
import { semanticCoverage, semanticFinding } from "./helpers/semantic-scan.js";
import { createApiTestFixtures } from "./support/api-events.js";
import { tokenUsageEvent } from "./support/usage-rollout.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const usage = { input_tokens: 10, cached_input_tokens: 0, output_tokens: 3 };
const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function fixture(
  partialCheckpoint?: "active" | "completed",
  native = false,
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const home = join(root, "home");
  let outputDir = join(root, "scan");
  const knowledgePath = join(root, "context.md");
  await mkdir(repository);
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(repository, "source.ts"), "export const value = 1;\n");
  await writeFile(knowledgePath, "Original immutable context");
  await writeFile(join(home, "config.toml"), 'model = "gpt-6-astra"\n');
  const version = JSON.parse(
    await readFile(join(pluginRoot, ".codex-plugin/plugin.json"), "utf8"),
  ).version;
  const environment = {
    ...process.env,
    CODEX_HOME: home,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    OPENAI_API_KEY: "synthetic-test-key",
    SYNTHETIC_SETTING: "captured",
  };
  const records = new Map<
    string,
    {
      registration: JsonObject;
      options: WorkbenchCommandOptions;
      mode: string;
      recipe: JsonObject;
    }
  >();
  const launches: Array<{
    runOptions?: { signal?: AbortSignal; outputSchema?: unknown };
    options: CodexOptions;
    threadOptions: ThreadOptions;
    knowledge?: string;
    preflightConfig: JsonObject;
  }> = [];
  const threadScans = new Map<string, string>();
  const completedPrompts: string[] = [];
  const commands: string[] = [];
  const parentPhases: unknown[] = [];
  let preparations = 0;
  const controller = new AbortController();
  let stopAfterSealing: "deep" | "standard" | undefined;
  let stopCommand = "complete-scan";
  let publicationFails = false;
  let stopAfterChildRegistration = false;
  let childRetirementFails = false;
  let finalPublicationFailure:
    "prepare-scan-completion" | "complete-scan" | undefined;
  let childProjectionFails = false;
  let runMustNotStart = false;
  let repositoryFindings: JsonObject[] | undefined;
  let budgetCrashPlugin: string | undefined;
  let interruptedPublication: "draft" | "receipt" | "budget" | undefined;
  let interruptPlugin: string;
  let publicationFailure: unknown;
  const cancellation = new Error("synthetic foreground cancellation");
  const interruptPublication = async (options: WorkbenchCommandOptions) => {
    expect(options.signal).toBeUndefined();
    interruptedPublication = undefined;
    controller.abort(cancellation);
    // The CLI handler aborts the scan while the foreground process group also
    // delivers SIGINT to its signal-free publication subprocess.
    try {
      return await runWorkbench({ ...options, pluginRoot: interruptPlugin }, [
        "get-scan",
      ]);
    } catch (error) {
      publicationFailure = error;
      throw error;
    }
  };
  let resumedChildFails = false;
  let reducerFailure: Error | undefined;
  let mergeDuplicates = false;
  let afterParentFailure: (() => Promise<void>) | undefined;
  let afterParentCompletion: (() => Promise<void>) | undefined;
  let firstChild: string | undefined;
  let firstChildEmpty = false;
  let firstChildCompleted:
    ReturnType<typeof Promise.withResolvers<void>> | undefined;
  const makeClient = (
    overrides: JsonObject = {},
    sourcePluginRoot = pluginRoot,
  ) =>
    new CodexSecurity(
      {
        pluginPath: sourcePluginRoot,
        codexOverrides: {
          model: "gpt-6-astra",
          model_reasoning_effort: "high",
          mcp_servers: {
            "codex-security": { command: "synthetic-workbench", enabled: true },
            "synthetic.server": { command: "synthetic-command" },
          },
          ...overrides,
        },
      },
      {
        environment,
        inheritedPermissions: {
          filesystem: { [join(root, "private")]: "deny" },
          network: { enabled: false },
        },
        prepareRuntime: async () => {
          preparations++;
          return {
            codexHome: home,
            configPath: join(root, "config-preflight.toml"),
            preserveCodexHomeConfig: true,
            persistentCredentialHome: true,
            credentialsAvailable: true,
            environment,
            plugin: {
              pluginRoot: sourcePluginRoot,
              installedRoot: pluginRoot,
              marketplaceRoot: pluginRoot,
              marketplaceName: "codex-security-sdk",
              name: "codex-security",
              version,
            },
          };
        },
        resolvePluginPython: async () => Bun.which("python3")!,
        prepareScanArtifactRestorer: async (options, directory) => {
          const writer = await prepareScanArtifactRestorer(options, directory);
          return {
            ...writer,
            async projectChild(
              ...args: Parameters<typeof writer.projectChild>
            ) {
              if (childProjectionFails)
                throw new Error("Synthetic child projection unavailable");
              return await writer.projectChild(...args);
            },
            async restore(path, contents) {
              if (
                interruptedPublication === "receipt" &&
                path === "artifacts/deep-scan/checkpoint.json" &&
                Object.hasOwn(
                  JSON.parse(Buffer.from(contents).toString()),
                  "finalCost",
                )
              )
                await interruptPublication(options);
              return await writer.restore(path, contents);
            },
          };
        },
        runWorkbench: async (options, args, input) => {
          commands.push(args[0]!);
          if (
            childRetirementFails &&
            args[0] === "fail-scan" &&
            records.get(args[2]!)?.mode === "standard"
          )
            throw new Error("Synthetic transient child retirement failure");
          if (
            args[0] === finalPublicationFailure &&
            records.get(args[2]!)?.mode === "deep"
          ) {
            finalPublicationFailure = undefined;
            throw new Error("Synthetic transient final publication failure");
          }
          if (
            (interruptedPublication === "draft" &&
              args[0] === "write-scan-draft" &&
              records.get(args[2]!)?.mode === "deep") ||
            (interruptedPublication === "budget" &&
              args[0] === "complete-budget-exhausted-scan")
          )
            return await interruptPublication(options);
          if (
            budgetCrashPlugin &&
            args[0] === "complete-budget-exhausted-scan"
          ) {
            return await runWorkbench(
              { ...options, pluginRoot: budgetCrashPlugin },
              args,
              input,
            );
          }
          if (args[0] === "list-global-findings" && repositoryFindings)
            return { findings: repositoryFindings };
          if (
            stopAfterSealing &&
            args[0] === stopCommand &&
            records.get(args[2]!)?.mode === stopAfterSealing
          ) {
            stopAfterSealing = undefined;
            controller.abort(
              new ScanTransportClosedError(
                "Synthetic process stop during completion",
              ),
            );
            throw controller.signal.reason;
          }
          if (
            publicationFails &&
            args[0] === "write-scan-draft" &&
            records.get(args[2]!)?.mode === "deep"
          )
            throw new Error("Synthetic publication failure");
          const result = await runWorkbench(options, args, input);
          if (
            args[0] === "complete-scan" &&
            records.get(args[2]!)?.mode === "deep" &&
            afterParentCompletion
          ) {
            const afterCompletion = afterParentCompletion;
            afterParentCompletion = undefined;
            await afterCompletion();
          }
          if (args[0] === "complete-scan" && args[2] === firstChild)
            firstChildCompleted?.resolve();
          if (args[0] === "fail-scan" && records.get(args[2]!)?.mode === "deep")
            await afterParentFailure?.();
          if (args[0] === "get-cli-scan-resume") {
            const record = records.get(result["scanId"] as string);
            if (record) record.options = options;
          }
          if (args[0] === "register-cli-scan") {
            const recipe = JSON.parse(input!).recipe;
            const mode = recipe.mode;
            records.set(result["scanId"] as string, {
              registration: result,
              options,
              mode,
              recipe,
            });
            if (mode === "standard") {
              const parent = [...records].find(
                ([, record]) => record.mode === "deep",
              );
              if (parent) {
                const saved = await runWorkbench(
                  { ...parent[1].options, signal: undefined },
                  ["get-scan", "--scan-id", parent[0]],
                );
                parentPhases.push((saved["scan"] as JsonObject)["progress"]);
              }
            }
            if (mode === "deep") {
              await writeFile(knowledgePath, "Changed after registration");
              environment.SYNTHETIC_SETTING = "later value";
            }
          }
          if (
            stopAfterChildRegistration &&
            args[0] === "register-cli-scan" &&
            records.get(result["scanId"] as string)?.mode === "standard"
          ) {
            stopAfterChildRegistration = false;
            controller.abort(
              new ScanTransportClosedError(
                "Synthetic process stop after child registration",
              ),
            );
            throw controller.signal.reason;
          }
          return result;
        },
        createCodex: (options) => {
          if (runMustNotStart)
            throw new Error("A sealed result must not prepare a Codex client");
          const makeThread = (
            threadOptions: ThreadOptions,
            resumed: string | null = null,
          ) => {
            let matchingDecision: unknown;
            const thread = {
              id: resumed,
              async runStreamed(
                prompt: string,
                runOptions?: { signal?: AbortSignal; outputSchema?: unknown },
              ) {
                const turnUsage =
                  resumed === null
                    ? usage
                    : {
                        input_tokens: usage.input_tokens * 2,
                        cached_input_tokens: usage.cached_input_tokens * 2,
                        output_tokens: usage.output_tokens * 2,
                      };
                const env = options.env!;
                const scanId = env["CODEX_SECURITY_SCAN_ID"]!;
                const record = records.get(scanId)!;
                const knowledge = env["CODEX_SECURITY_KNOWLEDGE_BASE"];
                const preflightConfig = parseToml(
                  await readFile(env["CODEX_SECURITY_CONFIG_PATH"]!, "utf8"),
                ) as JsonObject;
                launches.push({
                  runOptions,
                  options,
                  threadOptions,
                  knowledge,
                  preflightConfig,
                });
                if (knowledge)
                  expect(
                    await readFile(join(knowledge, "0-context.md.txt"), "utf8"),
                  ).toBe("Original immutable context");
                async function* events() {
                  if (firstChildCompleted && record.mode === "standard") {
                    firstChild ??= scanId;
                    if (scanId !== firstChild)
                      await firstChildCompleted.promise;
                  }
                  runOptions?.signal?.throwIfAborted();
                  thread.id ??= randomUUID();
                  threadScans.set(thread.id, scanId);
                  await mkdir(join(home, "sessions"), { recursive: true });
                  await appendFile(
                    join(home, "sessions", `rollout-${thread.id}.jsonl`),
                    JSON.stringify({
                      type: "session_meta",
                      payload: {
                        id: thread.id,
                        timestamp: new Date().toISOString(),
                        cwd: threadOptions.workingDirectory,
                      },
                    }) + "\n",
                  );
                  yield { type: "thread.started", thread_id: thread.id };
                  if (record.mode === "standard") {
                    const draft = {
                      scanId,
                      ...(partialCheckpoint ? { complete: false } : {}),
                      findings:
                        firstChildEmpty && scanId === firstChild
                          ? []
                          : [
                              semanticFinding({
                                ...(scanId === firstChild
                                  ? { title: "First completed discovery" }
                                  : {}),
                                locations: [
                                  { path: "source.ts", startLine: 1 },
                                ],
                              }),
                            ],
                      coverage: semanticCoverage(
                        partialCheckpoint
                          ? {
                              completeness: "partial",
                              deferred: [
                                {
                                  id: "pending-candidate",
                                  candidateId: "pending-candidate",
                                  reason:
                                    "Independent source validation is pending.",
                                  candidate: {
                                    title: "Pending source review",
                                    evidence: "Synthetic saved evidence",
                                  },
                                },
                              ],
                            }
                          : {},
                      ),
                    };
                    const documents = prepareSemanticScanDraft(
                      {
                        targetContract: record.registration[
                          "contract"
                        ] as JsonObject,
                        mode: "standard",
                        targetRevision: record.registration[
                          "targetRevision"
                        ] as string,
                      },
                      draft,
                    );
                    if (partialCheckpoint) {
                      for (const [name, value] of Object.entries({
                        "scan-manifest.json": documents.manifest,
                        "findings.json": documents.findings,
                        "coverage.json": documents.coverage,
                      }))
                        await writeFile(
                          join(env["CODEX_SECURITY_SCAN_DIR"]!, name),
                          JSON.stringify(value),
                        );
                      await appendFile(
                        join(home, "sessions", `rollout-${thread.id}.jsonl`),
                        JSON.stringify(tokenUsageEvent(turnUsage)) + "\n",
                      );
                      if (partialCheckpoint === "completed") {
                        try {
                          yield { type: "turn.completed", usage: turnUsage };
                        } finally {
                          controller.abort(cancellation);
                        }
                        return;
                      }
                      controller.abort(cancellation);
                      throw cancellation;
                    }
                    await runWorkbench(
                      record.options,
                      ["write-scan-draft", "--scan-id", scanId],
                      JSON.stringify({ documents, checkpoint: draft }),
                    );
                  }
                  let response = "Completed";
                  if (
                    record.mode === "deep" &&
                    !prompt.endsWith("Write follow-up notes")
                  ) {
                    if (reducerFailure) throw reducerFailure;
                    if (prompt.startsWith("Compare every finding")) {
                      const { findings } = JSON.parse(
                        prompt.split("\n").at(-1)!,
                      );
                      matchingDecision = {
                        matches: mergeDuplicates
                          ? [
                              {
                                beforeOccurrenceIds: findings.before.map(
                                  (finding: { occurrenceId: string }) =>
                                    finding.occurrenceId,
                                ),
                                afterOccurrenceIds: findings.after.map(
                                  (finding: { occurrenceId: string }) =>
                                    finding.occurrenceId,
                                ),
                                confidence: "high",
                                reason:
                                  "Both synthetic observations describe the same correction.",
                              },
                            ]
                          : [],
                        uncertain: [],
                        related: [],
                        request: null,
                      };
                    }
                    response = JSON.stringify(matchingDecision);
                  }
                  yield {
                    type: "item.completed",
                    item: {
                      type: "agent_message",
                      id: "response",
                      text: response,
                    },
                  };
                  await appendFile(
                    join(home, "sessions", `rollout-${thread.id}.jsonl`),
                    JSON.stringify(tokenUsageEvent(turnUsage)) + "\n",
                  );
                  if (
                    resumedChildFails &&
                    resumed !== null &&
                    record.mode === "standard"
                  )
                    throw new Error(
                      "Synthetic resumed child execution failure",
                    );
                  completedPrompts.push(prompt);
                  yield {
                    type: "turn.completed",
                    usage: turnUsage,
                  };
                }
                return { events: events() };
              },
            };
            return thread;
          };
          return {
            startThread: (options) => makeThread(options),
            resumeThread: (id, options) => makeThread(options, id),
          };
        },
      },
      { surface: "sdk" },
    );
  let registeredScan: ScanOptions["registeredScan"];
  if (native) {
    const started = await runWorkbench(
      { python: Bun.which("python3")!, pluginRoot, environment },
      [
        "begin-deep-scan",
        "--thread-id",
        "native-owner",
        "--target-path",
        repository,
        "--scan-root",
        join(root, "native-scans"),
      ],
    );
    const scan = started["scan"] as JsonObject;
    outputDir = scan["scanDir"] as string;
    registeredScan = {
      scanId: scan["scanId"] as string,
      scanDir: outputDir,
      threadId: "native-owner",
      handoffClaimToken: scan["handoffClaimToken"] as string,
    };
  }
  const options: ScanOptions = {
    ...(registeredScan === undefined ? {} : { registeredScan }),
    outputDir,
    signal: controller.signal,
    mode: "deep",
    knowledgeBasePaths: [knowledgePath],
    workers: 2,
    subagents: 3,
    maxDiscoveryRuns: 2,
    maxTimeHours: 1,
    stopAfterNoNew: 3,
    stopAfterConsecutiveErrors: 2,
    onWarning() {},
  };
  return {
    root,
    home,
    repository,
    outputDir,
    knowledgePath,
    options,
    records,
    launches,
    threadScans,
    completedPrompts,
    commands,
    parentPhases,
    makeClient,
    preparations: () => preparations,
    stopAfterChildRegistration() {
      stopAfterChildRegistration = true;
    },
    failChildRetirement(value: boolean) {
      childRetirementFails = value;
    },
    stopAfterSealing(mode: "deep" | "standard" = "deep") {
      stopAfterSealing = mode;
    },
    stopBeforeSealing(mode: "deep" | "standard" = "standard") {
      stopAfterSealing = mode;
      stopCommand = "prepare-scan-completion";
    },
    stopBeforeBudgetCompletion() {
      stopAfterSealing = "deep";
      stopCommand = "complete-budget-exhausted-scan";
    },
    failPublication(value: boolean) {
      publicationFails = value;
    },
    failFinalPublication(command: NonNullable<typeof finalPublicationFailure>) {
      finalPublicationFailure = command;
    },
    failChildProjection(value: boolean) {
      childProjectionFails = value;
    },
    afterCompletion(callback: () => Promise<void>) {
      afterParentCompletion = callback;
    },
    cancellation,
    publicationFailure: () => publicationFailure,
    async interruptPublication(stage: typeof interruptedPublication) {
      interruptedPublication = stage;
      interruptPlugin = join(root, "interrupted-publication-plugin");
      await mkdir(join(interruptPlugin, "scripts"), { recursive: true });
      await writeFile(
        join(interruptPlugin, "scripts/workbench_db.py"),
        "import signal\nsignal.raise_signal(signal.SIGINT)\n",
      );
    },
    forbidCodex() {
      runMustNotStart = true;
    },
    setRepositoryFindings(findings: JsonObject[]) {
      repositoryFindings = findings;
    },
    async stopBudgetAfterSealing() {
      budgetCrashPlugin = join(root, "budget-crash-plugin");
      await mkdir(join(budgetCrashPlugin, "scripts"), { recursive: true });
      await writeFile(
        join(budgetCrashPlugin, "scripts/workbench_db.py"),
        `import os, sys
sys.path.insert(0, ${JSON.stringify(join(pluginRoot, "scripts"))})
import workbench_db as db
original = db._write_prepared_scan_finalization
def stop_after_sealing(*args, **kwargs):
    original(*args, **kwargs)
    os._exit(73)
db._write_prepared_scan_finalization = stop_after_sealing
db.main()
`,
      );
    },
    restoreWorkbench() {
      budgetCrashPlugin = undefined;
    },
    failResumedChild() {
      resumedChildFails = true;
    },
    mergeDuplicates() {
      mergeDuplicates = true;
    },
    failReducer(error: Error, afterFailure: () => Promise<void>) {
      reducerFailure = error;
      afterParentFailure = afterFailure;
    },
    completeFirstChildBeforeSibling() {
      firstChildCompleted = Promise.withResolvers<void>();
    },
    makeFirstChildEmpty() {
      firstChildEmpty = true;
      firstChildCompleted = Promise.withResolvers<void>();
    },
  };
}

test.each(["active", "completed"] as const)(
  "cancellation retains file-authored discovery checkpoints (%s worker)",
  async (phase) => {
    const h = await fixture(phase);
    await using client = h.makeClient();
    await expect(
      client.run(h.repository, { ...h.options, workers: 1, maxCostUsd: 1 }),
    ).rejects.toBeInstanceOf(ScanInterruptedError);
    expect(h.launches).toHaveLength(1);
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "canceled",
    });
    const findings = JSON.parse(
      await readFile(join(h.outputDir, "findings.json"), "utf8"),
    );
    const coverage = JSON.parse(
      await readFile(join(h.outputDir, "coverage.json"), "utf8"),
    );
    expect(findings.findings).toHaveLength(1);
    expect(coverage.completeness).toBe("partial");
    expect(coverage.deferred).toContainEqual(
      expect.objectContaining({
        reason: "Independent source validation is pending.",
        sourceCandidateId: "pending-candidate",
        candidate: {
          title: "Pending source review",
          evidence: "Synthetic saved evidence",
        },
      }),
    );
    expect(h.commands).not.toContain("complete-scan");
    expect(h.commands).not.toContain("write-scan-draft");
    const child = [...h.records].find(
      ([, record]) => record.mode === "standard",
    )!;
    const receipt = await runWorkbench(
      { ...child[1].options, signal: undefined },
      ["get-scan", "--scan-id", child[0]],
    );
    expect((receipt["scan"] as JsonObject)["cost"]).toMatchObject(
      estimateScanCost("gpt-6-astra", usage)!,
    );
  },
);

test("ordinary children and reducer share one immutable preparation and knowledge directory", async () => {
  const h = await fixture();
  await using client = h.makeClient();
  const result = await client.run(h.repository, h.options);
  expect(h.preparations()).toBe(1);
  expect(h.launches).toHaveLength(3);
  expect(new Set(h.launches.map((launch) => launch.knowledge)).size).toBe(1);
  const workerConfig = {
    features: {
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 4,
      },
    },
  };
  for (const launch of h.launches) {
    expect(launch.options.env!["SYNTHETIC_SETTING"]).toBe("captured");
    expect(launch.preflightConfig).toMatchObject(workerConfig);
    expect(
      h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.recipe[
        "config"
      ],
    ).toMatchObject(workerConfig);
    expect(launch.options.config).toMatchObject({
      ...workerConfig,
      model: "gpt-6-astra",
      model_reasoning_effort: "high",
      mcp_servers: {
        "codex-security": { command: "node", enabled: false },
        "synthetic.server": { command: "synthetic-command" },
      },
      permissions: {
        codex_security_scan: {
          filesystem: {
            [join(h.root, "private")]: "deny",
            [launch.knowledge!]: "read",
          },
          network: { enabled: false },
        },
      },
    });
  }
  expect(result.findings.findings).toHaveLength(2);
  expect(h.parentPhases).toEqual([
    expect.objectContaining({ phase: "discovery" }),
    expect.objectContaining({ phase: "discovery" }),
  ]);
  expect(result.cost).not.toBeNull();
  expect(await readFile(join(h.home, "config.toml"), "utf8")).toBe(
    'model = "gpt-6-astra"\n',
  );
  expect(h.commands.filter((command) => command === "list-scans")).toHaveLength(
    1,
  );
});

test("a deterministic child receipt verifies the final cost without a reducer", async () => {
  const h = await fixture();
  const warnings: string[] = [];
  await using client = h.makeClient();
  const result = await client.run(h.repository, {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 1,
    maxCostUsd: 1,
    onWarning: (message) => warnings.push(message),
  });
  expect(h.launches).toHaveLength(1);
  expect(result.threadId).toBeNull();
  expect(result.findings.findings).toHaveLength(1);
  expect(result.cost).toEqual(estimateScanCost("gpt-6-astra", usage));
  expect(warnings).toEqual([]);
});

test("shared matching reads evidence through the prepared parent session", async () => {
  const h = await fixture();
  h.mergeDuplicates();
  await using client = h.makeClient();
  const result = await client.run(h.repository, h.options);
  expect(result.findings.findings).toHaveLength(1);
  expect(
    result.findings.findings[0]!.provenance["sourceFindings"],
  ).toHaveLength(2);
  const parentTurns = h.launches.filter(
    (launch) =>
      h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
      "deep",
  );
  expect(parentTurns).toHaveLength(2);
  expect(h.preparations()).toBe(1);
  expect(h.threadScans.size).toBe(3);
  for (const turn of parentTurns) {
    expect(turn.options.config).toMatchObject({
      model: "gpt-6-astra",
      model_reasoning_effort: "high",
      permissions: {
        codex_security_scan: {
          filesystem: { [join(h.root, "private")]: "deny" },
          network: { enabled: false },
        },
      },
    });
    expect(turn.runOptions?.signal).toBeInstanceOf(AbortSignal);
    expect(turn.runOptions?.outputSchema).toMatchObject({
      properties: { matches: { type: "array" }, request: expect.any(Object) },
    });
  }
  expect(
    h.completedPrompts.some((prompt) => prompt.includes('"content":')),
  ).toBe(true);
  expect(result.cost).not.toBeNull();
});

test("custom provider recipes preserve fresh and resumed discovery and reducer settings", async () => {
  const h = await fixture();
  const provider = {
    name: "Synthetic custom provider",
    base_url: "https://provider.example.test/v1",
    wire_api: "responses",
    env_http_headers: { "X-Synthetic": "SYNTHETIC_SETTING" },
    request_max_retries: 7,
    auth: {
      command: "synthetic-auth",
      args: ["session"],
      refresh_interval_ms: 1000,
    },
  };
  h.stopBeforeSealing();
  await using first = h.makeClient({
    profile: "selected",
    profiles: { selected: { model_provider: "synthetic" } },
    model_providers: {
      synthetic: {
        ...provider,
        experimental_bearer_token: "synthetic-private-bearer",
        http_headers: { Authorization: "Bearer synthetic-private-header" },
      },
    },
  });
  const options = {
    ...h.options,
    workers: 1,
    knowledgeBasePaths: undefined,
  };
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan-recipe",
    "--scan-id",
    parentId,
  ]);
  const config = (saved["recipe"] as JsonObject)["config"] as JsonObject;
  const replayProvider = {
    ...provider,
    auth: { ...provider.auth, cwd: h.home },
  };
  expect(config["model_providers"]).toEqual({ synthetic: replayProvider });
  expect(JSON.stringify(saved)).not.toContain("synthetic-private-");
  await using resumed = h.makeClient(config);
  const result = await resumed.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(result.findings.findings).toHaveLength(2);
  expect(h.launches[0]!.options.env!["CODEX_SECURITY_SCAN_ID"]).toBe(
    h.launches[1]!.options.env!["CODEX_SECURITY_SCAN_ID"],
  );
  expect(
    h.launches.some(
      (launch) =>
        h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
        "deep",
    ),
  ).toBe(true);
  for (const launch of h.launches) {
    expect(launch.options.config).toMatchObject({
      model_provider: "synthetic",
      model_providers: { synthetic: replayProvider },
    });
    expect(launch.preflightConfig).not.toHaveProperty("model_providers");
  }
});

test("a reused client's sealed read uses its installed plugin after the source is removed", async () => {
  const h = await fixture();
  const source = join(h.root, "plugin-source");
  await cp(pluginRoot, source, { recursive: true });
  await using client = h.makeClient({}, source);
  const options = { ...h.options, knowledgeBasePaths: undefined };
  h.stopAfterSealing();
  await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const findings = JSON.parse(
    await readFile(join(h.outputDir, "findings.json"), "utf8"),
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  await rm(source, { recursive: true });
  h.forbidCodex();
  const restored = await client.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(restored.findings).toEqual(findings);
  expect(h.launches).toHaveLength(3);
});

test("a sealed resume does not construct a model client or launch new work", async () => {
  const h = await fixture();
  h.stopAfterSealing();
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(ScanTransportClosedError);
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const findings = JSON.parse(
    await readFile(join(h.outputDir, "findings.json"), "utf8"),
  );
  const priorFinding = {
    findingId: "prior-open-issue",
    title: "Earlier issue",
    status: "open",
    confirmedInLatestScan: false,
  };
  h.setRepositoryFindings([priorFinding]);
  h.forbidCodex();
  await using resumed = h.makeClient();
  const restored = await resumed.run(h.repository, {
    ...h.options,
    signal: undefined,
    knowledgeBasePaths: undefined,
    resumeScanId: parentId,
  });
  expect(restored.findings).toEqual(findings);
  expect(restored.repositoryFindings).toMatchObject([priorFinding]);
  expect(h.launches).toHaveLength(3);
});

test("zero-work Deep Scan preserves a zero receipt across interrupted sealing", async () => {
  const h = await fixture();
  const options = {
    ...h.options,
    maxTimeHours: 1e-12,
    maxCostUsd: 1,
    knowledgeBasePaths: undefined,
  };
  h.stopAfterSealing();
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  const zeroCost = estimateScanCost("gpt-6-astra", {
    input_tokens: 0,
    output_tokens: 0,
  });
  expect(checkpoint.passes).toEqual([]);
  expect(checkpoint.mergeStarted).toBeUndefined();
  expect(checkpoint.finalCost).toEqual(zeroCost);
  expect(h.launches).toHaveLength(0);
  h.forbidCodex();
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(result.cost).toEqual(zeroCost);
  expect(result.findings.findings).toEqual([]);
  expect(result.coverage.completeness).toBe("partial");
  expect(h.launches).toHaveLength(0);
});

async function interruptedSealedChild() {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  const options = {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 3,
    knowledgeBasePaths: undefined,
    maxCostUsd: passCost.estimatedUsd * 1.5,
  };
  h.stopAfterSealing("standard");
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const [childId, childRecord] = [...h.records].find(
    ([, record]) => record.mode === "standard",
  )!;
  const saved = await runWorkbench(
    { ...childRecord.options, signal: undefined },
    ["get-scan", "--scan-id", childId],
  );
  const child = saved["scan"] as JsonObject;
  expect(child["progress"]).toMatchObject({ status: "running" });
  expect(h.launches).toHaveLength(1);
  const childDirectory = childRecord.registration["scanDir"] as string;
  const manifest = JSON.parse(
    await readFile(join(childDirectory, "scan-manifest.json"), "utf8"),
  );
  expect(manifest.scan.status).toBe("completed");
  expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
  return {
    h,
    child,
    childId,
    childRecord,
    passCost,
    resumeOptions: { ...options, signal: undefined, resumeScanId: parentId },
  };
}

test.each(["live", "archived"])(
  "a sealed child resumes from %s session accounting and counts against the Deep Scan budget",
  async (storage) => {
    const { h, childId, childRecord, passCost, resumeOptions } =
      await interruptedSealedChild();
    if (storage === "archived")
      await rename(join(h.home, "sessions"), join(h.home, "archived_sessions"));
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, resumeOptions);
    const saved = await runWorkbench(
      { ...childRecord.options, signal: undefined },
      ["get-scan", "--scan-id", childId],
    );
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
    expect(saved["scan"]).toMatchObject({ cost: passCost });
    expect(h.launches).toHaveLength(2);
    expect(h.commands).toContain("complete-budget-exhausted-scan");
    expect(result.findings.findings).toHaveLength(2);
    expect(result.cost?.estimatedUsd).toBeCloseTo(
      passCost.estimatedUsd * 2,
      12,
    );
  },
);

test.each([
  ["sdk", false],
  ["native", false],
  ["native", true],
] as const)(
  "%s resume retains archived reducer subagent usage (budget: %p)",
  async (resume, budget) => {
    const h = await fixture(undefined, resume === "native");
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      ...(budget
        ? {
            maxCostUsd:
              estimateScanCost("gpt-6-astra", usage)!.estimatedUsd * 10,
          }
        : {}),
    };
    h.failPublication(true);
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      DeepScanPublicationError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const reducerThreadId = [...h.threadScans].find(
      ([, scanId]) => scanId === parentId,
    )![0];
    const archivedUsage = { input_tokens: 1000, output_tokens: 100 };
    await mkdir(join(h.home, "archived_sessions"));
    await writeFile(
      join(h.home, "archived_sessions", "reducer-subagent.jsonl"),
      [
        {
          type: "session_meta",
          payload: {
            id: "archived-reducer-subagent",
            cwd: join(h.outputDir, "artifacts", "deep-scan", "merge"),
            parent_thread_id: reducerThreadId,
            timestamp: new Date().toISOString(),
          },
        },
        tokenUsageEvent(archivedUsage),
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );
    h.failPublication(false);
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, {
      ...options,
      ...(resume === "native"
        ? { registeredScan: options.registeredScan! }
        : { resumeScanId: parentId }),
    });
    expect(result.cost).toMatchObject({
      inputTokens: usage.input_tokens * 3 + archivedUsage.input_tokens,
      outputTokens: usage.output_tokens * 3 + archivedUsage.output_tokens,
    });
    expect(result.cost?.estimatedUsd).toBeCloseTo(
      estimateScanCost("gpt-6-astra", {
        input_tokens: usage.input_tokens * 3 + archivedUsage.input_tokens,
        cached_input_tokens: 0,
        output_tokens: usage.output_tokens * 3 + archivedUsage.output_tokens,
      })!.estimatedUsd,
      12,
    );
    expect(h.launches).toHaveLength(3);
    if (budget) {
      expect(result.cost!.estimatedUsd).toBeGreaterThan(options.maxCostUsd!);
      expect(result.coverage.completeness).toBe("partial");
      expect(h.commands).toContain("complete-budget-exhausted-scan");
    }
    const completed = await runWorkbench(
      { ...parent.options, signal: undefined },
      ["get-scan", "--scan-id", parentId],
    );
    expect(completed["scan"]).toMatchObject({
      cost: result.cost,
      progress: { status: "complete" },
    });
  },
);

test("a sealed child without persisted usage rejects cost-limited Deep Scan resume", async () => {
  const { h, child, resumeOptions } = await interruptedSealedChild();
  const sessionPath = join(
    h.home,
    "sessions",
    `rollout-${child["continuationThreadId"]}.jsonl`,
  );
  const metadata = (await readFile(sessionPath, "utf8"))
    .split("\n")
    .filter((line) => line && JSON.parse(line).type === "session_meta");
  await writeFile(sessionPath, metadata.join("\n") + "\n");
  await using resumed = h.makeClient();
  await expect(resumed.run(h.repository, resumeOptions)).rejects.toBeInstanceOf(
    ScanCostTrackingError,
  );
  expect(h.launches).toHaveLength(1);
});

test("sealed recovery rejects a partial receipt when final accounting is unavailable", async () => {
  const h = await fixture();
  h.stopAfterSealing();
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(ScanTransportClosedError);
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const checkpointPath = join(
    h.outputDir,
    "artifacts/deep-scan/checkpoint.json",
  );
  const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
  expect(checkpoint.finalCost).not.toBeNull();
  delete checkpoint.finalCost;
  await writeFile(checkpointPath, JSON.stringify(checkpoint));
  h.forbidCodex();
  await using resumed = h.makeClient();
  await expect(
    resumed.run(h.repository, {
      ...h.options,
      signal: undefined,
      knowledgeBasePaths: undefined,
      resumeScanId: parentId,
      requireCost: true,
    }),
  ).rejects.toThrow("no verified cost receipt");
  expect(h.launches).toHaveLength(3);
});

test("accepted publication failure remains resumable without repeating child work", async () => {
  const h = await fixture();
  h.failPublication(true);
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(DeepScanPublicationError);
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  h.failPublication(false);
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...h.options,
    knowledgeBasePaths: undefined,
    resumeScanId: parentId,
  });
  expect(result.findings.findings).toHaveLength(2);
  expect(h.launches).toHaveLength(3);
});

test.each([
  { resumed: false, command: "prepare-scan-completion" },
  { resumed: true, command: "prepare-scan-completion" },
  { resumed: false, command: "complete-scan" },
  { resumed: true, command: "complete-scan" },
] as const)(
  "final Deep publication can retry accepted work (%p)",
  async ({ resumed, command }) => {
    const h = await fixture();
    const options = { ...h.options, knowledgeBasePaths: undefined };
    let resumeScanId: string | undefined;
    if (resumed) {
      h.stopBeforeSealing("deep");
      await using first = h.makeClient();
      await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      resumeScanId = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )![0];
    }

    h.failFinalPublication(command);
    await using interrupted = h.makeClient();
    const failure = await interrupted
      .run(h.repository, { ...options, signal: undefined, resumeScanId })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toContain(
      "Synthetic transient final publication failure",
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "running",
    });
    expect(failure).toBeInstanceOf(DeepScanPublicationError);
    expect(h.commands).not.toContain("fail-scan");
    const accepted = await loadDeepScanCheckpoint(h.outputDir);
    expect(accepted!.mergedScanIds).toHaveLength(2);
    expect(accepted!.aggregate!.findings).toHaveLength(2);
    expect(accepted!.finalCost).toBeDefined();
    expect(accepted!.finalCost).not.toBeNull();
    expect(h.launches).toHaveLength(3);
    const manifest = JSON.parse(
      await readFile(join(h.outputDir, "scan-manifest.json"), "utf8"),
    );
    if (command === "complete-scan") {
      expect(manifest.scan.sealedAt).toBeString();
      h.forbidCodex();
    } else {
      expect(manifest.scan.sealedAt).toBeUndefined();
    }

    await using retry = h.makeClient();
    const result = await retry.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    expect(result.findings.findings).toHaveLength(2);
    expect(result.cost).toEqual(accepted!.finalCost!);
    expect(h.launches).toHaveLength(3);
    const completed = await runWorkbench(
      { ...parent.options, signal: undefined },
      ["get-scan", "--scan-id", parentId],
    );
    expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
  },
);

test("lost final completion response preserves the completed Deep result", async () => {
  const h = await fixture();
  const artifacts = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const readArtifacts = () =>
    Promise.all(artifacts.map((name) => readFile(join(h.outputDir, name))));
  let sealedArtifacts: Awaited<ReturnType<typeof readArtifacts>> | undefined;
  h.afterCompletion(async () => {
    sealedArtifacts = await readArtifacts();
    throw new Error("Synthetic lost final completion response");
  });
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(DeepScanPublicationError);
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "complete",
  });
  expect(sealedArtifacts).toBeDefined();
  expect(
    JSON.parse(sealedArtifacts![0]!.toString()).scan.sealedAt,
  ).toBeString();
  expect(await readArtifacts()).toEqual(sealedArtifacts!);
  expect(h.commands).not.toContain("fail-scan");

  expect(h.launches).toHaveLength(3);
});

test("a resumed child projection failure keeps accepted work resumable", async () => {
  const h = await fixture();
  const options = { ...h.options, knowledgeBasePaths: undefined };
  h.failPublication(true);
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    DeepScanPublicationError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const accepted = await loadDeepScanCheckpoint(h.outputDir);
  expect(accepted!.mergedScanIds).toHaveLength(2);
  expect(h.launches).toHaveLength(3);

  h.failPublication(false);
  h.failChildProjection(true);
  await using interrupted = h.makeClient();
  await expect(
    interrupted.run(h.repository, { ...options, resumeScanId: parentId }),
  ).rejects.toBeInstanceOf(DeepScanRecoveryError);
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "running",
  });
  expect(h.commands).not.toContain("fail-scan");
  expect((await loadDeepScanCheckpoint(h.outputDir))!.mergedScanIds).toEqual(
    accepted!.mergedScanIds,
  );

  h.failChildProjection(false);
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    resumeScanId: parentId,
  });
  expect(result.findings.findings).toHaveLength(2);
  expect(h.launches).toHaveLength(3);
  const completed = await runWorkbench(
    { ...parent.options, signal: undefined },
    ["get-scan", "--scan-id", parentId],
  );
  expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "complete",
  });
});

test("publication recovery keeps verified cost when one child is empty", async () => {
  const h = await fixture();
  h.makeFirstChildEmpty();
  h.failPublication(true);
  const options = {
    ...h.options,
    knowledgeBasePaths: undefined,
    maxCostUsd: 1,
    requireCost: true,
  };
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    DeepScanPublicationError,
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const accepted = await loadDeepScanCheckpoint(h.outputDir);
  expect(accepted!.mergedScanIds).toHaveLength(2);
  expect(accepted!.aggregate!.findings).toHaveLength(1);
  expect(accepted!.mergeStarted).not.toBe(true);
  expect(h.launches).toHaveLength(2);
  expect(
    h.launches.every(
      (launch) =>
        h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
        "standard",
    ),
  ).toBe(true);

  h.failPublication(false);
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    resumeScanId: parentId,
  });
  expect(h.launches).toHaveLength(2);
  expect(result.threadId).toBeNull();
  expect(result.findings.findings).toHaveLength(1);
  expect(result.findings.findings[0]!.provenance["sourceFindings"]).toEqual(
    Object.entries(accepted!.aggregate!.sourceFindings).map(
      ([id, finding]) => ({
        id,
        finding,
      }),
    ),
  );
  expect(result.cost?.estimatedUsd).toBeCloseTo(
    estimateScanCost("gpt-6-astra", usage)!.estimatedUsd * 2,
    12,
  );
  const completed = await loadDeepScanCheckpoint(h.outputDir);
  expect(completed!.finalCost).toEqual(result.cost);
});

test.each([
  ["draft", false],
  ["receipt", false],
  ["receipt", true],
  ["budget", true],
] as const)(
  "foreground interruption during %s publication cancels retained output (budget: %p)",
  async (stage, budget) => {
    const h = await fixture();
    await h.interruptPublication(stage);
    await using client = h.makeClient();
    const failure = await client
      .run(h.repository, {
        ...h.options,
        knowledgeBasePaths: undefined,
        ...(budget
          ? {
              workers: 1,
              maxDiscoveryRuns: 3,
              maxCostUsd:
                estimateScanCost("gpt-6-astra", usage)!.estimatedUsd * 1.5,
            }
          : {}),
      })
      .then(
        () => null,
        (error: unknown) => error,
      );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "canceled",
    });
    expect(failure).toBeInstanceOf(ScanInterruptedError);
    expect(failure).not.toBeInstanceOf(DeepScanPublicationError);
    expect((failure as Error).cause).toBe(h.cancellation);
    expect(String(h.publicationFailure())).toContain("KeyboardInterrupt");
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.mergedScanIds.length).toBeGreaterThan(0);
    expect(h.launches).toHaveLength(budget ? 2 : 3);
    if (stage === "draft") expect(checkpoint.terminalReason).toBe("canceled");
  },
);

test.each([false, true])(
  "follow-up writes fresh output while sealed reports stay read-only (resumed: %p)",
  async (resumed) => {
    const h = await fixture();
    let resumeScanId: string | undefined;
    if (resumed) {
      h.stopAfterSealing();
      await using first = h.makeClient();
      await expect(first.run(h.repository, h.options)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      await writeFile(h.knowledgePath, "Original immutable context");
      resumeScanId = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )![0];
    }
    await using client = h.makeClient();
    await client.run(h.repository, {
      ...h.options,
      ...(resumed ? { resumeScanId, signal: undefined } : {}),
      postScanPrompt: "Write follow-up notes",
    });
    const followUp = h.launches.at(-1)!;
    const output = followUp.threadOptions.workingDirectory!;
    expect(dirname(output)).toBe(join(h.outputDir, "artifacts/follow-up"));
    expect(followUp.options.config).toMatchObject({
      permissions: {
        codex_security_scan: {
          filesystem: {
            [h.outputDir]: { ".": "read" },
            [output]: { ".": "write" },
            [join(h.root, "private")]: "deny",
          },
        },
      },
    });
    const parentId = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )![0];
    const record = h.records.get(parentId)!;
    const saved = await runWorkbench(record.options, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
  },
);

test("budget exhaustion seals accepted findings without a reducer session", async () => {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  await using client = h.makeClient();
  const result = await client.run(h.repository, {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 3,
    maxCostUsd: passCost.estimatedUsd * 1.5,
  });
  expect(h.launches).toHaveLength(2);
  expect(
    h.launches.every(
      (launch) =>
        h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
        "standard",
    ),
  ).toBe(true);
  expect(h.commands).toContain("complete-budget-exhausted-scan");
  expect(result.threadId).toBeNull();
  expect(result.findings.findings).toHaveLength(2);
  expect(result.coverage.completeness).toBe("partial");
  expect(result.cost).not.toBeNull();
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  expect(checkpoint.finalCost).toEqual(result.cost);
});

test("failure follow-up survives the parent's own failed-status transition", async () => {
  const h = await fixture();
  let tracker: DeepScanProgressTracker | undefined;
  const start = spyOn(
    DeepScanProgressTracker.prototype,
    "start",
  ).mockImplementation(function (this: DeepScanProgressTracker) {
    tracker = this;
  });
  const failure = new Error("Synthetic reducer failure");
  h.failReducer(failure, async () => {
    await tracker!.refresh();
  });
  try {
    await using client = h.makeClient();
    await expect(
      client.run(h.repository, {
        ...h.options,
        postScanPrompt: "Write follow-up notes",
      }),
    ).rejects.toBe(failure);
    expect(
      h.completedPrompts.some((prompt) =>
        prompt.endsWith("Write follow-up notes"),
      ),
    ).toBe(true);
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "failed",
    });
  } finally {
    start.mockRestore();
  }
});

test.each(["direct", "resumed"])(
  "first parallel batch budget recovery (%s) preserves completed discovery without a reducer",
  async (recovery) => {
    const h = await fixture();
    h.completeFirstChildBeforeSibling();
    const passCost = estimateScanCost("gpt-6-astra", usage)!;
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 2,
      maxDiscoveryRuns: 4,
      maxCostUsd: passCost.estimatedUsd * 1.5,
    };
    await using client = h.makeClient();
    let result;
    if (recovery === "resumed") {
      h.stopBeforeBudgetCompletion();
      await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      const [parentId, parent] = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )!;
      const interrupted = await runWorkbench(
        { ...parent.options, signal: undefined },
        ["get-scan", "--scan-id", parentId],
      );
      expect((interrupted["scan"] as JsonObject)["progress"]).toMatchObject({
        status: "running",
      });
      await expect(
        readFile(join(h.outputDir, "scan-manifest.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
      const receipt = JSON.parse(
        await readFile(
          join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
          "utf8",
        ),
      );
      expect(receipt.finalCost.estimatedUsd).toBeCloseTo(
        passCost.estimatedUsd * 2,
        12,
      );
      expect(h.launches).toHaveLength(2);
      await using resumed = h.makeClient();
      result = await resumed.run(h.repository, {
        ...options,
        signal: undefined,
        resumeScanId: parentId,
      });
    } else {
      result = await client.run(h.repository, options);
    }
    expect(h.launches).toHaveLength(2);
    expect(
      h.launches.every(
        (launch) =>
          h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!
            .mode === "standard",
      ),
    ).toBe(true);
    expect(result.threadId).toBeNull();
    expect(result.coverage.completeness).toBe("partial");
    expect(result.findings.findings).toContainEqual(
      expect.objectContaining({ title: "First completed discovery" }),
    );
    expect(result.cost?.estimatedUsd).toBeCloseTo(
      passCost.estimatedUsd * 2,
      12,
    );
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.finalCost).toEqual(result.cost);
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
  },
);

test("resumed reducer budget recovery includes completed child receipts before enforcing the saved limit", async () => {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  const options = {
    ...h.options,
    knowledgeBasePaths: undefined,
    maxCostUsd: passCost.estimatedUsd * 3.5,
  };
  h.stopBeforeSealing("deep");
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  const parentScan = saved["scan"] as JsonObject;
  expect(parentScan["progress"]).toMatchObject({ status: "running" });
  expect(h.launches).toHaveLength(3);
  for (const [childId, child] of h.records) {
    if (child.mode !== "standard") continue;
    const complete = await runWorkbench(
      { ...child.options, signal: undefined },
      ["get-scan", "--scan-id", childId],
    );
    expect(complete["scan"]).toMatchObject({
      cost: passCost,
      progress: { status: "complete" },
    });
    // A prior execution can have a different price for the same token counts.
    await runWorkbench({ ...child.options, signal: undefined }, [
      "complete-scan",
      "--scan-id",
      childId,
      "--cost-json",
      JSON.stringify({ ...passCost, estimatedUsd: passCost.estimatedUsd / 2 }),
    ]);
  }
  await appendFile(
    join(
      h.home,
      "sessions",
      `rollout-${parentScan["continuationThreadId"]}.jsonl`,
    ),
    JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: {
            input_tokens: usage.input_tokens * 4,
            cached_input_tokens: usage.cached_input_tokens * 4,
            output_tokens: usage.output_tokens * 4,
          },
        },
      },
    }) + "\n",
  );
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(h.launches).toHaveLength(3);
  expect(result.findings.findings).toHaveLength(2);
  expect(result.coverage.completeness).toBe("partial");
  const expectedCost = {
    ...estimateScanCost("gpt-6-astra", {
      input_tokens: usage.input_tokens * 6,
      cached_input_tokens: usage.cached_input_tokens * 6,
      output_tokens: usage.output_tokens * 6,
    })!,
    estimatedUsd: result.cost!.estimatedUsd,
  };
  expect(result.cost?.estimatedUsd).toBeCloseTo(passCost.estimatedUsd * 5, 12);
  expect(result.cost).toEqual(expectedCost);
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  expect(checkpoint.finalCost).toEqual(expectedCost);
  const complete = await runWorkbench(
    { ...parent.options, signal: undefined },
    ["get-scan", "--scan-id", parentId],
  );
  expect(complete["scan"]).toMatchObject({
    cost: expectedCost,
    progress: { status: "complete" },
  });
});

test("budget exhaustion resumes from its final receipt after sealing before database completion", async () => {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  await h.stopBudgetAfterSealing();
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 1,
      maxDiscoveryRuns: 3,
      maxCostUsd: passCost.estimatedUsd * 1.5,
    }),
  ).rejects.toBeInstanceOf(DeepScanPublicationError);
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "running",
  });
  const manifestPath = join(h.outputDir, "scan-manifest.json");
  const sealedManifest = await readFile(manifestPath, "utf8");
  const manifest = JSON.parse(sealedManifest);
  expect(manifest.scan.status).toBe("completed");
  expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  const expectedCost = estimateScanCost("gpt-6-astra", {
    input_tokens: usage.input_tokens * 2,
    cached_input_tokens: usage.cached_input_tokens * 2,
    output_tokens: usage.output_tokens * 2,
  });
  expect(checkpoint.finalCost).toEqual(expectedCost);
  expect(h.launches).toHaveLength(2);
  expect(parent.recipe["maxCostUsd"]).toBe(passCost.estimatedUsd * 1.5);

  h.restoreWorkbench();
  h.forbidCodex();
  await using resumed = h.makeClient();
  const restored = await resumed.run(h.repository, {
    ...h.options,
    signal: undefined,
    knowledgeBasePaths: undefined,
    resumeScanId: parentId,
    maxCostUsd: parent.recipe["maxCostUsd"] as number,
  });
  expect(restored.cost).toEqual(expectedCost);
  expect(restored.findings.findings).toHaveLength(2);
  expect(restored.coverage.completeness).toBe("partial");
  expect(await readFile(manifestPath, "utf8")).toBe(sealedManifest);
  expect(h.launches).toHaveLength(2);
  const completed = await runWorkbench(
    { ...parent.options, signal: undefined },
    ["get-scan", "--scan-id", parentId],
  );
  expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "complete",
  });
});

function unavailableFinalCost(
  h: Awaited<ReturnType<typeof fixture>>,
  mode: string,
) {
  const scans = new WeakMap<ScanCostTracker, string>();
  const start = ScanCostTracker.prototype.start;
  const stop = ScanCostTracker.prototype.stop;
  const startSpy = spyOn(ScanCostTracker.prototype, "start").mockImplementation(
    function (this: ScanCostTracker, threadId: string) {
      scans.set(this, h.threadScans.get(threadId)!);
      return start.call(this, threadId);
    },
  );
  const stopSpy = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
    async function (this: ScanCostTracker, fallbackUsage?: unknown) {
      const snapshot = await stop.call(this, fallbackUsage);
      return h.records.get(scans.get(this)!)?.mode === mode &&
        h.launches.length > 1
        ? { usage: null, cost: null }
        : snapshot;
    },
  );
  return {
    [Symbol.dispose]() {
      stopSpy.mockRestore();
      startSpy.mockRestore();
    },
  };
}

test.each(["standard", "deep"])(
  "budget exhaustion does not finalize an unavailable %s cost receipt",
  async (mode) => {
    const h = await fixture();
    using _failure = unavailableFinalCost(h, mode);
    const passCost = estimateScanCost("gpt-6-astra", usage)!;
    await using client = h.makeClient();
    await expect(
      client.run(h.repository, {
        ...h.options,
        workers: mode === "standard" ? 1 : 2,
        maxDiscoveryRuns: 3,
        maxCostUsd: passCost.estimatedUsd * (mode === "standard" ? 1.5 : 2.5),
      }),
    ).rejects.toBeInstanceOf(ScanCostTrackingError);
    expect(h.launches).toHaveLength(mode === "standard" ? 2 : 3);
    expect(h.commands).not.toContain("complete-budget-exhausted-scan");
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.finalCost).toBeUndefined();
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "failed",
    });
  },
);

test.each(["budget", "execution"])(
  "a resumed child with unavailable final usage cannot reuse its earlier cost receipt after %s failure",
  async (failure) => {
    const h = await fixture();
    const passCost = estimateScanCost("gpt-6-astra", usage)!;
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 1,
      maxDiscoveryRuns: 3,
      maxCostUsd: passCost.estimatedUsd * (failure === "budget" ? 1.5 : 10),
    };
    h.stopBeforeSealing();
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const [childId, child] = [...h.records].find(
      ([, record]) => record.mode === "standard",
    )!;
    const previous = await runWorkbench(
      { ...child.options, signal: undefined },
      ["get-scan", "--scan-id", childId],
    );
    expect(previous["scan"]).toMatchObject({
      cost: passCost,
      progress: { status: "running" },
    });
    const childManifest = JSON.parse(
      await readFile(
        join(child.registration["scanDir"] as string, "scan-manifest.json"),
        "utf8",
      ),
    );
    expect(childManifest.scan.sealedAt).toBeUndefined();

    if (failure === "execution") h.failResumedChild();
    using _failure = unavailableFinalCost(h, "standard");
    await using resumed = h.makeClient();
    let reportedCost = 0;
    await expect(
      resumed.run(h.repository, {
        ...options,
        signal: undefined,
        resumeScanId: parentId,
        onCost(cost) {
          reportedCost = Math.max(reportedCost, cost.estimatedUsd);
        },
      }),
    ).rejects.toBeInstanceOf(ScanCostTrackingError);
    expect(reportedCost).toBeCloseTo(passCost.estimatedUsd * 2, 12);
    expect(h.launches).toHaveLength(2);
    expect(h.records.size).toBe(2);
    expect(h.commands).not.toContain("complete-budget-exhausted-scan");
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.finalCost).toBeUndefined();
    expect(checkpoint.costUnavailable).toBe(true);
    const failed = await runWorkbench({ ...child.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      childId,
    ]);
    expect(failed["scan"]).toMatchObject({
      cost: estimateScanCost("gpt-6-astra", {
        input_tokens: usage.input_tokens * 2,
        cached_input_tokens: usage.cached_input_tokens * 2,
        output_tokens: usage.output_tokens * 2,
      }),
      progress: { status: "failed" },
    });
    const parentSaved = await runWorkbench(
      { ...parent.options, signal: undefined },
      ["get-scan", "--scan-id", parentId],
    );
    expect((parentSaved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "failed",
    });
  },
);

test("budgeted resume retries pending child retirement before rejecting unavailable cost", async () => {
  const h = await fixture();
  const options = {
    ...h.options,
    knowledgeBasePaths: undefined,
    workers: 1,
    maxCostUsd: 1,
  };
  h.stopAfterChildRegistration();
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const [childId, child] = [...h.records].find(
    ([, record]) => record.mode === "standard",
  )!;
  const readScan = async (id: string, record: typeof parent) =>
    (
      await runWorkbench({ ...record.options, signal: undefined }, [
        "get-scan",
        "--scan-id",
        id,
      ])
    )["scan"] as JsonObject;
  expect(await readScan(childId, child)).toMatchObject({
    progress: { status: "running" },
    continuationThreadId: null,
  });
  expect(h.launches).toHaveLength(0);
  h.failChildRetirement(true);
  await using interrupted = h.makeClient();
  const resumeOptions = {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  };
  await expect(
    interrupted.run(h.repository, resumeOptions),
  ).rejects.toBeInstanceOf(DeepScanRecoveryError);
  const checkpointPath = join(
    h.outputDir,
    "artifacts/deep-scan/checkpoint.json",
  );
  expect(JSON.parse(await readFile(checkpointPath, "utf8"))).toMatchObject({
    costUnavailable: true,
    pendingStop: { reason: "failed" },
  });
  for (const [id, record] of [
    [parentId, parent],
    [childId, child],
  ] as const)
    expect(await readScan(id, record)).toMatchObject({
      progress: { status: "running" },
    });

  h.failChildRetirement(false);
  await using resumed = h.makeClient();
  await expect(resumed.run(h.repository, resumeOptions)).rejects.toBeInstanceOf(
    ScanInterruptedError,
  );
  for (const [id, record] of [
    [parentId, parent],
    [childId, child],
  ] as const)
    expect(await readScan(id, record)).toMatchObject({
      progress: { status: "failed" },
    });
  const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
  expect(checkpoint).toMatchObject({
    costUnavailable: true,
    terminalReason: "failed",
  });
  expect(checkpoint.pendingStop).toBeUndefined();
  expect(checkpoint.finalCost).toBeUndefined();
  expect(h.launches).toHaveLength(0);
  expect(h.records.size).toBe(2);
  expect(h.commands).not.toContain("complete-budget-exhausted-scan");
});
