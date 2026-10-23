import { randomUUID } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "bun:test";
import type { CodexOptions, ThreadOptions } from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import { CodexSecurity, type ScanOptions } from "../../src/api.js";
import type { JsonObject } from "../../src/config.js";
import { definedEnvironment } from "../../src/execution-auth.js";
import {
  prepareScanArtifactRestorer,
  runWorkbench,
} from "../../src/runtime.js";
import { prepareSemanticScanDraft } from "../../src/scan-semantics.js";
import { ScanTransportClosedError } from "../../src/scan-execution.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../../src/thread-source.js";
import { semanticCoverage, semanticFinding } from "../helpers/semantic-scan.js";
import { createApiTestFixtures } from "./api-events.js";
import { tokenUsageEvent, writeSession } from "./usage-rollout.js";

export const pluginRoot = fileURLToPath(
  new URL("../../../../plugins/codex-security/", import.meta.url),
);
export const usage = {
  input_tokens: 10,
  cached_input_tokens: 0,
  output_tokens: 3,
};

export function createDeepApiFixtures() {
  const { temporaryDirectory, cleanup } = createApiTestFixtures();
  async function fixture(
    partialCheckpoint?: "active" | "completed",
    native = false,
    observeSubagents = false,
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
    const environment: Record<string, string> = {
      ...definedEnvironment(process.env),
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-test-key",
      SYNTHETIC_SETTING: "captured",
    };
    let runtimeEnvironment: Record<string, string> | undefined;
    const records = new Map<
      string,
      {
        registration: JsonObject;
        options: Parameters<typeof runWorkbench>[0];
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
    let launchObserver:
      ((launch: (typeof launches)[number]) => Promise<void>) | undefined;
    const threadScans = new Map<string, string>();
    const observedSubagents: Array<{ id: string; mode: string; path: string }> =
      [];
    const completedPrompts: string[] = [];
    const commands: string[] = [];
    const parentPhases: unknown[] = [];
    let preparations = 0;
    let reportedUsage: typeof usage & { reasoning_output_tokens?: number } =
      usage;
    const controller = new AbortController();
    let stopAfterSealing: "deep" | "standard" | undefined;
    let stopCommand = "complete-scan";
    let publicationFails = false;
    let stopAfterChildRegistration = false;
    let afterChildRegistration: (() => Promise<void>) | undefined;
    let checkpointObserver:
      ((checkpoint: JsonObject) => Promise<void>) | undefined;
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
    const interruptPublication = async (
      options: Parameters<typeof runWorkbench>[0],
    ) => {
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
              "codex-security": {
                command: "synthetic-workbench",
                enabled: true,
              },
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
              environment: runtimeEnvironment ?? environment,
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
            const writer = await prepareScanArtifactRestorer(
              options,
              directory,
            );
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
                await writer.restore(path, contents);
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
              args[0] === "save-scan-artifact" &&
              args[4] === "artifacts/deep-scan/checkpoint.json"
            )
              await checkpointObserver?.(JSON.parse(input!));
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
            if (
              args[0] === "fail-scan" &&
              records.get(args[2]!)?.mode === "deep"
            )
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
                const afterRegistration = afterChildRegistration;
                afterChildRegistration = undefined;
                await afterRegistration?.();
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
                environment["SYNTHETIC_SETTING"] = "later value";
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
              throw new Error(
                "A sealed result must not prepare a Codex client",
              );
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
                      ? reportedUsage
                      : {
                          ...reportedUsage,
                          input_tokens: reportedUsage.input_tokens * 2,
                          cached_input_tokens:
                            reportedUsage.cached_input_tokens * 2,
                          output_tokens: reportedUsage.output_tokens * 2,
                          ...(reportedUsage.reasoning_output_tokens ===
                          undefined
                            ? {}
                            : {
                                reasoning_output_tokens:
                                  reportedUsage.reasoning_output_tokens * 2,
                              }),
                        };
                  const env = options.env!;
                  const scanId = env["CODEX_SECURITY_SCAN_ID"]!;
                  const record = records.get(scanId)!;
                  if (record.mode === "deep") {
                    const saved = await runWorkbench(
                      { ...record.options, signal: undefined },
                      ["get-scan", "--scan-id", scanId],
                    );
                    parentPhases.push(
                      (saved["scan"] as JsonObject)["progress"],
                    );
                  }
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
                  await launchObserver?.(launches.at(-1)!);
                  if (knowledge)
                    expect(
                      await readFile(
                        join(knowledge, "0-context.md.txt"),
                        "utf8",
                      ),
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
                    if (observeSubagents) {
                      const subagentId = randomUUID();
                      const path = await writeSession(
                        home,
                        subagentId,
                        {},
                        {
                          parent: thread.id,
                          cwd: threadOptions.workingDirectory,
                        },
                      );
                      observedSubagents.push({
                        id: subagentId,
                        mode: record.mode,
                        path,
                      });
                    }
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
                      threadOptions.threadSource ===
                      CODEX_SECURITY_THREAD_SOURCES.suggestOwners
                    ) {
                      response = JSON.stringify({
                        identityIndex: -1,
                        reason: "Synthetic owner inference abstains.",
                        evidenceIds: [],
                      });
                    } else if (
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
      environment,
      setRuntimeEnvironment(value: Record<string, string>) {
        runtimeEnvironment = value;
      },
      repository,
      outputDir,
      knowledgePath,
      options,
      records,
      launches,
      observeLaunch(observer: NonNullable<typeof launchObserver>) {
        launchObserver = observer;
      },
      threadScans,
      observedSubagents,
      completedPrompts,
      commands,
      parentPhases,
      makeClient,
      preparations: () => preparations,
      setUsage(value: typeof reportedUsage) {
        reportedUsage = value;
      },
      stopAfterChildRegistration() {
        stopAfterChildRegistration = true;
      },
      afterChildRegistration(callback: () => Promise<void>) {
        afterChildRegistration = callback;
      },
      observeCheckpoint(observer: NonNullable<typeof checkpointObserver>) {
        checkpointObserver = observer;
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
      failFinalPublication(
        command: NonNullable<typeof finalPublicationFailure>,
      ) {
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
  return { fixture, cleanup };
}
