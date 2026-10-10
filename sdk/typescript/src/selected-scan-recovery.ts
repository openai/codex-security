import { mkdtemp, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import type { ScanOptions } from "./api.js";
import type { CodexSecurityConfig, JsonObject } from "./config.js";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "./config.js";
import type { ScanExpectation } from "./contract.js";
import { ScanCostTracker, type ScanCost } from "./cost.js";
import { resumeSelectedDeepScan } from "./deep-scan-finalization.js";
import {
  CodexSecurityError,
  ScanCostLimitExceededError,
  errorMessage,
} from "./errors.js";
import { isRecord } from "./record.js";
import {
  expandHome,
  cleanupSdkDirectory,
  canonicalConfigPath,
  codexSecurityCredentialHome,
  codexSecurityStateDirectory,
  pluginMetadata,
  requireOutputOutsideRepository,
  resolvePluginPath,
  resolvePluginPython,
  runWorkbench,
  validateOutputDir,
  type ProcessEnvironment,
  type WorkbenchCommandOptions,
} from "./runtime.js";
import { type ScanExecutionAttribution } from "./scan-sessions.js";
import {
  DiffTarget,
  enclosingGitWorktreeRoot,
  resolveRepositoryPath,
  type NormalizedTarget,
} from "./targets.js";
import type { TurnResultMetadata } from "./result.js";

/** Recover publication only when a saved selection outlived its startup inputs. */
export async function recoverSelectedScanStartup<T>(input: {
  repository: string;
  normalizedTarget?: NormalizedTarget;
  options: ScanOptions;
  config: CodexSecurityConfig;
  environment: ProcessEnvironment;
  signal: AbortSignal;
  startupError: unknown;
  workbench: typeof runWorkbench;
  python: typeof resolvePluginPython;
  warn: (message: string, details?: { kind: "target_changed" }) => void;
  registered: (
    scan: {
      scanId: string;
      scanDir: string;
      startedAt?: string;
    },
    command: WorkbenchCommandOptions,
    threadId: string,
  ) => void;
  cost: (cost: Readonly<ScanCost>) => void;
  collect: (context: {
    scanDir: string;
    threadId: string;
    pluginRoot: string;
    python: string;
    expectation: ScanExpectation;
    turnResult: TurnResultMetadata;
  }) => Promise<T>;
}): Promise<T | null> {
  const { options, signal } = input;
  if (
    options.resumeScanId === undefined ||
    options.mode !== "deep" ||
    !options.outputDir ||
    options.archiveExisting ||
    options.parentScanId !== undefined ||
    options.workflowId !== undefined ||
    options.mock
  )
    return null;
  signal.throwIfAborted();
  const repository = resolveRepositoryPath(input.repository);
  const boundRepository = await realpath(repository).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return repository;
      throw error;
    },
  );
  const protectedRoot =
    (await enclosingGitWorktreeRoot(boundRepository, signal)) ??
    boundRepository;
  const scanDir = await validateOutputDir(options.outputDir, true);
  if (scanDir === null) return null;
  requireOutputOutsideRepository(protectedRoot, scanDir);
  const temporaryRoot = await realpath(tmpdir());
  requireOutputOutsideRepository(protectedRoot, temporaryRoot, "temporary");
  const workspace = await mkdtemp(
    join(temporaryRoot, "codex-security-recovery-"),
  );
  try {
    const pluginRoot = await resolvePluginPath(
      input.config.pluginPath,
      workspace,
      signal,
    );
    const plugin = await pluginMetadata(pluginRoot);
    const python = await input.python({
      configuredPath: input.config.pythonPath,
      environment: input.environment,
      protectedRoot,
      signal,
    });
    const stateDirectory = codexSecurityStateDirectory(input.environment);
    requireOutputOutsideRepository(
      protectedRoot,
      await canonicalConfigPath(stateDirectory),
    );
    const command: WorkbenchCommandOptions = {
      python,
      pluginRoot,
      protectedRoot,
      signal,
      environment: {
        ...input.environment,
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      },
    };
    const saved = await input.workbench(command, [
      "get-cli-scan-resume",
      "--scan-id",
      options.resumeScanId,
    ]);
    if (saved["selectedFinalization"] !== true) return null;
    const recipe = saved["recipe"];
    const target = isRecord(recipe) ? recipe["target"] : null;
    const threadId = saved["threadId"];
    if (
      saved["scanId"] !== options.resumeScanId ||
      saved["scanDir"] !== scanDir ||
      !isRecord(recipe) ||
      recipe["repository"] !== boundRepository ||
      !isRecord(target) ||
      typeof threadId !== "string" ||
      !threadId ||
      typeof saved["targetRevision"] !== "string"
    ) {
      throw new CodexSecurityError(
        "The workbench returned mismatched scan resume context.",
      );
    }
    // Match the caller's saved scope without consulting files that publication no longer reads.
    const requested = options.target ?? "repository";
    const paths = Array.isArray(requested)
      ? [
          ...new Set(
            requested.map(
              (path) =>
                relative(
                  boundRepository,
                  resolve(boundRepository, expandHome(path)),
                )
                  .split(sep)
                  .join("/") || ".",
            ),
          ),
        ]
      : [];
    const matches =
      input.normalizedTarget !== undefined
        ? JSON.stringify(input.normalizedTarget) === JSON.stringify(target)
        : requested === "repository"
          ? target["kind"] === "repository"
          : requested instanceof DiffTarget
            ? target["kind"] === requested.kind &&
              [target["base"], target["baseRef"]].includes(requested.base) &&
              (requested.kind === "working_tree" ||
                [target["head"], target["headRef"]].includes(requested.head))
            : Array.isArray(requested) &&
              target["kind"] === "paths" &&
              JSON.stringify(paths) === JSON.stringify(target["paths"]);
    if (!matches)
      throw new CodexSecurityError(
        "The workbench returned mismatched scan resume context.",
      );
    if (
      options.expectedPluginVersion !== undefined &&
      options.expectedPluginVersion !== plugin.version
    )
      throw new CodexSecurityError(
        "The selected plugin version does not match the expected plugin version.",
      );
    const deep = await input.workbench(command, [
      "get-deep-scan",
      "--scan-id",
      options.resumeScanId,
      "--thread-id",
      threadId,
    ]);
    const run = deep["deepScan"];
    if (
      !isRecord(run) ||
      !isRecord(run["finalizationInput"]) ||
      !["running", "succeeded"].includes(String(run["status"]))
    )
      throw new CodexSecurityError(
        "The saved Deep Scan selection is unavailable.",
      );
    const model = scanModelConfiguration({
      ...DEFAULT_CODEX_CONFIG,
      ...(isRecord(recipe["config"]) ? (recipe["config"] as JsonObject) : {}),
    }).model;
    input.registered(
      {
        scanId: options.resumeScanId,
        scanDir,
        ...(typeof saved["startedAt"] === "string"
          ? { startedAt: saved["startedAt"] }
          : {}),
      },
      command,
      threadId,
    );
    let lowerBound: Readonly<ScanCost> | null = null;
    const tracker = new ScanCostTracker({
      codexHome: codexSecurityCredentialHome(input.environment),
      model,
      scanDirectory: scanDir,
      ...(options.maxCostUsd === undefined
        ? {}
        : {
            onCostLowerBound: (cost: Readonly<ScanCost>) => {
              lowerBound = cost;
            },
          }),
    });
    tracker.setAttributionReader(async () => {
      const context = await input.workbench(command, [
        "get-scan",
        "--scan-id",
        options.resumeScanId!,
      ]);
      const scan = context["scan"];
      return isRecord(scan) && isRecord(scan["executionAttribution"])
        ? (scan["executionAttribution"] as unknown as ScanExecutionAttribution)
        : undefined;
    });
    tracker.start(threadId);
    const snapshot = await tracker.stop().catch((error: unknown) => {
      if (options.maxCostUsd !== undefined) throw error;
      input.warn(`Could not track scan cost: ${errorMessage(error)}`);
      return { usage: null, cost: null };
    });
    signal.throwIfAborted();
    if (snapshot.cost !== null) input.cost(snapshot.cost);
    await resumeSelectedDeepScan({
      scanId: options.resumeScanId,
      threadId,
      pluginRoot,
      signal,
      runWorkbench: (args) => input.workbench(command, args),
    });
    const budgetCost = snapshot.cost ?? lowerBound;
    const budgetError =
      options.maxCostUsd !== undefined &&
      budgetCost !== null &&
      budgetCost.estimatedUsd > options.maxCostUsd
        ? new ScanCostLimitExceededError(
            options.maxCostUsd,
            budgetCost,
            scanDir,
          )
        : null;
    const completionArgs =
      budgetError === null
        ? [
            "complete-scan",
            "--scan-id",
            options.resumeScanId,
            ...(snapshot.cost === null
              ? []
              : ["--cost-json", JSON.stringify(snapshot.cost)]),
          ]
        : [
            "complete-budget-exhausted-scan",
            "--scan-id",
            options.resumeScanId,
            "--cost-json",
            JSON.stringify(snapshot.cost ?? { lowerBound: budgetCost }),
            `--message=${budgetError.message}`,
          ];
    const preparation =
      budgetError === null
        ? await input.workbench(command, [
            "prepare-scan-completion",
            "--scan-id",
            options.resumeScanId,
          ])
        : undefined;
    const completion = await input
      .workbench(command, completionArgs)
      .catch(async (error: unknown) => {
        const context = await input.workbench(command, [
          "get-scan",
          "--scan-id",
          options.resumeScanId!,
        ]);
        const scan = context["scan"];
        if (
          !isRecord(scan) ||
          !isRecord(scan["progress"]) ||
          scan["progress"]["status"] !== "complete"
        )
          throw error;
        return input.workbench(command, [
          "complete-scan",
          "--scan-id",
          options.resumeScanId!,
        ]);
      });
    const targetWarnings = new Set([
      ...(Array.isArray(preparation?.["targetWarnings"])
        ? preparation["targetWarnings"]
        : []),
      ...(Array.isArray(completion["targetWarnings"])
        ? completion["targetWarnings"]
        : []),
    ]);
    const completed = completion["scan"];
    if (isRecord(completed) && Array.isArray(completed["warnings"])) {
      for (const warning of completed["warnings"])
        if (typeof warning === "string")
          input.warn(
            warning,
            targetWarnings.has(warning)
              ? { kind: "target_changed" }
              : undefined,
          );
    }
    if (
      options.maxCostUsd !== undefined &&
      (snapshot.cost === null || snapshot.cost.coverage === "partial")
    )
      input.warn(
        "Scan completed, but its cost limit could not be verified because model pricing or token usage is unavailable.",
      );
    if (options.postScanPrompt?.trim() || options.postScanPromptFile)
      input.warn(
        `Could not run post-scan instructions: ${errorMessage(input.startupError)}`,
      );
    return await input.collect({
      scanDir,
      threadId,
      pluginRoot,
      python,
      expectation: {
        repository: recipe["repository"] as string,
        repositoryRevision:
          saved["targetRevision"] === "unversioned"
            ? null
            : saved["targetRevision"],
        target: target as unknown as NormalizedTarget,
        mode: "deep",
        pluginVersion:
          typeof saved["sealedProducerVersion"] === "string"
            ? saved["sealedProducerVersion"]
            : plugin.version,
      },
      turnResult: { status: "completed", model, usage: snapshot.usage },
    });
  } finally {
    await cleanupSdkDirectory(workspace).catch((error: unknown) =>
      input.warn(
        `Could not clean up scan recovery files: ${errorMessage(error)}`,
      ),
    );
  }
}
