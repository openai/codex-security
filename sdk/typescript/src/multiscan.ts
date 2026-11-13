import { notify } from "./value.js";
import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  rmdir,
  truncate,
  utimes,
  writeFile,
} from "node:fs/promises";
import { hostname } from "node:os";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { promisify } from "node:util";
import Papa from "papaparse";
import type { CodexSecurity, ScanOptions } from "./api.js";
import type { CodexSecurityConfig, JsonObject } from "./config.js";
import { ContractSchemaError, loadContract, readScanFile } from "./contract.js";
import type { ScanCost, ScanUsageMeasurement } from "./cost.js";
import { BatchCostPool, batchScanBudget } from "./batch-cost.js";
import { deepScanOptions } from "./deep-config.js";
import { readThreatModelPath } from "./artifact-export.js";
import {
  OutputDirectoryNotEmptyError,
  errorMessage,
  ScanCostLimitExceededError,
} from "./errors.js";
import {
  readKnowledgeBaseSnapshot,
  type KnowledgeBaseSnapshot,
} from "./knowledge-base.js";
import { type DocumentRoots, resolveScanPrompts } from "./prompt-files.js";
import {
  canonicalConfigPath,
  createWindowsOutputDirectory,
  requireSecureOutputAncestry,
  requireWindowsOutputPath,
  resolvePluginPath,
  validateOutputDir,
} from "./runtime.js";
import {
  DiffTarget,
  gitOutput,
  gitProtectionRoots,
  nullIfMissingPath,
  UNSUPPORTED_GIT_ENVIRONMENT,
  resolveTargetPath,
  type ScanMode,
} from "./targets.js";
import {
  meetsSeverity,
  type ScanPromptSettings,
  type ScanSettings,
} from "./scan-settings.js";
import { workflowDigest } from "./finding-workflow.js";
import type { ScanResult } from "./result.js";
import {
  resolveTrustedExecutable,
  withProtectedExecutableRoots,
} from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const CHECKOUT_MARKER = ".git/codex-security-campaign-attempt";
const REQUIRED_ARTIFACTS = ["scan-manifest.json", "findings.json", "report.md"];
const LOCK_LEASE_MS = 30_000;
const LOCK_HEARTBEAT_MS = 5_000;
const WINDOWS_DEVICE_PATH_NAME =
  /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;

class AttemptNumberExhaustedError extends Error {}

type MultiscanTask = ReturnType<typeof parseInventory>[number];

interface MultiscanReceipt extends MultiscanTask {
  status: "completed" | "failed";
  attempt: number;
  operationId?: string;
  outputDir: string;
  threatModelPath?: string;
  cost?: ScanCost;
  measurement?: Readonly<ScanUsageMeasurement>;
  usage?: JsonObject;
  outcome?: "completed" | "failed" | "canceled";
  error?: string;
  warnings?: string[];
  policyFailed?: boolean;
  knowledgeBaseFailure?: true;
  checkoutOccupied?: true;
  cleanupPending?: "checkout" | "recovery-checkout";
}

interface MultiscanHistory {
  maxAttempt: number;
  scan?: MultiscanReceipt;
}

type MultiscanKnowledge = Partial<
  Record<
    ScanMode,
    | { snapshot: KnowledgeBaseSnapshot; failure?: never }
    | { snapshot?: never; failure: { error: unknown } }
  >
>;

export interface MultiscanOptions extends ScanPromptSettings {
  inputPath: string;
  outputDir: string;
  githubHost?: string;
  knowledgeBasePaths?: string[];
  workers: number;
  mode: ScanMode;
  maxAttempts: number;
  recoverScan?(
    scanDir: string,
    prompts: ScanPromptSettings &
      Pick<ScanOptions, "onMeasurement" | "onTelemetry"> & {
        maxTotalCostShareUsd?: number;
        knowledgeBaseSnapshot?: KnowledgeBaseSnapshot;
        /** @internal Preserve correlation when the resumed SDK has no saved binding. */
        telemetryContext?: { operationId: string; parentAttemptId?: string };
      },
  ): Promise<
    | (Pick<ScanResult, "manifest" | "cost" | "findings"> & {
        usage?: JsonObject;
        alreadyCompleted?: boolean;
      })
    | undefined
  >;
  maxCostUsd?: number;
  maxTotalCostUsd?: number;
  // Prompts are shared across modes and prepared from the top-level options.
  scanOptionsByMode?: Partial<
    Record<ScanMode, Omit<ScanSettings, keyof ScanPromptSettings>>
  >;
  config: CodexSecurityConfig;
  createSecurity(
    config: CodexSecurityConfig,
  ): Pick<CodexSecurity, "run" | "close">;
  signal?: AbortSignal;
  onProgress?(event: {
    repository: string;
    status: "started" | "completed" | "failed";
    attempt: number;
    maxCostUsd?: number;
    error?: string;
    warning?: string;
  }): void;
}

export interface MultiscanResult {
  total: number;
  completed: number;
  failed: number;
  skipped: number;
  resultsPath: string;
  warnings?: { repository: string; warnings: string[] }[];
  policyFailed?: boolean;
}

export async function runMultiscan(
  options: MultiscanOptions,
): Promise<MultiscanResult> {
  options.signal?.throwIfAborted();
  if (!Number.isSafeInteger(options.workers) || options.workers < 1) {
    throw new Error("Multiscan workers must be a positive integer.");
  }
  if (!Number.isSafeInteger(options.maxAttempts) || options.maxAttempts < 1) {
    throw new Error("Multiscan max attempts must be a positive integer.");
  }
  const tasks = parseInventory(
    await readFile(options.inputPath, "utf8"),
    dirname(resolveTargetPath(options.inputPath)),
    options.mode,
  );
  for (const mode of new Set(tasks.map((task) => task.mode))) {
    deepScanOptions({ ...options.scanOptionsByMode?.[mode], mode });
  }
  if (
    tasks.some(
      (task) =>
        task.scope === undefined &&
        options.scanOptionsByMode?.[task.mode]?.target instanceof DiffTarget,
    )
  ) {
    throw new Error(
      "Bulk scans do not support diff or working-tree scopes because their checkouts are clean, shallow snapshots. Use repository or path scopes instead.",
    );
  }
  // Direct input paths need no source discovery. Prompts and knowledge share the result.
  let pendingRoots: Promise<DocumentRoots> | undefined;
  const documentRoots = () =>
    (pendingRoots ??= bulkDocumentRoots(tasks, options.signal));
  const requestedOutput = resolve(options.outputDir);
  const localSources = [
    ...new Set(tasks.map((task) => task.repository).filter(isAbsolute)),
  ];
  const worktrees = await Promise.all(
    localSources.map((source) => gitProtectionRoots(source, options.signal)),
  );
  const executableRoots = (output: string) => [
    ...localSources,
    ...worktrees.flat(),
    join(output, "checkouts"),
    join(output, "recovery-checkouts"),
  ];
  const prompts = await resolveScanPrompts(options, () =>
    withProtectedExecutableRoots(
      executableRoots(requestedOutput),
      documentRoots,
    ),
  );
  const resolvedOptions: MultiscanOptions = {
    ...options,
    ...prompts,
    ...(options.scanOptionsByMode === undefined
      ? {}
      : {
          scanOptionsByMode: Object.fromEntries(
            Object.entries(options.scanOptionsByMode).map(
              ([mode, settings]) => [mode, { ...settings, ...prompts }],
            ),
          ),
        }),
  };
  if (
    resolvedOptions.validationPrompt !== undefined &&
    tasks.some((task) => task.mode === "deep")
  ) {
    throw new Error("Custom validation is not supported for Deep scans.");
  }
  if (options.recoverScan !== undefined) {
    const manifest = await lstat(join(requestedOutput, "manifest.json")).catch(
      undefinedIfMissingFile,
    );
    if (!manifest?.isFile())
      throw new Error("Bulk recovery requires an existing campaign manifest.");
  }
  const output = await ensureOutputDirectory(requestedOutput, "artifacts");
  if (process.platform !== "win32") await requireSecureOutputAncestry(output);
  const unlock = await acquireLock(output);
  let pluginWorkspace: string | undefined;
  let pluginRoot: Promise<string> | undefined;
  const resumePluginRoot = (): Promise<string> =>
    (pluginRoot ??= (async () => {
      if (options.config.pluginPath !== undefined) {
        pluginWorkspace = await mkdtemp(join(output, ".resume-plugin-"));
      }
      return await resolvePluginPath(
        options.config.pluginPath,
        pluginWorkspace ?? output,
        options.signal,
      );
    })());
  try {
    const result = await withProtectedExecutableRoots(
      executableRoots(output),
      () =>
        runCampaign(
          resolvedOptions,
          tasks,
          output,
          resumePluginRoot,
          documentRoots,
        ),
    );
    return (await realpath(requestedOutput).catch(() => undefined)) === output
      ? { ...result, resultsPath: join(requestedOutput, "results.jsonl") }
      : result;
  } finally {
    await Promise.all([
      unlock(),
      pluginWorkspace === undefined
        ? undefined
        : rm(pluginWorkspace, { recursive: true, force: true }),
    ]);
  }
}

async function bulkDocumentRoots(
  tasks: readonly MultiscanTask[],
  signal?: AbortSignal,
): Promise<DocumentRoots> {
  const roots: string[] = [];
  for (const repository of new Set(tasks.map((task) => task.repository))) {
    if (!isAbsolute(repository)) continue;
    const source = await realpath(repository).catch(nullIfMissingPath);
    if (source === null) {
      // Git also accepts an omitted .git suffix; wholly missing rows fail at checkout.
      if (await lstat(repository + ".git").catch(nullIfMissingPath))
        return null;
      continue;
    }
    // Only an ordinary worktree and its own .git directory share one boundary.
    const marker = await lstat(join(source, ".git")).catch(nullIfMissingPath);
    if (!marker?.isDirectory()) return null;
    const layout = await gitOutput(
      source,
      [
        "rev-parse",
        "--path-format=relative",
        "--show-toplevel",
        "--git-common-dir",
      ],
      signal,
      undefined,
      source,
      "utf8",
      process.cwd(),
    ).catch(() => null);
    signal?.throwIfAborted();
    if (layout !== "./\n.git" && layout !== "./\r\n.git") return null;
    roots.push(source);
  }
  return roots;
}

async function runCampaign(
  options: MultiscanOptions,
  tasks: MultiscanTask[],
  output: string,
  resumePluginRoot: () => Promise<string>,
  documentRoots: () => Promise<DocumentRoots>,
): Promise<MultiscanResult> {
  const ledger = join(output, "results.jsonl");
  await ensureOutputDirectory(join(output, "checkouts"));
  await ensureOutputDirectory(join(output, "artifacts"));
  const knowledgeByMode: MultiscanKnowledge = {};
  const sharedKnowledge = options.knowledgeBasePaths?.length
    ? readKnowledgeBaseSnapshot(
        options.knowledgeBasePaths,
        options.signal,
        documentRoots,
      )
    : undefined;
  for (const mode of new Set(tasks.map((task) => task.mode))) {
    try {
      const paths = options.scanOptionsByMode?.[mode]?.knowledgeBasePaths;
      const snapshot = await (sharedKnowledge ??
        (paths?.length
          ? readKnowledgeBaseSnapshot(paths, options.signal, documentRoots)
          : undefined));
      if (snapshot !== undefined) knowledgeByMode[mode] = { snapshot };
    } catch (error) {
      options.signal?.throwIfAborted();
      knowledgeByMode[mode] = { failure: { error } };
    }
  }
  await ensureManifest(
    join(output, "manifest.json"),
    tasks,
    options,
    knowledgeByMode,
  );
  const receipts = await readReceipts(
    ledger,
    options.recoverScan !== undefined,
  );
  const pending: MultiscanTask[] = [];
  const rejectedCompleted = new Set<string>();
  let completed = 0;
  let policyFailed = false;
  const warnings: NonNullable<MultiscanResult["warnings"]> = [];
  const hasPolicy = Object.values(options.scanOptionsByMode ?? {}).some(
    (settings) => settings.failureSeverity !== undefined,
  );
  let untouched = 0;
  for (const task of tasks) {
    const history = receipts.get(task.id.toLowerCase());
    const receipt = history?.scan;
    if (
      receipt === undefined ||
      knowledgeByMode[task.mode]?.failure !== undefined
    ) {
      if (history === undefined && options.recoverScan !== undefined) {
        const attempts = await readdir(
          join(output, "artifacts", task.id),
        ).catch((error: NodeJS.ErrnoException) => {
          if (error.code !== "ENOENT") throw error;
          return [];
        });
        if (!attempts.some((name) => /^attempt-[1-9][0-9]*$/u.test(name))) {
          untouched += 1;
          continue;
        }
      }
      pending.push(task);
      continue;
    }
    const artifactRoot = await ensureOutputDirectory(
      join(output, "artifacts", task.id),
    );
    const artifactOutput = join(artifactRoot, `attempt-${receipt.attempt}`);
    const selectedArtifactOutput = join(
      resolve(options.outputDir),
      "artifacts",
      task.id,
      `attempt-${receipt.attempt}`,
    );
    const completedReceipt =
      receipt.status === "completed" ||
      (receipt.status === "failed" &&
        receipt.error === "Multiscan repository coverage is incomplete.");
    const selectedOutputMatches =
      receipt.outputDir === artifactOutput ||
      receipt.outputDir === selectedArtifactOutput;
    const artifactsPresent =
      selectedOutputMatches && (await hasArtifacts(artifactOutput));
    if (
      completedReceipt &&
      selectedOutputMatches &&
      (!(await hasCompletedContract(
        artifactOutput,
        await resumePluginRoot(),
        options.signal,
      )) ||
        !artifactsPresent)
    ) {
      rejectedCompleted.add(artifactOutput);
      pending.push(task);
      continue;
    }
    if (artifactsPresent) {
      if (receipt.status === "completed") {
        try {
          if (receipt.cleanupPending === "checkout") {
            await removeCheckout(
              join(output, "checkouts", task.id),
              artifactOutput,
              options.signal,
            );
          } else if (receipt.cleanupPending === "recovery-checkout") {
            const recoveryRoot = join(output, "recovery-checkouts");
            await lstat(recoveryRoot);
            await ensureOutputDirectory(recoveryRoot);
            const taskRoot = join(recoveryRoot, task.id);
            await lstat(taskRoot);
            await ensureOutputDirectory(taskRoot);
            await removeCheckout(
              join(taskRoot, `attempt-${receipt.attempt}`),
              artifactOutput,
              options.signal,
            );
          }
        } catch {}
      }
      if (receipt.status !== "failed" && receipt.warnings?.length) {
        warnings.push({ repository: task.id, warnings: receipt.warnings });
        for (const warning of receipt.warnings) {
          notifyProgress(options, {
            repository: task.id,
            status: "completed",
            attempt: receipt.attempt,
            warning,
          });
        }
      }
      if (completedReceipt) {
        policyFailed ||= receipt.policyFailed === true;
        completed += 1;
        continue;
      }
    }
    pending.push(task);
  }
  const skipped = completed + untouched;
  let failed = 0;
  const summarize = (): MultiscanResult => ({
    total: tasks.length,
    completed,
    failed,
    skipped,
    resultsPath: ledger,
    ...(warnings.length === 0 ? {} : { warnings }),
    ...(hasPolicy ? { policyFailed } : {}),
  });
  if (pending.length === 0) return summarize();

  const pool =
    options.maxTotalCostUsd === undefined
      ? undefined
      : new BatchCostPool(
          options.maxTotalCostUsd,
          pending.length * options.maxAttempts,
        );
  let next = 0;
  let receiptTail = Promise.resolve();
  const worker = async (
    security: Pick<CodexSecurity, "run" | "close">,
  ): Promise<void> => {
    for (;;) {
      options.signal?.throwIfAborted();
      const task = pending[next++];
      if (task === undefined) return;
      const knowledge = knowledgeByMode[task.mode];
      const scanSettings = options.scanOptionsByMode?.[task.mode];
      const budget = batchScanBudget(pool?.share, {
        ...options,
        maxCostUsd: options.maxCostUsd ?? scanSettings?.maxCostUsd,
      });
      const history = receipts.get(task.id.toLowerCase());
      let operationId = history?.scan?.operationId;
      let maxAttempt = history?.maxAttempt ?? 0;
      const nextAttempt = () => {
        if (maxAttempt === Number.MAX_SAFE_INTEGER)
          throw new AttemptNumberExhaustedError(
            `No more attempt numbers are available for ${task.id}. Start a separate campaign in a new --output-dir.`,
          );
        return ++maxAttempt;
      };
      let recoveryAttempt = history?.scan?.attempt ?? 0;
      const artifactRoot = join(output, "artifacts", task.id);
      if (options.recoverScan !== undefined) {
        await ensureOutputDirectory(artifactRoot);
        for (const name of await readdir(artifactRoot)) {
          const match = /^attempt-([1-9][0-9]*)$/u.exec(name);
          if (match && Number.isSafeInteger(Number(match[1]))) {
            maxAttempt = Math.max(maxAttempt, Number(match[1]));
            recoveryAttempt = Math.max(recoveryAttempt, Number(match[1]));
          }
        }
      }
      for (let retry = 0; retry < options.maxAttempts; retry += 1) {
        options.signal?.throwIfAborted();
        let attempt = maxAttempt;
        if (options.recoverScan === undefined) attempt = nextAttempt();
        else if (retry === 0) attempt = recoveryAttempt;
        let scanDir = join(artifactRoot, `attempt-${attempt}`);
        let checkout: string | undefined;
        let protectedRoot = join(output, "checkouts", task.id);
        let attemptedResume = false;
        let failure: string | undefined;
        let cleanupFailure: string | undefined;
        const runWarnings: string[] = [];
        let attemptPolicyFailed: boolean | undefined;
        let cost: Readonly<ScanCost> | null = null;
        let measurement: Readonly<ScanUsageMeasurement> | null = null;
        let reservation: ReturnType<BatchCostPool["reserve"]> | undefined;
        let savedUsage: JsonObject | undefined;
        const observers: Pick<ScanOptions, "onMeasurement" | "onTelemetry"> = {
          onMeasurement: (value) => {
            reservation?.record(value.cost);
            measurement = value;
            cost = value.cost;
          },
          onTelemetry: (event) => {
            operationId = event.operationId;
          },
        };
        let threatModelPath: string | null | undefined;
        let exhaustedBudget = false;
        let requiresRecovery = false;
        let knowledgeBaseFailure = false;
        let checkoutOccupied = false;
        try {
          reservation = pool?.reserve(budget.maxCostUsd);
          const maxCostUsd = reservation?.maxCostUsd ?? budget.maxCostUsd;
          await ensureOutputDirectory(artifactRoot);
          let result:
            | (Pick<ScanResult, "manifest" | "cost" | "findings"> &
                Partial<Pick<ScanResult, "threatModelPath">> & {
                  usage?: JsonObject;
                  alreadyCompleted?: boolean;
                })
            | undefined;
          if (
            options.recoverScan !== undefined &&
            retry === 0 &&
            attempt > 0 &&
            !rejectedCompleted.has(scanDir)
          ) {
            const existing = await lstat(scanDir).catch(undefinedIfMissingFile);
            if (existing !== undefined) {
              await ensureOutputDirectory(scanDir);
              const retainedCheckout = join(
                output,
                "recovery-checkouts",
                task.id,
                `attempt-${attempt}`,
              );
              const retained = await lstat(retainedCheckout).catch(
                (error: NodeJS.ErrnoException) => {
                  if (error.code !== "ENOENT") throw error;
                  return undefined;
                },
              );
              if (retained !== undefined) protectedRoot = retainedCheckout;
              attemptedResume = true;
              notifyProgress(options, {
                repository: task.id,
                attempt,
                status: "started",
                maxCostUsd,
              });
              if (knowledge?.failure !== undefined) {
                knowledgeBaseFailure = true;
                throw knowledge.failure.error;
              }
              result = await options.recoverScan(scanDir, {
                ...options,
                ...(options.maxTotalCostUsd === undefined
                  ? {}
                  : { maxTotalCostShareUsd: maxCostUsd }),
                knowledgeBaseSnapshot: knowledge?.snapshot,
                ...observers,
                ...(operationId === undefined
                  ? {}
                  : { telemetryContext: { operationId } }),
              });
              attemptedResume = result !== undefined;
            }
          }
          if (result === undefined) {
            if (options.recoverScan !== undefined) attempt = nextAttempt();
            scanDir = join(artifactRoot, `attempt-${attempt}`);
            notifyProgress(options, {
              repository: task.id,
              attempt,
              status: "started",
              maxCostUsd,
            });
            if (options.recoverScan === undefined)
              await validateOutputDir(scanDir);
            if (knowledge?.failure !== undefined) {
              knowledgeBaseFailure = true;
              throw knowledge.failure.error;
            }
            if (options.recoverScan !== undefined) {
              const checkoutRoot = await ensureOutputDirectory(
                join(output, "recovery-checkouts"),
              );
              const taskRoot = await ensureOutputDirectory(
                join(checkoutRoot, task.id),
              );
              checkout = join(taskRoot, `attempt-${attempt}`);
              // Reserve both paths before starting work. An interrupted attempt is never replaced.
              await mkdir(scanDir, { mode: 0o700 });
              await mkdir(checkout, { mode: 0o700 });
            } else {
              const destination = join(output, "checkouts", task.id);
              try {
                await mkdir(destination, { mode: 0o700 });
                checkout = destination;
              } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "EEXIST")
                  throw error;
                checkoutOccupied = true;
                throw new Error(
                  `Bulk checkout is already occupied: ${destination}. Retry with --recover to use a fresh checkout, or inspect and move the retained checkout before an ordinary retry.`,
                );
              }
            }
            protectedRoot = checkout;
            // Claim the fresh checkout before Git or the scanner can fail.
            const marker = await checkoutMarker(checkout, scanDir);
            await mkdir(join(checkout, ".git"), { mode: 0o700 });
            await writeFile(join(checkout, CHECKOUT_MARKER), marker, {
              flag: "wx",
              mode: 0o600,
            });
            await checkoutRevision(
              task,
              checkout,
              options.signal,
              options.githubHost,
            );
            if (task.scope !== undefined) {
              const scoped = await realpath(join(checkout, task.scope));
              const outside = relative(await realpath(checkout), scoped);
              if (
                outside === ".." ||
                outside.startsWith(`..${sep}`) ||
                isAbsolute(outside)
              ) {
                throw new Error("Multiscan scope escapes its repository.");
              }
            }
            const scanPrompt = [options.scanPrompt?.trim(), task.prompt]
              .filter(Boolean)
              .join("\n\n");
            operationId ??= randomUUID();
            result = await security.run(checkout, {
              ...scanSettings,
              knowledgeBaseSnapshot: knowledge?.snapshot,
              ...(task.scope === undefined
                ? {}
                : { target: [resolve(checkout, task.scope)] }),
              ...(options.knowledgeBasePaths?.length
                ? { knowledgeBasePaths: options.knowledgeBasePaths }
                : {}),
              mode: task.mode,
              telemetryContext: { operationId },
              outputDir: scanDir,
              ...(scanPrompt ? { scanPrompt } : {}),
              ...(options.validationPrompt === undefined
                ? {}
                : { validationPrompt: options.validationPrompt }),
              ...(options.postScanPrompt === undefined
                ? {}
                : { postScanPrompt: options.postScanPrompt }),
              ...budget,
              maxCostUsd,
              ...observers,
              onWarning: (warning) => {
                runWarnings.push(warning);
                notifyProgress(options, {
                  repository: task.id,
                  attempt,
                  status: "started",
                  warning,
                });
              },
              ...(options.signal === undefined
                ? {}
                : { signal: options.signal }),
            });
          }
          threatModelPath = result.threatModelPath;
          cost = result.cost;
          if (!result.alreadyCompleted) reservation?.record(cost);
          savedUsage = result.usage;
          const failureSeverity = scanSettings?.failureSeverity;
          if (failureSeverity !== undefined) {
            attemptPolicyFailed = result.findings.findings.some((finding) =>
              meetsSeverity(finding, failureSeverity),
            );
          }
          if (result.manifest.scan.status !== "completed")
            throw new Error(`Multiscan scan ${result.manifest.scan.status}.`);
        } catch (error) {
          if (error instanceof AttemptNumberExhaustedError) throw error;
          // Recovery retains its resumable attempt and checkout; SDK telemetry records cancellation.
          if (options.signal?.aborted && options.recoverScan !== undefined)
            options.signal.throwIfAborted();
          if (pool && !reservation) exhaustedBudget = true;
          if (error instanceof ScanCostLimitExceededError) {
            cost = error.cost;
            reservation?.record(cost);
            exhaustedBudget = true;
          }
          requiresRecovery = error instanceof OutputDirectoryNotEmptyError;
          failure = requiresRecovery
            ? `Bulk attempt directory is not empty: ${scanDir}. Existing artifacts were preserved. Run the same bulk-scan command with --recover to recover interrupted scans or retry failed scans in new attempt directories.`
            : errorMessage(error);
        } finally {
          if (options.recoverScan === undefined && checkout !== undefined) {
            cleanupFailure = await removeCheckout(checkout, scanDir);
          }
        }
        const reportedErrors = [failure, cleanupFailure].filter(
          (message): message is string => message !== undefined,
        );
        let reportedError =
          reportedErrors.length === 0 ? undefined : reportedErrors.join("; ");
        const status = failure !== undefined ? "failed" : "completed";
        if (threatModelPath === undefined)
          threatModelPath = await readThreatModelPath(scanDir, {
            pythonPath: options.config.pythonPath,
            protectedRoot,
            signal: options.signal?.aborted ? undefined : options.signal,
          });
        const recoveryCheckout =
          options.recoverScan !== undefined && failure === undefined
            ? checkout
            : undefined;
        const receipt: MultiscanReceipt = {
          ...task,
          status,
          attempt,
          ...(operationId === undefined ? {} : { operationId }),
          outputDir: scanDir,
          ...(threatModelPath === null ? {} : { threatModelPath }),
          ...(cost === null ? {} : { cost }),
          ...(measurement === null ? {} : { measurement }),
          ...(savedUsage === undefined ? {} : { usage: savedUsage }),
          outcome: options.signal?.aborted ? "canceled" : status,
          ...(reportedError === undefined ? {} : { error: reportedError }),
          ...(recoveryCheckout !== undefined
            ? { cleanupPending: "recovery-checkout" }
            : failure === undefined && cleanupFailure !== undefined
              ? { cleanupPending: "checkout" }
              : {}),
          ...(knowledgeBaseFailure ? { knowledgeBaseFailure: true } : {}),
          ...(checkoutOccupied ? { checkoutOccupied: true } : {}),
          ...(runWarnings.length === 0 ? {} : { warnings: runWarnings }),
          policyFailed: attemptPolicyFailed,
        };
        const receiptLine = `${JSON.stringify(receipt)}\n`;
        receiptTail = receiptTail.then(() =>
          appendReceipt(ledger, receiptLine),
        );
        await receiptTail;
        options.signal?.throwIfAborted();
        if (recoveryCheckout !== undefined) {
          reportedError = await removeCheckout(recoveryCheckout, scanDir);
        }
        notifyProgress(options, {
          repository: task.id,
          attempt,
          status,
          ...(reportedError === undefined ? {} : { error: reportedError }),
        });
        if (failure === undefined) {
          policyFailed ||= attemptPolicyFailed === true;
          if (runWarnings.length > 0) {
            warnings.push({ repository: task.id, warnings: runWarnings });
          }
          completed += 1;
          break;
        }
        if (
          exhaustedBudget ||
          attemptedResume ||
          requiresRecovery ||
          checkoutOccupied
        ) {
          failed += 1;
          break;
        }
        if (retry === options.maxAttempts - 1) failed += 1;
      }
    }
  };
  const results = await Promise.allSettled(
    Array.from(
      { length: Math.min(options.workers, pending.length) },
      async () => {
        const security = options.createSecurity(options.config);
        try {
          await worker(security);
        } finally {
          await security.close();
        }
      },
    ),
  );
  const rejection = results.find((result) => result.status === "rejected");
  if (rejection?.status === "rejected") throw rejection.reason;
  return summarize();
}

function notifyProgress(
  options: MultiscanOptions,
  event: Parameters<NonNullable<MultiscanOptions["onProgress"]>>[0],
): void {
  notify(() => options.onProgress?.(event));
}

// A completed attempt can be revisited after its checkout path was reused.
async function checkoutMarker(
  checkout: string,
  scanDir: string,
): Promise<string> {
  const directory = await lstat(checkout, { bigint: true });
  if (!directory.isDirectory())
    throw new Error("The campaign checkout is no longer a directory.");
  return JSON.stringify([
    scanDir,
    String(directory.dev),
    String(directory.ino),
  ]);
}

async function removeCheckout(
  checkout: string,
  scanDir: string,
  signal?: AbortSignal,
): Promise<string | undefined> {
  try {
    const marker = await lstat(join(checkout, CHECKOUT_MARKER)).catch(
      undefinedIfMissingFile,
    );
    if (!marker?.isFile()) return undefined;
    const expected = Buffer.from(await checkoutMarker(checkout, scanDir));
    if (
      marker.size === expected.length &&
      (
        await readScanFile(
          checkout,
          CHECKOUT_MARKER,
          "campaign checkout marker",
          signal,
        )
      ).equals(expected)
    ) {
      await rm(checkout, { recursive: true, force: true });
    }
  } catch (error) {
    return `Multiscan checkout cleanup failed: ${errorMessage(error)}`;
  }
}

async function ensureOutputDirectory(
  path: string,
  retainedDirectory?: string,
): Promise<string> {
  const linkedOutput =
    "Multiscan output directories must not be symbolic links.";
  let metadata = await lstat(path, { bigint: true }).catch(
    undefinedIfMissingFile,
  );
  if (metadata === undefined) {
    if (process.platform === "win32") {
      // Resolve parent aliases while leaving the leaf for lstat to verify.
      path = join(await canonicalConfigPath(dirname(path)), basename(path));
      try {
        await createWindowsOutputDirectory(path, true);
      } catch (error) {
        if ((await lstat(path).catch(() => undefined))?.isSymbolicLink()) {
          throw new Error(linkedOutput, { cause: error });
        }
        throw error;
      }
    } else {
      await mkdir(path, { recursive: true, mode: 0o700 });
    }
    metadata = await lstat(path, { bigint: true });
  }
  if (metadata.isSymbolicLink()) {
    throw new Error(linkedOutput);
  }
  if (!metadata.isDirectory()) {
    throw new Error("Multiscan output paths must be directories.");
  }
  const canonical = await realpath(path);
  const directory = await lstat(canonical, { bigint: true });
  if (directory.dev !== metadata.dev || directory.ino !== metadata.ino) {
    throw new Error("Multiscan output directories changed during preparation.");
  }
  if (process.platform === "win32") {
    await requireWindowsOutputPath(canonical, true, retainedDirectory);
    return canonical;
  }
  if ((directory.mode & 0o022n) !== 0n) {
    throw new Error(
      "Multiscan output directories must not be group- or world-writable.",
    );
  }
  const owner = process.geteuid?.();
  if (owner !== undefined && directory.uid !== BigInt(owner)) {
    throw new Error(
      "Multiscan output directories must be owned by the current user.",
    );
  }
  return canonical;
}

async function appendReceipt(path: string, receipt: string): Promise<void> {
  const file = await open(path, "a", 0o600);
  try {
    await file.writeFile(receipt, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
}

async function acquireLock(output: string): Promise<() => Promise<void>> {
  const path = join(output, ".lock");
  const ownerPath = join(path, "owner.json");
  try {
    await mkdir(path, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const existing = await inspectLock(path);
    if (!existing.stale) {
      throw new Error("A multiscan supervisor is already running.");
    }
    const stale = await recoverLock(output, path, existing.owner);
    try {
      return await acquireLock(output);
    } finally {
      await rm(stale, { recursive: true, force: true });
    }
  }
  // Windows file IDs can exceed JavaScript's safe integer range.
  const createdLock = await lstat(path, { bigint: true });
  const owner = `${JSON.stringify({
    pid: process.pid,
    ownerId: randomUUID(),
    hostname: hostname(),
    processStartedAt: performance.timeOrigin,
  })}\n`;
  try {
    await writeFile(ownerPath, owner, { flag: "wx", mode: 0o600 });
  } catch (error) {
    const currentLock = await lstat(path, { bigint: true }).catch(
      undefinedIfMissingFile,
    );
    if (
      currentLock?.dev === createdLock.dev &&
      currentLock.ino === createdLock.ino
    ) {
      await rmdir(path).catch((cleanup: NodeJS.ErrnoException) => {
        if (
          cleanup.code !== "ENOENT" &&
          cleanup.code !== "ENOTEMPTY" &&
          cleanup.code !== "EEXIST"
        ) {
          throw cleanup;
        }
      });
    }
    throw error;
  }

  let heartbeat = Promise.resolve();
  const timer = setInterval(() => {
    heartbeat = heartbeat
      .then(async () => {
        if ((await readFile(ownerPath, "utf8")) !== owner) return;
        const now = new Date();
        await utimes(ownerPath, now, now);
      })
      .catch(() => {});
  }, LOCK_HEARTBEAT_MS);
  timer.unref();

  return async () => {
    clearInterval(timer);
    await heartbeat;
    const current = await readFile(ownerPath, "utf8").catch(
      undefinedIfMissingFile,
    );
    if (current === owner) await rm(path, { recursive: true });
  };
}

async function inspectLock(
  path: string,
): Promise<{ owner: string | undefined; stale: boolean }> {
  const ownerPath = join(path, "owner.json");
  let owner: string;
  let modifiedAt: number;
  try {
    owner = await readFile(ownerPath, "utf8");
    modifiedAt = (await lstat(ownerPath)).mtimeMs;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return {
      owner: undefined,
      stale: Date.now() - (await lstat(path)).mtimeMs > LOCK_LEASE_MS,
    };
  }

  let identity: {
    pid?: number;
    ownerId?: string;
    hostname?: string;
    processStartedAt?: number;
  };
  try {
    identity = (JSON.parse(owner) ?? {}) as typeof identity;
  } catch {
    return { owner, stale: Date.now() - modifiedAt > LOCK_LEASE_MS };
  }

  if (
    typeof identity.ownerId === "string" &&
    typeof identity.hostname === "string" &&
    typeof identity.processStartedAt === "number"
  ) {
    const sameProcess =
      identity.pid === process.pid &&
      identity.hostname === hostname() &&
      identity.processStartedAt === performance.timeOrigin;
    return {
      owner,
      stale: !sameProcess && Date.now() - modifiedAt > LOCK_LEASE_MS,
    };
  }

  if (
    identity.pid === undefined ||
    !Number.isSafeInteger(identity.pid) ||
    identity.pid < 1
  ) {
    return { owner, stale: Date.now() - modifiedAt > LOCK_LEASE_MS };
  }
  try {
    process.kill(identity.pid, 0);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") {
      return { owner, stale: true };
    }
    if ((error as NodeJS.ErrnoException).code === "EPERM") {
      return { owner, stale: false };
    }
    throw error;
  }
  return {
    owner,
    stale:
      identity.pid === process.pid &&
      modifiedAt + 1_000 < performance.timeOrigin,
  };
}

async function recoverLock(
  output: string,
  path: string,
  expectedOwner: string | undefined,
): Promise<string> {
  const recoveryPath = join(path, ".recovering");
  let claim;
  try {
    claim = await open(recoveryPath, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      if (Date.now() - (await lstat(recoveryPath)).mtimeMs > LOCK_LEASE_MS) {
        await rm(recoveryPath, { force: true });
        return await recoverLock(output, path, expectedOwner);
      }
      throw new Error("A multiscan supervisor is already running.");
    }
    throw error;
  }
  await claim.close();

  let moved = false;
  try {
    const current = await inspectLock(path);
    if (
      current.owner !== expectedOwner ||
      (expectedOwner !== undefined && !current.stale)
    ) {
      throw new Error("A multiscan supervisor is already running.");
    }
    const stale = join(output, `.lock.stale-${randomUUID()}`);
    await rename(path, stale);
    moved = true;
    return stale;
  } finally {
    if (!moved) await rm(recoveryPath, { force: true });
  }
}

async function ensureManifest(
  path: string,
  tasks: MultiscanTask[],
  options: Pick<
    MultiscanOptions,
    | "scanPrompt"
    | "validationPrompt"
    | "postScanPrompt"
    | "maxCostUsd"
    | "scanOptionsByMode"
    | "config"
  >,
  knowledgeByMode: MultiscanKnowledge,
): Promise<void> {
  const knowledgeDigests: Partial<Record<ScanMode, string | null>> =
    Object.fromEntries(
      Object.entries(knowledgeByMode).map(([mode, knowledge]) => [
        mode,
        knowledge.snapshot === undefined
          ? null
          : workflowDigest(knowledge.snapshot.documents),
      ]),
    );
  const manifest = {
    version: 2,
    tasks,
    scanPrompt: options.scanPrompt,
    validationPrompt: options.validationPrompt,
    postScanPrompt: options.postScanPrompt,
    maxCostUsd: options.maxCostUsd,
    // Failed modes cannot start scans; bind their inputs only after repair.
    ...(Object.keys(knowledgeDigests).length > 0
      ? { knowledgeBaseDigests: knowledgeDigests }
      : {}),
    ...(options.scanOptionsByMode === undefined &&
    Object.keys(options.config.codexOverrides ?? {}).length === 0 &&
    options.config.pluginPath === undefined &&
    options.config.pythonPath === undefined
      ? {}
      : {
          configurationDigest: workflowDigest({
            scanOptions: options.scanOptionsByMode,
            codex: options.config.codexOverrides,
            pluginPath: options.config.pluginPath,
            pythonPath: options.config.pythonPath,
          }),
        }),
  };
  const expected = `${JSON.stringify(manifest, null, 2)}\n`;
  try {
    await writeFile(path, expected, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const existing = await readFile(path, "utf8");
    if (existing === expected) return;
    const { knowledgeBaseDigests: savedDigests = {}, ...savedInputs } =
      JSON.parse(existing) as Record<string, unknown> & {
        knowledgeBaseDigests?: Partial<Record<ScanMode, string | null>>;
      };
    const { knowledgeBaseDigests: _, ...expectedInputs } = manifest;
    const mismatch = (): never => {
      throw new Error(
        "Multiscan manifest does not match existing output directory.",
      );
    };
    if (JSON.stringify(savedInputs) !== JSON.stringify(expectedInputs))
      mismatch();
    const boundDigests = { ...savedDigests };
    for (const mode of Object.keys({
      ...savedDigests,
      ...knowledgeDigests,
    }) as ScanMode[]) {
      const saved = savedDigests[mode];
      const current = knowledgeDigests[mode];
      if (
        saved === undefined ||
        current === undefined ||
        (saved !== null && current !== null && saved !== current)
      ) {
        mismatch();
      }
      boundDigests[mode] = saved ?? current;
    }
    // Preserve bound modes when their inputs are temporarily unavailable.
    if (Object.keys(boundDigests).length > 0)
      manifest.knowledgeBaseDigests = boundDigests;
    const bound = `${JSON.stringify(manifest, null, 2)}\n`;
    if (bound !== existing) {
      const temporary = `${path}.${randomUUID()}.tmp`;
      try {
        await writeFile(temporary, bound, { flag: "wx", mode: 0o600 });
        await rename(temporary, path);
      } finally {
        await rm(temporary, { force: true });
      }
    }
  }
}

async function readReceipts(
  path: string,
  preserveInterrupted = false,
): Promise<Map<string, MultiscanHistory>> {
  let contents: Buffer;
  try {
    contents = await readFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
    throw error;
  }
  const end = contents.lastIndexOf(10) + 1;
  const lines = contents.subarray(0, end).toString("utf8").split("\n");
  const receipts = new Map<string, MultiscanHistory>();
  for (const [index, line] of lines.entries()) {
    if (!line) continue;
    let saved;
    try {
      saved = JSON.parse(line);
      if (!isValidTaskId(saved?.id))
        throw new Error("Expected a receipt with a valid task id");
      if (!Number.isSafeInteger(saved.attempt) || saved.attempt < 1)
        throw new Error("Expected a positive integer receipt attempt");
      if (saved.status === "completed_with_incomplete_coverage")
        saved.status = "completed";
      if (saved.status !== "completed" && saved.status !== "failed")
        throw new Error("Expected a completed or failed receipt status");
      if (typeof saved.outputDir !== "string" || !saved.outputDir.trim())
        throw new Error("Expected a nonempty string outputDir");
      if (
        saved.cleanupPending !== undefined &&
        saved.cleanupPending !== "checkout" &&
        saved.cleanupPending !== "recovery-checkout"
      )
        throw new Error(
          "Expected cleanupPending to be checkout or recovery-checkout",
        );
      for (const flag of [
        "knowledgeBaseFailure",
        "checkoutOccupied",
        "policyFailed",
      ]) {
        if (saved[flag] !== undefined && typeof saved[flag] !== "boolean")
          throw new Error(`Expected a boolean ${flag}`);
      }
    } catch (cause) {
      throw new Error(
        `${path}:${index + 1}: ${errorMessage(cause)}. Restore a complete ledger backup that includes every committed attempt, or start a separate campaign in a new --output-dir.`,
        { cause },
      );
    }
    const receipt = saved as MultiscanReceipt;
    const id = receipt.id.toLowerCase();
    const previous = receipts.get(id);
    receipts.set(id, {
      maxAttempt: Math.max(previous?.maxAttempt ?? 0, receipt.attempt),
      // Pre-scan failures reserve an attempt but leave the last scan recoverable.
      scan:
        receipt.knowledgeBaseFailure || receipt.checkoutOccupied
          ? previous?.scan
          : receipt,
    });
  }
  if (contents.at(-1) !== 10) {
    const partial = contents.subarray(end);
    if (preserveInterrupted) {
      await writeFile(`${path}.interrupted-${randomUUID()}`, partial, {
        flag: "wx",
        mode: 0o600,
      });
    }
    await truncate(path, end);
  }
  return receipts;
}

async function hasArtifacts(path: string): Promise<boolean> {
  try {
    if (!(await lstat(path)).isDirectory()) return false;
    for (const artifact of REQUIRED_ARTIFACTS) {
      if (!(await lstat(join(path, artifact))).isFile()) return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function hasCompletedContract(
  path: string,
  pluginRoot: string,
  signal?: AbortSignal,
): Promise<boolean> {
  try {
    signal?.throwIfAborted();
    const contract = await loadContract(path, { pluginRoot, signal });
    return contract.manifest.scan.status === "completed";
  } catch (error) {
    signal?.throwIfAborted();
    if (error instanceof ContractSchemaError) throw error;
    return false;
  }
}

function isValidTaskId(id: unknown): id is string {
  return (
    typeof id === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(id) &&
    !id.endsWith(".") &&
    !WINDOWS_DEVICE_PATH_NAME.test(id)
  );
}

function parseInventory(
  source: string,
  directory: string,
  defaultMode: ScanMode,
) {
  const { data: rows, errors } = Papa.parse<string[]>(source, {
    delimiter: ",",
    skipEmptyLines: "greedy",
  });
  if (errors.length > 0) {
    throw new Error(`Multiscan CSV could not be parsed: ${errors[0]!.message}`);
  }
  const headers = rows.shift()?.map((header) => header.trim());
  if (
    headers === undefined ||
    !["id", "repository", "revision"].every((name) => headers.includes(name)) ||
    new Set(headers).size !== headers.length
  ) {
    throw new Error(
      "Multiscan CSV requires id, repository, and revision columns.",
    );
  }
  if (rows.length === 0)
    throw new Error("Multiscan CSV must contain at least one repository.");
  const seen = new Set<string>();
  return rows.map((fields) => {
    if (fields.length !== headers.length) {
      throw new Error("Multiscan CSV rows must match their header columns.");
    }
    const get = (name: string): string =>
      fields[headers.indexOf(name)]?.trim() ?? "";
    const id = get("id");
    if (!isValidTaskId(id)) {
      throw new Error("Multiscan task IDs must be safe, unique path names.");
    }
    if (seen.has(id.toLowerCase()))
      throw new Error("Multiscan task IDs must be unique.");
    seen.add(id.toLowerCase());
    const revision = get("revision").toLowerCase();
    if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(revision)) {
      throw new Error("Multiscan revisions must be full immutable Git SHAs.");
    }
    const mode = get("mode") || defaultMode;
    if (mode !== "standard" && mode !== "deep") {
      throw new Error("Multiscan mode must be standard or deep.");
    }
    const scope = get("scope");
    const prompt = get("prompt");
    if (
      scope &&
      (isAbsolute(scope) ||
        scope.includes("\\") ||
        scope.split("/").includes("..") ||
        (process.platform === "win32" && scope.includes(":")) ||
        scope.includes("\0"))
    ) {
      throw new Error("Multiscan scope must stay inside its repository.");
    }
    const repository = normalizeRepository(get("repository"), directory);
    return {
      id,
      repository,
      revision,
      mode: mode as ScanMode,
      ...(scope ? { scope } : {}),
      ...(prompt ? { prompt } : {}),
    };
  });
}

function normalizeRepository(repository: string, directory: string): string {
  if (!repository || repository.length > 4096 || repository.includes("\0")) {
    throw new Error(
      "Multiscan repositories must be safe local paths or Git URLs.",
    );
  }
  if (/^[^@\s/:]+@[^:\s/]+:.+$/u.test(repository)) return repository;
  if (!repository.includes("://")) {
    const path = resolveTargetPath(repository, directory);
    if (process.platform !== "win32") return path;
    try {
      return realpathSync.native(path);
    } catch {
      return path;
    }
  }
  let url: URL;
  try {
    url = new URL(repository);
  } catch {
    throw new Error("Multiscan repository URL is invalid.");
  }
  if (url.protocol !== "https:" && url.protocol !== "ssh:") {
    throw new Error("Multiscan repository URL protocol is unsupported.");
  }
  if (
    url.password ||
    (url.protocol === "https:" && url.username) ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "Repository URLs must not contain embedded credentials, query strings, or fragments.",
    );
  }
  return repository;
}

async function checkoutRevision(
  task: MultiscanTask,
  path: string,
  signal?: AbortSignal,
  githubHost?: string,
): Promise<void> {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (UNSUPPORTED_GIT_ENVIRONMENT.has(name.toUpperCase()))
      delete environment[name];
  }
  environment["GIT_TERMINAL_PROMPT"] = "0";
  environment["GIT_LFS_SKIP_SMUDGE"] = "1";
  environment["GIT_DEFAULT_HASH"] =
    task.revision.length === 64 ? "sha256" : "sha1";
  const command = await resolveTrustedExecutable(
    "git",
    environment,
    resolve(process.cwd()),
  );
  if (command === null) {
    throw new Error("Git is not available on a trusted PATH.");
  }
  const git = async (...args: string[]): Promise<string> => {
    // Use the resolved absolute path so Windows PATHEXT cannot prefer a
    // .bat/.cmd shim over the trusted executable selected above.
    const result = await execFile(
      command.executable,
      [
        "-c",
        "core.hooksPath=/dev/null",
        ...buildGitHubCredentialArgs(githubHost),
        "-C",
        path,
        ...args,
      ],
      { env: command.environment, signal },
    );
    return result.stdout.trim();
  };
  await git("init", "--quiet");
  await git(
    "fetch",
    "--quiet",
    "--no-tags",
    "--depth=1",
    "--",
    task.repository,
    task.revision,
  );
  await git("checkout", "--quiet", "--detach", "FETCH_HEAD");
  if ((await git("rev-parse", "HEAD")).toLowerCase() !== task.revision) {
    throw new Error("Git checkout revision did not match the pinned SHA.");
  }
}

export function buildGitHubCredentialArgs(host: string | undefined): string[] {
  if (host === undefined) return [];
  let url: URL;
  try {
    url = new URL(`https://${host}`);
  } catch {
    throw new Error("GitHub credential host is invalid.");
  }
  if (
    url.host !== host.toLowerCase() ||
    url.pathname !== "/" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error("GitHub credential host is invalid.");
  }
  const key = `credential.${url.origin}.helper`;
  return ["-c", `${key}=`, "-c", `${key}=!gh auth git-credential`];
}

function undefinedIfMissingFile(error: NodeJS.ErrnoException): undefined {
  if (error.code !== "ENOENT") throw error;
  return undefined;
}
