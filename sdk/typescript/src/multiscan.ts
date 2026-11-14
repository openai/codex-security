import { notify } from "./value.js";
import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  readlink,
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
  extname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  sep,
} from "node:path";
import { promisify } from "node:util";
import Papa from "papaparse";
import type { CodexSecurity, ScanOptions } from "./api.js";
import type { CodexSecurityConfig, JsonObject } from "./config.js";
import {
  ContractSchemaError,
  hasSealedReport,
  loadContract,
  loadContractWithScanDirectory,
  readScanFile,
  validatedFileDigests,
} from "./contract.js";
import type { ScanCost, ScanUsageMeasurement } from "./cost.js";
import { BatchCostPool, batchScanBudget } from "./batch-cost.js";
import { deepScanOptions } from "./deep-config.js";
import { readThreatModelPath } from "./artifact-export.js";
import {
  ContractValidationError,
  OutputDirectoryNotEmptyError,
  InvalidTargetError,
  errorMessage,
  ScanCostLimitExceededError,
} from "./errors.js";
import { isExplicitPathWithTrailingWhitespace } from "./executable-path.js";
import { isRecord } from "./record.js";
import {
  readKnowledgeBaseSnapshot,
  type KnowledgeBaseSnapshot,
} from "./knowledge-base.js";
import { type DocumentRoots, resolveScanPrompts } from "./prompt-files.js";
import {
  bundledPluginRoot,
  canonicalConfigPath,
  createWindowsOutputDirectory,
  environmentValue,
  expandHome,
  expandHomeForLookup,
  isPythonPathCandidate,
  executablePathForSpawn,
  pluginHelperEnvironment,
  requireSecureOutputAncestry,
  requireWindowsOutputPath,
  validateOutputDir,
  resolvePluginPath,
  resolvePluginPythonCommand,
} from "./runtime.js";
import {
  DiffTarget,
  normalizeTarget,
  gitOutput,
  gitProtectionRoots,
  nullIfMissingPath,
  UNSUPPORTED_GIT_ENVIRONMENT,
  relativePathIsOutside,
  resolveTargetPath,
  type ScanMode,
} from "./targets.js";
import {
  meetsSeverity,
  type ScanPromptSettings,
  type ScanSettings,
} from "./scan-settings.js";
import { workflowDigest, scanRequestDigest } from "./finding-workflow.js";
import type { ScanResult } from "./result.js";
import {
  readRegisteredScanAuthority,
  type RegisteredScanAuthority,
} from "./saved-scan-bootstrap.js";
import {
  resolveTrustedExecutable,
  withProtectedExecutableRoots,
} from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const CHECKOUT_MARKER = ".git/codex-security-campaign-attempt";
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
  targetId?: string;
  scanId?: string;
  resolvedScope?: string;
  snapshotDigest?: string;
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
  /** @internal Environment of the invoking CLI dependency. */
  environment?: NodeJS.ProcessEnv;
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
  const output = await ensureOutputDirectory(requestedOutput, {
    retainedDirectory: "artifacts",
  });
  if (process.platform !== "win32") await requireSecureOutputAncestry(output);
  const unlock = await acquireLock(output);
  let pluginWorkspace: string | undefined;
  let pluginRoot: Promise<string> | undefined;
  const resolveResumePluginRoot = (): Promise<string> =>
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
          resolveResumePluginRoot,
          documentRoots,
        ),
    );
    return (await realpath(requestedOutput).catch(() => undefined)) === output
      ? { ...result, resultsPath: join(requestedOutput, "results.jsonl") }
      : result;
  } finally {
    if (pluginWorkspace !== undefined) {
      await rm(pluginWorkspace, { recursive: true, force: true }).catch(
        () => undefined,
      );
    }
    await unlock();
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
  resolveResumePluginRoot: () => Promise<string>,
  documentRoots: () => Promise<DocumentRoots>,
): Promise<MultiscanResult> {
  const environment = options.environment ?? process.env;
  const ledger = join(output, "results.jsonl");
  const checkoutRoot = await ensureOutputDirectory(join(output, "checkouts"));
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
  const pending: {
    task: MultiscanTask;
    receipt: MultiscanReceipt | undefined;
    maxAttempt: number;
  }[] = [];
  const restoreReport = async (
    scanDir: string,
    schemaPluginRoot: string,
    protectedRoot: string,
  ): Promise<void> => {
    try {
      // Configured historical archives may contain schemas without helper scripts.
      const [python, helperRoot] = await Promise.all([
        resolvePluginPythonCommand({
          configuredPath: options.config.pythonPath,
          environment: pluginHelperEnvironment(environment),
          protectedRoot,
          signal: options.signal,
        }),
        bundledPluginRoot(),
      ]);
      await execFile(
        executablePathForSpawn(python.executable),
        [
          "-I",
          "-X",
          "utf8",
          "-B",
          join(helperRoot, "scripts", "finalize_scan_contract.py"),
          "--scan-dir",
          scanDir,
          "--schema-dir",
          join(schemaPluginRoot, "schemas"),
          "--report-only",
        ],
        {
          env: python.environment,
          maxBuffer: Infinity,
          windowsHide: true,
          signal: options.signal,
        },
      );
      options.signal?.throwIfAborted();
    } catch (error) {
      if (options.signal?.aborted) options.signal.throwIfAborted();
      throw new Error(
        `Multiscan report recovery is required: ${errorMessage(error)}`,
      );
    }
  };
  const rejectedAttempts = new Set<string>();
  let completed = 0;
  let policyFailed = false;
  const warnings: NonNullable<MultiscanResult["warnings"]> = [];
  const hasPolicy = Object.values(options.scanOptionsByMode ?? {}).some(
    (settings) => settings.failureSeverity !== undefined,
  );
  let untouched = 0;
  for (const task of tasks) {
    const history = receipts.get(task.id.toLowerCase());
    const saved = history?.scan;
    const receipt = saved && matchesTask(saved, task) ? saved : undefined;
    if (saved !== undefined && receipt === undefined) {
      rejectedAttempts.add(
        join(output, "artifacts", task.id, `attempt-${saved.attempt}`),
      );
    }
    const work = { task, receipt, maxAttempt: history?.maxAttempt ?? 0 };
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
      pending.push(work);
      continue;
    }
    const artifactRoot = await ensureOutputDirectory(
      join(output, "artifacts", task.id),
    );
    const attemptName = `attempt-${receipt.attempt}`;
    const artifactOutput = join(artifactRoot, attemptName);
    const selectedArtifactOutput = join(
      resolve(options.outputDir),
      "artifacts",
      task.id,
      attemptName,
    );
    const completedReceipt =
      receipt.status === "completed" ||
      (receipt.status === "failed" &&
        receipt.error === "Multiscan repository coverage is incomplete.");
    const selectedOutputMatches =
      receipt.outputDir === artifactOutput ||
      receipt.outputDir === selectedArtifactOutput;
    if (selectedOutputMatches) {
      const schemaPluginRoot = await resolveResumePluginRoot();
      const loaded = await readCampaignContract(
        artifactOutput,
        schemaPluginRoot,
        options.signal,
      );
      if (
        completedReceipt &&
        loaded?.contract.manifest.scan.status !== "completed"
      ) {
        rejectedAttempts.add(artifactOutput);
        pending.push(work);
        continue;
      }
      const canonicalArtifactOutput = await realpath(artifactOutput).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT" || error.code === "ENOTDIR") {
            return undefined;
          }
          throw error;
        },
      );
      if (canonicalArtifactOutput === undefined) {
        pending.push(work);
        continue;
      }

      if (
        relative(
          join(output, "artifacts", task.id, attemptName),
          canonicalArtifactOutput,
        ) !== ""
      ) {
        throw new Error(
          "Multiscan recovery is required: saved artifacts are outside their expected campaign directory.",
        );
      }
      const checkout = join(checkoutRoot, task.id);
      const resumed = await loadResumableScan(
        loaded,
        options,
        artifactOutput,
        schemaPluginRoot,
        receipt,
        checkout,
        (registered) =>
          matchesRegisteredRequest(
            registered,
            options,
            task,
            artifactOutput,
            knowledgeByMode[task.mode]?.snapshot,
            receipt.operationId,
          ),
        restoreReport,
        (warning) => {
          warnings.push({ repository: task.id, warnings: [warning] });
          notifyProgress(options, {
            repository: task.id,
            status: receipt.status,
            attempt: receipt.attempt,
            warning,
          });
        },
      );
      if (resumed !== undefined) {
        if (receipt.status !== "failed" && receipt.warnings?.length) {
          warnings.push({ repository: task.id, warnings: receipt.warnings });
          for (const warning of receipt.warnings) {
            notifyProgress(options, {
              repository: task.id,
              status: receipt.status,
              attempt: receipt.attempt,
              warning,
            });
          }
        }
        const failureSeverity =
          options.scanOptionsByMode?.[task.mode]?.failureSeverity;
        policyFailed ||=
          failureSeverity !== undefined &&
          resumed.findings.some((finding) =>
            meetsSeverity(finding, failureSeverity),
          );
        completed += 1;
        continue;
      }
    }
    pending.push(work);
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
      const work = pending[next++];
      if (work === undefined) return;
      const { task, receipt: previous } = work;
      const knowledge = knowledgeByMode[task.mode];
      const scanSettings = options.scanOptionsByMode?.[task.mode];
      const budget = batchScanBudget(pool?.share, {
        ...options,
        maxCostUsd: options.maxCostUsd ?? scanSettings?.maxCostUsd,
      });
      let operationId = previous?.operationId;
      let maxAttempt = work.maxAttempt;
      const nextAttempt = () => {
        if (maxAttempt === Number.MAX_SAFE_INTEGER)
          throw new AttemptNumberExhaustedError(
            `No more attempt numbers are available for ${task.id}. Start a separate campaign in a new --output-dir.`,
          );
        return ++maxAttempt;
      };
      let recoveryAttempt = previous?.attempt ?? 0;
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
        let protectedRoot = join(checkoutRoot, task.id);
        let attemptedResume = false;
        let failure: string | undefined;
        let cleanupFailure: string | undefined;
        const runWarnings: string[] = [];
        let attemptPolicyFailed: boolean | undefined;
        let targetId: string | undefined;
        let scanId: string | undefined;
        let resolvedScope: string | undefined;
        let snapshotDigest: string | undefined;
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
            !rejectedAttempts.has(scanDir)
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
                undefinedIfMissingFile,
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
              const authority = await readRegisteredScanAuthority(
                scanDir,
                environment,
                options.signal,
              );
              const recorded =
                previous?.attempt === attempt ? previous : undefined;
              const normalCheckout = join(checkoutRoot, task.id);
              const roots = await campaignCheckoutRoots(
                normalCheckout,
                retainedCheckout,
                authority !== undefined &&
                  resolve(authority.target_path) !== resolve(normalCheckout),
              );
              const matchesRequest = (registered: RegisteredScanAuthority) =>
                matchesRegisteredRequest(
                  registered,
                  options,
                  task,
                  scanDir,
                  knowledge?.snapshot,
                  recorded?.operationId,
                );
              if (
                authority !== undefined &&
                registeredTaskMatches(authority, task.revision, roots) &&
                (recorded?.scanId === undefined ||
                  recorded.scanId === authority.id) &&
                matchesRequest(authority)
              ) {
                protectedRoot = authority.target_path;
                const loadRegistered = async () => {
                  const accepted = await loadRegisteredCampaignScan(
                    await readCampaignContract(
                      scanDir,
                      await resolveResumePluginRoot(),
                      options.signal,
                    ),
                    matchesRequest,
                    environment,
                    options.signal,
                  );
                  if (accepted instanceof Error) throw accepted;
                  if (accepted === undefined) return undefined;
                  const root = await verifiedCampaignCheckout(
                    accepted,
                    options,
                    task,
                    normalCheckout,
                    retainedCheckout,
                    recorded,
                  );
                  return root === undefined ? undefined : accepted;
                };
                if (
                  authority.status !== "complete" ||
                  (await loadRegistered()) !== undefined
                ) {
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
                  if (result !== undefined) {
                    const accepted = await loadRegistered();
                    result =
                      accepted !== undefined &&
                      (await hasCampaignReport(scanDir))
                        ? { ...result, ...accepted.contract }
                        : undefined;
                  }
                }
              }
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
            const normalCheckout = join(checkoutRoot, task.id);
            if (options.recoverScan === undefined) {
              try {
                if (attempt === 1) {
                  await mkdir(normalCheckout, { mode: 0o700 });
                  checkout = normalCheckout;
                } else if (
                  await lstat(normalCheckout).catch(undefinedIfMissingFile)
                ) {
                  checkoutOccupied = true;
                }
              } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "EEXIST")
                  throw error;
                checkoutOccupied = true;
              }
              if (checkoutOccupied) {
                requiresRecovery = true;
                throw new Error(
                  `Bulk checkout is already occupied: ${normalCheckout}. Retry with --recover to use a fresh checkout, or inspect and move the retained checkout before an ordinary retry.`,
                );
              }
            }
            // Each new Git checkout has a distinct history identity. Recreating
            // it at a previously registered path would invalidate that binding.
            if (checkout === undefined) {
              const isolatedRoot = await ensureOutputDirectory(
                join(output, "recovery-checkouts"),
              );
              const taskRoot = await ensureOutputDirectory(
                join(isolatedRoot, task.id),
              );
              const isolatedCheckout = join(taskRoot, `attempt-${attempt}`);
              if (options.recoverScan !== undefined)
                await mkdir(scanDir, { mode: 0o700 });
              await mkdir(isolatedCheckout, { mode: 0o700 });
              checkout = isolatedCheckout;
            }
            protectedRoot = checkout;
            // Claim the fresh checkout before Git or the scanner can fail.
            await claimCheckout(checkout, scanDir);
            await checkoutRevision(
              task,
              checkout,
              options.signal,
              options.githubHost,
            );
            const gitDir = join(checkout, ".git");
            if (
              relative(await realpath(gitDir), gitDir) !== "" ||
              !(await lstat(gitDir)).isDirectory()
            )
              throw new Error(
                "The campaign checkout must have a real Git directory.",
              );
            if (task.scope !== undefined) {
              const scoped = await realpath(join(checkout, task.scope));
              const outside = relative(await realpath(checkout), scoped);
              if (relativePathIsOutside(outside)) {
                throw new Error("Multiscan scope escapes its repository.");
              }
              resolvedScope = outside.split(sep).join("/") || ".";
            }
            operationId ??= randomUUID();
            result = await security.run(checkout, {
              ...campaignScanOptions(
                options,
                task,
                scanDir,
                checkout,
                knowledge?.snapshot,
              ),
              telemetryContext: { operationId },
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
          if (task.scope !== undefined) {
            resolvedScope ??= result.manifest?.scan.scope.includePaths[0];
            if (resolvedScope === undefined) {
              const saved = await loadContract(scanDir, {
                pluginRoot: await resolveResumePluginRoot(),
                signal: options.signal,
              });
              resolvedScope = saved.manifest.scan.scope.includePaths[0];
            }
          }
          targetId = result.manifest?.scan.target.targetId;
          scanId = result.manifest?.scan.id;
          snapshotDigest = result.manifest?.scan.target.snapshotDigest;
          const failureSeverity =
            options.scanOptionsByMode?.[task.mode]?.failureSeverity;
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
          if (error instanceof OutputDirectoryNotEmptyError) {
            requiresRecovery = true;
            failure = `Bulk attempt directory is not empty: ${scanDir}. Inspect the preserved artifacts before running the same bulk-scan command with --recover.`;
          } else {
            failure = errorMessage(error);
          }
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
        if (
          threatModelPath === undefined &&
          !requiresRecovery &&
          (checkout !== undefined || attemptedResume)
        )
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
          ...(targetId === undefined ? {} : { targetId }),
          ...(scanId === undefined ? {} : { scanId }),
          ...(resolvedScope === undefined ? {} : { resolvedScope }),
          ...(snapshotDigest === undefined ? {} : { snapshotDigest }),
          ...(threatModelPath === null ? {} : { threatModelPath }),
          ...(cost === null ? {} : { cost }),
          ...(measurement === null ? {} : { measurement }),
          ...(savedUsage === undefined ? {} : { usage: savedUsage }),
          outcome: options.signal?.aborted ? "canceled" : status,
          ...(reportedError === undefined ? {} : { error: reportedError }),
          ...(recoveryCheckout !== undefined
            ? { cleanupPending: "recovery-checkout" }
            : failure === undefined && cleanupFailure !== undefined
              ? {
                  cleanupPending:
                    checkout === join(checkoutRoot, task.id)
                      ? "checkout"
                      : "recovery-checkout",
                }
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

// A checkout path can be reused after cleanup. Its marker belongs to this
// directory identity and this scan attempt, including across process restarts.
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

async function claimCheckout(checkout: string, scanDir: string): Promise<void> {
  const marker = await checkoutMarker(checkout, scanDir);
  await mkdir(join(checkout, ".git"), { mode: 0o700 });
  await writeFile(join(checkout, CHECKOUT_MARKER), marker, {
    flag: "wx",
    mode: 0o600,
  });
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
  {
    privateGitMetadata = false,
    retainedDirectory,
  }: { privateGitMetadata?: boolean; retainedDirectory?: string } = {},
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
  const owner = process.geteuid?.();
  if (owner !== undefined && directory.uid !== BigInt(owner)) {
    throw new Error(
      "Multiscan output directories must be owned by the current user.",
    );
  }
  if ((directory.mode & 0o022n) !== 0n) {
    if (privateGitMetadata) await chmod(canonical, 0o700);
    else
      throw new Error(
        "Multiscan output directories must not be group- or world-writable.",
      );
  }
  return canonical;
}

async function canonicalCreationPath(path: string): Promise<string> {
  let ancestor = dirname(path);
  for (;;) {
    try {
      return resolve(await realpath(ancestor), relative(ancestor, path));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      const parent = dirname(ancestor);
      if (parent === ancestor) throw error;
      ancestor = parent;
    }
  }
}

async function canonicalPythonPath(path: string): Promise<string> {
  try {
    await realpath(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    for (let ancestor = path; ; ancestor = dirname(ancestor)) {
      const metadata = await lstat(ancestor).catch(undefinedIfMissingFile);
      if (metadata?.isSymbolicLink()) {
        const target = await readlink(ancestor);
        return canonicalPythonPath(
          (isAbsolute(target)
            ? target
            : `${dirname(ancestor)}${sep}${target}`) +
            path.slice(ancestor.length),
        );
      }
      if (metadata !== undefined || dirname(ancestor) === ancestor) break;
    }
  }
  return canonicalCreationPath(path);
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

function matchesTask(receipt: MultiscanReceipt, task: MultiscanTask): boolean {
  return (
    receipt.id === task.id &&
    receipt.repository === task.repository &&
    receipt.revision === task.revision &&
    receipt.mode === task.mode &&
    receipt.scope === task.scope &&
    receipt.prompt === task.prompt
  );
}

function parseReceipt(
  path: string,
  line: string,
  lineNumber: number,
): MultiscanReceipt {
  let value: unknown;
  const invalid = `${path}:${lineNumber}: Multiscan recovery is required: results line ${lineNumber} is not a valid receipt.`;
  const recovery =
    "Restore a complete ledger backup that includes every committed attempt, or start a separate campaign in a new --output-dir.";
  try {
    value = JSON.parse(line);
  } catch (cause) {
    throw new Error(`${invalid} ${errorMessage(cause)}. ${recovery}`, {
      cause,
    });
  }
  if (!isRecord(value) || typeof value["id"] !== "string")
    throw new Error(`${invalid} ${recovery}`);
  const attempt = value["attempt"];
  if (
    typeof attempt !== "number" ||
    !Number.isSafeInteger(attempt) ||
    attempt < 1
  )
    throw new Error(
      `${invalid} Expected a positive integer receipt attempt. ${recovery}`,
    );
  if (
    !["repository", "revision", "outputDir"].every(
      (field) => typeof value[field] === "string",
    ) ||
    (value["mode"] !== "standard" && value["mode"] !== "deep") ||
    !["completed", "completed_with_incomplete_coverage", "failed"].includes(
      value["status"] as string,
    ) ||
    ![
      "scope",
      "prompt",
      "targetId",
      "scanId",
      "operationId",
      "resolvedScope",
      "snapshotDigest",
      "error",
      "warning",
    ].every(
      (field) => value[field] === undefined || typeof value[field] === "string",
    ) ||
    (value["warnings"] !== undefined &&
      !(
        Array.isArray(value["warnings"]) &&
        value["warnings"].every((warning) => typeof warning === "string")
      )) ||
    (value["knowledgeBaseFailure"] !== undefined &&
      value["knowledgeBaseFailure"] !== true) ||
    (value["checkoutOccupied"] !== undefined &&
      (value["checkoutOccupied"] !== true || value["status"] !== "failed")) ||
    (value["coverage"] !== undefined &&
      !["complete", "partial", "unknown"].includes(value["coverage"] as string))
  ) {
    throw new Error(`${invalid} ${recovery}`);
  }
  if (value["status"] === "completed_with_incomplete_coverage")
    value["status"] = "completed";
  return value as unknown as MultiscanReceipt;
}

async function readReceipts(
  path: string,
  preserveInterrupted = false,
): Promise<Map<string, MultiscanHistory>> {
  let contents: Buffer;
  try {
    contents = await readFile(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return new Map();
    }
    throw error;
  }
  const end = contents.lastIndexOf(10) + 1;
  const lines = contents.subarray(0, end).toString("utf8").split("\n");
  const receipts = new Map<string, MultiscanHistory>();
  for (const [index, line] of lines.entries()) {
    if (!line) continue;
    const receipt = parseReceipt(path, line, index + 1);
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
  if (end < contents.length) {
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

function campaignScanOptions(
  options: MultiscanOptions,
  task: MultiscanTask,
  scanDir: string,
  checkout: string,
  knowledgeBaseSnapshot?: KnowledgeBaseSnapshot,
): ScanOptions {
  const scanPrompt = [options.scanPrompt?.trim(), task.prompt]
    .filter(Boolean)
    .join("\n\n");
  return {
    ...options.scanOptionsByMode?.[task.mode],
    knowledgeBaseSnapshot,
    ...(task.scope === undefined
      ? {}
      : { target: [resolve(checkout, task.scope)] }),
    ...(options.knowledgeBasePaths?.length
      ? { knowledgeBasePaths: options.knowledgeBasePaths }
      : {}),
    mode: task.mode,
    outputDir: scanDir,
    ...(scanPrompt ? { scanPrompt } : {}),
    ...(options.validationPrompt === undefined
      ? {}
      : { validationPrompt: options.validationPrompt }),
    ...(options.postScanPrompt === undefined
      ? {}
      : { postScanPrompt: options.postScanPrompt }),
    ...(options.maxCostUsd === undefined
      ? {}
      : { maxCostUsd: options.maxCostUsd }),
  };
}

function matchesRegisteredRequest(
  { recipe, target_path: checkout }: RegisteredScanAuthority,
  options: MultiscanOptions,
  task: MultiscanTask,
  scanDir: string,
  knowledgeBaseSnapshot?: KnowledgeBaseSnapshot,
  operationId?: string,
): boolean {
  const saved = recipe["scanRequestDigest"];
  if (typeof saved !== "string") return false;
  const scan = campaignScanOptions(
    options,
    task,
    scanDir,
    checkout,
    knowledgeBaseSnapshot,
  );
  const matches = (settings: ScanOptions): boolean => {
    if (scanRequestDigest(options.config, settings, checkout) === saved)
      return true;
    if (Array.isArray(settings.target)) {
      // A legacy digest could collapse symlink/.. traversal. Confirm the
      // scope against the private registration before accepting that digest.
      const scope = recipe["target"];
      const paths =
        isRecord(scope) && scope["kind"] === "paths"
          ? scope["paths"]
          : undefined;
      const lexical = settings.target.map(
        (path) =>
          relative(checkout, resolve(checkout, path)).split(sep).join("/") ||
          ".",
      );
      if (
        !Array.isArray(paths) ||
        settings.target.some((path) => path.split(sep).includes("..")) ||
        lexical.length !== paths.length ||
        !lexical.every((path, index) => path === paths[index])
      )
        return false;
      if (scanRequestDigest(options.config, settings) === saved) return true;
      settings = { ...settings, target: lexical };
    }
    return (
      scanRequestDigest(options.config, settings) === saved ||
      (operationId !== undefined &&
        scanRequestDigest(options.config, settings, undefined, {
          operationId,
        }) === saved)
    );
  };
  if (matches(scan)) return true;
  // A batch reservation sets these execution options for just this attempt.
  const limit = recipe["maxCostUsd"];
  return (
    options.maxTotalCostUsd !== undefined &&
    typeof limit === "number" &&
    recipe["ownerSuggestions"] === false &&
    (scan.maxCostUsd === undefined || limit <= scan.maxCostUsd) &&
    matches({
      ...scan,
      maxCostUsd: limit,
      skipFindingMatching: true,
      ownerSuggestions: false,
    })
  );
}

function registeredTaskMatches(
  authority: RegisteredScanAuthority,
  revision: string,
  targetRoots: readonly string[],
): boolean {
  return (
    authority.target_revision === revision &&
    targetRoots.some((root) => resolve(root) === resolve(authority.target_path))
  );
}

async function campaignCheckoutRoots(
  checkout: string,
  recoveryCheckout: string,
  validateRecoveryParents: boolean,
): Promise<string[]> {
  if (process.platform === "win32" && validateRecoveryParents) {
    // Validate lexical parents before canonicalization follows Windows aliases.
    for (const parent of [
      dirname(dirname(recoveryCheckout)),
      dirname(recoveryCheckout),
    ]) {
      if (await lstat(parent).catch(undefinedIfMissingFile))
        await ensureOutputDirectory(parent);
    }
  }
  return [
    checkout,
    process.platform === "win32"
      ? await canonicalCreationPath(recoveryCheckout)
      : recoveryCheckout,
  ];
}

function readCampaignContract(
  path: string,
  pluginRoot: string,
  signal?: AbortSignal,
) {
  return loadContractWithScanDirectory(path, {
    validateRecoveryCoverage: true,
    pluginRoot,
    signal,
  }).catch((error: unknown) => {
    signal?.throwIfAborted();
    if (error instanceof ContractSchemaError) throw error;
    return undefined;
  });
}

type CampaignContract = Awaited<ReturnType<typeof readCampaignContract>>;

async function loadRegisteredCampaignScan(
  loaded: CampaignContract,
  matchesRequest: (authority: RegisteredScanAuthority) => boolean,
  environment: NodeJS.ProcessEnv,
  signal?: AbortSignal,
) {
  if (loaded === undefined) return undefined;
  const authority = await readRegisteredScanAuthority(
    loaded.scanDirectory,
    environment,
    signal,
  );
  if (authority === undefined) return undefined;
  if (authority.id !== loaded.contract.manifest.scan.id)
    return new ContractValidationError(
      `Scan artifacts do not match selected scan ${authority.id}.`,
    );
  if (
    authority.status !== "complete" ||
    !matchesRequest(authority) ||
    authority.seal_manifest_digest !==
      `sha256:${validatedFileDigests.get(loaded.contract.manifest)!.get("scan-manifest.json")!}`
  )
    return undefined;
  return { contract: loaded.contract, authority };
}

async function hasCampaignReport(scanDir: string): Promise<boolean> {
  const report = await lstat(join(scanDir, "report.md")).catch(
    undefinedIfMissingFile,
  );
  return report?.isFile() === true;
}

async function loadResumableScan(
  loaded: CampaignContract,
  options: MultiscanOptions,
  path: string,
  pluginRoot: string,
  receipt: MultiscanReceipt,
  checkout: string,
  matchesRequest: (authority: RegisteredScanAuthority) => boolean,
  restoreReport: (
    scanDir: string,
    schemaRoot: string,
    protectedRoot: string,
  ) => Promise<void>,
  onWarning: (warning: string) => void,
) {
  const { signal, recoverScan } = options;
  const environment = options.environment ?? process.env;
  const accepted = await loadRegisteredCampaignScan(
    loaded,
    matchesRequest,
    environment,
    signal,
  );
  if (accepted instanceof Error) {
    // Registered report recovery must retain its selected-scan integrity error.
    // Otherwise invalid saved evidence starts a new scan at the original CSV target.
    if (
      recoverScan !== undefined &&
      (await lstat(join(path, "report.md")).catch(undefinedIfMissingFile)) ===
        undefined
    )
      throw accepted;
    return undefined;
  }
  if (accepted === undefined) return undefined;
  if (
    receipt.status !== "completed" &&
    !(
      receipt.status === "failed" &&
      receipt.error === "Multiscan repository coverage is incomplete."
    )
  )
    return undefined;
  const campaignRoot = dirname(dirname(dirname(path)));
  const recoveryCheckout = join(
    campaignRoot,
    "recovery-checkouts",
    receipt.id,
    `attempt-${receipt.attempt}`,
  );
  let createdCheckout: string | undefined;
  const restorePaths = async (root: string, paths: readonly string[]) => {
    if (root !== checkout) {
      await ensureOutputDirectory(join(campaignRoot, "recovery-checkouts"));
      await ensureOutputDirectory(dirname(recoveryCheckout));
    }
    try {
      await mkdir(root, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await ensureOutputDirectory(root);
      await checkoutRevision(
        receipt,
        root,
        signal,
        options.githubHost,
        true,
        paths,
      );
      return;
    }
    createdCheckout = root;
    await claimCheckout(root, path);
    await checkoutRevision(receipt, root, signal, options.githubHost);
  };
  try {
    const matchedRoot = await verifiedCampaignCheckout(
      accepted,
      options,
      receipt,
      checkout,
      recoveryCheckout,
      receipt,
      restorePaths,
    );
    if (matchedRoot === undefined) return undefined;
    const reportSealed = await hasSealedReport(
      path,
      accepted.contract.manifest,
      signal,
    );
    const reportMissing =
      (await lstat(join(path, "report.md")).catch(undefinedIfMissingFile)) ===
      undefined;
    if (reportMissing && recoverScan !== undefined) {
      if ((await recoverScan(path, options)) === undefined) return undefined;
      const recovered = await loadRegisteredCampaignScan(
        await readCampaignContract(path, pluginRoot, signal),
        matchesRequest,
        environment,
        signal,
      );
      if (recovered instanceof Error) throw recovered;
      if (
        recovered === undefined ||
        recovered.authority.seal_manifest_digest !==
          accepted.authority.seal_manifest_digest
      )
        return undefined;
    }
    if (
      reportMissing &&
      receipt.scanId === undefined &&
      recoverScan === undefined
    )
      return undefined;
    if (!reportSealed) {
      const helperEnvironment = pluginHelperEnvironment(environment);
      const inherited = environmentValue(helperEnvironment, "PYTHON", true);
      const configuredPythonPath =
        options.config.pythonPath ?? inherited?.trim();
      // PATH discovery excludes campaign sources. Only an explicit executable
      // path can refer to an alias that needs restoring in the pinned checkout.
      if (configuredPythonPath && isPythonPathCandidate(configuredPythonPath)) {
        const paths = [configuredPythonPath];
        if (
          options.config.pythonPath === undefined &&
          inherited &&
          isExplicitPathWithTrailingWhitespace(inherited, process.platform)
        ) {
          paths.unshift(inherited);
        }
        for (const pythonPath of paths) {
          const candidate =
            expandHomeForLookup(pythonPath, environment) +
            (process.platform === "win32" && extname(pythonPath) === ""
              ? ".exe"
              : "");
          if (await realpath(candidate).catch(undefinedIfMissingFile)) break;
          const selected = relative(
            matchedRoot,
            await canonicalPythonPath(candidate),
          );
          if (!relativePathIsOutside(selected)) {
            await restorePaths(matchedRoot, [selected]);
            if (await realpath(candidate).catch(undefinedIfMissingFile)) break;
          }
        }
      }
      await restoreReport(path, pluginRoot, matchedRoot);
    }
    if (!(await hasCampaignReport(path))) return undefined;
    // The ledger can request cleanup only of the checkout bound to this scan.
    const cleanupKind =
      matchedRoot === checkout ? "checkout" : "recovery-checkout";
    if (
      createdCheckout === undefined &&
      receipt.status === "completed" &&
      receipt.cleanupPending === cleanupKind
    ) {
      const selected = cleanupKind === "checkout" ? checkout : recoveryCheckout;
      try {
        if (await lstat(selected).catch(undefinedIfMissingFile)) {
          if (cleanupKind === "recovery-checkout")
            await ensureOutputDirectory(dirname(dirname(selected)));
          const parent = await ensureOutputDirectory(dirname(selected));
          if (relative(parent, dirname(matchedRoot)) !== "")
            throw new Error("The registered checkout directory has moved.");
          const warning = await removeCheckout(selected, path, signal);
          if (warning !== undefined) onWarning(warning);
        }
      } catch (error) {
        onWarning(`Multiscan checkout cleanup failed: ${errorMessage(error)}`);
      }
    }
    return accepted.contract.findings;
  } finally {
    if (createdCheckout !== undefined) {
      const warning = await removeCheckout(createdCheckout, path);
      if (warning !== undefined) onWarning(warning);
    }
  }
}

type RegisteredCampaignScan = Exclude<
  Awaited<ReturnType<typeof loadRegisteredCampaignScan>>,
  Error | undefined
>;

async function verifiedCampaignCheckout(
  { contract, authority }: RegisteredCampaignScan,
  options: MultiscanOptions,
  task: MultiscanTask,
  checkout: string,
  recoveryCheckout: string,
  receipt?: MultiscanReceipt,
  restorePaths?: (root: string, paths: readonly string[]) => Promise<void>,
): Promise<string | undefined> {
  const { manifest, mode } = contract;
  const { target, scope, producer } = manifest.scan;
  const requestedTarget =
    task.scope === undefined
      ? options.scanOptionsByMode?.[task.mode]?.target
      : [task.scope];
  const requestedPaths: readonly string[] | undefined = Array.isArray(
    requestedTarget,
  )
    ? requestedTarget
    : undefined;
  const targetIdFor = (root: string) =>
    `target_sha256_${createHash("sha256").update(`local-workspace\0${root}`).digest("hex")}`;
  const targetRoots = await campaignCheckoutRoots(
    checkout,
    recoveryCheckout,
    requestedPaths !== undefined && target.targetId !== targetIdFor(checkout),
  );
  const matchedRoot = targetRoots.find(
    (root) => target.targetId === targetIdFor(root),
  );
  const expectedMode =
    requestedPaths !== undefined
      ? "scoped_path"
      : task.mode === "deep"
        ? "deep_repository"
        : "repository";
  if (
    manifest.scan.status !== "completed" ||
    (receipt?.scanId !== undefined && receipt.scanId !== manifest.scan.id) ||
    producer.name !== "codex-security-plugin" ||
    matchedRoot === undefined ||
    !registeredTaskMatches(authority, task.revision, [matchedRoot]) ||
    (receipt?.targetId !== undefined && receipt.targetId !== target.targetId) ||
    target.kind !== "git_revision" ||
    target.snapshotDigest !== undefined ||
    receipt?.snapshotDigest !== undefined ||
    target.displayName !== basename(matchedRoot) ||
    target.revision !== task.revision ||
    mode !== expectedMode ||
    scope.excludePaths.length !== 0
  )
    return undefined;
  const sealedArtifacts = new Set(
    manifest.scan.artifacts.map(({ path }) => path),
  );
  if (
    !sealedArtifacts.has("findings.json") ||
    (manifest.scan.coverageRef !== undefined &&
      !sealedArtifacts.has(manifest.scan.coverageRef))
  )
    return undefined;
  let expectedPaths: readonly unknown[] = ["."];
  if (requestedPaths !== undefined) {
    const metadata = await lstat(matchedRoot).catch(undefinedIfMissingFile);
    const target = authority.recipe["target"];
    if (metadata === undefined && target !== undefined) {
      // Normal completion removes the checkout. Registration preserves the
      // canonical paths resolved from the authenticated scan request.
      if (
        !isRecord(target) ||
        target["kind"] !== "paths" ||
        !Array.isArray(target["paths"])
      )
        return undefined;
      expectedPaths = target["paths"];
    } else {
      if (metadata === undefined) {
        // Older registrations may need the pinned checkout to resolve a scope.
        if (restorePaths === undefined) return undefined;
        await restorePaths(matchedRoot, requestedPaths);
      } else if (
        !metadata.isDirectory() ||
        relative(await realpath(matchedRoot), matchedRoot) !== ""
      ) {
        return undefined;
      }
      const paths =
        task.scope === undefined
          ? requestedPaths
          : [resolve(matchedRoot, task.scope)];
      try {
        expectedPaths = (
          await normalizeTarget(matchedRoot, paths, options.signal)
        ).paths;
      } catch (error) {
        if (!(error instanceof InvalidTargetError)) throw error;
        if (restorePaths === undefined) return undefined;
        if (!error.message.startsWith("Path target does not exist:"))
          throw error;
        // An interrupted checkout can be missing individual tracked paths.
        await restorePaths(matchedRoot, requestedPaths);
        expectedPaths = (
          await normalizeTarget(matchedRoot, paths, options.signal)
        ).paths;
      }
      if (
        receipt?.scope !== undefined &&
        receipt.resolvedScope === undefined &&
        expectedPaths[0] !== posix.normalize(receipt.scope).replace(/\/+$/u, "")
      )
        return undefined;
    }
  }
  const actualPaths = new Set(scope.includePaths);
  if (
    actualPaths.size !== scope.includePaths.length ||
    actualPaths.size !== expectedPaths.length ||
    !expectedPaths.every(
      (path) => typeof path === "string" && actualPaths.has(path),
    ) ||
    (receipt?.resolvedScope !== undefined &&
      (expectedPaths.length !== 1 ||
        receipt.resolvedScope !== expectedPaths[0]))
  )
    return undefined;
  return matchedRoot;
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
    if (
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(id) ||
      id.endsWith(".") ||
      WINDOWS_DEVICE_PATH_NAME.test(id)
    ) {
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
  restoreIncomplete = false,
  restorePaths: readonly string[] = ["."],
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
    restoreIncomplete ? [process.cwd(), path] : process.cwd(),
  );
  if (command === null) {
    throw new Error("Git is not available on a trusted PATH.");
  }
  const gitDirectory = join(path, ".git");
  const retained =
    restoreIncomplete &&
    (await lstat(gitDirectory).catch(undefinedIfMissingFile));
  // The retained repository's configuration must remain usable throughout repair.
  // Use a private Git directory for configuration and refs, sharing only its objects and index.
  await using repair = retained
    ? {
        directory: await mkdtemp(join(dirname(path), ".repair-git-")),
        async [Symbol.asyncDispose]() {
          await rm(this.directory, { recursive: true, force: true });
        },
      }
    : undefined;
  const gitOptions: string[] = [];
  const gitEnvironment = { ...command.environment };
  const gitOutput = async (
    args: string[],
    input?: string | Buffer,
  ): Promise<Buffer> => {
    // Use the resolved absolute path so Windows PATHEXT cannot prefer a
    // .bat/.cmd shim over the trusted executable selected above.
    const pending = execFile(
      command.executable,
      [
        "--no-replace-objects",
        "-c",
        "core.hooksPath=/dev/null",
        ...buildGitHubCredentialArgs(githubHost),
        "-C",
        path,
        ...gitOptions,
        ...args,
      ],
      {
        env: gitEnvironment,
        signal,
        maxBuffer: Infinity,
        encoding: "buffer",
      },
    );
    let inputError: Error | undefined;
    if (input !== undefined) {
      pending.child.stdin!.on("error", (error: Error) => {
        inputError = error;
      });
      pending.child.stdin!.end(input);
    }
    const output = await pending;
    if (inputError !== undefined) throw inputError;
    return output.stdout;
  };
  const git = async (...args: string[]): Promise<string> =>
    (await gitOutput(args)).toString("utf8").trim();
  let retainedHead: string | undefined;
  if (repair) {
    const canonicalGit = await ensureOutputDirectory(gitDirectory, {
      privateGitMetadata: true,
    });
    const canonicalObjects = await ensureOutputDirectory(
      join(gitDirectory, "objects"),
      { privateGitMetadata: true },
    );
    for (const entry of await readdir(canonicalObjects)) {
      if (/^[0-9a-f]{2}$/.test(entry))
        await ensureOutputDirectory(join(canonicalObjects, entry), {
          privateGitMetadata: true,
        });
    }
    if (
      await lstat(join(canonicalObjects, "pack")).catch(undefinedIfMissingFile)
    )
      await ensureOutputDirectory(join(canonicalObjects, "pack"), {
        privateGitMetadata: true,
      });
    for (const entry of [
      "config",
      "config.worktree",
      "FETCH_HEAD",
      "shallow",
      "index",
      "logs",
      "logs/HEAD",
    ]) {
      const saved = await lstat(join(gitDirectory, entry)).catch(
        undefinedIfMissingFile,
      );
      if (
        saved?.isSymbolicLink() ||
        ((entry === "FETCH_HEAD" || entry === "logs/HEAD") &&
          saved !== undefined &&
          saved.nlink > 1)
      ) {
        throw new Error(
          "The retained campaign checkout has linked Git metadata write destinations.",
        );
      }
    }
    await ensureOutputDirectory(join(gitDirectory, "refs"), {
      privateGitMetadata: true,
    });
    const commonBinding = await readFile(
      join(gitDirectory, "commondir"),
      "utf8",
    ).catch(undefinedIfMissingFile);
    if (
      commonBinding !== undefined &&
      (await realpath(resolve(gitDirectory, commonBinding.trim()))) !==
        canonicalGit
    )
      throw new Error(
        "The retained campaign checkout has Git bindings outside its own directory.",
      );

    // Reading the ref needs neither a worktree checkout nor the retained filters.
    if (await lstat(join(canonicalGit, "HEAD")).catch(undefinedIfMissingFile)) {
      retainedHead = await git(
        "--git-dir",
        canonicalGit,
        "--work-tree",
        path,
        "rev-parse",
        "--verify",
        "--quiet",
        "HEAD",
      ).catch((error: unknown) => {
        if ((error as { code?: number }).code === 1) return undefined;
        throw error;
      });
    }
    gitOptions.push("--git-dir", repair.directory, "--work-tree", path);
    gitEnvironment["GIT_OBJECT_DIRECTORY"] = canonicalObjects;
    gitEnvironment["GIT_INDEX_FILE"] = join(canonicalGit, "index");
    const configured = async (
      file: string,
      key: string,
      type: "bool" | "path",
    ): Promise<string | undefined> => {
      try {
        const value = await gitOutput([
          "config",
          "--null",
          "--no-includes",
          "--file",
          file,
          `--type=${type}`,
          "--get",
          key,
        ]);
        return value.subarray(0, -1).toString("utf8");
      } catch (error) {
        if ((error as { code?: number }).code === 1) return undefined;
        throw error;
      }
    };
    const local = join(canonicalGit, "config");
    const layers = [
      local,
      ...((await configured(local, "extensions.worktreeConfig", "bool")) ===
      "true"
        ? [join(canonicalGit, "config.worktree")]
        : []),
    ];
    for (const file of layers) {
      const worktree = await configured(file, "core.worktree", "path");
      if (
        worktree !== undefined &&
        (await realpath(
          isAbsolute(worktree) ? worktree : `${gitDirectory}${sep}${worktree}`,
        )) !== (await realpath(path))
      )
        throw new Error(
          "The retained campaign checkout has Git bindings outside its own directory.",
        );
      for (const key of ["core.ignorecase", "core.filemode", "core.symlinks"]) {
        const value = await configured(file, key, "bool");
        if (value !== undefined) gitOptions.push("-c", key + "=" + value);
      }
    }
    await git("init", "--quiet", "--template=");
    if (retainedHead)
      await writeFile(join(repair.directory, "HEAD"), retainedHead + "\n");
    const shallow = await readFile(join(canonicalGit, "shallow")).catch(
      undefinedIfMissingFile,
    );
    if (shallow) await writeFile(join(repair.directory, "shallow"), shallow);
  } else {
    await git("init", "--quiet");
  }
  let locallyPinned = false;
  let incompleteObjects = false;
  if (restoreIncomplete) {
    try {
      await git(
        "rev-parse",
        "--verify",
        "--quiet",
        `${task.revision}^{commit}`,
      );
      const reachable = await git(
        "rev-list",
        "--objects",
        "--missing=print",
        "--no-walk",
        task.revision,
      );
      incompleteObjects = reachable
        .split("\n")
        .some((line) => line.startsWith("?"));
      locallyPinned = !incompleteObjects;
    } catch (error) {
      if ((error as { code?: number }).code !== 1) throw error;
    }
  }
  if (!locallyPinned) {
    await git(
      ...(incompleteObjects ? ["-c", "fetch.negotiationAlgorithm=noop"] : []),
      "fetch",
      "--quiet",
      "--no-tags",
      "--depth=1",
      "--no-auto-gc",
      "--no-write-commit-graph",
      "--",
      task.repository,
      task.revision,
    );
    if (
      repair &&
      (await lstat(join(repair.directory, "shallow")).catch(
        undefinedIfMissingFile,
      ))
    )
      await rename(
        join(repair.directory, "shallow"),
        join(gitDirectory, "shallow"),
      );
  }
  if (
    restoreIncomplete &&
    !(await lstat(join(path, ".git", "index")).catch(undefinedIfMissingFile))
  ) {
    // Rebuild the lost index without restoring unrelated deleted worktree files.
    await git("read-tree", retainedHead || task.revision);
  }
  if (!retainedHead)
    await git(
      "checkout",
      "--quiet",
      "--detach",
      ...(restoreIncomplete ? ["--no-overwrite-ignore"] : []),
      task.revision,
    );
  if (restoreIncomplete) {
    const ignoreCase =
      (
        await git("config", "--bool", "core.ignorecase").catch(
          (error: unknown) => {
            if ((error as { code?: number }).code === 1) return "false";
            throw error;
          },
        )
      ).trim() === "true";
    const comparisonPath = (name: string) =>
      ignoreCase ? name.toLowerCase() : name;
    const links = (await gitOutput(["ls-tree", "-r", "-z", task.revision]))
      .toString("utf8")
      .split("\0")
      .filter((entry) => entry.startsWith("120000 "))
      .map((entry) => entry.slice(entry.indexOf("	") + 1));
    const aliases = new Set<string>();
    const requiredDirectories = new Set<string>();
    const trackedLinkTarget = async (name: string, visited: Set<string>) => {
      visited.add(name);
      aliases.add(name);
      const target = (
        await gitOutput(["show", `${task.revision}:${name}`])
      ).toString("utf8");
      // Preserve ".." after links until the filesystem resolves the path.
      return isAbsolute(target)
        ? target
        : `${path}${sep}${dirname(name)}${sep}${target}`;
    };
    const canonicalTrackedPath = async (
      requested: string,
      visited: Set<string>,
    ): Promise<string> => {
      for (let ancestor = requested; ; ancestor = dirname(ancestor)) {
        try {
          await realpath(ancestor);
          for (const traversal of requested.matchAll(
            /[\\/]\.\.(?=[\\/]|$)/gu,
          )) {
            const directory = await canonicalTrackedPath(
              requested.slice(0, traversal.index),
              new Set(visited),
            );
            if (!relativePathIsOutside(relative(path, directory)))
              requiredDirectories.add(directory);
          }
          return canonicalCreationPath(requested);
        } catch (error) {
          undefinedIfMissingFile(error as NodeJS.ErrnoException);
        }
        const name = links.find(
          (link) =>
            comparisonPath(link) ===
            comparisonPath(relative(path, ancestor).split(sep).join("/")),
        );
        if (name !== undefined && !visited.has(name)) {
          return canonicalTrackedPath(
            (await trackedLinkTarget(name, visited)) +
              requested.slice(ancestor.length),
            visited,
          );
        }
        if (dirname(ancestor) === ancestor)
          return canonicalCreationPath(requested);
      }
    };
    const selectedPaths = new Set<string>();
    for (const requested of restorePaths) {
      let selected =
        relative(
          path,
          await canonicalCreationPath(resolve(path, expandHome(requested))),
        )
          .split(sep)
          .join("/") || ".";
      const visited = new Set<string>();
      for (;;) {
        const name = links.find(
          (link) =>
            comparisonPath(selected) === comparisonPath(link) ||
            comparisonPath(selected).startsWith(comparisonPath(link) + "/"),
        );
        if (name === undefined || visited.has(name)) break;
        selected = posix.join(
          relative(
            path,
            await canonicalTrackedPath(
              await trackedLinkTarget(name, visited),
              visited,
            ),
          )
            .split(sep)
            .join("/"),
          selected.slice(name.length + 1),
        );
      }
      if (!relativePathIsOutside(selected)) selectedPaths.add(selected);
    }
    const restoreAll = selectedPaths.has(".");
    const scopes = [...selectedPaths, ...aliases].map((name) =>
      Buffer.from(comparisonPath(name)),
    );
    const worktreeDeleted = await gitOutput(["ls-files", "--deleted", "-z"]);
    const deletedPaths = Buffer.concat([
      worktreeDeleted,
      await gitOutput([
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=D",
        "--no-renames",
        "-z",
        task.revision,
        "--",
      ]),
    ]);
    const selectedDeleted: Buffer[] = [];
    let start = 0;
    for (
      let end = deletedPaths.indexOf(0);
      end !== -1;
      end = deletedPaths.indexOf(0, start)
    ) {
      const name = deletedPaths.subarray(start, end);
      const comparisonName = ignoreCase
        ? Buffer.from(name.toString("utf8").toLowerCase())
        : name;
      if (
        scopes.some(
          (scope) =>
            restoreAll ||
            comparisonName.equals(scope) ||
            (comparisonName[scope.length] === 47 &&
              comparisonName.subarray(0, scope.length).equals(scope)),
        )
      ) {
        if (await canRestoreDeletedPath(path, name))
          selectedDeleted.push(deletedPaths.subarray(start, end + 1));
      }
      start = end + 1;
    }
    const deleted = Buffer.concat(selectedDeleted);
    if (deleted.length !== 0) {
      await gitOutput(
        [
          "--literal-pathspecs",
          "restore",
          `--source=${task.revision}`,
          "--worktree",
          "--pathspec-from-file=-",
          "--pathspec-file-nul",
        ],
        deleted,
      );
    }
    for (const directory of requiredDirectories)
      await mkdir(directory, { recursive: true });
  }
  if (
    (await git("rev-parse", "HEAD")).toLowerCase() !==
    (retainedHead || task.revision)
  ) {
    throw new Error("Git checkout revision did not match the pinned SHA.");
  }
  if (repair && !retainedHead) {
    // Publish the recovered detached HEAD only after the worktree is ready.
    await rename(join(repair.directory, "HEAD"), join(gitDirectory, "HEAD"));
  }
}

// Git names are raw bytes. Restore missing entries only through real directories.
async function canRestoreDeletedPath(
  root: string,
  name: Buffer,
): Promise<boolean> {
  const prefix = Buffer.from(root + sep);
  for (let end = name.length; end !== -1; end = name.lastIndexOf(47, end - 1)) {
    const candidate = Buffer.concat([prefix, name.subarray(0, end)]);
    try {
      const entry = await lstat(candidate);
      if (end === name.length || !entry.isDirectory()) return false;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOTDIR") return false;
      undefinedIfMissingFile(error as NodeJS.ErrnoException);
    }
  }
  return true;
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
