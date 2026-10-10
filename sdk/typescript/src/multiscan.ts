import { notify } from "./value.js";
import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { realpathSync } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
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
  delimiter,
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
import type { CodexSecurity } from "./api.js";
import type { CodexSecurityConfig } from "./config.js";
import { hasSealedReport, loadContract } from "./contract.js";
import type { ScanCost } from "./cost.js";
import { readThreatModelPath } from "./artifact-export.js";
import {
  OutputDirectoryNotEmptyError,
  InvalidTargetError,
  PluginPythonUnavailableError,
  errorMessage,
  ScanCostLimitExceededError,
} from "./errors.js";
import type { CoverageDocument, FindingsDocument } from "./models.js";
import {
  readKnowledgeBaseSnapshot,
  type KnowledgeBaseSnapshot,
} from "./knowledge-base.js";
import { resolveScanPrompts } from "./prompt-files.js";
import {
  bundledPluginRoot,
  environmentValue,
  expandHome,
  isPythonPathCandidate,
  executablePathForSpawn,
  pluginHelperEnvironment,
  requireSecureOutputAncestry,
  validateOutputDir,
  resolvePluginPath,
  resolvePluginPythonCommand,
} from "./runtime.js";
import {
  DiffTarget,
  normalizeTarget,
  UNSUPPORTED_GIT_ENVIRONMENT,
  relativePathIsOutside,
  type ScanMode,
  type ScanTarget,
} from "./targets.js";
import {
  meetsSeverity,
  type ScanPromptSettings,
  type ScanSettings,
} from "./scan-settings.js";
import { workflowDigest } from "./finding-workflow.js";
import type { ScanResult } from "./result.js";
import {
  inspectTrustedExecutable,
  resolveTrustedExecutable,
} from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const REQUIRED_ARTIFACTS = [
  "scan-manifest.json",
  "findings.json",
  "coverage.json",
  "report.md",
];
const LOCK_LEASE_MS = 30_000;
const LOCK_HEARTBEAT_MS = 5_000;
const WINDOWS_DEVICE_PATH_NAME =
  /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu;

interface MultiscanTask {
  id: string;
  repository: string;
  revision: string;
  mode: ScanMode;
  scope?: string;
  prompt?: string;
}

interface MultiscanReceipt extends MultiscanTask {
  status: "completed" | "completed_with_incomplete_coverage" | "failed";
  attempt: number;
  outputDir: string;
  targetId?: string;
  scanId?: string;
  resolvedScope?: string;
  snapshotDigest?: string;
  threatModelPath?: string;
  coverage?: CoverageDocument["completeness"];
  cost?: ScanCost;
  error?: string;
  warning?: string;
  warnings?: string[];
  policyFailed?: boolean;
  knowledgeBaseFailure?: true;
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
    prompts: ScanPromptSettings & {
      knowledgeBaseSnapshot?: KnowledgeBaseSnapshot;
    },
  ): Promise<Pick<ScanResult, "coverage" | "cost" | "findings"> | undefined>;
  maxCostUsd?: number;
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
    status:
      "started" | "completed" | "completed_with_incomplete_coverage" | "failed";
    attempt: number;
    error?: string;
    warning?: string;
  }): void;
}

export interface MultiscanResult {
  total: number;
  completed: number;
  incomplete: number;
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
    dirname(resolve(options.inputPath)),
    options.mode,
  );
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
  const repositories: string[] = [];
  if (
    [
      [options.scanPrompt, options.scanPromptFile],
      [options.validationPrompt, options.validationPromptFile],
      [options.postScanPrompt, options.postScanPromptFile],
    ].some(([inline, file]) => inline === undefined && file !== undefined)
  ) {
    for (const repository of new Set(tasks.map((task) => task.repository))) {
      if (!isAbsolute(repository)) continue;
      try {
        repositories.push(await realpath(repository));
      } catch (error) {
        // Missing sources retain the campaign's per-repository failure behavior.
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "ENOENT" && code !== "ENOTDIR") throw error;
      }
    }
  }
  // Shared inputs use actual local CSV sources as directory-link boundaries,
  // not the invocation directory, and are read once before any scan starts.
  const prompts = await resolveScanPrompts(options, repositories);
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
  const requestedOutput = resolve(options.outputDir);
  if (options.recoverScan !== undefined) {
    const manifest = await lstat(join(requestedOutput, "manifest.json")).catch(
      undefinedIfMissingFile,
    );
    if (!manifest?.isFile())
      throw new Error("Bulk recovery requires an existing campaign manifest.");
  }
  const output = await ensureOutputDirectory(requestedOutput);
  await requireSecureOutputAncestry(output);
  const unlock = await acquireLock(output);
  let pluginWorkspace: string | undefined;
  let pluginRoot: Promise<string> | undefined;
  const resolveResumePluginRoot = (): Promise<string> =>
    (pluginRoot ??= (async () => {
      if (options.config.pluginPath !== undefined) {
        pluginWorkspace = join(output, `.resume-plugin-${randomUUID()}`);
        await mkdir(pluginWorkspace, { mode: 0o700 });
      }
      return await resolvePluginPath(
        options.config.pluginPath,
        pluginWorkspace ?? output,
        options.signal,
      );
    })());
  try {
    const result = await runCampaign(
      resolvedOptions,
      tasks,
      output,
      resolveResumePluginRoot,
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

async function runCampaign(
  options: MultiscanOptions,
  tasks: MultiscanTask[],
  output: string,
  resolveResumePluginRoot: () => Promise<string>,
): Promise<MultiscanResult> {
  const ledger = join(output, "results.jsonl");
  const checkoutRoot = await ensureOutputDirectory(join(output, "checkouts"));
  await ensureOutputDirectory(join(output, "artifacts"));
  const knowledgeByMode: MultiscanKnowledge = {};
  const sharedKnowledge = options.knowledgeBasePaths?.length
    ? readKnowledgeBaseSnapshot(options.knowledgeBasePaths, options.signal)
    : undefined;
  for (const mode of new Set(tasks.map((task) => task.mode))) {
    try {
      const paths = options.scanOptionsByMode?.[mode]?.knowledgeBasePaths;
      const snapshot = await (sharedKnowledge ??
        (paths?.length
          ? readKnowledgeBaseSnapshot(paths, options.signal)
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
          environment: pluginHelperEnvironment(process.env),
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
  let completed = 0;
  let incomplete = 0;
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
      !matchesTask(receipt, task) ||
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
    const attemptName = `attempt-${receipt.attempt}`;
    const artifactOutput = join(artifactRoot, attemptName);
    const selectedArtifactOutput = join(
      resolve(options.outputDir),
      "artifacts",
      task.id,
      attemptName,
    );
    if (
      receipt.outputDir === artifactOutput ||
      receipt.outputDir === selectedArtifactOutput
    ) {
      const canonicalArtifactOutput = await realpath(artifactOutput).catch(
        (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOENT" || error.code === "ENOTDIR") {
            return undefined;
          }
          throw error;
        },
      );
      if (canonicalArtifactOutput === undefined) {
        pending.push(task);
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
      const schemaPluginRoot = await resolveResumePluginRoot();
      const resumed = await loadResumableScan(
        artifactOutput,
        schemaPluginRoot,
        receipt,
        checkout,
        options.scanOptionsByMode?.[task.mode]?.target,
        options.signal,
        options.githubHost,
        restoreReport,
        options.config.pythonPath ??
          environmentValue(pluginHelperEnvironment(process.env), "PYTHON"),
        options.recoverScan === undefined
          ? undefined
          : (scanDir) => options.recoverScan!(scanDir, options),
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
          failureSeverity !== undefined
            ? resumed.findings.findings.some((finding) =>
                meetsSeverity(finding, failureSeverity),
              )
            : receipt.policyFailed === true;
        if (resumed.completeness === "complete") completed += 1;
        else {
          incomplete += 1;
          notifyProgress(options, {
            repository: task.id,
            status: "completed_with_incomplete_coverage",
            attempt: receipt.attempt,
            warning:
              receipt.warning ??
              `Scan coverage is ${resumed.completeness}; results may be incomplete.`,
          });
        }
        continue;
      }
    }
    pending.push(task);
  }
  const skipped = completed + incomplete + untouched;
  let failed = 0;
  const summarize = (): MultiscanResult => ({
    total: tasks.length,
    completed,
    incomplete,
    failed,
    skipped,
    resultsPath: ledger,
    ...(warnings.length === 0 ? {} : { warnings }),
    ...(hasPolicy ? { policyFailed } : {}),
  });
  if (pending.length === 0) return summarize();

  let next = 0;
  const worker = async (
    security: Pick<CodexSecurity, "run" | "close">,
  ): Promise<void> => {
    for (;;) {
      options.signal?.throwIfAborted();
      const task = pending[next++];
      if (task === undefined) return;
      const knowledge = knowledgeByMode[task.mode];
      const history = receipts.get(task.id.toLowerCase());
      let maxAttempt = history?.maxAttempt ?? 0;
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
        if (options.recoverScan === undefined) attempt = ++maxAttempt;
        else if (retry === 0) attempt = recoveryAttempt;
        let scanDir = join(artifactRoot, `attempt-${attempt}`);
        let checkout: string | undefined;
        let protectedRoot = join(checkoutRoot, task.id);
        let attemptedResume = false;
        let failure: string | undefined;
        let warning: string | undefined;
        const runWarnings: string[] = [];
        let attemptPolicyFailed: boolean | undefined;
        let targetId: string | undefined;
        let scanId: string | undefined;
        let resolvedScope: string | undefined;
        let snapshotDigest: string | undefined;
        let coverage: CoverageDocument["completeness"] | undefined;
        let cost: Readonly<ScanCost> | null = null;
        let threatModelPath: string | null | undefined;
        let exhaustedBudget = false;
        let requiresRecovery = false;
        let knowledgeBaseFailure = false;
        try {
          await ensureOutputDirectory(artifactRoot);
          let result:
            | (Pick<ScanResult, "coverage" | "cost" | "findings"> &
                Partial<Pick<ScanResult, "threatModelPath" | "manifest">>)
            | undefined;
          if (options.recoverScan !== undefined && retry === 0 && attempt > 0) {
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
              });
              if (knowledge?.failure !== undefined) {
                knowledgeBaseFailure = true;
                throw knowledge.failure.error;
              }
              result = await options.recoverScan(scanDir, {
                ...options,
                knowledgeBaseSnapshot: knowledge?.snapshot,
              });
              attemptedResume = result !== undefined;
            }
          }
          const scanSettings = options.scanOptionsByMode?.[task.mode];
          if (result === undefined) {
            if (options.recoverScan !== undefined) attempt = ++maxAttempt;
            scanDir = join(artifactRoot, `attempt-${attempt}`);
            notifyProgress(options, {
              repository: task.id,
              attempt,
              status: "started",
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
              await validateOutputDir(scanDir);
              checkout = join(checkoutRoot, task.id);
              await rm(checkout, { recursive: true, force: true });
              await mkdir(checkout, { mode: 0o700 });
            }
            protectedRoot = checkout;
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
              resolvedScope = outside.split(sep).join("/") || ".";
            }
            const scanPrompt = [options.scanPrompt?.trim(), task.prompt]
              .filter(Boolean)
              .join("\n\n");
            result = await security.run(checkout, {
              ...scanSettings,
              knowledgeBaseSnapshot: knowledge?.snapshot,
              ...(task.scope === undefined ? {} : { target: [task.scope] }),
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
          const failureSeverity = scanSettings?.failureSeverity;
          if (failureSeverity !== undefined) {
            attemptPolicyFailed = result.findings.findings.some((finding) =>
              meetsSeverity(finding, failureSeverity),
            );
          }
          coverage = result.coverage.completeness;
          if (coverage !== "complete") {
            if (!(await hasArtifacts(scanDir))) {
              throw new Error(
                "Multiscan scan output is missing required artifacts.",
              );
            }
            warning = `Scan coverage is ${coverage}; results may be incomplete.`;
          }
        } catch (error) {
          if (options.signal?.aborted === true) options.signal.throwIfAborted();
          if (error instanceof ScanCostLimitExceededError) {
            cost = error.cost;
            exhaustedBudget = true;
          }
          requiresRecovery = error instanceof OutputDirectoryNotEmptyError;
          failure = requiresRecovery
            ? `Bulk attempt directory is not empty: ${scanDir}. Existing artifacts and checkout were preserved. Run the same bulk-scan command with --recover to recover interrupted scans or retry failed scans in new attempt directories.`
            : errorMessage(error);
        } finally {
          if (options.recoverScan === undefined && checkout !== undefined) {
            await rm(checkout, { recursive: true, force: true });
          }
        }
        const status =
          failure !== undefined
            ? "failed"
            : warning === undefined
              ? "completed"
              : "completed_with_incomplete_coverage";
        if (threatModelPath === undefined)
          threatModelPath = await readThreatModelPath(scanDir, {
            pythonPath: options.config.pythonPath,
            protectedRoot,
            signal: options.signal,
          });
        await appendReceipt(
          ledger,
          `${JSON.stringify({
            ...task,
            status,
            attempt,
            outputDir: scanDir,
            ...(targetId === undefined ? {} : { targetId }),
            ...(scanId === undefined ? {} : { scanId }),
            ...(resolvedScope === undefined ? {} : { resolvedScope }),
            ...(snapshotDigest === undefined ? {} : { snapshotDigest }),
            ...(threatModelPath === null ? {} : { threatModelPath }),
            ...(coverage === undefined ? {} : { coverage }),
            ...(cost === null ? {} : { cost }),
            ...(failure === undefined ? {} : { error: failure }),
            ...(knowledgeBaseFailure ? { knowledgeBaseFailure: true } : {}),
            ...(warning === undefined ? {} : { warning }),
            ...(runWarnings.length === 0 ? {} : { warnings: runWarnings }),
            policyFailed: attemptPolicyFailed,
          })}\n`,
        );
        if (
          options.recoverScan !== undefined &&
          failure === undefined &&
          checkout !== undefined
        ) {
          await rm(checkout, { recursive: true, force: true });
        }
        notifyProgress(options, {
          repository: task.id,
          attempt,
          status,
          ...(failure === undefined ? {} : { error: failure }),
          ...(warning === undefined ? {} : { warning }),
        });
        if (failure === undefined) {
          policyFailed ||= attemptPolicyFailed === true;
          if (runWarnings.length > 0) {
            warnings.push({ repository: task.id, warnings: runWarnings });
          }
          if (warning === undefined) completed += 1;
          else incomplete += 1;
          break;
        }
        if (exhaustedBudget || attemptedResume || requiresRecovery) {
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

async function ensureOutputDirectory(
  path: string,
  privateGitMetadata = false,
): Promise<string> {
  const metadata = await lstat(path, { bigint: true }).catch(
    undefinedIfMissingFile,
  );
  if (metadata?.isSymbolicLink()) {
    throw new Error("Multiscan output directories must not be symbolic links.");
  }
  if (metadata !== undefined && !metadata.isDirectory()) {
    throw new Error("Multiscan output paths must be directories.");
  }
  let prepared = path;
  if (metadata === undefined) {
    prepared =
      process.platform === "win32" ? await canonicalCreationPath(path) : path;
    await mkdir(prepared, { recursive: true, mode: 0o700 });
  }
  const canonical = await realpath(prepared);
  const directory = await lstat(canonical, { bigint: true });
  if (
    metadata !== undefined &&
    (directory.dev !== metadata.dev || directory.ino !== metadata.ino)
  ) {
    throw new Error("Multiscan output directories changed during preparation.");
  }
  if (process.platform === "win32") return canonical;
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
    identity = JSON.parse(owner) as typeof identity;
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

function isReceiptRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseReceipt(line: string, lineNumber: number): MultiscanReceipt {
  let value: unknown;
  try {
    value = JSON.parse(line);
  } catch {
    value = undefined;
  }
  if (
    !isReceiptRecord(value) ||
    !["id", "repository", "revision", "outputDir"].every(
      (field) => typeof value[field] === "string",
    ) ||
    (value["mode"] !== "standard" && value["mode"] !== "deep") ||
    !["completed", "completed_with_incomplete_coverage", "failed"].includes(
      value["status"] as string,
    ) ||
    typeof value["attempt"] !== "number" ||
    !Number.isSafeInteger(value["attempt"]) ||
    value["attempt"] < 1 ||
    ![
      "scope",
      "prompt",
      "targetId",
      "scanId",
      "resolvedScope",
      "snapshotDigest",
      "error",
      "warning",
    ].every(
      (field) => value[field] === undefined || typeof value[field] === "string",
    ) ||
    (value["coverage"] !== undefined &&
      !["complete", "partial", "unknown"].includes(value["coverage"] as string))
  ) {
    throw new Error(
      `Multiscan recovery is required: results line ${lineNumber} is not a valid receipt.`,
    );
  }
  return value as unknown as MultiscanReceipt;
}

async function readReceipts(
  path: string,
  preserveInterrupted = false,
): Promise<Map<string, MultiscanHistory>> {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return new Map();
    }
    throw error;
  }
  const lines = contents.split("\n");
  if (!contents.endsWith("\n")) {
    const partial = lines.pop()!;
    if (preserveInterrupted) {
      await writeFile(`${path}.interrupted-${randomUUID()}`, partial, {
        flag: "wx",
        mode: 0o600,
      });
    }
    await truncate(
      path,
      Buffer.byteLength(contents) - Buffer.byteLength(partial),
    );
  }
  const receipts = new Map<string, MultiscanHistory>();
  for (const [index, line] of lines.entries()) {
    if (!line) continue;
    const receipt = parseReceipt(line, index + 1);
    const id = receipt.id.toLowerCase();
    const previous = receipts.get(id);
    receipts.set(id, {
      maxAttempt: Math.max(previous?.maxAttempt ?? 0, receipt.attempt),
      // Extraction failures never start or modify a scan; keep its last receipt.
      scan: receipt.knowledgeBaseFailure ? previous?.scan : receipt,
    });
  }
  return receipts;
}

async function loadResumableScan(
  path: string,
  pluginRoot: string,
  receipt: MultiscanReceipt,
  checkout: string,
  configuredTarget: ScanTarget | undefined,
  signal: AbortSignal | undefined,
  githubHost: string | undefined,
  restoreReport: (
    scanDir: string,
    schemaRoot: string,
    protectedRoot: string,
  ) => Promise<void>,
  configuredPythonPath: string | undefined,
  recoverScan:
    | ((
        scanDir: string,
      ) => ReturnType<NonNullable<MultiscanOptions["recoverScan"]>>)
    | undefined,
): Promise<
  | {
      completeness: CoverageDocument["completeness"];
      checkout: string;
      findings: FindingsDocument;
    }
  | undefined
> {
  const saved = await loadContract(path, { pluginRoot, signal }).catch(() => {
    if (signal?.aborted === true) signal.throwIfAborted();
    return undefined;
  });
  if (saved === undefined) return undefined;
  const { manifest, findings, coverage } = saved;
  const { target, scope, producer } = manifest.scan;
  const campaignRoot = dirname(dirname(dirname(path)));
  const recoveryCheckout = join(
    campaignRoot,
    "recovery-checkouts",
    receipt.id,
    `attempt-${receipt.attempt}`,
  );
  const recoveryTarget =
    receipt.scope === undefined ? configuredTarget : [receipt.scope];
  if (
    process.platform === "win32" &&
    Array.isArray(recoveryTarget) &&
    target.targetId !==
      `target_sha256_${createHash("sha256").update(`local-workspace\0${checkout}`).digest("hex")}`
  ) {
    // Validate the lexical parents before canonicalization follows Windows aliases.
    await ensureOutputDirectory(join(campaignRoot, "recovery-checkouts"));
    await ensureOutputDirectory(dirname(recoveryCheckout));
  }
  const targetRoots = [
    checkout,
    process.platform === "win32"
      ? await canonicalCreationPath(recoveryCheckout)
      : recoveryCheckout,
  ];
  const matchedRoot = targetRoots.find(
    (root) =>
      target.targetId ===
      `target_sha256_${createHash("sha256").update(`local-workspace\0${root}`).digest("hex")}`,
  );
  const requestedTarget =
    receipt.scope === undefined
      ? (configuredTarget ?? "repository")
      : [receipt.scope];
  const requestedPaths = Array.isArray(requestedTarget)
    ? requestedTarget
    : undefined;
  const expectedMode =
    requestedPaths !== undefined
      ? "scoped_path"
      : receipt.mode === "deep"
        ? "deep_repository"
        : "repository";
  if (
    manifest.scan.status !== "completed" ||
    producer.name !== "codex-security-plugin" ||
    matchedRoot === undefined ||
    (receipt.targetId !== undefined && receipt.targetId !== target.targetId) ||
    target.kind !== "git_revision" ||
    target.snapshotDigest !== undefined ||
    receipt.snapshotDigest !== undefined ||
    target.displayName !== basename(matchedRoot) ||
    target.revision !== receipt.revision ||
    coverage.mode !== expectedMode ||
    scope.excludePaths.length !== 0
  )
    return undefined;
  const completeness = coverage.completeness;
  const matchesOutcome =
    completeness === "complete"
      ? receipt.status === "completed"
      : (receipt.status === "completed_with_incomplete_coverage" &&
          (receipt.coverage ?? completeness) === completeness) ||
        (receipt.status === "failed" &&
          receipt.error === "Multiscan repository coverage is incomplete.");
  if (!matchesOutcome) return undefined;
  const reportSealed = await hasSealedReport(path, manifest, signal);
  const reportMissing =
    (await lstat(join(path, "report.md")).catch(undefinedIfMissingFile)) ===
    undefined;
  if (
    reportMissing &&
    recoverScan !== undefined &&
    (await recoverScan(path)) === undefined
  )
    return undefined;
  if (
    reportMissing &&
    (receipt.scanId === undefined
      ? recoverScan === undefined
      : receipt.scanId !== manifest.scan.id)
  )
    return undefined;
  let pythonPath: string | undefined;
  if (!reportSealed) {
    const automaticAvailable =
      configuredPythonPath === undefined
        ? await resolvePluginPythonCommand({
            protectedRoot: matchedRoot,
            environment: pluginHelperEnvironment(process.env),
            signal,
          }).then(
            () => true,
            (error: unknown) => {
              if (error instanceof PluginPythonUnavailableError) return false;
              signal?.throwIfAborted();
              throw new Error(
                `Multiscan report recovery is required: ${errorMessage(error)}`,
              );
            },
          )
        : false;
    const selections =
      configuredPythonPath !== undefined
        ? [configuredPythonPath]
        : automaticAvailable
          ? []
          : process.platform === "win32"
            ? ["python", "python3", "py"]
            : ["python3", "python"];
    for (const configuredPythonPath of selections) {
      let candidates: string[];
      if (isPythonPathCandidate(configuredPythonPath)) {
        candidates = [
          resolve(
            expandHome(configuredPythonPath) +
              (process.platform === "win32" &&
              extname(configuredPythonPath) === ""
                ? ".exe"
                : ""),
          ),
        ];
      } else {
        const inspected = await inspectTrustedExecutable(
          configuredPythonPath,
          pluginHelperEnvironment(process.env),
          matchedRoot,
        );
        const suffixes =
          process.platform !== "win32" ||
          /\.(?:exe|com)$/iu.test(configuredPythonPath)
            ? [""]
            : [".exe", ".com"];
        candidates =
          inspected.executable !== null
            ? []
            : (inspected.environment["PATH"]?.split(delimiter) ?? []).flatMap(
                (entry) =>
                  suffixes.map((suffix) =>
                    join(entry, configuredPythonPath + suffix),
                  ),
              );
      }
      for (const candidate of candidates) {
        const selected = relative(
          matchedRoot,
          await canonicalPythonPath(candidate),
        );
        if (!relativePathIsOutside(selected)) {
          pythonPath = selected;
          break;
        }
      }
      if (pythonPath !== undefined) break;
    }
  }

  const checkoutPython =
    !reportSealed &&
    pythonPath !== undefined &&
    !relativePathIsOutside(pythonPath);
  let expectedPaths = ["."];
  let createdCheckout = false;
  try {
    if (requestedPaths !== undefined || checkoutPython) {
      // Scope spellings and tracked links are relative to the recorded checkout.
      if (matchedRoot !== checkout) {
        await ensureOutputDirectory(join(campaignRoot, "recovery-checkouts"));
        await ensureOutputDirectory(dirname(recoveryCheckout));
      }
      try {
        await mkdir(matchedRoot, { mode: 0o700 });
        createdCheckout = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        await ensureOutputDirectory(matchedRoot);
      }
      if (createdCheckout) {
        await checkoutRevision(receipt, matchedRoot, signal, githubHost);
      } else if (
        checkoutPython &&
        pythonPath !== undefined &&
        !(await realpath(join(matchedRoot, pythonPath)).catch(
          undefinedIfMissingFile,
        ))
      ) {
        await checkoutRevision(receipt, matchedRoot, signal, githubHost, true, [
          pythonPath,
        ]);
      }
    }
    if (requestedPaths !== undefined) {
      let normalized;
      try {
        normalized = await normalizeTarget(matchedRoot, requestedPaths, signal);
      } catch (error) {
        if (
          createdCheckout ||
          !(error instanceof InvalidTargetError) ||
          !error.message.startsWith("Path target does not exist:")
        ) {
          throw error;
        }
        // Interrupted preparation or cleanup may leave a pinned checkout incomplete.
        await checkoutRevision(
          receipt,
          matchedRoot,
          signal,
          githubHost,
          true,
          requestedPaths,
        );
        normalized = await normalizeTarget(matchedRoot, requestedPaths, signal);
      }
      expectedPaths = [...normalized.paths];
      if (
        receipt.scope !== undefined &&
        expectedPaths[0] !==
          posix.normalize(receipt.scope).replace(/\/+$/, "") &&
        receipt.resolvedScope === undefined
      )
        return undefined;
    }
    if (
      scope.includePaths.length !== expectedPaths.length ||
      scope.includePaths.some((path, index) => path !== expectedPaths[index]) ||
      (receipt.resolvedScope !== undefined &&
        (expectedPaths.length !== 1 ||
          receipt.resolvedScope !== expectedPaths[0]))
    )
      return undefined;
    const sealedArtifacts = new Set(
      manifest.scan.artifacts.map((artifact) => artifact.path),
    );
    if (
      !sealedArtifacts.has("findings.json") ||
      !sealedArtifacts.has("coverage.json")
    ) {
      return undefined;
    }
    if (
      completeness === "complete" &&
      (coverage.deferred.length !== 0 ||
        coverage.surfaces.some(
          (surface) => surface.disposition === "needs_follow_up",
        ))
    ) {
      return undefined;
    }
    const surfaceIds = new Set<string>();
    for (const surface of coverage.surfaces) {
      if (surfaceIds.has(surface.id)) return undefined;
      surfaceIds.add(surface.id);
    }
    const findingIds = new Set<string>();
    const occurrenceIds = new Set<string>();
    for (const finding of findings.findings) {
      if (
        findingIds.has(finding.findingId) ||
        occurrenceIds.has(finding.occurrenceId)
      ) {
        return undefined;
      }
      findingIds.add(finding.findingId);
      occurrenceIds.add(finding.occurrenceId);
      if (
        finding.locations.some(
          (location) =>
            location.endLine !== undefined &&
            location.endLine < location.startLine,
        )
      ) {
        return undefined;
      }
      const evidenceIds = new Set<string>();
      for (const evidence of finding.codeEvidence ?? []) {
        if (evidenceIds.has(evidence.id)) return undefined;
        evidenceIds.add(evidence.id);
      }
      // loadContract preserves supported sealed references through canonical legacy validation.
    }

    if (!reportSealed) await restoreReport(path, pluginRoot, matchedRoot);
    return {
      completeness,
      checkout: matchedRoot,
      findings,
    };
  } finally {
    if (createdCheckout)
      await rm(matchedRoot, { recursive: true, force: true });
  }
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

function parseInventory(
  source: string,
  directory: string,
  defaultMode: ScanMode,
): MultiscanTask[] {
  const { data: rows, errors } = Papa.parse<string[]>(source, {
    delimiter: ",",
    skipEmptyLines: "greedy",
  });
  if (errors.length > 0) {
    throw new Error(`Multiscan CSV could not be parsed: ${errors[0]!.message}`);
  }
  const headers = rows.shift();
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
    return {
      id,
      repository: normalizeRepository(get("repository"), directory),
      revision,
      mode,
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
    const path = resolve(directory, repository);
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
    restoreIncomplete
      ? (await inspectTrustedExecutable("git", environment, path)).environment
      : environment,
    resolve(process.cwd()),
  );
  if (command === null) {
    throw new Error("Git is not available on a trusted PATH.");
  }
  const gitOutput = async (
    args: string[],
    input?: string | Buffer,
  ): Promise<Buffer> => {
    // Use the resolved absolute path so Windows PATHEXT cannot prefer a
    // .bat/.cmd shim over the trusted executable selected above.
    const pending = execFile(
      command.executable,
      [
        "-c",
        "core.hooksPath=/dev/null",
        ...buildGitHubCredentialArgs(githubHost),
        "-C",
        path,
        ...args,
      ],
      {
        env: command.environment,
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
  let retainedGit = false;
  if (restoreIncomplete) {
    const gitDirectory = join(path, ".git");
    const metadata = await lstat(gitDirectory).catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    });
    if (metadata !== undefined) {
      retainedGit = true;
      const canonicalGit = await ensureOutputDirectory(gitDirectory, true);
      const canonicalObjects = await ensureOutputDirectory(
        join(gitDirectory, "objects"),
        true,
      );
      for (const entry of await readdir(canonicalObjects)) {
        if (/^[0-9a-f]{2}$/.test(entry))
          await ensureOutputDirectory(join(canonicalObjects, entry), true);
      }
      if (
        await lstat(join(canonicalObjects, "pack")).catch(
          undefinedIfMissingFile,
        )
      )
        await ensureOutputDirectory(join(canonicalObjects, "pack"), true);
      for (const entry of [
        "config",
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
      const head = await lstat(join(gitDirectory, "HEAD")).catch(
        undefinedIfMissingFile,
      );
      const refs = await lstat(join(gitDirectory, "refs")).catch(
        undefinedIfMissingFile,
      );
      if (head === undefined || refs === undefined) {
        const common = await readFile(
          join(gitDirectory, "commondir"),
          "utf8",
        ).catch(undefinedIfMissingFile);
        if (
          common !== undefined &&
          (await realpath(resolve(gitDirectory, common.trim()))) !==
            canonicalGit
        ) {
          throw new Error(
            "The retained campaign checkout has Git bindings outside its own directory.",
          );
        }
        if (
          await lstat(join(gitDirectory, "refs")).catch(undefinedIfMissingFile)
        )
          await ensureOutputDirectory(join(gitDirectory, "refs"), true);
        await git("init", "--quiet", "--template=");
      }
      const [common, objects, worktree] = await Promise.all([
        git("rev-parse", "--path-format=absolute", "--git-common-dir"),
        git("rev-parse", "--path-format=absolute", "--git-path", "objects"),
        git("rev-parse", "--show-toplevel"),
      ]);
      if (
        (await realpath(common)) !== canonicalGit ||
        (await realpath(objects)) !== canonicalObjects ||
        (await realpath(worktree)) !== (await realpath(path))
      ) {
        throw new Error(
          "The retained campaign checkout has Git bindings outside its own directory.",
        );
      }
    }
  }
  if (!retainedGit) await git("init", "--quiet");
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
  }
  if (
    restoreIncomplete &&
    !(await lstat(join(path, ".git", "index")).catch(undefinedIfMissingFile))
  ) {
    // Rebuild the lost index without restoring unrelated deleted worktree files.
    await git("read-tree", task.revision);
  }
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
          visited.add(name);
          aliases.add(name);
          const target = (
            await gitOutput(["show", `${task.revision}:${name}`])
          ).toString("utf8");
          return canonicalTrackedPath(
            (isAbsolute(target)
              ? target
              : `${path}${sep}${dirname(name)}${sep}${target}`) +
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
        visited.add(name);
        aliases.add(name);
        const target = (
          await gitOutput(["show", `${task.revision}:${name}`])
        ).toString("utf8");
        selected = posix.join(
          relative(
            path,
            await canonicalTrackedPath(
              isAbsolute(target)
                ? target
                : `${path}${sep}${dirname(name)}${sep}${target}`,
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
        const existing = await lstat(
          Buffer.concat([Buffer.from(path + sep), name]),
        ).catch(async (error: NodeJS.ErrnoException) => {
          if (error.code === "ENOTDIR") return null;
          undefinedIfMissingFile(error);
          for (
            let end = name.lastIndexOf(47);
            end !== -1;
            end = name.lastIndexOf(47, end - 1)
          ) {
            const ancestor = await lstat(
              Buffer.concat([Buffer.from(path + sep), name.subarray(0, end)]),
            ).catch((error: NodeJS.ErrnoException) => {
              if (error.code === "ENOTDIR") return null;
              return undefinedIfMissingFile(error);
            });
            if (ancestor !== undefined && !ancestor?.isDirectory()) return null;
          }
          return undefined;
        });
        if (existing === undefined)
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
