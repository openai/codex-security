import { execFile as execFileCallback } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
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
  dirname,
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
import { safeErrorMessage, ScanCostLimitExceededError } from "./errors.js";
import type { CoverageDocument } from "./models.js";
import {
  bundledPluginRoot,
  pluginHelperEnvironment,
  requireSecureOutputAncestry,
  resolvePluginPath,
  resolvePluginPythonCommand,
} from "./runtime.js";
import { outermostGitMarkerRoot, type ScanMode } from "./targets.js";
import {
  resolveTrustedExecutable,
  type TrustedExecutable,
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
  resolvedScope?: string;
  snapshotDigest?: string;
  coverage?: CoverageDocument["completeness"];
  cost?: ScanCost;
  error?: string;
  warning?: string;
  warnings?: string[];
}

export interface MultiscanOptions {
  inputPath: string;
  outputDir: string;
  githubHost?: string;
  knowledgeBasePaths?: string[];
  workers: number;
  mode: ScanMode;
  maxAttempts: number;
  maxCostUsd?: number;
  scanPrompt?: string;
  postScanPrompt?: string;
  config: CodexSecurityConfig;
  createSecurity(
    config: CodexSecurityConfig,
  ): Pick<CodexSecurity, "run" | "close">;
  signal?: AbortSignal;
  onProgress?(event: {
    repository: string;
    status:
      | "started"
      | "completed"
      | "completed_with_incomplete_coverage"
      | "failed";
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
  warned: number;
  skipped: number;
  resultsPath: string;
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
  const requestedOutput = resolve(options.outputDir);
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
      options,
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
  await ensureOutputDirectory(join(output, "checkouts"));
  await ensureOutputDirectory(join(output, "artifacts"));
  await ensureManifest(join(output, "manifest.json"), tasks, options);
  const { receipts, warnedIds } = await readReceipts(ledger, tasks);
  const pending: MultiscanTask[] = [];
  let reportRuntime: Promise<[TrustedExecutable, string]> | undefined;
  const restoreReport = async (
    scanDir: string,
    schemaPluginRoot: string,
  ): Promise<void> => {
    try {
      // Configured historical archives may contain schemas without helper scripts.
      const [python, helperRoot] = await (reportRuntime ??= (async () => {
        const repositories = [
          process.cwd(),
          ...tasks.map((task) => task.repository).filter(isAbsolute),
        ];
        const repositoryRoots = await Promise.all(
          [...new Set(repositories)].map(async (repository) => {
            const canonical = await realpath(repository).catch(() =>
              resolve(repository),
            );
            const metadata = await lstat(canonical).catch(() => undefined);
            return metadata?.isDirectory()
              ? await outermostGitMarkerRoot(canonical, options.signal)
              : canonical;
          }),
        );
        return await Promise.all([
          resolvePluginPythonCommand({
            configuredPath: options.config.pythonPath,
            environment: pluginHelperEnvironment(process.env),
            additionalProtectedRoots: [output, ...repositoryRoots],
            signal: options.signal,
          }),
          bundledPluginRoot(),
        ]);
      })());
      await execFile(
        python.executable,
        [
          "-I",
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
        `Multiscan report recovery is required: ${safeErrorMessage(error)}`,
      );
    }
  };
  let completed = 0;
  let incomplete = 0;
  for (const task of tasks) {
    const receipt = receipts.get(task.id.toLowerCase());
    if (receipt === undefined || !matchesTask(receipt, task)) {
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
      const checkout = join(output, "checkouts", task.id);
      const schemaPluginRoot = await resolveResumePluginRoot();
      const resumed = await loadResumableScan(
        artifactOutput,
        schemaPluginRoot,
        receipt,
        checkout,
        options.signal,
      );
      if (resumed !== undefined) {
        if (!resumed.reportSealed) {
          await restoreReport(canonicalArtifactOutput, schemaPluginRoot);
        }
        await rm(checkout, {
          recursive: true,
          force: true,
        }).catch(() => undefined);
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
  const skipped = completed + incomplete;
  if (pending.length === 0) {
    return {
      total: tasks.length,
      completed,
      incomplete,
      failed: 0,
      warned: warnedIds.size,
      skipped,
      resultsPath: ledger,
    };
  }

  let next = 0;
  let failed = 0;
  const worker = async (
    security: Pick<CodexSecurity, "run" | "close">,
  ): Promise<void> => {
    for (;;) {
      options.signal?.throwIfAborted();
      const task = pending[next++];
      if (task === undefined) return;
      const taskId = task.id.toLowerCase();
      let attempt = receipts.get(taskId)?.attempt ?? 0;
      for (let retry = 0; retry < options.maxAttempts; retry += 1) {
        options.signal?.throwIfAborted();
        attempt += 1;
        if (!Number.isSafeInteger(attempt)) {
          throw new Error(
            "Multiscan recovery is required: the next attempt is not a safe integer.",
          );
        }
        const checkout = join(output, "checkouts", task.id);
        const scanDir = join(
          output,
          "artifacts",
          task.id,
          `attempt-${attempt}`,
        );
        const progress = { repository: task.id, attempt };
        notifyProgress(options, { ...progress, status: "started" });
        let failure: string | undefined;
        let warning: string | undefined;
        let targetId: string | undefined;
        let resolvedScope: string | undefined;
        let snapshotDigest: string | undefined;
        let coverage: CoverageDocument["completeness"] | undefined;
        let cost: Readonly<ScanCost> | null = null;
        let exhaustedBudget = false;
        const warnings: string[] = [];
        const recordWarning = (message: unknown): void => {
          const safeWarning = safeErrorMessage(message);
          warnings.push(safeWarning);
          warnedIds.add(taskId);
          notifyProgress(options, {
            ...progress,
            status: "started",
            warning: safeWarning,
          });
        };
        try {
          await ensureOutputDirectory(dirname(scanDir));
          await rm(checkout, { recursive: true, force: true });
          await mkdir(checkout, { mode: 0o700 });
          await checkoutRevision(
            task,
            checkout,
            options.signal,
            options.githubHost,
          );
          if (task.scope !== undefined) {
            const scoped = await realpath(join(checkout, task.scope));
            const canonicalCheckout = await realpath(checkout);
            const outside = relative(canonicalCheckout, scoped);
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
          const result = await security.run(checkout, {
            ...(task.scope === undefined ? {} : { target: [task.scope] }),
            ...(options.knowledgeBasePaths?.length
              ? { knowledgeBasePaths: options.knowledgeBasePaths }
              : {}),
            mode: task.mode,
            outputDir: scanDir,
            ...(scanPrompt ? { scanPrompt } : {}),
            ...(options.postScanPrompt === undefined
              ? {}
              : { postScanPrompt: options.postScanPrompt }),
            ...(options.maxCostUsd === undefined
              ? {}
              : { maxCostUsd: options.maxCostUsd }),
            onWarning: recordWarning,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          });
          cost = result.cost;
          targetId = result.manifest.scan.target.targetId;
          snapshotDigest = result.manifest.scan.target.snapshotDigest;
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
          failure = safeErrorMessage(error);
        } finally {
          await rm(checkout, { recursive: true, force: true }).catch(
            (error: unknown) => {
              recordWarning(
                `Multiscan checkout cleanup failed: ${safeErrorMessage(error)}`,
              );
            },
          );
        }
        const status =
          failure !== undefined
            ? "failed"
            : warning === undefined
              ? "completed"
              : "completed_with_incomplete_coverage";
        await appendReceipt(
          ledger,
          `${JSON.stringify({
            ...task,
            status,
            attempt,
            outputDir: scanDir,
            ...(targetId === undefined ? {} : { targetId }),
            ...(resolvedScope === undefined ? {} : { resolvedScope }),
            ...(snapshotDigest === undefined ? {} : { snapshotDigest }),
            ...(coverage === undefined ? {} : { coverage }),
            ...(cost === null ? {} : { cost }),
            ...(failure === undefined ? {} : { error: failure }),
            ...(warning === undefined ? {} : { warning }),
            ...(warnings.length === 0 ? {} : { warnings }),
          })}\n`,
        );
        notifyProgress(options, {
          ...progress,
          status,
          ...(failure === undefined ? {} : { error: failure }),
          ...(warning === undefined ? {} : { warning }),
        });
        if (failure === undefined) {
          if (warning === undefined) completed += 1;
          else incomplete += 1;
          break;
        }
        if (exhaustedBudget) {
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
  return {
    total: tasks.length,
    completed,
    incomplete,
    failed,
    warned: warnedIds.size,
    skipped,
    resultsPath: ledger,
  };
}

function notifyProgress(
  options: MultiscanOptions,
  event: Parameters<NonNullable<MultiscanOptions["onProgress"]>>[0],
): void {
  try {
    void Promise.resolve(options.onProgress?.(event)).catch(() => {});
  } catch {}
}

async function ensureOutputDirectory(path: string): Promise<string> {
  const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
  if (metadata?.isSymbolicLink()) {
    throw new Error("Multiscan output directories must not be symbolic links.");
  }
  await mkdir(path, { recursive: true, mode: 0o700 });
  const canonical = await realpath(path);
  const directory = await lstat(canonical);
  if (
    metadata !== undefined &&
    (directory.dev !== metadata.dev || directory.ino !== metadata.ino)
  ) {
    throw new Error("Multiscan output directories changed during preparation.");
  }
  if (process.platform === "win32") return canonical;
  if ((directory.mode & 0o022) !== 0) {
    throw new Error(
      "Multiscan output directories must not be group- or world-writable.",
    );
  }
  const owner = process.geteuid?.();
  if (owner !== undefined && directory.uid !== owner) {
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
  const createdLock = await lstat(path);
  const owner = `${JSON.stringify({
    pid: process.pid,
    ownerId: randomUUID(),
    hostname: hostname(),
    processStartedAt: performance.timeOrigin,
  })}\n`;
  try {
    await writeFile(ownerPath, owner, { flag: "wx", mode: 0o600 });
  } catch (error) {
    const currentLock = await lstat(path).catch(
      (cleanup: NodeJS.ErrnoException) => {
        if (cleanup.code !== "ENOENT") throw cleanup;
        return undefined;
      },
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
      (error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
        return undefined;
      },
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
    "scanPrompt" | "postScanPrompt" | "maxCostUsd"
  >,
): Promise<void> {
  const expected = `${JSON.stringify(
    {
      version: 1,
      tasks,
      ...(options.scanPrompt === undefined
        ? {}
        : { scanPrompt: options.scanPrompt }),
      ...(options.postScanPrompt === undefined
        ? {}
        : { postScanPrompt: options.postScanPrompt }),
      ...(options.maxCostUsd === undefined
        ? {}
        : { maxCostUsd: options.maxCostUsd }),
    },
    null,
    2,
  )}\n`;
  try {
    await writeFile(path, expected, { flag: "wx", mode: 0o600 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    if ((await readFile(path, "utf8")) !== expected) {
      throw new Error(
        "Multiscan manifest does not match existing output directory.",
      );
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
  const cost = isReceiptRecord(value) ? value["cost"] : undefined;
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
      "resolvedScope",
      "snapshotDigest",
      "error",
      "warning",
    ].every(
      (field) => value[field] === undefined || typeof value[field] === "string",
    ) ||
    (value["coverage"] !== undefined &&
      !["complete", "partial", "unknown"].includes(
        value["coverage"] as string,
      )) ||
    (value["warnings"] !== undefined &&
      (!Array.isArray(value["warnings"]) ||
        !value["warnings"].every((warning) => typeof warning === "string"))) ||
    (cost !== undefined &&
      (!isReceiptRecord(cost) ||
        typeof cost["model"] !== "string" ||
        ![
          "inputTokens",
          "cachedInputTokens",
          "cacheWriteInputTokens",
          "outputTokens",
          "estimatedUsd",
        ].every(
          (field) =>
            typeof cost[field] === "number" && Number.isFinite(cost[field]),
        )))
  ) {
    throw new Error(
      `Multiscan recovery is required: results line ${lineNumber} is not a valid receipt.`,
    );
  }
  return value as unknown as MultiscanReceipt;
}

async function readReceipts(
  path: string,
  tasks: readonly MultiscanTask[],
): Promise<{
  receipts: Map<string, MultiscanReceipt>;
  warnedIds: Set<string>;
}> {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { receipts: new Map(), warnedIds: new Set() };
    }
    throw error;
  }
  const lines = contents.split("\n");
  if (!contents.endsWith("\n")) {
    const partial = lines.pop()!;
    await truncate(
      path,
      Buffer.byteLength(contents) - Buffer.byteLength(partial),
    );
  }
  const receipts = new Map<string, MultiscanReceipt>();
  const warnedIds = new Set<string>();
  const indexedTasks = new Map(
    tasks.map((task) => [task.id.toLowerCase(), task]),
  );
  for (const [index, line] of lines.entries()) {
    if (!line) continue;
    const receipt = parseReceipt(line, index + 1);
    const id = receipt.id.toLowerCase();
    receipts.set(id, receipt);
    const task = indexedTasks.get(id);
    if (
      task !== undefined &&
      matchesTask(receipt, task) &&
      Array.isArray(receipt.warnings) &&
      receipt.warnings.length > 0
    ) {
      warnedIds.add(id);
    }
  }
  return { receipts, warnedIds };
}

async function loadResumableScan(
  path: string,
  pluginRoot: string,
  receipt: MultiscanReceipt,
  checkout: string,
  signal?: AbortSignal,
): Promise<
  | {
      completeness: CoverageDocument["completeness"];
      reportSealed: boolean;
    }
  | undefined
> {
  try {
    const { manifest, coverage } = await loadContract(path, {
      pluginRoot,
      signal,
    });
    const { target, scope, producer } = manifest.scan;
    const targetId =
      receipt.targetId ??
      `target_sha256_${createHash("sha256")
        .update(`local-workspace\0${checkout}`)
        .digest("hex")}`;
    const expectedScope =
      receipt.scope === undefined
        ? "."
        : receipt.resolvedScope ??
          posix.normalize(receipt.scope).replace(/\/+$/, "");
    const expectedMode =
      receipt.scope !== undefined
        ? "scoped_path"
        : receipt.mode === "deep"
          ? "deep_repository"
          : "repository";
    const expectedKind =
      receipt.snapshotDigest === undefined ? "git_revision" : "git_worktree";
    if (
      producer.name !== "codex-security-plugin" ||
      target.targetId !== targetId ||
      target.kind !== expectedKind ||
      target.snapshotDigest !== receipt.snapshotDigest ||
      target.displayName !== receipt.id ||
      target.revision !== receipt.revision ||
      coverage.mode !== expectedMode ||
      scope.includePaths.length !== 1 ||
      scope.includePaths[0] !== expectedScope ||
      scope.excludePaths.length !== 0
    ) {
      return undefined;
    }
    const completeness = coverage.completeness;
    const matchesOutcome =
      completeness === "complete"
        ? receipt.status === "completed"
        : (receipt.status === "completed_with_incomplete_coverage" &&
            (receipt.coverage ?? completeness) === completeness) ||
          (receipt.status === "failed" &&
            receipt.error === "Multiscan repository coverage is incomplete.");
    return matchesOutcome
      ? {
          completeness,
          reportSealed: await hasSealedReport(path, manifest, signal),
        }
      : undefined;
  } catch {
    if (signal?.aborted === true) signal.throwIfAborted();
    return undefined;
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
      /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/iu.test(id)
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
  if (!repository.includes("://")) return resolve(directory, repository);
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
  const repositoryVariables = new Set([
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  ]);
  for (const name of Object.keys(environment)) {
    if (repositoryVariables.has(name.toUpperCase())) delete environment[name];
  }
  environment["GIT_TERMINAL_PROMPT"] = "0";
  environment["GIT_LFS_SKIP_SMUDGE"] = "1";
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
