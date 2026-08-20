import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
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
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import Papa from "papaparse";
import type { CodexSecurity } from "./api.js";
import type { CodexSecurityConfig } from "./config.js";
import type { ScanCost } from "./cost.js";
import { safeErrorMessage, ScanCostLimitExceededError } from "./errors.js";
import type { CoverageDocument } from "./models.js";
import { requireSecureOutputAncestry } from "./runtime.js";
import type { ScanMode } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

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
  coverage?: CoverageDocument["completeness"];
  cost?: ScanCost;
  error?: string;
  warning?: string;
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
  try {
    const result = await runCampaign(options, tasks, output);
    return (await realpath(requestedOutput).catch(() => undefined)) === output
      ? { ...result, resultsPath: join(requestedOutput, "results.jsonl") }
      : result;
  } finally {
    await unlock();
  }
}

async function runCampaign(
  options: MultiscanOptions,
  tasks: MultiscanTask[],
  output: string,
): Promise<MultiscanResult> {
  const ledger = join(output, "results.jsonl");
  await ensureOutputDirectory(join(output, "checkouts"));
  await ensureOutputDirectory(join(output, "artifacts"));
  await ensureManifest(join(output, "manifest.json"), tasks, options);
  const receipts = await readReceipts(ledger);
  const pending: MultiscanTask[] = [];
  let completed = 0;
  let incomplete = 0;
  for (const task of tasks) {
    const receipt = receipts.get(task.id.toLowerCase());
    if (receipt === undefined) {
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
    if (
      (receipt.outputDir === artifactOutput ||
        receipt.outputDir === selectedArtifactOutput) &&
      (await hasArtifacts(artifactOutput))
    ) {
      if (receipt.status === "completed") {
        completed += 1;
        continue;
      }
      const coverage =
        receipt.status === "completed_with_incomplete_coverage"
          ? receipt.coverage ?? "unknown"
          : await legacyIncompleteCoverage({
              ...receipt,
              outputDir: artifactOutput,
            });
      if (coverage !== undefined) {
        incomplete += 1;
        notifyProgress(options, {
          repository: task.id,
          status: "completed_with_incomplete_coverage",
          attempt: receipt.attempt,
          warning:
            receipt.warning ??
            `Scan coverage is ${coverage}; results may be incomplete.`,
        });
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
      let attempt = receipts.get(task.id.toLowerCase())?.attempt ?? 0;
      for (let retry = 0; retry < options.maxAttempts; retry += 1) {
        options.signal?.throwIfAborted();
        attempt += 1;
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
        let coverage: CoverageDocument["completeness"] | undefined;
        let cost: Readonly<ScanCost> | null = null;
        let exhaustedBudget = false;
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
            onWarning: (warning) =>
              notifyProgress(options, {
                ...progress,
                status: "started",
                warning,
              }),
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          });
          cost = result.cost;
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
          await rm(checkout, { recursive: true, force: true });
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
            ...(coverage === undefined ? {} : { coverage }),
            ...(cost === null ? {} : { cost }),
            ...(failure === undefined ? {} : { error: failure }),
            ...(warning === undefined ? {} : { warning }),
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
  const metadata = await lstat(path, { bigint: true }).catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      return undefined;
    },
  );
  if (metadata?.isSymbolicLink()) {
    throw new Error("Multiscan output directories must not be symbolic links.");
  }
  await mkdir(path, { recursive: true, mode: 0o700 });
  const canonical = await realpath(path);
  const directory = await lstat(canonical, { bigint: true });
  if (
    metadata !== undefined &&
    (directory.dev !== metadata.dev || directory.ino !== metadata.ino)
  ) {
    throw new Error("Multiscan output directories changed during preparation.");
  }
  if (process.platform === "win32") return canonical;
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

async function readReceipts(
  path: string,
): Promise<Map<string, MultiscanReceipt>> {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return new Map();
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
  return new Map(
    lines.filter(Boolean).map((line): [string, MultiscanReceipt] => {
      const receipt = JSON.parse(line) as MultiscanReceipt;
      return [receipt.id.toLowerCase(), receipt];
    }),
  );
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

async function legacyIncompleteCoverage(
  receipt: MultiscanReceipt,
): Promise<Exclude<CoverageDocument["completeness"], "complete"> | undefined> {
  if (
    receipt.status !== "failed" ||
    receipt.error !== "Multiscan repository coverage is incomplete."
  ) {
    return undefined;
  }
  try {
    const coverage = JSON.parse(
      await readFile(join(receipt.outputDir, "coverage.json"), "utf8"),
    ) as { completeness?: unknown };
    return coverage.completeness === "partial" ||
      coverage.completeness === "unknown"
      ? coverage.completeness
      : undefined;
  } catch {
    return undefined;
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
