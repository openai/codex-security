import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
  truncate,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import Papa from "papaparse";
import type { CodexSecurity } from "./api.js";
import type { CodexSecurityConfig } from "./config.js";
import type { ScanCost } from "./cost.js";
import { redactedErrorMessage } from "./errors.js";
import type { ScanMode } from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const REQUIRED_ARTIFACTS = [
  "scan-manifest.json",
  "findings.json",
  "coverage.json",
  "report.md",
];
const MAX_LOCK_OWNER_BYTES = 4 * 1024;

interface MultiscanLockOwner {
  pid: number;
  token?: string;
}

interface MultiscanTask {
  id: string;
  repository: string;
  revision: string;
  mode: ScanMode;
  scope?: string;
}

interface MultiscanReceipt extends MultiscanTask {
  status: "completed" | "failed";
  attempt: number;
  outputDir: string;
  cost?: ScanCost;
  error?: string;
}

export interface MultiscanOptions {
  inputPath: string;
  outputDir: string;
  githubHost?: string;
  knowledgeBasePaths?: string[];
  workers: number;
  mode: ScanMode;
  maxAttempts: number;
  config: CodexSecurityConfig;
  createSecurity(
    config: CodexSecurityConfig,
  ): Pick<CodexSecurity, "run" | "close">;
  signal?: AbortSignal;
  onProgress?(event: {
    repository: string;
    status: "started" | "completed" | "failed";
    attempt: number;
    error?: string;
  }): void;
}

export interface MultiscanResult {
  total: number;
  completed: number;
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
  const output = resolve(options.outputDir);
  await ensureOutputDirectory(output);
  const unlock = await acquireLock(output);
  try {
    return await runCampaign(options, tasks, output);
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
  await ensureManifest(join(output, "manifest.json"), tasks);
  const receipts = await readReceipts(ledger);
  const pending: MultiscanTask[] = [];
  let completed = 0;
  for (const task of tasks) {
    const receipt = receipts.get(task.id.toLowerCase());
    if (
      receipt?.status === "completed" &&
      receipt.outputDir ===
        join(output, "artifacts", task.id, `attempt-${receipt.attempt}`) &&
      (await hasArtifacts(receipt.outputDir))
    ) {
      completed += 1;
    } else {
      pending.push(task);
    }
  }
  const skipped = completed;
  if (pending.length === 0) {
    return {
      total: tasks.length,
      completed,
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
        options.onProgress?.({ ...progress, status: "started" });
        let failure: string | undefined;
        let cost: Readonly<ScanCost> | null = null;
        try {
          await mkdir(dirname(scanDir), { recursive: true, mode: 0o700 });
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
          const result = await security.run(checkout, {
            ...(task.scope === undefined ? {} : { target: [task.scope] }),
            ...(options.knowledgeBasePaths?.length
              ? { knowledgeBasePaths: options.knowledgeBasePaths }
              : {}),
            mode: task.mode,
            outputDir: scanDir,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          });
          cost = result.cost;
          if (result.coverage.completeness !== "complete") {
            throw new Error("Multiscan repository coverage is incomplete.");
          }
        } catch (error) {
          if (options.signal?.aborted === true) options.signal.throwIfAborted();
          failure = redactedErrorMessage(error);
        } finally {
          await rm(checkout, { recursive: true, force: true });
        }
        const status = failure === undefined ? "completed" : "failed";
        await appendReceipt(
          ledger,
          `${JSON.stringify({
            ...task,
            status,
            attempt,
            outputDir: scanDir,
            ...(cost === null ? {} : { cost }),
            ...(failure === undefined ? {} : { error: failure }),
          })}\n`,
        );
        options.onProgress?.({
          ...progress,
          status,
          ...(failure === undefined ? {} : { error: failure }),
        });
        if (failure === undefined) {
          completed += 1;
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
    failed,
    skipped,
    resultsPath: ledger,
  };
}

async function ensureOutputDirectory(path: string): Promise<void> {
  const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
    if (error.code !== "ENOENT") throw error;
    return undefined;
  });
  if (metadata?.isSymbolicLink()) {
    throw new Error("Multiscan output directories must not be symbolic links.");
  }
  await mkdir(path, { recursive: true, mode: 0o700 });
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
  const recovery = join(output, ".lock.recovery");
  const token = randomUUID();
  const pending = join(output, `.lock.pending-${token}`);
  const owner = `${JSON.stringify({ pid: process.pid, token })}\n`;
  const file = await open(pending, "wx", 0o600);
  let published = false;
  try {
    try {
      await file.writeFile(owner, "utf8");
      await file.sync();
    } finally {
      await file.close();
    }

    for (;;) {
      try {
        await link(pending, path);
        published = true;
        const recovering = await readLockOwner(recovery);
        if (recovering !== null && recovering.token !== token) {
          if (processIsRunning(recovering.pid)) {
            throw new Error("A multiscan supervisor is already running.");
          }
          await acquireRecoveryMarker(recovery, pending, token);
          await releaseLock(recovery, token);
        }
        if ((await readLockOwner(path))?.token !== token) {
          throw new Error("A multiscan supervisor is already running.");
        }
        published = false;
        return async () => await releaseLock(path, token);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EPERM" || code === "ENOTSUP" || code === "EOPNOTSUPP") {
          throw new Error(
            "Multiscan output requires a filesystem that supports atomic hard links; choose a local output directory.",
            { cause: error },
          );
        }
        if (code !== "EEXIST") throw error;
      }

      const existing = await readLockOwner(path);
      if (existing !== null && processIsRunning(existing.pid)) {
        throw new Error("A multiscan supervisor is already running.");
      }

      await acquireRecoveryMarker(recovery, pending, token);
      try {
        const current = await readLockOwner(path);
        if (current !== null && processIsRunning(current.pid)) {
          throw new Error("A multiscan supervisor is already running.");
        }
        const metadata = await lstat(path);
        if (metadata.isDirectory()) {
          const stale = join(output, `.lock.stale-${token}`);
          await rename(path, stale);
          const moved = await readLockOwner(stale);
          if (moved !== null && processIsRunning(moved.pid)) {
            await rename(stale, path);
            throw new Error("A multiscan supervisor is already running.");
          }
          try {
            for (let attempts = 0; ; attempts += 1) {
              try {
                await link(pending, path);
                published = true;
                break;
              } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
                  throw error;
                }
                const occupant = await readLockOwner(path);
                if (
                  attempts >= 32 ||
                  (occupant !== null && occupant.token === undefined) ||
                  (await readLockOwner(recovery))?.token !== token
                ) {
                  throw error;
                }
                await new Promise<void>((resolve) => setTimeout(resolve, 1));
              }
            }
            await rm(stale, { recursive: true, force: true });
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "EEXIST") {
              await rm(stale, { recursive: true, force: true });
              throw new Error("A multiscan supervisor is already running.");
            }
            throw error;
          }
        } else {
          if ((await readLockOwner(recovery))?.token !== token) {
            throw new Error("A multiscan supervisor is already running.");
          }
          await rename(pending, path);
          published = true;
        }
        if (
          (await readLockOwner(recovery))?.token !== token ||
          (await readLockOwner(path))?.token !== token
        ) {
          throw new Error("A multiscan supervisor is already running.");
        }
        published = false;
        return async () => await releaseLock(path, token);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      } finally {
        await releaseLock(recovery, token);
      }
    }
  } finally {
    try {
      if (published) await releaseLock(path, token);
    } finally {
      await rm(pending, { force: true });
    }
  }
}

async function acquireRecoveryMarker(
  path: string,
  pending: string,
  token: string,
): Promise<void> {
  try {
    await link(pending, path);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }

  const previous = await readLockOwner(path);
  if (previous?.token === undefined || processIsRunning(previous.pid)) {
    throw new Error("A multiscan supervisor is already running.");
  }
  const takeover = `${path}.takeover`;
  try {
    await link(pending, takeover);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      const abandoned = await readLockOwner(takeover);
      if (abandoned?.token !== undefined && !processIsRunning(abandoned.pid)) {
        const cleanup = `${takeover}.cleanup`;
        try {
          await link(pending, cleanup);
        } catch (failure) {
          if ((failure as NodeJS.ErrnoException).code === "EEXIST") {
            throw new Error("A multiscan supervisor is already running.");
          }
          throw failure;
        }
        try {
          const current = await readLockOwner(takeover);
          if (
            current?.token !== abandoned.token ||
            current.pid !== abandoned.pid ||
            processIsRunning(current.pid)
          ) {
            throw new Error("A multiscan supervisor is already running.");
          }
          await rm(takeover, { force: true });
          return await acquireRecoveryMarker(path, pending, token);
        } finally {
          await releaseLock(cleanup, token);
        }
      }
      throw new Error("A multiscan supervisor is already running.");
    }
    throw error;
  }
  try {
    const current = await readLockOwner(path);
    if (
      current?.token !== previous.token ||
      current.pid !== previous.pid ||
      processIsRunning(current.pid)
    ) {
      throw new Error("A multiscan supervisor is already running.");
    }
    await rename(takeover, path);
    if ((await readLockOwner(path))?.token !== token) {
      throw new Error("A multiscan supervisor is already running.");
    }
  } finally {
    await releaseLock(takeover, token);
  }
}

async function readLockOwner(path: string): Promise<MultiscanLockOwner | null> {
  let metadata;
  try {
    metadata = await lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  let ownerPath = path;
  if (metadata.isDirectory()) {
    ownerPath = join(path, "owner.json");
    try {
      metadata = await lstat(ownerPath);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return null;
      throw error;
    }
  }
  if (!metadata.isFile() || metadata.size > MAX_LOCK_OWNER_BYTES) {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(await readFile(ownerPath, "utf8"));
  } catch (error) {
    if (
      error instanceof SyntaxError ||
      (error as NodeJS.ErrnoException).code === "ENOENT" ||
      (error as NodeJS.ErrnoException).code === "ENOTDIR"
    ) {
      return null;
    }
    throw error;
  }
  if (
    typeof value !== "object" ||
    value === null ||
    !("pid" in value) ||
    !Number.isSafeInteger(value.pid) ||
    (value.pid as number) <= 0 ||
    (value.pid as number) > 2_147_483_647 ||
    ("token" in value && typeof value.token !== "string")
  ) {
    return null;
  }
  return {
    pid: value.pid as number,
    ...("token" in value ? { token: value.token as string } : {}),
  };
}

function processIsRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    if (code === "EPERM") return true;
    throw error;
  }
}

async function releaseLock(path: string, token: string): Promise<void> {
  const owner = await readLockOwner(path);
  if (owner?.token === token) {
    await rm(path, { force: true });
  }
}

async function ensureManifest(
  path: string,
  tasks: MultiscanTask[],
): Promise<void> {
  const expected = `${JSON.stringify({ version: 1, tasks }, null, 2)}\n`;
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
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(id)) {
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
  for (const name of [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  ]) {
    delete environment[name];
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
