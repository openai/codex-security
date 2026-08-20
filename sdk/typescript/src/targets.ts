import { execFile as execFileCallback } from "node:child_process";
import { existsSync } from "node:fs";
import { lstat, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { InvalidTargetError } from "./errors.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const UNSUPPORTED_GIT_ENVIRONMENT = new Set([
  "GIT_DIR",
  "GIT_WORK_TREE",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_REPLACE_REF_BASE",
]);
const GIT_REPOSITORY_ENVIRONMENT = new Set([
  ...UNSUPPORTED_GIT_ENVIRONMENT,
  "GIT_CEILING_DIRECTORIES",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_GRAFT_FILE",
  "GIT_IMPLICIT_WORK_TREE",
  "GIT_NAMESPACE",
  "GIT_NO_REPLACE_OBJECTS",
  "GIT_PREFIX",
  "GIT_SHALLOW_FILE",
]);

export type ScanMode = "standard" | "deep";
export type DiffTargetKind = "refs" | "working_tree";

export interface DiffTargetOptions {
  kind: DiffTargetKind;
  base: string;
  head?: string;
}

export class DiffTarget {
  readonly #brand = "DiffTarget";
  public readonly kind: DiffTargetKind;
  public readonly base: string;
  public readonly head?: string;

  public constructor(options: DiffTargetOptions) {
    void this.#brand;
    this.kind = options.kind;
    this.base = options.base;
    this.head = options.head;
    if (this.kind !== "refs" && this.kind !== "working_tree") {
      throw new InvalidTargetError(
        `Unsupported diff target kind: ${String(this.kind)}`,
      );
    }
    if (typeof this.base !== "string" || this.base.length === 0) {
      throw new InvalidTargetError("The diff base ref must be non-empty.");
    }
    if (
      this.kind === "refs" &&
      (typeof this.head !== "string" || this.head.length === 0)
    ) {
      throw new InvalidTargetError(
        "Git diff refs must include a non-empty head ref.",
      );
    }
    if (this.kind === "working_tree" && this.head !== undefined) {
      throw new InvalidTargetError(
        "Working-tree targets cannot specify a head ref.",
      );
    }
    Object.freeze(this);
  }

  public static refs({
    base,
    head = "HEAD",
  }: {
    base: string;
    head?: string;
  }): DiffTarget {
    return new DiffTarget({ kind: "refs", base, head });
  }

  public static workingTree({
    base = "HEAD",
  }: { base?: string } = {}): DiffTarget {
    return new DiffTarget({ kind: "working_tree", base });
  }
}

export type ScanTarget = "repository" | DiffTarget | readonly string[];
export type NormalizedTargetKind =
  | "repository"
  | "paths"
  | "refs"
  | "working_tree";

export interface NormalizedTarget {
  kind: NormalizedTargetKind;
  paths: readonly string[];
  base?: string;
  head?: string;
  baseRef?: string;
  headRef?: string;
}

export async function normalizeRepository(
  repository: string,
  signal?: AbortSignal,
): Promise<string> {
  const candidate = resolveRepositoryPath(repository);
  let canonical: string;
  try {
    canonical = await abortable(() => realpath(candidate), signal);
    if (!(await abortable(() => stat(canonical), signal)).isDirectory()) {
      throw new Error("not a directory");
    }
  } catch (error) {
    throwIfAborted(signal);
    throw new InvalidTargetError(
      `Repository is not a directory: ${candidate}`,
      {
        cause: error,
      },
    );
  }
  return canonical;
}

export function resolveRepositoryPath(repository: string): string {
  return resolve(expandHome(repository));
}

export async function enclosingGitWorktreeRoot(
  repository: string,
  signal?: AbortSignal,
): Promise<string | null> {
  try {
    const root = await gitOutput(
      repository,
      ["rev-parse", "--show-toplevel"],
      signal,
    );
    return await abortable(() => realpath(root), signal);
  } catch {
    throwIfAborted(signal);
    return null;
  }
}

export function validatedGitEnvironment(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): void {
  const unsupported = Object.entries(environment).find(
    ([name, value]) =>
      UNSUPPORTED_GIT_ENVIRONMENT.has(name.toUpperCase()) &&
      value !== undefined &&
      value.trim() !== "",
  );
  if (unsupported !== undefined) {
    throw new InvalidTargetError(
      `${unsupported[0]} is not supported for Codex Security scans.`,
    );
  }
}

export async function normalizeTarget(
  repository: string,
  target: ScanTarget,
  signal?: AbortSignal,
): Promise<NormalizedTarget> {
  const root = await normalizeRepository(repository, signal);
  throwIfAborted(signal);
  if (target === "repository") {
    return { kind: "repository", paths: [] };
  }

  if (target instanceof DiffTarget) {
    if (target.kind !== "refs" && target.kind !== "working_tree") {
      throw new InvalidTargetError(
        `Unsupported diff target kind: ${String(target.kind)}`,
      );
    }
    if (typeof target.base !== "string" || target.base.length === 0) {
      throw new InvalidTargetError("The diff base ref must be non-empty.");
    }
    if (
      target.kind === "refs" &&
      (typeof target.head !== "string" || target.head.length === 0)
    ) {
      throw new InvalidTargetError(
        "Git diff refs must include a non-empty head ref.",
      );
    }
    if (target.kind === "working_tree" && target.head !== undefined) {
      throw new InvalidTargetError(
        "Working-tree targets cannot specify a head ref.",
      );
    }
    await requireGitRepository(root, signal);
    const base = await resolveGitRef(root, target.base, signal);
    if (target.kind === "refs") {
      const head = target.head;
      if (typeof head !== "string" || head.length === 0) {
        throw new InvalidTargetError(
          "Git diff refs must include a non-empty head ref.",
        );
      }
      return {
        kind: "refs",
        paths: [],
        base,
        head: await resolveGitRef(root, head, signal),
        baseRef: target.base,
        headRef: head,
      };
    }
    return {
      kind: "working_tree",
      paths: [],
      base,
      head: await resolveGitRef(root, "HEAD", signal),
      baseRef: target.base,
      headRef: "HEAD",
    };
  }

  if (!Array.isArray(target)) {
    throw new InvalidTargetError(
      "Scan target must be 'repository', a DiffTarget, or an array of paths.",
    );
  }
  if (target.length === 0) {
    throw new InvalidTargetError(
      "A path scan target must contain at least one path.",
    );
  }

  const paths: string[] = [];
  for (const value of target) {
    throwIfAborted(signal);
    if (typeof value !== "string") {
      throw new InvalidTargetError(
        "Path scan targets must contain only strings.",
      );
    }
    if (value.length === 0) {
      throw new InvalidTargetError(
        "Path scan targets must not contain an empty path.",
      );
    }
    const candidate = isAbsolute(expandHome(value))
      ? resolve(expandHome(value))
      : resolve(root, expandHome(value));
    if (!existsSync(candidate)) {
      throw new InvalidTargetError(`Path target does not exist: ${value}`);
    }
    let canonical: string;
    try {
      canonical = await abortable(() => realpath(candidate), signal);
    } catch (error) {
      throwIfAborted(signal);
      throw new InvalidTargetError(`Path target does not exist: ${value}`, {
        cause: error,
      });
    }
    const relativePath = relative(root, canonical);
    if (
      relativePath === ".." ||
      relativePath.startsWith(`..${sep}`) ||
      isAbsolute(relativePath)
    ) {
      throw new InvalidTargetError(
        `Path target is outside the repository: ${value}`,
      );
    }
    const normalized = relativePath.split(sep).join("/") || ".";
    if (!paths.includes(normalized)) {
      paths.push(normalized);
    }
  }
  return { kind: "paths", paths };
}

export async function validateCommittedDiffCheckout(
  repository: string,
  target: NormalizedTarget,
  signal?: AbortSignal,
): Promise<void> {
  if (target.kind !== "refs") return;

  const checkoutHead = await resolveGitRef(repository, "HEAD", signal);
  if (checkoutHead !== target.head) {
    throw new InvalidTargetError(
      `Committed-diff scans require the repository checkout to match the requested head revision. Checkout HEAD is ${checkoutHead}; requested head is ${target.head}. Check out the requested head and retry.`,
    );
  }

  const status = await gitOutput(
    repository,
    ["status", "--porcelain=v1", "--untracked-files=all"],
    signal,
  );
  if (status.length !== 0) {
    throw new InvalidTargetError(
      "Committed-diff scans require a clean repository checkout. Commit, stash, or remove local changes and retry. Use `git stash --include-untracked` to stash untracked files.",
    );
  }

  const tracked = await gitOutput(repository, ["ls-files", "-t", "-z"], signal);
  if (tracked.split("\0").some((entry) => entry.startsWith("S "))) {
    throw new InvalidTargetError(
      "Committed-diff scans require a full repository checkout. Sparse checkouts are not supported; materialize skipped tracked files and retry.",
    );
  }
}

export function validateMode(target: NormalizedTarget, mode: ScanMode): void {
  if (mode !== "standard" && mode !== "deep") {
    throw new InvalidTargetError(`Unsupported scan mode: ${String(mode)}`);
  }
  if (
    mode === "deep" &&
    (target.kind === "refs" || target.kind === "working_tree")
  ) {
    throw new InvalidTargetError(
      "Deep mode supports repository and path targets only.",
    );
  }
}

export async function repositoryRevision(
  repository: string,
  signal?: AbortSignal,
): Promise<string | null> {
  try {
    return await gitOutput(
      repository,
      ["rev-parse", "--verify", "HEAD^{commit}"],
      signal,
    );
  } catch {
    throwIfAborted(signal);
    return null;
  }
}

async function requireGitRepository(
  repository: string,
  signal?: AbortSignal,
): Promise<void> {
  let root: string;
  try {
    root = await gitOutput(
      repository,
      ["rev-parse", "--show-toplevel"],
      signal,
    );
  } catch (error) {
    throwIfAborted(signal);
    throw new InvalidTargetError(
      `Diff targets require a Git repository: ${repository}`,
      {
        cause: error,
      },
    );
  }
  const canonicalRoot = await abortable(() => realpath(root), signal);
  if (canonicalRoot !== repository) {
    throw new InvalidTargetError(
      `Diff target repository must be the Git worktree root: ${canonicalRoot}`,
    );
  }
}

async function resolveGitRef(
  repository: string,
  ref: string,
  signal?: AbortSignal,
): Promise<string> {
  try {
    return await gitOutput(
      repository,
      ["rev-parse", "--verify", "--end-of-options", `${ref}^{commit}`],
      signal,
    );
  } catch (error) {
    throwIfAborted(signal);
    throw new InvalidTargetError(`unknown Git ref: ${ref}`, { cause: error });
  }
}

async function gitOutput(
  repository: string,
  args: readonly string[],
  signal?: AbortSignal,
): Promise<string> {
  throwIfAborted(signal);
  const command = await resolveTrustedExecutable(
    "git",
    isolatedGitEnvironment(args[0] === "rev-parse"),
    await outermostGitMarkerRoot(repository, signal),
  );
  if (command === null)
    throw new Error("Git is not available on a trusted PATH.");
  throwIfAborted(signal);
  const { stdout } = await execFile(
    command.executable,
    ["-c", "core.fsmonitor=false", "-C", repository, ...args],
    {
      encoding: "utf8",
      signal,
      env: command.environment,
    },
  );
  return stdout.replace(process.platform === "win32" ? /\r?\n$/u : /\n$/u, "");
}

async function outermostGitMarkerRoot(
  repository: string,
  signal?: AbortSignal,
): Promise<string> {
  let current = repository;
  let root = repository;
  while (true) {
    throwIfAborted(signal);
    try {
      await lstat(join(current, ".git"));
      root = current;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const parent = dirname(current);
    if (parent === current) return root;
    current = parent;
  }
}

function isolatedGitEnvironment(
  preserveGitConfiguration: boolean,
): NodeJS.ProcessEnv {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    const normalized = name.toUpperCase();
    if (
      GIT_REPOSITORY_ENVIRONMENT.has(normalized) ||
      normalized === "GIT_ALLOW_PROTOCOL" ||
      (!preserveGitConfiguration && normalized.startsWith("GIT_"))
    ) {
      delete environment[name];
    }
  }
  environment["GIT_ALLOW_PROTOCOL"] = "";
  return environment;
}

export async function abortable<T>(
  operation: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  if (signal === undefined) return await operation();
  throwIfAborted(signal);
  return await new Promise<T>((resolvePromise, reject) => {
    const onAbort = (): void => reject(abortReason(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    void Promise.resolve()
      .then(operation)
      .then(
        (value) => {
          signal.removeEventListener("abort", onAbort);
          resolvePromise(value);
        },
        (error: unknown) => {
          signal.removeEventListener("abort", onAbort);
          reject(error);
        },
      );
  });
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) throw abortReason(signal);
}

function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

function expandHome(value: string): string {
  if (value === "~") {
    return homedir();
  }
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    return resolve(homedir(), value.slice(2).replace(/^[/\\]+/, ""));
  }
  return value;
}
