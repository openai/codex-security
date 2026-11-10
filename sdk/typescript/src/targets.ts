import {
  expandHome,
  isolatedGitEnvironment,
  walkGitMarkers,
  normalizeRepository,
  requireUtf8Path,
  enclosingGitWorktreeRoot,
  relativePathIsOutside,
  gitOutput,
  gitMarkerRoot,
  abortable,
  throwIfAborted,
  nullIfMissingPath,
} from "#plugin-shared/checkout/git";
export {
  UNSUPPORTED_GIT_ENVIRONMENT,
  normalizeRepository,
  resolveRepositoryPath,
  enclosingGitWorktreeRoot,
  gitMetadataDirectories,
  gitObjectDirectories,
  relativePathIsOutside,
  validatedGitEnvironment,
  repositoryRevision,
  trustedGitCommand,
  gitOutput,
  gitMarkerRoot,
  abortable,
  nullIfMissingFile,
  nullIfMissingPath,
} from "#plugin-shared/checkout/git";
import { isNonEmptyString } from "./value.js";
import { execFile as execFileCallback } from "node:child_process";
import type { Stats } from "node:fs";
import { copyFile, lstat, mkdtemp, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { InvalidTargetError, errorMessage } from "./errors.js";
import type { TrustedExecutable } from "./trusted-executable.js";

import type { ScanMode } from "./scan-modes.js";
export type { ScanMode } from "./scan-modes.js";

const execFile = promisify(execFileCallback);

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
    requireValidDiffTarget(this);
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

function requireValidDiffTarget(target: DiffTargetOptions): void {
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
}

export type ScanTarget = "repository" | DiffTarget | readonly string[];
export type NormalizedTargetKind =
  "repository" | "paths" | "refs" | "working_tree";

export interface NormalizedTarget {
  kind: NormalizedTargetKind;
  paths: readonly string[];
  base?: string;
  head?: string;
  baseRef?: string;
  headRef?: string;
}

export async function enclosingGitWorktreeRoots(
  repository: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const roots: string[] = [];
  let directory = repository;
  for (;;) {
    const root = await enclosingGitWorktreeRoot(directory, signal, {
      requireIfPresent: true,
    });
    if (root === null) return roots;
    roots.push(root);
    const parent = dirname(root);
    if (parent === root) return roots;
    directory = parent;
  }
}

export async function isGitMetadataDirectory(
  repository: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const metadata = async (name: string, followLinks = false) =>
    await (followLinks ? stat : lstat)(join(repository, name)).catch(
      nullIfMissingPath,
    );
  const head = await metadata("HEAD");
  if (head === null) {
    // A common directory can outlive its main worktree's HEAD. Require both
    // Git storage directories and its format declaration, not names alone.
    if (!(await metadata("config", true))?.isFile()) return false;
    const [objects, refs] = await Promise.all([
      metadata("objects", true),
      metadata("refs", true),
    ]);
    if (!objects?.isDirectory() || !refs?.isDirectory()) return false;
    try {
      const version = await gitOutput(
        repository,
        [
          "config",
          "--no-includes",
          "--file",
          join(repository, "config"),
          "--type=int",
          "--get",
          "core.repositoryformatversion",
        ],
        signal,
        { LC_ALL: "C" },
      );
      return /^\d+$/u.test(version);
    } catch (error) {
      throwIfAborted(signal);
      // Application folders can share these filenames without using Git's
      // config format. Missing or invalid declarations do not identify metadata.
      if (
        error instanceof Error &&
        "code" in error &&
        (error.code === 1 ||
          (error.code === 128 &&
            "stderr" in error &&
            typeof error.stderr === "string" &&
            /fatal: bad (?:config line|numeric config value)/u.test(
              error.stderr,
            )))
      )
        return false;
      throw error;
    }
  }
  if (!head.isFile() && !head.isSymbolicLink()) return false;
  try {
    // Resolve from outside the candidate so Git does not load its configuration.
    const directory = await gitOutput(
      repository,
      ["rev-parse", "--resolve-git-dir", repository],
      signal,
      { LC_ALL: "C" },
      dirname(repository),
    );
    return (
      relative(await realpath(directory), await realpath(repository)) === ""
    );
  } catch (error) {
    throwIfAborted(signal);
    if (
      error instanceof Error &&
      "code" in error &&
      error.code === 128 &&
      "stderr" in error &&
      typeof error.stderr === "string" &&
      error.stderr.trimEnd() === `fatal: not a gitdir '${repository}'`
    )
      return false;
    throw error;
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
    requireValidDiffTarget(target);
    await requireGitRepository(root, signal);
    const base = await resolveGitRef(root, target.base, signal);
    const kind = target.kind === "refs" ? "refs" : "working_tree";
    const head = kind === "refs" ? target.head : "HEAD";
    if (!isNonEmptyString(head)) {
      throw new InvalidTargetError(
        "Git diff refs must include a non-empty head ref.",
      );
    }
    return {
      kind,
      paths: [],
      base,
      head: await resolveGitRef(root, head, signal),
      baseRef: target.base,
      headRef: head,
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

  const paths = new Set<string>();
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
    requireUtf8Path("Path target", value);
    const candidate = isAbsolute(expandHome(value))
      ? resolve(expandHome(value))
      : resolve(root, expandHome(value));
    let canonical: string;
    try {
      // Some runtimes cannot canonicalize special files to filesystem paths.
      requireScanPathType(
        value,
        await abortable(() => stat(candidate), signal),
      );
      const resolved = await abortable(
        () => realpath(candidate, { encoding: "buffer" }),
        signal,
      );
      canonical = resolved.toString();
      if (!isAbsolute(canonical)) {
        throw new InvalidTargetError(`Could not resolve path target: ${value}`);
      }
      requireScanPathType(
        value,
        await abortable(() => lstat(resolved), signal),
      );
      requireUtf8Path("Path target", value, resolved);
    } catch (error) {
      throwIfAborted(signal);
      if (error instanceof InvalidTargetError) throw error;
      throw new InvalidTargetError(`Path target does not exist: ${value}`, {
        cause: error,
      });
    }
    const relativePath = relative(root, canonical);
    if (relativePathIsOutside(relativePath)) {
      throw new InvalidTargetError(
        `Path target is outside the repository: ${value}`,
      );
    }
    if (
      process.platform === "win32" &&
      relativePath.split(sep).some((part) => part.includes(":"))
    ) {
      throw new InvalidTargetError(
        `Path target contains an unsupported colon component: ${value}`,
      );
    }
    const normalized = relativePath.split(sep).join("/") || ".";
    paths.add(normalized);
  }
  return { kind: "paths", paths: [...paths] };
}

function requireScanPathType(value: string, metadata: Stats): void {
  if (!metadata.isFile() && !metadata.isDirectory()) {
    throw new InvalidTargetError(
      `Path target is not a regular file or directory: ${value}`,
    );
  }
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

  const tracked = (
    await gitOutput(repository, ["ls-files", "-v", "-z"], signal)
  ).split("\0");
  if (tracked.some((entry) => /^[Ss] /u.test(entry))) {
    throw new InvalidTargetError(
      "Committed-diff scans require a full repository checkout. Sparse checkouts are not supported; materialize skipped tracked files and retry.",
    );
  }
  if (tracked.some((entry) => entry.startsWith("h "))) {
    await verifyAssumedUnchangedFiles(repository, signal);
  }
}

async function verifyAssumedUnchangedFiles(
  repository: string,
  signal?: AbortSignal,
): Promise<void> {
  const index = await gitOutput(
    repository,
    ["rev-parse", "--path-format=absolute", "--git-path", "index"],
    signal,
  );
  // Git changes to the repository before resolving GIT_INDEX_FILE, even when TMPDIR is relative.
  const directory = await mkdtemp(
    join(await realpath(tmpdir()), "codex-security-git-index-"),
  );
  const copy = join(directory, "index");
  try {
    // Git refreshes stat data and flags. Keep that write and any hooks out of the checkout.
    await copyFile(index, copy);
    await gitOutput(
      repository,
      [
        "-c",
        `core.hooksPath=${directory}`,
        "-c",
        "core.splitIndex=false",
        "update-index",
        "--really-refresh",
      ],
      signal,
      { GIT_INDEX_FILE: copy },
    );
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === 1) {
      throw new InvalidTargetError(
        "Committed-diff scans require a clean repository checkout. A tracked file marked assume-unchanged has changed on disk.",
        { cause: error },
      );
    }
    throw error;
  } finally {
    await rm(directory, { recursive: true, force: true });
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
      `Diff targets require a Git repository: ${repository}. ${errorMessage(error)}`,
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
    throw new InvalidTargetError(
      `unknown Git ref: ${ref}. ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

/** Read-only identity for matching saved history with an already selected host Git. */
export async function gitHistoryIdentity(
  repository: string,
  git: TrustedExecutable,
  signal?: AbortSignal,
): Promise<{ commonDirectory: string | null; origin: string | null }> {
  const read = async (args: readonly string[]): Promise<string | null> => {
    try {
      const { stdout } = await execFile(
        git.executable,
        ["-c", "core.fsmonitor=false", "-C", repository, ...args],
        {
          encoding: "utf8",
          signal,
          env: isolatedGitEnvironment(true, git.environment),
          maxBuffer: Infinity,
        },
      );
      return (
        stdout.replace(process.platform === "win32" ? /\r?\n$/u : /\n$/u, "") ||
        null
      );
    } catch {
      throwIfAborted(signal);
      return null;
    }
  };
  const [commonDirectory, origin] = await Promise.all([
    read(["rev-parse", "--path-format=absolute", "--git-common-dir"]),
    read(["remote", "get-url", "origin"]),
  ]);
  return { commonDirectory, origin };
}

/** Protect both the stored path's checkout and its resolved destination. */
export async function gitProtectionRoots(
  repository: string,
  signal?: AbortSignal,
): Promise<string[]> {
  const roots = await Promise.all([
    gitMarkerRoot(repository, signal, "outermost"),
    walkGitMarkers(resolve(repository), signal, "outermost"),
  ]);
  return [...new Set(roots.filter((root): root is string => root !== null))];
}
