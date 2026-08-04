import { execFile as execFileCallback } from "node:child_process";
import { relative, resolve, sep } from "node:path";
import { promisify } from "node:util";

import { SecurityError, canonicalPath, isDirectory, pathExists } from "./util.mjs";

const execFile = promisify(execFileCallback);

export const SCAN_MODES = ["standard", "deep"];

/**
 * Git is invoked with a scrubbed environment so a repository-local config or an
 * inherited GIT_DIR cannot redirect the revision resolution used to identify
 * the scan target.
 */
export function gitEnvironment() {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.startsWith("GIT_")) delete environment[name];
  }
  environment["GIT_CONFIG_NOSYSTEM"] = "1";
  environment["GIT_TERMINAL_PROMPT"] = "0";
  environment["GIT_OPTIONAL_LOCKS"] = "0";
  return environment;
}

export async function git(repository, args, options = {}) {
  const { stdout } = await execFile("git", ["-C", repository, ...args], {
    env: gitEnvironment(),
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    windowsHide: true,
    signal: options.signal,
  });
  return stdout;
}

export async function isGitRepository(repository) {
  try {
    const stdout = await git(repository, ["rev-parse", "--is-inside-work-tree"]);
    return stdout.trim() === "true";
  } catch {
    return false;
  }
}

export async function repositoryRevision(repository) {
  try {
    return (await git(repository, ["rev-parse", "HEAD"])).trim();
  } catch {
    return null;
  }
}

async function resolveCommit(repository, revision, label) {
  try {
    const stdout = await git(repository, ["rev-parse", "--verify", `${revision}^{commit}`]);
    const resolved = stdout.trim();
    if (!/^[0-9a-f]{40}$/.test(resolved)) {
      throw new Error(`unexpected revision output: ${resolved}`);
    }
    return resolved;
  } catch (error) {
    throw new SecurityError(
      `${label} could not be resolved in this repository: ${revision}`,
      { cause: error },
    );
  }
}

export async function resolveRepositoryPath(value) {
  const absolute = resolve(value);
  if (!(await isDirectory(absolute))) {
    throw new SecurityError(`Scan target is not a directory: ${value}`);
  }
  return await canonicalPath(absolute);
}

/**
 * Normalizes the CLI target flags into the shape register-cli-scan validates.
 *
 * `paths` are stored repository-relative with POSIX separators because that is
 * what the workbench recipe validator requires; passing native Windows paths
 * here is rejected on the Python side rather than silently widening scope.
 */
export async function normalizeTarget(repository, options) {
  const selectors = [
    options.paths?.length ? "paths" : null,
    options.diff !== undefined ? "diff" : null,
    options.workingTree !== undefined ? "working-tree" : null,
  ].filter(Boolean);
  if (selectors.length > 1) {
    throw new SecurityError(
      `Choose one scan target: ${selectors.map((name) => `--${name}`).join(", ")} cannot be combined.`,
    );
  }

  if (options.paths?.length) {
    const paths = [];
    for (const entry of options.paths) {
      const absolute = resolve(repository, entry);
      const relativePath = relative(repository, absolute);
      if (
        relativePath === "" ||
        relativePath.startsWith("..") ||
        relativePath.includes(`..${sep}`)
      ) {
        throw new SecurityError(`--path must stay inside the repository: ${entry}`);
      }
      if (!(await pathExists(absolute))) {
        throw new SecurityError(`--path does not exist: ${entry}`);
      }
      paths.push(relativePath.split(sep).join("/"));
    }
    return { kind: "paths", paths: [...new Set(paths)].sort() };
  }

  if (options.diff !== undefined) {
    if (!(await isGitRepository(repository))) {
      throw new SecurityError("--diff requires the target to be a Git repository.");
    }
    const [rawBase, rawHead] = splitDiffRange(options.diff);
    const base = await resolveCommit(repository, rawBase, "Base revision");
    const head = await resolveCommit(repository, rawHead ?? "HEAD", "Head revision");
    if (base === head) {
      throw new SecurityError("The base and head revisions of a diff scan must differ.");
    }
    return {
      kind: "refs",
      paths: [],
      base,
      head,
      baseRef: rawBase,
      headRef: rawHead ?? "HEAD",
    };
  }

  if (options.workingTree !== undefined) {
    if (!(await isGitRepository(repository))) {
      throw new SecurityError("--working-tree requires the target to be a Git repository.");
    }
    const baseRef = options.workingTree === true ? "HEAD" : options.workingTree;
    const base = await resolveCommit(repository, baseRef, "Base revision");
    const head = await resolveCommit(repository, "HEAD", "Head revision");
    return { kind: "working_tree", paths: [], base, head, baseRef, headRef: "HEAD" };
  }

  return { kind: "repository", paths: [] };
}

function splitDiffRange(value) {
  const trimmed = String(value).trim();
  if (trimmed === "") {
    throw new SecurityError("--diff requires a revision or revision range.");
  }
  const separator = trimmed.includes("...") ? "..." : trimmed.includes("..") ? ".." : null;
  if (separator === null) return [trimmed, undefined];
  const [base, head] = trimmed.split(separator);
  if (!base) throw new SecurityError(`--diff is missing a base revision: ${value}`);
  return [base, head === "" ? undefined : head];
}

export function targetDescription(target) {
  switch (target.kind) {
    case "repository":
      return "entire repository";
    case "paths":
      return `scoped paths (${target.paths.join(", ")})`;
    case "refs":
      return `diff ${target.baseRef}..${target.headRef}`;
    case "working_tree":
      return `working tree vs ${target.baseRef}`;
    default:
      return target.kind;
  }
}

export function skillNameFor(target, mode) {
  if (target.kind === "refs" || target.kind === "working_tree") return "security-diff-scan";
  return mode === "deep" ? "deep-security-scan" : "security-scan";
}

export async function changedFileCount(repository, target) {
  if (target.kind === "refs") {
    const stdout = await git(repository, ["diff", "--name-only", `${target.base}..${target.head}`]);
    return stdout.split("\n").filter((line) => line.trim() !== "").length;
  }
  if (target.kind === "working_tree") {
    const stdout = await git(repository, ["status", "--porcelain"]);
    return stdout.split("\n").filter((line) => line.trim() !== "").length;
  }
  return null;
}
