import { AsyncLocalStorage } from "node:async_hooks";
import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import {
  basename,
  delimiter,
  dirname,
  extname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";

export interface TrustedExecutable {
  executable: string;
  environment: Record<string, string | undefined>;
}

export interface InspectedExecutable {
  executable: string | null;
  environment: Record<string, string | undefined>;
}

const additionalRoots = new AsyncLocalStorage<readonly string[]>();

function canonicalRoot(root: string): Promise<string> {
  return realpath(root).catch(() => resolve(root));
}

/** Include every selected source when a campaign launches tools from a new checkout. */
export async function withProtectedExecutableRoots<T>(
  roots: readonly string[],
  run: () => Promise<T>,
): Promise<T> {
  const canonical = await Promise.all(roots.map(canonicalRoot));
  return additionalRoots.run(
    [...new Set([...(additionalRoots.getStore() ?? []), ...canonical])],
    run,
  );
}

/** Host launchers and the workbench inherit the same Git search path as checkout. */
export function campaignCommandEnvironment(
  environment: Record<string, string | undefined>,
): Promise<Record<string, string | undefined>> | undefined {
  if (!additionalRoots.getStore() || searchPath(environment) === undefined)
    return undefined;
  return inspectTrustedExecutable("git", environment, []).then(
    (command) => command.environment,
  );
}

function searchPath(
  environment: Readonly<NodeJS.ProcessEnv>,
): string | undefined {
  return (
    environment["PATH"] ??
    Object.entries(environment).find(
      ([name, value]) => value !== undefined && name.toUpperCase() === "PATH",
    )?.[1]
  );
}

export async function resolveTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string | readonly string[],
): Promise<TrustedExecutable | null> {
  const inspected = await inspectTrustedExecutable(
    candidate,
    environment,
    protectedRoot,
  );
  return inspected.executable === null
    ? null
    : { executable: inspected.executable, environment: inspected.environment };
}

export async function inspectTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string | readonly string[],
): Promise<InspectedExecutable> {
  const roots = await Promise.all(
    (typeof protectedRoot === "string" ? [protectedRoot] : protectedRoot).map(
      canonicalRoot,
    ),
  );
  const campaign = additionalRoots.getStore();
  if (campaign) roots.push(...campaign);
  const isProtected = (path: string) =>
    roots.some((root) => isWithin(root, path));
  const path = searchPath(environment);
  const entries: string[] = [];
  for (let entry of path?.split(delimiter) ?? []) {
    if (
      process.platform === "win32" &&
      entry.startsWith('"') &&
      entry.endsWith('"')
    ) {
      entry = entry.slice(1, -1);
    }
    if (entry.length === 0) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isProtected(canonical)) continue;
    // A directory containing the separator can be on PATH through a safe alias.
    // Keep that absolute spelling so joining the entries cannot split its name.
    const directory = canonical.includes(delimiter)
      ? isAbsolute(entry)
        ? entry
        : `${process.cwd()}${sep}${entry}`
      : canonical;
    if (
      !directory.includes(delimiter) &&
      !isProtected(directory) &&
      !entries.includes(directory)
    )
      entries.push(directory);
  }

  const pathLike = candidate.includes("/") || candidate.includes("\\");
  // execFile cannot launch batch files, but their symlink targets still affect PATH trust.
  // CreateProcess appends .exe to an extensionless explicit path, so inspect the file that
  // will actually run instead of rejecting an otherwise valid Windows configuration.
  const windows = process.platform === "win32";
  const suffixes =
    !windows || /\.(?:exe|com)$/iu.test(candidate)
      ? [""]
      : pathLike
        ? [extname(candidate) === "" ? ".exe" : ""]
        : [".exe", ".com", ".bat", ".cmd", ""];
  const names = suffixes.map((suffix) => candidate + suffix);
  // The POSIX npm Codex launcher also searches the campaign PATH for Node.
  if (campaign && !windows && candidate === "git") names.push("node");
  const candidates = (pathLike ? [null] : entries).flatMap((entry) => {
    // PATH lookup traverses links before "..". join() would collapse it first.
    const directory = entry ?? "";
    const prefix =
      directory && !directory.endsWith(sep) ? directory + sep : directory;
    return names.map((name) => ({
      entry,
      path: entry === null && windows ? resolve(name) : prefix + name,
      runnable: windows ? /\.(?:exe|com)$/iu.test(name) : name === candidate,
    }));
  });
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const current of candidates) {
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) continue;
    if (isProtected(canonical)) {
      if (current.entry !== null) unsafeEntries.add(current.entry);
      continue;
    }
    if (process.platform === "win32" && /\.(?:bat|cmd)$/iu.test(canonical)) {
      continue;
    }
    if (!current.runnable) continue;
    try {
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      if (!(await stat(canonical)).isFile()) continue;
      // Keep explicit virtualenv launchers, but resolve repository-local aliases
      // to the trusted target instead of invoking them from the repository.
      const invocationPath = pathLike
        ? join(await realpath(dirname(current.path)), basename(current.path))
        : current.path;
      executable ??=
        pathLike && (isProtected(current.path) || isProtected(invocationPath))
          ? canonical
          : invocationPath;
    } catch {
      continue;
    }
  }

  const sanitizedEnvironment = { ...environment };
  for (const name of Object.keys(sanitizedEnvironment)) {
    if (name.toUpperCase() === "PATH") delete sanitizedEnvironment[name];
  }
  const filteredPath = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
  // An empty POSIX PATH searches the current directory.
  sanitizedEnvironment["PATH"] =
    campaign && process.platform !== "win32" && !filteredPath
      ? "/dev/null"
      : filteredPath;
  return { executable, environment: sanitizedEnvironment };
}

/** @internal */
export function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}
