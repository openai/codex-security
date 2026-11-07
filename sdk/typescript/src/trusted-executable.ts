import { AsyncLocalStorage } from "node:async_hooks";
import { constants } from "node:fs";
import { pathToFileURL } from "node:url";
import { access, readlink, realpath, stat } from "node:fs/promises";
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

interface ToolPathView {
  path: string;
  cleanup(): void;
  allows: (path: string) => boolean;
}

const campaignScope = new AsyncLocalStorage<{
  roots: readonly string[];
  views: Map<string, ToolPathView>;
  project?: (
    path: string,
    cwd: string,
    roots: readonly string[],
    mode: "campaign",
  ) => ToolPathView;
}>();

function canonicalRoot(root: string): Promise<string> {
  return realpath(root).catch(() => resolve(root));
}

async function campaignPathHelper() {
  const { bundledPluginRoot } = await import("./runtime.js");
  const path = join(await bundledPluginRoot(), "mcp/helpers.mjs");
  const project = (await import(pathToFileURL(path).href)).default
    .posixToolPath;
  if (typeof project !== "function")
    throw new Error("The bundled plugin is missing campaign tool lookup.");
  return project;
}

/** Include every selected source when a campaign launches tools from a new checkout. */
export async function withProtectedExecutableRoots<T>(
  roots: readonly string[],
  run: () => Promise<T>,
): Promise<T> {
  const canonical = await Promise.all(roots.map(canonicalRoot));
  const scope = {
    roots: [
      ...new Set([...(campaignScope.getStore()?.roots ?? []), ...canonical]),
    ],
    views: new Map<string, ToolPathView>(),
    project:
      process.platform === "win32" ? undefined : await campaignPathHelper(),
  };
  try {
    return await campaignScope.run(scope, run);
  } finally {
    for (const view of scope.views.values()) view.cleanup();
  }
}

/** Host launchers and the workbench inherit the same Git search path as checkout. */
export function campaignCommandEnvironment(
  environment: Record<string, string | undefined>,
): Promise<Record<string, string | undefined>> | undefined {
  if (!campaignScope.getStore() || searchPath(environment) === undefined)
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
  const selectedRoots = await Promise.all(
    (typeof protectedRoot === "string" ? [protectedRoot] : protectedRoot).map(
      canonicalRoot,
    ),
  );
  const campaign = campaignScope.getStore();
  const extra = campaign
    ? selectedRoots.filter(
        (root) => !campaign.roots.some((base) => isWithin(base, root)),
      )
    : selectedRoots;
  const roots = campaign ? [...campaign.roots, ...extra] : selectedRoots;
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

  let view: ToolPathView | undefined;
  if (campaign?.project) {
    // Workers inherit this PATH across process boundaries. Keep the links until
    // every row, including its pending child processes, has settled.
    const path = entries.join(delimiter);
    const cwd = process.cwd();
    const key = JSON.stringify([cwd, extra, path]);
    view = campaign.views.get(key);
    if (!view) {
      view = campaign.project(path || "/dev/null", cwd, roots, "campaign");
      campaign.views.set(key, view);
    }
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
  const primary = suffixes.map((suffix) => candidate + suffix);
  // Windows inventory searches for ripgrep after checkout passes PATH to the plugin.
  const names =
    campaign && windows && candidate === "git"
      ? [...primary, "rg.exe", "rg.com"]
      : primary;
  const candidates = (pathLike ? [null] : entries).flatMap((entry) => {
    // PATH lookup traverses links before "..". join() would collapse it first.
    const directory = entry ?? "";
    const prefix =
      directory && !directory.endsWith(sep) ? directory + sep : directory;
    return names.map((name) => ({
      entry,
      path: entry === null && windows ? resolve(name) : prefix + name,
      runnable:
        primary.includes(name) && (!windows || /\.(?:exe|com)$/iu.test(name)),
    }));
  });
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const current of candidates) {
    if (campaign && windows && current.entry !== null) {
      // A sibling checkout can populate or replace this Windows shim later.
      const link = await readlink(current.path).catch(() => undefined);
      if (link && isProtected(resolve(dirname(current.path), link))) {
        unsafeEntries.add(current.entry);
        continue;
      }
    }
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) continue;
    const crossesSource = view !== undefined && !view.allows(current.path);
    if (isProtected(canonical) || (!pathLike && crossesSource)) {
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
        pathLike &&
        (crossesSource ||
          isProtected(current.path) ||
          isProtected(invocationPath))
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
  const filteredPath =
    view?.path ??
    entries.filter((entry) => !unsafeEntries.has(entry)).join(delimiter);
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
