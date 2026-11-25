import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import { delimiter, isAbsolute, join, relative, resolve, sep } from "node:path";

export interface TrustedExecutable {
  executable: string;
  environment: Record<string, string | undefined>;
}

export type TraceTool = "git" | "opengrep" | "rg";

export async function resolveTrustedExecutable(
  name: TraceTool,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<TrustedExecutable | null> {
  const root = await realpath(protectedRoot).catch(() =>
    resolve(protectedRoot),
  );
  const windows = process.platform === "win32";
  const searchPath =
    environment["PATH"] ??
    Object.entries(environment).find(
      ([name]) => name.toUpperCase() === "PATH",
    )?.[1];
  const entries: string[] = [];
  for (let entry of searchPath?.split(delimiter) ?? []) {
    if (windows && entry.startsWith('"') && entry.endsWith('"')) {
      entry = entry.slice(1, -1);
    }
    if (entry.length === 0) continue;
    const canonical = await realpath(entry).catch(() => null);
    if (canonical === null || isWithin(root, canonical)) continue;
    if (!entries.includes(canonical)) entries.push(canonical);
  }

  // Inspect all entries, even after finding a runnable tool. Batch files and
  // later symlinks into the checkout can still make the inherited PATH unsafe.
  const suffixes = windows ? [".exe", ".com", ".bat", ".cmd", ""] : [""];
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const entry of entries) {
    for (const suffix of suffixes) {
      const path = join(entry, name + suffix);
      const canonical = await realpath(path).catch(() => null);
      if (canonical === null) continue;
      if (isWithin(root, canonical)) {
        unsafeEntries.add(entry);
        continue;
      }
      if (windows) {
        if (suffix !== ".exe" && suffix !== ".com") continue;
        if (/\.(?:bat|cmd)$/iu.test(canonical)) continue;
      }
      try {
        await access(canonical, windows ? constants.F_OK : constants.X_OK);
        if ((await stat(canonical)).isFile()) executable ??= path;
      } catch {
        continue;
      }
    }
  }
  if (executable === null) return null;

  const sanitizedEnvironment = { ...environment };
  for (const name of Object.keys(sanitizedEnvironment)) {
    if (name.toUpperCase() === "PATH") delete sanitizedEnvironment[name];
  }
  sanitizedEnvironment["PATH"] = entries
    .filter((entry) => !unsafeEntries.has(entry))
    .join(delimiter);
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
