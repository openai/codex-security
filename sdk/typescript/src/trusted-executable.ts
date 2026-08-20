import { constants } from "node:fs";
import { access, realpath, stat } from "node:fs/promises";
import {
  delimiter,
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

export async function resolveTrustedExecutable(
  candidate: string,
  environment: Readonly<Record<string, string | undefined>>,
  protectedRoot: string,
): Promise<TrustedExecutable | null> {
  const root = await realpath(protectedRoot).catch(() =>
    resolve(protectedRoot),
  );
  const path = Object.entries(environment).find(
    ([name]) => name.toUpperCase() === "PATH",
  )?.[1];
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
    if (canonical === null || isWithin(root, canonical)) continue;
    if (!entries.includes(canonical)) entries.push(canonical);
  }

  const pathLike = candidate.includes("/") || candidate.includes("\\");
  // execFile cannot launch batch files, but their symlink targets still affect PATH trust.
  // CreateProcess appends .exe to an extensionless explicit path, so inspect the file that
  // will actually run instead of rejecting an otherwise valid Windows configuration.
  const extensions =
    process.platform === "win32"
      ? /\.(?:exe|com)$/iu.test(candidate)
        ? [{ suffix: "", runnable: true }]
        : pathLike
          ? extname(candidate) === ""
            ? [{ suffix: ".exe", runnable: true }]
            : [{ suffix: "", runnable: false }]
          : [
              { suffix: ".exe", runnable: true },
              { suffix: ".com", runnable: true },
              { suffix: ".bat", runnable: false },
              { suffix: ".cmd", runnable: false },
              { suffix: "", runnable: false },
            ]
      : [{ suffix: "", runnable: true }];
  const candidates = pathLike
    ? extensions.map((extension) => ({
        entry: null,
        path: resolve(`${candidate}${extension.suffix}`),
        runnable: extension.runnable,
      }))
    : entries.flatMap((entry) =>
        extensions.map((extension) => ({
          entry,
          path: join(entry, `${candidate}${extension.suffix}`),
          runnable: extension.runnable,
        })),
      );
  const unsafeEntries = new Set<string>();
  let executable: string | null = null;
  for (const current of candidates) {
    const canonical = await realpath(current.path).catch(() => null);
    if (canonical === null) continue;
    if (isWithin(root, canonical)) {
      if (current.entry !== null) unsafeEntries.add(current.entry);
      continue;
    }
    if (!current.runnable) continue;
    try {
      await access(
        canonical,
        process.platform === "win32" ? constants.F_OK : constants.X_OK,
      );
      if (!(await stat(canonical)).isFile()) continue;
      executable ??= pathLike ? canonical : current.path;
    } catch {
      continue;
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

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return (
    path === "" ||
    (path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path))
  );
}
