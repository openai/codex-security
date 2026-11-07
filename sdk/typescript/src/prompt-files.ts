import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readlink, realpath } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  resolve,
  sep,
} from "node:path";
import { CodexSecurityError } from "./errors.js";
import { expandHome } from "./runtime.js";
import { isWithin } from "./trusted-executable.js";
import type { ScanPromptSettings } from "./scan-settings.js";

type ResolvedScanPrompts = Pick<
  ScanPromptSettings,
  "scanPrompt" | "validationPrompt" | "postScanPrompt"
> & {
  scanPromptFile: undefined;
  validationPromptFile: undefined;
  postScanPromptFile: undefined;
};

/** Resolve selected files once; an inline SDK prompt overrides its file. */
export async function resolveScanPrompts(
  options: ScanPromptSettings,
  repository: string | readonly string[],
  directory = process.cwd(),
): Promise<ResolvedScanPrompts> {
  const read = async (inline: string | undefined, file: string | undefined) =>
    inline !== undefined || file === undefined
      ? inline
      : await readRegularInputFile(
          resolve(directory, expandHome(file)),
          repository,
        );
  const [scanPrompt, validationPrompt, postScanPrompt] = await Promise.all([
    read(options.scanPrompt, options.scanPromptFile),
    read(options.validationPrompt, options.validationPromptFile),
    read(options.postScanPrompt, options.postScanPromptFile),
  ]);
  if (
    options.validationPrompt === undefined &&
    validationPrompt !== undefined &&
    !validationPrompt.trim()
  ) {
    throw new CodexSecurityError("The validation prompt must not be empty.");
  }
  return {
    scanPrompt:
      options.scanPrompt !== undefined || scanPrompt?.trim()
        ? scanPrompt
        : undefined,
    validationPrompt,
    postScanPrompt:
      options.postScanPrompt !== undefined || postScanPrompt?.trim()
        ? postScanPrompt
        : undefined,
    // Spreading the resolved prompts back into options must clear file inputs,
    // including blank files, so later preparation does not read them again.
    scanPromptFile: undefined,
    validationPromptFile: undefined,
    postScanPromptFile: undefined,
  };
}

/** Walk the directories actually traversed, including the paths stored in operator aliases. */
async function* inputDirectoryLinks(directory: string, signal?: AbortSignal) {
  const pending = [
    isAbsolute(directory) ? directory : `${process.cwd()}${sep}${directory}`,
  ];
  const inspected = new Set<string>();
  while (pending.length) {
    const input = pending.pop()!;
    let path = parse(input).root;
    const components = input
      .slice(path.length)
      .split(process.platform === "win32" ? /[\\/]+/u : /\/+/u);
    for (const component of components) {
      if (!component || component === ".") continue;
      // Keep ".." so a link before it is inspected using filesystem semantics.
      path += (path.endsWith(sep) ? "" : sep) + component;
      if (inspected.has(path)) continue;
      signal?.throwIfAborted();
      inspected.add(path);
      if (!(await lstat(path)).isSymbolicLink()) continue;
      const owner = await realpath(dirname(path));
      yield { path, owner };
      const target = await readlink(path);
      pending.push(isAbsolute(target) ? target : `${owner}${sep}${target}`);
    }
  }
}

/** Report the first link that redirects a selected input out of its repository. */
export async function escapingInputDirectoryLink(
  directory: string,
  destination: string,
  canonicalRoots: readonly string[],
  signal?: AbortSignal,
): Promise<string | null> {
  if (directory === destination) return null;
  const outsideRoots = canonicalRoots.filter(
    (root) => !isWithin(root, destination),
  );
  if (outsideRoots.length === 0) return null;
  for await (const { path, owner } of inputDirectoryLinks(directory, signal)) {
    if (outsideRoots.some((root) => isWithin(root, owner))) return path;
  }
  return null;
}

export async function readRegularInputFile(
  path: string,
  repository: string | readonly string[],
  metadata?: Pick<BigIntStats, "isFile" | "dev" | "ino">,
): Promise<string> {
  const selected = metadata ?? (await lstat(path, { bigint: true }));
  if (!selected.isFile()) {
    throw new CodexSecurityError("Input files must be regular files.");
  }
  const canonicalParent = await realpath(dirname(path));
  const repositories =
    typeof repository === "string" ? [repository] : repository;
  const roots = await Promise.all(repositories.map((root) => realpath(root)));
  if (await escapingInputDirectoryLink(dirname(path), canonicalParent, roots)) {
    throw new CodexSecurityError(
      "Input files must not follow repository directory links outside the selected repository.",
    );
  }
  const file = await open(
    join(canonicalParent, basename(path)),
    constants.O_RDONLY |
      (constants.O_NOFOLLOW ?? 0) |
      (constants.O_NONBLOCK ?? 0),
  );
  try {
    const opened = await file.stat({ bigint: true });
    if (
      !opened.isFile() ||
      opened.dev !== selected.dev ||
      opened.ino !== selected.ino
    ) {
      throw new CodexSecurityError("Input files must remain regular files.");
    }
    return await file.readFile({ encoding: "utf8" });
  } finally {
    await file.close();
  }
}
