import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readlink, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
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

/** An unavailable source row must not prevent other rows from loading shared inputs. */
export function nullIfUnavailableInputRoot(error: NodeJS.ErrnoException): null {
  if (
    ["ENOENT", "ENOTDIR", "ENAMETOOLONG", "ELOOP", "EACCES", "EPERM"].includes(
      error.code ?? "",
    )
  )
    return null;
  throw error;
}

export interface DocumentSourceSelection {
  directories: readonly string[];
  lookupSavedRoots?: (
    linkOwners: readonly string[],
  ) => Promise<readonly string[]>;
}

/** Walk the selected path and the raw targets of any directory links it traverses. */
export async function escapingInputDirectoryLink(
  selected: string,
  destination: string,
  selection: DocumentSourceSelection,
  signal?: AbortSignal,
): Promise<string | null> {
  if (selected === destination) return null;
  const outside = (roots: readonly string[]) =>
    roots.filter((root) => !isWithin(root, destination));
  const known = outside(selection.directories);
  if (!known.length && !selection.lookupSavedRoots) return null;
  const linkOwners = new Map<string, string>();

  const directory = dirname(selected);
  const pending = [
    isAbsolute(directory) ? directory : `${process.cwd()}${sep}${directory}`,
  ];
  const inspected = new Set<string>();
  while (pending.length) {
    for (let path = pending.pop()!; ; path = dirname(path)) {
      const parent = dirname(path);
      if (parent === path) break;
      // Drop trailing separators without normalizing a link target's ".." components.
      const entry = parent + (parent.endsWith(sep) ? "" : sep) + basename(path);
      if (inspected.has(entry)) break;
      signal?.throwIfAborted();
      inspected.add(entry);
      if (!(await lstat(entry)).isSymbolicLink()) continue;
      const owner = await realpath(parent);
      if (known.some((root) => isWithin(root, owner))) return entry;
      if (selection.lookupSavedRoots) linkOwners.set(owner, entry);
      const target = await readlink(entry);
      pending.push(isAbsolute(target) ? target : `${owner}${sep}${target}`);
    }
  }
  if (linkOwners.size && selection.lookupSavedRoots) {
    const recorded = outside(
      await selection.lookupSavedRoots([...linkOwners.keys()]),
    );
    for (const [owner, entry] of linkOwners) {
      if (recorded.some((root) => isWithin(root, owner))) return entry;
    }
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
  const canonical = join(canonicalParent, basename(path));
  if (
    await escapingInputDirectoryLink(path, canonical, { directories: roots })
  ) {
    throw new CodexSecurityError(
      "Input files must not follow repository directory links outside the selected repository.",
    );
  }
  const file = await open(
    canonical,
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
