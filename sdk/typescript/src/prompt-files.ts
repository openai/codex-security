import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readlink, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { CodexSecurityError } from "./errors.js";
import { expandHome } from "./runtime.js";
import { isWithin } from "./trusted-executable.js";
import type { ScanPromptSettings } from "./scan-settings.js";

export const requireCanonicalDocumentPaths = Symbol(
  "requireCanonicalDocumentPaths",
);
export type DocumentRoots =
  readonly string[] | typeof requireCanonicalDocumentPaths;
export type DocumentRootSource = DocumentRoots | (() => Promise<DocumentRoots>);

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
  repository: string | DocumentRootSource,
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

/** A selected source cannot use a directory link to supply a document outside it. */
export async function escapingInputDirectoryLink(
  path: string,
  destination: string,
  source: DocumentRootSource,
  signal?: AbortSignal,
): Promise<string | undefined> {
  if (path === destination) return;
  const roots = typeof source === "function" ? await source() : source;
  if (roots === requireCanonicalDocumentPaths) {
    throw new CodexSecurityError(
      "Select the document by its canonical path when the source checkout is unknown.",
    );
  }
  const outside = roots.filter((root) => !isWithin(root, destination));
  if (!outside.length) return;

  const pending = [dirname(path)];
  const inspected = new Set<string>();
  while (pending.length) {
    for (let path = pending.pop()!; ; path = dirname(path)) {
      const parent = dirname(path);
      if (parent === path) break;
      // Strip trailing separators without collapsing ".." after a directory link.
      const entry = parent + (parent.endsWith(sep) ? "" : sep) + basename(path);
      if (inspected.has(entry)) break;
      inspected.add(entry);
      signal?.throwIfAborted();
      if (!(await lstat(entry)).isSymbolicLink()) continue;
      const owner = await realpath(parent);
      if (outside.some((root) => isWithin(root, owner))) return entry;
      // An operator alias can itself point through a link in a selected source.
      const target = await readlink(entry);
      pending.push(isAbsolute(target) ? target : `${owner}${sep}${target}`);
    }
  }
}

export async function readRegularInputFile(
  path: string,
  repository: string | DocumentRootSource,
  metadata?: Pick<BigIntStats, "isFile" | "dev" | "ino">,
): Promise<string> {
  const selected = metadata ?? (await lstat(path, { bigint: true }));
  if (!selected.isFile()) {
    throw new CodexSecurityError("Input files must be regular files.");
  }
  const canonicalParent = await realpath(dirname(path));
  const repositories =
    typeof repository === "string" ? [repository] : repository;
  const roots = Array.isArray(repositories)
    ? await Promise.all(repositories.map((root: string) => realpath(root)))
    : repositories;
  const canonical = join(canonicalParent, basename(path));
  if (await escapingInputDirectoryLink(path, canonical, roots)) {
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
