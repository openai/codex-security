import { constants, type BigIntStats } from "node:fs";
import { lstat, open, readlink, realpath } from "node:fs/promises";
import {
  basename,
  dirname,
  format,
  isAbsolute,
  join,
  parse,
  sep,
} from "node:path";
import { sameCheckedFileDevice } from "./contract.js";
import { CodexSecurityError } from "./errors.js";
import { resolveInputPath, resolveParentTraversal } from "./runtime.js";
import { isWithin } from "./trusted-executable.js";
import type { ScanPromptSettings } from "./scan-settings.js";

/** Canonical source directories, or null when a checkout cannot be verified. */
export type DocumentRoots = readonly string[] | null;
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
          resolveInputPath(file, directory),
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
export async function checkDocumentPath(
  path: string,
  canonical: string,
  source: DocumentRootSource,
  signal?: AbortSignal,
): Promise<void> {
  if (path === canonical) return;
  const roots = typeof source === "function" ? await source() : source;
  const outside = roots?.filter((root) => !isWithin(root, canonical));
  if (outside?.length === 0) return;

  const directories = new Set([dirname(path)]);
  for (const directory of directories) {
    const parsed = parse(directory);
    if (!parsed.base) continue;
    directories.add(parsed.dir);
    signal?.throwIfAborted();
    // A trailing slash would make lstat follow the link. Keep any raw "..".
    const entry = format(parsed);
    if (!(await lstat(entry)).isSymbolicLink()) continue;
    if (!outside) {
      throw new CodexSecurityError(
        "Select the document by its canonical path when the source checkout is unknown.",
      );
    }
    const owner = await realpath(await resolveParentTraversal(parsed.dir));
    if (outside.some((root) => isWithin(root, owner))) {
      throw new CodexSecurityError(
        `Input files must not follow repository directory links outside the selected repository: ${entry}`,
      );
    }
    // An external alias can point through a directory link inside a checkout.
    const target = await readlink(entry);
    directories.add(isAbsolute(target) ? target : `${owner}${sep}${target}`);
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
  const canonical = join(
    await realpath(await resolveParentTraversal(dirname(path))),
    basename(path),
  );
  const roots = typeof repository === "string" ? [repository] : repository;
  await checkDocumentPath(
    path,
    canonical,
    Array.isArray(roots)
      ? await Promise.all(
          roots.map(async (root: string) =>
            realpath(await resolveParentTraversal(root)),
          ),
        )
      : roots,
  );
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
      !(await sameCheckedFileDevice(
        file,
        { path: canonical, metadata: selected },
        opened,
      ))
    ) {
      throw new CodexSecurityError("Input files must remain regular files.");
    }
    return await file.readFile({ encoding: "utf8" });
  } finally {
    await file.close();
  }
}
