import { constants, type BigIntStats } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { CodexSecurityError } from "./errors.js";
import { expandHome } from "./runtime.js";
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
  for (const repository of repositories) {
    const canonicalRepository = await realpath(repository);
    if (isOutsidePath(relative(canonicalRepository, canonicalParent))) {
      for (let ancestor = dirname(path); ; ancestor = dirname(ancestor)) {
        if (
          !isOutsidePath(
            relative(canonicalRepository, await realpath(ancestor)),
          )
        ) {
          throw new CodexSecurityError(
            "Input files must not follow repository directory links outside the selected repository.",
          );
        }
        if (dirname(ancestor) === ancestor) break;
      }
    }
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

export function isOutsidePath(path: string): boolean {
  return path === ".." || path.startsWith(`..${sep}`) || isAbsolute(path);
}
