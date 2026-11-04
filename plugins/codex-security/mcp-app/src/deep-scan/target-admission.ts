import { opendir } from "node:fs/promises";
import { relative } from "node:path";
import { setImmediate } from "node:timers/promises";
import { encodeGitPath } from "../helpers/inventory-git.js";
import {
  scopePath,
  ScopePathNotFoundError,
} from "../helpers/generate-inventory.js";
import { lstat } from "../helpers/inventory-paths.js";
import type { DeepScanRunState } from "./types.js";

/** Validate all registered selections, then admit the first physically nonempty member. */
export async function checkSelectedTargets(
  run: DeepScanRunState,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();
  const selections = run.includePaths ?? [run.scope];
  const storedFiles = new Set(run.filePaths ?? []);
  const checkedPath = async (path: string) => {
    await setImmediate();
    signal.throwIfAborted();
    const target = scopePath(run.targetPath, path, undefined, true, true);
    const info = lstat(target);
    if (!relative(run.targetPath, target) && !info.isDirectory())
      throw new Error(
        `Deep Scan repository is no longer a directory: ${target}`,
      );
    if (storedFiles.has(path) && !info.isFile())
      throw new Error(`Selected file is no longer a regular file: ${path}`);
    return { target, isFile: info.isFile() };
  };
  // Missing or unsafe selections fail the initial scope and file-type checks,
  // even when another selected member contains a directory entry.
  for (const path of selections) await checkedPath(path);

  let failure: { error: unknown } | undefined;
  for (const path of selections) {
    let target: string;
    try {
      const selection = await checkedPath(path);
      if (selection.isFile) return;
      target = selection.target;
    } catch (error) {
      signal.throwIfAborted();
      // A previously validated directory may become unavailable before its entry probe.
      if (
        storedFiles.has(path) ||
        !(
          error instanceof ScopePathNotFoundError ||
          (error instanceof Error && ("errno" in error || "winerror" in error))
        )
      )
        throw error;
      failure ??= { error };
      continue;
    }
    try {
      const directory = await opendir(
        encodeGitPath(target),
        // Node accepts raw entry names; OpenDirOptions omits this encoding.
        { encoding: "buffer" as BufferEncoding, bufferSize: 1 },
      );
      try {
        signal.throwIfAborted();
        const entry = await directory.read();
        signal.throwIfAborted();
        if (entry !== null) return;
      } finally {
        await directory.close();
      }
    } catch (error) {
      signal.throwIfAborted();
      failure ??= { error };
    }
  }
  signal.throwIfAborted();
  if (failure) throw failure.error;
  throw new Error(
    "Deep Scan target is empty; no security audit was performed.",
  );
}
