import { opendir } from "node:fs/promises";
import { encodeGitPath } from "../helpers/inventory-git.js";
import { scopePath } from "../helpers/generate-inventory.js";
import { fsPath, regular } from "../helpers/inventory-paths.js";
import type { DeepScanRunState } from "./types.js";

/** Check physical selections without changing the shared inventory's ignore rules. */
export async function checkSelectedTargets(
  run: DeepScanRunState,
  signal: AbortSignal,
): Promise<void> {
  signal.throwIfAborted();
  const files = new Set(run.filePaths ?? []);
  const targets = (run.includePaths ?? [run.scope]).map((path) => ({
    path,
    target: scopePath(run.targetPath, path, undefined, true, true),
  }));
  for (const { path, target } of targets) {
    if (files.has(path) && !regular(target))
      throw new Error(`Selected file is no longer a regular file: ${path}`);
  }
  let failure: { error: unknown } | undefined;
  for (const { target } of targets) {
    signal.throwIfAborted();
    try {
      if (regular(target)) return;
      const directory = await opendir(
        process.platform === "win32" ? encodeGitPath(target) : fsPath(target),
        { bufferSize: 1 },
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
