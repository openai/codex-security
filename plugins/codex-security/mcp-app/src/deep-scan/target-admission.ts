import { readdir } from "node:fs/promises";
import { scopePath } from "../helpers/generate-inventory.js";
import { regular } from "../helpers/inventory-paths.js";
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
      const entries = await readdir(target);
      signal.throwIfAborted();
      if (entries.length > 0) return;
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
