import { linkSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { CodexSecurityError } from "./errors.js";

/** Publish a complete report atomically, preserving an existing destination. */
export async function saveDependencyReport(
  path: string | undefined,
  report: unknown,
  signal: AbortSignal,
  onCommitted: () => void,
) {
  signal.throwIfAborted();
  if (path === undefined) {
    onCommitted();
    return;
  }
  const directory = await mkdtemp(join(dirname(path), ".report-"));
  try {
    const staged = join(directory, "report.json");
    await writeFile(staged, `${JSON.stringify(report, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    signal.throwIfAborted();
    try {
      linkSync(staged, path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST")
        throw new CodexSecurityError(
          `Report destination already exists: ${path}`,
          { cause: error },
        );
      throw error;
    }
    onCommitted();
  } finally {
    await rm(directory, { recursive: true, force: true }).catch(() => {
      // A cleanup failure cannot undo publication or replace the save error.
    });
  }
}
