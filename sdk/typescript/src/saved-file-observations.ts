import type { JsonObject } from "./config.js";
import { observedFilesFromLogs } from "./observed-files.js";
import { readSavedScanLogs, type ScanLogSource } from "./scan-logs.js";

/** Refresh the saved set without replacing evidence from earlier scan attempts. */
export async function refreshObservedFiles(
  scan: ScanLogSource,
  codexHomes: readonly string[],
  record: (args: readonly string[], input: string) => Promise<JsonObject>,
): Promise<ScanLogSource> {
  const targetPath = scan["targetPath"];
  const startedAt = scan["startedAt"];
  const completedAt = scan["completedAt"];
  if (
    typeof targetPath !== "string" ||
    typeof startedAt !== "string" ||
    !Number.isFinite(Date.parse(startedAt)) ||
    (completedAt !== null &&
      completedAt !== undefined &&
      (typeof completedAt !== "string" ||
        !Number.isFinite(Date.parse(completedAt))))
  ) {
    return scan;
  }
  if (
    !scan.continuationThreadId &&
    !scan.threadIds?.length &&
    !scan.executionThreadIds?.length
  ) {
    return scan;
  }
  const logs = await readSavedScanLogs(scan, codexHomes, {
    allowMissingRoot: true,
    workerWindow: { startedAt, completedAt },
  });
  // Missing logs cannot establish a measured zero, or erase earlier evidence.
  if (logs.sessions.length === 0) return scan;
  const files = observedFilesFromLogs(
    { targetPath, startedAt, completedAt },
    logs,
  );
  const observedFilesRead = await record(
    ["record-observed-files", "--scan-id", scan.scanId],
    JSON.stringify({ files }),
  );
  return { ...scan, observedFilesRead };
}
