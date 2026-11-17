import type { JsonObject } from "./config.js";
import { createObservedFileCollector } from "./observed-files.js";
import {
  readSavedScanLogs,
  savedScanLogBoundaries,
  type ScanLogSource,
} from "./scan-logs.js";

/** Refresh the saved set without replacing evidence from earlier scan attempts. */
export async function refreshObservedFiles(
  scan: ScanLogSource,
  codexHomes: readonly string[],
  record: (args: readonly string[], input: string) => Promise<JsonObject>,
): Promise<ScanLogSource> {
  const targetPath = scan["targetPath"];
  const startedAt = scan.lifecycle?.startedAt;
  // The log reader retains the final scan turn up to the next turn. Only
  // older scans without this boundary need a timestamp cutoff on each event.
  const bounds = savedScanLogBoundaries(scan);
  const completedAt = bounds.logCompletedAt ? null : bounds.completedAt;
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
  if (!scan.executionThreadIds?.length) return scan;
  const collector = createObservedFileCollector({
    targetPath,
    startedAt,
    completedAt,
  });
  const logs = await readSavedScanLogs(scan, codexHomes, {
    allowMissingRoot: true,
    executionOnly: true,
    onEvent: collector.observe,
  });
  // Missing logs cannot establish a measured zero, or erase earlier evidence.
  if (logs.sessions.length === 0) return scan;
  const observedFilesRead = await record(
    ["record-observed-files", "--scan-id", scan.scanId],
    JSON.stringify({ files: collector.files() }),
  );
  return { ...scan, observedFilesRead };
}
