import { join } from "node:path";
import type { ScanResult } from "./result.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { ReadOnlyCodexOptions } from "./scan-comparison.js";
import { findingsAtScanRevision } from "./owner-evidence.js";
import {
  suggestOwnersFromScan,
  type SuggestOwnersOptions,
} from "./suggest-owners.js";

export const OWNER_SUGGESTIONS_ARTIFACT = "owner-suggestions.json";

/** Write enrichment beside the sealed scan, without changing its manifest or findings. */
export async function writeScanOwnerSuggestions(
  repository: string,
  result: ScanResult,
  writer: ScanArtifactRestorer,
  options: SuggestOwnersOptions & Pick<ReadOnlyCodexOptions, "auth">,
  _surface: "sdk" | "cli" = "sdk",
): Promise<string> {
  const target = result.manifest.scan.target;
  const revision = target.revision ?? target.headRevision;
  if (
    result.manifest.scan.status !== "completed" ||
    !revision ||
    !["git_revision", "git_diff"].includes(target.kind)
  )
    throw new Error(
      "Owner suggestions require a completed scan of committed Git content.",
    );
  const report = await suggestOwnersFromScan(
    repository,
    await findingsAtScanRevision(
      repository,
      revision,
      result.findings.findings,
      options.signal,
    ),
    options,
  );
  if (report.revision !== revision)
    throw new Error("Owner report revision does not match the completed scan.");
  await writer.restore(
    OWNER_SUGGESTIONS_ARTIFACT,
    Buffer.from(`${JSON.stringify(report)}\n`),
  );
  return join(result.scanDir, OWNER_SUGGESTIONS_ARTIFACT);
}
