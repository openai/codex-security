import { join, relative, sep } from "node:path";
import type { ScanResult } from "./result.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { ReadOnlyCodexOptions } from "./scan-comparison.js";
import {
  enclosingGitWorktreeRoot,
  normalizeRepository,
  repositoryRevision,
} from "./targets.js";
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
  if ((await repositoryRevision(repository, options.signal)) !== revision)
    throw new Error(
      "Owner checkout does not match the completed scan revision.",
    );
  const scanRoot = await normalizeRepository(repository, options.signal);
  const gitRoot =
    (await enclosingGitWorktreeRoot(scanRoot, options.signal, {
      requireIfPresent: true,
    })) ?? scanRoot;
  const prefix = relative(gitRoot, scanRoot).split(sep).join("/");
  const report = await suggestOwnersFromScan(
    repository,
    result.findings.findings.map((finding) => ({
      ...finding,
      sourceRevision: revision,
      locations: finding.locations.map((location) => ({
        ...location,
        path: prefix ? `${prefix}/${location.path}` : location.path,
      })),
    })),
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
