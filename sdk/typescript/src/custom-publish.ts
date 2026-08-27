import { loadContract } from "./contract.js";
import { CodexSecurityError } from "./errors.js";
import { FindingsClient, type FindingsRequest } from "./findings-client.js";
import type { Finding } from "./models.js";
import { bundledPluginRoot } from "./runtime.js";

export interface PublishScanToCustomOptions {
  /** Findings API base URL, such as http://localhost:3000. */
  findingsUrl: string;
  /** Validate and preview the upload without making an HTTP request. */
  dryRun?: boolean;
  expectedScanId?: string;
  signal?: AbortSignal;
}

export interface CustomPublicationResult {
  scanId: string;
  repositoryId: string;
  findingIds: string[];
  findingCount: number;
  dryRun?: true;
  findings?: Finding[];
}

/** Publish complete, sealed findings to a findings API without changing scan artifacts. */
export async function publishScanToCustom(
  scanDirectory: string,
  options: PublishScanToCustomOptions,
): Promise<CustomPublicationResult> {
  return await publishScanToCustomInternal(scanDirectory, options);
}

/** @internal */
export async function publishScanToCustomInternal(
  scanDirectory: string,
  options: PublishScanToCustomOptions,
  dependencies: { fetch?: FindingsRequest } = {},
): Promise<CustomPublicationResult> {
  const { manifest, findings } = await loadContract(scanDirectory, {
    pluginRoot: await bundledPluginRoot(),
    signal: options.signal,
    expectedScanId: options.expectedScanId,
  });
  if (findings.findings.length === 0) {
    throw new CodexSecurityError(
      "The completed scan has no findings to publish.",
    );
  }
  const repositoryId = manifest.scan.target.targetId;
  const findingIds = options.dryRun
    ? findings.findings.map((finding) => finding.findingId)
    : await new FindingsClient(
        options.findingsUrl,
        options.signal,
        dependencies.fetch,
      ).publish(findings.findings, repositoryId);
  return {
    scanId: manifest.scan.id,
    repositoryId,
    findingIds,
    findingCount: findingIds.length,
    ...(options.dryRun ? { dryRun: true, findings: findings.findings } : {}),
  };
}
