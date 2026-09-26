import { loadContractWithScanDirectory } from "./contract.js";
import { CodexSecurityError } from "./errors.js";
import { FindingsClient, type FindingsRequest } from "./findings-client.js";
import type { Finding } from "./models.js";
import { bundledPluginRoot, type runWorkbench } from "./runtime.js";
import {
  FindingWorkflow,
  workflowDestination,
  workflowDigest,
} from "./finding-workflow.js";

export interface PublishScanToCustomOptions {
  /** Resume publication within the named local findings workflow. */
  workflowId?: string;
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
  dependencies: {
    fetch?: FindingsRequest;
    environment?: NodeJS.ProcessEnv;
    runWorkbench?: typeof runWorkbench;
  } = {},
): Promise<CustomPublicationResult> {
  const { contract, scanDirectory: canonicalDirectory } =
    await loadContractWithScanDirectory(scanDirectory, {
      pluginRoot: await bundledPluginRoot(),
      signal: options.signal,
      expectedScanId: options.expectedScanId,
    });
  const { manifest, findings } = contract;
  if (findings.findings.length === 0 && options.workflowId === undefined) {
    throw new CodexSecurityError(
      "The completed scan has no findings to publish.",
    );
  }
  const repositoryId = manifest.scan.target.targetId;
  const publish = async (): Promise<CustomPublicationResult> => {
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
  };
  if (options.workflowId === undefined || options.dryRun)
    return await publish();
  const workflow = new FindingWorkflow(
    options.workflowId,
    dependencies.environment,
    dependencies.runWorkbench,
  );
  await workflow.protectArtifacts(canonicalDirectory);
  await workflow.bind({
    scanId: manifest.scan.id,
    scanDir: canonicalDirectory,
    artifactDigest: workflowDigest(contract),
    destination: workflowDestination(options.findingsUrl),
  });
  await workflow.complete("scan", null);
  return await workflow.run("publish", publish);
}
