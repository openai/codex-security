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
import {
  PublicationTelemetryRecorder,
  type PublicationTelemetry,
  type PublicationTelemetryObserver,
} from "./publication-telemetry.js";

export interface PublishScanToCustomOptions {
  /** Resume publication within the named local findings workflow. */
  workflowId?: string;
  /** Findings API base URL, such as http://localhost:3000. */
  findingsUrl: string;
  /** Validate and preview the upload without making an HTTP request. */
  dryRun?: boolean;
  expectedScanId?: string;
  signal?: AbortSignal;
  /** Best-effort content-free outcome accounting, including preparation failures. */
  onTelemetry?: PublicationTelemetryObserver;
}

export interface CustomPublicationResult {
  scanId: string;
  repositoryId: string;
  findingIds: string[];
  findingCount: number;
  dryRun?: true;
  findings?: Finding[];
  telemetry?: PublicationTelemetry;
}

interface CustomPublicationDependencies {
  fetch?: FindingsRequest;
  environment?: NodeJS.ProcessEnv;
  runWorkbench?: typeof runWorkbench;
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
  dependencies: CustomPublicationDependencies = {},
): Promise<CustomPublicationResult> {
  const telemetry = new PublicationTelemetryRecorder(
    "custom",
    options.onTelemetry,
  );
  try {
    const result = await publishScanToCustomAttempt(
      scanDirectory,
      options,
      dependencies,
      telemetry,
    );
    telemetry.notify(result.telemetry!);
    return result;
  } catch (error) {
    telemetry.notify(
      telemetry.snapshot(
        telemetry.outcome === "indeterminate"
          ? "indeterminate"
          : options.signal?.aborted
            ? "canceled"
            : "failed",
      ),
    );
    throw error;
  }
}

async function publishScanToCustomAttempt(
  scanDirectory: string,
  options: PublishScanToCustomOptions,
  dependencies: CustomPublicationDependencies,
  telemetry: PublicationTelemetryRecorder,
): Promise<CustomPublicationResult> {
  const { contract, scanDirectory: canonicalDirectory } =
    await loadContractWithScanDirectory(scanDirectory, {
      pluginRoot: await bundledPluginRoot(),
      signal: options.signal,
      expectedScanId: options.expectedScanId,
    });
  const { manifest, findings } = contract;
  telemetry.counts.selected = findings.findings.length;
  if (findings.findings.length === 0 && options.workflowId === undefined) {
    throw new CodexSecurityError(
      "The completed scan has no findings to publish.",
    );
  }
  const repositoryId = manifest.scan.target.targetId;
  let invoked = false;
  const publish = async (): Promise<CustomPublicationResult> => {
    invoked = true;
    const client = options.dryRun
      ? null
      : new FindingsClient(
          options.findingsUrl,
          options.signal,
          dependencies.fetch,
        );
    if (client !== null) {
      telemetry.attempted = true;
      telemetry.counts.submitted = findings.findings.length;
      // The bulk API acknowledges IDs; it does not distinguish inserts from upserts.
      telemetry.counts.created = null;
      telemetry.counts.reused = null;
      telemetry.counts.acknowledged = null;
      telemetry.counts.failed = null;
      telemetry.outcome = "indeterminate";
    }
    const findingIds =
      client === null
        ? findings.findings.map((finding) => finding.findingId)
        : await client.publish(findings.findings, repositoryId);
    telemetry.outcome = options.dryRun ? "preview" : "completed";
    telemetry.counts.acknowledged = options.dryRun ? 0 : findingIds.length;
    telemetry.counts.failed = 0;
    return {
      scanId: manifest.scan.id,
      repositoryId,
      findingIds,
      findingCount: findingIds.length,
      ...(options.dryRun ? { dryRun: true, findings: findings.findings } : {}),
      telemetry: telemetry.snapshot(),
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
  const result = await workflow.run("publish", publish);
  if (invoked) return result;
  telemetry.counts.reused = result.findingCount;
  return { ...result, telemetry: telemetry.snapshot("completed") };
}
