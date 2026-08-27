import { loadContractWithScanDirectory } from "../contract.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
} from "../runtime.js";
import {
  resolveCompletedScan,
  type SavedScanDependencies,
} from "../saved-scan.js";
import { CodexReviewRunner } from "./codex-review.js";
import {
  FindingDeduplicator,
  type DeduplicationResult,
} from "./deduplication.js";
import {
  CodexDeduplicationReviewer,
  type DeduplicationReviewer,
} from "./deduplication-reviewer.js";
import { FindingsClient, type FindingsRequest } from "../findings-client.js";
import type { FindingSearchScope } from "../finding-retrieval.js";
import {
  FindingWorkflow,
  workflowDestination,
  workflowDigest,
} from "../finding-workflow.js";
import { publishScanToCustomInternal } from "../custom-publish.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "./checkpointed-review.js";

export interface DeduplicateScanOptions {
  /** Resume the named local findings workflow, including custom publication. */
  workflowId?: string;
  /** Findings API base URL. The scan's findings must already be indexed there. */
  findingsUrl: string;
  /** Search all repositories instead of the saved scan's targetId. Defaults to false. */
  allRepositories?: boolean;
  signal?: AbortSignal;
}

export interface DeduplicateScanResult extends DeduplicationResult {
  scanId: string;
}

/** Review a saved scan against embedding candidates and persist accepted duplicate groups. */
export async function deduplicateScan(
  scanId: string,
  options: DeduplicateScanOptions,
): Promise<DeduplicateScanResult> {
  return await deduplicateScanInternal(scanId, options);
}

/** @internal */
export async function deduplicateScanInternal(
  scanId: string,
  options: DeduplicateScanOptions,
  dependencies: Partial<SavedScanDependencies> & {
    environment?: NodeJS.ProcessEnv;
    reviewer?: DeduplicationReviewer;
    reviewRunner?: Pick<CodexReviewRunner, "run">;
    fetch?: FindingsRequest;
  } = {},
): Promise<DeduplicateScanResult> {
  options.signal?.throwIfAborted();
  const environment = dependencies.environment ?? process.env;
  const pluginRoot = await bundledPluginRoot();
  const scan = await resolveCompletedScan(scanId, {
    currentDirectory: dependencies.currentDirectory ?? (() => process.cwd()),
    runWorkbench:
      dependencies.runWorkbench ??
      (async (args) => {
        const stateEnvironment = {
          ...environment,
          CODEX_SECURITY_STATE_DIR: codexSecurityStateDirectory(environment),
        };
        return await runWorkbench(
          {
            environment: stateEnvironment,
            pluginRoot,
            python: await resolvePluginPython({
              environment: stateEnvironment,
            }),
            signal: options.signal,
            failureMessage: "Could not read Codex Security scan history",
          },
          args,
        );
      }),
  });
  const { contract, scanDirectory } = await loadContractWithScanDirectory(
    scan.scanDir,
    {
      pluginRoot,
      expectedScanId: scan.scanId,
      signal: options.signal,
    },
  );
  const client = new FindingsClient(
    options.findingsUrl,
    options.signal,
    dependencies.fetch,
  );
  const scope: FindingSearchScope =
    options.allRepositories === true
      ? { allRepositories: true }
      : { repositoryId: contract.manifest.scan.target.targetId };
  const workflow =
    options.workflowId === undefined
      ? undefined
      : new FindingWorkflow(
          options.workflowId,
          environment,
          dependencies.runWorkbench === undefined
            ? undefined
            : (_options, args, input) =>
                dependencies.runWorkbench!(args, input),
        );
  if (workflow) {
    await workflow.protectArtifacts(scanDirectory);
    await workflow.bind({
      scanId: scan.scanId,
      scanDir: scanDirectory,
      artifactDigest: workflowDigest(contract),
      destination: workflowDestination(options.findingsUrl),
      scope,
    });
    await workflow.complete("scan", null);
    await publishScanToCustomInternal(
      scanDirectory,
      {
        findingsUrl: options.findingsUrl,
        workflowId: options.workflowId,
        expectedScanId: scan.scanId,
        signal: options.signal,
      },
      {
        environment,
        fetch: dependencies.fetch,
        runWorkbench:
          dependencies.runWorkbench === undefined
            ? undefined
            : (_options, args, input) =>
                dependencies.runWorkbench!(args, input),
      },
    );
  }
  const dedupe = async (): Promise<DeduplicateScanResult> => {
    const saved = (await workflow?.get())?.stages.dedupe;
    if (saved?.pendingWrite) {
      await client.storeDedupeGroups(saved.pendingWrite.groups);
      return saved.result as DeduplicateScanResult;
    }
    const runner =
      dependencies.reviewRunner ??
      new CodexReviewRunner(
        environment,
        undefined,
        options.signal,
        scan["targetPath"] as string,
      );
    const checkpoints = workflow
      ? new CheckpointedReviewRunner(
          workflow,
          runner,
          await workflow.sourceSnapshot(scan["targetPath"] as string),
          scope,
          await reviewSettingsDigest(environment),
        )
      : undefined;
    const deduplicator = new FindingDeduplicator(
      {
        potentialDuplicates: (findingId) =>
          client.potentialDuplicates(findingId, scope),
      },
      dependencies.reviewer ??
        new CodexDeduplicationReviewer(checkpoints ?? runner),
      options.signal,
    );
    const reviewed = await deduplicator.run(
      contract.findings.findings.map((finding) => finding.findingId),
    );
    await checkpoints?.assertSourceUnchanged();
    options.signal?.throwIfAborted();
    const result: DeduplicateScanResult = { scanId: scan.scanId, ...reviewed };
    await workflow?.prepareDedupe(result, { groups: result.duplicateGroups });
    await client.storeDedupeGroups(result.duplicateGroups);
    return result;
  };
  return workflow ? await workflow.run("dedupe", dedupe) : await dedupe();
}
