import { loadContract } from "../contract.js";
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

export interface DeduplicateScanOptions {
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
  const contract = await loadContract(scan.scanDir, {
    pluginRoot,
    expectedScanId: scan.scanId,
    signal: options.signal,
  });
  const client = new FindingsClient(
    options.findingsUrl,
    options.signal,
    dependencies.fetch,
  );
  const scope: FindingSearchScope =
    options.allRepositories === true
      ? { allRepositories: true }
      : { repositoryId: contract.manifest.scan.target.targetId };
  const deduplicator = new FindingDeduplicator(
    {
      potentialDuplicates: (findingId) =>
        client.potentialDuplicates(findingId, scope),
    },
    dependencies.reviewer ??
      new CodexDeduplicationReviewer(
        new CodexReviewRunner(
          environment,
          undefined,
          options.signal,
          scan["targetPath"] as string,
        ),
      ),
    options.signal,
  );
  const result = await deduplicator.run(
    contract.findings.findings.map((finding) => finding.findingId),
  );
  options.signal?.throwIfAborted();
  await client.storeDedupeGroups(result.duplicateGroups);
  return {
    scanId: scan.scanId,
    ...result,
  };
}
