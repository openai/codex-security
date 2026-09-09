import { randomUUID } from "node:crypto";
import { lstat } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { loadContractWithScanDirectory } from "../contract.js";
import {
  bundledPluginRoot,
  codexSecurityStateDirectory,
  prepareCodexSecurityStateSubdirectory,
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
import {
  publishScanToCustomInternal,
  type CustomPublicationResult,
} from "../custom-publish.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "./checkpointed-review.js";
import { normalizeRepository } from "../targets.js";
import {
  CodexSecurityError,
  DeduplicationReviewError,
  safeErrorMessage,
  type DeduplicationRecovery,
} from "../errors.js";

export interface DeduplicateScanOptions {
  /** Resume the named local findings workflow, including custom publication. */
  workflowId?: string;
  /** Findings API base URL. The scan's findings must already be indexed there. */
  findingsUrl: string;
  /** Search all repositories instead of the scan's targetId. Defaults to false. */
  allRepositories?: boolean;
  signal?: AbortSignal;
}

export interface DeduplicateScanDirectoryOptions
  extends DeduplicateScanOptions {
  /** Local repository checkout used to review duplicate candidates. */
  repository: string;
  /** Require the sealed artifacts to belong to this scan. */
  expectedScanId?: string;
}

export interface DeduplicateScanResult extends DeduplicationResult {
  scanId: string;
  /** Accepted upload receipt when this call could not confirm its local checkpoint. */
  publication?: CustomPublicationResult;
}

/** Review a saved scan against embedding candidates and persist accepted duplicate groups. */
export async function deduplicateScan(
  scanId: string,
  options: DeduplicateScanOptions,
): Promise<DeduplicateScanResult> {
  return await deduplicateScanInternal(scanId, options);
}

/** Review a complete, sealed scan directory without resolving local scan history. */
export async function deduplicateScanDirectory(
  scanDirectory: string,
  options: DeduplicateScanDirectoryOptions,
): Promise<DeduplicateScanResult> {
  return await deduplicateScanDirectoryInternal(scanDirectory, options);
}

type DeduplicateScanDependencies = Partial<SavedScanDependencies> & {
  environment?: NodeJS.ProcessEnv;
  reviewer?: DeduplicationReviewer;
  reviewRunner?: Pick<CodexReviewRunner, "run">;
  fetch?: FindingsRequest;
  /** Retain current-call recovery output even when cancellation throws a primitive. */
  onPublication?: (
    publication: CustomPublicationResult,
  ) => void | Promise<void>;
  onRecovery?: (recovery: DeduplicationRecovery) => void | Promise<void>;
};

/** @internal */
export async function deduplicateScanDirectoryInternal(
  scanDirectory: string,
  options: DeduplicateScanDirectoryOptions,
  dependencies: DeduplicateScanDependencies = {},
): Promise<DeduplicateScanResult> {
  options.signal?.throwIfAborted();
  const repository = await normalizeRepository(
    options.repository,
    options.signal,
  );
  return await deduplicateResolvedScan(
    scanDirectory,
    repository,
    options.expectedScanId,
    options,
    dependencies,
    await bundledPluginRoot(),
    true,
  );
}

/** @internal */
export async function deduplicateScanInternal(
  scanId: string,
  options: DeduplicateScanOptions,
  dependencies: DeduplicateScanDependencies = {},
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
  return await deduplicateResolvedScan(
    scan.scanDir,
    scan["targetPath"] as string,
    scan.scanId,
    options,
    dependencies,
    pluginRoot,
    false,
  );
}

async function deduplicateResolvedScan(
  selectedDirectory: string,
  repositoryPath: string,
  expectedScanId: string | undefined,
  options: DeduplicateScanOptions,
  dependencies: DeduplicateScanDependencies,
  pluginRoot: string,
  bindRepository: boolean,
): Promise<DeduplicateScanResult> {
  const environment = dependencies.environment ?? process.env;
  const { contract, scanDirectory } = await loadContractWithScanDirectory(
    selectedDirectory,
    {
      pluginRoot,
      expectedScanId,
      signal: options.signal,
    },
  );
  const scanId = contract.manifest.scan.id;
  const client = new FindingsClient(
    options.findingsUrl,
    options.signal,
    dependencies.fetch,
  );
  const scope: FindingSearchScope =
    options.allRepositories === true
      ? { allRepositories: true }
      : { repositoryId: contract.manifest.scan.target.targetId };
  const makeWorkflow = (id: string) =>
    new FindingWorkflow(
      id,
      environment,
      dependencies.runWorkbench === undefined
        ? undefined
        : (workbenchOptions, args, input) =>
            dependencies.runWorkbench!(args, input, workbenchOptions.signal),
    );
  let workflow = makeWorkflow(options.workflowId ?? `dedupe_${randomUUID()}`);
  await workflow.protectArtifacts(scanDirectory);
  const source =
    options.workflowId === undefined
      ? await workflow.sourceSnapshot(repositoryPath, options.signal)
      : undefined;
  const settingsDigest =
    options.workflowId === undefined
      ? await reviewSettingsDigest(environment)
      : undefined;
  const binding = {
    ...(bindRepository || options.workflowId === undefined
      ? { repositoryPath }
      : {}),
    scanId,
    scanDir: scanDirectory,
    artifactDigest: workflowDigest(contract),
    destination: workflowDestination(options.findingsUrl),
    scope,
  };
  const requestDigest = workflowDigest({ binding, source, settingsDigest });
  if (options.workflowId === undefined) {
    const selected = await workflow.selectDedupe(requestDigest, binding);
    workflow = makeWorkflow(selected.id);
  }
  const operationKey = workflowDigest(workflow.id);
  await workflow.protectArtifacts(
    scanDirectory,
    join(
      codexSecurityStateDirectory(environment),
      "dedupe-locks",
      `${operationKey}.sqlite3`,
    ),
  );
  const release = await acquireDedupeLock(environment, operationKey);
  try {
    const state = await workflow.bind({
      ...binding,
      ...(options.workflowId === undefined
        ? { dedupeRequestDigest: requestDigest }
        : {}),
    });
    await workflow.complete("scan", null);
    const recovery: DeduplicationRecovery = {
      scanId,
      operationId: workflow.id,
      ...(options.workflowId === undefined
        ? {}
        : { workflowId: options.workflowId }),
      findingsUrl: workflowDestination(options.findingsUrl),
      allRepositories: options.allRepositories === true,
      phase: "publication",
      findingIds: [],
      findingCount: contract.findings.findings.length,
      pendingWrite: false,
    };
    let publication: CustomPublicationResult | undefined;
    try {
      if (
        options.workflowId !== undefined &&
        state.dedupeRequestDigest === undefined
      ) {
        publication = await publishScanToCustomInternal(
          scanDirectory,
          {
            findingsUrl: options.findingsUrl,
            workflowId: options.workflowId,
            expectedScanId: scanId,
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
        if (publication.warnings?.length) {
          try {
            void Promise.resolve(
              dependencies.onPublication?.(publication),
            ).catch(() => undefined);
          } catch {
            // Optional recovery output must not stop deduplication.
          }
        }
      }
      const dedupe = async (): Promise<DeduplicateScanResult> => {
        const saved = (await workflow.get())?.stages.dedupe;
        if (saved?.pendingWrite) {
          recovery.phase = "groups";
          recovery.pendingWrite = true;
          await client.storeDedupeGroups(saved.pendingWrite.groups);
          recovery.pendingWrite = false;
          return saved.result as DeduplicateScanResult;
        }
        let diagnosticsDirectory: string | undefined;
        if (dependencies.reviewRunner === undefined) {
          diagnosticsDirectory = join(
            codexSecurityStateDirectory(environment),
            "dedupe",
            operationKey,
          );
          try {
            await workflow.protectArtifacts(
              scanDirectory,
              diagnosticsDirectory,
            );
          } catch {
            // Optional diagnostics must not block the review or alter its error.
            diagnosticsDirectory = undefined;
          }
        }
        const runner =
          dependencies.reviewRunner ??
          new CodexReviewRunner(
            environment,
            undefined,
            options.signal,
            repositoryPath,
            diagnosticsDirectory,
          );
        const checkpoints = new CheckpointedReviewRunner(
          workflow,
          runner,
          source ??
            (await workflow.sourceSnapshot(repositoryPath, options.signal)),
          scope,
          settingsDigest ?? (await reviewSettingsDigest(environment)),
          options.signal,
        );
        const reviewer =
          dependencies.reviewer ?? new CodexDeduplicationReviewer(checkpoints);
        const deduplicator = new FindingDeduplicator(
          {
            potentialDuplicates: async (findingId) => {
              recovery.phase = "candidates";
              recovery.findingIds = [findingId];
              const saved = await workflow.candidateNeighborhood(findingId);
              if (saved !== null) return saved;
              const candidates = await client.potentialDuplicates(
                findingId,
                scope,
              );
              return await workflow.saveCandidateNeighborhood(
                findingId,
                candidates,
              );
            },
          },
          {
            screen: async (findings) => {
              recovery.phase = "screening";
              recovery.findingIds = findings.map(
                (finding) => finding.findingId,
              );
              return await reviewer.screen(findings);
            },
            reviewPair: async (findings) => {
              recovery.phase = "pair-review";
              recovery.findingIds = findings.map(
                (finding) => finding.findingId,
              );
              return await reviewer.reviewPair(findings);
            },
          },
          options.signal,
        );
        const reviewed = await deduplicator.run(
          contract.findings.findings.map((finding) => finding.findingId),
        );
        await checkpoints.assertSourceUnchanged(options.signal);
        options.signal?.throwIfAborted();
        const result: DeduplicateScanResult = { scanId, ...reviewed };
        recovery.phase = "groups";
        recovery.findingIds = [];
        await workflow.prepareDedupe(result, {
          groups: result.duplicateGroups,
        });
        recovery.pendingWrite = true;
        await client.storeDedupeGroups(result.duplicateGroups);
        recovery.pendingWrite = false;
        return result;
      };
      const result = await workflow.run("dedupe", dedupe);
      options.signal?.throwIfAborted();
      // Publication recovery describes this call, not the cached review result.
      return publication?.warnings?.length
        ? { ...result, publication }
        : result;
    } catch (error) {
      const failure =
        error instanceof CodexSecurityError
          ? error
          : new CodexSecurityError(safeErrorMessage(error), { cause: error });
      Object.assign(
        recovery,
        await workflow.dedupeProgress().catch(() => ({})),
      );
      if (
        error instanceof DeduplicationReviewError &&
        error.metadata.diagnosticsPath
      )
        recovery.diagnosticsPath = error.metadata.diagnosticsPath;
      failure.deduplicationRecovery = recovery;
      if (publication?.warnings?.length) failure.publication = publication;
      await workflow.fail("dedupe", failure);
      try {
        void Promise.resolve(dependencies.onRecovery?.(recovery)).catch(
          () => undefined,
        );
      } catch {
        // Recovery output must not replace the original failure.
      }
      if (options.signal?.aborted) throw error;
      throw failure;
    }
  } finally {
    await release();
  }
}

async function acquireDedupeLock(
  environment: NodeJS.ProcessEnv,
  key: string,
): Promise<() => Promise<void>> {
  const directory = await prepareCodexSecurityStateSubdirectory(
    join(codexSecurityStateDirectory(environment), "dedupe-locks"),
    environment,
  );
  const lockPath = join(directory, `${key}.sqlite3`);
  const metadata = await lstat(lockPath).catch((error: unknown) => {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  });
  if (metadata?.isSymbolicLink())
    throw new CodexSecurityError(
      "Deduplication must not follow a linked lock file.",
    );
  type Database = { exec(sql: string): void; close(): void };
  type Constructor = new (path: string) => Database;
  const require = createRequire(import.meta.url);
  const Database = process.versions["bun"]
    ? (require("bun:sqlite") as { Database: Constructor }).Database
    : (require("node:sqlite") as { DatabaseSync: Constructor }).DatabaseSync;
  const database = new Database(lockPath);
  try {
    // The process owns this transaction until it finishes or dies. A paused
    // process retains its lock; no time-based lease can start duplicate reviews.
    database.exec("BEGIN IMMEDIATE");
  } catch (error) {
    database.close();
    if ((error as Error).message.includes("locked"))
      throw new CodexSecurityError(
        "Deduplication for these inputs is already running. Wait for it to finish before retrying.",
      );
    throw error;
  }
  return async () => {
    database.close();
  };
}
