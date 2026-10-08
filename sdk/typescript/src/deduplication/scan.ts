import { loadContractWithScanDirectory } from "../contract.js";
import type { CodexSecuritySurface } from "../api.js";
import { environmentEntry } from "../auth.js";
import {
  bundledPluginRoot,
  runWorkbench,
  codexSecurityStateDirectory,
  canonicalizeModelSafePath,
} from "../runtime.js";
import {
  resolveCompletedScan,
  type SavedScanDependencies,
} from "../saved-scan.js";
import { savedScanWorkbench } from "../saved-scan-bootstrap.js";
import { CodexReviewRunner, reviewSqliteHome } from "./codex-review.js";
import { mkdir } from "node:fs/promises";
import { isWithin } from "../trusted-executable.js";
import {
  FindingDeduplicator,
  deduplicationConcurrency,
  type DeduplicationResult,
} from "./deduplication.js";
import {
  CodexGroupingReviewer,
  type DeduplicationReviewer,
} from "./deduplication-reviewer.js";
import { FindingsClient, type FindingsRequest } from "../findings-client.js";
import type {
  FindingSearchScope,
  FindingSourceSnapshot,
} from "../finding-retrieval.js";
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
import { normalizeRepository } from "../targets.js";
import { LocalDeduplication, type FindingEmbeddingBinding } from "./local.js";
import { configuredCodexHome, readCodexHomeConfig } from "../auth.js";
import { CodexSecurityError } from "../errors.js";
import { comparisonEnvironment } from "../scan-comparison.js";
import { isDeepStrictEqual } from "node:util";
import { isRecord } from "../record.js";
import { resolveCodexProfile, type JsonObject } from "../config.js";
import { savedSourceContext } from "./deduplication-prompts.js";
import {
  emitDiagnostic,
  type DeduplicationDiagnosticObserver,
} from "./diagnostics.js";

export interface DeduplicateScanOptions {
  /** Resume the named findings workflow; remote mode includes custom publication. */
  workflowId?: string;
  /** Optional Findings API. Omit to prepare and deduplicate findings in local SQLite. */
  findingsUrl?: string;
  /** Custom vector space for local deduplication; cannot be combined with findingsUrl. */
  embedding?: FindingEmbeddingBinding;
  /** Search all repositories instead of the scan's targetId. Defaults to false. */
  allRepositories?: boolean;
  /** Shared concurrency limit for deduplication jobs. Defaults to 8. */
  concurrency?: number;
  /** Best-effort progress and native review diagnostics; observer failures are ignored. */
  onDiagnostic?: DeduplicationDiagnosticObserver;
  signal?: AbortSignal;
}

export interface DeduplicateScanDirectoryOptions extends DeduplicateScanOptions {
  /** Local repository checkout used to review duplicate candidates. */
  repository: string;
  /** Require the sealed artifacts to belong to this scan. */
  expectedScanId?: string;
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

/** Review a complete, sealed scan directory without resolving local scan history. */
export async function deduplicateScanDirectory(
  scanDirectory: string,
  options: DeduplicateScanDirectoryOptions,
): Promise<DeduplicateScanResult> {
  return await deduplicateScanDirectoryInternal(scanDirectory, options);
}

type DeduplicateScanDependencies = Partial<SavedScanDependencies> & {
  surface?: CodexSecuritySurface;
  environment?: NodeJS.ProcessEnv;
  reviewer?: DeduplicationReviewer;
  reviewRunner?: Pick<CodexReviewRunner, "run">;
  resolveReviewEnvironment?: typeof comparisonEnvironment;
  fetch?: FindingsRequest;
};

/** @internal */
export async function deduplicateScanDirectoryInternal(
  scanDirectory: string,
  options: DeduplicateScanDirectoryOptions,
  dependencies: DeduplicateScanDependencies = {},
): Promise<DeduplicateScanResult> {
  options.signal?.throwIfAborted();
  deduplicationConcurrency(options.concurrency);
  return await deduplicateResolvedScan(
    scanDirectory,
    await normalizeRepository(options.repository, options.signal),
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
  deduplicationConcurrency(options.concurrency);
  const environment = dependencies.environment ?? process.env;
  const pluginRoot = await bundledPluginRoot();
  const bootstrap = dependencies.runWorkbench
    ? undefined
    : await savedScanWorkbench(scanId, {
        environment,
        pluginRoot,
        currentDirectory: dependencies.currentDirectory?.() ?? process.cwd(),
        signal: options.signal,
      });
  const scan = await resolveCompletedScan(scanId, {
    currentDirectory: dependencies.currentDirectory ?? (() => process.cwd()),
    runWorkbench:
      bootstrap ??
      ((args, input) =>
        dependencies.runWorkbench!(args, input, options.signal)),
  });
  return await deduplicateResolvedScan(
    scan.scanDir,
    scan["targetPath"] as string,
    scan.scanId,
    options,
    bootstrap
      ? { ...dependencies, environment: bootstrap.environment }
      : dependencies,
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
  if (options.embedding !== undefined && options.findingsUrl !== undefined)
    throw new CodexSecurityError(
      "Custom embeddings are only supported for local deduplication.",
    );
  const { contract, scanDirectory } = await loadContractWithScanDirectory(
    selectedDirectory,
    {
      pluginRoot,
      expectedScanId,
      signal: options.signal,
    },
  );
  const scanId = contract.manifest.scan.id;
  const scope: FindingSearchScope =
    options.allRepositories === true
      ? { allRepositories: true }
      : { repositoryId: contract.manifest.scan.target.targetId };
  const injectedWorkbench = dependencies.runWorkbench;
  const workbench: typeof runWorkbench | undefined =
    injectedWorkbench &&
    (({ signal }, args, input) =>
      injectedWorkbench(args, input, signal ?? options.signal));
  const local =
    options.findingsUrl === undefined
      ? new LocalDeduplication(
          environment,
          scope,
          repositoryPath,
          options.signal,
          workbench,
          options.embedding,
        )
      : undefined;
  const client =
    local ??
    new FindingsClient(
      options.findingsUrl!,
      options.signal,
      dependencies.fetch,
    );
  const workflow =
    options.workflowId === undefined
      ? undefined
      : new FindingWorkflow(
          options.workflowId,
          environment,
          workbench,
          undefined,
          repositoryPath,
        );
  if (workflow) {
    await workflow.protectArtifacts(scanDirectory);
    await workflow.bind({
      ...(bindRepository ? { repositoryPath } : {}),
      scanId,
      scanDir: scanDirectory,
      artifactDigest: workflowDigest(contract),
      destination: local
        ? `sqlite:${codexSecurityStateDirectory(environment)}`
        : workflowDestination(options.findingsUrl!),
      scope,
    });
    await workflow.complete("scan", null);
    if (!local)
      await publishScanToCustomInternal(
        scanDirectory,
        {
          findingsUrl: options.findingsUrl!,
          workflowId: options.workflowId,
          expectedScanId: scanId,
          signal: options.signal,
        },
        {
          environment,
          fetch: dependencies.fetch,
          runWorkbench: workbench,
        },
      );
  }
  const dedupe = async (): Promise<DeduplicateScanResult> => {
    if (local) {
      await (
        workflow ?? new FindingWorkflow(scanId, environment)
      ).protectArtifacts(scanDirectory);
      emitDiagnostic(options.onDiagnostic, { event: "preparation.started" });
      await local.prepare(
        contract.findings.findings,
        contract.manifest.scan.target.targetId,
      );
      emitDiagnostic(options.onDiagnostic, { event: "preparation.completed" });
    }
    const saved = (await workflow?.get())?.stages.dedupe;
    if (saved?.pendingWrite) {
      if (
        local &&
        (saved.pendingWrite.local?.inputDigest !== local.inputDigest ||
          workflowDigest(saved.pendingWrite.local.source) !==
            workflowDigest(
              await workflow!.sourceSnapshot(
                repositoryPath,
                saved.pendingWrite.local.gitDisabled,
                (saved.pendingWrite.local.source["privateStatePaths"] ??
                  []) as string[],
              ),
            ))
      ) {
        throw new CodexSecurityError(
          "Local deduplication inputs changed. Use a new workflow ID to review them.",
        );
      }
      await client.storeDedupeGroups(saved.pendingWrite.groups);
      return saved.result as DeduplicateScanResult;
    }
    const reviewEnvironment = dependencies.reviewer
      ? environment
      : await (dependencies.resolveReviewEnvironment ?? comparisonEnvironment)(
          environment,
          undefined,
          options.signal,
        );
    const reviewConfiguration = dependencies.reviewer
      ? {}
      : await modelConfigurationForReview(
          environment,
          reviewEnvironment,
          options.signal,
        );
    const runner =
      dependencies.reviewRunner ??
      new CodexReviewRunner(
        reviewEnvironment,
        undefined,
        options.signal,
        repositoryPath,
        undefined,
        options.onDiagnostic,
        dependencies.surface ?? "sdk",
      );
    const privateStatePaths: string[] = [];
    if (workflow && !dependencies.reviewer) {
      const root = await canonicalizeModelSafePath(repositoryPath);
      const sqliteHome = await canonicalizeModelSafePath(
        reviewSqliteHome(reviewEnvironment, reviewConfiguration),
      );
      if (isWithin(root, sqliteHome)) {
        if (isWithin(sqliteHome, root))
          throw new CodexSecurityError(
            "Native SQLite storage must not be the reviewed repository root when checkpointing deduplication.",
          );
        // Create missing private parents before capturing source; native startup owns the database files.
        await mkdir(sqliteHome, { recursive: true, mode: 0o700 });
        privateStatePaths.push(sqliteHome);
      }
    }
    const source = workflow
      ? await workflow.sourceSnapshot(repositoryPath, false, privateStatePaths)
      : undefined;
    const checkpoints = workflow
      ? new CheckpointedReviewRunner(
          workflow,
          runner,
          source!,
          scope,
          await reviewSettingsDigest(reviewEnvironment, reviewConfiguration),
          options.onDiagnostic,
        )
      : undefined;
    const sourceRepositories = new Map<string, readonly string[]>(
      contract.findings.findings.map((finding) => [
        finding.findingId,
        [contract.manifest.scan.target.targetId],
      ]),
    );
    const sourceSnapshots = new Map<string, FindingSourceSnapshot>();
    const deduplicator = new FindingDeduplicator(
      {
        potentialDuplicates: async (findingId) => {
          const neighborhood = await client.potentialDuplicates(
            findingId,
            scope,
          );
          for (const finding of [
            neighborhood.finding,
            ...neighborhood.potentialDuplicates,
          ]) {
            const repositories = Object.hasOwn(
              neighborhood.repositoryIds ?? {},
              finding.findingId,
            )
              ? neighborhood.repositoryIds![finding.findingId]
              : undefined;
            if (repositories !== undefined)
              sourceRepositories.set(finding.findingId, repositories);
            else if (scope.repositoryId !== undefined)
              sourceRepositories.set(finding.findingId, [scope.repositoryId]);
            const snapshot = Object.hasOwn(
              neighborhood.sourceSnapshots ?? {},
              finding.findingId,
            )
              ? neighborhood.sourceSnapshots![finding.findingId]
              : undefined;
            if (snapshot !== undefined)
              sourceSnapshots.set(finding.findingId, snapshot);
          }
          return neighborhood;
        },
      },
      dependencies.reviewer ??
        new CodexGroupingReviewer(
          checkpoints ?? runner,
          reviewConfiguration,
          (findings) =>
            savedSourceContext(
              contract.manifest.scan.target.targetId,
              findings,
              sourceRepositories,
              sourceSnapshots,
            ),
        ),
      options.signal,
      options.concurrency,
    );
    const reviewed = await deduplicator.run(
      contract.findings.findings.map((finding) => finding.findingId),
    );
    await checkpoints?.assertSourceUnchanged();
    options.signal?.throwIfAborted();
    const result: DeduplicateScanResult = { scanId, ...reviewed };
    await workflow?.prepareDedupe(result, {
      groups: result.duplicateGroups,
      ...(local
        ? {
            local: {
              inputDigest: local.inputDigest,
              source: source!,
              gitDisabled:
                environmentEntry(environment, "CODEX_SECURITY_GIT") === "",
            },
          }
        : {}),
    });
    await client.storeDedupeGroups(result.duplicateGroups);
    return result;
  };
  return workflow ? await workflow.run("dedupe", dedupe) : await dedupe();
}

async function modelConfigurationForReview(
  source: NodeJS.ProcessEnv,
  effective: NodeJS.ProcessEnv,
  signal?: AbortSignal,
): Promise<JsonObject> {
  const selected = resolveCodexProfile(
    await readCodexHomeConfig(effective, signal),
  );
  if (configuredCodexHome(source) === configuredCodexHome(effective))
    return selected;
  const ambient = resolveCodexProfile(
    await readCodexHomeConfig(source, signal),
  );
  const providerIdentity = (config: JsonObject) => {
    const provider = config["model_provider"] ?? "openai";
    const definitions = config["model_providers"];
    const definition =
      typeof provider === "string" &&
      isRecord(definitions) &&
      isRecord(definitions[provider])
        ? definitions[provider]
        : undefined;
    return {
      provider,
      baseUrl: definition?.["base_url"],
      wireApi: definition?.["wire_api"] ?? "responses",
      openaiBaseUrl:
        provider === "openai" ? config["openai_base_url"] : undefined,
    };
  };
  // A managed sign-in home can contain only authentication/runtime settings.
  // Keep compatible caller model choices without crossing provider namespaces.
  if (
    isDeepStrictEqual(providerIdentity(ambient), providerIdentity(selected))
  ) {
    for (const key of ["model", "model_reasoning_effort"])
      if (selected[key] === undefined && ambient[key] !== undefined)
        selected[key] = ambient[key];
  }
  return selected;
}
