import { readJson, writeJson } from "./support/json.ts";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import type {
  DeepScanConfig,
  DeepScanRunState,
  DeepScanStore,
  PersistedDeepScanWorker,
  DeepScanWorkerMutation,
  DedupCommit,
  CodexWorkerRequest,
  CodexWorkerResult,
  CodexWorkerArtifactContext,
  CodexWorkerDiagnostic,
  DeepScanClock,
} from "../src/deep-scan/types.js";
import { sourceReferences } from "./support/source-references.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { once } from "node:events";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { importModule } from "./import-module.ts";

export const {
  DeepScanCoordinator,
  DeepScanCoordinatorRegistry,
  DeepScanNonRetryableError,
  DeepScanRemoteCoordinator,
  AsyncLock,
  classifyCodexWorkerError,
  startOrJoinDeepScanCoordinator,
} = await importModule({
  stdin: {
    contents: `
      export * from "./registry.ts";
      export { classifyCodexWorkerError } from "./errors.ts";
    `,
    resolveDir: new URL("../src/deep-scan/", import.meta.url).pathname,
  },
  loader: { ".md": "text" },
});
export const claimDedupInputs = (claim: StoreInput<"claimDedup">) =>
  claim.workerIds.map((discoveryWorkerId, inputOrder) => ({
    dedupWorkerId: claim.id,
    discoveryWorkerId,
    inputOrder,
  }));

export const recordSleeps =
  (sleeps: number[]): DeepScanClock["sleep"] =>
  async (delayMs, signal) => {
    assert.equal(signal.aborted, false);
    sleeps.push(delayMs);
  };

export const temporaryDirectories = createTemporaryDirectories(true);
export async function fixtureRun(
  config: Partial<DeepScanConfig> = {},
): Promise<{ pluginRoot: string; run: DeepScanRunState }> {
  const root = await temporaryDirectories.create(
    "codex-security-deep-coordinator-",
  );
  return {
    pluginRoot: path.join(root, "plugin"),
    run: {
      scanId: randomUUID(),
      status: "running" as const,
      targetPath: path.join(root, "target"),
      scope: ".",
      scanDir: path.join(root, "scan"),
      config: {
        workers: 1,
        subagents: 0,
        stopAfterNoNew: 1,
        maxDiscoveryRuns: 1,
        ...config,
        stopAfterConsecutiveErrors:
          config.stopAfterConsecutiveErrors ?? config.stopAfterNoNew ?? 1,
      },
      dispatchedCount: 0,
      noNewStreak: 0,
      consecutiveErrors: 0,
    },
  };
}

export type TestWorker = PersistedDeepScanWorker &
  Pick<DeepScanWorkerMutation, "replaceableFailureKind">;
export type StoreInput<Method extends keyof DeepScanStore> = Parameters<
  DeepScanStore[Method]
>[0];

export class FakeStore {
  run: DeepScanRunState;
  declare failProgressAt: number | undefined;
  constructor(run: DeepScanRunState) {
    this.run = structuredClone(run);
  }

  workerUpdates: DeepScanWorkerMutation[] = [];
  workers = new Map<string, TestWorker>();
  completionSequence = 0;
  progress: StoreInput<"updateProgress">[] = [];
  dedupClaims: StoreInput<"claimDedup">[] = [];
  dedupCommits: DedupCommit[] = [];
  dedupCommitCalls: DedupCommit[] = [];
  failDedupCommitFromCall: number | undefined = undefined;
  loseEveryDedupCommitResponseAfterCommit = false;
  failureMessages: string[] = [];
  finishCalls: StoreInput<"finish">[] = [];
  failFinish = false;
  rejectFailurePersistence = false;
  replacementManifestBeforeFinishRejection: string | undefined = undefined;
  replacementCandidatesBeforeDedupRejection: string | undefined = undefined;
  loseFirstFinishResponseAfterCommit = false;
  loseFirstDiscoveryAcceptanceResponseAfterCommit = false;
  loseFirstDedupCommitResponseAfterCommit = false;
  dedupCommitResponseGate?: PromiseWithResolvers<void>;
  blockDiscoveryUpdate?: "failed" | "succeeded";
  discoveryBlocked = Promise.withResolvers<void>();
  discoveryGate = Promise.withResolvers<void>();
  dedupCommitted = Promise.withResolvers<void>();
  failNextTerminalGet = false;
  publicationFailureMessages: string[] = [];

  async get(_scanId?: string, _threadId?: string): Promise<DeepScanRunState> {
    if (this.failNextTerminalGet && this.run.status !== "running") {
      this.failNextTerminalGet = false;
      throw new Error("database is locked");
    }
    return structuredClone({
      ...this.run,
      ...(this.workers.size > 0
        ? { persistedWorkers: [...this.workers.values()] }
        : {}),
    });
  }

  async claimCoordinator(_input?: StoreInput<"claimCoordinator">) {
    return { run: structuredClone(this.run), acquired: true };
  }

  async heartbeatCoordinator(_input?: StoreInput<"heartbeatCoordinator">) {
    this.run.updatedAt = new Date().toISOString();
    return structuredClone(this.run);
  }

  async updateWorker(update: DeepScanWorkerMutation) {
    if (update.error) {
      assert.equal(
        update.error.length <= 2_400,
        true,
        "persisted worker errors must be bounded",
      );
    }
    if (
      update.kind === "discovery" &&
      update.status === this.blockDiscoveryUpdate
    ) {
      this.discoveryBlocked.resolve();
      await this.discoveryGate.promise;
      if (update.status === "succeeded" && this.run.status !== "running") {
        throw new Error(
          "Only a running Deep Scan can update orchestration state.",
        );
      }
    }
    this.workerUpdates.push(structuredClone(update));
    const previous = this.workers.get(update.id);
    const persisted: TestWorker = {
      mergeState: "none" as const,
      ...previous,
      ...structuredClone(update),
    };
    if (
      update.kind === "discovery" &&
      update.status === "queued" &&
      !previous
    ) {
      this.run.dispatchedCount += 1;
    }
    if (
      update.kind === "discovery" &&
      update.status === "canceled" &&
      update.replaceableFailureKind &&
      previous?.status === "running"
    ) {
      this.run.consecutiveErrors += 1;
    }
    if (
      update.kind === "discovery" &&
      update.status === "succeeded" &&
      !persisted.completionSequence
    ) {
      persisted.completionSequence = ++this.completionSequence;
      persisted.mergeState = "buffered";
      this.run.consecutiveErrors = 0;
    }
    if (
      update.kind === "dedup" &&
      update.status === "failed" &&
      previous?.status === "running"
    ) {
      const claim = this.dedupClaims.find(
        (candidate) => candidate.id === update.id,
      );
      for (const workerId of claim?.workerIds ?? []) {
        const discovery = this.workers.get(workerId);
        if (
          discovery?.status === "succeeded" &&
          discovery.mergeState === "merging"
        ) {
          this.workers.set(workerId, { ...discovery, mergeState: "buffered" });
        }
      }
    }
    persisted.consecutiveErrors = this.run.consecutiveErrors;
    this.workers.set(update.id, persisted);
    if (
      this.loseFirstDiscoveryAcceptanceResponseAfterCommit &&
      update.kind === "discovery" &&
      update.status === "succeeded"
    ) {
      this.loseFirstDiscoveryAcceptanceResponseAfterCommit = false;
      throw new Error(
        "fixture lost discovery acceptance response after commit",
      );
    }
    return structuredClone(persisted);
  }

  async claimDedup(input: StoreInput<"claimDedup">) {
    this.dedupClaims.push(structuredClone(input));
    for (const workerId of input.workerIds) {
      const discovery = this.workers.get(workerId);
      assert.equal(discovery?.mergeState, "buffered");
      this.workers.set(workerId, { ...discovery, mergeState: "merging" });
    }
    await this.updateWorker({
      id: input.id,
      scanId: input.scanId,
      kind: "dedup" as const,
      status: "running" as const,
      promptPath: input.promptPath,
      artifactDir: input.artifactDir,
      attempt: 1,
    });
  }

  async commitDedup(commit: DedupCommit) {
    this.dedupCommitCalls.push(structuredClone(commit));
    if (
      this.failDedupCommitFromCall !== undefined &&
      this.dedupCommitCalls.length >= this.failDedupCommitFromCall
    ) {
      if (this.replacementCandidatesBeforeDedupRejection) {
        await writeFile(
          this.dedupCommits.at(-1)!.resultManifestPath,
          this.replacementCandidatesBeforeDedupRejection,
        );
      }
      throw new DeepScanNonRetryableError(
        "fixture rejected the reducer commit",
      );
    }
    if (this.dedupCommits.some((previous) => previous.id === commit.id)) {
      if (this.loseEveryDedupCommitResponseAfterCommit) {
        throw new Error("fixture lost the committed reducer response");
      }
      return structuredClone(this.run);
    }
    this.dedupCommits.push(structuredClone(commit));
    const claim = this.dedupClaims.find((claim) => claim.id === commit.id);
    assert.ok(claim);
    if (commit.newFindings > 0) this.run.noNewStreak = 0;
    else this.run.noNewStreak += claim.workerIds.length;
    for (const workerId of claim.workerIds) {
      const discovery = this.workers.get(workerId);
      assert.equal(discovery?.mergeState, "merging");
      this.workers.set(workerId, { ...discovery, mergeState: "merged" });
    }
    await this.updateWorker({
      ...this.workers.get(commit.id)!,
      id: commit.id,
      scanId: commit.scanId,
      kind: "dedup" as const,
      status: "succeeded",
      attempt: this.workers.get(commit.id)?.attempt ?? 1,
      resultManifestPath: commit.resultManifestPath,
    });
    this.dedupCommitted.resolve();
    if (this.loseEveryDedupCommitResponseAfterCommit) {
      throw new Error("fixture lost the committed reducer response");
    }
    if (this.dedupCommitResponseGate)
      await this.dedupCommitResponseGate.promise;
    if (this.loseFirstDedupCommitResponseAfterCommit) {
      this.loseFirstDedupCommitResponseAfterCommit = false;
      throw new Error("fixture lost dedup commit response after commit");
    }
    return structuredClone(this.run);
  }

  async finish(input: StoreInput<"finish">) {
    this.finishCalls.push(structuredClone(input));
    if (this.run.status === "succeeded") return structuredClone(this.run);
    if (this.failFinish) {
      if (this.replacementManifestBeforeFinishRejection) {
        await writeFile(
          input.manifestPath,
          this.replacementManifestBeforeFinishRejection,
        );
      }
      throw new DeepScanNonRetryableError("fixture finish persistence failure");
    }
    if (input.stagedManifestPath)
      await rename(input.stagedManifestPath, input.manifestPath);
    const latestReducer = this.dedupCommits.at(-1);
    const draft = latestReducer?.resultManifestPath
      ? await readJson(latestReducer.resultManifestPath!)
      : {
          scanId: this.run.scanId,
          findings: [],
          coverage: {
            completeness: "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: [],
          },
        };
    await writeJson(input.manifestPath, {
      scan: {
        scanId: draft.scanId,
        mode: "deep",
        ...(draft.threatModel ? { threatModel: draft.threatModel } : {}),
      },
      findings: draft.findings,
      coverage: draft.coverage,
    });
    this.run.status = "succeeded";
    this.run.terminalReason = input.reason;
    this.run.manifestPath = input.manifestPath;
    if (
      this.loseFirstFinishResponseAfterCommit &&
      this.finishCalls.length === 1
    ) {
      throw new Error("fixture lost finish response after commit");
    }
    return structuredClone(this.run);
  }

  async fail(
    _scanId: string,
    message: string,
    status: "failed" | "interrupted" = "failed",
    manifestPath?: string,
    stagedManifestPath?: string,
  ) {
    this.failureMessages.push(message);
    if (this.rejectFailurePersistence) {
      throw new DeepScanNonRetryableError(
        "fixture rejected stale failure persistence",
      );
    }
    if (stagedManifestPath && manifestPath)
      await rename(stagedManifestPath, manifestPath);
    this.run.status = status;
    this.run.error = message;
    this.run.manifestPath = manifestPath;
    return structuredClone(this.run);
  }

  async recordStoppedPublicationFailure(_scanId: string, message: string) {
    this.publicationFailureMessages.push(message);
    const original = this.run.error?.trim();
    this.run.error = original
      ? boundedFixtureErrorPair(message, original)
      : message;
    return structuredClone(this.run);
  }

  async updateProgress(input: StoreInput<"updateProgress">) {
    if (this.failProgressAt && --this.failProgressAt === 0) {
      throw new Error("fixture progress persistence failure");
    }
    this.progress.push(structuredClone(input));
  }
}

interface ExecutorOptions {
  blockDedupAfterWrite?: boolean;
  blockDiscoveryAfterWrite?: boolean;
  corruptAcceptedSource?: boolean;
  dropLastDedupFinding?: boolean;
  failFirstDiscoveryAttempt?: boolean;
  invalidFirstDedupResult?: boolean;
  omitFirstDedupCandidateLedger?: boolean;
  writePartialBeforeFailure?: boolean;
  blockDiscoveryAfterCalls?: number;
  invalidDedupFromCall?: number;
  invalidDiscoveryAttempts?: number;
  malformedDiscoveryAttempts?: number;
  canonicalCandidateId?: string;
  discoveryCandidateId?: string;
  discoveryFailureMessage?: string;
  nonRetryableDiscoveryMessage?: string;
  dedupEvidenceByCall?: string[];
  failDiscoveryWorkersAfterGate?: string[];
  nonRetryableDiscoveryWorkers?: string[];
  dedupDiagnostics?: CodexWorkerDiagnostic[];
  discoveryDiagnostics?: CodexWorkerDiagnostic[];
  discoveryCandidates?: Record<string, string>;
  discoveryFailureMessages?: Record<string, string>;
  discoveryGates?: Record<string, Promise<void>>;
  missingDedupResultsByLabel?: Record<string, number>;
}

export class FakeExecutor {
  options: ExecutorOptions;
  discoveryStarted = Promise.withResolvers<void>();
  dedupStarted = Promise.withResolvers<void>();
  dedupGate?: PromiseWithResolvers<void>;
  dedupArtifactsWritten = Promise.withResolvers<void>();
  discoveryArtifactsWritten = Promise.withResolvers<void>();
  constructor(options: ExecutorOptions = {}) {
    this.options = options;
  }

  discoveryCalls = 0;
  discoveryAttempts = new Map<string, number>();
  discoveryPromptPaths = new Map<string, Set<string>>();
  discoveryWorkingDirectories = new Set<string>();
  discoveryResumeThreadIds: (string | undefined)[] = [];
  discoveryContinuationPrompts: (string | undefined)[] = [];
  discoveryThreadIds: string[] = [];
  runningDiscovery = 0;
  maximumDiscoveryConcurrency = 0;
  runningDedup = 0;
  maximumDedupConcurrency = 0;
  dedupCalls = 0;
  dedupAttemptsByLabel = new Map<string, number>();
  dedupResumeThreadIds: (string | undefined)[] = [];
  dedupThreadIds: string[] = [];
  dedupContinuationPrompts: (string | undefined)[] = [];
  dedupPromptPaths: string[] = [];
  dedupArtifactContexts: CodexWorkerArtifactContext[] = [];
  dedupSignal: AbortSignal | undefined = undefined;

  async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
    const threadId = request.resumeThreadId ?? randomUUID();
    await request.onThreadStarted?.(threadId);
    if (request.kind === "discovery") {
      const workerId = await workerIdFromPrompt(request.promptPath);
      this.discoveryWorkingDirectories.add(request.workingDirectory);
      this.discoveryResumeThreadIds.push(request.resumeThreadId);
      this.discoveryContinuationPrompts.push(request.continuationPrompt);
      this.discoveryThreadIds.push(threadId);
      this.discoveryCalls += 1;
      this.discoveryAttempts.set(
        workerId,
        (this.discoveryAttempts.get(workerId) ?? 0) + 1,
      );
      const promptPaths = this.discoveryPromptPaths.get(workerId) ?? new Set();
      promptPaths.add(request.promptPath);
      this.discoveryPromptPaths.set(workerId, promptPaths);
      this.runningDiscovery += 1;
      this.maximumDiscoveryConcurrency = Math.max(
        this.maximumDiscoveryConcurrency,
        this.runningDiscovery,
      );
      this.discoveryStarted.resolve();
      try {
        const message =
          this.options.discoveryFailureMessages?.[workerId] ??
          this.options.discoveryFailureMessage;
        if (message) throw new Error(message);
        if (this.options.failFirstDiscoveryAttempt) {
          this.options.failFirstDiscoveryAttempt = false;
          if (this.options.writePartialBeforeFailure) {
            await writeFile(
              path.join(request.workingDirectory, "partial-progress.txt"),
              "preserve me\n",
            );
          }
          throw new Error("transient worker failure");
        }
        if (this.options.nonRetryableDiscoveryMessage) {
          throw new DeepScanNonRetryableError(
            this.options.nonRetryableDiscoveryMessage,
          );
        }
        if (this.options.nonRetryableDiscoveryWorkers?.includes(workerId)) {
          throw new DeepScanNonRetryableError("fixture configuration failure");
        }
        await this.options.discoveryGates?.[workerId];
        if (this.options.failDiscoveryWorkersAfterGate?.includes(workerId)) {
          throw new DeepScanNonRetryableError("fixture late discovery failure");
        }
        if (
          this.options.blockDiscoveryAfterCalls !== undefined &&
          this.discoveryCalls > this.options.blockDiscoveryAfterCalls
        ) {
          await waitForAbort(request.signal);
        }
        const omitArtifact = (this.options.invalidDiscoveryAttempts ?? 0) > 0;
        const malformedResult =
          (this.options.malformedDiscoveryAttempts ?? 0) > 0;
        if (omitArtifact) this.options.invalidDiscoveryAttempts! -= 1;
        if (malformedResult) this.options.malformedDiscoveryAttempts! -= 1;
        const candidateId =
          this.options.discoveryCandidates?.[workerId] ??
          this.options.discoveryCandidateId;
        const { promptPath, workingDirectory, artifactContext } = request;
        const context = await promptContext(promptPath);
        assert.equal(artifactContext?.layout, "worker");
        assert.equal(artifactContext.root, workingDirectory);
        if (!omitArtifact) {
          const draft = standardScanDraft(
            context.scanId,
            candidateId,
            context.workerLabel,
          );
          await writeJson(
            path.join(artifactContext.root, "result.json"),
            draft,
          );
        }
        if (malformedResult) {
          await writeFile(
            path.join(request.artifactContext!.root, "result.json"),
            "{malformed",
          );
        }
        this.discoveryArtifactsWritten.resolve();
        if (this.options.blockDiscoveryAfterWrite)
          await waitForAbort(request.signal);
        return {
          threadId,
          diagnostics: this.options.discoveryDiagnostics,
        };
      } finally {
        this.runningDiscovery -= 1;
      }
    }

    this.runningDedup += 1;
    this.dedupSignal = request.signal;
    this.dedupResumeThreadIds.push(request.resumeThreadId);
    this.dedupThreadIds.push(threadId);
    this.dedupContinuationPrompts.push(request.continuationPrompt);
    this.dedupPromptPaths.push(request.promptPath);
    this.dedupArtifactContexts.push(request.artifactContext!);
    this.maximumDedupConcurrency = Math.max(
      this.maximumDedupConcurrency,
      this.runningDedup,
    );
    this.dedupStarted.resolve();
    try {
      if (this.dedupGate) await this.dedupGate.promise;
      if (request.signal.aborted)
        throw new DOMException("aborted", "AbortError");
      this.dedupCalls += 1;
      const reducerLabel = (await promptContext(request.promptPath))
        .reducerLabel;
      const reducerAttempt =
        (this.dedupAttemptsByLabel.get(reducerLabel) ?? 0) + 1;
      this.dedupAttemptsByLabel.set(reducerLabel, reducerAttempt);
      if (
        reducerAttempt <=
        (this.options.missingDedupResultsByLabel?.[reducerLabel] ?? 0)
      ) {
        return {
          threadId,
          diagnostics: this.options.dedupDiagnostics,
        };
      }
      const invalidResult =
        (this.options.invalidDedupFromCall !== undefined &&
          this.dedupCalls >= this.options.invalidDedupFromCall) ||
        this.options.invalidFirstDedupResult;
      this.options.invalidFirstDedupResult &&= false;
      await writeDedupArtifacts(request, invalidResult, {
        canonicalCandidateId: this.options.canonicalCandidateId,
        evidence: this.options.dedupEvidenceByCall?.[this.dedupCalls - 1],
        dropLastFinding: this.options.dropLastDedupFinding,
        corruptAcceptedSource: this.options.corruptAcceptedSource,
      });
      if (this.options.omitFirstDedupCandidateLedger && this.dedupCalls === 1) {
        await rm(path.join(request.artifactContext!.root, "result.json"));
      }
      this.dedupArtifactsWritten.resolve();
      if (this.options.blockDedupAfterWrite) await waitForAbort(request.signal);
      return {
        threadId,
        diagnostics: this.options.dedupDiagnostics,
      };
    } finally {
      this.runningDedup -= 1;
    }
  }
}

export async function workerIdFromPrompt(promptPath: string) {
  return (await promptContext(promptPath)).workerLabel ?? promptPath;
}

export async function promptContext(promptPath: string) {
  const prompt = await readFile(promptPath, "utf8");
  const encoded = prompt.match(/```json\n([\s\S]*?)\n```/)?.[1];
  if (!encoded) throw new Error(`Missing JSON context in ${promptPath}`);
  return JSON.parse(encoded);
}

async function writeDedupArtifacts(
  request: CodexWorkerRequest,
  invalidResult: boolean | undefined,
  options: {
    canonicalCandidateId?: string;
    evidence?: string;
    dropLastFinding?: boolean;
    corruptAcceptedSource?: boolean;
  } = {},
) {
  const context = await promptContext(request.promptPath);
  const artifactContext = request.artifactContext!;
  assert.equal(artifactContext?.layout, "reducer");
  const reducer = artifactContext.deepReducer;
  assert.ok(reducer);
  const workerIds = reducer.claimedWorkers.map((worker) => worker.id);
  assert.deepEqual(context.claimedWorkerIds, workerIds);
  const workerDrafts = await Promise.all(
    reducer.claimedWorkers.map(async (worker) => {
      const result = await readJson(worker.resultPath);
      result.findings = result.findings.map(sourceReferences(worker));
      return result;
    }),
  );
  const previousDraft = reducer.previousReducerResultPath
    ? await readJson(reducer.previousReducerResultPath)
    : undefined;
  const mergedFindings = new Map<string, CoordinatorFinding>();
  for (const finding of [
    ...(previousDraft?.findings ?? []),
    ...workerDrafts.flatMap((draft) => draft.findings),
  ]) {
    const findingIdentity =
      finding.identity?.anchor ??
      finding.provenance?.candidateId ??
      finding.ruleId;
    mergedFindings.set(findingIdentity, {
      ...mergedFindings.get(findingIdentity),
      ...finding,
      ...(options.evidence === undefined
        ? {}
        : { rootCause: { summary: options.evidence } }),
      provenance: {
        ...finding.provenance,
        sourceFindingIds: [
          ...new Set([
            ...(mergedFindings.get(findingIdentity)?.provenance
              .sourceFindingIds ?? []),
            ...(finding.provenance.sourceFindingIds ?? []),
          ]),
        ],
      },
    });
  }
  const draft = standardScanDraft(
    previousDraft?.scanId ?? workerDrafts[0]?.scanId,
    undefined,
    context.reducerLabel,
  );
  draft.findings = [...mergedFindings.values()];
  if (options.canonicalCandidateId && draft.findings.length > 0) {
    draft.findings[0].provenance.candidateId = options.canonicalCandidateId;
  }
  delete (draft as { coverage?: unknown }).coverage;
  if (invalidResult) (draft as { findings: unknown }).findings = "invalid";
  if (options.dropLastFinding) draft.findings.pop();
  const resultPath = path.join(artifactContext.root, "result.json");
  await writeJson(resultPath, draft);
  if (options.corruptAcceptedSource) {
    const source = reducer.claimedWorkers.at(-1);
    await writeFile(source!.resultPath, "{invalid standard scan\n");
  }
}

export function standardScanDraft(
  scanId: string,
  candidateId: string | undefined,
  workerLabel: string,
) {
  return {
    scanId,
    threatModel: { summary: `Independent threat model for ${workerLabel}.` },
    findings: candidateId
      ? [
          {
            ruleId: "sql-injection.fixture",
            title: "Unsafe fixture query",
            summary:
              "A request-controlled value reaches a security-sensitive sink.",
            severity: { level: "high" },
            confidence: {
              level: "high",
              rationale: "Source evidence establishes reachability.",
            },
            taxonomy: { category: "sql-injection", cwe: ["CWE-89"] },
            locations: [{ path: "fixture.py", startLine: 1, endLine: 1 }],
            remediation: "Use a parameterized query.",
            provenance: {
              source: "local_plugin",
              candidateId,
              workerId: workerLabel,
            },
          },
        ]
      : [],
    coverage: {
      completeness: "complete",
      surfaces: [
        {
          label: "Fixture query",
          disposition: candidateId ? "reported" : "no_issue_found",
        },
      ],
      explicitExclusions: [],
      deferred: [],
    },
  };
}

async function waitForAbort(signal: AbortSignal) {
  if (!signal.aborted) await once(signal, "abort");
  throw new DOMException("aborted", "AbortError");
}

export async function eventually(predicate: () => boolean) {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("condition did not become true");
}

export async function assertNoPublishedCandidates(scanDir: string) {
  await assert.rejects(
    readFile(path.join(scanDir, "scan-manifest.json"), "utf8"),
    (error: NodeJS.ErrnoException) => error.code === "ENOENT",
  );
}

export const immediateClock: DeepScanClock = {
  now: () => 1_700_000_000_000,
  sleep: async (_delayMs, signal) => {
    if (signal.aborted) throw new DOMException("aborted", "AbortError");
  },
};

function boundedFixtureErrorPair(primary: string, secondary: string) {
  const separator = "\nOriginal Deep Scan failure:\n";
  const available = 2_400 - separator.length;
  let primaryBudget = Math.min(primary.length, Math.floor(available / 2));
  const secondaryBudget = Math.min(secondary.length, available - primaryBudget);
  primaryBudget = Math.min(primary.length, available - secondaryBudget);
  return (
    boundedFixtureErrorText(primary, primaryBudget) +
    separator +
    boundedFixtureErrorText(secondary, secondaryBudget)
  );
}

function boundedFixtureErrorText(message: string, maximum: number) {
  if (message.length <= maximum) return message;
  const digest = createHash("sha256").update(message).digest("hex");
  const suffix = `\n...[truncated; sha256:${digest}]`;
  return message.slice(0, maximum - suffix.length) + suffix;
}

export function createCoordinator(
  fixture: Awaited<ReturnType<typeof fixtureRun>>,
  store: FakeStore,
  executor: { run(request: CodexWorkerRequest): Promise<CodexWorkerResult> },
  options: Partial<CoordinatorOptions> = {},
) {
  return new DeepScanCoordinator({
    run: fixture.run,
    store,
    executor,
    pluginRoot: fixture.pluginRoot,
    clock: immediateClock,
    ...options,
  });
}

type CoordinatorFinding = ReturnType<
  typeof standardScanDraft
>["findings"][number] & {
  identity?: { anchor: string };
  provenance: { sourceFindingIds?: string[] };
};

export function runCoordinator(...args: Parameters<typeof createCoordinator>) {
  const coordinator = createCoordinator(...args);
  coordinator.start();
  return coordinator.wait(undefined, 5_000);
}

export function recordingClock(sleeps: number[]): DeepScanClock {
  return {
    now: immediateClock.now,
    sleep: async (delayMs) => void sleeps.push(delayMs),
  };
}

export async function coordinatorFixture(config: Partial<DeepScanConfig> = {}) {
  const fixture = await fixtureRun(config);
  return { fixture, store: new FakeStore(fixture.run) };
}
