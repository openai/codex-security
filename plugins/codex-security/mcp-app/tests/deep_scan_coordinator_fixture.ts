import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import { readJson, writeJson } from "./support/json.ts";
import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import type {
  DeepScanConfig,
  DeepScanRunState,
  DeepScanStore,
  PersistedDeepScanWorker,
  DeepScanWorkerMutation,
  CodexWorkerRequest,
  CodexWorkerResult,
  CodexWorkerDiagnostic,
  DeepScanClock,
} from "../src/deep-scan/types.js";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { once } from "node:events";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { importModule } from "./import-module.ts";

export const {
  DeepScanCoordinator,
  DeepScanCoordinatorRegistry,
  WorkbenchDeepScanStore,
  DeepScanNonRetryableError,
  DeepScanRemoteCoordinator,
  AsyncLock,
  classifyCodexWorkerError,
  startOrJoinDeepScanCoordinator,
  recordCodexSecurityWorkerScanDraft,
} = await importModule({
  stdin: {
    contents: `
      export * from "./registry.ts";
      export { WorkbenchDeepScanStore } from "./store.ts";
      export { classifyCodexWorkerError } from "./errors.ts";
      export { recordCodexSecurityWorkerScanDraft } from "../artifact-scan-draft.ts";
    `,
    resolveDir: path.join(import.meta.dirname, "../src/deep-scan/"),
  },
  loader: { ".md": "text" },
});
export const iterationInputs = (claim: StoreInput<"recordIteration">) =>
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
  iterations: StoreInput<"recordIteration">[] = [];
  failureMessages: string[] = [];
  finishCalls: StoreInput<"finish">[] = [];
  failFinish = false;
  rejectFailurePersistence = false;
  replacementManifestBeforeFinishRejection: string | undefined = undefined;
  iterationResponseGate?: PromiseWithResolvers<void>;
  blockDiscoveryUpdate?: "failed" | "succeeded";
  discoveryBlocked = Promise.withResolvers<void>();
  discoveryGate = Promise.withResolvers<void>();
  iterationCommitted = Promise.withResolvers<void>();
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
    persisted.consecutiveErrors = this.run.consecutiveErrors;
    this.workers.set(update.id, persisted);
    return structuredClone(persisted);
  }

  async recordIteration(input: StoreInput<"recordIteration">) {
    for (const id of input.workerIds) {
      const worker = this.workers.get(id)!;
      assert.equal(worker.mergeState, "buffered");
      this.workers.set(id, { ...worker, mergeState: "merged" });
    }
    this.workers.set(input.id, {
      id: input.id,
      kind: "dedup",
      status: "succeeded",
      mergeState: "none",
      attempt: 0,
      promptPath: input.resultPath,
      artifactDir: path.dirname(input.resultPath),
      resultManifestPath: input.resultPath,
    });
    this.iterations.push(structuredClone(input));
    this.run.noNewStreak = input.noNewStreak;
    this.run.consecutiveErrors = input.consecutiveErrors;
    this.iterationCommitted.resolve();
    await this.iterationResponseGate?.promise;
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
    const latest = this.iterations.at(-1);
    const draft = latest?.resultPath
      ? await readJson(latest.resultPath)
      : {
          scanId: this.run.scanId,
          findings: [],
          reviewState: {
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
      reviewState: draft.reviewState,
    });
    this.run.status = "succeeded";
    this.run.terminalReason = input.reason;
    this.run.manifestPath = input.manifestPath;
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
      ? `${message}\nOriginal Deep Scan failure:\n${original}`
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
  blockDiscoveryAfterWrite?: boolean;
  failFirstDiscoveryAttempt?: boolean;
  writePartialBeforeFailure?: boolean;
  blockDiscoveryAfterCalls?: number;
  invalidDiscoveryAttempts?: number;
  malformedDiscoveryAttempts?: number;
  discoveryCandidateId?: string;
  discoveryFailureMessage?: string;
  nonRetryableDiscoveryMessage?: string;
  failDiscoveryWorkersAfterGate?: string[];
  nonRetryableDiscoveryWorkers?: string[];
  discoveryDiagnostics?: CodexWorkerDiagnostic[];
  discoveryCandidates?: Record<string, string>;
  discoveryFailureMessages?: Record<string, string>;
  discoveryGates?: Record<string, Promise<void>>;
}

export class FakeExecutor {
  options: ExecutorOptions;
  discoveryStarted = Promise.withResolvers<void>();
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

  async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
    const threadId = request.resumeThreadId ?? randomUUID();
    await request.onThreadStarted?.(threadId);
    assert.equal(request.kind, "discovery");
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
        await writeJson(path.join(artifactContext.root, "result.json"), draft);
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

export function standardScanDraft(
  scanId: string,
  candidateId: string | undefined,
  workerLabel: string,
): ScanDraftInput {
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
    reviewState: {
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

export function createCoordinator(
  fixture: Awaited<ReturnType<typeof fixtureRun>>,
  store: FakeStore,
  executor: CoordinatorOptions["executor"],
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
