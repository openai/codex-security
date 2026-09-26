import { lstat } from "node:fs/promises";
import { join, relative } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { CodexSecurity, ScanOptions } from "./api.js";
import type { JsonObject } from "./config.js";
import { loadContract, readScanFile } from "./contract.js";
import type { ScanCost } from "./cost.js";
import {
  ScanCostLimitExceededError,
  ScanInterruptedError,
  safeErrorMessage,
} from "./errors.js";
import type { DeepScanOptions } from "./scan-settings.js";
import {
  combineScanCoverage,
  createScanMergeValidator,
  projectScanMergeWriteups,
  scanMergeInput,
  scanMergePrompt,
  type ScanMergeInput,
} from "./scan-merge.js";
import type { ScanArtifactRestorer } from "./runtime.js";
import type { SemanticScan } from "./scan-semantics.js";
import {
  ScanPermissionError,
  ScanTransportClosedError,
} from "./scan-execution.js";

export const DEEP_SCAN_CHECKPOINT = "artifacts/deep-scan/checkpoint.json";

/** Required usage tracking must stop the entire composition before another pass. */
export class ScanCostTrackingError extends ScanInterruptedError {}

export interface DeepScanCheckpoint {
  version: 2;
  startedAt: string;
  passes: Array<{
    directory: string;
    scanId?: string;
    failed?: true;
    // Saved with the failure streak so recovery accounts for each success once.
    completed?: true;
  }>;
  mergedScanIds: string[];
  aggregate: SemanticScan | null;
  noNewStreak: number;
  consecutiveErrors: number;
  mergeFailures?: number;
  legacy?: {
    discoveryRuns: number;
    coverage: JsonObject;
    cost?: ScanCost;
    originThreadId?: string;
  };
  terminalReason?: "saturated" | "capped" | "failed" | "canceled";
}

interface SavedPass {
  completedAt?: string | null;
  scanId: string;
  scanDir: string;
  parentScanId: string;
  targetPath: string;
  continuationThreadId?: string | null;
  progress: { status: string };
  cost?: ScanCost;
}

export interface DeepScanComposition {
  scanId: string;
  scanDir: string;
  repository: string;
  pluginRoot: string;
  startedAt: string;
  settings: Required<DeepScanOptions>;
  scanOptions: ScanOptions;
  signal: AbortSignal;
  createClient(): Pick<CodexSecurity, "run" | "close">;
  workbench(args: readonly string[], input?: string): Promise<JsonObject>;
  merge(prompt: string, signal: AbortSignal): Promise<unknown>;
  onRetry?(message: string): void;
  onCleanupError?(error: unknown): void;
  writer: ScanArtifactRestorer;
  publish(draft: SemanticScan): Promise<void>;
  onCost(key: string, cost: Readonly<ScanCost> | null): void;
  historicalCost?(threadId: string): Promise<ScanCost | null>;
}

/** Compose complete ordinary scans; only accepted merge state belongs to the parent. */
export async function runDeepScans(
  input: DeepScanComposition,
): Promise<DeepScanCheckpoint> {
  const { scanId, scanDir, settings, signal, workbench } = input;
  let state: DeepScanCheckpoint;
  try {
    state = JSON.parse(
      (
        await readScanFile(
          scanDir,
          DEEP_SCAN_CHECKPOINT,
          "Deep Scan checkpoint",
        )
      ).toString("utf8"),
    );
  } catch (error) {
    // No parent checkpoint exists on a new normal scan registration.
    if (
      await lstat(join(scanDir, DEEP_SCAN_CHECKPOINT)).then(
        () => true,
        (cause: NodeJS.ErrnoException) => {
          if (cause.code === "ENOENT") return false;
          throw cause;
        },
      )
    )
      throw error;
    state = {
      version: 2,
      startedAt: input.startedAt,
      passes: [],
      mergedScanIds: [],
      aggregate: null,
      noNewStreak: 0,
      consecutiveErrors: 0,
    };
  }
  if (state.version !== 2)
    throw new Error("Unsupported saved Deep Scan checkpoint.");
  const passDirectory = (index: number): string =>
    `artifacts/deep-scan/passes/pass-${index + 1}`;
  for (const [index, pass] of state.passes.entries()) {
    if (pass.directory !== passDirectory(index))
      throw new Error("Saved scan pass escaped its parent.");
  }
  let saveTail = Promise.resolve();
  let savedSnapshot: string | undefined;
  let queuedSave: { snapshot: string; pending: Promise<void> } | undefined;
  const save = async (): Promise<void> => {
    const snapshot = JSON.stringify(state);
    // A newer complete snapshot includes the changes of every queued caller.
    // All callers share its durability barrier; an in-flight write is unchanged.
    if (queuedSave) {
      queuedSave.snapshot = snapshot;
      return queuedSave.pending;
    }
    const queued = { snapshot, pending: Promise.resolve() };
    queued.pending = saveTail.then(async () => {
      queuedSave = undefined;
      const snapshot = queued.snapshot;
      // Reuse only a successful write, after all earlier saves have settled.
      if (snapshot === savedSnapshot) return;
      savedSnapshot = undefined;
      await workbench(
        [
          "save-scan-artifact",
          "--scan-id",
          scanId,
          "--artifact-path",
          DEEP_SCAN_CHECKPOINT,
        ],
        snapshot,
      );
      savedSnapshot = snapshot;
    });
    queuedSave = queued;
    saveTail = queued.pending.catch(() => undefined);
    return queued.pending;
  };
  await save();
  const previousRuns = state.legacy?.discoveryRuns ?? 0;
  if (state.legacy && !state.legacy.cost) {
    const cost = state.legacy.originThreadId
      ? await input.historicalCost?.(state.legacy.originThreadId)
      : null;
    if (cost) {
      state.legacy.cost = cost;
      await save();
    }
    if (!cost && input.scanOptions.requireCost)
      throw new Error(
        "Restore the original Deep Scan session logs to verify its saved cost limit.",
      );
  }
  if (state.legacy?.cost) input.onCost("legacy", state.legacy.cost);
  const validateMerge = await createScanMergeValidator(input.pluginRoot);
  const accepted = new Map<string, ScanMergeInput>();
  const saved = new Map<string, SavedPass>();
  const reportPassCost = (key: string, cost: Readonly<ScanCost> | null) => {
    input.onCost(key, cost);
    if (cost === null && input.scanOptions.requireCost)
      throw new ScanCostTrackingError(
        "The child scan cost is unavailable; its cost limit cannot be verified.",
        scanDir,
      );
  };
  const refreshPasses = async (recoverOutcomes = false): Promise<void> => {
    const listed = await workbench([
      "list-scans",
      "--scan-root",
      join(scanDir, "artifacts/deep-scan/passes"),
    ]);
    const records = listed["scans"] as unknown as SavedPass[];
    if (recoverOutcomes)
      records.sort((a, b) =>
        (a.completedAt ?? "").localeCompare(b.completedAt ?? ""),
      );
    let recoveredSuccess = false;
    for (const record of records) {
      const index = state.passes.findIndex(
        (pass) =>
          relative(join(scanDir, pass.directory), record.scanDir) === "",
      );
      if (index < 0) continue;
      if (
        record.parentScanId !== scanId ||
        record.targetPath !== input.repository
      ) {
        throw new Error("Saved scan pass belongs to another parent or target.");
      }
      const pass = state.passes[index]!;
      if (pass.scanId !== undefined && pass.scanId !== record.scanId) {
        throw new Error("Saved scan pass registration changed.");
      }
      pass.scanId = record.scanId;
      if (
        recoverOutcomes &&
        record.progress.status === "failed" &&
        (!pass.failed || recoveredSuccess)
      ) {
        pass.failed = true;
        state.consecutiveErrors += 1;
      }
      saved.set(record.scanId, record);
      if (
        record.progress.status === "complete" ||
        (record.progress.status === "failed" && record.continuationThreadId)
      )
        reportPassCost(pass.directory, record.cost ?? null);
      else if (record.cost) input.onCost(pass.directory, record.cost);
      if (
        record.progress.status === "complete" &&
        !accepted.has(record.scanId)
      ) {
        const contract = await loadContract(record.scanDir, {
          pluginRoot: input.pluginRoot,
          signal,
        });
        if (contract.manifest.scan.id !== record.scanId)
          throw new Error("Saved scan artifacts changed identity.");
        accepted.set(
          record.scanId,
          await projectScanMergeWriteups(
            scanMergeInput({ ...contract, scanDir: record.scanDir }, scanId),
            input.writer,
            signal,
          ),
        );
        if (
          recoverOutcomes &&
          (recoveredSuccess ||
            (!pass.completed &&
              !state.mergedScanIds.includes(record.scanId))) &&
          state.consecutiveErrors < settings.stopAfterConsecutiveErrors
        ) {
          state.consecutiveErrors = 0;
          recoveredSuccess = true;
        }
        pass.completed = true;
      }
    }
    await save();
  };
  const deadline =
    Date.parse(state.startedAt) + settings.maxTimeHours * 3_600_000;
  await refreshPasses(
    state.terminalReason === undefined && Date.now() < deadline,
  );
  if (state.mergedScanIds.some((id) => !accepted.has(id))) {
    throw new Error(
      "An accepted merge input is no longer a sealed child scan.",
    );
  }
  const deadlineController = new AbortController();
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  const tick = (): void => {
    const remaining = deadline - Date.now();
    if (remaining <= 0)
      deadlineController.abort(
        new Error("deep_scan_discovery_deadline_reached"),
      );
    else deadlineTimer = setTimeout(tick, Math.min(remaining, 2_147_483_647));
  };
  tick();
  const externalStop = new AbortController();
  const consecutiveErrorLimit = new Error(
    "Deep Scan reached its consecutive error limit.",
  );
  const executionSignal = AbortSignal.any([signal, externalStop.signal]);
  const discoverySignal = AbortSignal.any([
    executionSignal,
    deadlineController.signal,
  ]);
  let polling = false;
  const cancellationTimer = setInterval(() => {
    if (polling) return;
    polling = true;
    void workbench(["get-scan", "--scan-id", scanId])
      .then((result) => {
        const scan = result["scan"] as JsonObject;
        const progress = scan["progress"] as JsonObject;
        if (
          progress["status"] === "canceled" ||
          progress["status"] === "failed"
        ) {
          externalStop.abort(new Error("The saved parent scan stopped."));
        }
      })
      .catch(() => undefined)
      .finally(() => {
        polling = false;
      });
  }, 1_000);
  cancellationTimer.unref();
  const mergePending = async (allowEmpty = false): Promise<void> => {
    if ((state.mergeFailures ?? 0) >= settings.stopAfterConsecutiveErrors)
      throw new Error("Deep Scan reached its consecutive merge error limit.");
    const pending = state.passes.flatMap((pass) => {
      const result =
        pass.scanId === undefined ? undefined : accepted.get(pass.scanId);
      return result && !state.mergedScanIds.includes(result.scanId)
        ? [result]
        : [];
    });
    if (!pending.length && (!allowEmpty || state.aggregate !== null)) return;
    const prompt = await scanMergePrompt(
      scanId,
      pending,
      state.aggregate,
      scanDir,
      input.writer,
    );
    let merged: ReturnType<typeof validateMerge>;
    let validationError: unknown;
    for (;;) {
      executionSignal.throwIfAborted();
      try {
        const response = await input.merge(
          validationError === undefined
            ? prompt
            : `${prompt}\n\nYour previous merge response failed validation: ${safeErrorMessage(validationError)}\nReturn a complete corrected JSON object using the same source findings and schema.`,
          executionSignal,
        );
        try {
          merged = validateMerge(response, pending, state.aggregate);
        } catch (error) {
          validationError = error;
          throw error;
        }
        break;
      } catch (error) {
        if (
          executionSignal.aborted ||
          error instanceof ScanPermissionError ||
          isCodexCybersecurityPolicyRefusal(error)
        )
          throw error;
        state.mergeFailures = (state.mergeFailures ?? 0) + 1;
        await save();
        if (state.mergeFailures >= settings.stopAfterConsecutiveErrors)
          throw error;
      }
    }
    executionSignal.throwIfAborted();
    state.aggregate = {
      ...merged.aggregate,
      coverage: combineScanCoverage(
        [...accepted.values()],
        scanDir,
        [],
        state.legacy?.coverage,
      ),
    };
    state.mergeFailures = 0;
    state.mergedScanIds.push(...pending.map((result) => result.scanId));
    state.noNewStreak =
      merged.newFindings > 0 ? 0 : state.noNewStreak + pending.length;
    await save();
    await input.publish(state.aggregate);
  };
  const runPass = async (
    pass: DeepScanCheckpoint["passes"][number],
  ): Promise<void> => {
    const client = input.createClient();
    let latestCost: Readonly<ScanCost> | undefined;
    try {
      // These existing retry delays do not create another logical scan.
      const retries = [60_000, 180_000, 540_000];
      for (let attempt = 0; ; attempt += 1) {
        discoverySignal.throwIfAborted();
        try {
          const result = await client.run(input.repository, {
            ...input.scanOptions,
            mode: "standard",
            outputDir: join(scanDir, pass.directory),
            ...(pass.scanId === undefined
              ? { parentScanId: scanId }
              : { resumeScanId: pass.scanId, parentScanId: undefined }),
            deepScanPass: true,
            signal: discoverySignal,
            onRegisteredScan: async (registration) => {
              pass.scanId = registration["scanId"] as string;
              await save();
            },
            onCost: (cost) => {
              latestCost = cost;
              input.onCost(pass.directory, cost);
            },
          });
          accepted.set(
            result.manifest.scan.id,
            await projectScanMergeWriteups(
              scanMergeInput(result, scanId),
              input.writer,
              signal,
            ),
          );
          reportPassCost(pass.directory, result.cost);
          executionSignal.throwIfAborted();
          pass.completed = true;
          state.consecutiveErrors = 0;
          await save();
          return;
        } catch (error) {
          if (
            error instanceof ScanCostTrackingError ||
            error instanceof ScanPermissionError ||
            isCodexCybersecurityPolicyRefusal(error)
          )
            externalStop.abort(error);
          if (discoverySignal.aborted) throw error;
          if (attempt >= retries.length) {
            if (pass.scanId !== undefined) {
              await workbench([
                "fail-scan",
                "--scan-id",
                pass.scanId,
                "--message",
                safeErrorMessage(error).slice(0, 2400),
                ...(latestCost
                  ? ["--cost-json", JSON.stringify(latestCost)]
                  : []),
              ]);
            }
            pass.failed = true;
            state.consecutiveErrors += 1;
            if (state.consecutiveErrors >= settings.stopAfterConsecutiveErrors)
              externalStop.abort(consecutiveErrorLimit);
            await save();
            return;
          }
          input.onRetry?.(
            `Deep Scan pass ${state.passes.indexOf(pass) + 1} will retry: ${safeErrorMessage(error)}`,
          );
          await delay(retries[attempt], undefined, { signal: discoverySignal });
        }
      }
    } catch (error) {
      if (
        discoverySignal.aborted &&
        !(discoverySignal.reason instanceof ScanTransportClosedError) &&
        pass.scanId !== undefined
      ) {
        await workbench([
          "fail-scan",
          "--scan-id",
          pass.scanId,
          "--message",
          safeErrorMessage(discoverySignal.reason).slice(0, 2400),
          ...(latestCost ? ["--cost-json", JSON.stringify(latestCost)] : []),
        ]).catch(() => undefined);
      }
      throw error;
    } finally {
      try {
        await client.close();
      } catch (error) {
        input.onCleanupError?.(error);
      }
    }
  };
  try {
    if (state.consecutiveErrors >= settings.stopAfterConsecutiveErrors)
      throw consecutiveErrorLimit;
    while (state.terminalReason === undefined) {
      executionSignal.throwIfAborted();
      await mergePending();
      const discoveryDeadlineReached =
        deadlineController.signal.aborted || Date.now() >= deadline;
      if (
        !discoveryDeadlineReached &&
        state.noNewStreak >= settings.stopAfterNoNew
      ) {
        state.terminalReason = "saturated";
        break;
      }
      const unfinished = state.passes.filter(
        (pass) =>
          !pass.failed &&
          (pass.scanId === undefined ||
            saved.get(pass.scanId)?.progress.status === "running"),
      );
      if (
        discoveryDeadlineReached ||
        (unfinished.length === 0 &&
          previousRuns + state.passes.length >= settings.maxDiscoveryRuns)
      ) {
        if (
          !discoveryDeadlineReached &&
          state.aggregate === null &&
          state.consecutiveErrors > 0
        )
          throw new Error(
            "Deep Scan stopped because every discovery run failed.",
          );
        state.terminalReason = "capped";
        break;
      }
      const batch = unfinished.slice(0, settings.workers);
      while (
        batch.length < settings.workers &&
        previousRuns + state.passes.length < settings.maxDiscoveryRuns
      ) {
        const pass = { directory: passDirectory(state.passes.length) };
        state.passes.push(pass);
        batch.push(pass);
      }
      await save();
      const results = await Promise.allSettled(batch.map(runPass));
      executionSignal.throwIfAborted();
      if (!deadlineController.signal.aborted) {
        for (const result of results)
          if (result.status === "rejected") throw result.reason;
      }
      await refreshPasses();
    }
    await mergePending(true);
    const unresolved = state.passes
      .filter((pass) => !pass.scanId || !accepted.has(pass.scanId))
      .map((pass) => pass.directory);
    state.aggregate = {
      ...state.aggregate!,
      coverage: combineScanCoverage(
        [...accepted.values()],
        scanDir,
        unresolved,
        state.legacy?.coverage,
      ),
    };
    await save();
    await input.publish(state.aggregate);
    return state;
  } catch (error) {
    if (signal.reason instanceof ScanTransportClosedError) throw error;
    state.terminalReason =
      signal.reason instanceof ScanCostLimitExceededError
        ? "capped"
        : executionSignal.aborted &&
            executionSignal.reason !== consecutiveErrorLimit &&
            !(executionSignal.reason instanceof ScanCostTrackingError) &&
            !(executionSignal.reason instanceof ScanPermissionError) &&
            !isCodexCybersecurityPolicyRefusal(executionSignal.reason)
          ? "canceled"
          : "failed";
    if (state.aggregate !== null) {
      state.aggregate = {
        ...state.aggregate,
        coverage: combineScanCoverage(
          [...accepted.values()].filter((pass) =>
            state.mergedScanIds.includes(pass.scanId),
          ),
          scanDir,
          state.passes
            .filter(
              (pass) =>
                !pass.scanId || !state.mergedScanIds.includes(pass.scanId),
            )
            .map((pass) => pass.directory),
          state.legacy?.coverage,
        ),
      };
    }
    await save().catch(() => undefined);
    if (state.aggregate !== null)
      await input.publish(state.aggregate).catch(() => undefined);
    throw error;
  } finally {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    clearInterval(cancellationTimer);
  }
}

function isCodexCybersecurityPolicyRefusal(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  if (
    /\b(?:429|rate[ _-]*limit(?:ed|ing)?|too many requests)\b/iu.test(message)
  )
    return false;
  return [
    /\bflagged for possible cybersecurity risk\b/iu,
    /\bflagged for potentially high-risk cyber activity\b/iu,
    /\bcyber[_\s-]?policy\b/iu,
    /\b(?:cybersecurity|cyber)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
    /\b(?:content|safety)[ _-]*policy[ _-]*(?:violation|refusal|refused)\b/iu,
    /\b(?:refusal|refused)\b[^\n]*\b(?:cybersecurity|cyber|safety policy)\b/iu,
    /\b(?:cybersecurity|cyber|safety policy)\b[^\n]*\b(?:refusal|refused)\b/iu,
  ].some((pattern) => pattern.test(message));
}
