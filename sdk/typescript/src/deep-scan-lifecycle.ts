import type {
  DeepScanCheckpoint,
  DeepScanPass,
} from "./deep-scan-checkpoint.js";
import type { ScanMergeResult } from "./scan-merge.js";
import type { SemanticCoverage } from "./semantic-models.js";

export function passDirectory(index: number): string {
  return `artifacts/deep-scan/passes/pass-${index + 1}`;
}

export function reservePass(state: DeepScanCheckpoint): DeepScanPass {
  const pass = { directory: passDirectory(state.passes.length) };
  state.passes.push(pass);
  return pass;
}

export function registerPass(pass: DeepScanPass, scanId: string): void {
  if (pass.scanId !== undefined && pass.scanId !== scanId)
    throw new Error("Saved scan pass registration changed.");
  pass.scanId = scanId;
}

export function observePassCompletion(
  state: DeepScanCheckpoint,
  pass: DeepScanPass,
  replayAfterSuccess = false,
): boolean {
  const observed =
    replayAfterSuccess ||
    (!pass.completed && !state.mergedScanIds.includes(pass.scanId!));
  if (observed) state.consecutiveErrors = 0;
  pass.completed = true;
  return observed;
}

export function observePassFailure(
  state: DeepScanCheckpoint,
  pass: DeepScanPass,
  replayAfterSuccess = false,
): void {
  if (pass.failed && !replayAfterSuccess) return;
  pass.failed = true;
  state.consecutiveErrors += 1;
}

export function exhaustPassRetries(
  state: DeepScanCheckpoint,
  pass: DeepScanPass,
  errorLimit: number,
): boolean {
  observePassFailure(state, pass);
  // This decision is durable in the same snapshot as the threshold counter.
  const stopped = state.consecutiveErrors >= errorLimit;
  if (stopped) stopDiscovery(state, "failed");
  return stopped;
}

export function acceptMerge(
  state: DeepScanCheckpoint,
  merged: ScanMergeResult,
  pendingScanIds: readonly string[],
  coverage: SemanticCoverage,
): void {
  state.aggregate = { ...merged.aggregate, coverage };
  state.mergeFailures = 0;
  state.mergedScanIds.push(...pendingScanIds);
  const novelPasses = new Set(merged.newFindingScanIds);
  for (const scanId of pendingScanIds)
    state.noNewStreak = novelPasses.has(scanId) ? 0 : state.noNewStreak + 1;
}

export function stopDiscovery(
  state: DeepScanCheckpoint,
  reason: NonNullable<DeepScanCheckpoint["terminalReason"]>,
): void {
  // Required failure remains terminal even if another worker later completes.
  if (state.terminalReason !== "failed") state.terminalReason = reason;
}

export function discoveryStopReason(
  state: DeepScanCheckpoint,
  input: {
    deadlineReached: boolean;
    hasUnfinishedPasses: boolean;
    maxDiscoveryRuns: number;
    stopAfterNoNew: number;
  },
): "saturated" | "capped" | undefined {
  if (
    !input.deadlineReached &&
    !input.hasUnfinishedPasses &&
    state.noNewStreak >= input.stopAfterNoNew
  )
    return "saturated";
  if (
    input.deadlineReached ||
    (!input.hasUnfinishedPasses &&
      state.passes.length >= input.maxDiscoveryRuns)
  )
    return "capped";
  return undefined;
}
