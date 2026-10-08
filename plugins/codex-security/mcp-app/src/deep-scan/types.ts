import type { DeepReducerContext } from "../artifact-io.js";
import type { WorkbenchDeepScanStore } from "./store.js";

export type DeepScanTerminalReason = "saturated" | "capped";

export type DeepScanRunStatus =
  "running" | "succeeded" | "canceled" | "failed" | "interrupted";

export type DeepScanWorkerKind = "setup" | "discovery" | "dedup";

export type DeepScanWorkerStatus =
  "queued" | "running" | "succeeded" | "failed" | "canceled";

export type DeepScanMergeState = "none" | "buffered" | "merging" | "merged";

/** Effective configuration and durable run state returned by the workbench. */
export interface DeepScanConfig {
  workers: number;
  subagents: number;
  stopAfterNoNew: number;
  stopAfterConsecutiveErrors: number;
  maxDiscoveryRuns: number;
  maxTimeHours?: number;
}

export interface DeepScanRunState {
  scanId: string;
  status: DeepScanRunStatus;
  coordinatorGeneration?: number;
  createdAt?: string;
  updatedAt?: string;
  targetPath: string;
  scope: string;
  userContext?: string;
  scanDir: string;
  config: DeepScanConfig;
  dispatchedCount: number;
  noNewStreak: number;
  consecutiveErrors: number;
  manifestPath?: string;
  terminalReason?: DeepScanTerminalReason;
  error?: string;
  persistedWorkers?: PersistedDeepScanWorker[];
  persistedDedupInputs?: PersistedDeepScanDedupInput[];
}

export interface PersistedDeepScanDedupInput {
  dedupWorkerId: string;
  discoveryWorkerId: string;
  inputOrder: number;
}

export interface DeepScanCoordinatorClaim {
  run: DeepScanRunState;
  acquired: boolean;
}

export interface DeepScanCoordinatorLeaseInput {
  scanId: string;
  threadId: string;
  handoffClaimToken?: string;
}

/** Fields supplied when the coordinator changes one worker. */
export interface DeepScanWorkerMutation {
  id: string;
  scanId: string;
  kind: DeepScanWorkerKind;
  status: DeepScanWorkerStatus;
  promptPath: string;
  artifactDir: string;
  attempt: number;
  threadId?: string;
  resultManifestPath?: string;
  error?: string;
  replaceableFailureKind?: DeepScanReplaceableFailureKind;
}

export type DeepScanReplaceableFailureKind =
  "policy_refusal" | "transient_error" | "invalid_discovery_artifacts";

/** The authoritative worker record returned after SQLite commits the change. */
export interface PersistedDeepScanWorker extends Omit<
  DeepScanWorkerMutation,
  "scanId" | "replaceableFailureKind"
> {
  completionSequence?: number;
  consecutiveErrors?: number;
  mergeState: DeepScanMergeState;
}

/** Inputs committed atomically when a reducer finishes. */
export interface DedupCommit {
  id: string;
  scanId: string;
  newFindings: number;
  resultManifestPath: string;
  candidateLedgerPath?: string;
}

/** Durable operations implemented by the Python workbench. */
export type DeepScanStore = Omit<
  WorkbenchDeepScanStore,
  "begin" | "coordinatorLeaseArgs"
>;

/** Host-bound worker artifact state; never populate this from model input. */
export interface CodexWorkerArtifactContext {
  root: string;
  layout: "worker" | "reducer";
  deepReducer?: DeepReducerContext;
}

/** Transport-neutral contract for one top-level Codex worker. */
export interface CodexWorkerRequest {
  kind: DeepScanWorkerKind;
  promptPath: string;
  workingDirectory: string;
  subagents: number;
  signal: AbortSignal;
  resumeThreadId?: string;
  continuationPrompt?: string;
  artifactContext?: CodexWorkerArtifactContext;
  onThreadStarted?: (threadId: string) => Promise<void> | void;
}

export interface CodexWorkerResult {
  threadId?: string;
  diagnostics?: CodexWorkerDiagnostic[];
}

/**
 * Sanitized SDK evidence that is safe to persist in SQLite and manifests.
 *
 * Never add raw command text, command output, prompts, or repository paths
 * here. The coordinator only needs stable classifications that explain why a
 * worker could not satisfy its artifact contract.
 */
export interface CodexWorkerDiagnostic {
  code:
    | "sandbox_namespace_exhausted"
    | "file_change_failed"
    | "artifact_tool_failed";
  message: string;
}

export interface CodexWorkerExecutor {
  run(request: CodexWorkerRequest): Promise<CodexWorkerResult>;
}

export interface DeepScanClock {
  now(): number;
  sleep(delayMs: number, signal: AbortSignal): Promise<void>;
}

export interface DeepScanLogEvent {
  event: string;
  scanId: string;
  workerId?: string;
  kind?: DeepScanWorkerKind;
  attempt?: number;
  threadId?: string;
  count?: number;
  completed?: number;
  newFindings?: number;
  pass?: number;
  reason?: string;
  total?: number;
}

export type DeepScanLogger = (event: DeepScanLogEvent) => void;
