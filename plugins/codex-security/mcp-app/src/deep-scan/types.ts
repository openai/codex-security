import type { DeepReducerContext } from "../artifact-io.js";

export type DeepScanTerminalReason = "saturated" | "capped";

export type DeepScanRunStatus =
  | "running"
  | "succeeded"
  | "canceled"
  | "failed"
  | "interrupted";

export type DeepScanWorkerKind = "setup" | "discovery" | "dedup";

export type DeepScanWorkerStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "canceled";

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

export interface DeepScanCanonicalArtifacts {
  inScopeFilesPath: string;
  candidateLedgerPath: string;
}

export type DeepScanReducerArtifacts = DeepScanCanonicalArtifacts;

export interface DeepScanRunState {
  scanId: string;
  status: DeepScanRunStatus;
  phase?: "setup" | "discovery" | "reducing" | "terminal";
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
  canonicalArtifacts?: DeepScanCanonicalArtifacts;
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

export interface BeginDeepScanResult {
  run: DeepScanRunState;
  shouldStart: boolean;
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
  | "policy_refusal"
  | "transient_error"
  | "invalid_discovery_artifacts";

/** The authoritative worker record returned after SQLite commits the change. */
export interface PersistedDeepScanWorker {
  id: string;
  kind: DeepScanWorkerKind;
  status: DeepScanWorkerStatus;
  promptPath: string;
  artifactDir: string;
  attempt: number;
  threadId?: string;
  resultManifestPath?: string;
  completionSequence?: number;
  consecutiveErrors?: number;
  mergeState: DeepScanMergeState;
  error?: string;
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
export interface DeepScanStore {
  begin(input: {
    scanId?: string;
    targetPath?: string;
    scope?: string;
    userContext?: string;
    handoffClaimToken?: string;
    model?: string;
    reasoningEffort?: string;
    threadId: string;
    scanRoot: string;
  }): Promise<BeginDeepScanResult>;
  get(scanId: string, threadId: string): Promise<DeepScanRunState>;
  claimCoordinator(input: DeepScanCoordinatorLeaseInput): Promise<DeepScanCoordinatorClaim>;
  heartbeatCoordinator(input: DeepScanCoordinatorLeaseInput): Promise<DeepScanRunState>;
  cancel(scanId: string, threadId: string): Promise<Record<string, unknown>>;
  updateWorker(update: DeepScanWorkerMutation): Promise<PersistedDeepScanWorker>;
  claimDedup(input: {
    id: string;
    scanId: string;
    workerIds: string[];
    promptPath: string;
    artifactDir: string;
  }): Promise<void>;
  commitDedup(commit: DedupCommit): Promise<DeepScanRunState>;
  finish(input: {
    scanId: string;
    reason: DeepScanTerminalReason;
    manifestPath: string;
    stagedManifestPath?: string;
    omittedWorkerIds: string[];
  }): Promise<DeepScanRunState>;
  fail(
    scanId: string,
    message: string,
    status?: "failed" | "interrupted",
    manifestPath?: string,
    stagedManifestPath?: string
  ): Promise<DeepScanRunState>;
  recordStoppedPublicationFailure(
    scanId: string,
    message: string,
    coordinatorGeneration?: number
  ): Promise<DeepScanRunState>;
  updateProgress(input: {
    scanId: string;
    handoffClaimToken?: string;
    phase?: "preflight" | "discovery";
    deepReviewPass?: number;
    reviewItemsTotal?: number;
    reviewItemsCompleted?: number;
  }): Promise<void>;
}

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
  finalResponse: string;
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
  code: "sandbox_namespace_exhausted" | "file_change_failed" | "artifact_tool_failed";
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
