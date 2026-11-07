import type { DiscoveryBoardContext } from "../artifact-io.js";
import type { WorkerTokenUsage } from "./usage-receipt.js";
import type { DeepScanExecutionSettingsSnapshot } from "./recovery-settings.js";

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

export interface DeepScanFinalizationInput {
  version: number;
  resultPath: string | null;
  resultSha256: string | null;
  terminalReason: DeepScanTerminalReason;
  omittedWorkerIds: string[];
  selectedAt: string;
}

export interface DeepScanRunState {
  scanId: string;
  startDisposition?: "created" | "joined";
  schemaVersion?: number;
  sdkOwnsCompletion?: boolean;
  serviceTier?: string;
  severityRubric?: { markdown: string; revision: number; sha256: string };
  workflowVersion?: string;
  finalizationInput?: DeepScanFinalizationInput;
  usageOwner?: {
    threadId: string | null;
    turnId: string | null;
    startedAt: string;
  } | null;
  executionSettings?: DeepScanExecutionSettingsSnapshot | null;
  status: DeepScanRunStatus;
  coordinatorGeneration?: number;
  discoveryStarted?: boolean;
  createdAt?: string;
  updatedAt?: string;
  targetPath: string;
  scope: string;
  includePaths?: string[];
  filePaths?: string[];
  userContext?: string;
  model?: string;
  reasoningEffort?: string;
  scanDir: string;
  workerUsageDirectory?: string;
  completionSequence?: number;
  config: DeepScanConfig;
  dispatchedCount: number;
  noNewStreak: number;
  consecutiveErrors: number;
  manifestPath?: string;
  terminalReason?: DeepScanTerminalReason;
  error?: string;
  persistedWorkers?: PersistedDeepScanWorker[];
  persistedDedupInputs?: PersistedDeepScanDedupInput[];
  persistedMergeClaims?: PersistedDeepScanMergeClaim[];
  committedMerge?: {
    workerId: string;
    resultManifestPath: string;
    resultManifestSha256: string;
    newFindings: number;
  };
}

export interface PersistedDeepScanMergeClaim {
  workerId: string;
  previousWorkerId?: string;
  previousResultPath?: string;
  previousResultSha256?: string;
}

export interface PersistedDeepScanDedupInput {
  dedupWorkerId: string;
  discoveryWorkerId: string;
  inputOrder: number;
  resultManifestPath?: string;
  resultManifestSha256?: string;
  attempt?: number;
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
  terminalFailure?: boolean;
  replaceableFailureKind?: DeepScanReplaceableFailureKind;
}

export type DeepScanReplaceableFailureKind =
  "policy_refusal" | "transient_error" | "invalid_discovery_artifacts";

/** The authoritative worker record returned after SQLite commits the change. */
export interface PersistedDeepScanWorker extends Omit<
  DeepScanWorkerMutation,
  "scanId" | "terminalFailure" | "replaceableFailureKind"
> {
  acceptedResultPath?: string;
  acceptedResultSha256?: string;
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
export interface DeepScanStore {
  get(scanId: string, threadId: string): Promise<DeepScanRunState>;
  claimCoordinator(
    input: DeepScanCoordinatorLeaseInput,
  ): Promise<DeepScanCoordinatorClaim>;
  heartbeatCoordinator(
    input: DeepScanCoordinatorLeaseInput,
  ): Promise<DeepScanRunState>;
  updateWorker(
    update: DeepScanWorkerMutation,
  ): Promise<PersistedDeepScanWorker>;
  recordIteration(input: {
    scanId: string;
    id: string;
    workerIds: string[];
    resultPath: string;
    noNewStreak: number;
    consecutiveErrors: number;
  }): Promise<DeepScanRunState>;
  selectFinalization?(input: {
    scanId: string;
    coordinatorGeneration?: number;
    reason: DeepScanTerminalReason;
    manifestPath: string;
    resultPath?: string;
    omittedWorkerIds: string[];
  }): Promise<DeepScanRunState>;
  finish(input: {
    scanId: string;
    coordinatorGeneration?: number;
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
    stagedManifestPath?: string,
  ): Promise<DeepScanRunState>;
  recordStoppedPublicationFailure(
    scanId: string,
    message: string,
    coordinatorGeneration?: number,
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
  layout: "worker";
  discoveryBoard?: DiscoveryBoardContext;
}

/** Transport-neutral contract for one top-level Codex worker. */
export interface CodexWorkerRequest extends WorkerTelemetryOptions {
  kind: "discovery";
  promptPath: string;
  workingDirectory: string;
  subagents: number;
  signal: AbortSignal;
  resumeThreadId?: string;
  continuationPrompt?: string;
  artifactContext?: CodexWorkerArtifactContext;
  onNonRetryableError?: (error: Error) => void;
}

export interface WorkerTelemetryOptions {
  attemptId?: string;
  /** Host-bound receipt storage, excluded from model filesystem access. */
  workerUsageDirectory?: string;
  onThreadStarted?: (threadId: string) => Promise<void> | void;
  onAttribution?: (attribution: WorkerAttribution) => void;
  onUsage?: (
    usage: WorkerTokenUsage | null,
    turnId?: string,
  ) => Promise<void> | void;
}

export interface WorkerAttribution {
  operationId?: string;
  attemptId: string;
  parentAttemptId?: string;
}

export interface CodexWorkerResult {
  threadId?: string;
  turnId?: string;
  usage?: WorkerTokenUsage | null;
  diagnostics?: CodexWorkerDiagnostic[];
}

/** SDK failure diagnostics retained alongside artifact-validation failures. */
export interface CodexWorkerDiagnostic {
  code:
    | "sandbox_namespace_exhausted"
    | "file_change_failed"
    | "artifact_tool_failed"
    | "worker_error";
  message: string;
}

export interface CodexWorkerExecutor {
  run(request: CodexWorkerRequest): Promise<CodexWorkerResult>;
  compareFindings?(
    prompt: string,
    workingDirectory: string,
    signal: AbortSignal,
    schema: Record<string, unknown>,
    telemetry?: WorkerTelemetryOptions,
  ): Promise<string>;
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
  retainedFindings?: number;
  pass?: number;
  reason?: string;
  total?: number;
  timestamp?: string;
  durationMs?: number;
  outcome?: "succeeded" | "failed" | "canceled";
  retry?: boolean;
  resumed?: boolean;
  attemptId?: string;
  operationId?: string;
  parentAttemptId?: string;
}

export type DeepScanLogger = (event: DeepScanLogEvent) => void;
