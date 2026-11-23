import type { DiscoveryBoardContext } from "../artifact-io.js";
import type { WorkbenchDeepScanStore } from "./store.js";
import type { z } from "zod";
import type { WorkerTokenUsage } from "./usage-receipt.js";
import type {
  configSchema,
  finalizationInputSchema,
  mergeClaimSchema,
  dedupInputSchema,
  runSchema,
  workerSchema,
} from "./response.js";

/** Effective configuration and durable run state returned by the workbench. */
export type DeepScanConfig = z.output<typeof configSchema>;
export type DeepScanRunState = Omit<
  z.output<typeof runSchema>,
  | "persistedWorkers"
  | "persistedDedupInputs"
  | "persistedMergeClaims"
  | "finalizationInput"
  | "usageOwner"
  | "executionSettings"
> & {
  finalizationInput?: z.output<typeof runSchema>["finalizationInput"];
  usageOwner?: z.output<typeof runSchema>["usageOwner"];
  executionSettings?: z.output<typeof runSchema>["executionSettings"];
  persistedMergeClaims?: PersistedDeepScanMergeClaim[];
  parentComplete?: boolean;
  persistedWorkers?: PersistedDeepScanWorker[];
  persistedDedupInputs?: PersistedDeepScanDedupInput[];
  startDisposition?: "created" | "joined";
};
export type DeepScanTerminalReason = NonNullable<
  DeepScanRunState["terminalReason"]
>;
export type PersistedDeepScanDedupInput = z.output<typeof dedupInputSchema>;
/** The authoritative worker record returned after SQLite commits the change. */
export type PersistedDeepScanWorker = z.output<typeof workerSchema> & {
  consecutiveErrors?: number;
};
export type DeepScanWorkerKind = PersistedDeepScanWorker["kind"];
export type DeepScanRunStatus = DeepScanRunState["status"];
export type DeepScanWorkerStatus = PersistedDeepScanWorker["status"];
export type DeepScanMergeState = PersistedDeepScanWorker["mergeState"];
export type DeepScanFinalizationInput = z.output<
  typeof finalizationInputSchema
>;
export type PersistedDeepScanMergeClaim = z.output<typeof mergeClaimSchema>;
export interface DeepScanCanonicalArtifacts {
  inScopeFilesPath: string;
  candidateLedgerPath: string;
}
export type DeepScanReducerArtifacts = DeepScanCanonicalArtifacts;

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
export type DeepScanWorkerMutation = Omit<
  PersistedDeepScanWorker,
  "completionSequence" | "consecutiveErrors" | "mergeState"
> & {
  scanId: string;
  validatedResultSha256?: string;
  terminalFailure?: boolean;
  replaceableFailureKind?: DeepScanReplaceableFailureKind;
};

export type DeepScanReplaceableFailureKind =
  "policy_refusal" | "transient_error" | "invalid_discovery_artifacts";

/** Durable operations implemented by the Python workbench. */
export type DeepScanStore = Omit<
  WorkbenchDeepScanStore,
  | "begin"
  | "cancel"
  | "releaseCoordinator"
  | "coordinatorGeneration"
  | "selectFinalization"
> & {
  selectFinalization?: WorkbenchDeepScanStore["selectFinalization"];
};

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
