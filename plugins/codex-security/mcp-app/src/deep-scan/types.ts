import type { DeepReducerContext } from "../artifact-io.js";
import type { WorkbenchDeepScanStore } from "./store.js";
import type { z } from "zod";
import type {
  configSchema,
  dedupInputSchema,
  runSchema,
  workerSchema,
} from "./response.js";

/** Effective configuration and durable run state returned by the workbench. */
export type DeepScanConfig = z.output<typeof configSchema>;
export type DeepScanRunState = Omit<
  z.output<typeof runSchema>,
  "persistedWorkers" | "persistedDedupInputs"
> & {
  persistedWorkers?: PersistedDeepScanWorker[];
  persistedDedupInputs?: PersistedDeepScanDedupInput[];
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
  replaceableFailureKind?: DeepScanReplaceableFailureKind;
};

export type DeepScanReplaceableFailureKind =
  "policy_refusal" | "transient_error" | "invalid_discovery_artifacts";

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
  onNonRetryableError?: (error: Error) => void;
}

export interface CodexWorkerResult {
  threadId?: string;
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
