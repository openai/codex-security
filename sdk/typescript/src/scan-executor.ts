import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import type { ScanActivity } from "./scan-activity.js";
import { scanPhaseSchema, type ScanProgress } from "./worker-progress.js";

/** One Standard scan. The host owns execution, persistence and reconciliation. */
export interface ScanExecutionRequest {
  version: 2;
  requestId: string;
  scanId: string;
  repository: string;
  revision: string;
  scope: { paths: string[] };
  identity: { runId: string; attemptId: string; buildId: string };
  prompt: string;
  model: string;
  reasoningEffort: string;
  runtime: {
    pluginRoot: string;
    pluginVersion: string;
    stateDirectory: string;
    outputDirectory: string;
    /** Runtime context only. Credentials belong to the host executor. */
    environment: Record<string, string>;
    /** Per-attempt attribution; IDs are for correlation, not metric labels. */
    requestMetadata?: Readonly<Record<string, string>>;
  };
}

export const ScanExecutionResultSchema = z
  .strictObject({
    requestId: z.string().min(1),
    status: z.enum(["completed", "failed", "canceled", "acceptance_unknown"]),
    sessionId: z.string().min(1).optional(),
    finalResponse: z.string().optional(),
    /** Host usage is opaque; absence means unknown, not zero. */
    usage: z.unknown().optional(),
    message: z.string().optional(),
    error: z
      .strictObject({
        code: z.number().int(),
        message: z.string(),
        data: z.unknown().optional(),
      })
      .optional(),
  })
  .refine(
    (value) => value.status !== "completed" || value.sessionId !== undefined,
    {
      message: "Completed execution requires a sessionId.",
    },
  );
export type ScanExecutionResult = z.infer<typeof ScanExecutionResultSchema>;
export type ScanExecutionEvent =
  | { type: "progress"; progress: ScanProgress }
  | { type: "activity"; activity: ScanActivity };

export const ScanExecutionEventSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("progress"),
    progress: z.strictObject({
      phase: scanPhaseSchema,
      filesCompleted: z.number().int().nonnegative(),
      filesTotal: z.number().int().nonnegative(),
      reviewItems: z
        .strictObject({
          completed: z.number().int().nonnegative(),
          total: z.number().int().nonnegative(),
        })
        .refine(({ completed, total }) => completed <= total)
        .optional(),
    }),
  }),
  z.strictObject({
    type: z.literal("activity"),
    activity: z.strictObject({
      id: z.string(),
      kind: z.enum(["command", "tool", "reasoning", "message"]),
      status: z.enum(["running", "completed", "failed"]),
      description: z.string(),
      paths: z.array(z.string()),
      worker: z.number().int().optional(),
    }),
  }),
]);

export interface ScanExecutor {
  /** Submit once. On abort, settle with the host's recorded outcome and usage. */
  run(
    request: ScanExecutionRequest,
    options: {
      signal: AbortSignal;
      onEvent?: (event: ScanExecutionEvent) => void;
    },
  ): Promise<ScanExecutionResult>;
}

/** Carries the exact execution outcome even when finalization cannot complete. */
export class ScanExecutionError extends CodexSecurityError {
  /** Foreign receipts remain available for reconciliation, not accounting. */
  readonly receiptMatchesRequest: boolean;

  constructor(
    public readonly result: ScanExecutionResult,
    message?: string,
    options: { receiptMatchesRequest?: boolean } = {},
  ) {
    super(
      message ??
        result.message ??
        result.error?.message ??
        `Hosted execution ${result.status}.`,
    );
    this.receiptMatchesRequest = options.receiptMatchesRequest ?? true;
  }
}
