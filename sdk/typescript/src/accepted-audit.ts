/** Result acceptance is independent of process completion and source coverage. */
export interface AuditEvidence<Result> {
  checkpoint?: Result;
  accepted?: Result;
}

export type AuditOutcome<Execution, Result> = AuditEvidence<Result> &
  (
    | { status: "accepted"; execution: Execution; accepted: Result }
    | { status: "checkpoint"; execution: Execution }
    | {
        status: "failed" | "canceled";
        execution?: Execution;
        stage: "execution" | "acceptance";
        error: unknown;
      }
  );

/**
 * Run one audit attempt under its parent scan. Callers bind the execution and
 * artifact adapters; retries, registration, matching and sealing stay outside.
 */
export async function runAcceptedAudit<Execution, Result>(input: {
  signal: AbortSignal;
  execute: () => Promise<Execution>;
  accept: (execution: Execution) => Promise<AuditEvidence<Result>>;
}): Promise<AuditOutcome<Execution, Result>> {
  let execution: Execution | undefined;
  let evidence: AuditEvidence<Result> = {};
  let stage: "execution" | "acceptance" = "execution";
  try {
    input.signal.throwIfAborted();
    execution = await input.execute();
    input.signal.throwIfAborted();
    stage = "acceptance";
    evidence = await input.accept(execution);
    input.signal.throwIfAborted();
    return evidence.accepted === undefined
      ? { ...evidence, execution, status: "checkpoint" }
      : {
          ...evidence,
          execution,
          accepted: evidence.accepted,
          status: "accepted",
        };
  } catch (error) {
    return {
      ...evidence,
      execution,
      stage,
      error,
      status: input.signal.aborted ? "canceled" : "failed",
    };
  }
}

/** A completed audit may still report partial or unknown source coverage. */
export function auditEvidence<Result extends { complete?: boolean }>(
  checkpoint: Result,
): AuditEvidence<Result> {
  return checkpoint.complete === false
    ? { checkpoint }
    : { checkpoint, accepted: checkpoint };
}
