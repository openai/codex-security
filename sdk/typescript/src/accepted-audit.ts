/** Accepted evidence may still describe partial or unknown source coverage. */
export interface AuditEvidence<Result> {
  checkpoint?: Result;
  accepted?: Result;
}

export type AuditOutcome<Execution, Result> = AuditEvidence<Result> &
  (
    | { status: "accepted"; execution: Execution; accepted: Result }
    | { status: "checkpoint"; execution: Execution }
  );

/** One attempt; enclosing callers own retries and public completion. */
export async function runAcceptedAudit<Execution, Result>(input: {
  signal: AbortSignal;
  execute: () => Promise<Execution>;
  accept: (execution: Execution) => Promise<AuditEvidence<Result>>;
}): Promise<AuditOutcome<Execution, Result>> {
  input.signal.throwIfAborted();
  const execution = await input.execute();
  input.signal.throwIfAborted();
  const evidence = await input.accept(execution);
  input.signal.throwIfAborted();
  return evidence.accepted === undefined
    ? { ...evidence, execution, status: "checkpoint" }
    : {
        ...evidence,
        execution,
        status: "accepted",
        accepted: evidence.accepted,
      };
}

/** Process completion alone does not accept an unfinished audit checkpoint. */
export function auditEvidence<Result extends { complete?: boolean }>(
  checkpoint: Result,
): AuditEvidence<Result> {
  return checkpoint.complete === false
    ? { checkpoint }
    : { checkpoint, accepted: checkpoint };
}
