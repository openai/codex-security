export interface ScanDraftInput {
  scanId: string;
  complete?: boolean;
  handoffClaimToken?: string;
  scope?: Record<string, unknown>;
  threatModel?: Record<string, unknown>;
  findings: Record<string, unknown>[];
  coverage: Record<string, unknown>;
}

/** Accepted evidence may still describe partial or unknown source coverage. */
export interface AuditEvidence {
  checkpoint?: ScanDraftInput;
  accepted?: ScanDraftInput;
}

export type AuditOutcome<Execution> = AuditEvidence &
  (
    | { status: "accepted"; execution: Execution; accepted: ScanDraftInput }
    | { status: "checkpoint"; execution: Execution }
  );

/** One attempt; enclosing callers own retries and public completion. */
export async function runAcceptedAudit<Execution>(input: {
  signal: AbortSignal;
  execute: () => Promise<Execution>;
  accept: (execution: Execution) => Promise<AuditEvidence>;
}): Promise<AuditOutcome<Execution>> {
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
export function auditEvidence(checkpoint: ScanDraftInput): AuditEvidence {
  return checkpoint.complete === false
    ? { checkpoint }
    : { checkpoint, accepted: checkpoint };
}
