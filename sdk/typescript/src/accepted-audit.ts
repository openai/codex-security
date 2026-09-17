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
export type AuditOutcome<Execution> = {
  execution: Execution;
  checkpoint?: ScanDraftInput;
} & (
  { status: "accepted"; accepted: ScanDraftInput } | { status: "checkpoint" }
);

/** One attempt; enclosing callers own retries and public completion. */
export async function runAcceptedAudit<Execution>(input: {
  signal: AbortSignal;
  execute: () => Promise<Execution>;
  accept: (execution: Execution) => Promise<ScanDraftInput | void>;
}): Promise<AuditOutcome<Execution>> {
  input.signal.throwIfAborted();
  const execution = await input.execute();
  input.signal.throwIfAborted();
  const checkpoint = await input.accept(execution);
  input.signal.throwIfAborted();
  if (checkpoint === undefined) return { execution, status: "checkpoint" };
  // Process completion alone does not accept an unfinished audit checkpoint.
  return checkpoint.complete === false
    ? { checkpoint, execution, status: "checkpoint" }
    : { checkpoint, execution, status: "accepted", accepted: checkpoint };
}
