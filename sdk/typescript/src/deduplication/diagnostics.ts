import type { DeduplicationReviewStage } from "../errors.js";

/** Best-effort diagnostics; never written to the dedupe result's JSON stream. */
export interface DeduplicationDiagnostic {
  event: string;
  timestamp: string;
  reviewId?: string;
  stage?: DeduplicationReviewStage;
  model?: string;
  effort?: string;
  attempt?: number;
  message?: string;
  /** Native thread/turn/item identifiers, usage, or diagnostic details. */
  details?: Readonly<Record<string, unknown>>;
}

export type DeduplicationDiagnosticObserver = (
  diagnostic: DeduplicationDiagnostic,
) => void;

export function emitDiagnostic(
  observer: DeduplicationDiagnosticObserver | undefined,
  diagnostic: Omit<DeduplicationDiagnostic, "timestamp">,
): void {
  try {
    void Promise.resolve(
      observer?.({ timestamp: new Date().toISOString(), ...diagnostic }),
    ).catch(() => {});
  } catch {
    // Optional diagnostics must not interrupt a review or discard its result.
  }
}
