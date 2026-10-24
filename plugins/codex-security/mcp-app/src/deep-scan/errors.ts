import type { DeepScanRunState } from "./types.js";

const STALE_COORDINATOR_GENERATION_MESSAGE =
  "Deep Scan coordinator lease belongs to a newer generation.";

// The SDK currently exposes only the message for turn errors. Match known
// refusal messages exactly so repository output embedded in another error
// cannot be mistaken for a refusal.
const CYBERSECURITY_POLICY_REFUSAL_MESSAGES = new Set([
  "Request blocked by cyberPolicy.",
  "Request blocked by a safety policy violation.",
  "This content was flagged for possible cybersecurity risk.",
  "This content was flagged for potentially high-risk cyber activity.",
  "This request has been flagged for possible cybersecurity risk.",
  "This request has been flagged for potentially high-risk cyber activity.",
]);

/** Explicitly opt a confirmed scan-wide prerequisite failure out of retries. */
export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}

const USAGE_LIMIT_MESSAGES = new Set([
  "Quota exceeded. Check your plan and billing details.",
  "Your workspace is out of credits. Add credits to continue.",
  "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
  "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
  "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
]);

// Codex reports failures from remote context compaction with this prefix.
const REMOTE_COMPACTION_ERROR_PREFIX = "Error running remote compact task: ";

// Codex exec exposes only text for failed turns. Match its native quota messages here.
export function codexWorkerTurnError(message: string): Error {
  const reason = message.startsWith(REMOTE_COMPACTION_ERROR_PREFIX)
    ? message.slice(REMOTE_COMPACTION_ERROR_PREFIX.length)
    : message;
  if (
    USAGE_LIMIT_MESSAGES.has(reason) ||
    reason.startsWith("You’ve hit your usage limit.") ||
    reason.startsWith("You’ve hit your usage limit for ")
  ) {
    return new DeepScanNonRetryableError(message);
  }
  return new Error(message);
}

/** A store read confirmed that this coordinator no longer owns the scan. */
export class DeepScanOwnershipChangedError extends Error {
  constructor(
    readonly run: DeepScanRunState,
    cause: unknown,
  ) {
    super(errorMessage(cause), { cause });
    this.name = "DeepScanOwnershipChangedError";
  }
}

/** Only a store-confirmed state for this scan establishes ownership loss. */
export function confirmedOwnershipChange(
  error: unknown,
  scanId: string,
): DeepScanOwnershipChangedError | undefined {
  for (let cause = error; cause instanceof Error; cause = cause.cause) {
    if (
      cause instanceof DeepScanOwnershipChangedError &&
      cause.run.scanId === scanId
    )
      return cause;
  }
}

export function deepScanErrorMessage(error: unknown): string {
  return (
    (error instanceof Error ? error.message : String(error)).trim() ||
    "Codex Security Deep Scan failed."
  );
}

export function isStaleCoordinatorGenerationError(error: unknown): boolean {
  for (let current = error; current instanceof Error; current = current.cause) {
    if (current.message.includes(STALE_COORDINATOR_GENERATION_MESSAGE))
      return true;
  }
  return false;
}

/** A safety refusal retires the refused thread; it is not a broken scan. */
export function isCodexCybersecurityPolicyRefusal(error: unknown): boolean {
  return CYBERSECURITY_POLICY_REFUSAL_MESSAGES.has(errorMessage(error));
}

export function classifyCodexWorkerError(error: unknown): Error {
  // OS error codes alone do not establish a permanent failure, and SDK errors
  // can contain arbitrary command output. Leave both on the normal retry path
  // unless a producer explicitly identifies the failure as nonretryable. The
  // worker runner handles exact policy refusals without failing the scan.
  return error instanceof Error ? error : new Error(String(error));
}

export function abortError(reason?: unknown): Error {
  const error = new Error("Deep Scan worker was aborted.", { cause: reason });
  error.name = "AbortError";
  return error;
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function errorNameWithCode(error: Error): string {
  const code =
    "code" in error && typeof error.code === "string" ? error.code : undefined;
  return code ? `${error.name}:${code}` : error.name;
}
