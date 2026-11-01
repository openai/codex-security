import type { DeepScanRunState } from "./types.js";

const STALE_COORDINATOR_GENERATION_MESSAGE =
  "Deep Scan coordinator lease belongs to a newer generation.";

// The SDK currently exposes only the message for turn errors. Match known
// terminal messages exactly so repository output embedded in another error
// cannot be mistaken for a permanent failure.
const NON_RETRYABLE_TURN_MESSAGES = new Set([
  "Request blocked by cyberPolicy.",
  "Request blocked by a safety policy violation.",
  "This content was flagged for possible cybersecurity risk.",
  "This content was flagged for possible cybersecurity risk. If this seems wrong, try rephrasing your request. To get authorized for security work, join the Trusted Access for Cyber program: https://chatgpt.com/cyber",
  "This content was flagged for potentially high-risk cyber activity.",
  "This request has been flagged for possible cybersecurity risk.",
  "This request has been flagged for potentially high-risk cyber activity.",
  "Quota exceeded. Check your plan and billing details.",
  "Your workspace is out of credits. Add credits to continue.",
  "Your workspace is out of credits. Ask your workspace owner to refill in order to continue.",
  "You hit your spend cap set in your workspace. Increase your spend cap to continue.",
  "You hit your spend cap set by the owner of your workspace. Ask an owner to increase your spend cap to continue.",
]);

/** A confirmed terminal worker failure that stops the scan without retries. */
export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}

// Classify only terminal turn failures; diagnostics can contain arbitrary output.
export function codexWorkerTurnError(message: string): Error {
  if (
    NON_RETRYABLE_TURN_MESSAGES.has(message) ||
    message.startsWith("You’ve hit your usage limit.") ||
    message.startsWith("You’ve hit your usage limit for ")
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

export function classifyCodexWorkerError(error: unknown): Error {
  // OS error codes alone do not establish a permanent failure, and SDK errors
  // can contain arbitrary command output. Leave both on the normal retry path
  // unless a producer explicitly identifies the failure as nonretryable.
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
