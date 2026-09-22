import { createHash } from "node:crypto";

const MAX_PERSISTED_ERROR_LENGTH = 2_400;

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

/** Retire this worker without retrying its conversation; the scan may replace it. */
export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}

/** Opt in only at a producer that has confirmed a scan-wide prerequisite failed. */
export class DeepScanFatalError extends DeepScanNonRetryableError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanFatalError";
  }
}

/** Keep SQLite's bounded diagnostic useful while the manifest retains the full error. */
export function boundedDeepScanErrorMessage(error: unknown): string {
  return boundedDeepScanErrorText(
    deepScanErrorMessage(error),
    MAX_PERSISTED_ERROR_LENGTH,
  );
}

export function boundedDeepScanErrorPair(
  primary: unknown,
  separator: string,
  secondary: unknown,
): string {
  const primaryMessage = deepScanErrorMessage(primary);
  const secondaryMessage = deepScanErrorMessage(secondary);
  const available = MAX_PERSISTED_ERROR_LENGTH - separator.length;
  const balancedBudget = Math.floor(available / 2);
  let primaryBudget = Math.min(primaryMessage.length, balancedBudget);
  const secondaryBudget = Math.min(
    secondaryMessage.length,
    available - primaryBudget,
  );
  primaryBudget = Math.min(primaryMessage.length, available - secondaryBudget);
  return [
    boundedDeepScanErrorText(primaryMessage, primaryBudget),
    separator,
    boundedDeepScanErrorText(secondaryMessage, secondaryBudget),
  ].join("");
}

function deepScanErrorMessage(error: unknown): string {
  return (
    (error instanceof Error ? error.message : String(error)).trim() ||
    "Codex Security Deep Scan failed."
  );
}

function boundedDeepScanErrorText(message: string, maxLength: number): string {
  if (message.length <= maxLength) return message;
  const digest = createHash("sha256").update(message).digest("hex");
  const suffix = `\n...[truncated; sha256:${digest}]`;
  if (suffix.length >= maxLength) return message.slice(0, maxLength);
  return `${message.slice(0, maxLength - suffix.length)}${suffix}`;
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
  const message = error instanceof Error ? error.message : String(error);
  return CYBERSECURITY_POLICY_REFUSAL_MESSAGES.has(message);
}

export function classifyCodexWorkerError(error: unknown): Error {
  const normalized = error instanceof Error ? error : new Error(String(error));
  if (normalized instanceof DeepScanNonRetryableError) return normalized;
  if (isCodexCybersecurityPolicyRefusal(normalized)) {
    return new DeepScanNonRetryableError(normalized.message, {
      cause: normalized,
    });
  }
  // OS error codes alone do not establish a permanent failure, and SDK errors
  // can contain arbitrary command output. Leave both on the normal retry path
  // unless a producer explicitly identifies the failure as nonretryable.
  return normalized;
}
