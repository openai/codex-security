/** Explicitly opt a confirmed permission prerequisite failure out of retries. */
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

// Codex exec exposes only text for failed turns. Match its native quota messages here.
export function codexWorkerTurnError(message: string): Error {
  if (
    USAGE_LIMIT_MESSAGES.has(message) ||
    message.startsWith("You’ve hit your usage limit.") ||
    message.startsWith("You’ve hit your usage limit for ")
  ) {
    return new DeepScanNonRetryableError(message);
  }
  return new Error(message);
}
