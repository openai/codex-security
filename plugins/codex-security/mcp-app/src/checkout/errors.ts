/** Returns the original error message without altering its contents. */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function abortReason(signal: AbortSignal): unknown {
  return (
    signal.reason ??
    new DOMException("The operation was aborted.", "AbortError")
  );
}

/** Base error for Codex Security SDK failures. */
export class CodexSecurityError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class InvalidTargetError extends CodexSecurityError {}
