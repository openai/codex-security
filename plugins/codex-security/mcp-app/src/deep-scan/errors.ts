import { isCodexUsageLimit } from "../../../../../sdk/typescript/src/errors.js";

/** Explicitly opt a confirmed permission prerequisite failure out of retries. */
export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}

export function codexWorkerTurnError(message: string): Error {
  return isCodexUsageLimit(message)
    ? new DeepScanNonRetryableError(message)
    : new Error(message);
}
