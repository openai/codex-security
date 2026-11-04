import { isCodexNonRetryableFailure } from "../../../../../sdk/typescript/src/errors.js";

/** A confirmed terminal worker failure stops the scan without retries. */
export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}

export function codexWorkerTurnError(message: string): Error {
  return isCodexNonRetryableFailure(message)
    ? new DeepScanNonRetryableError(message)
    : new Error(message);
}
