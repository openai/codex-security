/** Explicitly opt a confirmed permission prerequisite failure out of retries. */
export class DeepScanNonRetryableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeepScanNonRetryableError";
  }
}
