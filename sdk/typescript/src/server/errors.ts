export class FindingsError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "finding_conflict"
      | "embedding_unavailable"
      | "embedding_failed"
      | "deduplication_failed",
    message: string,
  ) {
    super(message);
  }
}
