export class FindingsError extends Error {
  constructor(
    readonly code:
      | "invalid_request"
      | "finding_conflict"
      | "embedding_unavailable"
      | "embedding_failed"
      | "finding_not_indexed",
    message: string,
  ) {
    super(message);
  }
}
