export const FINDINGS_ERROR_STATUS = {
  invalid_request: 400,
  finding_conflict: 409,
  embedding_unavailable: 503,
  embedding_failed: 502,
  finding_not_indexed: 404,
  not_found: 404,
  internal_error: 500,
} as const;

export type FindingsErrorCode = keyof typeof FINDINGS_ERROR_STATUS;

export interface FindingsErrorResponse {
  error: FindingsErrorCode;
  message?: string;
}

export function parseFindingsErrorResponse(
  value: unknown,
): FindingsErrorResponse | undefined {
  if (
    typeof value !== "object" ||
    value === null ||
    !("error" in value) ||
    typeof value.error !== "string" ||
    !Object.hasOwn(FINDINGS_ERROR_STATUS, value.error) ||
    ("message" in value && typeof value.message !== "string")
  ) {
    return undefined;
  }
  return {
    error: value.error as FindingsErrorCode,
    ...("message" in value ? { message: value.message as string } : {}),
  };
}
