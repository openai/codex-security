import {
  FINDINGS_ERROR_STATUS,
  type FindingsErrorCode,
  type FindingsErrorResponse,
} from "../findings-errors.js";

export class FindingsError extends Error {
  constructor(
    readonly code: FindingsErrorCode,
    message: string,
  ) {
    super(message);
  }

  get status(): number {
    return FINDINGS_ERROR_STATUS[this.code];
  }

  toJSON(): FindingsErrorResponse {
    return { error: this.code, message: this.message };
  }
}
