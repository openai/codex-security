import type { DeduplicationReviewStage } from "../errors.js";

export interface DeduplicationReviewAttribution {
  version: 1;
  beneficiaryObservationIds: string[];
  contextObservationIds: string[];
}

/** Serializable review contract shared by local and host-provided execution. */
export interface DeduplicationReviewRequest {
  requestId: string;
  /** Present in records mode; IDs identify this review's host observations. */
  attribution?: DeduplicationReviewAttribution;
  stage: DeduplicationReviewStage;
  model: string;
  effort: string;
  prompt: string;
  trustedInstructions: string;
  /** Tool submission contract, not an OpenAI strict Structured Outputs schema. */
  schema: unknown;
  /** SAME.mergedFinding must satisfy this additional schema. */
  findingSchema: unknown;
}

/** Execute one review. Codex Security validates the returned structured answer. */
export interface DeduplicationReviewRunner {
  run(
    request: DeduplicationReviewRequest,
    options?: { signal?: AbortSignal },
  ): Promise<unknown>;
}
