import type { DeduplicationReviewStage } from "../errors.js";

/** Serializable review contract shared by local and host-provided execution. */
export interface DeduplicationReviewRequest {
  requestId: string;
  stage: DeduplicationReviewStage;
  model: string;
  effort: string;
  /** Assignment containing the supplied findings as untrusted evidence. */
  prompt: string;
  /** Review and source-access rules to install as trusted model instructions. */
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
