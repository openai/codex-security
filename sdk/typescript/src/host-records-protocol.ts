import { randomUUID } from "node:crypto";
import type { Readable } from "node:stream";
import { z } from "zod";
import {
  classifySeverityRecords,
  type ClassifySeverityRecordsInput,
} from "./classify-severity-records.js";
import { missingSubmissionPrompt } from "./deduplication/deduplication-prompts.js";
import {
  runRecords,
  type DeduplicateRecordsInput,
} from "./deduplication/records.js";
import type { DeduplicationReviewRequest } from "./deduplication/review.js";
import {
  PendingReviewSubmission,
  runHostProtocol,
  type HostExecute,
} from "./host-protocol.js";
import {
  validateRecords,
  type ValidateRecordsInput,
} from "./validation-records.js";

const missingSubmission = z.strictObject({
  status: z.literal("missing_submission"),
});
const released = z.strictObject({ status: z.literal("released") });

async function runDeduplicationReview(
  request: DeduplicationReviewRequest,
  validateSubmission: (value: unknown) => void,
  execute: HostExecute,
) {
  const first = await execute(request.requestId, {
    ...request,
    supportsContinuation: true,
    supportsSubmissionValidation: true,
  });
  let rejection: string | undefined;
  if (first instanceof PendingReviewSubmission) {
    try {
      validateSubmission(first.submission);
    } catch (error) {
      rejection =
        error instanceof Error ? error.message : "Invalid submission.";
    }
    if (rejection === undefined) {
      const receipt = await execute(
        randomUUID(),
        { requestId: request.requestId },
        undefined,
        "review.release",
      );
      released.parse(receipt);
      return first.submission;
    }
  } else if (!missingSubmission.safeParse(first).success) return first;
  const result = await execute(
    randomUUID(),
    {
      requestId: request.requestId,
      prompt: missingSubmissionPrompt(rejection),
    },
    undefined,
    "review.continue",
  );
  if (missingSubmission.safeParse(result).success)
    throw new Error(
      "Review ended without a terminal submission after correction.",
    );
  return result;
}

const labels = {
  dedupe: "Deduplication",
  validate: "Validation",
  "classify-severity": "Records processing",
};

/** Adapt record reviews to the shared host transport without replaying work. */
export function runHostRecordsProtocol(
  command: keyof typeof labels,
  input: Readable,
  output: Parameters<typeof runHostProtocol>[1],
  options: {
    signal?: AbortSignal;
    classificationRuns?: number;
    environment?: NodeJS.ProcessEnv;
  } = {},
): Promise<number> {
  return runHostProtocol(
    input,
    output,
    {
      label: labels[command],
      requestMethod: "review.run",
      run: async (params, execute, signal) => {
        if (command === "dedupe")
          return runRecords(
            params as DeduplicateRecordsInput,
            (request, validate) =>
              runDeduplicationReview(request, validate, execute),
            signal,
          );
        const reviewRunner = {
          run: (review: { requestId: string }) =>
            execute(review.requestId, review),
        };
        if (command === "validate")
          return {
            status: "completed",
            result: await validateRecords(params as ValidateRecordsInput, {
              signal,
              reviewRunner,
            }),
          };
        return classifySeverityRecords(params as ClassifySeverityRecordsInput, {
          classificationRuns: options.classificationRuns,
          environment: options.environment,
          signal,
          reviewRunner,
        });
      },
    },
    options.signal,
  );
}
