import { randomUUID } from "node:crypto";
import type { Readable } from "node:stream";
import { z } from "zod";
import { missingSubmissionPrompt } from "./deduplication-prompts.js";
import { PendingReviewSubmission, runHostProtocol } from "../host-protocol.js";
import { runRecords, type DeduplicateRecordsInput } from "./records.js";

const missingSubmission = z.strictObject({
  status: z.literal("missing_submission"),
});
const released = z.strictObject({ status: z.literal("released") });

export async function runRecordsProtocol(
  input: Readable,
  output: Parameters<typeof runHostProtocol>[1],
  signal?: AbortSignal,
): Promise<number> {
  return await runHostProtocol(
    input,
    output,
    {
      label: "Deduplication",
      requestMethod: "review.run",
      run: (params, execute, signal) =>
        runRecords(
          params as DeduplicateRecordsInput,
          async (request, validateSubmission) => {
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
                  error instanceof Error
                    ? error.message
                    : "Invalid submission.";
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
            } else if (!missingSubmission.safeParse(first).success)
              return first;
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
          },
          signal,
        ),
    },
    signal,
  );
}
