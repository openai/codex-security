import { randomUUID } from "node:crypto";
import type { Readable } from "node:stream";
import { z } from "zod";
import { missingSubmissionPrompt } from "./deduplication-prompts.js";
import { runHostProtocol } from "../host-protocol.js";
import { deduplicateRecords, type DeduplicateRecordsInput } from "./records.js";

const missingSubmission = z.strictObject({
  status: z.literal("missing_submission"),
});

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
        deduplicateRecords(params as DeduplicateRecordsInput, {
          signal,
          reviewRunner: {
            async run(request) {
              const first = await execute(request.requestId, {
                ...request,
                supportsContinuation: true,
              });
              if (!missingSubmission.safeParse(first).success) return first;
              const result = await execute(
                randomUUID(),
                {
                  requestId: request.requestId,
                  prompt: missingSubmissionPrompt(),
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
          },
        }),
    },
    signal,
  );
}
