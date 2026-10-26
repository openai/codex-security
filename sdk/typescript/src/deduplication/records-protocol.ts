import type { Readable } from "node:stream";
import { z } from "zod";
import { HostResponseError, runHostProtocol } from "../host-protocol.js";
import { InvalidDeduplicationDecision } from "../errors.js";
import {
  runDeduplicateRecords,
  type DeduplicateRecordsInput,
} from "./records.js";

const hostFailure = z.object({
  feedbackVersion: z.literal(1),
  kind: z.enum([
    "cancelled",
    "permanent_rejection",
    "transient_rejection",
    "invalid_decisions",
    "internal_failure",
    "uncertain_acceptance",
  ]),
});
const feedbackPeer = hostFailure.extend({ kind: z.string() });
const serializableFailure = hostFailure.extend({
  message: z.string(),
  host: z.object({ code: z.number() }).optional(),
});

function failure(error: unknown) {
  const host = error instanceof HostResponseError ? error : undefined;
  return {
    feedbackVersion: 1,
    kind: host
      ? (hostFailure.safeParse(host.data).data?.kind ?? "uncertain_acceptance")
      : error instanceof InvalidDeduplicationDecision
        ? "invalid_decisions"
        : "internal_failure",
    message: error instanceof Error ? error.message : "Review failed.",
    ...(host && { host: { code: host.code, data: host.data } }),
  };
}

export async function runRecordsProtocol(
  input: Readable,
  output: Parameters<typeof runHostProtocol>[1],
  signal?: AbortSignal,
  lineFeedOnly = false,
): Promise<number> {
  let feedbackEnabled = false;
  return await runHostProtocol(
    input,
    output,
    {
      label: "Deduplication",
      requestMethod: "review.run",
      lineFeedOnly,
      errorData: (error) => (feedbackEnabled ? failure(error) : undefined),
      flushError: () => feedbackEnabled,
      serializationErrorData(data, brief) {
        const failure = serializableFailure.safeParse(data).data;
        if (failure && brief) failure.message = failure.message.slice(0, 4096);
        return failure;
      },
      onFeedback: () => {
        feedbackEnabled = true;
      },
      isFeedbackError: (data) => feedbackPeer.safeParse(data).success,
      transportErrorData(code, message, outstanding) {
        if (
          !feedbackEnabled &&
          !(lineFeedOnly && code === -32000 && outstanding)
        )
          return undefined;
        const kind =
          code === -32800
            ? "cancelled"
            : outstanding
              ? "uncertain_acceptance"
              : "internal_failure";
        return { feedbackVersion: 1, kind, message };
      },
      errorCode(error) {
        if (!feedbackEnabled || error instanceof InvalidDeduplicationDecision)
          return -32602;
        return error instanceof HostResponseError ? error.code : -32603;
      },
      run: (params, execute, signal) =>
        runDeduplicateRecords(
          params as DeduplicateRecordsInput,
          {
            signal,
            reviewRunner: {
              run(request, options) {
                const validate = (candidate: unknown) => {
                  try {
                    options!.validate!(candidate);
                    return { valid: true };
                  } catch (error) {
                    if (!(error instanceof InvalidDeduplicationDecision))
                      throw error;
                    return { valid: false, failure: failure(error) };
                  }
                };
                return execute(request.requestId, request, undefined, validate);
              },
            },
          },
          () => feedbackEnabled,
        ),
    },
    signal,
  );
}
