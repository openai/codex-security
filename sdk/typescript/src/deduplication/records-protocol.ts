import type { Readable } from "node:stream";
import { runHostProtocol } from "../host-protocol.js";
import { deduplicateRecords, type DeduplicateRecordsInput } from "./records.js";

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
            run: (request) => execute(request.requestId, request),
          },
        }),
    },
    signal,
  );
}
