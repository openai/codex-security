import type { Readable } from "node:stream";
import { runHostProtocol, type TakeHostDiagnostics } from "./host-protocol.js";

export type RecordsProtocolOutput = Parameters<typeof runHostProtocol>[1];

/** Adapt record reviews to the shared host transport without replaying work. */
export function runHostRecordsProtocol<
  Review extends { requestId: string },
  Result extends { status: "completed" | "unresolved" },
>(
  input: Readable,
  output: RecordsProtocolOutput,
  run: (
    input: unknown,
    options: {
      signal: AbortSignal;
      reviewRunner: { run(review: Review): Promise<unknown> };
    },
  ) => Promise<Result>,
  signal?: AbortSignal,
  takeDiagnostics?: TakeHostDiagnostics,
): Promise<number> {
  return runHostProtocol(
    input,
    output,
    {
      label: "Records processing",
      requestMethod: "review.run",
      takeDiagnostics,
      run: (params, execute, signal) =>
        run(params, {
          signal,
          reviewRunner: {
            run: (review) => execute(review.requestId, review),
          },
        }),
    },
    signal,
  );
}
