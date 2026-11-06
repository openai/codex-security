import type { Readable } from "node:stream";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { runHostProtocol } from "./host-protocol.js";
import {
  type HostedScanInput,
  HostedScanPreparationError,
  runHostedScanInternal,
} from "./hosted-scan.js";
import {
  ScanExecutionEventSchema,
  ScanExecutionResultSchema,
} from "./scan-executor.js";

export async function runHostedScanProtocol(
  input: Readable,
  output: Parameters<typeof runHostProtocol>[1],
  signal?: AbortSignal,
): Promise<number> {
  return await runHostProtocol(
    input,
    output,
    {
      label: "Scan",
      requestMethod: "execution.run",
      awaitCancellationReceipt: true,
      allowConcurrentExecutions: (params) =>
        typeof params === "object" &&
        params !== null &&
        "version" in params &&
        params.version === 3,
      errorData: (error) =>
        error instanceof HostedScanPreparationError
          ? { reason: error.reason }
          : undefined,
      run: async (params, execute, signal, onEvent) =>
        await runHostedScanInternal("cli", params as HostedScanInput, {
          signal,
          onEvent,
          executor: {
            run: async (request, options) =>
              ScanExecutionResultSchema.parse(
                await execute(
                  request.requestId,
                  request,
                  (event) => {
                    const parsed = ScanExecutionEventSchema.safeParse(event);
                    if (parsed.success) options.onEvent?.(parsed.data);
                  },
                  undefined,
                  options.signal,
                ),
              ),
            release: async (sessionId) => {
              const released = z.strictObject({
                status: z.literal("completed"),
                sessionId: z.literal(sessionId),
              });
              released.parse(
                await execute(
                  randomUUID(),
                  { version: 3, sessionId },
                  undefined,
                  "execution.release",
                ),
              );
            },
          },
        }),
    },
    signal,
  );
}
