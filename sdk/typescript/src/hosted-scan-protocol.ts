import type { Readable } from "node:stream";
import { runHostProtocol } from "./host-protocol.js";
import {
  type HostedScanInput,
  HostedScanPreparationError,
  runHostedScan,
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
      errorData: (error) =>
        error instanceof HostedScanPreparationError
          ? { reason: error.reason }
          : undefined,
      run: async (params, execute, signal, onEvent) =>
        await runHostedScan(params as HostedScanInput, {
          signal,
          onEvent,
          executor: {
            run: async (request, options) =>
              ScanExecutionResultSchema.parse(
                await execute(request.requestId, request, (event) => {
                  const parsed = ScanExecutionEventSchema.safeParse(event);
                  if (parsed.success) options.onEvent?.(parsed.data);
                }),
              ),
          },
        }),
    },
    signal,
  );
}
