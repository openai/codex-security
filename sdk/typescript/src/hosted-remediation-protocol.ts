import type { Readable } from "node:stream";
import { runHostProtocol } from "./host-protocol.js";
import {
  HostedRemediationPreparationError,
  runHostedRemediation,
  type HostedRemediationInput,
  type RemediationExecutionResult,
} from "./hosted-remediation.js";
import { isRecord } from "./record.js";

/** SDK launcher for prepared hosted checkouts; no local inference fallback. */
export async function runHostedRemediationProtocol(
  input: Readable,
  output: Parameters<typeof runHostProtocol>[1],
  signal?: AbortSignal,
): Promise<number> {
  return await runHostProtocol(
    input,
    output,
    {
      label: "Remediation",
      requestMethod: "execution.run",
      progressMethod: "remediation.progress",
      awaitCancellationReceipt: true,
      errorData: (error) =>
        error instanceof HostedRemediationPreparationError
          ? { reason: error.reason }
          : undefined,
      run: async (params, execute, signal, onEvent) =>
        await runHostedRemediation(params as HostedRemediationInput, {
          signal,
          onEvent,
          executor: {
            run: async (request, options) =>
              (await execute(request.requestId, request, (event) => {
                if (isRecord(event)) options.onEvent?.(event);
              })) as RemediationExecutionResult,
          },
        }),
    },
    signal,
  );
}
