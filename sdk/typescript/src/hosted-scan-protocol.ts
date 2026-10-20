import type { Readable } from "node:stream";
import { runHostProtocol } from "./host-protocol.js";
import {
  type ScanExecutionRequest,
  type HostedScanInput,
  HostedScanPreparationError,
  runHostedScan,
} from "./hosted-scan.js";
import {
  ScanExecutionEventSchema,
  ScanExecutionResultSchema,
} from "./scan-executor.js";

/** The host supplies inference; repository evidence and report writing stay in the CLI. */
export type HostedOwnerInferenceRequest = Pick<
  ScanExecutionRequest,
  | "version"
  | "requestId"
  | "scanId"
  | "repository"
  | "revision"
  | "scope"
  | "identity"
  | "model"
  | "reasoningEffort"
  | "prompt"
> & { schema: unknown };

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
      run: async (params, execute, signal, onEvent) => {
        let execution: ScanExecutionRequest | undefined;
        let ownerSequence = 0;
        return await runHostedScan(params as HostedScanInput, {
          signal,
          onEvent,
          executor: {
            run: async (request, options) => {
              execution = request;
              return ScanExecutionResultSchema.parse(
                await execute(request.requestId, request, (event) => {
                  const parsed = ScanExecutionEventSchema.safeParse(event);
                  if (parsed.success) options.onEvent?.(parsed.data);
                }),
              );
            },
          },
          ownerCodex: {
            startThread(options) {
              return {
                async run(prompt, runOptions) {
                  if (!execution)
                    throw new Error(
                      "Owner inference requires a scan execution.",
                    );
                  const request: HostedOwnerInferenceRequest = {
                    version: execution.version,
                    requestId: `owner-${++ownerSequence}`,
                    scanId: execution.scanId,
                    repository: execution.repository,
                    revision: execution.revision,
                    scope: execution.scope,
                    identity: execution.identity,
                    model: options.model ?? execution.model,
                    reasoningEffort:
                      options.modelReasoningEffort ?? execution.reasoningEffort,
                    prompt,
                    schema: runOptions.outputSchema,
                  };
                  const decision = await execute(
                    request.requestId,
                    request,
                    undefined,
                    {
                      requestMethod: "owner.infer",
                      cancelMethod: "owner.cancel",
                    },
                  );
                  return { finalResponse: JSON.stringify(decision) };
                },
              };
            },
          },
        });
      },
    },
    signal,
  );
}
