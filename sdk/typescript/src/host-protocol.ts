import { createInterface } from "node:readline";
import { type Readable, Writable } from "node:stream";
import { z } from "zod";
import { HostProtocolError } from "./errors.js";

const cancellationCode = -32800;
const rpcId = z.union([z.string(), z.number().int()]);
const envelope = z.strictObject({ jsonrpc: z.literal("2.0") });
const request = envelope.extend({
  id: rpcId,
  method: z.literal("run"),
  params: z.unknown(),
});
const cancellation = envelope.extend({
  method: z.literal("cancel"),
  params: z.strictObject({ id: rpcId }),
});
const progress = envelope.extend({
  method: z.literal("execution.progress"),
  params: z.strictObject({ requestId: z.string(), event: z.unknown() }),
});
const success = envelope.extend({ id: rpcId, result: z.unknown() });
const acceptsPendingReview = z.object({
  supportsSubmissionValidation: z.literal(true),
});
const response = z.union([
  success,
  success.extend({ reviewPending: z.literal(true) }),
  envelope.extend({
    id: rpcId,
    error: z.strictObject({
      code: z.number().int(),
      message: z.string(),
      data: z.unknown().optional(),
    }),
  }),
]);
/** Only the host can mark the RPC envelope. Model-controlled results remain plain JSON. */
export class PendingReviewSubmission {
  constructor(readonly submission: unknown) {}
}
type Output = Pick<NodeJS.WriteStream, "write"> & {
  on?(event: "error", listener: (error: Error) => void): unknown;
  off?(event: "error", listener: (error: Error) => void): unknown;
};
type Execute = (
  id: string,
  request: unknown,
  onProgress?: (event: unknown) => void,
  method?: string,
) => Promise<unknown>;

/** One bidirectional run, shared with dedupe. This transport never replays. */
export async function runHostProtocol(
  input: Readable,
  output: Output,
  operation: {
    label: string;
    requestMethod: string;
    progressMethod?: string;
    /** Scan cancellation must retain the host's eventual receipt and usage. */
    awaitCancellationReceipt?: boolean;
    errorData?: (error: unknown) => object | undefined;
    run(
      params: unknown,
      execute: Execute,
      signal: AbortSignal,
      onProgress: (event: unknown) => void,
    ): Promise<{ status: string }>;
  },
  signal?: AbortSignal,
): Promise<number> {
  const controller = new AbortController();
  let runId: string | number | undefined;
  let terminalCode: number | undefined;
  let completed = false;
  let pending:
    | {
        id: string;
        acceptsPendingReview: boolean;
        resolve(value: unknown): void;
        reject(error: Error): void;
        onProgress?: (event: unknown) => void;
      }
    | undefined;
  const { promise: completion, resolve: resolveCompletion } =
    Promise.withResolvers<number>();
  const complete = (code: number) => {
    if (completed) return;
    completed = true;
    resolveCompletion(code);
  };
  const stopOutput = (code: number) => {
    if (completed) return;
    complete(code);
    if (output instanceof Writable) {
      // Native stdout can emit close repeatedly when destroy() is called from
      // its close listener. Detach before destroying, even before cleanup runs.
      output.off("close", outputClosed);
      output.destroy();
    }
  };
  const lines = createInterface({
    input,
    crlfDelay: Infinity,
    terminal: false,
  });
  const send = async (message: object, onFlushed?: () => void) => {
    const line = `${JSON.stringify(message)}\n`;
    if (output instanceof Writable) {
      if (output.destroyed) throw new Error("Host output is closed.");
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const settle = (error?: Error | null) => {
          if (settled) return;
          settled = true;
          output.off("close", closed);
          // Node can emit error/close before the rejected Promise is observed.
          // Record the failed write now, so the selected result cannot win.
          if (error) outputError(error);
          else onFlushed?.();
          error ? reject(error) : resolve();
        };
        const closed = () =>
          settle(new Error("Host output closed during write."));
        output.once("close", closed);
        output.write(line, settle);
      });
    } else {
      output.write(line);
      onFlushed?.();
    }
  };
  const fail = (
    code: number,
    message: string,
    canWrite = true,
    data?: object,
  ) => {
    if (completed) return;
    if (terminalCode !== undefined) {
      if (!canWrite) stopOutput(2);
      return;
    }
    terminalCode = 2;
    const reason =
      code === cancellationCode
        ? new Error(message)
        : new HostProtocolError(message);
    controller.abort(reason);
    pending?.reject(reason);
    pending = undefined;
    // A peer that stopped reading cannot receive an error. Unblock both the
    // request write and completion instead of waiting for a write callback.
    if (
      !canWrite ||
      (output instanceof Writable &&
        (output.writableLength > 0 || output.writableNeedDrain))
    ) {
      stopOutput(2);
      return;
    }
    void send({
      jsonrpc: "2.0",
      id: runId ?? null,
      error: { code, message, ...(data === undefined ? {} : { data }) },
    })
      .catch(() => undefined)
      .then(() => complete(2));
  };
  const disconnected = () => {
    // Stdin EOF does not close stdout. If a terminal response is already being
    // written, its callback decides whether delivery succeeded.
    if (terminalCode === undefined)
      fail(-32000, "Host disconnected before the run completed.");
  };
  const inputError = (error: Error) => fail(-32000, error.message);
  const outputError = (error: Error) => fail(-32000, error.message, false);
  const outputClosed = () => outputError(new Error("Host output is closed."));
  const interrupted = () => {
    if (terminalCode !== undefined) stopOutput(2);
    else fail(cancellationCode, `${operation.label} canceled.`);
  };
  const canceled = () => {
    if (
      !operation.awaitCancellationReceipt ||
      terminalCode !== undefined ||
      (output instanceof Writable &&
        (output.writableLength > 0 || output.writableNeedDrain))
    ) {
      interrupted();
      return;
    }
    if (controller.signal.aborted) return;
    controller.abort(new Error(`${operation.label} canceled.`));
    if (pending)
      void send({
        jsonrpc: "2.0",
        method: "execution.cancel",
        params: { requestId: pending.id },
      }).catch(outputError);
  };
  input.on("error", inputError);
  input.on("close", disconnected);
  if (output instanceof Writable) output.on("close", outputClosed);
  lines.on("close", disconnected);
  lines.on("error", inputError);
  output.on?.("error", outputError);
  signal?.addEventListener("abort", interrupted, { once: true });
  lines.on("line", (line) => {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      fail(-32700, "Invalid JSON.");
      return;
    }
    const cancel = cancellation.safeParse(message);
    if (cancel.success) {
      if (runId === undefined || cancel.data.params.id !== runId)
        fail(-32600, "Cancellation does not match the active run.");
      else canceled();
      return;
    }
    if (terminalCode !== undefined) return;
    const run = request.safeParse(message);
    if (run.success) {
      if (runId !== undefined) {
        fail(-32600, "Only one run request is allowed.");
        return;
      }
      runId = run.data.id;
      void operation
        .run(
          run.data.params,
          (id, params, onProgress, method = operation.requestMethod) => {
            if (terminalCode !== undefined || controller.signal.aborted)
              return Promise.reject(controller.signal.reason);
            if (pending)
              return Promise.reject(new Error("Execution is already pending."));
            return new Promise((resolve, reject) => {
              pending = {
                id,
                resolve,
                reject,
                onProgress,
                acceptsPendingReview:
                  method === "review.run" &&
                  acceptsPendingReview.safeParse(params).success,
              };
              void send({
                jsonrpc: "2.0",
                id,
                method,
                params,
              }).catch(outputError);
            });
          },
          controller.signal,
          (event) => {
            if (terminalCode === undefined)
              void send({
                jsonrpc: "2.0",
                method: operation.progressMethod ?? "scan.progress",
                params: { id: runId, event },
              }).catch(outputError);
          },
        )
        .then(
          async (result) => {
            if (terminalCode !== undefined) return;
            const code = result.status === "completed" ? 0 : 1;
            terminalCode = code;
            try {
              await send({ jsonrpc: "2.0", id: runId, result }, () =>
                complete(code),
              );
            } catch {
              complete(2);
            }
          },
          (error: unknown) =>
            fail(
              -32602,
              error instanceof Error
                ? error.message
                : "Invalid run parameters.",
              true,
              operation.errorData?.(error),
            ),
        );
      return;
    }
    const event = progress.safeParse(message);
    if (
      event.success &&
      operation.awaitCancellationReceipt &&
      pending &&
      event.data.params.requestId === pending.id
    ) {
      // Optional progress must never interrupt execution, including bad events
      // or host observer exceptions. Correlation still rejects stale messages.
      try {
        pending.onProgress?.(event.data.params.event);
      } catch {}
      return;
    }
    const reply = response.safeParse(message);
    if (
      !reply.success ||
      !pending ||
      reply.data.id !== pending.id ||
      ("reviewPending" in reply.data && !pending.acceptsPendingReview)
    ) {
      fail(
        -32600,
        `Malformed, unexpected, or mismatched ${operation.requestMethod === "review.run" ? "review" : "execution"} response.`,
      );
      return;
    }
    const execution = pending;
    pending = undefined;
    if ("error" in reply.data)
      execution.reject(new Error(reply.data.error.message));
    else if ("reviewPending" in reply.data)
      execution.resolve(new PendingReviewSubmission(reply.data.result));
    else execution.resolve(reply.data.result);
  });
  if (signal?.aborted) interrupted();
  if (input.readableEnded || input.destroyed) disconnected();
  try {
    return await completion;
  } finally {
    lines.removeAllListeners("line");
    lines.removeListener("close", disconnected);
    lines.removeListener("error", inputError);
    lines.close();
    input.pause();
    input.removeListener("error", inputError);
    input.removeListener("close", disconnected);
    if (output instanceof Writable)
      output.removeListener("close", outputClosed);
    output.off?.("error", outputError);
    signal?.removeEventListener("abort", interrupted);
  }
}
