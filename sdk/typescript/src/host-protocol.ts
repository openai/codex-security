import { createInterface } from "node:readline";
import { type Readable, Writable } from "node:stream";
import { z } from "incur";

const rpcId = z.union([z.string(), z.number().int()]);
const request = z.strictObject({
  jsonrpc: z.literal("2.0"),
  id: rpcId,
  method: z.literal("run"),
  params: z.unknown(),
});
const cancellation = z.strictObject({
  jsonrpc: z.literal("2.0"),
  method: z.literal("cancel"),
  params: z.strictObject({ id: rpcId }),
});
const progress = z.strictObject({
  jsonrpc: z.literal("2.0"),
  method: z.literal("execution.progress"),
  params: z.strictObject({ requestId: z.string(), event: z.unknown() }),
});
const response = z.union([
  z.strictObject({ jsonrpc: z.literal("2.0"), id: rpcId, result: z.unknown() }),
  z.strictObject({
    jsonrpc: z.literal("2.0"),
    id: rpcId,
    error: z.strictObject({
      code: z.number().int(),
      message: z.string(),
      data: z.unknown().optional(),
    }),
  }),
]);
type Output = Pick<NodeJS.WriteStream, "write"> & {
  on?(event: "error", listener: (error: Error) => void): unknown;
  off?(event: "error", listener: (error: Error) => void): unknown;
};
type Execute = (
  id: string,
  request: unknown,
  onProgress?: (event: unknown) => void,
) => Promise<unknown>;

/** One bidirectional run, shared with dedupe. This transport never replays. */
export async function runHostProtocol(
  input: Readable,
  output: Output,
  operation: {
    label: string;
    requestMethod: string;
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
  let pending:
    | {
        id: string;
        resolve(value: unknown): void;
        reject(error: Error): void;
        onProgress?: (event: unknown) => void;
      }
    | undefined;
  const { promise: completion, resolve: complete } =
    Promise.withResolvers<number>();
  const stopOutput = (code: number) => {
    if (output instanceof Writable) output.destroy();
    complete(code);
  };
  const lines = createInterface({
    input,
    crlfDelay: Infinity,
    terminal: false,
  });
  const send = async (message: object) => {
    const line = `${JSON.stringify(message)}\n`;
    if (output instanceof Writable) {
      if (output.destroyed) throw new Error("Host output is closed.");
      await new Promise<void>((resolve, reject) => {
        let settled = false;
        const settle = (error?: Error | null) => {
          if (settled) return;
          settled = true;
          output.off("close", closed);
          error ? reject(error) : resolve();
        };
        const closed = () =>
          settle(new Error("Host output closed during write."));
        output.once("close", closed);
        output.write(line, settle);
      });
    } else output.write(line);
  };
  const fail = (
    code: number,
    message: string,
    canWrite = true,
    data?: object,
  ) => {
    if (terminalCode !== undefined) return;
    terminalCode = 2;
    controller.abort(new Error(message));
    pending?.reject(new Error(message));
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
    // A peer can close stdin after reading the terminal response but before its
    // write callback runs. Preserve the outcome without waiting on that peer.
    if (terminalCode !== undefined) stopOutput(terminalCode);
    else fail(-32000, "Host disconnected before the run completed.");
  };
  const inputError = (error: Error) => fail(-32000, error.message);
  const outputError = (error: Error) => fail(-32000, error.message, false);
  const interrupted = () => {
    if (terminalCode !== undefined) stopOutput(2);
    else fail(-32800, `${operation.label} canceled.`);
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
  if (output instanceof Writable) output.on("close", disconnected);
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
          (id, params, onProgress) => {
            if (terminalCode !== undefined || controller.signal.aborted)
              return Promise.reject(controller.signal.reason);
            if (pending)
              return Promise.reject(new Error("Execution is already pending."));
            return new Promise((resolve, reject) => {
              pending = { id, resolve, reject, onProgress };
              void send({
                jsonrpc: "2.0",
                id,
                method: operation.requestMethod,
                params,
              }).catch(outputError);
            });
          },
          controller.signal,
          (event) => {
            if (terminalCode === undefined)
              void send({
                jsonrpc: "2.0",
                method: "scan.progress",
                params: { id: runId, event },
              }).catch(outputError);
          },
        )
        .then(
          async (result) => {
            if (terminalCode !== undefined) return;
            terminalCode = result.status === "completed" ? 0 : 1;
            try {
              await send({ jsonrpc: "2.0", id: runId, result });
              complete(terminalCode);
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
    if (!reply.success || !pending || reply.data.id !== pending.id) {
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
      output.removeListener("close", disconnected);
    output.off?.("error", outputError);
    signal?.removeEventListener("abort", interrupted);
  }
}
