import { createInterface } from "node:readline";
import { type Readable, Writable } from "node:stream";
import { z } from "incur";
import { deduplicateRecords, type DeduplicateRecordsInput } from "./records.js";

const rpcId = z.union([z.string(), z.number().int()]);
const request = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: rpcId,
    method: z.literal("run"),
    params: z.unknown(),
  })
  .strict();
const cancellation = z
  .object({
    jsonrpc: z.literal("2.0"),
    method: z.literal("cancel"),
    params: z.object({ id: rpcId }).strict(),
  })
  .strict();
const response = z.union([
  z
    .object({ jsonrpc: z.literal("2.0"), id: rpcId, result: z.unknown() })
    .strict()
    .refine((value) => Object.hasOwn(value, "result")),
  z
    .object({
      jsonrpc: z.literal("2.0"),
      id: rpcId,
      error: z
        .object({
          code: z.number().int(),
          message: z.string(),
          data: z.unknown().optional(),
        })
        .strict(),
    })
    .strict(),
]);
type Output = Pick<NodeJS.WriteStream, "write"> & {
  on?(event: "error", listener: (error: Error) => void): unknown;
  off?(event: "error", listener: (error: Error) => void): unknown;
};

/** One bidirectional run. Stdout contains JSON-RPC envelopes only. */
export async function runRecordsProtocol(
  input: Readable,
  output: Output,
  signal?: AbortSignal,
): Promise<number> {
  const controller = new AbortController();
  let runId: string | number | undefined;
  let finished = false;
  let pending:
    | { id: string; resolve(value: unknown): void; reject(error: Error): void }
    | undefined;
  let complete!: (code: number) => void;
  const completion = new Promise<number>((resolve) => {
    complete = resolve;
  });
  const lines = createInterface({
    input,
    crlfDelay: Infinity,
    terminal: false,
  });
  const send = async (message: object) => {
    const line = `${JSON.stringify(message)}\n`;
    if (output instanceof Writable) {
      await new Promise<void>((resolve, reject) =>
        output.write(line, (error) => (error ? reject(error) : resolve())),
      );
    } else {
      output.write(line);
    }
  };
  const fail = (code: number, message: string, canWrite = true) => {
    if (finished) return;
    // Stop scheduling before notifying the host; a disconnect cannot become uniqueness.
    finished = true;
    controller.abort(new Error(message));
    pending?.reject(new Error(message));
    pending = undefined;
    const flushed = canWrite
      ? send({ jsonrpc: "2.0", id: runId ?? null, error: { code, message } })
      : Promise.resolve();
    void flushed.catch(() => undefined).then(() => complete(2));
  };
  const disconnected = () =>
    fail(-32000, "Host disconnected before the run completed.");
  const inputError = (error: Error) => fail(-32000, error.message);
  const outputError = (error: Error) => fail(-32000, error.message, false);
  const canceled = () => {
    if (finished) {
      // A terminal response may be blocked on a host that stopped reading.
      if (output instanceof Writable) output.destroy();
      complete(2);
    } else {
      fail(-32800, "Deduplication canceled.");
    }
  };
  input.on("error", inputError);
  input.on("close", disconnected);
  if (output instanceof Writable) output.on("close", disconnected);
  lines.on("close", disconnected);
  lines.on("error", inputError);
  output.on?.("error", outputError);
  signal?.addEventListener("abort", canceled, { once: true });
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
    if (finished) return;
    const run = request.safeParse(message);
    if (run.success) {
      if (runId !== undefined) {
        fail(-32600, "Only one run request is allowed.");
        return;
      }
      runId = run.data.id;
      void deduplicateRecords(run.data.params as DeduplicateRecordsInput, {
        signal: controller.signal,
        reviewRunner: {
          run(review) {
            if (finished) return Promise.reject(controller.signal.reason);
            return new Promise((resolve, reject) => {
              pending = { id: review.requestId, resolve, reject };
              void send({
                jsonrpc: "2.0",
                id: review.requestId,
                method: "review.run",
                params: review,
              }).catch(outputError);
            });
          },
        },
      }).then(
        async (result) => {
          if (finished) return;
          finished = true;
          try {
            await send({ jsonrpc: "2.0", id: runId, result });
            complete(result.status === "completed" ? 0 : 1);
          } catch {
            complete(2);
          }
        },
        (error: unknown) => {
          fail(
            -32602,
            error instanceof Error ? error.message : "Invalid run parameters.",
          );
        },
      );
      return;
    }
    const reply = response.safeParse(message);
    if (!reply.success || !pending || reply.data.id !== pending.id) {
      fail(-32600, "Malformed, unexpected, or mismatched review response.");
      return;
    }
    const review = pending;
    pending = undefined;
    if ("error" in reply.data)
      review.reject(new Error(reply.data.error.message));
    else review.resolve(reply.data.result);
  });
  if (signal?.aborted) canceled();
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
    signal?.removeEventListener("abort", canceled);
  }
}
