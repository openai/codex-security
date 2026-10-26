import { constants as bufferLimits } from "node:buffer";
import { StringDecoder } from "node:string_decoder";
import { type Readable, Writable } from "node:stream";
import { z } from "zod";

function guardLateDestroyError(stream: Readable | Writable | undefined) {
  if (!stream?.destroyed) return;
  // A destroyed stream can deliver its final error after protocol cleanup.
  const protect = () => {};
  stream.once("error", protect);
  observeDestroyed(stream, (closed) => closed.off("error", protect));
}

// A silent destroy may become observable as Node's last referenced handle closes.
const idleChecks = new Set<WeakRef<() => void>>();
let idleTimer: NodeJS.Timeout | undefined;
const checkIdle = () => {
  for (const observer of idleChecks) {
    const check = observer.deref();
    if (check) check();
    else idleChecks.delete(observer);
  }
  if (!idleChecks.size) {
    clearInterval(idleTimer);
    idleTimer = undefined;
    process.off("beforeExit", checkIdle);
  }
};
function observeDestroyed<T extends Readable | Writable>(
  input: T,
  settled: (stream: T) => void,
  onDestroy = false,
) {
  const stop = () => {
    input.off("close", check);
    const active = idleChecks.delete(observer);
    if (!idleChecks.size) checkIdle();
    return active;
  };
  const check = () => {
    if (!input.closed && !(onDestroy && input.destroyed)) return;
    if (stop()) settled(input);
  };
  const observer = new WeakRef(check);
  input.once("close", check);
  idleChecks.add(observer);
  if (!idleTimer) {
    idleTimer = setInterval(checkIdle, 1_000).unref();
    process.on("beforeExit", checkIdle);
  }
  setImmediate(checkIdle).unref();
  return stop;
}

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
const response = z.union([
  envelope.extend({ id: rpcId, result: z.unknown() }),
  envelope.extend({
    id: rpcId,
    error: z.strictObject({
      code: z.number().int(),
      message: z.string(),
      data: z.unknown().optional(),
    }),
  }),
]);
const validationEnvelope = z.object({
  id: rpcId,
  method: z.literal("review.validate"),
  params: z.object({ requestId: z.string() }).optional().catch(undefined),
});
const validationRequest = envelope.extend({
  id: rpcId,
  method: z.literal("review.validate"),
  params: z.strictObject({ requestId: z.string(), result: z.unknown() }),
});
const validationRequestEnvelope = validationRequest.extend({
  params: z.unknown().optional(),
});

/** A peer rejection, including the original machine-readable diagnostics. */
export class HostResponseError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
    this.name = "HostResponseError";
  }
}
type Output = Pick<NodeJS.WriteStream, "write"> & {
  on?(event: "error", listener: (error: Error) => void): unknown;
  off?(event: "error", listener: (error: Error) => void): unknown;
};
type Execute = (
  id: string,
  request: unknown,
  onProgress?: (event: unknown) => void,
  validate?: (value: unknown) => unknown,
) => Promise<unknown>;

/** One bidirectional run, shared with dedupe. This transport never replays. */
export async function runHostProtocol(
  input: Readable,
  output: Output,
  operation: {
    label: string;
    requestMethod: string;
    progressMethod?: string;
    lineFeedOnly?: boolean;
    /** Scan cancellation must retain the host's eventual receipt and usage. */
    awaitCancellationReceipt?: boolean;
    errorData?: (error: unknown) => object | undefined;
    errorCode?: (error: unknown) => number;
    serializationErrorData?: (
      data: object | undefined,
      brief?: boolean,
    ) => object | undefined;
    flushError?: () => boolean;
    transportErrorData?: (
      code: number,
      message: string,
      outstanding: boolean,
    ) => object | undefined;
    onFeedback?: () => void;
    isFeedbackError?: (data: unknown) => boolean;
    run(
      params: unknown,
      execute: Execute,
      signal: AbortSignal,
      onProgress: (event: unknown) => void,
    ): Promise<{ status: string }>;
  },
  signal?: AbortSignal,
): Promise<number> {
  const writeStream = output instanceof Writable ? output : undefined;
  const controller = new AbortController();
  let runId: string | number | undefined;
  let terminalCode: number | undefined;
  let terminalWriteStarted = false;
  let preserveTerminalOnEof = false;
  let preserveTerminalOnCancel = false;
  let completed = false;
  let validationAvailable = false;
  let validationWriting = false;
  const flushFeedback = () => operation.flushError?.() || validationWriting;
  const feedbackOutput = () => operation.lineFeedOnly || flushFeedback();
  const validationIds = new Set<string | number>();
  let validationFlush: Promise<void> | undefined;
  let queuedValidation: z.infer<typeof validationRequest> | undefined;
  let inputClosed = false;
  let buffered: string[] = [];
  let bufferedLength = 0;
  let waitingForLF = false;
  let negotiatedLF = false;
  const requiresLF = () =>
    operation.lineFeedOnly || waitingForLF || negotiatedLF;
  let peerReadReview = false;
  let inputFailure: Error | undefined;
  let destroyObserver: (() => void) | undefined;
  let outputObserver: (() => void) | undefined;
  const pendingOutputWrites = new Set<() => void>();
  let inputEvents: (() => void)[] | undefined;
  const receive = (event: () => void) => {
    if (inputEvents) return void inputEvents.push(event);
    inputEvents = [event];
    try {
      for (const next of inputEvents) next();
    } finally {
      inputEvents = undefined;
    }
  };
  const disconnectMessage = () =>
    inputFailure?.message ??
    input.errored?.message ??
    "Host disconnected before the run completed.";
  let settlingReply = false;
  let disconnectScheduled = false;
  const nonterminalWrites = new Set<Promise<void>>();
  let pending:
    | {
        id: string;
        resolve(value: unknown): void;
        reject(error: Error): void;
        onProgress?: (event: unknown) => void;
        validate?: (value: unknown) => unknown;
      }
    | undefined;
  type Ending = "lf" | "cr" | "eof";
  function feedbackFrame(ending: Ending, id: unknown, acceptCR = false) {
    if (pending && id === pending.id) peerReadReview = true;
    if (ending === "lf") negotiatedLF = true;
    const terminated =
      ending === "lf" || (acceptCR && ending === "cr" && !requiresLF());
    if (terminated) operation.onFeedback?.();
    else waitingForLF = true;
    return terminated;
  }
  const { promise: completion, resolve: resolveCompletion } =
    Promise.withResolvers<number>();
  const complete = (code: number) => {
    if (completed) return;
    completed = true;
    resolveCompletion(code);
  };
  const hasBackpressure = () =>
    Boolean(writeStream?.writableLength || writeStream?.writableNeedDrain);
  const hasBlockedWrite = () => nonterminalWrites.size > 0 && hasBackpressure();
  const stopOutput = (code: number) => {
    if (completed) return;
    complete(code);
    // Native stdout can emit close again when destroyed from its close listener.
    writeStream?.off("close", outputClosed).destroy();
  };
  const write = async (
    frame: string | object,
    onFlushed?: () => void,
    nonterminal = false,
  ) => {
    if (completed) return;
    const line =
      typeof frame === "string" ? frame : `${JSON.stringify(frame)}\n`;
    destroyObserver ??= observeDestroyed(input, inputClose);
    if (!writeStream) {
      output.write(line);
      onFlushed?.();
      return;
    }
    if (writeStream?.destroyed) throw new Error("Host output is closed.");
    const { promise, resolve, reject } = Promise.withResolvers<void>();
    const settle = (error?: Error | null) => {
      if (!pendingOutputWrites.delete(closed)) return;
      nonterminalWrites.delete(promise);
      if (error) {
        outputError(error);
        reject(error);
      } else {
        onFlushed?.();
        resolve();
      }
    };
    const closed = () => settle(new Error("Host output closed during write."));
    pendingOutputWrites.add(closed);
    if (nonterminal) nonterminalWrites.add(promise);
    outputObserver ??= observeDestroyed(writeStream, outputClosed, true);
    try {
      writeStream.write(line, settle);
    } catch (cause) {
      settle(cause instanceof Error ? cause : new Error(String(cause)));
    }
    return promise;
  };
  const fail = (
    code: number,
    message: string,
    {
      canWrite = true,
      data,
      validationId,
      flushBuffered = flushFeedback(),
    }: {
      canWrite?: boolean;
      data?: object | undefined;
      validationId?: string | number | undefined;
      flushBuffered?: boolean;
    } = {},
  ) => {
    if (completed) return;
    if (writeStream?.destroyed) canWrite = false;
    if (terminalCode !== undefined) {
      if (!canWrite) stopOutput(2);
      return;
    }
    terminalCode = 2;
    const receiptIds = new Set([queuedValidation?.id, validationId]);
    queuedValidation = undefined;
    data ??= operation.transportErrorData?.(
      code,
      message,
      pending !== undefined,
    );
    controller.abort(new Error(message));
    pending?.reject(new Error(message));
    pending = undefined;
    // A peer that stopped reading cannot receive an error. Unblock both the
    // request write and completion instead of waiting for a write callback.
    if (!canWrite || (!flushBuffered && hasBackpressure()))
      return stopOutput(2);
    void (async () => {
      const terminal = (id: string | number | null) => {
        const error = { code, message, data };
        const encode = () =>
          JSON.stringify({ jsonrpc: "2.0", id, error }) + "\n";
        for (const brief of [false, true]) {
          try {
            return encode();
          } catch (cause) {
            error.data = operation.serializationErrorData?.(data, brief);
            error.message = brief
              ? "Host could not serialize error data."
              : `${error.data ? "Host" : message}: could not serialize error data (${String(cause)}).`;
            error.data ??= operation.transportErrorData?.(
              -32603,
              error.message,
              false,
            );
            error.code = -32603;
          }
        }
        return encode();
      };
      preserveTerminalOnCancel =
        peerReadReview || validationWriting || settlingReply || code === -32800;
      preserveTerminalOnEof =
        preserveTerminalOnCancel ||
        (flushBuffered && !inputClosed) ||
        !hasBlockedWrite();
      if (feedbackOutput()) await Promise.all(nonterminalWrites);
      for (const id of receiptIds)
        if (id !== undefined && id !== runId) await write(terminal(id));
      terminalWriteStarted = true;
      await write(terminal(runId ?? null));
    })()
      .catch(() => undefined)
      .then(() => complete(2));
  };
  const failDisconnected = (flushBuffered: boolean) =>
    fail(-32000, disconnectMessage(), { flushBuffered });
  const disconnected = async (
    flushBuffered = validationWriting,
    observed = false,
  ) => {
    inputClosed = true;
    if (
      operation.onFeedback &&
      pending &&
      buffered.length &&
      !waitingForLF &&
      (!requiresLF() || hasBlockedWrite())
    ) {
      try {
        const frame: unknown = JSON.parse(buffered.join(""));
        const check = validationEnvelope.safeParse(frame).data;
        const reply = response.safeParse(frame).data;
        if (check && validationAvailable)
          feedbackFrame("eof", check.params?.requestId);
        else if (
          reply?.id === pending.id &&
          (requiresLF() ||
            ("error" in reply && operation.isFeedbackError?.(reply.error.data)))
        )
          feedbackFrame("eof", reply.id);
      } catch {
        /* An unfinished frame cannot establish that the peer read this request. */
      }
    }
    buffered = [];
    bufferedLength = 0;
    if (waitingForLF) operation.onFeedback?.();
    flushBuffered ||= peerReadReview;
    if (!observed && input.destroyed && !input.closed && !input.errored) {
      if (runId !== undefined) {
        destroyObserver ??= observeDestroyed(
          input,
          () => void disconnected(flushBuffered, true),
        );
        return void (await completion);
      }
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    if (terminalCode === undefined && !settlingReply && !preserveTerminalOnEof)
      return failDisconnected(flushBuffered);
    if (disconnectScheduled) return;
    disconnectScheduled = true;
    // Let selected answers settle; EOF must still interrupt uncorrelated blocked writes.
    setImmediate(() => {
      disconnectScheduled = false;
      if (
        terminalCode !== undefined &&
        nonterminalWrites.size > 0 &&
        (!preserveTerminalOnEof ||
          (!preserveTerminalOnCancel &&
            input.destroyed &&
            !input.readableEnded))
      )
        fail(-32000, disconnectMessage(), { canWrite: false });
      else if (terminalCode === undefined && !preserveTerminalOnEof)
        failDisconnected(settlingReply && flushFeedback());
    });
  };
  const inputError = (error: Error) =>
    receive(() => {
      inputFailure = error;
      void disconnected(validationWriting, true);
    });
  const outputError = (error: Error) =>
    fail(-32000, error.message, { canWrite: false });
  const outputClosed = () => {
    for (const close of pendingOutputWrites) close();
    outputError(new Error("Host output is closed."));
  };
  const cancelMessage = `${operation.label} canceled.`;
  const failCanceled = (flushBuffered: boolean) =>
    fail(-32800, cancelMessage, { flushBuffered });
  const interrupted = () => {
    if (terminalCode !== undefined) stopOutput(2);
    else failCanceled(false);
  };
  const canceled = () => {
    if (terminalCode !== undefined) {
      if (
        !feedbackOutput() ||
        terminalWriteStarted ||
        (!preserveTerminalOnCancel && hasBlockedWrite())
      )
        stopOutput(2);
      return;
    }
    if (!operation.awaitCancellationReceipt || hasBackpressure())
      return failCanceled(validationWriting || settlingReply);
    if (controller.signal.aborted) return;
    controller.abort(new Error(cancelMessage));
    if (pending)
      void write({
        jsonrpc: "2.0",
        method: "execution.cancel",
        params: { requestId: pending.id },
      }).catch(outputError);
  };
  input.prependListener("error", inputError);
  const inputClose = () =>
    receive(() => void disconnected(validationWriting, true));
  input.on("close", inputClose);
  writeStream?.on("close", outputClosed);
  output.on?.("error", outputError);
  signal?.addEventListener("abort", interrupted, { once: true });
  const onLine = (suffix: string, ending: Ending) => {
    if (bufferedLength + suffix.length > bufferLimits.MAX_STRING_LENGTH)
      return fail(-32700, "Invalid JSON.");
    let message: unknown;
    try {
      const line = buffered.join("") + suffix;
      if (!line && ending === "eof") return;
      message = JSON.parse(line);
    } catch {
      fail(-32700, "Invalid JSON.");
      return;
    }
    if (input.readableEnded && ending !== "eof")
      return failDisconnected(validationWriting);
    return onMessage(message, ending);
  };
  const onMessage = (message: unknown, ending: Ending = "lf"): false | void => {
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
      if (inputClosed || input.destroyed) return void disconnected();
      if (runId !== undefined) {
        fail(-32600, "Only one run request is allowed.");
        return;
      }
      runId = run.data.id;
      void operation
        .run(
          run.data.params,
          async (id, params, onProgress, validate) => {
            if (validationFlush) await validationFlush;
            if (terminalCode !== undefined || controller.signal.aborted)
              throw controller.signal.reason;
            if (inputClosed || input.destroyed || input.readableEnded) {
              await disconnected();
              failDisconnected(flushFeedback());
              throw controller.signal.reason;
            }
            if (pending) throw new Error("Execution is already pending.");
            return new Promise((resolve, reject) => {
              settlingReply = false;
              peerReadReview = false;
              pending = { id, resolve, reject, onProgress, validate };
              validationIds.clear();
              validationAvailable ||= validate !== undefined;
              void write(
                {
                  jsonrpc: "2.0",
                  id,
                  method: operation.requestMethod,
                  params,
                  ...(validate && operation.lineFeedOnly
                    ? { capabilities: { reviewValidation: 1 } }
                    : {}),
                },
                undefined,
                true,
              ).catch(outputError);
            });
          },
          controller.signal,
          (event) => {
            if (terminalCode === undefined)
              void write({
                jsonrpc: "2.0",
                method: operation.progressMethod ?? "scan.progress",
                params: { id: runId, event },
              }).catch(outputError);
          },
        )
        .then(
          async (result) => {
            if (terminalCode !== undefined) return;
            preserveTerminalOnEof = true;
            preserveTerminalOnCancel = !pending;
            if (validationWriting) {
              await validationFlush;
              if (terminalCode !== undefined) return;
            }
            const code = result.status === "completed" ? 0 : 1;
            terminalCode = code;
            try {
              terminalWriteStarted = true;
              await write({ jsonrpc: "2.0", id: runId, result }, () =>
                complete(code),
              );
            } catch {
              complete(2);
            }
          },
          (error: unknown) =>
            fail(
              operation.errorCode?.(error) ?? -32602,
              error instanceof Error
                ? error.message
                : "Invalid run parameters.",
              { data: operation.errorData?.(error) },
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
    const validationHeader = validationEnvelope.safeParse(message);
    if (validationHeader.success && validationAvailable) {
      const { id: validationId, params } = validationHeader.data;
      const reject = (message: string, code = -32600) =>
        fail(code, message, { validationId, flushBuffered: true });
      const wellFormed = validationRequestEnvelope.safeParse(message).success;
      if (ending === "cr" && !wellFormed)
        return reject("Malformed validation request.");
      if (!feedbackFrame(ending, params?.requestId)) return false;
      if (validationId === runId)
        return reject("Validation ID conflicts with the active run.");
      const validation = validationRequest.safeParse(message);
      if (!validation.success)
        return wellFormed
          ? reject("Invalid validation parameters.", -32602)
          : reject("Malformed validation request.");
      if (!pending?.validate || validation.data.params.requestId !== pending.id)
        return reject("Validation does not match the active review.");
      if (validationIds.has(validationId))
        return reject("Validation ID was already used.");
      if (validationWriting) {
        if (queuedValidation)
          return reject(
            "Wait for the validation response before sending another request.",
          );
        queuedValidation = validation.data;
        return;
      }
      try {
        const result = pending.validate(validation.data.params.result);
        const receipt =
          JSON.stringify({ jsonrpc: "2.0", id: validationId, result }) + "\n";
        validationWriting = true;
        validationIds.add(validationId);
        validationFlush = write(
          receipt,
          () =>
            queueMicrotask(() => {
              if (inputClosed || input.destroyed || input.readableEnded)
                return void disconnected(true);
              validationWriting = false;
              const queued = queuedValidation;
              queuedValidation = undefined;
              if (queued !== undefined) onMessage(queued);
            }),
          true,
        ).catch(outputError);
      } catch (error) {
        const failure =
          error instanceof Error
            ? error
            : new Error("Review validation failed.");
        fail(-32603, failure.message, {
          data: operation.errorData?.(failure),
          validationId,
          flushBuffered: true,
        });
      }
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
    if (!("error" in reply.data) && queuedValidation !== undefined)
      return fail(-32600, "Final response overtook pending validation.", {
        flushBuffered: true,
      });
    if (
      "error" in reply.data &&
      operation.isFeedbackError?.(reply.data.error.data) &&
      !feedbackFrame(ending, reply.data.id, true)
    )
      return false;
    const execution = pending;
    settlingReply = operation.flushError?.() === true;
    pending = undefined;
    if ("error" in reply.data) {
      const error = new HostResponseError(
        reply.data.error.code,
        reply.data.error.message,
        reply.data.error.data,
      );
      execution.reject(error);
      if (settlingReply || queuedValidation !== undefined)
        fail(operation.errorCode?.(error) ?? -32602, error.message, {
          data: operation.errorData?.(error),
          flushBuffered: true,
        });
    } else execution.resolve(reply.data.result);
  };
  const decoder = new StringDecoder("utf8");
  let lastWasCR = false;
  const readLines = (text: string) => {
    let start = lastWasCR && text.startsWith("\n") ? 1 : 0;
    lastWasCR = false;
    for (const { 0: delimiter, index } of text.matchAll(/\r\n|[\r\n]/g)) {
      // Legacy readline accepts bare CR. Negotiated JSONL requires an LF.
      if (index < start || (delimiter === "\r" && requiresLF())) continue;
      if (
        onLine(text.slice(start, index), delimiter === "\r" ? "cr" : "lf") ===
        false
      )
        continue;
      waitingForLF = false;
      buffered = [];
      bufferedLength = 0;
      start = index + delimiter.length;
      lastWasCR = delimiter === "\r" && start === text.length;
    }
    if (
      start < text.length &&
      bufferedLength <= bufferLimits.MAX_STRING_LENGTH
    ) {
      bufferedLength += text.length - start;
      if (bufferedLength <= bufferLimits.MAX_STRING_LENGTH)
        buffered.push(text.slice(start));
      else buffered = [];
    }
  };
  const onData = (chunk: Buffer | string) => {
    const text = typeof chunk === "string" ? chunk : decoder.write(chunk);
    if (text)
      receive(() => {
        if (!inputClosed) readLines(text);
      });
  };
  const onEnd = () =>
    receive(() => {
      if (requiresLF()) inputClosed = true;
      if (!inputClosed && !settlingReply) onLine(decoder.end(), "eof");
      void disconnected(validationWriting, true);
    });
  input.on("data", onData).on("end", onEnd);
  if (signal?.aborted) interrupted();
  if (input.readableEnded || input.destroyed) disconnected();
  input.resume();
  try {
    return await completion;
  } finally {
    destroyObserver?.();
    outputObserver?.();
    for (const close of pendingOutputWrites) close();
    input.off("data", onData).off("end", onEnd);
    input.pause();
    if (!inputFailure) guardLateDestroyError(input);
    guardLateDestroyError(writeStream);
    input.removeListener("error", inputError);
    input.removeListener("close", inputClose);
    writeStream?.off("close", outputClosed);
    output.off?.("error", outputError);
    signal?.removeEventListener("abort", interrupted);
  }
}
