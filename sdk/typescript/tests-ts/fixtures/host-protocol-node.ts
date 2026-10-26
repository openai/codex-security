import { strictEqual } from "node:assert";
import { PassThrough, Writable } from "node:stream";
import { constants as bufferLimits } from "node:buffer";
import { runHostProtocol } from "../../src/host-protocol.js";

const jsonrpc = "2.0";
const reviewId = "review-1";

function validation(
  requestId = reviewId,
  id = "check",
  result: unknown = "valid",
) {
  const params = { requestId, result };
  return { jsonrpc, id, method: "review.validate", params };
}

type Operation = Parameters<typeof runHostProtocol>[2];
const reviewOperation = { label: "Review", requestMethod: "review.run" };
export type Frame = {
  jsonrpc: string;
  id: string;
  method?: string;
  result?: { status?: string; usage?: number };
  error?: { code: number; message?: string; data?: unknown };
};
const encode = (value: unknown) => JSON.stringify(value) + "\n";
const start = { jsonrpc, id: "run-1", method: "run", params: {} };
const cancelRun = { jsonrpc, method: "cancel", params: { id: start.id } };
const afterIO = (callback: () => void) =>
  setImmediate(() => setImmediate(callback));
const syntheticInputError = new Error("Synthetic input error");
const lateError = new Error("Late destroy error");
const rejection = { code: -32009, message: "Synthetic rejection" };
function accepted(id: string, result: unknown = "valid") {
  return { jsonrpc, id, result };
}
const rejected = (id: string) => ({ jsonrpc, id, error: rejection });
const accept = () => ({ valid: true });
type ReviewCheck = ((candidate: unknown) => { valid: boolean }) | undefined;
function runRequests(...checks: ReviewCheck[]): Operation["run"] {
  return async (_params, execute) => {
    for (const [i, check] of checks.entries())
      await execute(`review-${i + 1}`, {}, undefined, check);
    return { status: "completed" };
  };
}

function validatingReviews(...checks: ReviewCheck[]) {
  return { flushError: () => true, run: runRequests(...checks) };
}

type PipeOptions = ConstructorParameters<typeof PassThrough>[0];
type TestOperation = Pick<Operation, "run"> & Partial<Operation>;
function protocolFixture(options?: PipeOptions) {
  const input = new PassThrough({
    emitClose: !scenario.startsWith("silent-input-"),
    ...options,
  });
  const controller = new AbortController();
  const messages: Frame[] = [];
  const send = (value: unknown) => input.write(encode(value));
  function writer(
    handle: (frame: Frame, done: () => void) => void,
    emitClose = true,
  ) {
    return new Writable({
      emitClose,
      write(chunk, _encoding, done) {
        const frame = JSON.parse(chunk.toString()) as Frame;
        messages.push(frame);
        handle(frame, done);
      },
    });
  }
  return {
    input,
    send,
    sendCheck: (...args: Parameters<typeof validation>) =>
      send(validation(...args)),
    writer,
    observe: (handle?: (frame: Frame) => void) =>
      writer((frame, done) => {
        handle?.(frame);
        done();
      }),
    cancel: () => send(cancelRun),
    interrupt: () => controller.abort(),
    async finish(output: Writable, operation: TestOperation) {
      const options = { ...reviewOperation, ...operation };
      const errorOnly = (event: "error") => strictEqual(event, "error");
      const listeners =
        scenario === "sync-adapter" ? { on: errorOnly, off: errorOnly } : {};
      const sink = isScenario("sync-adapter", "plain-cancel-adapter")
        ? { write: output.write.bind(output), ...listeners }
        : output;
      const done = runHostProtocol(input, sink, options, controller.signal);
      if (!input.destroyed) send(start);
      process.exitCode = await done;
      process.stdout.write(encode({ messages, destroyed: output.destroyed }));
    },
  };
}

const [, , scenario = "", family] = process.argv;
const isScenario = (...names: string[]) => names.includes(scenario);
if (scenario === "cli") {
  await (await import("../../src/cli.js")).main(process.argv.slice(3));
} else if (scenario === "idle-host") {
  const { observe, finish } = protocolFixture();
  void finish(observe(), { run: runRequests(undefined) });
} else if (family === "output") {
  const { input, interrupt, cancel, observe, finish } = protocolFixture();
  const output =
    scenario === "silent-terminal-output"
      ? new Writable({
          emitClose: false,
          write() {
            this.destroy();
          },
        })
      : observe(() => {
          if (scenario === "silent-input-legacy-output")
            setImmediate(() => input.destroy());
        });
  const legacyOutput = scenario === "silent-input-legacy-output";
  const stop = {
    "abort-output": interrupt,
    "cancel-output": cancel,
    "eof-output": () => input.end(),
    "close-output": () => output.emit("close"),
    "failed-output": () => output.destroy(syntheticInputError),
    "plain-cancel-adapter": () => {
      cancel();
      output.uncork();
    },
  }[scenario];
  if (stop) {
    output.cork();
    setImmediate(stop);
  }
  await finish(output, {
    lineFeedOnly: !legacyOutput && scenario !== "silent-terminal-output",
    run:
      legacyOutput || (stop && !isScenario("close-output", "failed-output"))
        ? runRequests(undefined)
        : runRequests(),
  });
} else if (family === "correction") {
  let releaseDestroy: (() => void) | undefined;
  const beforeStart = scenario.startsWith("destroy-before-start");
  const nextReview = scenario.startsWith("destroy-next-review");
  const silentPending = scenario.startsWith("destroy-before-start-pending");
  const { input, observe, send, sendCheck, finish } = protocolFixture({
    emitClose: !beforeStart && !scenario.includes("silent-late"),
    destroy(error, callback) {
      if (silentPending) {
        const cause = scenario.endsWith("-error") ? lateError : error;
        releaseDestroy = () => callback(cause);
      } else if (scenario.endsWith("late"))
        afterIO(() => callback(syntheticInputError));
      else setImmediate(callback, error);
    },
  });
  const output = observe((message) => {
    if (message.method === "review.run" && nextReview) {
      queueMicrotask(() => {
        send(accepted(message.id, "corrected"));
        input.destroy(
          scenario.endsWith("late") ? undefined : syntheticInputError,
        );
      });
    } else if (message.method === "review.run") {
      const check = validation(reviewId, "check-1", "invalid");
      if (scenario === "sync-invalid-params")
        Reflect.deleteProperty(check.params, "result");
      send(check);
    } else if (message.id === "check-1" && message.result) {
      const next = scenario === "reused-validation-id" ? "check-1" : "check-2";
      setImmediate(() => sendCheck(reviewId, next, "corrected"));
    } else if (message.id === "check-2") {
      send(accepted(reviewId, "corrected"));
      if (scenario === "sync-half-close") input.end();
    }
  });
  if (silentPending) send(start);
  if (beforeStart) input.destroy();
  if (scenario === "sync-paused") input.pause();
  const checks: ReviewCheck[] = [];
  if (!silentPending)
    checks.push((candidate) => ({ valid: candidate === "corrected" }));
  if (nextReview) checks.push(undefined);
  await finish(output, validatingReviews(...checks));
  releaseDestroy?.();
  if (silentPending) {
    await new Promise<void>((resolve) => setImmediate(resolve));
    if (input.listenerCount("close") || input.listenerCount("error"))
      throw new Error("Silent destruction retained protocol listeners");
  }
} else if (family === "selection") {
  const { input, writer, send, sendCheck, cancel, interrupt, finish } =
    protocolFixture();
  const inputError = () => input.emit("error", syntheticInputError);
  const output = writer((message, callback) => {
    if (message.method === "review.run") {
      if (scenario === "input-error-answered-write") {
        send(accepted(message.id));
        return setImmediate(() => {
          input.destroy(syntheticInputError);
          afterIO(callback);
        });
      }
      callback();
      if (scenario === "eof-selected-error")
        setImmediate(() => input.end(encode(rejected(message.id)) + "{}"));
      else
        queueMicrotask(() =>
          sendCheck(scenario.includes("stale-error") ? "stale" : message.id),
        );
    } else if (message.id === "check") {
      if (
        isScenario(
          "queued-validation-output",
          "repeated-pending-validation",
          "eof-queued-validation",
        )
      ) {
        if (scenario === "repeated-pending-validation") sendCheck();
        else {
          sendCheck(reviewId, "second");
          sendCheck(reviewId, "third");
        }
        if (scenario === "eof-queued-validation") input.end();
        else send(accepted(reviewId));
        return setImmediate(() => {
          if (output.destroyed || output.listenerCount("close") > 3)
            throw new Error(
              "Validation flush lost output or retained listeners",
            );
          callback();
        });
      }
      if (scenario === "silent-input-after-validation") {
        callback();
        return void setImmediate(() => input.destroy());
      }
      if (scenario.startsWith("destroy-output-")) {
        if (scenario === "destroy-output-pending-open")
          output._destroy = () => {};
        if (scenario === "destroy-output-late-error") {
          output._destroy = (_error, done) =>
            setImmediate(() => done(syntheticInputError));
          output.destroy();
          return void input.end();
        }
        if (scenario === "destroy-output-reusable") {
          output.destroy = () => output;
          return interrupt();
        }
        if (scenario.startsWith("destroy-output-selected"))
          send(accepted(reviewId));
        setImmediate(() => {
          output.destroy();
          if (!scenario.endsWith("-open")) input.end();
        });
        return;
      }
      if (scenario !== "eof-validation-drain") {
        const id = scenario === "eof-wrong-review" ? "wrong" : reviewId;
        const reply = scenario.endsWith("selected-rejection")
          ? rejected(id)
          : accepted(id);
        if (scenario === "cancel-drained-selected-rejection") {
          setImmediate(() => {
            send(reply);
            callback();
            queueMicrotask(cancel);
          });
          return;
        }
        if (scenario.startsWith("reentrant-"))
          input.emit("data", Buffer.from(encode(reply)));
        else send(reply);
      }
      if (scenario === "reentrant-close-selected-rejection")
        input.emit("close");
      else if (scenario === "reentrant-error-selected-rejection") inputError();
      else if (scenario.startsWith("input-error-")) queueMicrotask(inputError);
      else if (scenario === "cancel-selected-result") setImmediate(cancel);
      else input.end();
      // Hold the validation write while the selected result meets EOF or cancel.
      afterIO(callback);
    } else callback();
  }, !scenario.startsWith("destroy-output-"));
  const checks: ReviewCheck[] = [accept];
  if (scenario.endsWith("next-review")) checks.push(undefined);
  await finish(output, {
    ...validatingReviews(...checks),
    errorCode: () => -32009,
    errorData: () => ({ feedbackVersion: 1, kind: "permanent_rejection" }),
  });
} else if (family === "teardown") {
  const [ending = "", fault] = scenario.split(":");
  const earlyCancel = ending === "cancel" && fault === "missing";
  const { input, writer, send, sendCheck, cancel, interrupt, finish } =
    protocolFixture({
      destroy(error, callback) {
        if (scenario === "legacy-answer-eof-destroying")
          afterIO(() => callback(error));
        else if (scenario === "eof-destroy-error")
          queueMicrotask(() => callback(new Error("Synthetic teardown error")));
        else callback(error);
      },
    });
  const output = writer((message, callback) => {
    if (message.method === "review.run") {
      if (earlyCancel) afterIO(callback);
      else callback();
      queueMicrotask(() => {
        if (scenario.startsWith("legacy-answer-eof")) {
          if (scenario.endsWith("destroying"))
            input.prependOnceListener("end", () => input.destroy());
          send(accepted(message.id));
          input.end();
        } else if (fault) {
          const check = validation(fault === "stale" ? "stale" : message.id);
          if (fault === "missing")
            Reflect.deleteProperty(check.params, "result");
          send(check);
          if (earlyCancel) cancel();
        } else
          sendCheck(scenario === "eof-stale-validation" ? "stale" : message.id);
      });
    } else if (message.id === "check") {
      if (fault === "malformed")
        queueMicrotask(() => input.end("{malformed\n"));
      else if (
        scenario === "eof-stale-validation" ||
        (fault && ending !== "cancel")
      )
        input.end();
      else cancel();
      afterIO(() => {
        if (ending.startsWith("abort")) interrupt();
        callback();
      });
    } else if (message.id === start.id && message.result) {
      if (scenario === "lf-eof-before-flush")
        input.end(JSON.stringify(cancelRun));
      else if (scenario === "eof-destroy-error") input.end();
      else input.destroy(syntheticInputError);
      afterIO(callback);
    } else callback();
  });
  if (ending === "abort-reusable") output.destroy = () => output;
  await finish(output, {
    lineFeedOnly: scenario === "lf-eof-before-flush",
    flushError: () => Boolean(fault),
    async run(_params, execute) {
      if (scenario.startsWith("legacy-answer-eof")) {
        await execute(reviewId, {});
        await new Promise<void>((resolve) => setImmediate(resolve));
      } else if (
        fault ||
        isScenario("eof-stale-validation", "cancel-validation-write")
      )
        await execute(reviewId, {}, undefined, accept);
      return { status: "completed" };
    },
  });
} else if (family === "overlap") {
  const { input, writer, send, sendCheck, cancel, finish } = protocolFixture();
  const stale = scenario.includes("validation-stale")
    ? validation()
    : accepted(reviewId, "duplicate");
  const output = writer((message, callback) => {
    if (message.method === "review.run" && scenario === "eof-initial-run-id") {
      queueMicrotask(() => {
        sendCheck(reviewId, "run-1");
        input.end();
      });
      afterIO(callback);
    } else if (message.method === "review.run" && message.id === reviewId) {
      callback();
      queueMicrotask(() => sendCheck());
    } else if (message.id === "check") {
      if (scenario.startsWith("oversized-")) {
        const fragment = " ".repeat(1024 * 1024 - 1) + "\r";
        const chunks =
          Math.floor(bufferLimits.MAX_STRING_LENGTH / fragment.length) + 1;
        for (let i = 0; i < chunks; i++) input.emit("data", fragment);
        input.end(scenario === "oversized-delimited" ? "{}\n" : undefined);
        callback();
      } else if (scenario.endsWith("next-review")) {
        callback();
        const blocked = scenario.endsWith("stale-blocked-next-review");
        if (blocked) output.cork();
        queueMicrotask(() => {
          send(accepted(reviewId));
          if (blocked)
            setImmediate(() => {
              send(stale);
              if (scenario.startsWith("cancel-")) cancel();
              if (scenario.startsWith("error-then-close-")) {
                input.emit("error", syntheticInputError);
                setImmediate(() => input.destroy());
              } else if (scenario.startsWith("silent-input-")) input.destroy();
              else input.end();
              if (scenario === "eof-stale-blocked-next-review")
                setImmediate(() => output.uncork());
              if (scenario.startsWith("close-")) output.destroy();
            });
        });
      } else {
        const id = scenario.endsWith("conflicting-validation")
          ? start.id
          : "queued";
        sendCheck(reviewId, id);
        if (scenario === "eof-overtaking-final") send(accepted(reviewId));
        if (scenario === "cancel-conflicting-validation") cancel();
        input.end();
        afterIO(callback);
      }
    } else if (message.method === "review.run" && message.id === "review-2") {
      if (scenario === "eof-stale-blocked-next-review") callback();
      else if (scenario.endsWith("stale-next-review")) {
        send(stale);
        input.end();
        if (scenario === "eof-slow-review-stale-next-review")
          setTimeout(callback, 1_300);
        else if (scenario === "eof-slow-terminal-stale-next-review")
          setTimeout(callback, 150);
        else if (scenario === "close-stalled-stale-next-review")
          setImmediate(() => output.destroy());
        else afterIO(callback);
      } else if (scenario === "cancel-next-review") cancel();
      else
        input.end(
          scenario === "eof-truncated-blocked-next-review"
            ? '{"jsonrpc":'
            : undefined,
        );
    } else if (scenario === "eof-slow-terminal-stale-next-review")
      setTimeout(callback, 1_200);
    else callback();
  });
  await finish(output, validatingReviews(accept, accept));
} else if (family === "drain") {
  const { input, writer, send, sendCheck, cancel, finish } = protocolFixture({
    emitClose: false,
  });
  const output = writer((message, callback) => {
    if (message.method === "review.run") {
      if (!scenario.endsWith("validation-drain")) {
        queueMicrotask(() => {
          send(rejected(message.id));
          if (scenario === "cancel-correlated-rejection") cancel();
        });
        afterIO(callback);
      } else {
        callback();
        queueMicrotask(() => sendCheck());
      }
    } else if (message.id === "check") {
      sendCheck(reviewId, "queued");
      queueMicrotask(() =>
        scenario === "socket-close-validation-drain"
          ? input.emit("close", false)
          : scenario === "silent-validation-drain"
            ? input.destroy()
            : input.emit("error", syntheticInputError),
      );

      afterIO(callback);
    } else if (scenario === "cancel-terminal-rejection") cancel();
    else callback();
  });
  await finish(output, validatingReviews(accept));
} else if (family === "execution") {
  const { input, observe, finish, cancel } = protocolFixture();
  const fragmentReceipt = scenario === "reentrant-cancel-receipt";
  const withReceipt = fragmentReceipt || scenario === "drained-cancel-output";
  const receipt = encode(accepted("turn", { status: "cancelled", usage: 7 }));
  const emitChunk = (chunk: string) => input.emit("data", Buffer.from(chunk));
  const output = observe(({ method }) => {
    if (method === "execution.cancel" && withReceipt) {
      if (fragmentReceipt) emitChunk(receipt.slice(8));
      else input.write(receipt);
    }
    if (method !== "execution.run") return;
    setImmediate(() => {
      if (scenario === "drained-cancel-output") return void cancel();
      if (fragmentReceipt)
        return void emitChunk(encode(cancelRun) + receipt.slice(0, 8));
      output.cork();
      if (scenario === "legacy-stale-cancel")
        input.write(encode(accepted("stale", {})) + encode(cancelRun));
      else {
        input.destroy(syntheticInputError);
        setImmediate(() => output.uncork());
      }
    });
  });
  await finish(output, {
    requestMethod: "execution.run",
    awaitCancellationReceipt: withReceipt || scenario === "legacy-stale-cancel",
    run: withReceipt
      ? async (_params, execute) =>
          (await execute("turn", {})) as { status: string }
      : runRequests(undefined),
  });
} else {
  const output =
    scenario === "failed-terminal"
      ? new Writable({
          write(_chunk, _encoding, callback) {
            const fail = () =>
              callback(new Error("Synthetic terminal write failure"));
            if (process.argv[4] === "async") queueMicrotask(fail);
            else fail();
          },
        })
      : scenario === "close-after-flush"
        ? new Writable({
            write(_chunk, _encoding, callback) {
              this.end();
              callback();
            },
          })
        : scenario === "eof-before-flush"
          ? new Writable({
              write(_chunk, _encoding, callback) {
                process.stderr.write("writing\n");
                process.stdin.once("end", () => {
                  queueMicrotask(() => callback());
                });
              },
            })
          : process.stdout;
  // Windows stdout pipes write synchronously. Hold a native queued write
  // without blocking the event loop that must receive cancellation.
  const queued = isScenario("queued-execution", "queued-legacy-rejection");
  if (queued) output.cork();
  const code = await runHostProtocol(process.stdin, output, {
    label: "Scan",
    requestMethod: "execution.run",
    awaitCancellationReceipt: true,
    errorData: () => {
      if (scenario !== "deep-error-data") return undefined;
      const data: { detail?: object } = {};
      data.detail = data;
      return data;
    },
    async run(_params, execute) {
      if (scenario === "deep-error-data")
        throw new Error("Synthetic rejection");
      if (queued) {
        const execution = execute("request-1", {
          payload: "synthetic request",
        });
        process.stderr.write(
          JSON.stringify({ queued: output.writableLength > 0 }) + "\n",
        );
        await execution;
      }
      return { status: process.argv[3] ?? "completed" };
    },
  });
  process.stderr.write(JSON.stringify({ code }) + "\n");
  // Match the CLI: native stdout can remain open after destroy().
  process.exit(code);
}
