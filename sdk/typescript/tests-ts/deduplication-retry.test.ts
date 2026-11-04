import { setImmediate } from "node:timers";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const maximumDelay = 2_147_483_647;
const flush = () => new Promise<void>((resolve) => setImmediate(resolve));
afterEach(() => mock.restore());

function controlledTimers() {
  const timers: Array<{
    delay: number;
    signal?: AbortSignal;
    resolve: () => void;
  }> = [];
  mock.module("node:timers/promises", () => ({
    setTimeout: (
      delay: number,
      _value: undefined,
      { signal }: { signal?: AbortSignal },
    ) => {
      signal?.throwIfAborted();
      const pending = Promise.withResolvers<void>();
      const abort = () =>
        pending.reject(new DOMException("Timer aborted", "AbortError"));
      signal?.addEventListener("abort", abort, { once: true });
      timers.push({ delay, signal, resolve: pending.resolve });
      return pending.promise.finally(() =>
        signal?.removeEventListener("abort", abort),
      );
    },
  }));
  return timers;
}

for (const [delay, intervals] of [
  [0, [0]],
  [100, [100]],
  [maximumDelay, [maximumDelay]],
  [maximumDelay + 1, [maximumDelay, 1]],
  [2 * maximumDelay, [maximumDelay, maximumDelay]],
  [2 * maximumDelay + 123, [maximumDelay, maximumDelay, 123]],
] as const) {
  const name = `waits for the full ${delay}ms using supported timers`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.path, name)) return;
    const timers = controlledTimers();
    const { waitForRetry } = await import("../src/deduplication/retry.js");
    let completed = false;
    const waiting = waitForRetry(delay).then(() => {
      completed = true;
    });
    for (const [index, interval] of intervals.entries()) {
      await flush();
      expect(completed).toBe(false);
      expect(timers).toHaveLength(index + 1);
      expect(timers[index]!.delay).toBe(interval);
      timers[index]!.resolve();
    }
    await waiting;
    expect(completed).toBe(true);
    expect(timers).toHaveLength(intervals.length);
  });
}

for (const stage of ["before waiting", "first interval", "later interval"]) {
  const name = `preserves cancellation during ${stage}`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.path, name)) return;
    const timers = controlledTimers();
    const { waitForRetry } = await import("../src/deduplication/retry.js");
    const controller = new AbortController();
    const reason = new Error("Synthetic retry cancellation");
    if (stage === "before waiting") controller.abort(reason);
    const waiting = waitForRetry(
      2 * maximumDelay + 123,
      controller.signal,
    ).catch((error: unknown) => error);
    if (stage === "later interval") {
      timers[0]!.resolve();
      await flush();
    }
    const count =
      stage === "before waiting" ? 0 : stage === "first interval" ? 1 : 2;
    expect(timers).toHaveLength(count);
    expect(timers.every((timer) => timer.signal === controller.signal)).toBe(
      true,
    );
    controller.abort(reason);
    expect(await waiting).toBe(reason);
    expect(timers).toHaveLength(count);
  });
}

for (const kind of ["seconds", "HTTP date", "cancelled seconds"]) {
  const name = `honors a long Retry-After in ${kind} before another request`;
  test(name, async () => {
    if (runTestInSubprocess(import.meta.path, name)) return;
    const timers = controlledTimers();
    const { FindingsClient } = await import("../src/findings-client.js");
    const now = Date.UTC(2030, 0, 1);
    spyOn(Date, "now").mockReturnValue(now);
    const retryAfter =
      kind === "HTTP date"
        ? new Date(now + 2_147_484_000).toUTCString()
        : "2147484";
    const controller = new AbortController();
    let requests = 0;
    const request = mock(async () =>
      ++requests === 1
        ? new Response("busy", {
            status: 429,
            headers: { "Retry-After": retryAfter },
          })
        : Response.json({
            finding: { findingId: "synthetic" },
            potentialDuplicates: [],
          }),
    );
    const client = new FindingsClient(
      "http://synthetic.test",
      controller.signal,
      request,
      { random: () => 0 },
    );
    const result = client
      .potentialDuplicates("synthetic", {
        repositoryId: "synthetic-repository",
      })
      .catch((error: unknown) => error);
    await flush();
    expect(request).toHaveBeenCalledTimes(1);
    expect(timers).toHaveLength(1);
    expect(timers[0]!.delay).toBe(maximumDelay);
    timers[0]!.resolve();
    await flush();
    expect(request).toHaveBeenCalledTimes(1);
    expect(timers).toHaveLength(2);
    expect(timers[1]!.delay).toBe(353);
    if (kind === "cancelled seconds") {
      const reason = new Error("Synthetic request cancellation");
      controller.abort(reason);
      expect(await result).toBe(reason);
      expect(request).toHaveBeenCalledTimes(1);
    } else {
      timers[1]!.resolve();
      expect(await result).toMatchObject({
        finding: { findingId: "synthetic" },
      });
      expect(request).toHaveBeenCalledTimes(2);
    }
  });
}
