import { expect, test } from "bun:test";
import { pollDashboard } from "../dashboard/polling.js";
import type { DashboardSnapshot } from "../src/server/dashboard-types.js";

const snapshot: DashboardSnapshot = {
  overview: { findings: 0, groups: 0 },
  repositories: [],
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
  nextOffset: null,
  detail: null,
};

function clock() {
  let tick = () => {};
  let interval = 0;
  let cleared = false;
  return {
    timers: {
      setInterval(callback: () => void, milliseconds: number) {
        tick = callback;
        interval = milliseconds;
        return 1 as unknown as ReturnType<typeof setInterval>;
      },
      clearInterval() {
        cleared = true;
      },
    } as Pick<typeof globalThis, "setInterval" | "clearInterval">,
    tick: () => tick(),
    interval: () => interval,
    cleared: () => cleared,
  };
}

test("dashboard polls immediately and every five seconds without overlapping requests", async () => {
  const timer = clock();
  const calls: AbortSignal[] = [];
  const received: DashboardSnapshot[] = [];
  let resolve!: (value: DashboardSnapshot) => void;
  const stop = pollDashboard(
    (signal) => {
      calls.push(signal);
      return new Promise((done) => {
        resolve = done;
      });
    },
    (value) => received.push(value),
    () => {
      throw new Error("Unexpected poll failure");
    },
    timer.timers,
  );
  try {
    expect(calls).toHaveLength(1);
    expect(timer.interval()).toBe(5_000);
    timer.tick();
    expect(calls).toHaveLength(1);
    resolve(snapshot);
    await Promise.resolve();
    expect(received).toEqual([snapshot]);
    timer.tick();
    expect(calls).toHaveLength(2);
  } finally {
    stop();
  }
  expect(timer.cleared()).toBe(true);
  expect(calls.every((signal) => signal.aborted)).toBe(true);
  resolve(snapshot);
  await Promise.resolve();
  expect(received).toHaveLength(1);
});

test("dashboard reports refresh errors and retries on the next polling tick", async () => {
  const timer = clock();
  const received: DashboardSnapshot[] = [];
  const errors: unknown[] = [];
  let request = 0;
  const stop = pollDashboard(
    async () => {
      if (++request === 2) throw new Error("Synthetic connection failure");
      return { ...snapshot, total: request };
    },
    (value) => received.push(value),
    (error) => errors.push(error),
    timer.timers,
  );
  try {
    await Promise.resolve();
    timer.tick();
    await Promise.resolve();
    expect(errors).toHaveLength(1);
    expect(received.map((value) => value.total)).toEqual([1]);
    timer.tick();
    await Promise.resolve();
    expect(received.map((value) => value.total)).toEqual([1, 3]);
  } finally {
    stop();
  }
});

test("disposing an old selection suppresses late errors as well as late responses", async () => {
  const timer = clock();
  const errors: unknown[] = [];
  let reject!: (reason: Error) => void;
  const stop = pollDashboard(
    () =>
      new Promise((_resolve, fail) => {
        reject = fail;
      }),
    () => {
      throw new Error("Unexpected data");
    },
    (error) => errors.push(error),
    timer.timers,
  );
  stop();
  reject(new Error("Old request failed"));
  await Promise.resolve();
  expect(errors).toEqual([]);
});
