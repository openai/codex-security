import { once } from "node:events";
import { describe, expect, test, mock } from "bun:test";
import {
  DeepScanProgressTracker,
  deepScanProgressFromWorkbench,
  type DeepScanProgress,
} from "../src/deep-progress.js";

function workbenchResult(
  independentReviews?: Record<string, unknown>,
  status?: string,
): Record<string, unknown> {
  return {
    scan: {
      progress: {
        ...(status === undefined ? {} : { status }),
        ...(independentReviews === undefined ? {} : { independentReviews }),
      },
    },
  };
}

describe("Deep Scan progress", () => {
  test("reads durable independent-review counts from the workbench projection", () => {
    expect(
      deepScanProgressFromWorkbench(
        workbenchResult({
          completed: 34,
          active: 2,
          maximum: 40,
          consolidating: false,
        }),
      ),
    ).toEqual({ completed: 34, active: 2, maximum: 40, consolidating: false });
  });

  test("waits for the Deep Scan coordinator to create independent-review state", () => {
    expect(deepScanProgressFromWorkbench(workbenchResult())).toBeNull();
  });

  test.each([
    { completed: -1, active: 0, maximum: 40 },
    { completed: 0, active: 0, maximum: 0 },
    { completed: 0, active: "two", maximum: 40 },
    { completed: 2, active: 0, maximum: 40, consolidating: "false" },
    { completed: 2, active: 0, maximum: 40, consolidating: null },
  ])("rejects invalid workbench progress %#", (independentReviews) => {
    expect(() =>
      deepScanProgressFromWorkbench(workbenchResult(independentReviews)),
    ).toThrow("invalid Deep Scan progress");
  });

  test("reports only changed progress and ignores refresh after stop", async () => {
    const reads = [
      workbenchResult(),
      workbenchResult({ completed: 0, active: 2, maximum: 40 }),
      workbenchResult({ completed: 0, active: 2, maximum: 40 }),
      workbenchResult({ completed: 1, active: 1, maximum: 40 }),
    ];
    const progress: DeepScanProgress[] = [];
    const read = mock(async () => {
      return reads.shift() ?? workbenchResult();
    });
    const tracker = new DeepScanProgressTracker({
      read,
      onProgress: (update) => progress.push(update),
    });

    await tracker.refresh();
    await tracker.refresh();
    await tracker.refresh();
    await tracker.refresh();
    await tracker.stop();
    await tracker.refresh();

    expect(progress).toEqual([
      { completed: 0, active: 2, maximum: 40 },
      { completed: 1, active: 1, maximum: 40 },
    ]);
    expect(read).toHaveBeenCalledTimes(4);
  });

  test("does not queue or await stalled polls during stop", async () => {
    const progress: DeepScanProgress[] = [];
    const read = mock(async (signal: AbortSignal) => {
      await once(signal, "abort");
      aborted = true;
      return workbenchResult(
        { completed: 1, active: 0, maximum: 40 },
        "failed",
      );
    });
    let aborted = false;
    let stopped = false;
    const tracker = new DeepScanProgressTracker({
      read,
      onProgress: (update) => progress.push(update),
      onStopped: () => {
        stopped = true;
      },
    });

    const first = tracker.refresh();
    const second = tracker.refresh();
    tracker.stop();
    await Promise.all([first, second]);

    expect(read).toHaveBeenCalledTimes(1);
    expect(aborted).toBe(true);
    expect(stopped).toBe(false);
    expect(progress).toEqual([]);
  });

  test.each(["failed", "canceled"])(
    "reports external %s status while polling",
    async (status) => {
      let stopped = false;
      const tracker = new DeepScanProgressTracker({
        read: async () => workbenchResult(undefined, status),
        onProgress() {},
        onStopped: () => {
          stopped = true;
        },
      });
      await tracker.refresh();
      expect(stopped).toBe(true);
    },
  );
  test("reports reduction transitions when review counts remain unchanged", async () => {
    const reads = [false, true, true, false].map((consolidating) =>
      workbenchResult({ completed: 2, active: 2, maximum: 40, consolidating }),
    );
    const progress: DeepScanProgress[] = [];
    const tracker = new DeepScanProgressTracker({
      read: async () => reads.shift(),
      onProgress: (update) => progress.push(update),
    });
    for (let index = 0; index < 4; index++) await tracker.refresh();
    tracker.stop();
    expect(progress.map((update) => update.consolidating)).toEqual([
      false,
      true,
      false,
    ]);
  });
});
