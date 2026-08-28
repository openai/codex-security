import { describe, expect, test } from "bun:test";
import {
  DeepScanProgressTracker,
  deepScanProgressFromWorkbench,
  type DeepScanProgress,
} from "../src/deep-progress.js";

function workbenchResult(
  independentReviews?: Record<string, unknown>,
): Record<string, unknown> {
  return {
    scan: {
      progress: {
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
    ).toEqual({ completed: 34, active: 2, maximum: 40 });
  });

  test("waits for the Deep Scan coordinator to create independent-review state", () => {
    expect(deepScanProgressFromWorkbench(workbenchResult())).toBeNull();
  });

  test.each([
    { completed: -1, active: 0, maximum: 40 },
    { completed: 0, active: 0, maximum: 0 },
    { completed: 0, active: "two", maximum: 40 },
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
    let readCount = 0;
    const tracker = new DeepScanProgressTracker({
      read: async () => {
        readCount += 1;
        return reads.shift() ?? workbenchResult();
      },
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
    expect(readCount).toBe(4);
  });

  test("does not queue or await stalled polls during stop", async () => {
    const progress: DeepScanProgress[] = [];
    let readCount = 0;
    let aborted = false;
    const tracker = new DeepScanProgressTracker({
      read: async (signal) => {
        readCount += 1;
        return await new Promise((resolve) => {
          signal.addEventListener(
            "abort",
            () => {
              aborted = true;
              resolve(
                workbenchResult({ completed: 1, active: 0, maximum: 40 }),
              );
            },
            { once: true },
          );
        });
      },
      onProgress: (update) => progress.push(update),
    });

    const first = tracker.refresh();
    await Bun.sleep(0);
    const second = tracker.refresh();
    tracker.stop();
    await Promise.all([first, second]);

    expect(readCount).toBe(1);
    expect(aborted).toBe(true);
    expect(progress).toEqual([]);
  });
});
