import { once } from "node:events";
import { describe, expect, test, mock } from "bun:test";
import {
  ScanProgressTracker,
  scanProgressFromWorkbench,
  type SavedScanProgress,
  deepScanProgressFromWorkbench,
  type DeepScanProgress,
} from "../src/scan-progress.js";

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
    const tracker = new ScanProgressTracker({
      read,
      onDeepProgress: (update) => progress.push(update),
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
      return workbenchResult({ completed: 1, active: 0, maximum: 40 });
    });
    let aborted = false;
    const tracker = new ScanProgressTracker({
      read,
      onDeepProgress: (update) => progress.push(update),
    });

    const first = tracker.refresh();
    await Bun.sleep(0);
    const second = tracker.refresh();
    tracker.stop();
    await Promise.all([first, second]);

    expect(read).toHaveBeenCalledTimes(1);
    expect(aborted).toBe(true);
    expect(progress).toEqual([]);
  });

  test("reports reduction transitions when review counts remain unchanged", async () => {
    const reads = [false, true, true, false].map((consolidating) =>
      workbenchResult({ completed: 2, active: 2, maximum: 40, consolidating }),
    );
    const progress: DeepScanProgress[] = [];
    const tracker = new ScanProgressTracker({
      read: async () => reads.shift(),
      onDeepProgress: (update) => progress.push(update),
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

function savedProgress(phase: string, completed: number, total: number) {
  return {
    scan: {
      progress: {
        phase,
        coverage: { filesTotal: 8, closedRows: completed, worklistRows: total },
      },
    },
  };
}

test("saved progress keeps review items distinct from files", () => {
  expect(
    scanProgressFromWorkbench(savedProgress("validation", 11, 13)),
  ).toEqual({
    phase: "validation",
    filesTotal: 8,
    reviewItems: { completed: 11, total: 13 },
  });
  const snapshot = savedProgress("preflight", 0, 0);
  expect(
    scanProgressFromWorkbench({
      scan: {
        progress: {
          ...snapshot.scan.progress,
          coverage: { ...snapshot.scan.progress.coverage, filesTotal: null },
        },
      },
    }),
  ).toEqual({
    phase: "preflight",
    filesTotal: null,
    reviewItems: { completed: 0, total: 0 },
  });
  expect(scanProgressFromWorkbench({})).toBeNull();
});

test.each([
  ["unknown", 0, 13],
  ["discovery", -1, 13],
  ["discovery", 14, 13],
] as const)(
  "rejects invalid saved progress (%s, %p/%p)",
  (phase, completed, total) => {
    expect(() =>
      scanProgressFromWorkbench(savedProgress(phase, completed, total)),
    ).toThrow("invalid scan progress");
  },
);

test("publishes saved phase and count changes without model progress markers", async () => {
  const snapshots = [
    {},
    savedProgress("discovery", 1, 13),
    savedProgress("discovery", 1, 13),
    savedProgress("discovery", 2, 13),
    savedProgress("validation", 2, 13),
  ];
  const updates: SavedScanProgress[] = [];
  const read = mock(async () => snapshots.shift());
  const tracker = new ScanProgressTracker({
    read,
    onProgress: (update) => updates.push(update),
  });
  try {
    for (let index = 0; index < 5; index++) await tracker.refresh();
    expect(
      updates.map(({ phase, reviewItems }) => [phase, reviewItems.completed]),
    ).toEqual([
      ["discovery", 1],
      ["discovery", 2],
      ["validation", 2],
    ]);
  } finally {
    tracker.stop();
  }
  await tracker.refresh();
  expect(read).toHaveBeenCalledTimes(5);
});

test("recovers on the next refresh after a progress read fails", async () => {
  const updates: SavedScanProgress[] = [];
  let reads = 0;
  const tracker = new ScanProgressTracker({
    read: async () => {
      if (reads++ === 0) throw new Error("workbench unavailable");
      return savedProgress("validation", 13, 13);
    },
    onProgress: (update) => updates.push(update),
  });
  try {
    await expect(tracker.refresh()).rejects.toThrow("workbench unavailable");
    await tracker.refresh();
    expect(updates).toHaveLength(1);
    expect(updates[0]?.phase).toBe("validation");
  } finally {
    tracker.stop();
  }
});
