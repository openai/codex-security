import { expect, mock, test } from "bun:test";
import {
  ScanProgressTracker,
  scanProgressFromWorkbench,
  type SavedScanProgress,
} from "../src/scan-progress.js";

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
