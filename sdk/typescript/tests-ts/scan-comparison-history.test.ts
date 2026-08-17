import { expect, test } from "bun:test";
import {
  matchCompletedScan,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

test("preserves a stable finding across multiple earlier scans", async () => {
  const earlierA = { findingId: "stable", occurrenceId: "old-a" };
  const earlierB = { findingId: "stable", occurrenceId: "old-b" };
  const current = { findingId: "stable", occurrenceId: "current" };
  const commands: (readonly string[])[] = [];
  let modelCalled = false;

  await matchCompletedScan({
    scanId: "current-scan",
    repository: "/repository",
    previousFindings: [earlierA, earlierB],
    falsePositives: [],
    findings: [current],
    async workbench(args) {
      commands.push(args);
      return args[0] === "list-unmatched-scan-pairs"
        ? {
            batches: [
              {
                afterScanId: "current-scan",
                afterFindings: [current],
                beforeScans: [
                  { scanId: "scan-a", findings: [earlierA] },
                  { scanId: "scan-b", findings: [earlierB] },
                ],
              },
            ],
          }
        : {};
    },
    async matchFindings() {
      modelCalled = true;
      return { matches: [], uncertain: [] };
    },
  });

  expect(modelCalled).toBe(false);
  const saves = commands.filter(
    ([command]) => command === "save-scan-comparison",
  );
  expect(saves).toHaveLength(2);
  expect(saves.map((args) => args[2])).toEqual(["scan-a", "scan-b"]);

  const saved = saves.map(
    (args) => JSON.parse(args.at(-1)!) as ScanComparisonResult,
  );
  expect(saved[0]!.matches).toEqual([
    {
      beforeOccurrenceIds: ["old-a"],
      afterOccurrenceIds: ["current"],
      confidence: "high",
      reason: "The findings have the same stable identity.",
    },
  ]);
  expect(saved[1]!.matches).toEqual([
    {
      beforeOccurrenceIds: ["old-b"],
      afterOccurrenceIds: ["current"],
      confidence: "high",
      reason: "The findings have the same stable identity.",
    },
  ]);
});
