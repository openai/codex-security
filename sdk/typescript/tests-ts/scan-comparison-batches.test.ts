import { expect, test } from "bun:test";
import {
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const noMatches: ScanComparisonResult = { matches: [], uncertain: [] };

function codex(
  compare: (input: ScanComparisonInput, prompt: string) => ScanComparisonResult,
): NonNullable<ScanComparisonOptions["codex"]> {
  return {
    startThread: () => ({
      async run(prompt) {
        const input = JSON.parse(prompt.slice(prompt.lastIndexOf("\n") + 1));
        return { finalResponse: JSON.stringify(compare(input, prompt)) };
      },
    }),
  };
}

function finding(occurrenceId: string, characters = 5000) {
  return { occurrenceId, evidence: "x".repeat(characters) };
}

function match(beforeOccurrenceIds: string[], afterOccurrenceIds: string[]) {
  return {
    beforeOccurrenceIds,
    afterOccurrenceIds,
    confidence: "high" as const,
    reason: "Same synthetic root cause.",
  };
}

test("bounds large comparisons, covers every pair, and joins cross-batch groups", async () => {
  const input: ScanComparisonInput = {
    before: Array.from({ length: 155 }, (_, index) =>
      finding(`before-${index}`),
    ),
    after: Array.from({ length: 64 }, (_, index) => finding(`after-${index}`)),
  };
  expect(JSON.stringify(input).length).toBeGreaterThan(1048576);
  const pairs: string[] = [];
  let calls = 0;
  const result = await matchScanFindings(input, {
    codex: codex((batch, prompt) => {
      calls++;
      expect(prompt.length).toBeLessThanOrEqual(512 * 1024);
      expect(input.before).toEqual(expect.arrayContaining(batch.before));
      expect(input.after).toEqual(expect.arrayContaining(batch.after));
      for (const before of batch.before) {
        for (const after of batch.after) {
          pairs.push(`${before.occurrenceId}:${after.occurrenceId}`);
        }
      }
      return {
        matches: [
          match(
            batch.before.map(({ occurrenceId }) => occurrenceId),
            batch.after.map(({ occurrenceId }) => occurrenceId),
          ),
        ],
        uncertain: [],
      };
    }),
  });
  expect(calls).toBeGreaterThan(1);
  expect(pairs).toHaveLength(input.before.length * input.after.length);
  expect(new Set(pairs).size).toBe(pairs.length);
  expect(result.matches).toHaveLength(1);
  expect(new Set(result.matches[0]!.beforeOccurrenceIds)).toEqual(
    new Set(input.before.map(({ occurrenceId }) => occurrenceId)),
  );
  expect(new Set(result.matches[0]!.afterOccurrenceIds)).toEqual(
    new Set(input.after.map(({ occurrenceId }) => occurrenceId)),
  );
  expect(result.uncertain).toEqual([]);
});

test("joins connected groups and keeps unrelated findings separate", async () => {
  const targets: Record<string, string[]> = {
    one: ["first"],
    two: ["second"],
    bridge: ["first", "second"],
    independent: ["independent"],
    unmatched: [],
  };
  const result = await matchScanFindings(
    {
      before: Object.keys(targets).map((id) => finding(id, 300000)),
      after: ["first", "second", "independent", "new"].map((id) => finding(id)),
    },
    {
      codex: codex(({ before, after }) => {
        const earlier = before[0]!.occurrenceId;
        const later = after
          .map(({ occurrenceId }) => occurrenceId)
          .filter((id) => targets[earlier]!.includes(id));
        return {
          matches: later.length ? [match([earlier], later)] : [],
          uncertain: [],
        };
      }),
    },
  );
  expect(result.matches).toHaveLength(2);
  expect(new Set(result.matches[0]!.beforeOccurrenceIds)).toEqual(
    new Set(["one", "two", "bridge"]),
  );
  expect(new Set(result.matches[0]!.afterOccurrenceIds)).toEqual(
    new Set(["first", "second"]),
  );
  expect(result.matches[1]).toEqual(match(["independent"], ["independent"]));
  expect(result.uncertain).toEqual([]);
});

test.each([false, true])(
  "preserves cross-history uncertainty across batches (allowed: %p)",
  async (allowHistoricalUncertainty) => {
    const uncertain = (
      beforeOccurrenceId: string,
      afterOccurrenceId: string,
    ) => ({
      beforeOccurrenceId,
      afterOccurrenceId,
      reason: "Needs more evidence.",
    });
    const result = await matchScanFindings(
      {
        before: [finding("a", 300000), finding("b", 300000)],
        after: [finding("x", 300000), finding("y", 300000)],
      },
      {
        allowHistoricalUncertainty,
        codex: codex(({ before, after }) => {
          const left = before[0]!.occurrenceId;
          const right = after[0]!.occurrenceId;
          return left === "a" && right === "y"
            ? { matches: [match([left], [right])], uncertain: [] }
            : { matches: [], uncertain: [uncertain(left, right)] };
        }),
      },
    );
    expect(result.matches).toEqual([match(["a"], ["y"])]);
    expect(result.uncertain).toEqual([
      uncertain("b", "x"),
      ...(allowHistoricalUncertainty ? [uncertain("b", "y")] : []),
    ]);
  },
);

test("validates references against the current batch, not the whole input", async () => {
  await expect(
    matchScanFindings(
      {
        before: [finding("first", 300000), finding("other-batch", 300000)],
        after: [finding("after")],
      },
      {
        codex: codex(() => ({
          matches: [match(["other-batch"], ["after"])],
          uncertain: [],
        })),
      },
    ),
  ).rejects.toThrow("unknown before occurrence");
});

test("preserves related findings and known identities across batches", async () => {
  const input: ScanComparisonInput = {
    before: ["first", "second"].map((id) => ({
      ...finding(id, 300000),
      findingId: `finding-${id}`,
    })),
    after: [{ ...finding("after"), findingId: "finding-after" }],
    knownFindingGroups: [["finding-first", "finding-second"]],
  };
  const related = input.before.map(({ occurrenceId }) => ({
    beforeOccurrenceId: occurrenceId,
    afterOccurrenceId: "after",
    reason: "Distinct controls share context.",
  }));
  let calls = 0;
  const result = await matchScanFindings(input, {
    codex: codex((batch) => {
      calls++;
      expect(batch.knownFindingGroups).toEqual(input.knownFindingGroups);
      return {
        matches: [],
        uncertain: [],
        related: related.filter(({ beforeOccurrenceId }) =>
          batch.before.some(
            ({ occurrenceId }) => occurrenceId === beforeOccurrenceId,
          ),
        ),
      };
    }),
  });
  expect(calls).toBe(2);
  expect(result).toEqual({ matches: [], uncertain: [], related });
});

test("rejects cross-batch matches that split a confirmed finding identity", async () => {
  await expect(
    matchScanFindings(
      {
        before: ["first", "second"].map((id) => ({
          ...finding(id, 300000),
          findingId: `finding-${id}`,
        })),
        after: [finding("after-first"), finding("after-second")],
        knownFindingGroups: [["finding-first", "finding-second"]],
      },
      {
        codex: codex(({ before }) => {
          const id = before[0]!.occurrenceId;
          return {
            matches: [match([id], [`after-${id}`])],
            uncertain: [],
          };
        }),
      },
    ),
  ).rejects.toThrow("contradicts previously confirmed finding groups");
});

test("uses Codex's full allowance for individual pairs without truncation", async () => {
  const input = {
    before: [finding("before", 600000)],
    after: [finding("after")],
  };
  const calls: ScanComparisonInput[] = [];
  const options = {
    codex: codex((batch) => {
      calls.push(batch);
      return noMatches;
    }),
  };
  expect(await matchScanFindings(input, options)).toEqual(noMatches);
  expect(calls).toEqual([input]);
  const oversized = {
    before: [finding("before", 1048576)],
    after: [finding("after")],
  };
  await expect(matchScanFindings(oversized, options)).rejects.toThrow(
    "input limit",
  );
  expect(calls).toHaveLength(1);
  expect(oversized.before[0]!.evidence).toHaveLength(1048576);
});

test("stops between batches when canceled", async () => {
  const controller = new AbortController();
  let calls = 0;
  await expect(
    matchScanFindings(
      {
        before: [finding("first", 300000), finding("second", 300000)],
        after: [finding("after")],
      },
      {
        signal: controller.signal,
        codex: codex(() => {
          calls++;
          controller.abort();
          return noMatches;
        }),
      },
    ),
  ).rejects.toThrow();
  expect(calls).toBe(1);
});
