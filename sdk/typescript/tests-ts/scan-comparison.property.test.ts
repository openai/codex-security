import { describe, expect, test } from "bun:test";
import fc from "fast-check";
import {
  matchScanFindings,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";
import { propertyOptions } from "./support/property.js";

const identities = fc.uniqueArray(fc.uuid(), { minLength: 2, maxLength: 8 });

function fixture(ids: string[]) {
  const input: ScanComparisonInput = {
    before: ids.map((id) => ({ occurrenceId: `before-${id}` })),
    after: ids.map((id) => ({ occurrenceId: `after-${id}` })),
  };
  const result: ScanComparisonResult = {
    matches: ids.slice(1).map((id) => ({
      beforeOccurrenceIds: [`before-${id}`],
      afterOccurrenceIds: [`after-${id}`],
      confidence: "high",
      reason: "same synthetic control",
    })),
    uncertain: [
      {
        beforeOccurrenceId: `before-${ids[0]}`,
        afterOccurrenceId: `after-${ids[0]}`,
        reason: "needs more evidence",
      },
    ],
  };
  return { input, result };
}

function compare(
  input: ScanComparisonInput,
  response: unknown,
  options: Pick<ScanComparisonOptions, "allowHistoricalUncertainty"> = {},
) {
  return matchScanFindings(input, {
    ...options,
    codex: {
      startThread: () => ({
        run: async () => ({ finalResponse: JSON.stringify(response) }),
      }),
    },
  });
}

describe("finding-comparison invariants", () => {
  test("keeps transitive identity groups separate across repeated occurrences", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.array(
          fc.record({
            before: fc.integer({ min: 0, max: 4 }),
            after: fc.integer({ min: 0, max: 4 }),
          }),
          { minLength: 1, maxLength: 20 },
        ),
        async (counts) => {
          const before = counts.flatMap((count, group) =>
            Array.from({ length: count.before }, (_, occurrence) => ({
              occurrenceId: `before-${group}-${occurrence}`,
              findingId: `old-${group}`,
            })),
          );
          const after = counts.flatMap((count, group) =>
            Array.from({ length: count.after }, (_, occurrence) => ({
              occurrenceId: `after-${group}-${occurrence}`,
              findingId: `new-${group}`,
            })),
          );
          const knownFindingGroups = counts.flatMap((_, group) => [
            [`old-${group}`, `historical-${group}`],
            [`historical-${group}`, `new-${group}`],
          ]);
          const expected = counts
            .flatMap((count, group) =>
              count.before > 0 && count.after > 0
                ? [
                    [
                      Array.from(
                        { length: count.before },
                        (_, occurrence) => `before-${group}-${occurrence}`,
                      ),
                      Array.from(
                        { length: count.after },
                        (_, occurrence) => `after-${group}-${occurrence}`,
                      ),
                    ],
                  ]
                : [],
            )
            .sort();

          for (const input of [
            { before, after, knownFindingGroups },
            {
              before: [...before].reverse(),
              after: [...after].reverse(),
              knownFindingGroups: [...knownFindingGroups].reverse(),
            },
          ]) {
            const result = await compare(input, {
              matches: [],
              uncertain: [],
            });
            expect(
              result.matches
                .map(({ beforeOccurrenceIds, afterOccurrenceIds }) => [
                  [...beforeOccurrenceIds].sort(),
                  [...afterOccurrenceIds].sort(),
                ])
                .sort(),
            ).toEqual(expected);
            expect(result.uncertain).toEqual([]);
          }
        },
      ),
      propertyOptions,
    );
  });

  test("preserves valid identities regardless of finding order", async () => {
    await fc.assert(
      fc.asyncProperty(identities, async (ids) => {
        const { input, result } = fixture(ids);
        await expect(compare(input, result)).resolves.toEqual(result);
        await expect(
          compare(
            {
              before: [...input.before].reverse(),
              after: [...input.after].reverse(),
            },
            result,
          ),
        ).resolves.toEqual(result);
      }),
      propertyOptions,
    );
  });

  test("rejects invented identities and duplicate confirmed assignments", async () => {
    await fc.assert(
      fc.asyncProperty(identities, async (ids) => {
        const { input, result } = fixture(ids);
        const first = result.matches[0]!;
        for (const side of [
          "beforeOccurrenceIds",
          "afterOccurrenceIds",
        ] as const) {
          await expect(
            compare(input, {
              ...result,
              matches: [{ ...first, [side]: ["unknown-synthetic-occurrence"] }],
            }),
          ).rejects.toThrow(/unknown .* occurrence/u);
          await expect(
            compare(input, {
              ...result,
              matches: [
                { ...first, [side]: [...first[side], first[side][0]!] },
              ],
            }),
          ).rejects.toThrow(/more than once/u);
        }
        await expect(
          compare(input, { ...result, matches: [...result.matches, first] }),
        ).rejects.toThrow(/more than once/u);
      }),
      propertyOptions,
    );
  });

  test("keeps uncertain pairs unique and separate from confirmed matches", async () => {
    await fc.assert(
      fc.asyncProperty(identities, async (ids) => {
        const { input, result } = fixture(ids);
        const uncertain = result.uncertain[0]!;
        await expect(
          compare(input, { ...result, uncertain: [uncertain, uncertain] }),
        ).rejects.toThrow(/duplicate uncertain pair/u);
        const overlapsAfter = {
          ...uncertain,
          afterOccurrenceId: result.matches[0]!.afterOccurrenceIds[0]!,
        };
        const historical = { ...result, uncertain: [overlapsAfter] };
        await expect(compare(input, historical)).rejects.toThrow(
          /invalid uncertain pair/u,
        );
        await expect(
          compare(input, historical, { allowHistoricalUncertainty: true }),
        ).resolves.toEqual(historical);
        await expect(
          compare(
            input,
            {
              ...result,
              uncertain: [
                {
                  ...uncertain,
                  beforeOccurrenceId:
                    result.matches[0]!.beforeOccurrenceIds[0]!,
                },
              ],
            },
            { allowHistoricalUncertainty: true },
          ),
        ).rejects.toThrow(/invalid uncertain pair/u);
      }),
      propertyOptions,
    );
  });
});
