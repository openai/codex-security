import assert from "node:assert/strict";
import { join } from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";

const { checkSameFix } = await importSource(
  join(import.meta.dirname, "../src/deep-scan/same-fix.ts"),
);
const records = [0, 1].map(() => ({
  locations: [["fixture.ts", 1, 1]],
  evidence: [["fixture.ts", "lookup(id)"]],
}));
const groups = [
  { id: 0, worker: -1 },
  { id: 1, worker: 0 },
];
const review = { pair: 0, decision: "same", leftEvidence: 0, rightEvidence: 0 };
const confirmation = { id: 0, same: true, survivingPaths: [] };

for (const pass of [
  "pair review",
  "source confirmation",
  "non-boolean confirmation",
]) {
  test(`contradictory ${pass} preserves the two findings`, async () => {
    const matches = await checkSameFix(
      groups,
      [],
      records,
      new Map(),
      new Map([
        [0, [{ title: "Left" }]],
        [1, [{ title: "Right" }]],
      ]),
      async (_prompt: string, schema: { properties: object }) =>
        JSON.stringify(
          "reviews" in schema.properties
            ? {
                reviews:
                  pass === "pair review"
                    ? [review, { ...review, decision: "keep" }]
                    : [review],
              }
            : {
                sources:
                  pass === "source confirmation"
                    ? [confirmation, { ...confirmation, same: false }]
                    : [
                        {
                          ...confirmation,
                          same:
                            pass === "non-boolean confirmation"
                              ? "false"
                              : true,
                        },
                      ],
              },
        ),
      assert.fail,
    );
    assert.equal(matches.size, 0);
  });
}

test("repeated observations are compared once without dropping distinct attack or validation evidence", async () => {
  const left = {
    title: "Left",
    attackPath: { impact: "read" },
    validation: { evidence: "test A" },
  };
  const right = { title: "Right" };
  const copies = Array.from({ length: 10 }, () => structuredClone(left));
  const additional = {
    ...left,
    attackPath: { impact: "write" },
    validation: { evidence: "test B" },
  };
  const observed: unknown[] = [];
  const matches = await checkSameFix(
    groups,
    [],
    records,
    new Map(),
    new Map([
      [0, [...copies, additional]],
      [1, [right, right]],
    ]),
    async (prompt: string, schema: { properties: object }) => {
      const input = JSON.parse(prompt.split("\n").at(-1)!);
      if ("reviews" in schema.properties) {
        assert.equal(input.reports[0].attached.length, 1);
        return JSON.stringify({ reviews: [review] });
      }
      for (const { B } of input) observed.push([B.attackPath, B.validation]);
      return JSON.stringify({
        sources: input.map(({ id }: { id: number }) => ({
          ...confirmation,
          id,
        })),
      });
    },
    assert.fail,
  );
  assert.deepEqual(observed, [
    [left.attackPath, left.validation],
    [additional.attackPath, additional.validation],
  ]);
  assert.deepEqual(matches.get(1), new Set([0]));
});
