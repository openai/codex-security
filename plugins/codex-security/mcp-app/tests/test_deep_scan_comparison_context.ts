import assert from "node:assert/strict";
import { join } from "node:path";
import { test } from "node:test";
import type { ScanUnion } from "../src/deep-scan/artifact-validation.js";
import { standardScanDraft } from "./deep_scan_coordinator_fixture.ts";
import { importSource } from "./import-module.ts";

const { mergeBatch } = await importSource(
  join(import.meta.dirname, "../src/deep-scan/iteration.ts"),
);

function worker(id: string, titles: string[]) {
  const draft = standardScanDraft("fixture", "finding", id);
  const source = draft.findings[0]!;
  return {
    id,
    resultPath: join("/tmp", id, "result.json"),
    result: {
      ...draft,
      findings: titles.map((title) => ({ ...source, title })),
    },
  };
}

type Row = {
  id: number;
  title: string;
};
function grade(rows: Row[], defect: (row: Row) => string) {
  const groups = Map.groupBy(rows, defect);
  return JSON.stringify({
    uncertain: [],
    defects: [...groups.values()].map((rows) => ({
      operation: "query",
      failure: "check",
      path: "fixture.py",
      reports: rows.map(({ id }) => ({ id, evidence: 0 })),
    })),
  });
}

test("pairwise grades must agree on every member before forming a repair group", async () => {
  const result: ScanUnion = { scanId: "fixture", findings: [] };
  await mergeBatch(
    result,
    [worker("first", ["A", "B", "C"])],
    "/tmp",
    async (prompt: string) => {
      const rows: Row[] = JSON.parse(prompt.split("\n").at(-1)!);
      if (rows.length > 2)
        throw Object.assign(new Error("Input too large"), {
          code: "context_length_exceeded",
        });
      return grade(rows, (row) =>
        rows.some(({ title }) => title === "A") ? "common" : row.title,
      );
    },
    () => {},
  );
  assert.deepEqual(
    result.findings.map(({ title }) => title),
    ["A", "C"],
  );
});

for (const assignment of [
  "overlapping",
  "uncertain",
  "equal at distinct sites",
])
  test(`${assignment} repair assignments still reach disputed review after splitting`, async () => {
    const result: ScanUnion = { scanId: "fixture", findings: [] };
    const observation = worker("first", ["A", "B", "Unrelated"]);
    const findings = observation.result.findings.map((finding) => ({
      ...finding,
      ...(assignment === "equal at distinct sites" && {
        ruleId: finding.title,
        identity: { anchor: finding.title },
      }),
      codeEvidence: [
        {
          id: "site",
          path: "fixture.py",
          label: "query",
          explanation: "call site",
          startLine: 1,
          code: "query()",
        },
      ],
    }));
    let reviewed = 0;
    await mergeBatch(
      result,
      [{ ...observation, result: { ...observation.result, findings } }],
      "/tmp",
      async (prompt: string, schema: { properties: object }) => {
        const input = JSON.parse(prompt.split("\n").at(-1)!);
        if ("reviews" in schema.properties) {
          assert.deepEqual(input.pairs, [{ id: 0, left: 0, right: 1 }]);
          reviewed++;
          return JSON.stringify({
            reviews: [
              { pair: 0, decision: "same", leftEvidence: 0, rightEvidence: 0 },
            ],
          });
        }
        if ("sources" in schema.properties)
          return JSON.stringify({
            sources: [{ id: 0, same: true, survivingPaths: [] }],
          });
        const rows = input as Row[];
        if (rows.length > 2) throw new Error("context_length_exceeded");
        const overlaps = rows.every(({ title }) => title !== "Unrelated");
        const answer = JSON.parse(
          grade(rows, (row) => (overlaps ? "common" : row.title)),
        );
        if (overlaps && assignment === "uncertain")
          return JSON.stringify({
            uncertain: rows.map(({ id }) => id),
            defects: [],
          });
        if (overlaps && assignment === "overlapping")
          answer.defects.push({
            ...answer.defects[0],
            reports: [{ id: 0, evidence: 0 }],
          });
        return JSON.stringify(answer);
      },
      () => {},
    );
    assert.equal(reviewed, 1);
    assert.deepEqual(
      result.findings.map(({ title }) => title),
      assignment === "equal at distinct sites"
        ? ["A", "B", "Unrelated"]
        : ["A", "Unrelated"],
    );
  });

for (const failingPass of ["reviews", "sources"]) {
  test(`oversized disputed ${failingPass} leaves its pair separate and retains completed comparisons`, async () => {
    const { checkSameFix } = await importSource(
      join(import.meta.dirname, "../src/deep-scan/same-fix.ts"),
    );
    const titles = ["Large", "Small", "Alias"];
    const records = titles.map(() => ({
      locations: [["file.ts", 1, 1]],
      evidence: [["file.ts", "read()"]],
    }));
    const errors: Error[] = [];
    const size = new Error("context_length_exceeded");
    const matches = await checkSameFix(
      [
        { id: 0, worker: -1 },
        { id: 1, worker: -1 },
        { id: 2, worker: 0 },
      ],
      [],
      records,
      new Map([
        [0, [1]],
        [1, [1]],
        [2, [1]],
      ]),
      new Map(titles.map((title, id) => [id, [{ title }]])),
      async (prompt: string, schema: { properties: object }) => {
        const rows = JSON.parse(prompt.split("\n").at(-1)!);
        if ("reviews" in schema.properties) {
          const pairs = rows.pairs as { id: number; left: number }[];
          if (failingPass === "reviews" && pairs.some(({ left }) => left === 0))
            throw size;
          return JSON.stringify({
            reviews: pairs.map(({ id }) => ({
              pair: id,
              decision: "same",
              leftEvidence: 0,
              rightEvidence: 0,
            })),
          });
        }
        const claims = rows as { id: number; B: { title: string } }[];
        if (
          failingPass === "sources" &&
          claims.some(({ B }) => B.title === "Large")
        )
          throw size;
        return JSON.stringify({
          sources: claims.map(({ id }) => ({
            id,
            same: true,
            survivingPaths: [],
          })),
        });
      },
      (error: Error) => errors.push(error),
    );
    assert.deepEqual(matches.get(2), new Set([1]));
    assert.equal(errors.length, 1);
    assert.equal(errors[0], size);
  });
}

test("repeated observations are compared once without dropping distinct attack or validation evidence", async () => {
  const left = {
    title: "Left",
    attackPath: { impact: "read", resource: "tenant" },
    validation: { evidence: "test A" },
  };
  const right = { title: "Right" };
  const copies = [
    left,
    { ...left, attackPath: { resource: "tenant", impact: "read" } },
  ];
  const additional = {
    ...left,
    attackPath: { impact: "write" },
    validation: { evidence: "test B" },
  };
  const observed: unknown[] = [];
  const { checkSameFix } = await importSource(
    join(import.meta.dirname, "../src/deep-scan/same-fix.ts"),
  );
  const groups = [
    { id: 0, worker: -1 },
    { id: 1, worker: 0 },
  ];
  const records = groups.map(() => ({
    locations: [["fixture.ts", 1, 1]],
    evidence: [["fixture.ts", "read()"]],
  }));
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
        return JSON.stringify({
          reviews: [
            { pair: 0, decision: "same", leftEvidence: 0, rightEvidence: 0 },
          ],
        });
      }
      for (const { B } of input) observed.push([B.attackPath, B.validation]);
      return JSON.stringify({
        sources: input.map(({ id }: { id: number }) => ({
          same: true,
          survivingPaths: [],
          id,
        })),
      });
    },
    (error: unknown) => {
      throw error;
    },
  );
  assert.deepEqual(observed, [
    [left.attackPath, left.validation],
    [additional.attackPath, additional.validation],
  ]);
  assert.deepEqual(matches.get(1), new Set([0]));
});
