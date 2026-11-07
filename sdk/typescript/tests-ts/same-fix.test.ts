import { expect, test } from "bun:test";
import { checkSameFix } from "../src/same-fix.js";
import { semanticFinding } from "./helpers/semantic-scan.js";

function group(title: string) {
  const finding = semanticFinding({
    title,
    codeEvidence: [
      {
        id: "line",
        label: "Statement",
        path: "src/render.js",
        startLine: 1,
        code: "render(data)",
        explanation: "Both reports cite the same statement.",
      },
    ],
  });
  return { finding, originals: [finding] };
}

const accept = (pair: number) => ({
  pair,
  decision: "same",
  reason: "Same narrow edit",
  leftEvidence: 0,
  rightEvidence: 0,
});
const confirm = (id: number) => ({
  id,
  fixA: "Edit the renderer",
  fixB: "Edit the renderer",
  survivingPaths: [],
  same: true,
});

test("a failed review chunk cannot suppress later confirmations or authorize stale pairs", async () => {
  const groups = Array.from({ length: 7 }, (_, i) => group(String(i)));
  const batches: number[][] = [];
  const errors: unknown[] = [];
  const matches = await checkSameFix(
    groups,
    async (prompt) => {
      const input = JSON.parse(prompt.split("\n").at(-1)!);
      if (!input.pairs)
        return { sources: input.map(({ id }: { id: number }) => confirm(id)) };
      const ids = input.pairs.map(({ id }: { id: number }) => id);
      batches.push(ids);
      if (batches.length === 1) throw new Error("First chunk failed");
      return { reviews: [accept(0), accept(16), accept(17), accept(17)] };
    },
    (error) => errors.push(error),
  );
  expect(batches.map((batch) => batch.length)).toEqual([16, 5]);
  expect(batches.flat()).toEqual(Array.from({ length: 21 }, (_, i) => i));
  expect(errors).toHaveLength(1);
  expect([...matches]).toEqual([[6, new Set([1])]]);
});

test("repeated original evidence is confirmed once while distinct survivor cases stop early", async () => {
  const left = group("Left");
  const right = group("Right");
  for (let i = 0; i < 20; i++) left.originals.push({ ...left.finding });
  const calls: number[] = [];
  const compare = async (prompt: string) => {
    const input = JSON.parse(prompt.split("\n").at(-1)!);
    if (input.pairs) return { reviews: [accept(0)] };
    calls.push(input.length);
    return { sources: [] };
  };
  const fail = (error: unknown) => {
    throw error;
  };
  expect((await checkSameFix([left, right], compare, fail)).size).toBe(0);
  expect(calls).toEqual([1]);
  for (let i = 0; i < 20; i++)
    left.originals.push({ ...left.finding, title: String(i) });
  expect((await checkSameFix([left, right], compare, fail)).size).toBe(0);
  expect(calls).toEqual([1, 4]);
});

test("a separately cited control and an incomplete original survive model approval", async () => {
  const left = group("Shared check");
  const right = group("Additional policy");
  const policy = {
    ...right.finding,
    taxonomy: { category: "policy", cwe: ["CWE-862"] },
    locations: [
      ...right.finding.locations,
      { path: "policy.ts", startLine: 2, role: "control" },
    ],
  };
  const incomplete = {
    finding: right.finding,
    originals: [{ title: "Archived reference" }],
  };
  let calls = 0;
  const matches = await checkSameFix(
    [left, { ...right, originals: [right.finding, policy] }, incomplete],
    async (prompt) => {
      const input = JSON.parse(prompt.split("\n").at(-1)!);
      calls++;
      if (input.pairs) {
        expect(input.pairs).toHaveLength(1);
        return { reviews: [accept(0)] };
      }
      return { sources: input.map(({ id }: { id: number }) => confirm(id)) };
    },
    (error) => {
      throw error;
    },
  );
  expect(calls).toBeGreaterThan(0);
  expect(matches.size).toBe(0);
});

test("the primary evidence includes its immutable identity and excludes repeated attachments", async () => {
  const left = group("Primary");
  const primary = {
    ...left.finding,
    ruleId: "primary-rule",
    attackPath: { summary: "primary attack path" },
    validation: { summary: "primary validation" },
  };
  const secondary = {
    ...primary,
    ruleId: "attached-rule",
    attackPath: { summary: "secondary path" },
  };
  let reviewed = 0;
  await checkSameFix(
    [
      { finding: primary, originals: [primary, { ...primary }, secondary] },
      group("Peer"),
    ],
    async (prompt) => {
      const { reports } = JSON.parse(prompt.split("\n").at(-1)!);
      reviewed++;
      expect(reports[0].primary).toMatchObject({
        ruleId: "primary-rule",
        attackPath: { summary: "primary attack path" },
        validation: { summary: "primary validation" },
      });
      expect(reports[0].attached).toHaveLength(1);
      expect(reports[0].attached[0]).toMatchObject({
        ruleId: "attached-rule",
        attackPath: { summary: "secondary path" },
      });
      return { reviews: [] };
    },
    (error) => {
      throw error;
    },
  );
  expect(reviewed).toBe(1);
});

test("context-limited comparisons retain independent pairs through both review stages", async () => {
  for (const oversizedStage of ["review", "confirmation"]) {
    const errors: unknown[] = [];
    const matches = await checkSameFix(
      [group("First"), group("Second"), group("Oversized")],
      async (prompt) => {
        const input = JSON.parse(prompt.split("\n").at(-1)!);
        if (input.pairs) {
          if (
            oversizedStage === "review" &&
            input.reports.some(
              (report: { primary: { title: string } }) =>
                report.primary.title === "Oversized",
            )
          )
            throw Object.assign(new Error("prompt too long"), {
              code: "context_length_exceeded",
            });
          return {
            reviews: input.pairs.map(({ id }: { id: number }) => accept(id)),
          };
        }
        if (
          oversizedStage === "confirmation" &&
          input.some(
            ({ A, B }: { A: { title: string }; B: { title: string } }) =>
              A.title === "Oversized" || B.title === "Oversized",
          )
        )
          throw new Error("model ran out of room in the context window");
        return { sources: input.map(({ id }: { id: number }) => confirm(id)) };
      },
      (error) => errors.push(error),
    );
    expect(matches).toEqual(new Map([[1, new Set([0])]]));
    expect(errors).toHaveLength(2);
  }
});
