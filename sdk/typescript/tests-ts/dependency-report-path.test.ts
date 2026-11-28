import { expect, test } from "bun:test";
import { inspectPath } from "../src/exploitability/report/path.js";
import { prepareDependencyReport } from "../src/exploitability/report/model.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";
import {
  report,
  reviewed,
  sourceRef,
} from "./support/dependency-report-fixtures.js";

const sha = "a".repeat(40);
const path = "src/codec.ts";
function sample() {
  const section = prepareDependencyReport(stackReport()).sections[0]!;
  const finding = section.prepared!.findings.find(
    (f) => f.kind === "stack" && f.assessment.stack,
  )!;
  if (finding.kind !== "stack") throw new Error("Expected sample");
  const observation = finding.assessment.stack!;
  observation.frames.push(
    { rawIndex: 6, frame: { name: "outside", type: "function" } },
    {
      rawIndex: 2,
      frame: {
        name: "handle",
        sourceRevision: sha,
        type: "function",
        location: "/app.runfiles/_main/src/codec.ts:3",
      },
    },
  );
  return {
    finding,
    observation,
    target: section.stack!.target,
    run: () => inspectPath(finding, section.stack!.target),
  };
}
test("matches the saved caller line, not the third-party sink; preserves original frame positions", () => {
  const { run } = sample();
  const { frames, initialIndex } = run();
  expect(frames.map((f) => [f.role, f.rawIndex, f.omittedBefore])).toEqual([
    ["call", 6, 0],
    ["call", 4, 1],
    ["call_site", 2, 1],
    ["sink", 0, 1],
  ]);
  expect(frames[initialIndex]).toMatchObject({
    rawIndex: 2,
    line: 3,
    code: {
      path,
      commit: sha,
      startLine: 3,
      text: "return decode(bytes);",
      citationIndex: 0,
    },
  });
  expect(frames[3]?.code).toBeUndefined();
});
test("a missing or stale frame revision cannot borrow the revision of a sibling", () => {
  const { run, observation } = sample();
  const caller = observation.frames.find((f) => f.rawIndex === 2)!.frame;
  observation.frames[0]!.frame.sourceRevision = sha;
  for (const revision of [undefined, "d".repeat(40)]) {
    caller.sourceRevision = revision;
    expect(run().frames.find((f) => f.rawIndex === 2)?.code).toBeUndefined();
  }
});
test("exact path and line required; no basename or arbitrary suffix matches", () => {
  const { observation, run } = sample();
  const frame = observation.frames.find((f) => f.rawIndex === 2)!.frame;
  const code = () => run().frames.find((f) => f.rawIndex === 2)?.code;
  for (const location of [
    "other/codec.ts:3",
    "/other/src/codec.ts:3",
    "/app.runfiles/lib/src/codec.ts:3",
    "src/codec.ts:4",
  ]) {
    frame.location = location;
    expect(code()).toBeUndefined();
  }
  frame.location = path;
  frame.line = 3;
  expect(code()?.path).toBe(path);
  frame.location = "src/codec.ts:4";
  expect(code()).toBeUndefined();
});
test("source excerpts from a different revision or contradicting the same line never annotate a sample", () => {
  const { run, finding } = sample();
  const claim = finding.assessment.claims.find((c) => c.sources.length)!;
  const source = claim.sources[0]!;
  const code = () => run().frames.find((f) => f.rawIndex === 2)?.code;
  source.commit = "d".repeat(40);
  expect(code()).toBeUndefined();
  source.commit = sha;
  claim.sources.push({ ...source, text: "return other(bytes);" });
  expect(code()).toBeUndefined();
});
test("a missing or unreviewed source step is a gap, not a selectable call", () => {
  const line = 2;
  const use = reviewed(1, {
    decidingEvidence: [sourceRef("src/handler-1.ts", line)],
    trace: [
      {
        kind: "source",
        label: "Missing",
        site: { path: "different.ts", line },
      },
      { kind: "gap", label: "Producer unknown" },
    ],
  });
  const finding = prepareDependencyReport(report([use])).sections[0]!.prepared!
    .findings[0]!;
  const result = inspectPath(finding);
  expect(result.frames.map((f) => f.role)).toEqual(["gap", "gap"]);
  expect(result.initialIndex).toBe(-1);
});
