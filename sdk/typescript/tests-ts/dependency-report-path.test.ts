import { expect, test } from "bun:test";
import { inspectPath } from "../src/dependency/report/path.js";
import { prepareDependencyReport } from "../src/dependency/report/model.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";
import {
  report,
  reviewed,
  sourceRef,
} from "./support/dependency-report-fixtures.js";

const sha = "a".repeat(40);
const digest = "sha256:" + "1".repeat(64);
const path = "src/codec.ts";
const sourceBinding = {
  package: "example",
  version: sha,
  sourceSha: sha,
  provenance: "image metadata",
  imageDigest: digest,
};
function sample() {
  const section = prepareDependencyReport(stackReport()).sections[0]!;
  const finding = section.prepared!.findings.find(
    (f) => f.kind === "stack" && f.assessment.observation,
  )!;
  if (finding.kind !== "stack") throw new Error("Expected sample");
  const observation = finding.assessment.observation!;
  observation.frames.push(
    { rawIndex: 6, frame: { name: "outside", type: "function" } },
    {
      rawIndex: 2,
      frame: {
        name: "handle",
        type: "function",
        location: "/app.runfiles/_main/src/codec.ts:3",
      },
    },
  );
  observation.bindings.push({ ...sourceBinding });
  finding.assessment.scope.image_digest = digest;
  return {
    finding,
    observation,
    target: section.stack!.target,
    run: () => inspectPath(finding, section.stack!.target),
  };
}
test("matches the saved caller line, not the third-party sink; preserves raw gaps and range", () => {
  const { run } = sample();
  const { frames, initialIndex } = run();
  expect(
    frames.map((f) => [f.role, f.rawIndex, f.inRange, f.omittedBefore]),
  ).toEqual([
    ["call", 6, false, 0],
    ["source", 4, true, 1],
    ["call_site", 2, true, 1],
    ["sink", 0, true, 1],
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
test("refuses a stale image or revision, missing or conflicting bindings, and bindings for other frames", () => {
  const { run, observation } = sample();
  const code = () => run().frames.find((f) => f.rawIndex === 2)?.code;
  const other = { ...sourceBinding, sourceSha: "d".repeat(40) };
  for (const bindings of [
    [],
    [other],
    [sourceBinding, other],
    [{ ...sourceBinding, imageDigest: "sha256:" + "2".repeat(64) }],
    [{ ...sourceBinding, frameIndices: [0] }],
    [
      sourceBinding,
      {
        package: "dependency",
        provenance: "sample",
        version: "1",
        frameIndices: [2],
      },
    ],
  ]) {
    observation.bindings = bindings;
    expect(code()).toBeUndefined();
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
