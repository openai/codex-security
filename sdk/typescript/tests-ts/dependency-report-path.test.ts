import { expect, test } from "bun:test";
import { inspectPath } from "../src/exploitability/report/path.js";
import { prepareDependencyReport } from "../src/exploitability/report/model.js";
import {
  stackReport,
  stacksReport,
} from "./support/dependency-stack-report-fixture.js";
import {
  report,
  repositoryReport,
  reviewed,
  sourceRef,
} from "./support/dependency-report-fixtures.js";

const sha = "a".repeat(40);
const path = "src/codec.ts";
function sample() {
  const section = prepareDependencyReport(stacksReport(stackReport()))
    .sections[0]!;
  const finding = section.prepared!.findings.find(
    (f) => f.kind === "stack" && f.assessment.stack,
  )!;
  if (finding.kind !== "stack") throw new Error("Expected sample");
  const observation = finding.assessment.stack!;
  const caller: (typeof observation.frames)[number]["frame"] = {
    name: "handle",
    sourceRevision: sha,
    location: "/app.runfiles/_main/src/codec.ts:3",
  };
  observation.frames.push({ rawIndex: 2, frame: caller });
  const frame = () =>
    inspectPath(finding, section.stack!.target).frames.find(
      (f) => f.rawIndex === 2,
    )!;
  return { finding, observation, caller, frame };
}
test("a different reviewed revision cannot label the captured frame as its call site", () => {
  const { finding, frame } = sample();
  expect(frame().role).toBe("call_site");
  finding.item.evidence[0]!.commit = "d".repeat(40);
  expect(frame().role).toBe("call");
  expect(frame().code?.commit).toBe(sha);
});
test("a missing or stale frame revision cannot borrow the revision of a sibling", () => {
  const { caller, observation, frame } = sample();
  observation.frames[0]!.frame.sourceRevision = sha;
  for (const revision of [undefined, "d".repeat(40)]) {
    caller.sourceRevision = revision;
    expect(frame().code).toBeUndefined();
  }
});
test("exact path and line required; no basename or arbitrary suffix matches", () => {
  const { caller, frame } = sample();
  for (const location of [
    "other/codec.ts:3",
    "/other/src/codec.ts:3",
    "/app.runfiles/lib/src/codec.ts:3",
    "src/codec.ts:4",
  ]) {
    caller.location = location;
    expect(frame().code).toBeUndefined();
  }
  caller.location = path;
  caller.line = 3;
  expect(frame().code?.path).toBe(path);
  caller.location = "src/codec.ts:4";
  expect(frame().code).toBeUndefined();
});
test("source excerpts from a different revision or contradicting the same line never annotate a sample", () => {
  const { frame, finding } = sample();
  const claim = finding.assessment.claims.find((c) => c.sources.length)!;
  const source = claim.sources[0]!;
  source.commit = "d".repeat(40);
  expect(frame().code).toBeUndefined();
  source.commit = sha;
  claim.sources.push({ ...source, text: "return other(bytes);" });
  expect(frame().code).toBeUndefined();
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
  const finding = prepareDependencyReport(repositoryReport(report([use])))
    .sections[0]!.prepared!.findings[0]!;
  const result = inspectPath(finding);
  expect(result.frames.map((f) => f.role)).toEqual(["gap", "gap"]);
  expect(result.initialIndex).toBe(-1);
});
