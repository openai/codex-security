import { expect, test } from "bun:test";
import {
  readStackReport,
  stackFrames,
} from "../src/dependency-report-stacks.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

test("projects a sparse observation, query limits and no-match without inventing reviewed uses", () => {
  const input = stackReport();
  const report = readStackReport(input)!;
  expect(report.reviewPolicy).toBe("single_agent");
  expect(report.coverage).toEqual(input.coverage);
  expect(report).not.toHaveProperty("uses");
  const [path, missing] = report.assessments;
  expect(path?.scope.service).toBe("uploader");
  expect(path?.queryScope.service).toBeUndefined();
  expect(path?.observation).toEqual(input.assessments[0].observation);
  expect(
    stackFrames(path!.observation!).map(
      ({ rawIndex, source, sink, omittedBefore }) => ({
        rawIndex,
        source,
        sink,
        omittedBefore,
      }),
    ),
  ).toEqual([
    { rawIndex: 4, source: true, sink: false, omittedBefore: 0 },
    { rawIndex: 0, source: false, sink: true, omittedBefore: 3 },
  ]);
  expect(path?.reason).toBe(input.assessments[0].reason);
  expect(path?.use?.reason).toBe(input.assessments[0].use.reason);
  expect(path?.claims.map((c) => c.id)).toEqual(["copy", "call"]);
  expect(path?.claims[1]?.sources[0]?.text).toBe("return decode(bytes);");
  expect(JSON.stringify(report)).not.toContain("RAW_RECEIPT_CONTENT");
  expect(missing?.claims).toEqual([]);
  expect(missing?.observation).toBeNull();
  expect(missing?.use).toBeUndefined();
});

test("does not attach a different revision or hash in place of missing evidence", () => {
  const input = stackReport();
  const call = input.claims[1]!;
  input.claims.splice(
    1,
    1,
    { ...call, revision: call.revision + 1 },
    { ...call, hash: "f".repeat(64) },
  );
  const path = readStackReport(input)!.assessments[0]!;
  expect(path.claims.map((c) => c.id)).toEqual(["copy"]);
  expect(path.missingClaims).toEqual(input.claims[0]!.dependencies);
});

test("only recognizes the stack contract and rejects conflicting review policies", () => {
  expect(readStackReport({ schemaVersion: 2, uses: [] })).toBeUndefined();
  expect(() =>
    readStackReport({ ...stackReport(), reviewPolicy: "independent_review" }),
  ).toThrow();
});
