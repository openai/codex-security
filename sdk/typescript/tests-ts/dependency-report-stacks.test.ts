import { expect, test } from "bun:test";
import {
  readStackReport,
  stackFrames,
} from "../src/dependency-report-stacks.js";
import { renderDependencyReport } from "../src/dependency-report-renderer.js";
import { renderDependencyReportMarkdown } from "../src/dependency-report-markdown.js";
import { dependencyClaimHash } from "../src/dependency-stack-claims.js";
import { stackReport } from "./support/dependency-stack-report-fixture.js";

test("projects a sparse observation, query limits and no-match without inventing reviewed uses", () => {
  const input = stackReport();
  const report = readStackReport(input)!;
  expect(report.review).toBeNull();
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

test("only recognizes the stack contract and requires a nullable review", () => {
  expect(readStackReport({ schemaVersion: 2, uses: [] })).toBeUndefined();
  expect(() =>
    readStackReport({ ...stackReport(), review: undefined }),
  ).toThrow();
});

test("reviewed exports preserve each decision and the frozen advisory", () => {
  const input = stackReport();
  const advisory = {
    id: input.cve,
    url: "https://example.org/decoder",
    body: "The decoder requires the optional mode.",
    affected: [],
  };
  const draft = {
    ...input,
    advisoryDetails: [{ ...advisory, sha256: dependencyClaimHash(advisory) }],
  };
  const [observed, missing] = input.assessments;
  const review = {
    draftDigest: dependencyClaimHash(draft),
    decisions: [
      {
        workItemId: missing.workItemId,
        reason: "No runtime observation for the job.",
        followUp: null,
      },
      {
        workItemId: observed.workItemId,
        reason: "Checked configuration and sampled binding.",
        followUp: null,
      },
    ],
  };
  const reviewed = { ...draft, review };
  const report = readStackReport(reviewed)!;
  expect(report.assessments.map((a) => a.reviewReason)).toEqual([
    review.decisions[1]!.reason,
    review.decisions[0]!.reason,
  ]);
  for (const render of [
    renderDependencyReport,
    renderDependencyReportMarkdown,
  ]) {
    const output = render(reviewed);
    expect(output).toContain("Independently reviewed");
    expect(output).toContain(review.draftDigest);
    for (const decision of review.decisions)
      expect(output).toContain(decision.reason);
    expect(output).toContain(advisory.body);
    expect(output).toContain(observed.questionChecks[0]!.checked);
    expect(output).toContain(observed.questionChecks[0]!.missingEvidence);
    expect(output).not.toMatch(
      /finalized offline|omits the advisory description/iu,
    );
    expect(output).not.toContain("RAW_RECEIPT_CONTENT");
    expect(
      render({ ...input, advisoryLookupError: "Registry unavailable." }),
    ).toContain("Registry unavailable.");
  }
});
