import { expect, test } from "bun:test";
import { validationSummary } from "../src/validation-provider-report.js";
import type {
  ValidationItemRecord,
  ValidationProviderAssessment,
} from "../src/validation-provider.js";

function assessment(
  itemId: string,
  fields: Partial<ValidationItemRecord> = {},
): ValidationProviderAssessment {
  return {
    disposition: "reportable",
    provenance: { provider: "continuum", providerVersion: "1" },
    report: "Individual report for " + itemId,
    record: {
      itemId,
      provider: "continuum",
      resultScope: "issue",
      findingId: "aws-" + itemId,
      issueId: "issue",
      issueArn:
        "arn:aws:continuum:region:123456789012:environments/env/code-issues/issue",
      validationArtifactId: "validation",
      scoringArtifactId: "score",
      severityBefore: "high",
      severityAfter: "high",
      providerSeverity: "low",
      claimMatch: "unknown",
      verdict: "EXPLOITABLE",
      reasons: [
        {
          basis: "GRAPH",
          reason:
            "Basis: GRAPH — query_network_reachability returned EXPOSED via arn:aws:elasticloadbalancing:region:123456789012:loadbalancer/app/demo-app/opaque-id",
        },
      ],
      freshness: {
        stale: false,
        reasons: [],
        evidenceCreatedAt: "2026-11-13T00:00:00Z",
        scoredAt: "2026-11-13T00:01:00Z",
      },
      ...fields,
    },
  };
}

test("groups identical issue conclusions without inferring reachability or changing records", () => {
  const items = [assessment("first"), assessment("second")];
  const before = structuredClone(items);
  const summary = validationSummary(items);
  expect(summary).toContain("Items first, second");
  expect(summary).toContain("Issue reachability: unknown.");
  expect(summary).toContain("found public access through demo-app");
  expect(summary).not.toContain("opaque-id");
  expect(summary).not.toContain("\n");
  expect(items).toEqual(before);
});

test.each([
  { issueArn: "another" },
  { resultScope: "finding" },
  { verdict: "NOT_EXPLOITABLE" },
  { validationArtifactId: "other-proof" },
  { scoringArtifactId: "other-score" },
  { freshness: { stale: true, reasons: [] } },
  { providerSeverity: "critical" },
] satisfies Partial<ValidationItemRecord>[])(
  "keeps differing evidence or conclusions separate",
  (fields) => {
    const summary = validationSummary([
      assessment("a"),
      assessment("b", fields),
    ]);
    expect(summary.split("\n")).toHaveLength(2);
  },
);

test("escapes terminal controls in summary rows", () => {
  const summary = validationSummary([
    assessment("id\x1b[2J", { statusMessage: "\r\nforged" }),
  ]);
  expect(summary).toContain("id\\u001b[2J");
  expect(summary).toContain("\\u000d\\u000aforged");
});
