import { expect, test } from "bun:test";
import {
  validationReport,
  validationText,
} from "../src/validation-provider-report.js";
import type { ValidationProviderAssessment } from "../src/validation-provider.js";

const assessment = (id: string): ValidationProviderAssessment => ({
  disposition: "reportable",
  report: "unused",
  provenance: {
    provider: "continuum",
    providerVersion: "1",
    validatedAt: "2026-01-01T00:00:00Z",
  },
  record: {
    itemId: id,
    provider: "continuum",
    state: "validated",
    codexSeverity: "high",
    reasons: [],
    issue: {
      id: "issue-1",
      url: "https://example.com/issues/issue-1",
      title: "Missing ownership check",
      severity: "critical",
      verdict: "EXPLOITABLE",
      findingCount: 2,
      reachableFromAttacker: true,
      reachabilityBasis: "GRAPH",
      reachabilityReason: "The route accepts requests from untrusted callers.",
      checkedBy: "executed proof",
      validatedAt: "2026-01-01T00:00:00Z",
      validationBeforeSubmission: true,
    },
  },
});
test("groups two occurrences under one issue with the headline first", () => {
  const result = validationReport(
    ["first", "second"].map((id, index) => ({
      id,
      title: "Ownership check is missing",
      summary: "Another user's record is returned.",
      locations: [{ path: "src/route.ts", startLine: index + 10 }],
    })),
    [assessment("first"), assessment("second")],
  );
  expect(result.report.match(/^## /gmu)).toHaveLength(1);
  expect(result.report).toStartWith(
    "## Ownership check is missing\n\n**Continuum: exploitable, Critical, reachable from an attacker.** Codex rated these occurrences High.",
  );
  expect(result.report).toContain("src/route.ts:10");
  expect(result.report).toContain("src/route.ts:11");
  expect(result.report.match(/\*\*Scope:\*\*/gu)).toHaveLength(1);
  expect(result.report).toContain(
    "before this submission; Continuum had already validated the issue",
  );
  expect(result.summary.split("\n")).toHaveLength(1);
  expect(result.items).toHaveLength(2);
});
test("a named negative finding result remains visible beside an exploitable issue", () => {
  const item = assessment("first");
  item.record!.findingResult = { verdict: "NOT_EXPLOITABLE" };
  const result = validationReport([{ title: "Ownership check" }], [item]);
  expect(result.report).toContain("Continuum: exploitable");
  expect(result.report).toContain(
    "For this finding specifically (first):** Continuum returned not exploitable",
  );
});
test("shortens prose at boundaries without splitting a URL or ARN", () => {
  expect(
    validationText("One sentence. Another long sentence follows here.", 28),
  ).toBe("One sentence.…");
  expect(
    validationText(
      "See https://example.com/very/long/resource/name for details.",
      25,
    ),
  ).toBe("See…");
  expect(
    validationText(
      "Uses arn:aws:service:region:123456789012:resources/resource-name safely.",
      80,
    ),
  ).toBe("Uses resource-name safely.");
});
test("an unavailable occurrence does not hide another occurrence's ready issue result", () => {
  const waiting = assessment("first");
  waiting.record!.state = "unavailable";
  waiting.record!.unavailable = "A read failed.";
  const result = validationReport([{}, {}], [waiting, assessment("second")]);
  expect(result.summary).toContain("Continuum: exploitable, Critical");
  expect(result.report).toContain(
    "Occurrence first:** Continuum is unavailable",
  );
});

test("unknown reachability is not inferred from the reason", () => {
  const item = assessment("first");
  delete item.record!.issue!.reachableFromAttacker;
  item.record!.issue!.reachabilityReason = "NOT_EXPOSED cannot be established.";
  expect(validationReport([{}], [item]).summary).toContain(
    "reachability unknown",
  );
});
