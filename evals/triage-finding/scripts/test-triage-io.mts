#!/usr/bin/env node
import assert from "assert";
import triageIo from "../assertions/triage-io.mts";

function outputFor({ inputId, verdict }: { inputId: string; verdict: string }) {
  const stackRank = {
    rank_queue: verdict === "not_actionable" ? null : verdict,
    rank: verdict === "not_actionable" ? null : 1,
    rationale:
      verdict === "not_actionable" ? "not actionable" : "Example ranking",
    drivers: [],
  };
  return `\`\`\`json
{
  "schema_version": "triage-finding/v0",
  "repository": {
    "path": "/tmp/repo",
    "revision": "abc123"
  },
  "findings": [
    {
      "triage_item_id": "triage-001",
      "input_id": "${inputId}",
      "source_type": "${sourceType}",
      "title": "Example finding",
      "normalized_input": {},
      "verdict": "${verdict}",
      "confidence": "high",
      "exploitability_stack_rank": ${JSON.stringify(stackRank)},
      "affected_locations": [],
      "reachable_path": [],
      "evidence": [],
      "counterevidence": [],
      "proof_gaps": [],
      "recommended_next_step": "No action",
      "fix_finding_handoff": ${verdict === "confirmed" ? JSON.stringify("Fix handoff") : "null"}
    }
  ]
}
\`\`\``;
}

function assertPasses(
  name: string,
  output: unknown,
  context: import("../types.ts").AssertionContext,
) {
  const result = triageIo(output, context);
  assert.equal(result.pass, true, `${name}: ${result.reason}`);
}

function assertFails(
  name: string,
  output: unknown,
  context: import("../types.ts").AssertionContext,
  expectedReason: RegExp,
) {
  const result = triageIo(output, context);
  assert.equal(result.pass, false, `${name}: expected assertion to fail`);
  assert.match(
    result.reason,
    expectedReason,
    `${name}: unexpected failure reason`,
  );
}

const sourceType = "cve";

assertPasses(
  "vulnerable scanbench cases map to confirmed/positive",
  outputFor({
    inputId: "GHSA-example-000-vulnerable",
    verdict: "confirmed",
  }),
  {
    vars: {
      case_id: "ghsa-example-vulnerable",
      expected_ids: "GHSA-example-000-vulnerable",
      expected_source_types: sourceType,
      expected_verdicts: "confirmed",
      expected_binary_label: "positive",
    },
  },
);

assertPasses(
  "fixed scanbench cases map to not_actionable/negative",
  outputFor({
    inputId: "GHSA-example-000-fixed",
    verdict: "not_actionable",
  }),
  {
    vars: {
      case_id: "ghsa-example-fixed",
      expected_ids: "GHSA-example-000-fixed",
      expected_source_types: sourceType,
      expected_verdicts: "not_actionable",
      expected_binary_label: "negative",
    },
  },
);

assertFails(
  "fixed scanbench cases cannot be labeled confirmed",
  outputFor({
    inputId: "GHSA-example-000-fixed",
    verdict: "confirmed",
  }),
  {
    vars: {
      case_id: "ghsa-example-fixed",
      expected_ids: "GHSA-example-000-fixed",
      expected_source_types: sourceType,
      expected_verdicts: "confirmed",
      expected_binary_label: "positive",
    },
  },
  /fixed.*not_actionable|negative/,
);

assert.throws(() => triageIo("no json", { vars: {} }), {
  message: "Could not find a parseable triage-finding/v0 JSON block.",
});

console.log("triage-io assertion tests passed");
