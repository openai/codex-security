#!/usr/bin/env node
"use strict";

const assert = require("assert");
const triageIo = require("../assertions/triage-io.js");

function outputFor({ inputId, sourceType, verdict }) {
  const stackRank = {
    rank_queue: verdict === "not_actionable" ? null : verdict,
    rank: verdict === "not_actionable" ? null : 1,
    rationale: verdict === "not_actionable" ? "not actionable" : "Example ranking",
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

function baseContext({ caseId, inputId, sourceType, expectedVerdict, expectedBinaryLabel }) {
  return {
    vars: {
      case_id: caseId,
      expected_ids: inputId,
      expected_source_types: sourceType,
      expected_verdicts: expectedVerdict,
      expected_binary_label: expectedBinaryLabel,
    },
  };
}

function assertPasses(name, output, context) {
  const result = triageIo(output, context);
  assert.equal(result.pass, true, `${name}: ${result.reason}`);
}

function assertFails(name, output, context, expectedReason) {
  const result = triageIo(output, context);
  assert.equal(result.pass, false, `${name}: expected assertion to fail`);
  assert.match(result.reason, expectedReason, `${name}: unexpected failure reason`);
}

const sourceType = "cve";

assertPasses(
  "vulnerable scanbench cases map to confirmed/positive",
  outputFor({ inputId: "GHSA-example-000-vulnerable", sourceType, verdict: "confirmed" }),
  baseContext({
    caseId: "ghsa-example-vulnerable",
    inputId: "GHSA-example-000-vulnerable",
    sourceType,
    expectedVerdict: "confirmed",
    expectedBinaryLabel: "positive",
  }),
);

assertPasses(
  "fixed scanbench cases map to not_actionable/negative",
  outputFor({ inputId: "GHSA-example-000-fixed", sourceType, verdict: "not_actionable" }),
  baseContext({
    caseId: "ghsa-example-fixed",
    inputId: "GHSA-example-000-fixed",
    sourceType,
    expectedVerdict: "not_actionable",
    expectedBinaryLabel: "negative",
  }),
);

assertFails(
  "fixed scanbench cases cannot be labeled confirmed",
  outputFor({ inputId: "GHSA-example-000-fixed", sourceType, verdict: "confirmed" }),
  baseContext({
    caseId: "ghsa-example-fixed",
    inputId: "GHSA-example-000-fixed",
    sourceType,
    expectedVerdict: "confirmed",
    expectedBinaryLabel: "positive",
  }),
  /fixed.*not_actionable|negative/,
);

console.log("triage-io assertion tests passed");
