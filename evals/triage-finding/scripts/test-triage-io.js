#!/usr/bin/env node
"use strict";

const assert = require("assert");
const triageIo = require("../assertions/triage-io.js");

assert.throws(() => triageIo("no json", {}), {
  message: "Could not find a parseable triage-finding/v0 JSON block.",
});

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

function findingFor(inputId, verdict, rank, rankQueue = verdict) {
  const finding = JSON.parse(outputFor({ inputId, sourceType, verdict }).split("```json")[1].split("```")[0]).findings[0];
  finding.exploitability_stack_rank = { ...finding.exploitability_stack_rank, rank, rank_queue: rankQueue };
  return finding;
}

const queueFindings = [
  findingFor("confirmed-1", "confirmed", 1),
  findingFor("review-1", "needs_review", 1),
  findingFor("confirmed-2", "confirmed", 2),
  findingFor("closed", "not_actionable", null, null),
];
const contextFor = (findings) => ({
  vars: {
    expected_ids: findings.map((finding) => finding.input_id),
    expected_source_types: findings.map((finding) => finding.source_type),
    expected_verdicts: findings.map((finding) => finding.verdict),
  },
});
const queueContext = contextFor(queueFindings);
const queueOutput = (findings) => JSON.stringify({ schema_version: "triage-finding/v0", findings });
assertPasses("independent verdict queues", queueOutput(queueFindings), queueContext);
for (const [verdict, wrongQueue] of [["confirmed", "needs_review"], ["needs_review", "confirmed"], ["confirmed", null]]) {
  const findings = [findingFor("mismatch", verdict, 1, wrongQueue)];
  assertFails("queue matches verdict", queueOutput(findings), contextFor(findings), /rank_queue must match verdict/);
}
for (const rank of [1, 3]) {
  const findings = structuredClone(queueFindings);
  findings[2].exploitability_stack_rank.rank = rank;
  assertFails("ranks remain unique and contiguous", queueOutput(findings), queueContext, /ranks must be contiguous/);
}

console.log("triage-io assertion tests passed");
