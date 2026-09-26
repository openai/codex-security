#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
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

// Exercise the actual fixture: SQL-shaped text is returned as data, not executed.
const fixturePath = path.resolve(__dirname, "../fixtures/repo/src/server.js");
const routes = new Map();
const app = { get: (route, handler) => routes.set(route, handler) };
vm.runInNewContext(fs.readFileSync(fixturePath, "utf8"), {
  __dirname: path.dirname(fixturePath),
  module: { exports: {} },
  require(name) {
    if (name === "express") return () => app;
    if (name === "path") return path;
    throw new Error("Unexpected fixture dependency: " + name);
  },
}, { filename: fixturePath });
let response;
const query = "' OR 1=1 --";
routes.get("/search")({ query: { q: query } }, { json(value) { response = value; } });
assert.deepEqual(Object.keys(response), ["sql"]);
assert.equal(response.sql, "SELECT id, name FROM products WHERE name LIKE '%" + query + "%'");

const inputCases = fs.readFileSync(path.resolve(__dirname, "../tests/input-types.yaml"), "utf8");
const scannerCase = inputCases.match(/case_id: scanner-query[\s\S]*?(?=\n- description:|$)/)[0];
const scannerContext = { vars: { case_id: "scanner-query" } };
for (const field of ["expected_ids", "expected_source_types", "expected_verdicts"]) {
  scannerContext.vars[field] = scannerCase.match(new RegExp(field + ": (.+)"))[1];
}
function queryVerdict(inputId, verdict) {
  return JSON.parse(outputFor({ inputId, sourceType: "scanner_ticket", verdict }).match(/```json\n([\s\S]*?)\n```/)[1]);
}
const queryOutput = queryVerdict("SCAN-SQL-001", "not_actionable");
queryOutput.findings.push(queryVerdict("SCAN-SQL-TEST-ONLY", "not_actionable").findings[0]);
queryOutput.findings[1].triage_item_id = "triage-002";
assertPasses("a SQL text response is not confirmed SQL injection", JSON.stringify(queryOutput), scannerContext);
queryOutput.findings[0] = queryVerdict("SCAN-SQL-001", "confirmed").findings[0];
assertFails("a missing SQL sink cannot earn a confirmed verdict", JSON.stringify(queryOutput), scannerContext, /expected verdict not_actionable/);

console.log("triage-io assertion tests passed");
