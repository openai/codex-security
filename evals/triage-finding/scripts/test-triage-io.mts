#!/usr/bin/env node
import assert from "assert";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import triageIo from "../assertions/triage-io.mts";
import type { TriageFinding } from "../types.ts";

function outputFor({
  inputId,
  verdict,
  sourceType = "cve",
}: {
  inputId: string;
  verdict: string;
  sourceType?: string;
}) {
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

function findingFor(
  inputId: string,
  verdict: string,
  rank: number | null,
  rankQueue: string | null = verdict,
) {
  const finding: TriageFinding = JSON.parse(
    outputFor({ inputId, verdict }).split("```json")[1].split("```")[0],
  ).findings[0];
  finding.exploitability_stack_rank = {
    ...finding.exploitability_stack_rank,
    rank,
    rank_queue: rankQueue,
  };
  return finding;
}

const queueFindings = [
  findingFor("confirmed-1", "confirmed", 1),
  findingFor("review-1", "needs_review", 1),
  findingFor("confirmed-2", "confirmed", 2),
  findingFor("closed", "not_actionable", null, null),
];
const contextFor = (findings: TriageFinding[]) => ({
  vars: {
    expected_ids: findings.map((finding) => finding.input_id),
    expected_source_types: findings.map((finding) => finding.source_type),
    expected_verdicts: findings.map((finding) => finding.verdict),
  },
});
const queueContext = contextFor(queueFindings);
const queueOutput = (findings: TriageFinding[]) =>
  JSON.stringify({ schema_version: "triage-finding/v0", findings });
assertPasses(
  "independent verdict queues",
  queueOutput(queueFindings),
  queueContext,
);
for (const [verdict, wrongQueue] of [
  ["confirmed", "needs_review"],
  ["needs_review", "confirmed"],
  ["confirmed", null],
] as const) {
  const findings = [findingFor("mismatch", verdict, 1, wrongQueue)];
  assertFails(
    "queue matches verdict",
    queueOutput(findings),
    contextFor(findings),
    /rank_queue must match verdict/,
  );
}
for (const rank of [1, 3]) {
  const findings = structuredClone(queueFindings);
  findings[2].exploitability_stack_rank!.rank = rank;
  assertFails(
    "ranks remain unique and contiguous",
    queueOutput(findings),
    queueContext,
    /ranks must be contiguous/,
  );
}
assert.throws(() => triageIo("no json", { vars: {} }), {
  message: "Could not find a parseable triage-finding/v0 JSON block.",
});

// Exercise the actual fixture: SQL-shaped text is returned as data, not executed.
const fixturePath = path.resolve(
  import.meta.dirname,
  "../fixtures/repo/src/server.js",
);
type SearchHandler = (
  request: { query: { q: string } },
  response: { json(value: { sql: string }): void },
) => void;
const routes = new Map<string, SearchHandler>();
const app = {
  get: (route: string, handler: SearchHandler) => routes.set(route, handler),
};
vm.runInNewContext(
  fs.readFileSync(fixturePath, "utf8"),
  {
    __dirname: path.dirname(fixturePath),
    module: { exports: {} },
    require(name: string) {
      if (name === "express") return () => app;
      if (name === "path") return path;
      throw new Error("Unexpected fixture dependency: " + name);
    },
  },
  { filename: fixturePath },
);
let response: { sql: string } | undefined;
const query = "' OR 1=1 --";
routes.get("/search")!(
  { query: { q: query } },
  {
    json(value) {
      response = value;
    },
  },
);
assert.ok(response);
assert.deepEqual(Object.keys(response), ["sql"]);
assert.equal(
  response.sql,
  "SELECT id, name FROM products WHERE name LIKE '%" + query + "%'",
);

const inputCases = fs.readFileSync(
  path.resolve(import.meta.dirname, "../tests/input-types.yaml"),
  "utf8",
);
const scannerCase = inputCases.match(
  /case_id: scanner-query[\s\S]*?(?=\n- description:|$)/,
)![0];
const scannerVars: Record<string, string> = { case_id: "scanner-query" };
const scannerContext = { vars: scannerVars };
for (const field of [
  "expected_ids",
  "expected_source_types",
  "expected_verdicts",
]) {
  scannerVars[field] = scannerCase.match(new RegExp(field + ": (.+)"))![1];
}
function queryVerdict(inputId: string, verdict: string) {
  return JSON.parse(
    outputFor({ inputId, sourceType: "scanner_ticket", verdict }).match(
      /```json\n([\s\S]*?)\n```/,
    )![1],
  );
}
const queryOutput = queryVerdict("SCAN-SQL-001", "not_actionable");
queryOutput.findings.push(
  queryVerdict("SCAN-SQL-TEST-ONLY", "not_actionable").findings[0],
);
queryOutput.findings[1].triage_item_id = "triage-002";
assertPasses(
  "a SQL text response is not confirmed SQL injection",
  JSON.stringify(queryOutput),
  scannerContext,
);
queryOutput.findings[0] = queryVerdict("SCAN-SQL-001", "confirmed").findings[0];
assertFails(
  "a missing SQL sink cannot earn a confirmed verdict",
  JSON.stringify(queryOutput),
  scannerContext,
  /expected verdict not_actionable/,
);

console.log("triage-io assertion tests passed");
