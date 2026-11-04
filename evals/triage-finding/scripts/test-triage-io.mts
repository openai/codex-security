#!/usr/bin/env node
import assert from "assert";
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { parse } from "yaml";
import triageIo from "../assertions/triage-io.mts";
import type { TriageFinding } from "../types.ts";

function findingFor(
  inputId: string,
  verdict: string,
  rank: number | null = verdict === "not_actionable" ? null : 1,
  rankQueue: string | null = verdict === "not_actionable" ? null : verdict,
) {
  return {
    triage_item_id: "triage-001",
    input_id: inputId,
    source_type: "cve",
    title: "Example finding",
    normalized_input: {},
    verdict,
    confidence: "high",
    exploitability_stack_rank: {
      rank,
      rank_queue: rankQueue,
      rationale:
        verdict === "not_actionable" ? "not actionable" : "Example ranking",
      drivers: [],
    },
    affected_locations: [],
    reachable_path: [],
    evidence: [],
    counterevidence: [],
    proof_gaps: [],
    recommended_next_step: "No action",
    fix_finding_handoff: verdict === "confirmed" ? "Fix handoff" : null,
  };
}

const documentFor = (findings: TriageFinding[]) => ({
  schema_version: "triage-finding/v0",
  repository: { path: "/tmp/repo", revision: "abc123" },
  findings,
});

const queueOutput = (findings: TriageFinding[]) =>
  JSON.stringify({ schema_version: "triage-finding/v0", findings });

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

for (const [id, verdict, label, error] of [
  ["input-001", "confirmed", "positive", null],
  ["input-002", "not_actionable", "negative", null],
  ["input-002", "confirmed", "negative", /fixed.*not_actionable|negative/],
] as const) {
  const finding = findingFor(id, verdict);
  const output =
    "```json\n" +
    JSON.stringify(
      documentFor([
        {
          ...finding,
          evidence: label === "positive" ? ["Inline ``` fence in source."] : [],
        },
      ]),
      null,
      2,
    ) +
    "\n```";
  const context = {
    vars: {
      case_id: label === "positive" ? "case-001" : "case-002",
      expected_ids: id,
      expected_source_types: "cve",
      expected_verdicts: verdict,
      expected_binary_label: label,
    },
  };
  if (error)
    assertFails(
      "fixed scanbench case cannot be confirmed",
      output,
      context,
      error,
    );
  else assertPasses(`${verdict} maps to ${label}`, output, context);
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
const scannerContext = (
  parse(inputCases) as { vars: Record<string, string> }[]
).find((item) => item.vars.case_id === "scanner-query")!;
const scannerFinding = (id: string, verdict: string) => ({
  ...findingFor(id, verdict),
  source_type: "scanner_ticket",
});
const queryFindings = [
  scannerFinding("SCAN-SQL-001", "not_actionable"),
  {
    ...scannerFinding("SCAN-SQL-TEST-ONLY", "not_actionable"),
    triage_item_id: "triage-002",
  },
];
assertPasses(
  "a SQL text response is not confirmed SQL injection",
  JSON.stringify(documentFor(queryFindings)),
  scannerContext,
);
queryFindings[0] = scannerFinding("SCAN-SQL-001", "confirmed");
assertFails(
  "a missing SQL sink cannot earn a confirmed verdict",
  JSON.stringify(documentFor(queryFindings)),
  scannerContext,
  /expected verdict not_actionable/,
);

console.log("triage-io assertion tests passed");
