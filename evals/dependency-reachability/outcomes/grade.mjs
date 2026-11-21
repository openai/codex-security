import assert from "node:assert/strict";
import { selectedReceipt } from "../grade.mjs";
import { buildReportPacket } from "../report-packet.mjs";

const primary = "release_record";
const archive = "archived_release_record";

function sameRecord(value, expected) {
  return (
    value?.service === expected.service &&
    value.revision === expected.revision &&
    value.artifactDigest === expected.artifactDigest
  );
}

function hasRecord(result, expected) {
  if (
    sameRecord(result, expected) ||
    sameRecord(result?.structuredContent, expected)
  )
    return true;
  return result?.content?.some((block) => {
    try {
      return sameRecord(JSON.parse(block.text), expected);
    } catch {
      return false;
    }
  });
}

function hasReceipt(check, expected, tool) {
  const table = check.claimEvidence?.receipts ?? {};
  for (const [id, receipt] of Object.entries(table)) {
    if (receipt.server !== "service_records" || receipt.tool !== tool) continue;
    const { value } = selectedReceipt(table, id);
    if (hasRecord(value, expected)) return true;
  }
  return false;
}

function includesSource(sources, { path, line, endLine = line }) {
  return Object.entries(sources).some(([key, excerpt]) => {
    if (typeof excerpt !== "string") return false;
    const match = /^(.*):(\d+)(?:-(\d+))?$/u.exec(key);
    return (
      match &&
      match[1] === path &&
      Number(match[2]) <= endLine &&
      Number(match[3] ?? match[2]) >= line
    );
  });
}

// Exclude echoed instructions, searches, receipts and source excerpts. A tool
// returning a fact does not show that the investigator reported its result.
function statements(report) {
  const text = [
    ...report.limitations,
    ...report.premises.map((p) => p.statement),
  ];
  for (const row of [...report.uses, ...report.coverage]) {
    text.push(row.version, row.reason, row.location);
    for (const item of row.findingEvidence ?? []) text.push(item.fact);
  }
  return text.join("\n");
}

export function grade({
  fixture,
  expected,
  calls,
  scenario,
  repo,
  output,
  code,
}) {
  assert.equal(expected.service, fixture.service);
  assert.equal(expected.revision, fixture.revision);
  assert.match(expected.artifactDigest, /^sha256:[0-9a-f]{64}$/u);
  const expectBlock = scenario === "persistent" || scenario === "partial";
  const tool = scenario === "alternate" ? archive : primary;
  const scoped = calls.filter(
    (call) =>
      call.arguments?.service === expected.service &&
      call.arguments.revision === expected.revision,
  );
  const firstStatus =
    scenario === "healthy"
      ? "ok"
      : scenario === "partial"
        ? "partial"
        : "rate_limited";
  const exercised =
    scoped[0]?.name === primary && scoped[0].status === firstStatus;
  const received = scoped.some(
    (call) =>
      call.name === tool &&
      call.status === "ok" &&
      sameRecord(call.payload, expected),
  );
  const checks = output.checks ?? [output];
  if (code === 2) {
    const blocked = [...checks, output].find(
      (r) =>
        r.status === "blocked" &&
        r.code === "INVESTIGATION_BLOCKED" &&
        r.reason?.trim(),
    );
    if (!blocked)
      return {
        status: "error",
        passed: false,
        error: "CLI returned no structured block",
      };
    const { reason, blockReason, category } = blocked;
    const justified =
      blockReason === "outcomes_unsatisfied" ||
      category === "widespread_required_data_unavailable";
    if (!justified) return { status: "error", passed: false, error: reason };
    const describesGap = /artifact|digest|inventory|release[_ ]record/iu.test(
      reason,
    );
    return {
      status: "blocked",
      exercised,
      received,
      reason,
      blockReason,
      category,
      describesGap,
      passed: expectBlock && exercised && !received && describesGap,
    };
  }
  assert.equal(code, 0);
  assert.equal(checks.length, 1);
  const [check] = checks;
  assert.notEqual(check.status, "blocked");
  const { report } = buildReportPacket({
    report: { ...check, searches: [], assumptions: [] },
    repo,
    sha: fixture.revision,
  });
  const text = statements(report);
  const version = (
    text.match(/\b\d+\.\d+\.\d+(?:[+-][\w.-]+)?\b/gu) ?? []
  ).includes(fixture.version);
  const bindings = fixture.evidence.map((rule) =>
    includesSource(report.sources, rule),
  );
  const reportedDigest = text.includes(expected.artifactDigest);
  const retainedReceipt = hasReceipt(check, expected, tool);
  const claimsExecution = check.uses.some(
    (use) => use.verdict === "exploitable" || use.deployment === "running",
  );
  return {
    status: "published",
    exercised,
    received,
    version,
    bindings,
    reportedDigest,
    retainedReceipt,
    claimsExecution,
    passed:
      !expectBlock &&
      exercised &&
      received &&
      reportedDigest &&
      retainedReceipt &&
      version &&
      bindings.every(Boolean) &&
      !claimsExecution,
  };
}
