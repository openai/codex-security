import type { AssertionContext } from "../types.ts";
import {
  gradeFailures,
  extractTriageResult,
  parseExpected,
} from "./output.mts";

export default (output: unknown, context: AssertionContext) => {
  const result = extractTriageResult(
    output,
    "Could not find a parseable triage-finding/v0 JSON block.",
  );
  const expectedIds = parseExpected(context.vars.expected_ids);
  const expectedSourceTypes = parseExpected(context.vars.expected_source_types);
  const expectedVerdicts = parseExpected(context.vars.expected_verdicts);
  const failures = [];

  const binaryLabel = String(context.vars.expected_binary_label || "");
  if (binaryLabel === "positive" || binaryLabel === "negative") {
    const expectedVerdict =
      binaryLabel === "positive" ? "confirmed" : "not_actionable";
    if (
      expectedVerdicts.length === 1 &&
      expectedVerdicts[0] !== expectedVerdict
    ) {
      failures.push(
        `${binaryLabel} scanbench label: expected_verdicts must be ${expectedVerdict}, got ${expectedVerdicts[0]}`,
      );
    }
    if (
      context.vars.expected_binary_label &&
      context.vars.expected_binary_label !== binaryLabel
    ) {
      failures.push(
        `${binaryLabel} scanbench label: expected_binary_label must be ${binaryLabel}, got ${context.vars.expected_binary_label}`,
      );
    }
  }

  if (!Array.isArray(result.findings)) {
    failures.push("findings is not an array");
  } else if (result.findings.length !== expectedIds.length) {
    failures.push(
      `expected ${expectedIds.length} findings, got ${result.findings.length}`,
    );
  }

  const findings = Array.isArray(result.findings) ? result.findings : [];
  const ranksByQueue = new Map<
    string | null | undefined,
    { label: string; rank: number }[]
  >();
  findings.forEach((finding, index) => {
    const label = expectedIds[index] || `index ${index}`;

    for (const [field, expected] of [
      ["input_id", expectedIds[index]],
      ["source_type", expectedSourceTypes[index]],
      ["verdict", expectedVerdicts[index]],
    ] as const) {
      if (finding[field] !== expected) {
        failures.push(
          `${label}: expected ${field} ${expected}, got ${finding[field]}`,
        );
      }
    }

    const rank = finding.exploitability_stack_rank?.rank;
    const rankQueue = finding.exploitability_stack_rank?.rank_queue;
    if (finding.verdict === "not_actionable") {
      if (rank !== null || rankQueue !== null) {
        failures.push(
          `${label}: not_actionable finding must use null rank and rank_queue`,
        );
      }
    } else if (rankQueue !== finding.verdict) {
      failures.push(
        `${label}: rank_queue must match verdict ${finding.verdict}`,
      );
    } else if (!Number.isInteger(rank) || rank! < 1) {
      failures.push(
        `${label}: actionable or unresolved finding must use a positive integer rank`,
      );
    } else {
      const ranks = ranksByQueue.get(rankQueue) || [];
      ranks.push({ label, rank: rank! });
      ranksByQueue.set(rankQueue, ranks);
    }

    for (const field of [
      "affected_locations",
      "reachable_path",
      "evidence",
      "counterevidence",
      "proof_gaps",
    ]) {
      if (!Array.isArray(finding[field])) {
        failures.push(`${label}: ${field} is not an array`);
      }
    }

    const handoff = finding.fix_finding_handoff;
    if (finding.verdict === "confirmed") {
      if (typeof handoff !== "string" || handoff.trim().length === 0) {
        failures.push(
          `${label}: confirmed finding must include a non-empty fix_finding_handoff`,
        );
      }
    } else if (
      handoff !== null &&
      !(typeof handoff === "string" && handoff.trim().length === 0)
    ) {
      failures.push(
        `${label}: non-confirmed finding must not include a fix_finding_handoff`,
      );
    }
  });

  for (const [rankQueue, ranks] of ranksByQueue) {
    ranks.sort((left, right) => left.rank - right.rank);
    ranks.forEach(({ label, rank }, index) => {
      const expectedRank = index + 1;
      if (rank !== expectedRank) {
        failures.push(
          `${label}: ${rankQueue} ranks must be contiguous from 1; expected ${expectedRank}, got ${rank}`,
        );
      }
    });
  }

  return gradeFailures(
    failures,
    "Triage I/O matched expected source types, order, and verdicts.",
  );
};
