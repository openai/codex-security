function parseExpected(value) {
  if (Array.isArray(value)) {
    return value.map(String);
  }
  if (typeof value === "string") {
    return value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
}

function expectedScanbenchMapping(context) {
  const caseId = String(context.vars.case_id || "");
  const label = String(context.vars.expected_binary_label || "");
  const mappings = [];

  if (caseId.endsWith("-vulnerable")) {
    mappings.push({
      expectedVerdict: "confirmed",
      expectedBinaryLabel: "positive",
      label: "vulnerable scanbench case",
    });
  } else if (caseId.endsWith("-fixed")) {
    mappings.push({
      expectedVerdict: "not_actionable",
      expectedBinaryLabel: "negative",
      label: "fixed scanbench case",
    });
  }

  if (label === "positive") {
    mappings.push({
      expectedVerdict: "confirmed",
      expectedBinaryLabel: "positive",
      label: "positive scanbench label",
    });
  } else if (label === "negative") {
    mappings.push({
      expectedVerdict: "not_actionable",
      expectedBinaryLabel: "negative",
      label: "negative scanbench label",
    });
  }

  return mappings;
}

function extractJson(output) {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const fencedBlocks = [...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/gi)].map((match) =>
    match[1].trim(),
  );
  const candidates = fencedBlocks.length > 0 ? fencedBlocks : [text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1)];

  for (const candidate of candidates) {
    if (!candidate) {
      continue;
    }
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && parsed.schema_version === "triage-finding/v0") {
        return parsed;
      }
    } catch {
      // Keep trying other candidates.
    }
  }

  throw new Error("Could not find a parseable triage-finding/v0 JSON block.");
}

module.exports = (output, context) => {
  const result = extractJson(output);
  const expectedIds = parseExpected(context.vars.expected_ids);
  const expectedSourceTypes = parseExpected(context.vars.expected_source_types);
  const expectedVerdicts = parseExpected(context.vars.expected_verdicts);
  const failures = [];

  for (const mapping of expectedScanbenchMapping(context)) {
    if (expectedVerdicts.length === 1 && expectedVerdicts[0] !== mapping.expectedVerdict) {
      failures.push(
        `${mapping.label}: expected_verdicts must be ${mapping.expectedVerdict}, got ${expectedVerdicts[0]}`,
      );
    }
    if (
      context.vars.expected_binary_label &&
      context.vars.expected_binary_label !== mapping.expectedBinaryLabel
    ) {
      failures.push(
        `${mapping.label}: expected_binary_label must be ${mapping.expectedBinaryLabel}, got ${context.vars.expected_binary_label}`,
      );
    }
  }

  if (!Array.isArray(result.findings)) {
    failures.push("findings is not an array");
  } else if (result.findings.length !== expectedIds.length) {
    failures.push(`expected ${expectedIds.length} findings, got ${result.findings.length}`);
  }

  const findings = Array.isArray(result.findings) ? result.findings : [];
  const ranksByQueue = new Map();
  findings.forEach((finding, index) => {
    const label = expectedIds[index] || `index ${index}`;

    if (finding.input_id !== expectedIds[index]) {
      failures.push(`${label}: expected input_id ${expectedIds[index]}, got ${finding.input_id}`);
    }
    if (finding.source_type !== expectedSourceTypes[index]) {
      failures.push(`${label}: expected source_type ${expectedSourceTypes[index]}, got ${finding.source_type}`);
    }
    if (finding.verdict !== expectedVerdicts[index]) {
      failures.push(`${label}: expected verdict ${expectedVerdicts[index]}, got ${finding.verdict}`);
    }

    const rank = finding.exploitability_stack_rank?.rank;
    const rankQueue = finding.exploitability_stack_rank?.rank_queue;
    if (finding.verdict === "not_actionable") {
      if (rank !== null || rankQueue !== null) {
        failures.push(`${label}: not_actionable finding must use null rank and rank_queue`);
      }
    } else if (!Number.isInteger(rank) || rank < 1) {
      failures.push(`${label}: actionable or unresolved finding must use a positive integer rank`);
    } else {
      const ranks = ranksByQueue.get(rankQueue) || [];
      ranks.push({ label, rank });
      ranksByQueue.set(rankQueue, ranks);
    }

    for (const field of ["affected_locations", "reachable_path", "evidence", "counterevidence", "proof_gaps"]) {
      if (!Array.isArray(finding[field])) {
        failures.push(`${label}: ${field} is not an array`);
      }
    }

    const handoff = finding.fix_finding_handoff;
    if (finding.verdict === "confirmed") {
      if (typeof handoff !== "string" || handoff.trim().length === 0) {
        failures.push(`${label}: confirmed finding must include a non-empty fix_finding_handoff`);
      }
    } else if (handoff !== null && !(typeof handoff === "string" && handoff.trim().length === 0)) {
      failures.push(`${label}: non-confirmed finding must not include a fix_finding_handoff`);
    }
  });

  for (const [rankQueue, ranks] of ranksByQueue) {
    ranks.sort((left, right) => left.rank - right.rank);
    ranks.forEach(({ label, rank }, index) => {
      const expectedRank = index + 1;
      if (rank !== expectedRank) {
        failures.push(`${label}: ${rankQueue} ranks must be contiguous from 1; expected ${expectedRank}, got ${rank}`);
      }
    });
  }

  return {
    pass: failures.length === 0,
    score: failures.length === 0 ? 1 : 0,
    reason: failures.length === 0 ? "Triage I/O matched expected source types, order, and verdicts." : failures.join("; "),
  };
};
