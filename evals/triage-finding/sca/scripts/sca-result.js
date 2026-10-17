"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");
const {
  extractTriageResult,
} = require("../../sastbench/scripts/sastbench-result.mts");

const ROOT = path.resolve(__dirname, "../../../..");
const sdkRequire = createRequire(
  path.join(ROOT, "sdk/typescript/package.json"),
);
const Ajv = sdkRequire("ajv");
const schema = JSON.parse(
  fs.readFileSync(
    path.join(ROOT, "plugins/codex-security/schemas/triage-result.schema.json"),
    "utf8",
  ),
);
const validateTriage = new Ajv({ allErrors: true }).compile(schema);
const LABELS = ["affected", "not_affected", "unresolved"];
const VERDICTS = ["confirmed", "not_actionable", "needs_review"];
const EXPECTED = {
  affected: "confirmed",
  not_affected: "not_actionable",
  unresolved: "needs_review",
};
const FIXTURE_ROOT = path.resolve(__dirname, "../fixtures");
const CORPUS = JSON.parse(
  fs.readFileSync(path.join(FIXTURE_ROOT, "corpus.json"), "utf8"),
);

function finiteOrNull(value) {
  return Number.isFinite(value) && value >= 0 ? value : null;
}

function caseById(id) {
  const item = CORPUS.cases.find((entry) => entry.case_id === id);
  if (!item) throw new Error(`Unknown SCA case: ${id}`);
  return item;
}

function hasToken(text, token, characters = "A-Za-z0-9_./@-") {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^${characters}])${escaped}($|[^${characters}])`).test(
    text,
  );
}

function evidenceFailures(finding, testCase) {
  const failures = [];
  const component = testCase.input.component;
  const normalized = finding.normalized_input;
  if (!hasToken(normalized.vulnerable_component, component.name))
    failures.push("Wrong or absent package identity");
  if (
    !hasToken(
      `${normalized.vulnerable_component} ${normalized.affected_version_or_path}`,
      component.version,
      "A-Za-z0-9_.-",
    )
  )
    failures.push("Wrong or absent resolved version");
  if (!hasToken(normalized.affected_version_or_path, component.source))
    failures.push("Wrong or absent source lockfile");
  if (
    !testCase.input.advisory_ids.some((id) =>
      normalized.references.some((reference) =>
        hasToken(reference, id, "A-Za-z0-9_-"),
      ),
    )
  )
    failures.push("No matched advisory reference");

  // A real citation must identify a relevant source span and quote text from
  // that span. Merely repeating a filename, package name, or case ID is not evidence.
  const evidence = [...finding.evidence, ...finding.counterevidence];
  for (const required of testCase.required_evidence) {
    const source = fs
      .readFileSync(
        path.join(FIXTURE_ROOT, testCase.case_id, required.path),
        "utf8",
      )
      .split(/\r?\n/);
    const cited = evidence.some((text) => {
      const citations = [
        ...text.matchAll(/([A-Za-z0-9_./-]+):(\d+)(?:-(\d+))?/g),
      ];
      const quotes = [...text.matchAll(/`([^`\n]+)`/g)].map(
        (match) => match[1],
      );
      return citations.some((citation) => {
        const start = Number(citation[2]);
        const end = Number(citation[3] || citation[2]);
        if (
          citation[1] !== required.path ||
          start < 1 ||
          end < start ||
          end > source.length
        )
          return false;
        if (start > required.line || end < required.line) return false;
        const lines = source.slice(start - 1, end).join("\n");
        return quotes.some(
          (quote) => quote.includes(required.fragment) && lines.includes(quote),
        );
      });
    });
    if (!cited)
      failures.push(
        `Missing supported citation: ${required.path}:${required.line}`,
      );
  }
  if (finding.verdict === "needs_review" && finding.proof_gaps.length === 0)
    failures.push("Unresolved assessment has no proof gap");
  return failures;
}

function parseOutcome(output, testCase) {
  const result = extractTriageResult(output);
  if (!validateTriage(result))
    throw new Error(
      `Invalid triage schema: ${new Ajv().errorsText(validateTriage.errors)}`,
    );
  if (
    result.findings.length !== 1 ||
    result.findings[0].input_id !== testCase.input.input_id
  ) {
    throw new Error(
      "Expected exactly one assessment for the supplied match ID",
    );
  }
  const finding = result.findings[0];
  if (finding.source_type !== "advisory")
    throw new Error("Expected advisory source_type");
  return { finding, evidenceFailures: evidenceFailures(finding, testCase) };
}

function normalizePromptfooResult(row) {
  const testCase = caseById(
    row.vars?.case_id || row.testCase?.vars?.case_id || row.test?.vars?.case_id,
  );
  const base = {
    caseId: testCase.case_id,
    family: testCase.advisory_family,
    goldLabel: testCase.gold_label,
    latencyMs: finiteOrNull(row.latencyMs),
    costUsd: finiteOrNull(row.cost ?? row.response?.cost),
    tokenUsage: row.response?.tokenUsage || row.tokenUsage || null,
    // Human support is separate from mechanical citation correctness.
    reviewerSupported: row.metadata?.sca?.reviewerSupported ?? null,
  };
  const output = row.response?.output;
  if (output === undefined || output === null || output === "") {
    return {
      ...base,
      status: "model_error",
      verdict: null,
      evidenceFailures: [],
      error: String(
        row.response?.error || row.error || "Model returned no output",
      ),
    };
  }
  try {
    const parsed = parseOutcome(output, testCase);
    return {
      ...base,
      status: "ok",
      verdict: parsed.finding.verdict,
      evidenceFailures: parsed.evidenceFailures,
      error: null,
    };
  } catch (error) {
    return {
      ...base,
      status: "invalid_output",
      verdict: null,
      evidenceFailures: [],
      error: error.message,
    };
  }
}

function ratio(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator;
}

function summarize(outcomes) {
  const matrix = Object.fromEntries(
    LABELS.map((label) => [
      label,
      Object.fromEntries(
        [...VERDICTS, "model_error", "invalid_output"].map((value) => [
          value,
          0,
        ]),
      ),
    ]),
  );
  for (const outcome of outcomes) {
    if (!LABELS.includes(outcome.goldLabel))
      throw new Error(`Invalid gold label: ${outcome.goldLabel}`);
    const predicted =
      outcome.status === "ok" ? outcome.verdict : outcome.status;
    if (!(predicted in matrix[outcome.goldLabel]))
      throw new Error(`Invalid outcome: ${predicted}`);
    matrix[outcome.goldLabel][predicted] += 1;
  }
  const count = (predicate) => outcomes.filter(predicate).length;
  const valid = outcomes.filter((item) => item.status === "ok");
  const decisive = valid.filter((item) => item.verdict !== "needs_review");
  const confirmed = decisive.filter((item) => item.verdict === "confirmed");
  const dismissed = decisive.filter(
    (item) => item.verdict === "not_actionable",
  );
  const affected = count((item) => item.goldLabel === "affected");
  const unresolved = count((item) => item.goldLabel === "unresolved");
  const knownCosts = outcomes.filter(
    (item) => item.costUsd !== null && item.costUsd !== undefined,
  );
  const latencies = outcomes
    .map((item) => item.latencyMs)
    .filter((value) => value !== null && value !== undefined)
    .sort((a, b) => a - b);
  const middle = Math.floor(latencies.length / 2);
  return {
    attempted: outcomes.length,
    uniqueCases: new Set(outcomes.map((item) => item.caseId)).size,
    advisoryFamilies: new Set(outcomes.map((item) => item.family)).size,
    confusionMatrix: matrix,
    executionErrors: count((item) => item.status === "model_error"),
    invalidOutputs: count((item) => item.status === "invalid_output"),
    unsupportedEvidence: count(
      (item) => item.status === "ok" && item.evidenceFailures.length > 0,
    ),
    unjustifiedDecisionsOnUnresolved: decisive.filter(
      (item) => item.goldLabel === "unresolved",
    ).length,
    confirmationPrecision: ratio(
      confirmed.filter((item) => item.goldLabel === "affected").length,
      confirmed.length,
    ),
    affectedConfirmationRecall: ratio(matrix.affected.confirmed, affected),
    incorrectDismissalRate: ratio(matrix.affected.not_actionable, affected),
    dismissalPrecision: ratio(
      dismissed.filter((item) => item.goldLabel === "not_affected").length,
      dismissed.length,
    ),
    uncertaintyHandling: ratio(matrix.unresolved.needs_review, unresolved),
    decisionCoverage: ratio(decisive.length, outcomes.length),
    decisionAccuracy: ratio(
      decisive.filter((item) => item.verdict === EXPECTED[item.goldLabel])
        .length,
      decisive.length,
    ),
    mechanicalCitationPassRate: ratio(
      valid.filter((item) => item.evidenceFailures.length === 0).length,
      valid.length,
    ),
    // Do not infer expert evidence support from a string-matching assertion.
    reviewedDecisiveCount: decisive.filter(
      (item) => typeof item.reviewerSupported === "boolean",
    ).length,
    reviewerSupportedEvidenceRate: ratio(
      decisive.filter((item) => item.reviewerSupported === true).length,
      decisive.filter((item) => typeof item.reviewerSupported === "boolean")
        .length,
    ),
    medianLatencyMs:
      latencies.length === 0
        ? null
        : latencies.length % 2
          ? latencies[middle]
          : (latencies[middle - 1] + latencies[middle]) / 2,
    reportedCostUsd: knownCosts.reduce((sum, item) => sum + item.costUsd, 0),
    costCoverage: ratio(knownCosts.length, outcomes.length),
  };
}

/**
 * Score scanner occurrence retention independently of model verdicts. Aliases
 * may be grouped, but each input source/package/version/advisory occurrence
 * must still be present in the retained artifact.
 */
function matchRetention(supplied, retained) {
  const occurrences = (matches) =>
    new Set(
      matches.flatMap((match) =>
        match.advisory_ids.map((id) =>
          JSON.stringify([
            process.platform === "win32"
              ? match.component.source.replace(/\\/g, "/")
              : match.component.source,
            match.component.ecosystem,
            match.component.name,
            match.component.version,
            id,
          ]),
        ),
      ),
    );
  const expected = occurrences(supplied);
  const actual = occurrences(retained);
  const missing = [...expected].filter((item) => !actual.has(item));
  return {
    suppliedOccurrences: expected.size,
    retainedOccurrences: expected.size - missing.length,
    missing: missing.map((item) => JSON.parse(item)),
    rate: ratio(expected.size - missing.length, expected.size),
  };
}

function summarizeExport(document) {
  const rows = Array.isArray(document.results)
    ? document.results
    : document.results?.results;
  if (!Array.isArray(rows))
    throw new Error("Expected a Promptfoo JSON export with results rows");
  const arms = new Map();
  for (const row of rows) {
    const arm = `${row.provider?.label || row.provider?.id || "unknown-provider"} / ${row.prompt?.label || row.prompt?.id || "unknown-prompt"}`;
    const outcomes = arms.get(arm) || [];
    outcomes.push(normalizePromptfooResult(row));
    arms.set(arm, outcomes);
  }
  return {
    schema_version: "codex-security.sca-eval/v0",
    corpus_kind: CORPUS.kind,
    available_cases: CORPUS.cases.length,
    human_adjudicated_cases: 0,
    arms: Object.fromEntries(
      [...arms].map(([name, outcomes]) => [
        name,
        { ...summarize(outcomes), outcomes },
      ]),
    ),
  };
}

if (require.main === module) {
  const input = process.argv[2];
  if (!input)
    throw new Error(
      "Usage: node sca/scripts/sca-result.js <promptfoo-results.json>",
    );
  process.stdout.write(
    `${JSON.stringify(summarizeExport(JSON.parse(fs.readFileSync(input, "utf8"))), null, 2)}\n`,
  );
}

module.exports = {
  CORPUS,
  EXPECTED,
  FIXTURE_ROOT,
  caseById,
  evidenceFailures,
  parseOutcome,
  normalizePromptfooResult,
  summarize,
  summarizeExport,
  matchRetention,
};
