import { reviewerMode } from "../grade.mjs";

function median(times) {
  if (!times.length) return null;
  times.sort((a, b) => a - b);
  const mid = Math.floor(times.length / 2);
  return times.length % 2 ? times[mid] : (times[mid - 1] + times[mid]) / 2;
}

function sum(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) : null;
}

function strictPass({ status, grade }) {
  if (status !== "passed") return false;
  // Earlier case modules checked the selected evidence on their best match.
  return (
    grade?.strictPass ?? (grade?.pass && grade.selectedEvidenceCorrect) ?? null
  );
}

function runStats(results) {
  const batches = results.map((r) => r.reviewBatches).filter(Number.isFinite);
  const usage = results.map((r) => r.usage).filter(Boolean);
  return {
    cases: results.length,
    executionErrors: results.filter((r) => r.status === "execution_error")
      .length,
    medianMs: median(results.map((r) => r.elapsedMs).filter(Number.isFinite)),
    reviewBatches: sum(batches),
    progressLogs: batches.length,
    reportsWithUsage: usage.length,
    inputTokens: sum(usage.map((u) => u.input_tokens)),
    cachedInputTokens: sum(usage.map((u) => u.cached_input_tokens)),
    outputTokens: sum(usage.map((u) => u.output_tokens)),
  };
}

function deterministicScores(results) {
  const correct = (field) =>
    results.some((r) => typeof r.grade?.[field] === "boolean")
      ? results.filter((r) => r.grade?.[field] === true).length
      : null;
  const identity = correct("identityCorrect");
  const verdict = correct("verdictLabelCorrect");
  const strict = results.map(strictPass);
  return {
    ...runStats(results),
    passed: results.filter((r) => r.status === "passed").length,
    strictPassed: strict.includes(null) ? null : strict.filter(Boolean).length,
    verdict,
    identity,
    identityAndVerdict:
      identity === null || verdict === null
        ? null
        : results.filter(
            ({ grade }) => grade?.identityCorrect && grade.verdictLabelCorrect,
          ).length,
    version: correct("versionCorrect"),
    decidingEvidence: correct("evidenceCorrect"),
    selectedEvidence: correct("selectedEvidenceCorrect"),
  };
}

function compareDeterministic(enabled, disabled) {
  function wins(first, second, passed) {
    return first
      .filter((r, i) => passed(r) && passed(second[i]) === false)
      .map((r) => r.id);
  }
  const pass = (r) => r.status === "passed";
  return {
    enabled: deterministicScores(enabled),
    disabled: deterministicScores(disabled),
    gainedWithReview: wins(enabled, disabled, pass),
    lostWithReview: wins(disabled, enabled, pass),
    strictGainedWithReview: wins(enabled, disabled, strictPass),
    strictLostWithReview: wins(disabled, enabled, strictPass),
  };
}

function compareReportScores(enabled, disabled) {
  const matched = enabled
    .map((r, i) => [r, disabled[i]])
    .filter(([on, off]) => on.status === "scored" && off.status === "scored");
  function scores(results, side) {
    const mean = (field) =>
      matched.length
        ? sum(matched.map((pair) => pair[side].reportScore[field])) /
          matched.length
        : null;
    const count = (status) => results.filter((r) => r.status === status).length;
    const inputErrors = count("input_error");
    const ratingErrors = count("rating_error");
    return {
      ...runStats(results),
      inputErrors,
      ratingErrors,
      reportsScored: count("scored"),
      pairedReports: matched.length,
      accuracy: mean("accuracy"),
      comprehensiveness: mean("comprehensiveness"),
      blended: mean("blended"),
      blendedPerAttempt:
        results.length && !ratingErrors && !inputErrors
          ? sum(results.map((r) => r.reportScore?.blended ?? 0)) /
            results.length
          : null,
    };
  }
  const higherWithReview = [];
  const lowerWithReview = [];
  for (const [on, off] of matched) {
    if (on.reportScore.blended > off.reportScore.blended)
      higherWithReview.push(on.id);
    if (on.reportScore.blended < off.reportScore.blended)
      lowerWithReview.push(on.id);
  }
  return {
    enabled: scores(enabled, 0),
    disabled: scores(disabled, 1),
    higherWithReview,
    lowerWithReview,
  };
}

export function compareRuns(ids, results, { blended = false } = {}) {
  const byKey = new Map(results.map((r) => [reviewerMode(r) + "/" + r.id, r]));
  const enabled = [];
  const disabled = [];
  const pending = [];
  const inputMismatch = [];
  const elapsedDeltas = [];
  let matchedAdvisories = 0;
  for (const id of ids) {
    const on = byKey.get("enabled/" + id);
    const off = byKey.get("disabled/" + id);
    if (!on || !off) {
      pending.push(id);
      continue;
    }
    const haveAdvisories = on.advisorySha256 && off.advisorySha256;
    if (
      (on.sourceSha && off.sourceSha && on.sourceSha !== off.sourceSha) ||
      on.callerScope !== off.callerScope ||
      on.cve !== off.cve ||
      (haveAdvisories && on.advisorySha256 !== off.advisorySha256)
    ) {
      inputMismatch.push(id);
      continue;
    }
    // Retain errors in the denominator even if one process returned no report.
    if (haveAdvisories) matchedAdvisories++;
    enabled.push(on);
    disabled.push(off);
    if (Number.isFinite(on.elapsedMs) && Number.isFinite(off.elapsedMs))
      elapsedDeltas.push(on.elapsedMs - off.elapsedMs);
  }
  const grades = blended
    ? compareReportScores(enabled, disabled)
    : compareDeterministic(enabled, disabled);
  return {
    ...grades,
    medianPairedElapsedDeltaMs: median(elapsedDeltas),
    matchedAdvisories,
    inputMismatch,
    pending,
  };
}
