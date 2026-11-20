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

function score(results) {
  const correct = (field) =>
    results.some((r) => typeof r.grade?.[field] === "boolean")
      ? results.filter((r) => r.grade?.[field] === true).length
      : null;
  const identity = correct("identityCorrect");
  const verdict = correct("verdictLabelCorrect");
  const batches = results.map((r) => r.reviewBatches).filter(Number.isFinite);
  const usage = results.map((r) => r.usage).filter(Boolean);
  return {
    cases: results.length,
    passed: results.filter((r) => r.status === "passed").length,
    executionErrors: results.filter((r) => r.status === "execution_error")
      .length,
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
    medianMs: median(results.map((r) => r.elapsedMs).filter(Number.isFinite)),
    reviewBatches: sum(batches),
    progressLogs: batches.length,
    reportsWithUsage: usage.length,
    inputTokens: sum(usage.map((u) => u.input_tokens)),
    cachedInputTokens: sum(usage.map((u) => u.cached_input_tokens)),
    outputTokens: sum(usage.map((u) => u.output_tokens)),
  };
}

export function compareRuns(ids, results) {
  const byKey = new Map(results.map((r) => [reviewerMode(r) + "/" + r.id, r]));
  const enabled = [];
  const disabled = [];
  const pending = [];
  const inputMismatch = [];
  const gainedWithReview = [];
  const lostWithReview = [];
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
    if (on.status === "passed" && off.status !== "passed")
      gainedWithReview.push(id);
    if (off.status === "passed" && on.status !== "passed")
      lostWithReview.push(id);
    if (Number.isFinite(on.elapsedMs) && Number.isFinite(off.elapsedMs))
      elapsedDeltas.push(on.elapsedMs - off.elapsedMs);
  }
  return {
    enabled: score(enabled),
    disabled: score(disabled),
    medianPairedElapsedDeltaMs: median(elapsedDeltas),
    matchedAdvisories,
    gainedWithReview,
    lostWithReview,
    inputMismatch,
    pending,
  };
}
