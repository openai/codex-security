import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { reviewerMode, verifyClaimCitations, sourceReader } from "../grade.mjs";

// Each group needs one of its alternatives. A required absence across an entire
// file may be covered by multiple verified ranges belonging to the same use.
export function supported(anchor, citations) {
  const ranges = citations.filter((c) => c.path === anchor.path);
  if (
    !ranges.some((c) => !anchor.contains || c.excerpt.includes(anchor.contains))
  )
    return false;
  if (!anchor.completeFile) return true;
  let last = 0;
  for (const row of ranges.sort((a, b) => a.startLine - b.startLine)) {
    if (row.startLine > last + 1) return false;
    last = Math.max(last, row.endLine);
  }
  return last === ranges[0].totalLines;
}

function describeGroup(group) {
  return group
    .map(({ path, contains, completeFile }) => {
      if (completeFile) return `${path} (complete file)`;
      return contains ? `${path} (${contains})` : path;
    })
    .join(" or ");
}

export function validateSnapshot(scenario, repo, commit) {
  const { identityEvidence: identity, evidenceGroups: deciding } = scenario;
  const cache = new Map();
  for (const group of [...identity, ...deciding]) {
    const matches = group.some((anchor) => {
      if (!cache.has(anchor.path)) {
        const result = execFileSync(
          "git",
          ["-C", repo, "show", commit + ":" + anchor.path],
          { encoding: "utf8", maxBuffer: Infinity },
        );
        cache.set(anchor.path, result.replaceAll("\r\n", "\n"));
      }
      return (
        !anchor.contains || cache.get(anchor.path).includes(anchor.contains)
      );
    });
    assert(
      matches,
      "Required evidence absent from pinned snapshot: " + describeGroup(group),
    );
  }
  return { identityGroups: identity.length, decidingGroups: deciding.length };
}

// The fixture requires a captured checkout search for the affected package. A
// list of registered tools or an unscoped model assertion is not a search.
export function checkSearchAudit(searches, components) {
  assert(Array.isArray(searches), "missing checkout search audit");
  let traced = false;
  for (const record of searches) {
    const {
      source,
      tool,
      scope,
      startedAt,
      finishedAt,
      result,
      completeness,
      details,
      evidenceReferences,
    } = record;
    assert(
      Array.isArray(scope) && scope.every((v) => typeof v === "string"),
      "invalid search scope",
    );
    assert(
      typeof finishedAt === "string" &&
        Number.isFinite(Date.parse(finishedAt)) &&
        (startedAt === null ||
          (typeof startedAt === "string" &&
            Date.parse(startedAt) <= Date.parse(finishedAt))),
      "invalid search timestamps",
    );
    assert(
      Array.isArray(details) &&
        details.every((s) => typeof s === "string") &&
        Array.isArray(evidenceReferences) &&
        evidenceReferences.every((s) => typeof s === "string" && s.length),
      "invalid search details or references",
    );
    assert(
      ["matches", "no_match", "returned", "unknown", "not_run"].includes(
        result,
      ) &&
        [
          "complete",
          "partial",
          "error",
          "unknown",
          "unavailable",
          "skipped",
        ].includes(completeness) &&
        (!["skipped", "unavailable"].includes(completeness) ||
          result === "not_run") &&
        (completeness !== "error" || result === "unknown"),
      "invalid search outcome",
    );
    const packageMatch = scope.some(
      (s) =>
        s.startsWith("package=") &&
        components.some((name) => namesComponent(s.slice(8), name)),
    );
    const fileScope = scope.some(
      (s) =>
        /^(?:files|paths|searched|rules)=.+/u.test(s) ||
        s === "Checkout search scope",
    );
    if (
      packageMatch &&
      fileScope &&
      source === "Checkout trace graph" &&
      tool === "trace_codex_security_code" &&
      ["error", "partial", "complete"].includes(completeness)
    )
      traced = true;
  }
  assert(
    traced,
    "missing captured checkout tracer outcome for the expected package and scope",
  );
}

function namesComponent(label, name) {
  const normalized = label.toLowerCase();
  return (
    normalized === name ||
    normalized.startsWith(name + " ") ||
    normalized.split(/[^\w-]+/u).includes(name)
  );
}

function missingGroups(groups, citations) {
  return groups.filter(
    (group) => !group.some((anchor) => supported(anchor, citations)),
  );
}

function gradeUse(use, scenario, report, citations) {
  const versions = Object.hasOwn(scenario, "commandVersion")
    ? [scenario.commandVersion].flat()
    : [scenario.version, ...(scenario.versionAliases ?? [])];
  const verdictLabelCorrect = use.verdict === scenario.verdict;
  const versionCorrect = versions.includes(use.version);
  const { identityEvidence, evidenceGroups, commandCallSite: call } = scenario;
  const missingIdentity = missingGroups(identityEvidence, citations.displayed);
  const missingEvidence = missingGroups(evidenceGroups, citations.displayed);
  const identityCorrect = missingIdentity.length === 0;
  const evidenceCorrect = missingEvidence.length === 0;
  const errors = [];
  if (!use.reason?.trim() || !use.location?.trim())
    errors.push("Missing reason or location");
  if (!use.place) errors.push("Missing structured use scope");
  if (!verdictLabelCorrect) errors.push("Expected verdict " + scenario.verdict);
  if (!versionCorrect)
    errors.push("Expected version " + versions.map(String).join(" or "));
  for (const group of missingIdentity)
    errors.push("Missing identity citation: " + describeGroup(group));
  for (const group of missingEvidence)
    if (!missingIdentity.includes(group))
      errors.push("Missing deciding citation: " + describeGroup(group));

  if (
    scenario.needsDecidingGap &&
    !use.place?.unresolvedQuestions?.some((q) => q.trim())
  )
    errors.push("Missing deciding evidence question");

  const includesCall = (ranges) =>
    !call ||
    ranges.some(
      (c) =>
        c.path === call.path &&
        c.startLine <= call.line &&
        call.line <= c.endLine,
    );
  if (call) {
    const actual = use.proof?.sink?.callSite;
    if (
      actual?.path !== call.path ||
      actual.line !== call.line ||
      !includesCall(citations.displayed)
    )
      errors.push("Expected sink call at " + call.path + ":" + call.line);
  }
  if (use.place?.deploymentBasis === "observed") {
    const running = [...use.evidence, ...(use.observations ?? [])].some((ref) =>
      ref.supports?.includes("running"),
    );
    if (
      !scenario.observedBySource ||
      use.deployment !== "confirmed" ||
      !running
    )
      errors.push("Unjustified observed deployment");
  }
  if (
    use.place?.deploymentBasis === "assumed_not_deployed" &&
    (!report.assumptions?.some((s) => s.trim()) ||
      use.deployment === "confirmed")
  )
    errors.push("Explicit assumption required for assumed deployment");

  return {
    verdictLabelCorrect,
    versionCorrect,
    identityCorrect,
    identityGroupsMatched: identityEvidence.length - missingIdentity.length,
    evidenceCorrect,
    evidenceGroupsMatched: evidenceGroups.length - missingEvidence.length,
    selectedEvidenceCorrect:
      includesCall(citations.deciding) &&
      missingGroups(
        [...identityEvidence, ...evidenceGroups],
        citations.deciding,
      ).length === 0,
    location: use.location,
    version: use.version,
    verdict: use.verdict,
    errors,
  };
}

export function gradeSnapshot(
  report,
  scenario,
  repo,
  commit,
  reviewer = reviewerMode(report),
) {
  assert.equal(report.cve, scenario.cve);
  assert.equal(report.schemaVersion, 2);
  assert(
    !Object.hasOwn(report, "status"),
    "v2 reports contain per-use verdicts",
  );
  assert(["enabled", "disabled"].includes(reviewer), "unknown reviewer mode");
  assert.equal(reviewerMode(report), reviewer, "unexpected reviewer mode");
  const reviewed = reviewer === "enabled";
  const read = sourceReader(repo, commit);
  const components =
    scenario.component === "glibc"
      ? ["glibc", "gnu c library", "libc6"]
      : [scenario.component];
  const errors = [];
  let auditCorrect = true;
  try {
    checkSearchAudit(report.searches, components);
  } catch (error) {
    auditCorrect = false;
    errors.push(error.message);
  }
  const uses = report.uses.filter((u) =>
    components.some((c) => namesComponent(u.component, c)),
  );
  if (!uses.length)
    errors.push("Missing target component " + scenario.component);
  if (
    scenario.verdict !== "exploitable" &&
    uses.some((u) => u.verdict === "exploitable")
  )
    errors.push("Snapshot does not prove a confirmed exploitable running use");
  let claimsCorrect = uses.length > 0;
  for (const claim of report.claims ?? []) {
    const valid = reviewed
      ? claim.state === "approved" && claim.decision?.accepted === true
      : claim.state === "unreviewed" && claim.decision === undefined;
    if (!valid) {
      claimsCorrect = false;
      errors.push("Unexpected review state on claim " + claim.id);
    }
  }
  const grades = [];
  for (const use of uses) {
    try {
      const citations = verifyClaimCitations(
        report,
        use,
        read,
        commit,
        reviewed,
      );
      if (
        scenario.expectedService &&
        !namesComponent(use.location, scenario.expectedService)
      )
        continue;
      grades.push(gradeUse(use, scenario, report, citations));
    } catch (error) {
      claimsCorrect = false;
      errors.push(use.location + ": " + error.message);
    }
  }
  if (scenario.expectedService && !grades.length)
    errors.push("Missing assessed service " + scenario.expectedService);
  // Identify the assessed application first. Every dimension refers to this
  // same entry, even when a sibling reports the expected verdict or version.
  const best = grades.sort(
    (a, b) =>
      b.identityGroupsMatched - a.identityGroupsMatched ||
      a.errors.length - b.errors.length,
  )[0];
  if (best) errors.push(...best.errors);
  const pass = errors.length === 0;
  return {
    pass,
    strictPass:
      pass &&
      grades.some((g) => g.errors.length === 0 && g.selectedEvidenceCorrect),
    target: scenario.target,
    expectedVerdict: scenario.verdict,
    auditCorrect,
    claimsCorrect,
    verdictLabelCorrect: false,
    versionCorrect: false,
    identityCorrect: false,
    identityGroupsMatched: 0,
    evidenceCorrect: false,
    evidenceGroupsMatched: 0,
    selectedEvidenceCorrect: false,
    ...best,
    errors,
  };
}
