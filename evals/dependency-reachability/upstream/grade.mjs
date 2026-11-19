import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { approvedCitations, sourceReader } from "../grade.mjs";
import { checkoutPlacesV2 } from "./checkout-places-v2.mjs";

// Each group needs one of its alternatives. A required absence across an entire
// file may be covered by multiple verified ranges belonging to the same use.
function supported(anchor, citations) {
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

function groupsFor(scenario) {
  const expected = checkoutPlacesV2[scenario.id];
  return {
    expected,
    identity: expected.identityEvidence,
    deciding: scenario.evidenceGroups,
  };
}

export function validateSnapshot(scenario, repo, commit) {
  const { identity, deciding } = groupsFor(scenario);
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
      "pinned snapshot contains the required evidence in " +
        group.map((a) => a.path).join(" or "),
    );
  }
  return { identityGroups: identity.length, decidingGroups: deciding.length };
}

export function gradeSnapshot(report, scenario, repo, commit) {
  assert.equal(report.cve, scenario.cve);
  assert.equal(report.schemaVersion, 2);
  const { expected, identity, deciding } = groupsFor(scenario);
  const read = sourceReader(repo, commit);
  const allowedVersions = Object.hasOwn(scenario, "commandVersion")
    ? [scenario.commandVersion].flat()
    : [scenario.version, ...(scenario.versionAliases || [])];
  const components =
    scenario.component === "glibc"
      ? ["glibc", "gnu c library", "libc6"]
      : [scenario.component];
  const uses = report.uses.filter((u) =>
    components.some(
      (component) =>
        u.component.toLowerCase() === component ||
        u.component.toLowerCase().startsWith(component + " ") ||
        u.component
          .toLowerCase()
          .split(/[^\w-]+/u)
          .includes(component),
    ),
  );
  assert(uses.length, "target component was assessed");
  assert(
    !uses.some((u) => u.verdict === "exploitable"),
    "snapshot does not prove a confirmed exploitable running use",
  );
  // Grade one complete location. Combining two reports' source ranges could
  // accidentally prove a backported dependency is reachable from another service.
  const grades = uses.map((use) => {
    const errors = [];
    const check = (ok, issue) => {
      if (!ok) errors.push(issue);
    };
    const cites = approvedCitations(report, use, read, commit);
    check(
      use.reason?.trim() && use.location?.trim(),
      "missing reason or location",
    );
    check(use.verdict === expected.verdict, "expected " + expected.verdict);
    check(allowedVersions.includes(use.version), "wrong selected version");
    check(Boolean(use.place), "missing structured use scope");
    for (const [name, groups] of [
      ["identity", identity],
      ["deciding", deciding],
    ]) {
      for (const group of groups)
        check(
          group.some((a) => supported(a, cites)),
          name +
            " citation missing at " +
            group.map((a) => a.path).join(" or "),
        );
    }
    if (expected.needsDecidingGap)
      check(
        use.place?.unresolvedQuestions?.some((q) => q.trim()),
        "missing deciding evidence question",
      );
    const call = expected.callSite ?? scenario.commandCallSite;
    if (call) {
      const actual = use.proof?.sink?.callSite;
      check(
        actual?.path === call.path &&
          actual.line === call.line &&
          cites.some(
            (c) =>
              c.path === call.path &&
              c.startLine <= call.line &&
              call.line <= c.endLine,
          ),
        "incorrect sink call site",
      );
    }
    if (use.place?.deploymentBasis === "observed") {
      check(
        expected.observedBySource === true && use.deployment === "confirmed",
        "unjustified observed deployment",
      );
    }
    return {
      location: use.location,
      version: use.version,
      verdict: use.verdict,
      errors,
    };
  });
  grades.sort((a, b) => a.errors.length - b.errors.length);
  return {
    pass: grades[0].errors.length === 0,
    ...grades[0],
    target: expected.id,
  };
}
