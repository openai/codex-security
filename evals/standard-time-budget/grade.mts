import { posix } from "node:path";
import type {
  Finding as ScanFinding,
  FindingCodeEvidence,
  FindingLocation,
} from "../../sdk/typescript/src/models.js";
import type { Fixture, SourceCase } from "./fixtures.mts";

export type SourceLocation = FindingLocation;
type Finding = Pick<ScanFinding, "title" | "locations"> & {
  taxonomy: Pick<ScanFinding["taxonomy"], "cwe">;
  codeEvidence?: Pick<
    FindingCodeEvidence,
    "path" | "startLine" | "endLine" | "code" | "role"
  >[];
};

export interface Result {
  findings: Finding[];
  [key: string]: unknown;
}

interface EvidenceError {
  findingIndex?: number;
  evidenceIndex?: number;
  locationIndex?: number;
  caseId?: string;
  reason: string;
}

interface EvidenceCitation {
  declared: SourceLocation;
  verified?: SourceLocation;
}

export type GradeReport = ReturnType<typeof gradeResult>;

function validRange(location: SourceLocation, fixture: Fixture) {
  const source = fixture.files[posix.normalize(location.path)];
  const endLine = location.endLine ?? location.startLine;
  return (
    typeof source === "string" &&
    Number.isInteger(location.startLine) &&
    Number.isInteger(endLine) &&
    location.startLine > 0 &&
    endLine >= location.startLine &&
    endLine <= source.trimEnd().split("\n").length
  );
}

function overlaps(location: SourceLocation, expected: SourceCase) {
  return (
    posix.normalize(location.path) === expected.path &&
    location.startLine <= (expected.endLine ?? expected.line) &&
    (location.endLine ?? location.startLine) >= expected.line
  );
}

function matches(
  finding: Finding,
  expected: SourceCase,
  fixture: Fixture,
  citations: EvidenceCitation[],
  requirePrimaryRole: boolean,
) {
  if (
    !finding.taxonomy.cwe.some((cwe) =>
      expected.cwes.includes(String(cwe).trim().toUpperCase()),
    )
  )
    return false;

  return finding.locations.some((location) => {
    if (!validRange(location, fixture) || !overlaps(location, expected))
      return false;
    if (location.role) {
      if (!requirePrimaryRole) {
        return !/^(supporting|support|context|consumer|expected_control)$/u.test(
          location.role,
        );
      }
      if (location.role === "root_control" || location.role === "sink")
        return true;
      if (
        location.role !== "entrypoint" &&
        location.role !== "entrypoint/wrapper"
      )
        return false;
    }

    // The evidence must identify the role on a gold line the location cites.
    const cited = {
      ...expected,
      line: Math.max(expected.line, location.startLine),
      endLine: Math.min(
        expected.endLine ?? expected.line,
        location.endLine ?? location.startLine,
      ),
    };
    const verified = citations.filter(
      ({ verified }) => verified && overlaps(verified, cited),
    );
    if (requirePrimaryRole) {
      return verified.some(
        ({ declared: { role } }) =>
          role === "entrypoint" || role === "root_control" || role === "sink",
      );
    }
    const comparison = verified.some(
      ({ declared }) => declared.role === "expected_control",
    );
    const competing = citations.some(
      ({ declared }) =>
        declared.role !== "expected_control" && overlaps(declared, cited),
    );
    return !comparison || competing;
  });
}

function inspectEvidence(
  finding: Finding,
  fixture: Fixture,
  findingIndex: number,
) {
  const entries = finding.codeEvidence ?? [];
  const ranges: SourceLocation[] = [];
  const citations: EvidenceCitation[] = [];
  const errors: EvidenceError[] = [];
  if (!entries.length) {
    errors.push({ findingIndex, reason: "missing code evidence" });
  }
  for (const [evidenceIndex, entry] of entries.entries()) {
    const code = entry.code.replaceAll("\r\n", "\n").replace(/\n$/u, "");
    const range = {
      ...entry,
      endLine: entry.startLine + code.split("\n").length - 1,
    };
    const citation: EvidenceCitation = {
      declared: { ...entry, endLine: entry.endLine ?? range.endLine },
    };
    citations.push(citation);
    const source = fixture.files[posix.normalize(entry.path)];
    if (
      !code.trim() ||
      !validRange(range, fixture) ||
      code !==
        source!
          .split("\n")
          .slice(entry.startLine - 1, range.endLine)
          .join("\n")
    ) {
      errors.push({
        findingIndex,
        evidenceIndex,
        reason: "code does not match source at the cited lines",
      });
    } else if (!validRange(entry, fixture)) {
      errors.push({
        findingIndex,
        evidenceIndex,
        reason: "code evidence range does not exist in the source",
      });
    } else {
      ranges.push(range);
      citation.verified = {
        ...range,
        endLine: Math.min(range.endLine, entry.endLine ?? range.endLine),
      };
    }
  }
  return { ranges, citations, errors };
}

export function gradeResult(result: Result, fixture: Fixture) {
  const { findings } = result;
  const evidenceErrors: EvidenceError[] = [];
  const unmatchedFindings = [];
  const safeControlDetails = [];
  const matchCounts = new Map(
    fixture.positives.map((expected) => [expected.id, 0]),
  );
  for (const [findingIndex, finding] of findings.entries()) {
    const evidence = inspectEvidence(finding, fixture, findingIndex);
    for (const [locationIndex, location] of finding.locations.entries()) {
      if (!validRange(location, fixture)) {
        evidence.errors.push({
          findingIndex,
          locationIndex,
          reason: "location path or line range does not exist in the source",
        });
      }
    }
    evidenceErrors.push(...evidence.errors);
    const candidates = fixture.positives.filter((expected) =>
      matches(finding, expected, fixture, evidence.citations, true),
    );
    const matched = candidates.filter((expected) => {
      const grounded = evidence.ranges.some((range) =>
        overlaps(range, expected),
      );
      if (!grounded) {
        evidenceErrors.push({
          findingIndex,
          caseId: expected.id,
          reason: "code evidence does not cover the expected source line",
        });
      }
      return grounded && evidence.errors.length === 0;
    });
    for (const expected of matched) {
      matchCounts.set(expected.id, matchCounts.get(expected.id)! + 1);
    }
    const controls = fixture.controls.filter((expected) =>
      matches(finding, expected, fixture, evidence.citations, false),
    );
    if (controls.length) {
      safeControlDetails.push({
        findingIndex,
        title: finding.title,
        controlIds: controls.map((entry) => entry.id),
      });
    }
    if (!matched.length && !controls.length) {
      unmatchedFindings.push({
        findingIndex,
        title: finding.title,
        reason: candidates.length
          ? "expected case lacks authentic evidence"
          : "no matching source location and CWE in the gold cases",
      });
    }
  }
  const cases = fixture.positives.map((expected) => ({
    id: expected.id,
    found: matchCounts.get(expected.id)! > 0,
  }));
  const matchedIds = cases
    .filter((entry) => entry.found)
    .map((entry) => entry.id);
  const foundCount = matchedIds.length;
  const expectedCount = cases.length;
  return {
    passed:
      foundCount === expectedCount &&
      safeControlDetails.length === 0 &&
      unmatchedFindings.length === 0 &&
      evidenceErrors.length === 0,
    recall: foundCount / expectedCount,
    foundCount,
    expectedCount,
    matchedIds,
    cases,
    duplicateFindings: [...matchCounts.values()].reduce(
      (total, count) => total + Math.max(0, count - 1),
      0,
    ),
    safeControlFindings: safeControlDetails.length,
    safeControlDetails,
    unmatchedFindings,
    evidenceErrors,
    needsAdjudication:
      unmatchedFindings.length > 0 || safeControlDetails.length > 0,
    gradingMethod:
      "Heuristic source-line, CWE, and verbatim evidence matching; not independent exploit validation. Unmatched findings require manual adjudication and are not automatically false positives.",
  };
}
