import type { createFixture } from "./fixtures.mts";
type Fixture = ReturnType<typeof createFixture>;
type Expected = Fixture["positives"][number];
export interface SourceLocation {
  path: string;
  startLine: number;
  endLine?: number | null;
  role?: string;
}
export interface CodeEvidence {
  path: string;
  startLine: number;
  code?: string;
  [key: string]: unknown;
}
export interface Finding {
  title?: string;
  summary?: string;
  validation?: { summary?: string; limitations?: string[] };
  severity?: { rationale?: string };
  confidence?: { rationale?: string };
  remediation?: string;
  taxonomy?: { category?: string; cwe?: string[] };
  locations?: SourceLocation[];
  codeEvidence?: CodeEvidence[];
  [key: string]: unknown;
}
export interface Result {
  findings?: Finding[];
  [key: string]: unknown;
}

const explicitSecretTerms =
  /secrets?|credentials?|passwords?|tokens?|(?:api|private) ?keys?|hard ?cod(?:e[ds]?|ing)?/i;
const secretTerms = `${explicitSecretTerms.source}|sensitive ?(?:data|information) ?(?:exposure|disclosure)s?`;
const explicitSecretCategory = new RegExp(
  String.raw`\b(?:${explicitSecretTerms.source})\b`,
  "i",
);
const secretCategory = new RegExp(String.raw`\b(?:${secretTerms})\b`, "i");
const runtimeCategoryCwes = new Map([
  ["sensitive information in response", "CWE-201"],
  ["insertion of sensitive information into sent data", "CWE-201"],
  ["insufficiently protected credentials", "CWE-522"],
]);
const disclosureTerms =
  /(?:(?:sensitive )?(?:data|information) )?(?:(?:disclos|expos)(?:ures?|ed)|leak(?:s|ed|age)?)/;
const negatableTerms = `${secretTerms}|${disclosureTerms.source}`;
const negatedCategory = new RegExp(
  String.raw`^(?:(?:not(?: ?an?)?|non|no|without|den(?:y|ied)) ?(?:${negatableTerms})\b|(?:${negatableTerms}) ?free\b)`,
  "i",
);
const supportingLocation = (location: SourceLocation) =>
  /^(?:supporting|support|context|consumer|expected_control)$/.test(
    location.role ?? "",
  );

function normalizeSourcePath(path: string | undefined) {
  const normalized = path?.replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "");
  return process.platform === "win32" ? normalized?.toLowerCase() : normalized;
}

function sourceText(path: string, fixture: Fixture) {
  return Object.entries(fixture.files).find(
    ([sourcePath]) =>
      normalizeSourcePath(sourcePath) === normalizeSourcePath(path),
  )?.[1];
}

function validSourceRange(location: SourceLocation, fixture: Fixture) {
  const source = sourceText(location.path, fixture);
  const end = location.endLine ?? location.startLine;
  return (
    typeof source === "string" &&
    Number.isInteger(location.startLine) &&
    Number.isInteger(end) &&
    location.startLine > 0 &&
    end >= location.startLine &&
    end <= source.trimEnd().split("\n").length
  );
}

function matchesLocation(location: SourceLocation, expected: Expected) {
  const end = location.endLine ?? location.startLine;
  return (
    normalizeSourcePath(location.path) === normalizeSourcePath(expected.path) &&
    !supportingLocation(location) &&
    Number.isInteger(location.startLine) &&
    Number.isInteger(end) &&
    location.startLine > 0 &&
    location.startLine <= expected.endLine &&
    end >= location.startLine &&
    end >= expected.line &&
    end <= expected.lineCount
  );
}

function matches(
  finding: Finding,
  expected: Expected,
  codes = finding.taxonomy?.cwe ?? [],
) {
  const category = (finding.taxonomy?.category ?? "")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[-_\s]+/g, " ")
    .trim()
    .toLowerCase();
  if (
    negatedCategory.test(category) ||
    !finding.locations?.some((location) => matchesLocation(location, expected))
  )
    return false;
  const cwes = codes.map((value) =>
    value.trim().replace(/^cwe-0*(\d+)$/i, "CWE-$1"),
  );
  if (
    expected.id === "private-key" &&
    cwes.includes("CWE-321") &&
    /^(?:embedded[- ]+)?(?:cryptographic(?:[- ]+signing)?|signing)[- ]+keys?(?:[- ]+(?:exposure|disclosure))?$/i.test(
      category,
    )
  )
    return true;
  if (expected.category === "sensitive-data-exposure") {
    const exact = runtimeCategoryCwes.get(category);
    if (exact) return cwes.includes(exact);
    // The endpoint returns a value loaded at runtime. Source storage is a different defect.
    return (
      (/disclos|expos|leak|authenticat|authoriz|access[- ]control/i.test(
        category,
      ) ||
        (explicitSecretCategory.test(category) &&
          /\bresponses?\b/i.test(category))) &&
      !/hard ?cod|^(?:credential|secret|password|token)s? in source|cleartext storage/i.test(
        category,
      ) &&
      cwes.some((cwe) => expected.cwes.includes(cwe))
    );
  }
  return (
    secretCategory.test(category) &&
    cwes.some(
      (cwe) =>
        expected.cwes.includes(cwe) ||
        (["CWE-200", "CWE-540"].includes(cwe) &&
          explicitSecretCategory.test(category)),
    )
  );
}

function matchesConsumer(location: SourceLocation, expected: Expected) {
  return (
    expected.consumerLine !== null &&
    matchesLocation(location, {
      ...expected,
      line: expected.consumerLine,
      endLine: expected.consumerLine,
    })
  );
}

function evidenceIssues(finding: Finding, fixture: Fixture, index: number) {
  const evidence = (finding.codeEvidence ?? []).map((entry) => {
    const code = entry.code?.replaceAll("\r\n", "\n").replace(/\n$/u, "");
    return {
      ...entry,
      code,
      endLine: entry.startLine + (code?.split("\n").length ?? 0) - 1,
    };
  });
  const incorrectSnippets = evidence
    .filter(
      (entry) =>
        !entry.code?.trim() ||
        !validSourceRange(entry, fixture) ||
        entry.code !==
          sourceText(entry.path, fixture)!
            .replaceAll("\r\n", "\n")
            .split("\n")
            .slice(entry.startLine - 1, entry.endLine)
            .join("\n"),
    )
    .map(({ path, startLine }) => ({ path, startLine }));
  const missingCaseEvidence = fixture.positives
    .filter(
      (expected) =>
        matches(finding, expected) &&
        !evidence.some(
          (entry) =>
            matchesLocation(entry, expected) ||
            matchesConsumer(entry, expected),
        ),
    )
    .map(({ id }) => id);
  return !evidence.length ||
    incorrectSnippets.length ||
    missingCaseEvidence.length
    ? [{ index, incorrectSnippets, missingCaseEvidence }]
    : [];
}

/** Grade retained final findings, never keyword mentions or deferred candidates. */
export function gradeResult(result: Result | undefined, fixture: Fixture) {
  const errors = [];
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  if (!Array.isArray(result?.findings)) errors.push("missing findings array");
  const cases = fixture.positives.map((expected) => ({
    id: expected.id,
    found: findings.some((finding) => matches(finding, expected)),
  }));
  const falsePositives = findings.flatMap<{
    index: number;
    unexpectedLocations?: string[];
    reason?: string;
  }>((finding, index) => {
    const matchedCases = fixture.positives.filter((expected) =>
      matches(finding, expected),
    );
    const unexpectedLocations = (finding.locations ?? [])
      .filter(
        (location) =>
          !validSourceRange(location, fixture) ||
          (!supportingLocation(location) &&
            !matchedCases.some(
              (expected) =>
                matchesLocation(location, expected) ||
                // This sentence establishes the audience of the independently matched status route.
                (expected.category === "sensitive-data-exposure" &&
                  normalizeSourcePath(location.path) ===
                    normalizeSourcePath("README.md") &&
                  location.startLine === fixture.statusAccessLine &&
                  (location.endLine ?? location.startLine) ===
                    fixture.statusAccessLine) ||
                matchesConsumer(location, expected),
            )),
      )
      .map((location) => location.path);
    if (unexpectedLocations.length) return [{ index, unexpectedLocations }];
    const cwes = finding.taxonomy?.cwe ?? [];
    if (
      cwes.length === 0 ||
      cwes.some(
        (cwe) =>
          !matchedCases.some((expected) => matches(finding, expected, [cwe])),
      )
    ) {
      return [{ index, reason: "no expected secret location and taxonomy" }];
    }
    return [];
  });
  const found = cases.filter((entry) => entry.found).length;
  if (found !== cases.length) errors.push("missing retained secret findings");
  if (falsePositives.length)
    errors.push("false positives or incorrect taxonomy/locations");
  const evidenceFailures = findings.flatMap((finding, index) =>
    evidenceIssues(finding, fixture, index),
  );
  if (evidenceFailures.length) errors.push("missing or invalid code evidence");
  const discoveryPassed = errors.length === 0;
  const retained = findings.filter((finding) =>
    fixture.positives.some(
      (expected) =>
        expected.category !== "sensitive-data-exposure" &&
        matches(finding, expected),
    ),
  );
  const withStatus = retained.filter((finding) =>
    [
      finding.title,
      finding.summary,
      finding.validation?.summary,
      ...(finding.validation?.limitations ?? []),
      finding.confidence?.rationale,
      finding.severity?.rationale,
      finding.remediation,
    ].some(
      (field) =>
        typeof field === "string" && /\bValidity unchecked\b/i.test(field),
    ),
  ).length;
  if (withStatus !== retained.length)
    errors.push(
      "missing validity status on retained checked-in credential findings",
    );
  return {
    passed: errors.length === 0,
    discoveryPassed,
    validityCopy: { withStatus, retainedCredentialFindings: retained.length },
    cases,
    recall: found / cases.length,
    falsePositiveCount: falsePositives.length,
    falsePositives,
    evidenceFailures,
    errors,
  };
}
