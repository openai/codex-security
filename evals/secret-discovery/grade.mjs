import { posix, win32 } from "node:path";

const explicitSecretTerms =
  /secrets?|credentials?|passwords?|tokens?|(?:api|private)[-_ ]?keys?|hard[-_ ]?cod(?:e[ds]?|ing)?/i;
const secretTerms = `${explicitSecretTerms.source}|sensitive[-_ ]?(?:data|information)[-_ ]?exposures?`;
const explicitSecretCategory = new RegExp(
  String.raw`\b(?:${explicitSecretTerms.source})\b`,
  "i",
);
const secretCategory = new RegExp(String.raw`\b(?:${secretTerms})\b`, "i");
const negatedSecretCategory = new RegExp(
  String.raw`^(?:(?:not(?:[-_\s]*a)?|non|no|without)[-_\s]*(?:${secretTerms})\b|(?:${secretTerms})[-_\s]*free\b)`,
  "i",
);
const supportingLocation = (location) =>
  /^(?:supporting|support|context|consumer|expected_control)$/.test(
    location.role ?? "",
  );

function matchesExclusion(path, pattern, repo) {
  const paths = [repo, pattern].some(
    (value) => value && win32.parse(value).root.length > 1,
  )
    ? win32
    : posix;
  let normalized = paths.normalize(pattern);
  if (
    normalized.endsWith(paths.sep) &&
    normalized !== paths.parse(normalized).root
  ) {
    normalized = normalized.slice(0, -1);
  }
  let entry = path;
  if (paths.isAbsolute(pattern) && repo) {
    const relative = paths.relative(repo, normalized);
    if (
      !paths.isAbsolute(relative) &&
      relative !== ".." &&
      !relative.startsWith(`..${paths.sep}`)
    ) {
      // The repository prefix is a literal path, not part of the exclusion glob.
      normalized = relative || ".";
    } else {
      entry = paths.join(repo, path);
    }
  }
  if (paths === win32) {
    entry = entry.toLowerCase();
    normalized = normalized.toLowerCase();
  }
  // A directory exclusion also excludes the fixture files beneath it.
  while (true) {
    if (
      paths.relative(entry, normalized) === "" ||
      paths.matchesGlob(entry, normalized)
    )
      return true;
    const parent = paths.dirname(entry);
    if (parent === entry) return false;
    entry = parent;
  }
}

function normalizeSourcePath(path) {
  const normalized = path?.replaceAll("\\", "/").replace(/^(?:\.\/)+/u, "");
  return process.platform === "win32" ? normalized?.toLowerCase() : normalized;
}

function sourceText(path, fixture) {
  return Object.entries(fixture.files).find(
    ([sourcePath]) =>
      normalizeSourcePath(sourcePath) === normalizeSourcePath(path),
  )?.[1];
}

function validSourceRange(location, fixture) {
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

function matchesLocation(location, expected) {
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

function matches(finding, expected) {
  const category = (finding.taxonomy?.category ?? "")
    .replaceAll("_", " ")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .trim();
  return (
    !negatedSecretCategory.test(category) &&
    secretCategory.test(category) &&
    finding.taxonomy?.cwe?.some((value) => {
      const cwe = value.trim().replace(/^cwe-0*(\d+)$/i, "CWE-$1");
      return (
        expected.cwes.includes(cwe) ||
        (["CWE-200", "CWE-540"].includes(cwe) &&
          explicitSecretCategory.test(category))
      );
    }) &&
    finding.locations?.some((location) => matchesLocation(location, expected))
  );
}

function matchesConsumer(location, expected) {
  return (
    expected.consumerLine !== null &&
    matchesLocation(location, {
      ...expected,
      line: expected.consumerLine,
      endLine: expected.consumerLine,
    })
  );
}

function validEvidence(finding, fixture) {
  const evidence = (finding.codeEvidence ?? []).map((entry) => {
    const code = entry.code?.replaceAll("\r\n", "\n").replace(/\n$/u, "");
    return {
      ...entry,
      code,
      endLine: entry.startLine + (code?.split("\n").length ?? 0) - 1,
    };
  });
  return (
    evidence.length > 0 &&
    evidence.every(
      (entry) =>
        Boolean(entry.code?.trim()) &&
        validSourceRange(entry, fixture) &&
        entry.code ===
          sourceText(entry.path, fixture)
            .replaceAll("\r\n", "\n")
            .split("\n")
            .slice(entry.startLine - 1, entry.endLine)
            .join("\n"),
    ) &&
    fixture.positives
      .filter((expected) => matches(finding, expected))
      .every((expected) =>
        evidence.some(
          (entry) =>
            matchesLocation(entry, expected) ||
            matchesConsumer(entry, expected),
        ),
      )
  );
}

/** Grade retained final findings, never keyword mentions or deferred candidates. */
export function gradeResult(result, fixture, repo) {
  const errors = [];
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  if (!Array.isArray(result?.findings)) errors.push("missing findings array");
  const cases = fixture.positives.map((expected) => ({
    id: expected.id,
    found: findings.some((finding) => matches(finding, expected)),
  }));
  const falsePositives = findings.flatMap((finding, index) => {
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
                (location.role === "sink" &&
                  matchesConsumer(location, expected)),
            )),
      )
      .map((location) => location.path);
    if (unexpectedLocations.length) return [{ index, unexpectedLocations }];
    const cwes = finding.taxonomy?.cwe ?? [];
    if (
      cwes.length === 0 ||
      cwes.some(
        (cwe) =>
          !fixture.positives.some((expected) =>
            matches(
              { ...finding, taxonomy: { ...finding.taxonomy, cwe: [cwe] } },
              expected,
            ),
          ),
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
  if (findings.some((finding) => !validEvidence(finding, fixture)))
    errors.push("missing or invalid code evidence");
  if (
    result?.coverage?.completeness !== "complete" ||
    result.coverage.deferred?.length ||
    result.coverage.surfaces?.some(
      (surface) => surface.disposition === "needs_follow_up",
    ) ||
    result.coverage.explicitExclusions?.some(({ pattern }) =>
      Object.keys(fixture.files).some((path) =>
        matchesExclusion(path, pattern, repo),
      ),
    )
  )
    errors.push("incomplete coverage");
  return {
    passed: errors.length === 0,
    cases,
    recall: found / cases.length,
    falsePositiveCount: falsePositives.length,
    falsePositives,
    errors,
  };
}
