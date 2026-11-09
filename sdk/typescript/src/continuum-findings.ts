import { CodexSecurityError } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import {
  DEFAULT_CLOUD_STRING_BYTES,
  type ExternalImportTarget,
  validateEnrichedExternalEvidence,
} from "./external-import-contract.js";
import type { ImportedPackage, Provider } from "./external-import-models.js";
import { isRecord } from "./record.js";
import {
  array,
  awsTimestampSeconds,
  concreteVersion,
  normalizeRecords,
  readScannerJson,
  record,
  repositoryFilePath,
  requiredText,
  strings,
  text,
} from "./scanner-import.js";
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

const format = "aws-continuum-code-findings/v1";
const findingArn =
  /^(arn:[a-z0-9-]+:continuum:[a-z0-9-]+:\d{12}:environments\/([a-z0-9]+))\/code-findings\/([a-z0-9]+)$/u;

function identity(value: unknown) {
  const row = record(value, "Continuum finding");
  const arn = requiredText(row["findingArn"], "Continuum finding ARN");
  const match = findingArn.exec(arn);
  if (
    !match ||
    row["environmentId"] !== match[2] ||
    row["findingId"] !== match[3]
  )
    throw new Error(
      "Expected a Continuum finding ARN matching its environmentId and findingId.",
    );
  return { arn, scope: match[1]! };
}

function retainedRepository(
  provider: Provider,
  finding: ExternalFinding,
  target: ExternalImportTarget,
) {
  const {
    source_finding_id: id,
    evidence: { source_data: data },
  } = finding;
  const native = data?.["finding"];
  const marked = data?.["format"] === format;
  const nativeArn =
    isRecord(native) && findingArn.test(text(native["findingArn"]) ?? "");
  if (provider !== "continuum") {
    if (
      marked ||
      (data?.["sourceRepositoryUrl"] &&
        nativeArn &&
        native["findingArn"] === id)
    )
      throw new CodexSecurityError(
        "Retained AWS Continuum evidence requires the continuum provider.",
      );
    return;
  }
  if (!marked && !nativeArn && !findingArn.test(id)) return;
  const { arn, scope } = identity(native);
  if (arn !== id)
    throw new Error(
      "Continuum source finding ID does not match the retained finding ARN.",
    );
  return {
    url: declaredScannerRepositoryUrl(
      data?.["sourceRepositoryUrl"],
      "Continuum",
      target,
    ),
    scope,
  };
}

export const continuumReportRepositories = repositoryScopeValidator(
  { provider: "continuum", label: "AWS Continuum", scope: "environment" },
  retainedRepository,
);

function codeLocations(
  row: Record<string, unknown>,
  vulnerabilities: Record<string, unknown>[],
) {
  const locations: { path: string; line: number | null }[] = [];
  const seen = new Set<string>();
  let endLine: number | null = null;
  let snippet: string | null = null;
  function add(
    value: unknown,
    start: unknown,
    end: unknown,
    fragment: unknown,
  ) {
    const path = repositoryFilePath(value);
    if (!path) return;
    const line =
      typeof start === "number" && Number.isSafeInteger(start) && start > 0
        ? start
        : null;
    const key = JSON.stringify([path, line]);
    if (!seen.has(key)) {
      seen.add(key);
      locations.push({ path, line });
    }
    // The flat location and first nested location can describe the same range.
    if (locations[0]!.path === path && locations[0]!.line === line) {
      if (
        line !== null &&
        typeof end === "number" &&
        Number.isSafeInteger(end) &&
        end >= line
      )
        endLine ??= end;
      snippet ??= text(fragment);
    }
  }
  add(
    row["filePath"],
    row["lineNumber"],
    row["endLine"],
    row["vulnerableCode"],
  );
  for (const vulnerability of vulnerabilities) {
    for (const value of array(
      vulnerability["locations"] ?? [],
      "Continuum vulnerability locations",
    )) {
      const location = record(value, "Continuum vulnerability location");
      add(
        location["filePath"],
        location["startLine"],
        location["endLine"],
        vulnerability["code"],
      );
    }
  }
  return { locations, code: { end_line: endLine, snippet } };
}

function reportRows(input: unknown, previous: boolean) {
  if (Array.isArray(input) && !previous) return { rows: input, summary: false };
  const document = record(input, "Continuum report");
  if (
    Object.hasOwn(document, "nextToken") ||
    Object.hasOwn(document, "NextToken")
  )
    throw new Error(
      "Continuum export has a continuation token; supply the complete paginated CLI output.",
    );
  if (!("items" in document || "findingArn" in document))
    throw new Error(
      "Expected a Continuum ListCodeFindings or GetCodeFinding response.",
    );
  const summary = "items" in document;
  return {
    rows: summary ? array(document["items"], "Continuum items") : [document],
    summary,
  };
}

// Continuum's own findings name their weakness only as "CWE-89: ..." in subCategory.
function weaknessIds(row: Record<string, unknown>) {
  const ids = strings(row["cweIds"]);
  if (ids.length > 0) return ids;
  const named = /^(CWE-[1-9]\d*):/u.exec(text(row["subCategory"]) ?? "")?.[1];
  return named ? [named] : [];
}

function statusUpdatedAt(value: unknown) {
  const seconds = Math.floor(awsTimestampSeconds(value));
  return Number.isSafeInteger(seconds) && seconds >= 0 ? seconds : null;
}

const versionEcosystems = new Map([
  ["gradle", "maven"],
  ["pnpm", "npm"],
  ["yarn", "npm"],
]);

function affectedPackages(
  items: unknown[],
  target: ExternalImportTarget,
): ImportedPackage[] {
  const unique = new Map<string, ImportedPackage>();
  const field = (value: unknown) => {
    const result = text(value);
    return result &&
      !result.includes("\0") &&
      (target === "local" ||
        Buffer.byteLength(result) <= DEFAULT_CLOUD_STRING_BYTES)
      ? result
      : null;
  };
  for (const item of items) {
    if (!isRecord(item)) continue;
    const name = field(item["name"]);
    if (!name) continue;
    const ecosystem = field(item["packageManager"]);
    const manager = ecosystem?.toLowerCase();
    const syntax = manager ? (versionEcosystems.get(manager) ?? manager) : null;
    const version = (value: unknown) =>
      concreteVersion(field(value), syntax, false);
    const fixed = version(item["fixedInVersion"]);
    const pkg = {
      name,
      ecosystem,
      installed_version: version(item["version"]),
      fixed_versions: fixed ? [fixed] : [],
    };
    unique.set(JSON.stringify(pkg), pkg);
    // The Cloud contract accepts 100 structured packages. The native row keeps them all.
    if (target === "cloud" && unique.size === 100) break;
  }
  return [...unique.values()];
}

function normalize(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget,
  previous: boolean,
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Continuum",
    target,
  );
  const { rows, summary } = reportRows(input, previous);
  const scopes = new Set<string>();
  const output = normalizeRecords(
    rows,
    (value) => {
      const row = record(value, "Continuum finding");
      if (
        row["type"] !== "CONTINUUM_CODE_VULN" &&
        row["type"] !== "CUSTOMER_CODE_VULN"
      )
        throw new Error(
          "Expected a Continuum code vulnerability finding type.",
        );
      const severity = requiredText(
        row["severity"],
        "Continuum severity",
      ).toLowerCase();
      const vulnerabilities = array(
        row["vulnerabilities"] ?? [],
        "Continuum vulnerabilities",
      ).map((item) => record(item, "Continuum vulnerability"));
      const { locations, code } = codeLocations(row, vulnerabilities);
      const source = requiredText(row["source"], "Continuum source");
      const status = requiredText(row["status"], "Continuum status");
      const validation = record(
        row["validation"] ?? {},
        "Continuum validation",
      );
      const all = [row, ...vulnerabilities];
      const advisoryIds = [
        ...new Set(strings(all.map((item) => item["cveId"]))),
      ];
      const packages = all.flatMap((item) =>
        Array.isArray(item["affectedPackages"]) ? item["affectedPackages"] : [],
      );
      const packageFinding = advisoryIds.length > 0 || packages.length > 0;
      const posture =
        row["ocsfClass"] === "APPLICATION_SECURITY_POSTURE_FINDING" ||
        row["posture"] != null;
      const codeFinding =
        !summary &&
        !posture &&
        !packageFinding &&
        (code.snippet !== null ||
          locations.some((location) => location.line !== null));
      const evidence = {
        title: requiredText(row["title"], "Continuum title"),
        severity:
          severity === "fatal"
            ? "critical"
            : severity === "other"
              ? "unknown"
              : severity,
        description: text(row["detailedDescription"]) ?? text(row["summary"]),
        locations,
        advisory_ids: advisoryIds,
        source_scan_id: text(row["scanRunId"]),
        ...(codeFinding && {
          details: {
            kind: "sast",
            repository: { url: repository },
            scanner_origin: source,
            scanner_verdict: text(validation["verdict"]),
            source_status: status,
            // Earlier releases read cweIds only; keep their replay projection.
            weakness_ids: previous ? strings(row["cweIds"]) : weaknessIds(row),
            remediation_instructions: text(row["mitigation"]),
            code,
          },
        }),
        source_data: {
          format,
          sourceRepositoryUrl: repository,
          finding: structuredClone(row),
        },
      };
      const updatedAt = previous
        ? null
        : statusUpdatedAt(row["statusUpdatedAt"]);
      // Keep the status timestamp when structured packages exceed the Cloud budget.
      return validateEnrichedExternalEvidence(
        evidence,
        target,
        previous
          ? undefined
          : {
              packages: affectedPackages(packages, target),
              source_updated_at: updatedAt,
            },
        packages.length && updatedAt !== null
          ? { source_updated_at: updatedAt }
          : undefined,
      );
    },
    (value) => {
      const { arn, scope } = identity(value);
      scopes.add(scope);
      return arn;
    },
    target,
  );
  if (scopes.size > 1)
    throw new Error("Continuum findings must belong to the same environment.");
  return output;
}

export function normalizeContinuumFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalize(input, sourceRepositoryUrl, target, false);
}

/** @internal Reconstruct the original evidence for an interrupted Cloud request. */
export function normalizePreviousContinuumFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalize(input, sourceRepositoryUrl, target, true);
}

export async function readContinuumFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeContinuumFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
