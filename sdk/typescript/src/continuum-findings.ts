import { hash } from "node:crypto";
import { CodexSecurityError } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import {
  CLOUD_EVIDENCE_BYTES,
  CloudEvidenceSizeError,
  DEFAULT_CLOUD_STRING_BYTES,
  type ExternalImportTarget,
  repositoryUrlKey,
  validateEnrichedExternalEvidence,
  validateExternalEvidence,
  validateExternalEvidenceJson,
} from "./external-import-contract.js";
import type { ImportedPackage, Provider } from "./external-import-models.js";
import { isRecord } from "./record.js";
import {
  array,
  awsTimestampSeconds,
  concreteVersion,
  normalizeRecords,
  optionalArray,
  scannerJsonReader,
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
export const continuumIssueFormat = "aws-continuum-code-issues/v1";
const findingArn =
  /^(arn:[a-z0-9-]+:continuum:[a-z0-9-]+:\d{12}:environments\/([a-z0-9]+))\/code-findings\/([a-z0-9]+)$/u;
const issueArn =
  /^(arn:[a-z0-9-]+:continuum:[a-z0-9-]+:\d{12}:environments\/([a-z0-9]+))\/code-issues\/([a-z0-9]+)$/u;

export function findingIdentity(value: unknown) {
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
  return { arn, scope: match[1]!, id: match[3]! };
}

export function issueIdentity(value: unknown) {
  const issue = record(value, "Continuum issue");
  const arn = requiredText(issue["issueArn"], "Continuum issue ARN");
  const match = issueArn.exec(arn);
  if (!match || issue["issueId"] !== match[3])
    throw new Error("Expected a Continuum issue ARN matching its issueId.");
  return { arn, scope: match[1]!, environmentId: match[2]!, id: match[3]! };
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
  const isIssue =
    data?.["format"] === continuumIssueFormat || issueArn.test(id);
  const native = data?.[isIssue ? "issue" : "finding"];
  const marked = isIssue || data?.["format"] === format;
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
  const { arn, scope } = isIssue
    ? issueIdentity(native)
    : findingIdentity(native);
  if (arn !== id)
    throw new Error(
      `Continuum source finding ID does not match the retained ${isIssue ? "issue" : "finding"} ARN.`,
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

function findingVulnerabilities(row: Record<string, unknown>) {
  return array(row["vulnerabilities"] ?? [], "Continuum vulnerabilities").map(
    (item) => record(item, "Continuum vulnerability"),
  );
}

function* findingCodeLocations(
  row: Record<string, unknown>,
  vulnerabilities: Record<string, unknown>[],
) {
  yield {
    filePath: row["filePath"],
    startLine: row["lineNumber"],
    endLine: row["endLine"],
    code: row["vulnerableCode"],
  };
  for (const vulnerability of vulnerabilities) {
    for (const value of array(
      vulnerability["locations"] ?? [],
      "Continuum vulnerability locations",
    )) {
      const location = record(value, "Continuum vulnerability location");
      yield {
        filePath: location["filePath"],
        startLine: location["startLine"],
        endLine: location["endLine"],
        code: vulnerability["code"],
      };
    }
  }
}

function locationLine(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0
    ? value
    : null;
}

function codeLocations(
  ranges: Iterable<{
    filePath: unknown;
    startLine: unknown;
    endLine: unknown;
    code?: unknown;
  }>,
) {
  const locations: { path: string; line: number | null }[] = [];
  const seen = new Set<string>();
  let endLine: number | null = null;
  let snippet: string | null = null;
  for (const range of ranges) {
    const path = repositoryFilePath(range.filePath);
    if (!path) continue;
    const line = locationLine(range.startLine);
    const end = locationLine(range.endLine);
    const key = JSON.stringify([path, line]);
    if (!seen.has(key)) {
      seen.add(key);
      locations.push({ path, line });
    }
    // The flat location and first nested location can describe the same range.
    if (locations[0]!.path === path && locations[0]!.line === line) {
      if (line !== null && end !== null && end >= line) endLine ??= end;
      snippet ??= text(range.code);
    }
  }
  return { locations, code: { end_line: endLine, snippet } };
}

function reportRows(input: unknown) {
  if (Array.isArray(input)) return { rows: input, summary: false };
  const document = record(input, "Continuum report");
  if (
    Object.hasOwn(document, "nextToken") ||
    Object.hasOwn(document, "NextToken")
  )
    throw new Error(
      "Continuum export has a continuation token; supply the complete paginated CLI output.",
    );
  if (!(
    "items" in document ||
    "findingArn" in document ||
    "finding" in document
  ))
    throw new Error(
      "Expected a Continuum ListCodeFindings, GetCodeFinding, or finding with artifacts.",
    );
  const summary = "items" in document;
  return {
    rows: summary ? array(document["items"], "Continuum items") : [document],
    summary,
  };
}

function isFindingCapture(value: unknown): value is Record<string, unknown> {
  return isRecord(value) && !("findingArn" in value) && "finding" in value;
}

export function readPatch(value: unknown) {
  const artifact = record(value, "Continuum patch artifact");
  const patch = requiredText(artifact["patch"], "Continuum patch content");
  const sizeBytes = Buffer.byteLength(patch);
  const patchSha256 = hash("sha256", patch);
  if (
    artifact["sizeBytes"] !== sizeBytes ||
    artifact["patchSha256"] !== patchSha256
  )
    throw new Error(
      "Continuum patch content does not match its sizeBytes or patchSha256.",
    );
  return {
    artifactId: requiredText(
      artifact["artifactId"],
      "Continuum patch artifact ID",
    ),
    patch,
    patchSha256,
    sizeBytes,
    ...(artifact["format"] !== undefined && {
      format: requiredText(artifact["format"], "Continuum patch format"),
    }),
    ...(artifact["repositoryName"] !== undefined && {
      repositoryName: requiredText(
        artifact["repositoryName"],
        "Continuum patch repository",
      ),
    }),
  };
}

function projectArtifactBodies(
  artifacts: Record<string, unknown>[],
  key: "patches" | "evidence_artifacts",
  target: ExternalImportTarget,
  project: (artifacts: object[]) => ExternalFinding["evidence"],
) {
  if (!artifacts.length || target === "local") return project(artifacts);
  try {
    return project(artifacts);
  } catch (error) {
    if (!(error instanceof CloudEvidenceSizeError)) throw error;
  }

  // Measure bodies at their actual Cloud JSON depth and wire size.
  const bodyKey = key === "patches" ? "patch" : "body";
  const wireBytes = (entry: object) =>
    validateExternalEvidenceJson({ source_data: { [key]: [entry] } }, target);
  const marker = { contentOmitted: "cloud_evidence_limit" };
  const markerBytes = wireBytes(marker);
  const sizes = artifacts.map((artifact) => {
    try {
      return wireBytes({ [bodyKey]: artifact[bodyKey] }) - markerBytes;
    } catch (error) {
      if (error instanceof CloudEvidenceSizeError) return Infinity;
      throw error;
    }
  });
  const projected = artifacts.map(({ [bodyKey]: _, ...descriptor }, index) =>
    sizes[index]! > 0 ? { ...descriptor, ...marker } : artifacts[index]!,
  );
  const result = project(projected);
  let remaining =
    CLOUD_EVIDENCE_BYTES - validateExternalEvidenceJson(result, target);
  for (const [index, bytes] of sizes.entries()) {
    if (bytes > 0 && bytes <= remaining) {
      projected[index] = artifacts[index]!;
      remaining -= bytes;
    }
  }
  result.source_data![key] = projected;
  return result;
}

function subcategoryCwe(row: Record<string, unknown>) {
  return /^(CWE-[1-9]\d*):/u.exec(text(row["subCategory"]) ?? "")?.[1];
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

function linkedIssueFindings(
  value: unknown,
  issue: Record<string, unknown>,
  scope: string,
) {
  const ids = array(issue["findingIds"], "Continuum issue findingIds").map(
    (id) => requiredText(id, "Continuum issue finding ID"),
  );
  const missing = new Set(ids);
  const findings = new Map<string, Record<string, unknown>>();
  const invalidLinks =
    "Supply exactly one detail response per Continuum issue finding ID.";
  if (ids.length === 0 || missing.size !== ids.length)
    throw new Error(invalidLinks);
  for (const item of array(value, "Continuum issue findings")) {
    const { id, scope: findingScope } = findingIdentity(item);
    if (findingScope !== scope)
      throw new Error(
        "Continuum issue and linked finding must share an environment.",
      );
    if (!missing.delete(id)) throw new Error(invalidLinks);
    findings.set(id, record(item, "Continuum finding"));
  }
  if (missing.size) throw new Error(invalidLinks);
  return ids.map((id) => findings.get(id)!);
}

function issueFindingEvidence(
  finding: Record<string, unknown>,
  includeReviewEvidence: boolean,
) {
  const dependencyFields = (row: Record<string, unknown>) => ({
    cveId: text(row["cveId"]),
    affectedPackages: Array.isArray(row["affectedPackages"])
      ? row["affectedPackages"]
      : [],
  });
  const vulnerableCode =
    includeReviewEvidence && text(finding["vulnerableCode"]);
  const mitigation = includeReviewEvidence && text(finding["mitigation"]);
  const validation = finding["validation"];
  // Retain the inputs needed to replay the stored issue. The export on disk
  // retains the full finding details.
  return {
    findingArn: finding["findingArn"],
    findingId: finding["findingId"],
    environmentId: finding["environmentId"],
    ocsfClass:
      finding["posture"] != null
        ? "APPLICATION_SECURITY_POSTURE_FINDING"
        : text(finding["ocsfClass"]),
    ...dependencyFields(finding),
    filePath: text(finding["filePath"]),
    lineNumber: locationLine(finding["lineNumber"]),
    endLine: locationLine(finding["endLine"]),
    ...(vulnerableCode && { vulnerableCode }),
    ...(mitigation && { mitigation }),
    ...(includeReviewEvidence && isRecord(validation) && { validation }),
    vulnerabilities: findingVulnerabilities(finding).map((vulnerability) => {
      const code = includeReviewEvidence && text(vulnerability["code"]);
      return {
        ...dependencyFields(vulnerability),
        locations: vulnerability["locations"] ?? [],
        ...(code && { code }),
      };
    }),
  };
}

function issueEvidenceBody(artifact: Record<string, unknown>) {
  const body = artifact["body"];
  if (!isRecord(body)) return;
  if (artifact["artifactType"] === "VALIDATION_EVIDENCE") {
    if (isRecord(body["validationEvidence"]))
      return { validationEvidence: body["validationEvidence"] };
    if (typeof body["raw"] === "string") return { raw: body["raw"] };
  }
  const projection = body["prevalidationSignals"];
  if (artifact["artifactType"] !== "EVIDENCE" || !isRecord(projection)) return;
  const signals = array(
    projection["signals"] ?? [],
    "Continuum evidence signals",
  ).map((signal) => record(signal, "Continuum evidence signal"));
  return { prevalidationSignals: { ...projection, signals } };
}

function issueEvidenceDescriptor(artifact: Record<string, unknown>) {
  return {
    artifactId: requiredText(
      artifact["artifactId"],
      "Continuum evidence artifact ID",
    ),
    artifactType: artifact["artifactType"],
    ...(artifact["createdAt"] != null && { createdAt: artifact["createdAt"] }),
    ...(artifact["mediaType"] != null && { mediaType: artifact["mediaType"] }),
    ...(artifact["producer"] != null && { producer: artifact["producer"] }),
  };
}

export function singleFindingValidationIssue(
  issue: unknown,
  issueId: unknown,
  finding: ReturnType<typeof findingIdentity>,
) {
  if (!isRecord(issue) || typeof issueId !== "string") return null;
  const arn = `${finding.scope}/code-issues/${issueId}`;
  const ids = issue["findingIds"];
  if (
    issue["issueArn"] !== arn ||
    issue["issueId"] !== issueId ||
    !Array.isArray(ids) ||
    ids.length !== 1 ||
    ids[0] !== finding.id
  )
    return null;
  return { issueArn: arn, issueId, findingIds: [finding.id] };
}

export function selectFindingValidationArtifact(
  artifact: Record<string, unknown>,
  findingId: unknown,
) {
  if (artifact["artifactType"] !== "VALIDATION_EVIDENCE") return;
  const body = issueEvidenceBody(artifact);
  if (!body) return;
  const results = body.validationEvidence?.["perFindingResults"];
  if (results === undefined) return { scope: "issue", artifact };
  // A bundle's top-level proof can belong to a different finding.
  const matches = array(results, "Continuum per-finding results")
    .map((value) => record(value, "Continuum per-finding result"))
    .filter((result) => result["findingId"] === findingId);
  if (matches.length === 0) return;
  return {
    scope: "finding",
    artifact: {
      ...issueEvidenceDescriptor(artifact),
      body: {
        validationEvidence: {
          ...(matches.length === 1 && {
            exploitable: matches[0]!["exploitable"],
          }),
          perFindingResults: matches,
        },
      },
    },
  };
}

function issueEvidenceArtifacts(artifacts: Record<string, unknown>[]) {
  return artifacts.flatMap((artifact) => {
    const body = issueEvidenceBody(artifact);
    return body ? [{ ...issueEvidenceDescriptor(artifact), body }] : [];
  });
}

function normalizeContinuumIssues(
  document: Record<string, unknown>,
  repository: string,
  target: ExternalImportTarget,
): ExternalFindings {
  const environmentId = requiredText(
    document["environmentId"],
    "Continuum environment ID",
  );
  const rows = array(document["issues"], "Continuum issues");
  const scopes = new Set<string>();
  const result = normalizeRecords(
    rows,
    (value) => {
      const row = record(value, "Continuum issue record");
      const { artifacts, ...issue } = record(row["issue"], "Continuum issue");
      const { arn, id, scope } = issueIdentity(issue);
      const issueArtifacts = array(
        artifacts ?? row["evidenceArtifacts"] ?? [],
        "Continuum issue artifacts",
      ).map((artifact) => record(artifact, "Continuum issue artifact"));
      const evidenceArtifacts = issueEvidenceArtifacts(issueArtifacts);
      const patches = issueArtifacts
        .filter((artifact) => artifact["artifactType"] === "PATCH")
        .map((artifact) => {
          const body = record(artifact["body"], "Continuum patch body");
          return readPatch({
            ...record(body["patch"], "Continuum patch"),
            artifactId: artifact["artifactId"],
          });
        });
      const verdicts = new Set<string>();
      for (const artifact of evidenceArtifacts) {
        for (const signal of artifact.body.prevalidationSignals?.signals ??
          []) {
          const subject = signal["subjectRef"];
          const exploitability = signal["exploitability"];
          if (
            signal["dimension"] !== "EXPLOITABILITY" ||
            (subject !== id && subject !== arn) ||
            !isRecord(exploitability)
          )
            continue;
          const verdict = text(exploitability["verdict"]);
          if (verdict) verdicts.add(verdict);
        }
      }
      const scannerVerdict = verdicts.size > 1 ? "MIXED" : [...verdicts][0];
      const linked = linkedIssueFindings(row["findings"], issue, scope);
      const findings = linked.map((finding) =>
        issueFindingEvidence(finding, true),
      );
      const ranges = findings.flatMap((finding) =>
        Array.from(findingCodeLocations(finding, finding.vulnerabilities)),
      );
      const { locations, code } = codeLocations([
        ...ranges.filter(({ startLine }) => locationLine(startLine) !== null),
        ...ranges.filter(({ startLine }) => locationLine(startLine) === null),
      ]);
      const all = findings.flatMap((finding) => [
        finding,
        ...finding.vulnerabilities,
      ]);
      const advisories = [...new Set(strings(all.map((row) => row.cveId)))];
      const packages = all.flatMap((row) => row.affectedPackages);
      const dependency = advisories.length > 0 || packages.length > 0;
      const posture = findings.some(
        (finding) =>
          finding.ocsfClass === "APPLICATION_SECURITY_POSTURE_FINDING",
      );
      const status = requiredText(issue["status"], "Continuum issue status");
      const synopsis = requiredText(
        issue["synopsis"],
        "Continuum issue synopsis",
      );
      const details =
        posture || (!scannerVerdict && locations[0]?.line == null)
          ? undefined
          : {
              details: {
                kind: dependency ? "advisory" : "sast",
                ...(dependency && { advisory: { source: "repository" } }),
                repository: { url: repository },
                source_status: status,
                ...(scannerVerdict && { scanner_verdict: scannerVerdict }),
                remediation_instructions: text(issue["summary"]),
                code: { ...code, snippet: null },
              },
            };
      const reviewDetails = details && {
        details: {
          ...details.details,
          remediation_instructions:
            details.details.remediation_instructions ??
            findings.find(({ mitigation }) => mitigation)?.mitigation ??
            null,
          code,
        },
      };
      const dependencyEvidence = dependency
        ? {
            advisory_ids:
              target === "cloud" ? advisories.slice(0, 100) : advisories,
            packages: affectedPackages(packages, target),
          }
        : undefined;
      const source = {
        format: continuumIssueFormat,
        sourceRepositoryUrl: repository,
        environmentId,
        issue,
        ...(evidenceArtifacts.length && {
          evidence_artifacts: evidenceArtifacts,
        }),
      };
      const compactSource = structuredClone({
        ...source,
        findings: linked.map((finding) => issueFindingEvidence(finding, false)),
      });
      const findingsWithVerdicts = compactSource.findings.map(
        (finding, index) => {
          const verdict = text(findings[index]?.validation?.["verdict"]);
          return verdict ? { ...finding, validation: { verdict } } : finding;
        },
      );
      const evidence = validateEnrichedExternalEvidence(
        {
          title: requiredText(issue["name"], "Continuum issue name"),
          severity: text(issue["severity"])?.toLowerCase() ?? "unknown",
          description: [synopsis, text(issue["severityReasoning"])]
            .filter(Boolean)
            .join("\n\n"),
          // Keep every reported range in source_data, including ranges beyond
          // the Cloud limit for navigable locations.
          locations: target === "cloud" ? locations.slice(0, 100) : locations,
          source_updated_at:
            statusUpdatedAt(issue["updatedAt"]) ??
            statusUpdatedAt(issue["statusUpdatedAt"]),
          source_data: compactSource,
          ...(scannerVerdict &&
            details && {
              details: {
                ...details.details,
                remediation_instructions: null,
                code: null,
              },
            }),
        },
        target,
        {
          ...reviewDetails,
          ...dependencyEvidence,
          source_data: structuredClone({ ...source, findings }),
        },
        // Bulky linked validation evidence can exceed the Cloud record limit.
        // Keep the per-finding verdicts with the structured review fields if they fit.
        {
          ...reviewDetails,
          ...dependencyEvidence,
          source_data: { ...compactSource, findings: findingsWithVerdicts },
        },
        dependencyEvidence
          ? { ...reviewDetails, ...dependencyEvidence }
          : undefined,
        reviewDetails,
        dependencyEvidence ? { ...details, ...dependencyEvidence } : undefined,
        details,
        dependencyEvidence,
      );
      if (!patches.length) return evidence;
      // Fit optional patch bodies after selecting the scanner evidence to retain.
      return projectArtifactBodies(patches, "patches", target, (patches) =>
        validateExternalEvidence(
          { ...evidence, source_data: { ...evidence.source_data, patches } },
          target,
        ),
      );
    },
    (value) => {
      const issue = issueIdentity(
        record(value, "Continuum issue record")["issue"],
      );
      if (issue.environmentId !== environmentId)
        throw new Error(
          "Continuum issue ARN does not match the export environment.",
        );
      scopes.add(issue.scope);
      return issue.arn;
    },
    target,
  );
  if (scopes.size > 1)
    throw new Error("Continuum issues must belong to the same environment.");
  return result;
}

export function normalizeContinuumFindings(
  input: unknown,
  sourceRepositoryUrl?: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const issueReport =
    isRecord(input) && input["format"] === continuumIssueFormat;
  const capturedSource =
    issueReport && input["sourceRepositoryUrl"] !== undefined
      ? declaredScannerRepositoryUrl(
          input["sourceRepositoryUrl"],
          "Continuum",
          target,
        )
      : undefined;
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl || capturedSource,
    "Continuum",
    target,
  );
  if (issueReport) {
    if (
      capturedSource &&
      repositoryUrlKey(capturedSource) !== repositoryUrlKey(repository)
    )
      throw new Error(
        "The Continuum export repository does not match the declared source repository.",
      );
    const findings = normalizeContinuumIssues(
      input,
      capturedSource ?? repository,
      target,
    );
    return capturedSource
      ? { ...findings, report: { sourceRepositoryUrl: capturedSource } }
      : findings;
  }
  const { rows, summary } = reportRows(input);
  const scopes = new Set<string>();
  const output = normalizeRecords(
    rows,
    (value) => {
      const capture = !summary && isFindingCapture(value) ? value : undefined;
      const row = record(
        capture ? capture["finding"] : value,
        "Continuum finding",
      );
      const patches = optionalArray(
        capture?.["patches"],
        "Continuum patches",
      ).map(readPatch);
      const linkedIssue =
        text(row["createdIssueId"]) ?? text(row["duplicateOfIssueId"]);
      let validationIssue:
        ReturnType<typeof singleFindingValidationIssue> | undefined;
      const evidenceArtifacts = issueEvidenceArtifacts(
        optionalArray(
          capture?.["evidenceArtifacts"],
          "Continuum evidence artifacts",
        ).flatMap((value) => {
          const selected = selectFindingValidationArtifact(
            record(value, "Continuum validation artifact"),
            row["findingId"],
          );
          if (!selected) return [];
          if (selected.scope === "issue") {
            validationIssue ??= singleFindingValidationIssue(
              capture?.["validationIssue"],
              linkedIssue,
              findingIdentity(row),
            );
            if (!validationIssue) return [];
          }
          return [selected.artifact];
        }),
      );
      if ((patches.length || evidenceArtifacts.length) && !linkedIssue)
        throw new Error(
          `Continuum ${patches.length ? "patches" : "validation artifacts"} require a finding linked to an issue.`,
        );
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
      const vulnerabilities = findingVulnerabilities(row);
      const { locations, code } = codeLocations(
        findingCodeLocations(row, vulnerabilities),
      );
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
            weakness_ids: strings(row["cweIds"]),
            remediation_instructions: text(row["mitigation"]),
            code,
          },
        }),
        source_data: {
          format,
          sourceRepositoryUrl: repository,
          finding: structuredClone(row),
          ...(validationIssue && { validation_issue: validationIssue }),
        },
      };
      const updatedAt = statusUpdatedAt(row["statusUpdatedAt"]);
      const enrichment = {
        packages: affectedPackages(packages, target),
        source_updated_at: updatedAt,
      };
      // Native code findings can identify a CWE only in subCategory.
      const namedCwe =
        evidence.details?.weakness_ids.length === 0
          ? subcategoryCwe(row)
          : undefined;
      const inferred = namedCwe
        ? { details: { ...evidence.details, weakness_ids: [namedCwe] } }
        : undefined;
      // Keep previously admissible evidence if an optional projection exceeds the Cloud budget.
      return projectArtifactBodies(
        structuredClone(evidenceArtifacts),
        "evidence_artifacts",
        target,
        (validation) =>
          projectArtifactBodies(patches, "patches", target, (patches) =>
            validateEnrichedExternalEvidence(
              {
                ...evidence,
                source_data: {
                  ...evidence.source_data,
                  ...(validation.length && { evidence_artifacts: validation }),
                  ...(patches.length && { patches }),
                },
              },
              target,
              inferred ? { ...enrichment, ...inferred } : undefined,
              enrichment,
              packages.length && updatedAt !== null
                ? { source_updated_at: updatedAt }
                : undefined,
              inferred,
            ),
          ),
      );
    },
    (value) => {
      const { arn, scope } = findingIdentity(
        !summary && isFindingCapture(value) ? value["finding"] : value,
      );
      scopes.add(scope);
      return arn;
    },
    target,
  );
  if (scopes.size > 1)
    throw new Error("Continuum findings must belong to the same environment.");
  return output;
}

export const readContinuumFindings = scannerJsonReader(
  normalizeContinuumFindings,
);
