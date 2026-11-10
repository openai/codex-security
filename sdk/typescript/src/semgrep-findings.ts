import { markPreviousCloudProjection } from "./reader-selection.js";
import {
  normalizeSemgrepPlatformFindings,
  isSemgrepPlatformFormat,
  semgrepPlatformLegacyFormat,
  semgrepPlatformFormat,
} from "./semgrep-platform-findings.js";
import { isRecord } from "./record.js";
import {
  guardianSelectionFormat,
  normalizeGuardianSelection,
} from "./semgrep-guardian-findings.js";
import { parseHostedScannerJson } from "./hosted-scanner-http.js";
import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  cloudRepositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type {
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  messageText,
  nativeResultPath,
  parseNativeJsonResult,
  position,
  projectNativeJsonResult,
  sourceRepositoryUrl,
  ungatedText,
  weaknessIds,
} from "./native-json-findings.js";
import {
  array,
  normalizeRecords,
  optionalArray,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  sarifRunRepositories,
  sarifRunResults,
  stableId,
  readSarifRuns,
  text,
  validateSarifRuleReference,
} from "./scanner-import.js";

export interface SemgrepImportOptions {
  /** Independent source references from the SDK reader. */
  sourceRepositories?: readonly ExternalSourceRepository[];
  /** Source repository declared by the caller; never inferred from the destination. */
  sourceRepositoryUrl: string;
}

function sourceRepository(options: Partial<SemgrepImportOptions>): string {
  return sourceRepositoryUrl(options?.sourceRepositoryUrl, "Semgrep");
}

const severityLevels = new Map([
  ["CRITICAL", "critical"],
  ["HIGH", "high"],
  ["MEDIUM", "medium"],
  ["LOW", "low"],
  ["ERROR", "high"],
  ["WARNING", "medium"],
  ["INFO", "low"],
]);

function severity(value: unknown): string {
  return typeof value === "string"
    ? (severityLevels.get(value) ?? "unknown")
    : "unknown";
}

function identity(
  rule: string,
  path: string,
  line: number,
  column: number,
  endLine: number,
  endColumn: number,
): string {
  // CE omits fingerprints and source snippets. Its fallback is stable only while the range is stable.
  return stableId("semgrep-location", [
    rule,
    path,
    line,
    column,
    endLine,
    endColumn,
  ]);
}

function jsonIdentity(value: unknown): string {
  const result = record(value, "Semgrep result");
  const extra = record(result["extra"], "Semgrep extra");
  const supplied = ungatedText(extra["fingerprint"]);
  if (supplied) return stableId("semgrep", [supplied]);
  const start = record(result["start"], "Semgrep start");
  const end = record(result["end"], "Semgrep end");
  return identity(
    requiredText(result["check_id"], "Semgrep check_id"),
    requiredText(result["path"], "Semgrep path"),
    position(start["line"], "Start line"),
    position(start["col"], "Start column"),
    position(end["line"], "End line"),
    position(end["col"], "End column"),
  );
}

function sarifArtifactUri(
  artifact: Record<string, unknown>,
  runContext: Record<string, unknown>,
): string | null {
  const base = artifact["uriBaseId"];
  // Native Semgrep uses %SRCROOT% without defining a base. Keep other references raw.
  if (
    artifact["index"] !== undefined ||
    (base !== undefined &&
      (base !== "%SRCROOT%" ||
        record(runContext["originalUriBaseIds"] ?? {}, "SARIF URI bases")[
          base
        ] !== undefined))
  )
    return null;
  const uri = requiredText(artifact["uri"], "Semgrep artifact URI");
  // Semgrep's native formatter copies filesystem paths without URI encoding.
  return base === "%SRCROOT%" ? uri : decodeURIComponent(uri);
}

function primarySarifLocation(result: Record<string, unknown>) {
  const locations = array(result["locations"] ?? [], "Semgrep locations");
  if (locations.length !== 1)
    throw new Error("Expected Semgrep's single primary result location.");
  const location = record(locations[0], "Location");
  const physical = record(location["physicalLocation"], "Physical location");
  const artifact = record(physical["artifactLocation"], "Artifact location");
  return { physical, artifact };
}

function sarifIdentity(
  value: unknown,
  runContext: Record<string, unknown>,
): string {
  const result = record(value, "Semgrep result");
  const supplied = ungatedText(
    record(result["fingerprints"] ?? {}, "Semgrep fingerprints")[
      "matchBasedId/v1"
    ],
  );
  if (supplied) return stableId("semgrep", [supplied]);
  const { physical, artifact } = primarySarifLocation(result);
  const uri = sarifArtifactUri(artifact, runContext);
  if (uri === null)
    throw new Error(
      "Cannot derive a Semgrep CE identity from an indexed or unresolved base-relative artifact URI.",
    );
  const region = record(physical["region"], "Semgrep region");
  const line = position(region["startLine"], "Start line");
  const column = position(region["startColumn"] ?? 1, "Start column");
  return identity(
    requiredText(result["ruleId"], "Semgrep ruleId"),
    uri,
    line,
    column,
    position(region["endLine"] ?? line, "End line"),
    position(region["endColumn"] ?? column, "End column"),
  );
}

export function normalizeSemgrepFindings(
  input: unknown,
  options: Partial<SemgrepImportOptions> = {},
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = record(input, "Semgrep report");
  if (document["format"] === guardianSelectionFormat) {
    return normalizeGuardianSelection(
      document,
      target,
      options.sourceRepositoryUrl,
      options.sourceRepositories,
    );
  }
  if (isSemgrepPlatformFormat(document["format"])) {
    return normalizeSemgrepPlatformFindings(
      document,
      options?.sourceRepositoryUrl,
      target,
      options?.sourceRepositories,
    );
  }
  if (document["version"] === "2.1.0" && document["runs"] !== undefined)
    return normalizeSemgrepSarif(
      document,
      { ...options, sourceRepositoryUrl: options?.sourceRepositoryUrl ?? "" },
      target,
    );
  return normalizeSemgrepJson(document, options, target);
}

function nativeProjection(target: ExternalImportTarget, previous: boolean) {
  let changed = false;
  return {
    location(raw: string) {
      const oldPath = relativePath(raw);
      if (previous) return oldPath;
      // Semgrep retains its raw spelling; OpenGrep groups by the normalized path.
      const path = nativeResultPath(raw, oldPath) === null ? null : raw;
      if (path !== oldPath) changed = true;
      return path;
    },
    finish(findings: ExternalFindings, omittedExplanations = false) {
      if (target === "cloud" && (changed || omittedExplanations))
        markPreviousCloudProjection(findings);
      return findings;
    },
  };
}

/** @internal Rebuild the native JSON or SARIF that an earlier reader approved. */
export function normalizePreviousSemgrepFindings(
  input: unknown,
  options: Partial<SemgrepImportOptions>,
): ExternalFindings {
  const document = record(input, "Semgrep report");
  return document["version"] === "2.1.0" && document["runs"] !== undefined
    ? normalizeSarif(document, options, "cloud", true)
    : normalizeSemgrepJson(document, options, "cloud", true);
}

function normalizeSemgrepJson(
  document: Record<string, unknown>,
  options: Partial<SemgrepImportOptions>,
  target: ExternalImportTarget,
  previous = false,
): ExternalFindings {
  const repositoryUrl = sourceRepository(options);
  requiredText(document["version"], "Semgrep version");
  const { results, paths: _paths, time: _time, ...context } = document;
  const omitExplanations = !previous && Object.hasOwn(context, "explanations");
  if (omitExplanations) delete context["explanations"];
  const rows = array(results, "Semgrep results");
  if (!rows.length && document["errors"] === undefined)
    throw new Error("An empty Semgrep report must include its errors array.");
  if (optionalArray(document["errors"], "Semgrep errors").length)
    throw new Error(
      "The Semgrep report contains scan errors; supply a successful report before importing findings.",
    );
  const projection = nativeProjection(target, previous);
  const findings = normalizeRecords(
    rows,
    (value) =>
      projectNativeJsonResult(
        parseNativeJsonResult(value, "Semgrep", projection.location),
        {
          origin: "Semgrep",
          repositoryUrl,
          severity,
          reportContext: context,
          target,
        },
      ),
    jsonIdentity,
    target,
  );
  return projection.finish(findings, omitExplanations);
}

export function isSemgrepSarifDriver(name: string): boolean {
  return ["semgrep", "semgrep oss", "semgrep pro"].includes(name.toLowerCase());
}

export function normalizeSemgrepSarif(
  input: unknown,
  options: SemgrepImportOptions,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  return normalizeSarif(input, options, target);
}

function normalizeSarif(
  input: unknown,
  options: Partial<SemgrepImportOptions>,
  target: ExternalImportTarget,
  previous = false,
): ExternalFindings {
  const repositoryUrl = sourceRepository(options);
  const repositoryKey = cloudRepositoryUrlKey(repositoryUrl);
  const verifiedUrls = new Set([repositoryUrl]);
  const entries = readSarifRuns(input, "Semgrep", (context) => {
    for (const { url: declared } of sarifRunRepositories(
      context.run,
      "Semgrep",
    )) {
      if (verifiedUrls.has(declared)) continue;
      if (cloudRepositoryUrlKey(declared) !== repositoryKey)
        throw new Error(
          "SARIF source repository does not match the declared source repository URL.",
        );
      verifiedUrls.add(declared);
    }
    if (
      !isSemgrepSarifDriver(
        requiredText(context.driver["name"], "SARIF producer"),
      )
    )
      throw new Error("Expected a Semgrep SARIF producer.");
    return sarifRunResults(context, "Semgrep");
  });
  const projection = nativeProjection(target, previous);
  const findings = normalizeRecords(
    entries,
    ({ result: value, context }) => {
      const result = record(value, "Semgrep result");
      const properties = record(
        result["properties"] ?? {},
        "Semgrep result properties",
      );
      if (
        properties["exposure"] != null ||
        properties["dependencyPaths"] != null
      )
        throw new Error(
          "This adapter supports Semgrep SAST; Supply Chain reports need separate qualification.",
        );
      const ruleId = requiredText(result["ruleId"], "Semgrep ruleId");
      const selectedRule = context.rulesById.get(ruleId) ?? undefined;
      if (context.rulesById.size > 0 && !selectedRule)
        throw new Error(
          "Semgrep result must reference exactly one rule in its run.",
        );
      const rule = selectedRule?.rule;
      validateSarifRuleReference(result, ruleId, selectedRule, "Semgrep");
      const { physical, artifact } = primarySarifLocation(result);
      const rawPath = sarifArtifactUri(artifact, context.runContext);
      const region = record(physical["region"], "Semgrep region");
      const line = position(region["startLine"], "Start line");
      const column = position(region["startColumn"] ?? 1, "Start column");
      const endLine = position(region["endLine"] ?? line, "End line");
      const endColumn = position(region["endColumn"] ?? column, "End column");
      if (endLine < line || (endLine === line && endColumn < column))
        throw new Error("Semgrep source range ends before it starts.");
      const message = record(result["message"], "Semgrep message");
      const configuration = record(
        rule?.["defaultConfiguration"] ?? {},
        "Rule configuration",
      );
      const level = text(result["level"]) ?? text(configuration["level"]);
      // SARIF collapses severity categories; retain its diagnostic level and all original metadata.
      const mappedSeverity =
        level === "error"
          ? "high"
          : level === "warning"
            ? "medium"
            : level === "note"
              ? "low"
              : "unknown";
      // Native %SRCROOT% values are filesystem paths; direct URIs can name other targets.
      const absoluteUri =
        artifact["uriBaseId"] !== "%SRCROOT%" &&
        typeof artifact["uri"] === "string" &&
        /^[a-z][a-z\d+.-]*:/iu.test(artifact["uri"]);
      const path =
        rawPath === null || absoluteUri ? null : projection.location(rawPath);
      return validateExternalEvidence(
        {
          title: ruleId,
          description:
            text(message["markdown"]) ??
            messageText(message["text"], "Semgrep"),
          severity: mappedSeverity,
          locations: path ? [{ path, line }] : [],
          details: {
            kind: "sast",
            repository: { url: repositoryUrl },
            scanner_origin: "Semgrep",
            rule: { id: ruleId },
            weakness_ids: weaknessIds(
              record(rule?.["properties"] ?? {}, "Rule properties")["tags"],
            ),
            code: {
              end_line: path ? endLine : null,
              snippet: ungatedText(
                record(region["snippet"] ?? {}, "Snippet")["text"],
              ),
            },
            source_status:
              Array.isArray(result["suppressions"]) &&
              result["suppressions"].some((value) => {
                const status = record(value, "Suppression")["status"];
                return status === undefined || status === "accepted";
              })
                ? "suppressed"
                : null,
          },
          source_data: context.sourceData(result, rule),
        },
        target,
      );
    },
    ({ result, context }) => sarifIdentity(result, context.runContext),
    target,
  );
  return projection.finish(findings);
}

/** @internal Read the original file before resolving repository provenance. */
export async function readSemgrepReport(path: string): Promise<unknown> {
  return readScannerJson(path, (json) => {
    // Pick a parser before allocating the findings array. Verify the root:
    // the member can be nested in a native report or escaped in a Platform one.
    const parser = /"format"\s*:\s*"semgrep-platform-findings\/v[12]"/u.test(
      json,
    )
      ? parseHostedScannerJson
      : JSON.parse;
    const parsed: unknown = parser(json);
    const requiredParser =
      isRecord(parsed) &&
      (parsed["format"] === semgrepPlatformLegacyFormat ||
        parsed["format"] === semgrepPlatformFormat)
        ? parseHostedScannerJson
        : JSON.parse;
    return parser === requiredParser ? parsed : requiredParser(json);
  });
}

export async function readSemgrepFindings(
  path: string,
  options: Partial<SemgrepImportOptions> = {},
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeSemgrepFindings(
    await readSemgrepReport(path),
    options,
    target,
  );
}
