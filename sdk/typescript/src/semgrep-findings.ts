import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  cloudRepositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  messageText,
  parseNativeJsonResult,
  position,
  projectNativeJsonResult,
  sourceRepositoryUrl,
  ungatedText,
  weaknessIds,
} from "./native-json-findings.js";
import {
  array,
  hasSarifExternalPropertyReferences,
  indexSarifRules,
  normalizeRecords,
  optionalArray,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  sarifRepositoryUrls,
  sarifRunContextForResult,
  stableId,
  successfulSarifInvocations,
  text,
} from "./scanner-import.js";

export interface SemgrepImportOptions {
  /** Source repository declared by the caller; never inferred from the destination. */
  sourceRepositoryUrl: string;
}

function sourceRepository(options: SemgrepImportOptions): string {
  return sourceRepositoryUrl(options?.sourceRepositoryUrl, "Semgrep");
}

function severity(value: unknown): string {
  const levels: Record<string, string> = {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    ERROR: "high",
    WARNING: "medium",
    INFO: "low",
  };
  return typeof value === "string" ? (levels[value] ?? "unknown") : "unknown";
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
  const locations = array(result["locations"] ?? [], "Semgrep locations");
  if (locations.length !== 1)
    throw new Error("Expected Semgrep's single primary result location.");
  const physical = record(
    record(locations[0], "Location")["physicalLocation"],
    "Physical location",
  );
  const uri = sarifArtifactUri(
    record(physical["artifactLocation"], "Artifact location"),
    runContext,
  );
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
  options: SemgrepImportOptions,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = record(input, "Semgrep report");
  if (document["version"] === "2.1.0" && document["runs"] !== undefined)
    return normalizeSemgrepSarif(document, options, target);
  const repositoryUrl = sourceRepository(options);
  requiredText(document["version"], "Semgrep version");
  const { results, paths: _paths, time: _time, ...context } = document;
  const rows = array(results, "Semgrep results");
  if (!rows.length && document["errors"] === undefined)
    throw new Error("An empty Semgrep report must include its errors array.");
  if (optionalArray(document["errors"], "Semgrep errors").length)
    throw new Error(
      "The Semgrep report contains scan errors; supply a successful report before importing findings.",
    );
  return normalizeRecords(
    rows,
    (value) =>
      projectNativeJsonResult(parseNativeJsonResult(value, "Semgrep"), {
        origin: "Semgrep",
        repositoryUrl,
        severity,
        reportContext: context,
        target,
      }),
    jsonIdentity,
    target,
  );
}

export function normalizeSemgrepSarif(
  input: unknown,
  options: SemgrepImportOptions,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repositoryUrl = sourceRepository(options);
  const document = record(input, "Semgrep SARIF");
  if (document["version"] !== "2.1.0")
    throw new Error("Expected Semgrep SARIF 2.1.0.");
  const entries = array(document["runs"], "SARIF runs").flatMap((value) => {
    const run = record(value, "SARIF run");
    for (const declared of sarifRepositoryUrls(run, "Semgrep")) {
      if (
        cloudRepositoryUrlKey(declared) !== cloudRepositoryUrlKey(repositoryUrl)
      )
        throw new Error(
          "SARIF source repository does not match the declared source repository URL.",
        );
    }
    const tool = record(run["tool"], "SARIF tool");
    const driver = record(tool["driver"], "SARIF driver");
    if (
      !["semgrep", "semgrep oss", "semgrep pro"].includes(
        requiredText(driver["name"], "SARIF producer").toLowerCase(),
      )
    )
      throw new Error("Expected a Semgrep SARIF producer.");
    if (
      hasSarifExternalPropertyReferences(run["externalPropertyFileReferences"])
    )
      throw new Error("Use a self-contained Semgrep SARIF report.");
    for (const details of successfulSarifInvocations(run, "Semgrep")) {
      if (
        optionalArray(
          details["toolExecutionNotifications"],
          "Semgrep scan notifications",
        ).length
      )
        throw new Error("Semgrep SARIF contains scan error notifications.");
    }
    const rules = array(driver["rules"] ?? [], "Semgrep rules").map((r) =>
      record(r, "Semgrep rule"),
    );
    const rulesById = indexSarifRules(rules);
    const { runs: _runs, ...documentContext } = document;
    const { results: _results, tool: _tool, ...runContext } = run;
    const { rules: _rules, ...driverContext } = driver;
    const { driver: _driver, ...toolContext } = tool;
    return array(run["results"], "Semgrep results").map((result) => ({
      result,
      rulesById,
      hasRules: rules.length > 0,
      documentContext,
      runContext,
      driverContext,
      toolContext,
    }));
  });
  return normalizeRecords(
    entries,
    ({ result: value, rulesById, hasRules, ...context }) => {
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
      const selectedRule = rulesById.get(ruleId);
      if (selectedRule === null || (hasRules && selectedRule === undefined))
        throw new Error(
          "Semgrep result must reference exactly one rule in its run.",
        );
      const rule = selectedRule?.rule;
      const ruleIndex = selectedRule?.index;
      if (
        result["ruleIndex"] !== undefined &&
        result["ruleIndex"] !== ruleIndex
      )
        throw new Error("Semgrep ruleIndex and ruleId disagree.");
      if (result["rule"] !== undefined) {
        const ref = record(result["rule"], "Semgrep rule reference");
        if (
          ref["toolComponent"] !== undefined ||
          (ref["id"] !== undefined && ref["id"] !== ruleId) ||
          (ref["index"] !== undefined && ref["index"] !== ruleIndex) ||
          (ref["guid"] !== undefined && ref["guid"] !== rule?.["guid"])
        )
          throw new Error("Inconsistent or external Semgrep rule reference.");
      }
      const locations = array(result["locations"] ?? [], "Semgrep locations");
      if (locations.length !== 1)
        throw new Error("Expected Semgrep's single primary result location.");
      const physical = record(
        record(locations[0], "Location")["physicalLocation"],
        "Physical location",
      );
      const artifact = record(
        physical["artifactLocation"],
        "Artifact location",
      );
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
        rawPath === null || absoluteUri ? null : relativePath(rawPath);
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
          source_data: structuredClone({
            ...context,
            runContext: sarifRunContextForResult(
              context.runContext,
              result,
              rule,
              context.driverContext,
              context.toolContext,
              context.documentContext,
            ),
            ...(rule ? { rule } : {}),
            result,
          }),
        },
        target,
      );
    },
    ({ result, runContext }) => sarifIdentity(result, runContext),
    target,
  );
}

export async function readSemgrepFindings(
  path: string,
  options: SemgrepImportOptions,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeSemgrepFindings(await readScannerJson(path), options, target);
}
