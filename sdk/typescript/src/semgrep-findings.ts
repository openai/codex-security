import type { ExternalImportTarget } from "./external-import-contract.js";
import {
  cloudRepositoryUrlKey,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  array,
  hasSarifExternalPropertyReferences,
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  sarifRunContextForResult,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

export interface SemgrepImportOptions {
  /** Source repository declared by the caller; never inferred from the destination. */
  sourceRepositoryUrl: string;
}

function sourceRepository(options: SemgrepImportOptions): string {
  const value = requiredText(
    options?.sourceRepositoryUrl,
    "Semgrep sourceRepositoryUrl (--source-repository-url)",
  );
  const url = new URL(value);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw new Error(
      "Use an HTTP(S) source repository URL without credentials.",
    );
  return value;
}

function ungatedText(value: unknown): string | null {
  const supplied = text(value);
  // The current CLI emits this placeholder for gated Community Edition fields.
  return supplied === "requires login" ? null : supplied;
}

function messageText(value: unknown): string | null {
  if (typeof value !== "string")
    throw new Error("Expected a Semgrep message string.");
  return text(value);
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

function weaknessIds(value: unknown): string[] {
  const labels = typeof value === "string" ? [value] : strings(value);
  return [
    ...new Set(
      labels.flatMap((label) => {
        const match = /^(CWE-\d+)(?::|$)/u.exec(label);
        return match ? [match[1]!] : [];
      }),
    ),
  ];
}

function position(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1)
    throw new Error(`${label} must be a positive integer.`);
  return value;
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
  if (array(document["errors"] ?? [], "Semgrep errors").length)
    throw new Error(
      "The Semgrep report contains scan errors; supply a successful report before importing findings.",
    );
  const { results, paths: _paths, time: _time, ...context } = document;
  return normalizeRecords(
    array(results, "Semgrep results"),
    (value, sourceFindingId) => {
      const result = record(value, "Semgrep result");
      const extra = record(result["extra"], "Semgrep extra");
      const metadata = record(extra["metadata"] ?? {}, "Semgrep metadata");
      const product = metadata["product"];
      const validation = extra["validation_state"];
      if (
        (product != null && product !== "sast") ||
        extra["sca_info"] != null ||
        extra["historical_info"] != null ||
        (validation != null && validation !== "NO_VALIDATOR")
      )
        throw new Error(
          "This adapter supports Semgrep SAST; Supply Chain and Secrets reports need separate qualification.",
        );
      const rule = requiredText(result["check_id"], "Semgrep check_id");
      const rawPath = requiredText(result["path"], "Semgrep path");
      const start = record(result["start"], "Semgrep start");
      const end = record(result["end"], "Semgrep end");
      const line = position(start["line"], "Start line");
      const column = position(start["col"], "Start column");
      const endLine = position(end["line"], "End line");
      const endColumn = position(end["col"], "End column");
      if (endLine < line || (endLine === line && endColumn < column))
        throw new Error("Semgrep source range ends before it starts.");
      const path = relativePath(rawPath);
      return {
        source_finding_id: sourceFindingId,
        evidence: validateExternalEvidence(
          {
            title: rule,
            description: messageText(extra["message"]),
            severity: severity(extra["severity"]),
            locations: path ? [{ path, line }] : [],
            details: {
              kind: "sast",
              repository: { url: repositoryUrl },
              scanner_origin: "Semgrep",
              rule: { id: rule },
              weakness_ids: weaknessIds(metadata["cwe"]),
              code: {
                end_line: path ? endLine : null,
                snippet: ungatedText(extra["lines"]),
              },
              source_status:
                typeof extra["is_ignored"] === "boolean"
                  ? extra["is_ignored"]
                    ? "ignored"
                    : "open"
                  : null,
            },
            source_data: structuredClone({ report: context, result }),
          },
          target,
        ),
      };
    },
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
    for (const entry of array(
      run["versionControlProvenance"] ?? [],
      "Version control provenance",
    )) {
      const declared = text(
        record(entry, "Repository provenance")["repositoryUri"],
      );
      if (
        declared &&
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
    for (const invocation of array(
      run["invocations"] ?? [],
      "Semgrep invocations",
    )) {
      const details = record(invocation, "Semgrep invocation");
      if (details["executionSuccessful"] === false)
        throw new Error("Semgrep SARIF contains an unsuccessful invocation.");
      if (
        array(
          details["toolExecutionNotifications"] ?? [],
          "Semgrep scan notifications",
        ).length
      )
        throw new Error("Semgrep SARIF contains scan error notifications.");
    }
    const rules = array(driver["rules"] ?? [], "Semgrep rules").map((r) =>
      record(r, "Semgrep rule"),
    );
    const rulesById = new Map<
      unknown,
      { rule: Record<string, unknown>; index: number } | null
    >();
    for (const [index, rule] of rules.entries()) {
      const id = rule["id"];
      rulesById.set(id, rulesById.has(id) ? null : { rule, index });
    }
    const { runs: _runs, ...documentContext } = document;
    const { results: _results, tool: _tool, ...runContext } = run;
    const { rules: _rules, ...driverContext } = driver;
    const { driver: _driver, ...toolContext } = tool;
    return array(run["results"] ?? [], "Semgrep results").map((result) => ({
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
    ({ result: value, rulesById, hasRules, ...context }, sourceFindingId) => {
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
      return {
        source_finding_id: sourceFindingId,
        evidence: validateExternalEvidence(
          {
            title: ruleId,
            description:
              text(message["markdown"]) ?? messageText(message["text"]),
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
        ),
      };
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
