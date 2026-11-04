import { hash } from "node:crypto";
import { readFile, type FileHandle } from "node:fs/promises";
import { posix } from "node:path";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { SCAN_SEVERITIES } from "./scan-settings.js";
import { isRecord } from "./record.js";
import { previousAdmission } from "./external-import-contract.js";
import { rememberPreviousSelection } from "./reader-selection.js";

export function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

export function array(value: unknown, label: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  return value;
}

export function optionalArray(value: unknown, label: string): unknown[] {
  return value === undefined ? [] : array(value, label);
}

// A notification may omit its level and refer to a descriptor by index, GUID or ID.
function sarifDescriptorIndex(entries: unknown[], firstIndex = 0) {
  const byRef = new Map<string | number, Record<string, unknown>>();
  entries.forEach((item, index) => {
    if (!isRecord(item)) return;
    byRef.set(firstIndex + index, item);
    if (typeof item["guid"] === "string")
      byRef.set("guid:" + item["guid"].toLowerCase(), item);
    if (typeof item["id"] === "string") byRef.set("id:" + item["id"], item);
  });
  return (ref: Record<string, unknown>) => {
    if (typeof ref["index"] === "number" && ref["index"] >= 0)
      return byRef.get(ref["index"]);
    if (typeof ref["guid"] === "string")
      return byRef.get("guid:" + ref["guid"].toLowerCase());
    if (typeof ref["id"] === "string") return byRef.get("id:" + ref["id"]);
    if (firstIndex === -1) return byRef.get(-1);
  };
}

function notificationDescriptors(tool: unknown) {
  const metadata = isRecord(tool) ? tool : {};
  const extensions = optionalArray(
    metadata["extensions"],
    "SARIF tool extensions",
  );
  // The driver is the default component (index -1); extension indexes start at 0.
  const component = sarifDescriptorIndex(
    [metadata["driver"], ...extensions],
    -1,
  );
  const descriptors = new Map<
    Record<string, unknown>,
    ReturnType<typeof sarifDescriptorIndex>
  >();
  return (ref: unknown) => {
    if (!isRecord(ref)) return;
    const target = ref["toolComponent"];
    const owner = component(isRecord(target) ? target : {});
    if (!owner) return;
    let lookup = descriptors.get(owner);
    if (!lookup) {
      lookup = sarifDescriptorIndex(
        optionalArray(owner["notifications"], "SARIF notification descriptors"),
      );
      descriptors.set(owner, lookup);
    }
    return lookup(ref);
  };
}

export function successfulSarifInvocations(
  run: Record<string, unknown>,
  producer: string,
  notifications?: unknown[],
): Record<string, unknown>[] {
  function validate(
    value: unknown,
    resolve: ReturnType<typeof notificationDescriptors>,
  ) {
    const invocation = record(value, `${producer} invocation`);
    if (typeof invocation["executionSuccessful"] !== "boolean")
      throw new Error(
        `${producer} SARIF executionSuccessful must be a boolean.`,
      );
    if (!invocation["executionSuccessful"]) {
      const details = [
        "processStartFailureMessage",
        "exitCodeDescription",
        "exitCode",
        "exitSignalName",
        "toolExecutionNotifications",
        "toolConfigurationNotifications",
      ].flatMap((key) =>
        invocation[key] === undefined ? [] : [invocation[key]],
      );
      throw new Error(
        `${producer} SARIF contains an unsuccessful invocation.${details.length ? " " + JSON.stringify(details) : ""}`,
      );
    }
    const levels = new Map<Record<string, unknown>, unknown>();
    for (const override of optionalArray(
      invocation["notificationConfigurationOverrides"],
      "SARIF notification overrides",
    )) {
      if (!isRecord(override) || !isRecord(override["configuration"])) continue;
      const descriptor = resolve(override["descriptor"]);
      if (descriptor && override["configuration"]["level"] !== undefined)
        levels.set(descriptor, override["configuration"]["level"]);
    }
    for (const property of [
      "toolExecutionNotifications",
      "toolConfigurationNotifications",
    ]) {
      for (const entry of optionalArray(
        invocation[property],
        `${producer} ${property}`,
      )) {
        const notice = record(entry, `${producer} notification`);
        const descriptor = resolve(notice["descriptor"]);
        const defaults = descriptor?.["defaultConfiguration"];
        const level =
          notice["level"] ??
          (descriptor && levels.get(descriptor)) ??
          (isRecord(defaults) ? defaults["level"] : undefined);
        if (level === "error")
          throw new Error(
            `${producer} SARIF contains scan error notifications: ${JSON.stringify(notice)}`,
          );
        notifications?.push(notice);
      }
    }
    return invocation;
  }
  if (run["conversion"] !== undefined) {
    const conversion = record(run["conversion"], `${producer} conversion`);
    if (conversion["invocation"] !== undefined)
      validate(
        conversion["invocation"],
        notificationDescriptors(conversion["tool"]),
      );
  }
  const resolve = notificationDescriptors(run["tool"]);
  return optionalArray(run["invocations"], `${producer} invocations`).map(
    (value) => validate(value, resolve),
  );
}

export function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function requiredText(value: unknown, label: string): string {
  const result = text(value);
  if (!result) throw new Error(`${label} must be nonempty text.`);
  return result;
}

/** SARIF repository claims must be checked even when a run has no results. */
export function sarifRunRepositories(
  run: unknown,
  producer: string,
): { url: string; branch?: string }[] {
  if (run == null) return [];
  return array(
    record(run, `${producer} run context`)["versionControlProvenance"] ?? [],
    `${producer} version control provenance`,
  ).flatMap((entry) => {
    const ref = record(entry, `${producer} repository provenance`);
    const url =
      producer === "Semgrep"
        ? text(ref["repositoryUri"])
        : requiredText(ref["repositoryUri"], `${producer} repository URI`);
    return url === null
      ? []
      : [
          {
            url,
            ...(producer === "Semgrep" &&
              typeof ref["branch"] === "string" && { branch: ref["branch"] }),
          },
        ];
  });
}

export function scannerSeverity(value: string | null | undefined) {
  return SCAN_SEVERITIES.find((severity) => severity === value) ?? "unknown";
}

export function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((v): v is string => text(v) !== null)
    : [];
}

/** Paths that cannot be attributed to a repository stay in original evidence. */
export function relativePath(value: unknown): string | null {
  const path = text(value)?.replaceAll("\\", "/");
  return path &&
    !path.startsWith("/") &&
    !path.includes("\0") &&
    !/^[A-Za-z]:/.test(path) &&
    !path.split("/").includes("..")
    ? path
    : null;
}

// Hosted findings do not identify the scanner operating system or its path separator.
export function hostedRepositoryPath(value: unknown) {
  const path = text(value);
  return path && !path.includes("\\") && !path.includes("://")
    ? relativePath(path)
    : null;
}

export function repositoryFilePath(value: unknown): string | null {
  const relative = relativePath(value);
  if (!relative) return null;
  const path = posix.normalize(relative);
  // Anchor the SCP branch at the first eligible @ to avoid rescanning long filenames.
  return path === "." ||
    path.endsWith("/") ||
    /^(?:[a-z][a-z\d+.-]*:|~[^/]*(?:\/|$)|[^/][^/@]*@[^/]+:)/iu.test(path)
    ? null
    : path;
}

export function stableId(prefix: string, fields: unknown[]): string {
  return `${prefix}:${hash("sha256", JSON.stringify(fields))}`;
}

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
const gunzipAsync = promisify(gunzip);

async function readScannerBytes(path: string | FileHandle) {
  const bytes = await readFile(path);
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  return { gzip, bytes: gzip ? await gunzipAsync(bytes) : bytes };
}

export async function readScannerText(path: string): Promise<string> {
  const { bytes, gzip } = await readScannerBytes(path);
  const contents = strictUtf8.decode(bytes);
  if (!gzip && /\.gz$/iu.test(path) && !contents.trim())
    throw new Error("The report is blank and contains no gzip stream.");
  return contents;
}

export function parseJsonOrJsonl(contents: string, path: string): unknown {
  try {
    return JSON.parse(contents);
  } catch (error) {
    const lines = contents.split(/\r?\n/u).filter((line) => line.trim());
    if (!lines.length && /\.(?:json|csv)(?:\.gz)?$/iu.test(path)) throw error;
    return lines.map((line) => JSON.parse(line));
  }
}

export async function readScannerJson(
  path: string | FileHandle,
  parse: (json: string) => unknown = JSON.parse,
): Promise<unknown> {
  const { bytes } = await readScannerBytes(path);
  let decoded: string;
  try {
    decoded = strictUtf8.decode(bytes);
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner report is not valid UTF-8. ${errorMessage(error)}`,
      { cause: error },
    );
  }
  try {
    return parse(decoded.replace(/^\uFEFF/u, ""));
  } catch (error) {
    throw new CodexSecurityError(
      `Scanner JSON could not be parsed. ${errorMessage(error)}`,
      { cause: error },
    );
  }
}

/** Empty reference containers and property-bag metadata do not externalize data. */
export function hasSarifExternalPropertyReferences(value: unknown): boolean {
  if (value == null) return false;
  return Object.entries(
    record(value, "SARIF external property references"),
  ).some(
    ([key, references]) =>
      key !== "properties" &&
      (!Array.isArray(references) || references.length > 0),
  );
}

const sarifArtifactLocationFields = new Set([
  "artifactLocation",
  "analysisTarget",
  "executableLocation",
  "workingDirectory",
  "stdin",
  "stdout",
  "stderr",
  "stdoutStderr",
  "mappedTo",
  "displayBase",
]);

function sarifArtifactReferences(evidence: unknown) {
  const locations: Record<string, unknown>[] = [];
  let hasArtifactLink = false;
  function visit(value: unknown): void {
    if (typeof value === "string") {
      // SARIF message links can refer to an artifact without an artifactLocation.
      if (/sarif:/iu.test(value)) hasArtifactLink = true;
    } else if (Array.isArray(value)) value.forEach(visit);
    else if (isRecord(value))
      for (const [key, child] of Object.entries(value)) {
        if (key === "properties") continue;
        if (sarifArtifactLocationFields.has(key) && isRecord(child))
          locations.push(child);
        if (
          ["locations", "responseFiles", "analysisToolLogFiles"].includes(
            key,
          ) &&
          Array.isArray(child)
        )
          locations.push(...child.filter(isRecord));
        if (key === "originalUriBaseIds" && isRecord(child))
          locations.push(...Object.values(child).filter(isRecord));
        visit(child);
      }
  }
  visit(evidence);
  return { locations, hasArtifactLink };
}

const unresolvedUri = /[%:\\]|(?:^|\/)\.\.?(?:\/|$)/u;

function artifactUriMatcher(artifacts: unknown[]) {
  const uris = new Set<string>();
  let hasLocation = false;
  let base: unknown;
  for (const artifact of artifacts) {
    if (!isRecord(artifact) || !isRecord(artifact["location"])) continue;
    const { uri, uriBaseId } = artifact["location"];
    // Mixed bases or a URI that needs resolution can match any direct reference.
    if (
      (hasLocation && uriBaseId !== base) ||
      (typeof uri === "string" && unresolvedUri.test(uri))
    )
      return () => true;
    hasLocation = true;
    base = uriBaseId;
    if (typeof uri === "string") uris.add(uri);
  }
  return (uri: string, uriBaseId: unknown) =>
    hasLocation &&
    (uriBaseId !== base || unresolvedUri.test(uri) || uris.has(uri));
}

/** Keep original artifact indexes; omit only inventory unrelated to this finding. */
export function sarifRunContextSelector(runContext: Record<string, unknown>) {
  const { artifacts, ...context } = runContext;
  if (!Array.isArray(artifacts) || artifacts.length === 0)
    return () => runContext;
  let matchesUri: ReturnType<typeof artifactUriMatcher> | undefined;
  return (...selectedEvidence: unknown[]) => {
    const { locations, hasArtifactLink } = sarifArtifactReferences([
      context,
      ...selectedEvidence,
    ]);
    if (hasArtifactLink) return runContext;
    for (const location of locations) {
      const { index, uri, uriBaseId } = location;
      if (typeof index === "number" && index >= 0) return runContext;
      if (typeof uri === "string") {
        matchesUri ??= artifactUriMatcher(artifacts);
        if (matchesUri(uri, uriBaseId)) return runContext;
      }
    }
    return context;
  };
}

type IndexedSarifRule = { rule: Record<string, unknown>; index: number };

/** Duplicate IDs cannot identify a single rule in this run. */
export function indexSarifRules(
  entries: Iterable<[number, Record<string, unknown>]>,
) {
  const byId = new Map<unknown, IndexedSarifRule | null>();
  for (const [index, rule] of entries) {
    const id = rule["id"];
    byId.set(id, byId.has(id) ? null : { rule, index });
  }
  return byId;
}

/** Pair each result with its shared run context and original evidence. */
export function sarifRunResults(
  document: Record<string, unknown>,
  run: Record<string, unknown>,
  tool: Record<string, unknown>,
  driver: Record<string, unknown>,
  producer: "Endor" | "Semgrep",
) {
  const rules = array(driver["rules"] ?? [], `${producer} rules`).map((rule) =>
    record(rule, `${producer} rule`),
  );
  const rulesById = indexSarifRules(rules.entries());
  const { runs: _runs, ...documentContext } = document;
  const { results: _results, tool: _tool, ...runContext } = run;
  const { rules: _rules, ...driverContext } = driver;
  const { driver: _driver, ...toolContext } = tool;
  const selectRunContext = sarifRunContextSelector(runContext);
  // JS callers may supply lazy metadata. Preserve each adapter's original traversal order.
  const metadataInReadOrder =
    producer === "Semgrep"
      ? [driverContext, toolContext, documentContext]
      : [documentContext, driverContext, toolContext];
  const context = {
    rulesById,
    runContext,
    sourceData(
      result: Record<string, unknown>,
      rule?: Record<string, unknown>,
    ) {
      return structuredClone({
        documentContext,
        runContext: selectRunContext(result, rule, ...metadataInReadOrder),
        driverContext,
        toolContext,
        ...(rule ? { rule } : {}),
        result,
      });
    },
  };
  return optionalArray(run["results"], `${producer} results`).map((result) => ({
    result,
    context,
  }));
}

/** The top-level index and nested descriptor must agree with the selected driver rule. */
export function validateSarifRuleReference(
  result: Record<string, unknown>,
  ruleId: string,
  selected: IndexedSarifRule | undefined,
  producer: "Endor" | "Semgrep" | "Snyk",
) {
  // Snyk's original diagnostics use unqualified SARIF field names.
  const label = producer === "Snyk" ? "Result" : producer;
  if (
    result["ruleIndex"] !== undefined &&
    result["ruleIndex"] !== selected?.index
  )
    throw new Error(`${label} ruleIndex and ruleId disagree.`);
  if (result["rule"] === undefined) return;
  const reference = record(
    result["rule"],
    producer === "Snyk" ? "Rule reference" : `${producer} rule reference`,
  );
  if (
    reference["toolComponent"] !== undefined ||
    (reference["id"] !== undefined && reference["id"] !== ruleId) ||
    (reference["index"] !== undefined &&
      reference["index"] !== selected?.index) ||
    (reference["guid"] !== undefined &&
      reference["guid"] !== selected?.rule["guid"])
  )
    throw new Error(
      producer === "Snyk"
        ? "Result uses an inconsistent or external rule reference."
        : `Inconsistent or external ${producer} rule reference.`,
    );
}

interface SizeChange {
  index: number;
  position: number;
  id: string;
  previous: ExternalFinding["evidence"] | null;
}

type SelectionFilter = (
  selection: ExternalFindings,
  removedIds?: Set<string>,
) => void;

/** Track older size decisions while a single reader constructs its result. */
export function trackReaderSelection(result: ExternalFindings) {
  const changes: SizeChange[] = [];
  const uncertainIds = new Set<string>();

  function append(
    position: number,
    id: string,
    project: () => ExternalFinding["evidence"],
  ) {
    const index = result.findings.length;
    let outcome: unknown;
    try {
      const evidence = project();
      outcome = evidence;
      result.findings.push({ source_finding_id: id, evidence });
    } catch (error) {
      outcome = error;
      result.excluded.push({
        position,
        source_finding_id: id,
        reason: errorMessage(error),
      });
    }
    const previous =
      outcome && typeof outcome === "object"
        ? previousAdmission(outcome)
        : undefined;
    if (previous === "uncertain") uncertainIds.add(id);
    else if (previous !== undefined)
      changes.push({ index, position, id, previous });
  }

  function finish(filter?: SelectionFilter): ExternalFindings {
    if (!changes.length && !uncertainIds.size) {
      filter?.(result);
      return result;
    }
    const findings: ExternalFinding[] = [];
    const excluded: ExternalFindings["excluded"] = [];
    const restoredPositions = new Set<number>();
    let cursor = 0;
    for (const { index, position, id, previous } of changes) {
      while (cursor < index) findings.push(result.findings[cursor++]!);
      if (previous) {
        findings.push({ source_finding_id: id, evidence: previous });
        restoredPositions.add(position);
      } else {
        cursor++;
        excluded.push({
          position,
          source_finding_id: id,
          reason: "Evidence exceeds the Cloud limit of 256 KiB.",
        });
      }
    }
    while (cursor < result.findings.length)
      findings.push(result.findings[cursor++]!);
    for (const row of result.excluded) {
      if (!restoredPositions.has(row.position)) excluded.push(row);
    }
    excluded.sort((a, b) => a.position - b.position);
    const previous = { ...result, findings, excluded };
    // A removed sibling could have depended on an unproven row for its scope.
    filter?.(previous, uncertainIds.size ? uncertainIds : undefined);
    filter?.(result);
    const sourceFindingIds = [
      ...new Set([
        ...previous.findings.map((row) => row.source_finding_id),
        ...uncertainIds,
      ]),
    ];
    if (uncertainIds.size) {
      rememberPreviousSelection(result, {
        sourceFindingIds,
        uncertainFindingIds: [...uncertainIds],
        knownFindings: structuredClone(
          previous.findings.filter(
            (row) => !uncertainIds.has(row.source_finding_id),
          ),
        ),
      });
    } else {
      rememberPreviousSelection(result, {
        sourceFindingIds,
        snapshot: structuredClone(previous),
      });
    }
    return result;
  }

  return { append, finish, uncertainIds };
}

/** Exclude every colliding record: choosing the first could overwrite another occurrence. */
export function normalizeRecords<T>(
  records: T[],
  projectEvidence: (record: T, id: string) => ExternalFinding["evidence"],
  identify: (record: T) => string,
  target: "local" | "cloud" = "cloud",
  options: {
    report?: ExternalFindings["report"];
    notifications?: unknown[];
    filter?: SelectionFilter;
  } = {},
): ExternalFindings {
  const result: ExternalFindings = {
    read: records.length,
    findings: [],
    excluded: [],
    ...(options.report === undefined ? {} : { report: options.report }),
  };
  const selection = trackReaderSelection(result);
  const identified: { position: number; value: T; id: string }[] = [];
  const counts = new Map<string, number>();
  for (const [index, value] of records.entries()) {
    try {
      const id = identify(value);
      if (
        !id.trim() ||
        id.includes("\0") ||
        (target === "cloud" && Buffer.byteLength(id) > 512)
      )
        throw new Error(
          target === "cloud"
            ? "Source finding ID must contain 1–512 UTF-8 bytes and no NUL characters."
            : "Source finding ID must be nonempty and contain no NUL characters.",
        );
      identified.push({ position: index + 1, value, id });
      counts.set(id, (counts.get(id) ?? 0) + 1);
    } catch (error) {
      result.excluded.push({
        position: index + 1,
        source_finding_id: null,
        reason: errorMessage(error),
      });
    }
  }
  for (const { position, value, id } of identified) {
    if (counts.get(id)! > 1) {
      result.excluded.push({
        position,
        source_finding_id: id,
        reason:
          "Ambiguous duplicate source identity; select one complete finding or separate source projects.",
      });
      continue;
    }
    selection.append(position, id, () => projectEvidence(value, id));
  }
  result.excluded.sort((a, b) => a.position - b.position);
  if (!records.length && options.notifications?.length)
    result.report = { ...result.report, notifications: options.notifications };
  return selection.finish(options.filter);
}
