import { hash } from "node:crypto";
import { readFile, type FileHandle } from "node:fs/promises";
import { posix } from "node:path";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import validSemver from "semver/functions/valid.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { SCAN_SEVERITIES } from "./scan-settings.js";
import { asRecord, isRecord } from "./record.js";
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

// SARIF uses the same index/GUID/ID references for components and descriptors.
function sarifReferences<T>(
  entries: unknown[],
  select: (entry: Record<string, unknown>) => T,
  first = 0,
) {
  const refs = new Map<string | number, T>();
  entries.forEach((entry, index) => {
    if (!isRecord(entry)) return;
    const item = select(entry);
    refs.set(index + first, item);
    if (typeof entry["guid"] === "string")
      refs.set("guid:" + entry["guid"].toLowerCase(), item);
    if (typeof entry["id"] === "string") refs.set("id:" + entry["id"], item);
  });
  return (ref: unknown) => {
    const { index, guid, id } = asRecord(ref) ?? {};
    if (typeof index === "number" && index >= 0) return refs.get(index);
    if (typeof guid === "string") return refs.get("guid:" + guid.toLowerCase());
    return typeof id === "string" ? refs.get("id:" + id) : refs.get(-1);
  };
}

function notificationDescriptors(value: unknown) {
  const tool = asRecord(value);
  // The driver is the default component (-1); extension indexes start at 0.
  const component = sarifReferences(
    [
      tool?.["driver"],
      ...optionalArray(tool?.["extensions"], "SARIF tool extensions"),
    ],
    (owner) =>
      sarifReferences(
        optionalArray(owner["notifications"], "SARIF notification descriptors"),
        (entry) => entry,
      ),
    -1,
  );
  return (ref: unknown) => component(asRecord(ref)?.["toolComponent"])?.(ref);
}

export function validateSarifRun(
  run: Record<string, unknown>,
  producer: string,
): void {
  if (hasSarifExternalPropertyReferences(run["externalPropertyFileReferences"]))
    throw new Error(`Use a self-contained ${producer} SARIF report.`);
  function validate(
    values: unknown[],
    tool: unknown,
    strictExecution: boolean,
  ) {
    let descriptors: ReturnType<typeof notificationDescriptors> | undefined;
    const resolve = (ref: unknown) =>
      isRecord(ref)
        ? (descriptors ??= notificationDescriptors(tool))(ref)
        : undefined;
    for (const value of values) {
      const invocation = record(value, `${producer} invocation`);
      const successful = invocation["executionSuccessful"];
      if (typeof successful !== "boolean")
        throw new Error(
          `${producer} SARIF executionSuccessful must be a boolean.`,
        );
      const list = (key: string) =>
        optionalArray(invocation[key], `${producer} ${key}`);
      const execution = list("toolExecutionNotifications");
      const notices = execution.concat(list("toolConfigurationNotifications"));
      if (!successful) {
        const details = [
          invocation["processStartFailureMessage"],
          invocation["exitCodeDescription"],
          invocation["exitCode"],
          invocation["exitSignalName"],
          ...notices,
        ].filter((value) => value !== undefined);
        throw new Error(
          `${producer} SARIF contains an unsuccessful invocation.${details.length ? " " + JSON.stringify(details) : ""}`,
        );
      }
      if (strictExecution && execution.length)
        throw new Error(
          `${producer} SARIF contains scan error notifications: ${JSON.stringify(execution)}`,
        );
      const levels = new Map<Record<string, unknown>, unknown>();
      for (const value of list("notificationConfigurationOverrides")) {
        const override = asRecord(value);
        const descriptor = resolve(override?.["descriptor"]);
        const level = asRecord(override?.["configuration"])?.["level"];
        if (descriptor && level !== undefined) levels.set(descriptor, level);
      }
      for (const value of notices) {
        const notice = record(value, `${producer} notification`);
        const descriptor = resolve(notice["descriptor"]);
        const level =
          notice["level"] ??
          (descriptor && levels.get(descriptor)) ??
          asRecord(descriptor?.["defaultConfiguration"])?.["level"];
        if (level === "error")
          throw new Error(
            `${producer} SARIF contains scan error notifications: ${JSON.stringify(notice)}`,
          );
      }
    }
  }
  // Semgrep reports scanner errors as execution notices even below error level.
  validate(
    optionalArray(run["invocations"], `${producer} invocations`),
    run["tool"],
    producer === "Semgrep",
  );
  if (run["conversion"] !== undefined) {
    const conversion = record(run["conversion"], `${producer} conversion`);
    if (conversion["invocation"] !== undefined)
      validate([conversion["invocation"]], conversion["tool"], false);
  }
}

export function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

/** AWS APIs use epoch seconds and AWS CLI exports use timezone-qualified ISO dates. */
export function awsTimestampSeconds(value: unknown): number {
  if (typeof value === "number") return value;
  if (
    typeof value === "string" &&
    /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/u.test(value)
  )
    return Date.parse(value) / 1000;
  return NaN;
}

export function concreteVersion(
  value: unknown,
  ecosystem: string | null,
  osPackage: boolean,
): string | null {
  const version = text(value);
  if (!version) return null;
  // Debian versions use internal tildes for prereleases and backports.
  if (osPackage && version.includes("~"))
    return /^(?:\d+:)?\d[a-z\d.+~]*(?:-[a-z\d.+~]+)*$/iu.test(version)
      ? version
      : null;
  if (validSemver(version)) return version;
  if (ecosystem === "npm" || ecosystem === "cargo") return null;
  if (ecosystem === "java" || ecosystem === "maven") {
    if (
      version === "LATEST" ||
      version === "RELEASE" ||
      version.startsWith("latest.")
    )
      return null;
    return /^[a-z\d][\w.+-]*$/iu.test(version) && !version.endsWith("+")
      ? version
      : null;
  }
  if (!ecosystem && version.endsWith("+")) return null;
  const publicVersion =
    ecosystem === "pypi" ? version.split("+", 1)[0]! : version;
  return /\d/u.test(version) &&
    /^(?:\d+:)?[a-z\d][\w.+!-]*$/iu.test(version) &&
    !/(?:^|\.)x(?:\.|$)/iu.test(publicVersion)
    ? version
    : null;
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
    if (url === null) return [];
    const branch = ref["branch"];
    return [
      {
        url,
        ...(producer === "Semgrep" && typeof branch === "string" && { branch }),
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

async function readScannerInput(path: string | FileHandle) {
  const bytes = await readFile(path);
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b;
  return { gzip, bytes: gzip ? await gunzipAsync(bytes) : bytes };
}

export async function readScannerBytes(
  path: string | FileHandle,
): Promise<Buffer> {
  return (await readScannerInput(path)).bytes;
}

export async function readScannerText(path: string): Promise<string> {
  const { bytes, gzip } = await readScannerInput(path);
  const contents = strictUtf8.decode(bytes);
  // Empty JSONL is a valid stream of zero records; a blank JSON or CSV document isn't.
  if (!contents.trim()) {
    if (!gzip && /\.gz$/iu.test(path))
      throw new Error("The report is blank and contains no gzip stream.");
    if (/\.(?:json|csv)(?:\.gz)?$/iu.test(path))
      throw new Error("The report is blank.");
  }
  return contents;
}

export function parseJsonOrJsonl(contents: string): unknown {
  try {
    return JSON.parse(contents);
  } catch {
    return contents
      .split(/\r?\n/u)
      .filter((line) => line.trim())
      .map((line) => JSON.parse(line));
  }
}

export async function readScannerJson(
  path: string | FileHandle,
  parse: (json: string) => unknown = JSON.parse,
): Promise<unknown> {
  const bytes = await readScannerBytes(path);
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

type SarifRun = Record<
  "document" | "run" | "tool" | "driver",
  Record<string, unknown>
>;

/** Unpack the common SARIF envelope; each reader qualifies its own producer. */
export function readSarifRuns<T>(
  input: unknown,
  producer: "Semgrep" | "Snyk" | "Endor",
  read: (context: SarifRun) => T[],
): T[] {
  const document = record(input, `${producer} SARIF`);
  if (document["version"] !== "2.1.0")
    throw new Error(`Expected ${producer} SARIF 2.1.0.`);
  return array(document["runs"], "SARIF runs").flatMap((value) => {
    const run = record(value, "SARIF run");
    const tool = record(run["tool"], "SARIF tool");
    const driver = record(tool["driver"], "SARIF driver");
    return read({ document, run, tool, driver });
  });
}

/** Pair each result with its shared run context and original evidence. */
export function sarifRunResults(
  { document, run, tool, driver }: SarifRun,
  producer: "Endor" | "Semgrep",
) {
  validateSarifRun(run, producer);
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
  return selection.finish(options.filter);
}
