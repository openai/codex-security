import {
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  gitServiceHostname,
  hostedRepositoryMatches,
  hostedRepositoryUrlKey,
} from "./hosted-git-repository.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { isRecord } from "./record.js";
import { position, weaknessIds } from "./native-json-findings.js";
import {
  array,
  normalizeRecords,
  record,
  relativePath,
  repositoryFilePath,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";

export const semgrepSelectionFormat = "semgrep-platform-selection/v1";

export interface SemgrepPlatformScope {
  deployment: string;
  project: { id: string; name: string; url: string };
  ref: string;
  product: "sast";
}

export interface SemgrepPlatformSelection extends SemgrepPlatformScope {
  format: typeof semgrepSelectionFormat;
  /** Each native finding is JSON text so numbers retain their exact wire values through replay. */
  findings: string[];
}

// Node 22 supports JSON source text and raw values. The SDK targets the ES2022 type library.
const wireJson = JSON as JSON & {
  rawJSON(source: string): { rawJSON: string };
  isRawJSON(value: unknown): value is { rawJSON: string };
};

// A retained JSON number is represented as an object in JavaScript.
function responseRecord(value: unknown, label: string) {
  return record(wireJson.isRawJSON(value) ? undefined : value, label);
}

// Normalize equivalent JSON numbers exactly. Keep very large exponents compact.
function canonicalNumber(token: string, fixedDigits = 21): string {
  const [, sign = "", integer, fraction = "", exponent = "0"] =
    /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/iu.exec(token)!;
  const significant = (integer + fraction).replace(/^0+/u, "");
  if (!significant) return "0";
  let end = significant.length;
  while (significant[end - 1] === "0") end--;
  const digits = significant.slice(0, end);
  const point = BigInt(exponent) + BigInt(significant.length - fraction.length);
  // Ordinary evidence follows JSON.stringify’s fixed/scientific notation thresholds.
  if (point > -6n && point <= BigInt(fixedDigits)) {
    const split = Number(point);
    if (split <= 0) return sign + "0." + "0".repeat(-split) + digits;
    if (split >= digits.length) return sign + digits.padEnd(split, "0");
    return sign + digits.slice(0, split) + "." + digits.slice(split);
  }
  const trailing = digits.slice(1);
  const scientific = point - 1n;
  return (
    sign +
    digits.charAt(0) +
    (trailing ? "." + trailing : "") +
    "e" +
    (scientific >= 0n ? "+" : "") +
    scientific
  );
}

function sourceLine(value: unknown): number | null {
  if (value == null) return null;
  if (!wireJson.isRawJSON(value)) return position(value, "Semgrep source line");
  const exact = canonicalNumber(value.rawJSON);
  return position(
    /^\d+$/u.test(exact) ? Number(exact) : undefined,
    "Semgrep source line",
  );
}

/** Keep original number tokens, including adjacent int64 IDs above Number.MAX_SAFE_INTEGER. */
export function parseSemgrepResponse(json: string): Record<string, unknown> {
  return responseRecord(
    JSON.parse(
      json.replace(/^\uFEFF/u, ""),
      (_key: string, value: unknown, context?: { source?: string }) =>
        typeof value === "number" ? wireJson.rawJSON(context!.source!) : value,
    ),
    "Semgrep API response",
  );
}

function platformId(value: unknown): string | undefined {
  let token: string;
  if (wireJson.isRawJSON(value)) token = value.rawJSON;
  else if (typeof value === "string" && /^[1-9][0-9]*$/u.test(value))
    token = value;
  else return undefined;
  const id = canonicalNumber(token);
  if (/^[1-9][0-9]*$/u.test(id)) return id;
  // A large scientific value is an integer only when every significant digit lies left of its decimal point.
  const scientific = /^[1-9](?:\.(\d+))?e\+(\d+)$/u.exec(id);
  return scientific && BigInt(scientific[2]!) >= (scientific[1]?.length ?? 0)
    ? id
    : undefined;
}

export function semgrepPlatformId(value: unknown): string {
  const id = platformId(value);
  if (!id) throw new Error("Expected an exact, positive Semgrep Platform ID.");
  return id;
}

// Older selections retained full decimal ID tokens beyond Semgrep's native int64 range.
function archivedPlatformId(value: unknown): string {
  const token = wireJson.isRawJSON(value)
    ? canonicalNumber(value.rawJSON, Math.max(21, value.rawJSON.length))
    : value;
  return typeof token === "string" && /^[1-9][0-9]*$/u.test(token)
    ? token
    : semgrepPlatformId(value);
}

function scopeOf(
  deployment: unknown,
  project: unknown,
  ref: unknown,
): SemgrepPlatformScope {
  const row = responseRecord(project, "Semgrep project");
  const id = semgrepPlatformId(row["id"]);
  return {
    deployment: requiredText(deployment, "Semgrep deployment"),
    project: {
      id: text(row["id"]) ?? id,
      name: requiredText(row["name"], "Semgrep project name"),
      url: declaredScannerRepositoryUrl(
        row["url"],
        "Semgrep Platform",
        "local",
      ),
    },
    ref: requiredText(ref, "Semgrep ref"),
    product: "sast",
  };
}

/** Readers may pass the SCM web link from the project response or its equivalent Git transport. */
export function semgrepReferenceMatches(
  source: ExternalSourceRepository,
  url: string,
): boolean {
  // A standard explicit Git HTTP(S) helper carries the same fetch URL.
  const helper = /^(https?)::(?=([a-zA-Z]+):\/\/)/u.exec(url);
  if (helper)
    return (
      helper[1] === helper[2]!.toLowerCase() &&
      hostedRepositoryMatches(source, url.slice(helper[0].length))
    );
  if (hostedRepositoryMatches(source, url)) return true;
  try {
    // Serialize only a valid repository link. Git checkout URLs retain their original bytes.
    const link = declaredScannerRepositoryUrl(url, "Semgrep", "local");
    return hostedRepositoryMatches(source, new URL(link).href);
  } catch {
    return false;
  }
}

function repositoryContext(
  scope: SemgrepPlatformScope,
  references: readonly ExternalSourceRepository[] = [],
) {
  // Apply HTTP serialization to native HTTP URLs only. Git's SSH port has its own meaning.
  const http = (value: string) => URL.parse(value)?.href ?? value;
  const projectUrl = http(scope.project.url);
  const source: ExternalSourceRepository = { url: projectUrl };
  const nativeHost = gitServiceHostname(new URL(projectUrl).hostname);
  const ownPlatformMatches = ({ url, platform }: ExternalSourceRepository) =>
    platform !== undefined &&
    semgrepReferenceMatches({ url: projectUrl, platform }, url);
  const platform = isGitHubCloudHost(nativeHost)
    ? "github"
    : references.find(ownPlatformMatches)?.platform;
  if (platform) {
    source.platform = platform;
    if (
      references.some(
        (ref) =>
          ref.platform &&
          ref.platform !== platform &&
          (ownPlatformMatches(ref) || semgrepReferenceMatches(source, ref.url)),
      )
    )
      throw new Error(
        "Conflicting SCM platforms for the selected Semgrep repository.",
      );
  }
  const github = source.platform === "github";
  return {
    source,
    key: (url: string) =>
      hostedRepositoryUrlKey(http(url), github, source.platform === "gitlab"),
    name: (value: string) => (github ? value.toLowerCase() : value),
  };
}

function selectionRepository(
  scope: SemgrepPlatformScope,
  references: readonly ExternalSourceRepository[] = [],
) {
  const repository = repositoryContext(scope, references);
  if (
    !references.every(({ url }) =>
      semgrepReferenceMatches(repository.source, url),
    )
  )
    throw new Error(
      "The reader's source repository does not match the selected Semgrep project.",
    );
  return repository;
}

function checkRow(
  finding: Record<string, unknown>,
  scope: SemgrepPlatformScope,
  repository: Pick<ReturnType<typeof repositoryContext>, "name" | "key">,
  capture = false,
) {
  semgrepPlatformId(finding["id"]);
  const repo = responseRecord(
    finding["repository"],
    "Semgrep finding repository",
  );
  const repositoryId =
    repo["id"] == null ? undefined : semgrepPlatformId(repo["id"]);
  const url =
    repo["url"] == null
      ? null
      : declaredScannerRepositoryUrl(repo["url"], "Semgrep finding", "local");
  const name = repo["name"];
  const rowName = typeof name === "string" ? repository.name(name) : null;
  const encodedPath = new URL(scope.project.url).pathname.replace(
    /^\/|\/$/gu,
    "",
  );
  // Archived captures may retain the encoded path spelling as their repository name.
  const qualifiedName =
    rowName?.includes("/") &&
    (rowName === repository.name(decodeURIComponent(encodedPath)) ||
      (!capture && rowName === repository.name(encodedPath)));
  if (
    finding["ref"] !== scope.ref ||
    (repositoryId !== undefined &&
      repositoryId !== semgrepPlatformId(wireJson.rawJSON(scope.project.id))) ||
    (url !== null
      ? repository.key(url) !== repository.key(scope.project.url)
      : repositoryId === undefined || !qualifiedName)
  )
    throw new Error(
      "Semgrep finding does not belong to the selected project and ref.",
    );
  for (const product of [finding["issue_type"], finding["product"]]) {
    if (
      product != null &&
      (typeof product !== "string" ||
        !["sast", "code"].includes(product.toLowerCase()))
    )
      throw new Error("Select Semgrep Code (SAST) findings.");
  }
  if (
    finding["found_dependency"] != null ||
    finding["vulnerability_identifier"] != null
  )
    throw new Error("Select Semgrep Code (SAST) findings.");
}

interface SemgrepSelectionInput {
  deployment: string;
  ref: string;
  projectResponse: string;
  findingsResponses: Iterable<string>;
  findingIds: readonly string[];
}

function selectedRows(
  options: SemgrepSelectionInput,
  repositoryFor: (
    scope: SemgrepPlatformScope,
  ) => Pick<ReturnType<typeof repositoryContext>, "name" | "key">,
) {
  const scope = scopeOf(
    options.deployment,
    parseSemgrepResponse(options.projectResponse)["project"],
    options.ref,
  );
  // git-check-ref-format distinguishes literal branch/tag names from revision expressions.
  const refParts = scope.ref.split("/");
  if (
    refParts[0] !== "refs" ||
    refParts.length < 2 ||
    refParts.some(
      (part) => !part || part.startsWith(".") || part.endsWith(".lock"),
    ) ||
    scope.ref.endsWith(".") ||
    scope.ref.includes("..") ||
    scope.ref.includes("@{") ||
    /[\u0000-\u0020\u007f~^:?*\[\\]/u.test(scope.ref)
  )
    throw new Error(
      "Use a fully qualified Semgrep ref such as refs/heads/topic.",
    );
  const repository = repositoryFor(scope);
  const wanted = new Set(
    options.findingIds.map((id) =>
      semgrepPlatformId(requiredText(id, "Selected Semgrep finding ID")),
    ),
  );
  if (!wanted.size) throw new Error("Select at least one Semgrep finding ID.");
  const selected = new Map<string, Record<string, unknown>>();
  const pages =
    typeof options.findingsResponses === "string"
      ? [options.findingsResponses]
      : options.findingsResponses;
  for (const page of pages) {
    for (const finding of array(
      parseSemgrepResponse(page)["findings"],
      "Semgrep findings",
    )) {
      if (!isRecord(finding)) continue;
      const id = platformId(finding["id"]);
      if (!id || !wanted.has(id)) continue;
      if (selected.has(id))
        throw new Error(`Duplicate selected Semgrep finding ${id}.`);
      checkRow(finding, scope, repository, true);
      selected.set(id, finding);
    }
  }
  const rows = Array.from(wanted, (id) => {
    const value = selected.get(id);
    if (!value)
      throw new Error(
        `Selected Semgrep finding ${id} is missing from the supplied pages.`,
      );
    return value;
  });
  return { scope, rows };
}

/** Select existing SAST findings from native Web API responses for one project and ref. */
export function selectSemgrepPlatformFindings(
  options: SemgrepSelectionInput & {
    sourceRepositories?: readonly ExternalSourceRepository[];
  },
): SemgrepPlatformSelection {
  const { scope, rows } = selectedRows(options, (scope) =>
    selectionRepository(scope, options.sourceRepositories),
  );
  return {
    format: semgrepSelectionFormat,
    ...scope,
    findings: rows.map((row) => stringifySemgrepFinding(row)),
  };
}

/** Select SAST findings using the operator's exact, independently supplied HTTP(S) spelling. */
export function normalizeSelectedSemgrepPlatformFindings(
  options: SemgrepSelectionInput & {
    sourceRepositoryUrl: string;
  },
): ExternalFindings {
  const url = declaredScannerRepositoryUrl(
    options.sourceRepositoryUrl,
    "Semgrep",
    "local",
  );
  const { scope, rows } = selectedRows(options, (scope) => {
    if (scope.project.url !== url)
      throw new Error(
        "Selected Semgrep project does not match the operator's source repository URL.",
      );
    const exact = (value: string) => value;
    return { key: exact, name: exact };
  });
  return normalizeSelectionRows(rows, scope, "local");
}

function sourceId(
  scope: SemgrepPlatformScope,
  finding: Record<string, unknown>,
  idOf = semgrepPlatformId,
) {
  // Keep the same tuple for a selected import and a subsequent scoped Platform collection.
  const exact = (id: string) =>
    Number.isSafeInteger(Number(id)) ? Number(id) : id;
  return stableId("semgrep-platform", [
    scope.deployment,
    exact(idOf(wireJson.rawJSON(scope.project.id))),
    scope.product,
    scope.ref,
    exact(idOf(finding["id"])),
  ]);
}

function readScope(input: Record<string, unknown>) {
  if (input["product"] !== "sast")
    throw new Error("Select Semgrep Code (SAST) findings.");
  const project = record(input["project"], "Semgrep project");
  // The selector emits decimal strings; ordinary file JSON parsing would round numeric IDs.
  const id = requiredText(project["id"], "Semgrep selected project ID");
  const scope = scopeOf(
    input["deployment"],
    { ...project, id: wireJson.rawJSON(id) },
    input["ref"],
  );
  if (scope.project.id !== id && !/^[1-9][0-9]*$/u.test(id))
    throw new Error("Invalid saved Semgrep project ID.");
  scope.project.id = id;
  return scope;
}

const generatedId = /^semgrep-platform:[0-9a-f]{64}$/u;

/** Recognize retained Platform evidence after an SDK caller projects away wrapper fields. */
export function isSemgrepSelectionEvidence(finding: ExternalFinding): boolean {
  const data = finding.evidence.source_data;
  return (
    generatedId.test(finding.source_finding_id) ||
    data?.["format"] === semgrepSelectionFormat ||
    (data != null && Object.hasOwn(data, "semgrepPlatformFindingJson"))
  );
}

/** Recheck the source repository when an SDK caller supplies normalized evidence directly. */
export function semgrepSelectionRepository(
  finding: ExternalFinding,
  references: readonly ExternalSourceRepository[] = [],
): ExternalSourceRepository | undefined {
  if (!isSemgrepSelectionEvidence(finding)) return;
  const data = record(
    finding.evidence.source_data,
    "Semgrep Platform source data",
  );
  const scope = readScope(data);
  const row = parseSemgrepResponse(
    requiredText(data["semgrepPlatformFindingJson"], "Semgrep finding JSON"),
  );
  const repository = repositoryContext(scope, references);
  checkRow(row, scope, repository);
  if (
    generatedId.test(finding.source_finding_id) &&
    finding.source_finding_id !== sourceId(scope, row) &&
    finding.source_finding_id !== sourceId(scope, row, archivedPlatformId)
  )
    throw new Error(
      "The generated Semgrep finding ID does not match its native occurrence.",
    );
  const claimed = finding.evidence.details?.repository?.url;
  if (
    finding.evidence.branch !== scope.ref ||
    !claimed ||
    repository.key(
      declaredScannerRepositoryUrl(claimed, "Semgrep", "local"),
    ) !== repository.key(scope.project.url)
  )
    throw new Error(
      "The normalized finding does not match its original Semgrep repository and ref.",
    );
  return repository.source;
}

export function normalizeSemgrepPlatformSelection(
  input: Record<string, unknown>,
  declaredUrl?: string,
  target: ExternalImportTarget = "local",
  references: readonly ExternalSourceRepository[] = [],
) {
  const scope = readScope(input);
  const repository = selectionRepository(scope, references);
  if (
    declaredUrl &&
    repository.key(
      declaredScannerRepositoryUrl(declaredUrl, "Semgrep", "local"),
    ) !== repository.key(scope.project.url)
  )
    throw new Error(
      "Semgrep project does not match the declared source repository URL.",
    );
  const selected = array(input["findings"], "Semgrep selected findings");
  if (!selected.length)
    throw new Error(
      "A saved Semgrep selection must contain at least one finding.",
    );
  const rows = selected.map((value) => {
    const raw = requiredText(value, "Semgrep finding JSON");
    const finding = parseSemgrepResponse(raw);
    checkRow(finding, scope, repository);
    return finding;
  });
  return normalizeSelectionRows(rows, scope, target, archivedPlatformId);
}

function stringifySemgrepFinding(
  finding: Record<string, unknown>,
  idOf = semgrepPlatformId,
): string {
  const repository = responseRecord(
    finding["repository"],
    "Semgrep finding repository",
  );
  const nativeIds = [finding["id"], repository["id"]];
  return JSON.stringify(finding, (_key, value: unknown) => {
    if (wireJson.isRawJSON(value))
      return wireJson.rawJSON(
        nativeIds.includes(value)
          ? idOf(value)
          : canonicalNumber(value.rawJSON),
      );
    // Stable evidence only needs the retained row's object keys to be ordered.
    if (isRecord(value))
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [key, value[key]]),
      );
    return value;
  });
}

function normalizeSelectionRows(
  rows: Record<string, unknown>[],
  scope: SemgrepPlatformScope,
  target: ExternalImportTarget,
  idOf = semgrepPlatformId,
) {
  return normalizeRecords(
    rows,
    (finding) => {
      const rule = responseRecord(finding["rule"] ?? {}, "Semgrep rule");
      const name = text(rule["name"]) ?? text(finding["rule_name"]);
      const description =
        text(rule["message"]) ?? text(finding["rule_message"]);
      const location = responseRecord(
        finding["location"] ?? {},
        "Semgrep location",
      );
      const relative = relativePath(location["file_path"]);
      const path =
        relative &&
        !relative.endsWith("/.") &&
        !relative.includes("://") &&
        repositoryFilePath(relative)
          ? relative
          : null;
      const severity = text(finding["severity"])?.toLowerCase() ?? "";
      const startLine = path ? sourceLine(location["line"]) : null;
      return validateExternalEvidence(
        {
          title: requiredText(name ?? description, "Semgrep finding title"),
          description,
          severity: ["low", "medium", "high", "critical"].includes(severity)
            ? severity
            : "unknown",
          locations: path ? [{ path, line: startLine }] : [],
          branch: scope.ref,
          details: {
            kind: "sast",
            repository: { url: scope.project.url },
            scanner_origin: "Semgrep",
            rule: name ? { id: name } : null,
            source_status: text(finding["status"]),
            weakness_ids: weaknessIds(rule["cwe_names"]),
            code: {
              end_line:
                startLine !== null ? sourceLine(location["end_line"]) : null,
            },
          },
          source_data: {
            format: semgrepSelectionFormat,
            ...scope,
            project: { ...scope.project },
            semgrepPlatformFindingJson: stringifySemgrepFinding(finding, idOf),
          },
        },
        target,
      );
    },
    (finding) => sourceId(scope, finding, idOf),
    target,
  );
}
