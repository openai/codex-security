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
function canonicalNumber(token: string): string {
  const [, sign = "", integer, fraction = "", exponent = "0"] =
    /^(-?)(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/iu.exec(token)!;
  const significant = (integer + fraction).replace(/^0+/u, "");
  if (!significant) return "0";
  const digits = significant.replace(/0+$/u, "");
  const point = BigInt(exponent) + BigInt(significant.length - fraction.length);
  // Use the same fixed/scientific notation thresholds as JSON.stringify.
  if (point > -6n && point <= 21n) {
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
      (_key: string, value: unknown, context?: { source?: string }) => {
        if (typeof value === "number")
          return wireJson.rawJSON(context!.source!);
        // Vendor object order can change between reads without a finding changing.
        if (isRecord(value))
          return Object.fromEntries(
            Object.keys(value)
              .sort()
              .map((key) => [key, value[key]]),
          );
        return value;
      },
    ),
    "Semgrep API response",
  );
}

function platformId(value: unknown): string | undefined {
  const id = wireJson.isRawJSON(value)
    ? value.rawJSON
    : typeof value === "number" && Number.isSafeInteger(value)
      ? String(value)
      : value;
  return typeof id === "string" && /^[1-9][0-9]*$/u.test(id) ? id : undefined;
}

export function semgrepPlatformId(value: unknown): string {
  const id = platformId(value);
  if (!id) throw new Error("Expected an exact, positive Semgrep Platform ID.");
  return id;
}

function scopeOf(
  deployment: unknown,
  project: unknown,
  ref: unknown,
): SemgrepPlatformScope {
  const row = responseRecord(project, "Semgrep project");
  return {
    deployment: requiredText(deployment, "Semgrep deployment"),
    project: {
      id: semgrepPlatformId(row["id"]),
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
  if (isGitHubCloudHost(nativeHost)) source.platform = "github";
  else {
    const hint = references.find(
      ({ url, platform }) =>
        platform && semgrepReferenceMatches({ url: projectUrl, platform }, url),
    );
    if (hint?.platform) source.platform = hint.platform;
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
  const fullName = repository.name(scope.project.name);
  const name = repo["name"];
  const rowName = typeof name === "string" ? repository.name(name) : null;
  // Source URLs were checked segment-by-segment before matching display names.
  const projectPath = repository.name(
    decodeURIComponent(new URL(scope.project.url).pathname).replace(
      /^\/|\/$/gu,
      "",
    ),
  );
  const urlPathName =
    rowName !== null &&
    (rowName === projectPath || rowName + ".git" === projectPath);
  const qualifiedName =
    rowName !== null &&
    /^[^/]+(?:\/[^/]+)+$/u.test(rowName) &&
    (rowName === fullName || urlPathName);
  const matchedName =
    rowName === fullName ||
    rowName === fullName.split("/").at(-1) ||
    (urlPathName && fullName === rowName.split("/").at(-1));
  if (
    finding["ref"] !== scope.ref ||
    (repositoryId !== undefined && repositoryId !== scope.project.id) ||
    (repositoryId === undefined && name != null && !matchedName) ||
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
      !["sast", "code"].includes(String(product).toLowerCase())
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
  const repository = repositoryFor(scope);
  const wanted = new Set(options.findingIds.map(semgrepPlatformId));
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
      checkRow(finding, scope, repository);
      selected.set(id, finding);
    }
  }
  const rows = Array.from(wanted, (id) => {
    const value = selected.get(id);
    if (!value)
      throw new Error(
        `Selected Semgrep finding ${id} was not present in the supplied pages.`,
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
    findings: rows.map((row) => JSON.stringify(row)),
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
    if (!/^refs\/[^/]+(?:\/[^/]+)*$/u.test(scope.ref))
      throw new Error(
        "Use a fully qualified Semgrep ref such as refs/heads/topic.",
      );
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
) {
  // Keep the same tuple for a selected import and a subsequent scoped Platform collection.
  const exact = (id: string) =>
    Number.isSafeInteger(Number(id)) ? Number(id) : id;
  return stableId("semgrep-platform", [
    scope.deployment,
    exact(scope.project.id),
    scope.product,
    scope.ref,
    exact(semgrepPlatformId(finding["id"])),
  ]);
}

function readScope(input: Record<string, unknown>) {
  if (input["product"] !== "sast")
    throw new Error("Select Semgrep Code (SAST) findings.");
  const project = record(input["project"], "Semgrep project");
  // The selector emits decimal strings; ordinary file JSON parsing would round numeric IDs.
  requiredText(project["id"], "Semgrep selected project ID");
  return scopeOf(input["deployment"], project, input["ref"]);
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
    finding.source_finding_id !== sourceId(scope, row)
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
  const rows = array(input["findings"], "Semgrep selected findings").map(
    (value) => {
      const raw = requiredText(value, "Semgrep finding JSON");
      const finding = parseSemgrepResponse(raw);
      checkRow(finding, scope, repository);
      return finding;
    },
  );
  return normalizeSelectionRows(rows, scope, target);
}

function stringifySemgrepFinding(finding: Record<string, unknown>): string {
  return JSON.stringify(finding, function (this: unknown, key, value: unknown) {
    // Native occurrence and repository IDs must stay unsigned decimal tokens on replay.
    if (
      !wireJson.isRawJSON(value) ||
      (key === "id" && (this === finding || this === finding["repository"]))
    )
      return value;
    return wireJson.rawJSON(canonicalNumber(value.rawJSON));
  });
}

function normalizeSelectionRows(
  rows: Record<string, unknown>[],
  scope: SemgrepPlatformScope,
  target: ExternalImportTarget,
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
      const filePath = text(location["file_path"]);
      const path =
        filePath &&
        (/^[a-z][a-z0-9+.-]*:[/\\]/iu.test(filePath) ||
          filePath.includes("://"))
          ? null
          : relativePath(filePath);
      const startLine = path ? sourceLine(location["line"]) : null;
      return validateExternalEvidence(
        {
          title:
            name ??
            description ??
            `Semgrep finding ${semgrepPlatformId(finding["id"])}`,
          description,
          severity: text(finding["severity"])?.toLowerCase() ?? "unknown",
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
            semgrepPlatformFindingJson: stringifySemgrepFinding(finding),
          },
        },
        target,
      );
    },
    (finding) => sourceId(scope, finding),
    target,
  );
}
