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
  hostedRepositoryMatches,
  normalizeHostedGitRepositoryUrl,
  hostedRepositoryUrlKey,
  isPublicGitHost as publicGitHost,
  gitServiceHostname,
} from "./hosted-git-repository.js";
import { isGitHubCloudHost, parseGitRemote } from "./git-remote.js";
import { position, weaknessIds } from "./native-json-findings.js";
import {
  array,
  hostedRepositoryPath,
  normalizeRecords,
  record,
  relativePath,
  repositoryFilePath,
  scannerSeverity,
  strings,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";

import {
  canonicalNumber,
  hostedNumberToken,
  hostedNativeRepositoryUrl,
  hostedRepositoryUrl,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";
import { declaredScannerRepositoryUrl } from "./scanner-repository-url.js";
import {
  legacyDecimalInteger,
  restoreLegacyHostedNumbers,
} from "./hosted-scanner-v1.js";
import {
  semgrepV1Id,
  upgradeSemgrepPlatformReport,
} from "./semgrep-platform-v1.js";
import type { SemgrepImportOptions } from "./semgrep-findings.js";

export const semgrepPlatformFormat = "semgrep-platform-findings/v2";
export const semgrepPlatformLegacyFormat = "semgrep-platform-findings/v1";
export const SEMGREP_PLATFORM_PRODUCTS = ["sast", "sca", "ai_sast"] as const;
export type SemgrepPlatformProduct = (typeof SEMGREP_PLATFORM_PRODUCTS)[number];
export const semgrepSelectionFormat = "semgrep-platform-selection/v1";

export function isSemgrepPlatformFormat(
  format: unknown,
): format is
  | typeof semgrepSelectionFormat
  | typeof semgrepPlatformFormat
  | typeof semgrepPlatformLegacyFormat {
  return (
    format === semgrepSelectionFormat ||
    format === semgrepPlatformFormat ||
    format === semgrepPlatformLegacyFormat
  );
}

/** Recover the native collection scope, including when every row was excluded. */
export function semgrepPlatformReportScope(
  input: ExternalFindings,
  provider?: string,
) {
  const format = "sourceFormat" in input ? input.sourceFormat : undefined;
  if (
    format === undefined &&
    provider === "semgrep" &&
    "sourceRepositoryUrl" in input &&
    input.sourceRepositoryUrl !== undefined &&
    (input.findings.length === 0 ||
      input.findings.some((row) => isSemgrepPlatformEvidence(row, provider)))
  ) {
    // The object-row SDK retained only the binding on the envelope, including empty reports.
    return {
      url: hostedRepositoryUrl(input.sourceRepositoryUrl, "Semgrep Platform"),
    };
  }
  if (!isSemgrepPlatformFormat(format)) return;
  const scope = record(
    "semgrepPlatformScope" in input ? input.semgrepPlatformScope : undefined,
    "Normalized Semgrep report scope",
  );
  return {
    format,
    deployment: requiredText(scope["deployment"], "Semgrep deployment"),
    projectId: savedPlatformId(
      requiredText(scope["projectId"], "Semgrep project ID"),
    ),
    ref: requiredText(scope["ref"], "Semgrep ref"),
    product: scopeProduct(scope["product"], format !== semgrepSelectionFormat),
    url: hostedRepositoryUrl(
      "sourceRepositoryUrl" in input ? input.sourceRepositoryUrl : undefined,
      "Semgrep Platform",
    ),
  };
}

export function semgrepPlatformReportRepository(
  input: ExternalFindings,
  provider?: string,
) {
  return semgrepPlatformReportScope(input, provider)?.url;
}

export interface SemgrepPlatformScope {
  deployment: string;
  project: { id: string; name: string; url: string };
  ref: string;
  product: SemgrepPlatformProduct;
}

type ResolvedScope = SemgrepPlatformScope & {
  sourceRepositoryUrl?: string;
  nativeProjectUrl?: string;
};

export interface SemgrepPlatformSelection extends SemgrepPlatformScope {
  product: "sast";
  format: typeof semgrepSelectionFormat;
  /** Each native finding is JSON text so numbers retain their exact wire values through replay. */
  findings: string[];
}

// Raw JSON numbers are represented as JavaScript objects during lossless parsing.
export function responseRecord(value: unknown, label: string) {
  return record(
    hostedNumberToken(value) === undefined ? value : undefined,
    label,
  );
}

const wireJson = JSON as JSON & {
  rawJSON(source: string): { rawJSON: string };
  isRawJSON(value: unknown): value is { rawJSON: string };
};

function sourceLine(value: unknown, coerceStrings: boolean): number | null {
  if (value == null) return null;
  const token = hostedNumberToken(value);
  // A long fraction can round to an integer if it is converted before checking its decimal value.
  if (token !== undefined)
    return position(Number(legacyDecimalInteger(token)), "Semgrep source line");
  return position(
    coerceStrings ? Number(semgrepPlatformId(value)) : value,
    "Semgrep source line",
  );
}

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

export function semgrepPlatformIdOrUndefined(
  value: unknown,
): string | undefined {
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
  const id = semgrepPlatformIdOrUndefined(value);
  if (id === undefined)
    throw new Error("Expected an exact, positive Semgrep Platform ID.");
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

function savedPlatformId(value: unknown): string {
  if (typeof value !== "string") return semgrepPlatformId(value);
  const canonical = semgrepPlatformId(wireJson.rawJSON(value));
  if (canonical !== value && !/^[1-9][0-9]*$/u.test(value))
    throw new Error("Invalid saved Semgrep project ID.");
  return value;
}

function scopeOf(
  deployment: unknown,
  project: unknown,
  ref: unknown,
  readId = semgrepPlatformId,
  readUrl = hostedRepositoryUrl,
) {
  const row = responseRecord(project, "Semgrep project");
  const id = readId(row["id"]);
  return {
    deployment: requiredText(deployment, "Semgrep deployment"),
    project: {
      id: text(row["id"]) ?? id,
      name: requiredText(row["name"], "Semgrep project name"),
      url: readUrl(row["url"], "Semgrep Platform"),
    },
    ref: requiredText(ref, "Semgrep ref"),
    product: "sast" as const,
  };
}

export function projectAliases(
  name: string,
  url: string,
  references: SemgrepRepositoryReference = [],
  earlyV1 = false,
) {
  const { hostname, pathname } = new URL(url);
  const path = pathname.slice(1).replace(/\/$/u, "");
  const decodePath = (decode: (value: string) => string) =>
    path
      .split("/")
      .map((segment) => {
        try {
          // Keep encoded separators within their original segment.
          const label = decode(segment);
          return /[/\\]/u.test(label) ? segment : label;
        } catch {
          return segment;
        }
      })
      .join("/");
  const { name: key, source } = repositoryContext(url, references);
  const paths = [path, decodePath(decodeURIComponent)];
  const publicHost = publicGitHost(gitServiceHostname(hostname));
  const knownGitSuffix =
    source.platform === "github" || source.platform === "gitlab" || publicHost;
  if (knownGitSuffix)
    paths.push(...paths.map((path) => path.replace(/\.git$/u, "")));
  const pathKeys = new Set(
    paths.flatMap((path) => [
      key(path),
      key(path.slice(path.lastIndexOf("/") + 1)),
    ]),
  );
  const shortName = name.slice(name.lastIndexOf("/") + 1);
  const historicalPaths: string[] = [];
  if (earlyV1) {
    // Older exports used decodeURI, which preserves escaped reserved delimiters.
    for (const historical of [path, decodePath(decodeURI)]) {
      if (!publicGitHost(hostname)) historicalPaths.push(historical);
      if (publicHost || source.platform === "github")
        historicalPaths.push(historical.replace(/\.git$/u, ""));
    }
  }
  const hasHistoricalPath = (label: string) =>
    historicalPaths.some(
      (path) =>
        label === path || label === path.slice(path.lastIndexOf("/") + 1),
    );
  return {
    hasHistoricalPath,
    has: (label: string) =>
      label === name ||
      label === shortName ||
      pathKeys.has(key(label)) ||
      hasHistoricalPath(label),
  };
}

/** Older captures could derive a row label from their verified HTTP mapping for an SSH project. */
export function legacyProjectAliases(
  name: string,
  url: string,
  references: SemgrepRepositoryReference,
  mapping: string | undefined,
) {
  const native = projectAliases(name, url, references, true);
  const mapped =
    mapping && mapping !== url
      ? projectAliases(name, mapping, references, true)
      : undefined;
  return {
    has: (label: string) =>
      native.has(label) || !!mapped?.hasHistoricalPath(label),
  };
}

/** Compare HTTP origins canonically without folding paths on independent custom Git hosts. */
export function semgrepRepositoryUrlKey(value: string): string {
  return hostedRepositoryUrlKey(nativeHttp(value));
}

export type SemgrepRepositoryReference =
  readonly ExternalSourceRepository[] | ((url: string) => string);

/** A real HTTP URL can elide its default port. Git transport serializations retain explicit ports. */
function nativeHttp(url: string) {
  return URL.parse(url)?.href ?? url;
}

/** Readers may pass the SCM web link from the project response or its equivalent Git transport. */
export function semgrepReferenceMatches(
  source: ExternalSourceRepository,
  url: string,
): boolean {
  // A standard explicit Git HTTP(S) helper carries the same fetch URL.
  const helper = /^(?:https?|ftps?)::(?=([a-zA-Z]+):\/\/)/u.exec(url);
  if (helper)
    return (
      /^https?$/iu.test(helper[1]!) &&
      hostedRepositoryMatches(source, url.slice(helper[0].length))
    );
  if (hostedRepositoryMatches(source, url)) return true;
  try {
    // Serialize only a valid repository link. Git checkout URLs retain their original bytes.
    const link = hostedRepositoryUrl(url, "Semgrep");
    return hostedRepositoryMatches(source, new URL(link).href);
  } catch {
    return false;
  }
}

export function semgrepPlatformRepositoryReference(
  url: string,
  references: readonly ExternalSourceRepository[],
): ExternalSourceRepository {
  const projectUrl = nativeHttp(url);
  const source: ExternalSourceRepository = { url: projectUrl };
  const nativeHost = gitServiceHostname(URL.parse(url)?.hostname ?? "");
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
  return source;
}

/** Keep provider transport spelling independently of its resolved HTTP repository. */
export function semgrepProjectUrlEvidence(
  raw: unknown,
  resolved: string | undefined,
  mapping: string | undefined,
) {
  if (resolved === undefined) return { sourceRepositoryUrl: mapping };
  if (typeof raw === "string" && raw !== resolved)
    return {
      nativeProjectUrl: raw,
      ...(mapping && { sourceRepositoryUrl: mapping }),
    };
  return {};
}

/** Interpret a project's native SSH spelling only when its Git host is known. */
export function semgrepNativeProjectUrl(
  value: unknown,
  references: SemgrepRepositoryReference,
) {
  if (value == null || value === "") return;
  const label = "Semgrep project repository";
  if (typeof value === "string" && typeof references !== "function") {
    for (const reference of references) {
      if (reference.platform !== "github" && reference.platform !== "gitlab")
        continue;
      let host: string | undefined;
      try {
        host = parseGitRemote(reference.url)?.url.hostname;
      } catch {
        continue;
      }
      if (!host) continue;
      const url = normalizeHostedGitRepositoryUrl(
        reference.url,
        `https://${host}`,
        true,
      );
      if (
        /^https?:\/\//iu.test(url) &&
        semgrepReferenceMatches({ url, platform: reference.platform }, value)
      )
        return hostedNativeRepositoryUrl(value, label, host);
    }
  }
  return hostedNativeRepositoryUrl(value, label);
}

function referenceRepositoryKey(
  references: readonly ExternalSourceRepository[],
) {
  return (url: string) => repositoryContext(url, references).key(url);
}

function repositoryContext(
  projectUrl: string,
  references: SemgrepRepositoryReference = [],
) {
  const source = semgrepPlatformRepositoryReference(
    projectUrl,
    typeof references === "function" ? [] : references,
  );
  const github = source.platform === "github";
  return {
    source,
    key: (url: string) =>
      typeof references === "function"
        ? references(nativeHttp(url))
        : hostedRepositoryUrlKey(
            nativeHttp(url),
            github,
            source.platform === "gitlab",
          ),
    name: (name: string) => (github ? name.toLowerCase() : name),
  };
}

export function selectionRepository(
  projectUrl: string,
  references: readonly ExternalSourceRepository[] = [],
) {
  const repository = repositoryContext(projectUrl, references);
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

function repositoryWithOnlyAlias(
  finding: Record<string, unknown>,
  names: Pick<ReadonlySet<string>, "has">,
): string | undefined {
  const repo = record(
    finding["repository"] ?? {},
    "Semgrep finding repository",
  );
  const label = text(repo["name"]);
  return label && !names.has(label) && repo["id"] == null && !text(repo["url"])
    ? label
    : undefined;
}

/** Complete reports record the repository labels returned by the project-ID-scoped request. */
export function checkSemgrepPlatformRow(
  finding: Record<string, unknown>,
  scope: SemgrepPlatformScope,
  aliases?: Pick<ReadonlySet<string>, "has">,
  repository = repositoryContext(scope.project.url),
  readId = semgrepPlatformId,
  repositoryUrl = hostedNativeRepositoryUrl,
  capture = false,
) {
  const repo = responseRecord(
    finding["repository"] ?? (aliases ? {} : undefined),
    "Semgrep finding repository",
  );
  const repositoryId = repo["id"] == null ? undefined : readId(repo["id"]);
  const hasUrl =
    repo["url"] != null &&
    (repositoryUrl === hostedRepositoryUrl || repo["url"] !== "");
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
  const selectionRepositoryMatches =
    hasUrl || (repositoryId !== undefined && !!qualifiedName);
  if (!aliases) {
    readId(finding["id"]);
    if (!selectionRepositoryMatches)
      throw new Error(
        "Semgrep finding repository does not match the selected project and ref.",
      );
  }
  if (
    repositoryId !== undefined &&
    repositoryId !== semgrepPlatformId(wireJson.rawJSON(scope.project.id))
  )
    throw new Error(
      "Semgrep finding repository does not match the selected project and ref.",
    );
  const declaredProduct =
    scope.product === "sast" ? ["sast", "code"] : [scope.product];
  for (const product of [finding["issue_type"], finding["product"]]) {
    if (
      product != null &&
      (typeof product !== "string" ||
        !declaredProduct.includes(product.toLowerCase()))
    )
      throw new Error(
        scope.product === "sast"
          ? "Select Semgrep Code (SAST) findings."
          : "Semgrep finding does not match the selected product.",
      );
  }
  if (
    (!aliases || finding["ref"] !== undefined) &&
    finding["ref"] !== scope.ref
  )
    throw new Error(
      "Semgrep finding does not belong to the selected project and ref.",
    );
  if (hasUrl) {
    const url = repositoryUrl(
      repo["url"],
      "Semgrep finding repository",
      repository.source.platform === "github" ||
        repository.source.platform === "gitlab"
        ? new URL(repository.source.url).hostname
        : undefined,
    );
    if (repository.key(url) !== repository.key(scope.project.url))
      throw new Error(
        "Semgrep finding repository does not match the selected project and ref.",
      );
  }
  // A verified ID or URL can identify a bulk row whose optional display name is blank.
  const alias =
    typeof name === "string" && (repositoryId !== undefined || hasUrl)
      ? text(name)
      : name;
  if (
    aliases &&
    alias != null &&
    !aliases.has(requiredText(alias, "Semgrep repository name"))
  )
    throw new Error(
      "Semgrep finding repository does not match the selected project and ref.",
    );
  if (
    scope.product !== "sca" &&
    (finding["found_dependency"] != null ||
      finding["vulnerability_identifier"] != null)
  )
    throw new Error("Select Semgrep Code (SAST) findings.");
  return (
    scope.product === "sast" &&
    finding["ref"] === scope.ref &&
    selectionRepositoryMatches &&
    [finding["id"], repo["id"]].every(
      (id) => id == null || semgrepPlatformIdOrUndefined(id) !== undefined,
    )
  );
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
  ) => ReturnType<typeof repositoryContext>,
  repositoryUrl = hostedNativeRepositoryUrl,
) {
  const scope = scopeOf(
    options.deployment,
    parseSemgrepResponse(options.projectResponse)["project"],
    options.ref,
    semgrepPlatformId,
    (url, label) => declaredScannerRepositoryUrl(url, label, "local"),
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
      const id = semgrepPlatformIdOrUndefined(finding["id"]);
      if (!id || !wanted.has(id)) continue;
      if (selected.has(id))
        throw new Error(`Duplicate selected Semgrep finding ${id}.`);
      checkSemgrepPlatformRow(
        finding,
        scope,
        undefined,
        repository,
        semgrepPlatformId,
        repositoryUrl,
        true,
      );
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
    selectionRepository(scope.project.url, options.sourceRepositories),
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
  const url = hostedRepositoryUrl(options.sourceRepositoryUrl, "Semgrep");
  const { scope, rows } = selectedRows(
    options,
    (scope) => {
      if (scope.project.url !== url)
        throw new Error(
          "Selected Semgrep project does not match the operator's source repository URL.",
        );
      const exact = (value: string) => value;
      return { source: { url }, key: exact, name: exact };
    },
    hostedRepositoryUrl,
  );
  return normalizePlatformRows(
    rows.map((finding) => ({ finding, selectable: true })),
    scope,
    "local",
  );
}

function sourceId(
  scope: SemgrepPlatformScope,
  finding: Record<string, unknown>,
  readId = semgrepPlatformId,
) {
  // Keep the same tuple for a selected import and a subsequent scoped Platform collection.
  const exact = (id: string) =>
    Number.isSafeInteger(Number(id)) ? Number(id) : id;
  return stableId("semgrep-platform", [
    scope.deployment,
    exact(readId(wireJson.rawJSON(scope.project.id))),
    scope.product,
    scope.ref,
    exact(readId(finding["id"])),
  ]);
}

function scopeProduct(native: unknown, complete: boolean) {
  const product = SEMGREP_PLATFORM_PRODUCTS.find((value) => value === native);
  if (!product || (!complete && product !== "sast"))
    throw new Error(
      "Select a supported Semgrep Platform product for this report.",
    );
  return product;
}

function readScope(
  input: Record<string, unknown>,
  references: SemgrepRepositoryReference,
) {
  const complete =
    input["format"] === semgrepPlatformFormat ||
    input["format"] === semgrepPlatformLegacyFormat;
  const product = scopeProduct(input["product"], complete);
  const project = responseRecord(input["project"], "Semgrep project");
  if (
    input["format"] === semgrepPlatformFormat &&
    typeof project["id"] !== "string"
  )
    throw new Error(
      "A Semgrep Platform v2 project ID must be a positive decimal string.",
    );
  if (!complete) requiredText(project["id"], "Semgrep selected project ID");
  const mapping =
    complete && input["sourceRepositoryUrl"] !== undefined
      ? hostedRepositoryUrl(
          input["sourceRepositoryUrl"],
          "Semgrep source repository",
        )
      : undefined;
  // Captures expose an HTTP URL; stored occurrences retain the provider's SSH spelling.
  const projectUrl = project["url"];
  const suppliedNative = complete ? input["nativeProjectUrl"] : undefined;
  const raw =
    suppliedNative !== undefined
      ? requiredText(suppliedNative, "Semgrep native project URL")
      : complete &&
          typeof projectUrl === "string" &&
          !/^https?:\/\//iu.test(projectUrl)
        ? projectUrl
        : undefined;
  const native =
    raw === undefined ? undefined : semgrepNativeProjectUrl(raw, references);
  if (
    suppliedNative !== undefined &&
    (!native || native === raw || native !== projectUrl)
  )
    throw new Error(
      "Semgrep native project URL does not match its recorded HTTP repository.",
    );
  if (mapping && projectUrl != null) {
    const key = native && repositoryContext(native, references).key;
    if (key ? key(native!) !== key(mapping) : projectUrl !== mapping)
      throw new Error(
        "Semgrep project does not match its recorded source repository URL.",
      );
  }
  const scope = {
    ...scopeOf(
      input["deployment"],
      { ...project, url: native ?? mapping ?? project["url"] },
      input["ref"],
      savedPlatformId,
    ),
    ...(mapping && { sourceRepositoryUrl: mapping }),
    ...(native && { nativeProjectUrl: raw }),
    product,
  };
  const aliases = complete
    ? new Set(
        array(input["repositoryAliases"], "Semgrep repository aliases").map(
          (value) => requiredText(value, "Semgrep repository alias"),
        ),
      )
    : undefined;
  return { scope, aliases };
}

function matchesNativeInteger(
  value: unknown,
  expected: number | null | undefined,
): boolean {
  if (expected == null) return value == null;
  const token = hostedNumberToken(value);
  if (token === undefined) return value === expected;
  return expected === 0
    ? /^-?0(?:\.0+)?(?:e[+-]?\d+)?$/iu.test(token)
    : legacyDecimalInteger(token) === String(expected);
}

const generatedId = /^semgrep-platform:[0-9a-f]{64}$/u;
/** Current occurrences carry a provider-specific key; older v1 rows retain their native scope and finding. */
export function isSemgrepPlatformEvidence(
  finding: ExternalFinding,
  provider?: string,
): boolean {
  const data = finding.evidence.source_data;
  if (generatedId.test(finding.source_finding_id)) return true;
  if (!data) return false;
  if (
    isSemgrepPlatformFormat(data["format"]) ||
    Object.hasOwn(data, "semgrepPlatformFindingJson")
  )
    return true;
  // Other scanners can use the same project and finding fields, including numeric IDs.
  if (provider !== "semgrep") return false;
  const project = data["project"];
  const row = data["finding"];
  return (
    isRecord(row) &&
    "id" in row &&
    isRecord(project) &&
    project["id"] != null &&
    typeof project["name"] === "string" &&
    typeof data["ref"] === "string" &&
    typeof data["deployment"] === "string" &&
    SEMGREP_PLATFORM_PRODUCTS.some((product) => product === data["product"])
  );
}

function upgradeOriginalSemgrepFinding(
  data: Record<string, unknown>,
  references: SemgrepRepositoryReference,
): Record<string, unknown> {
  const {
    numericFields: _witness,
    finding: original,
    ...context
  } = restoreLegacyHostedNumbers(data);
  const converted = upgradeSemgrepPlatformReport(
    { ...context, findings: [original], findingCount: 1 },
    undefined,
    typeof references === "function"
      ? references
      : referenceRepositoryKey(references),
    references,
  );
  return {
    ...converted,
    semgrepPlatformFindingJson: array(
      converted["findings"],
      "Semgrep findings",
    )[0],
  };
}

/** Keep caller-supplied metadata while replacing the scanner's old wire representation. */
function canonicalSourceDataWithExtensions(
  retained: Record<string, unknown>,
  canonical: ReturnType<typeof platformSourceData>,
  original: boolean,
) {
  const extensions = (
    original: Record<string, unknown>,
    verified: Record<string, unknown>,
    replaced: string[] = [],
  ) =>
    Object.fromEntries(
      Object.entries(original).filter(
        ([key]) => !Object.hasOwn(verified, key) && !replaced.includes(key),
      ),
    );
  return {
    ...canonical,
    ...extensions(retained, canonical, [
      ...(original ? ["finding", "numericFields", "sourceRepositoryUrl"] : []),
      "nativeProjectUrl",
      "repositoryAliases",
      "repositoryWitnessJson",
      "idEncoding",
    ]),
    project: {
      ...canonical.project,
      ...extensions(
        record(retained["project"], "Semgrep project"),
        canonical.project,
      ),
    },
  };
}

function legacyWitnessKey(
  scope: SemgrepPlatformScope,
  projectUrlKey: string,
  label: string,
) {
  return JSON.stringify([
    scope.deployment,
    scope.project.id,
    scope.product,
    scope.ref,
    projectUrlKey,
    label,
  ]);
}

function nativeOccurrence(
  retained: Record<string, unknown>,
  references: SemgrepRepositoryReference,
) {
  let data = !isSemgrepPlatformFormat(retained["format"])
    ? {
        ...retained,
        format:
          (!Object.hasOwn(retained, "semgrepPlatformFindingJson") &&
            "finding" in retained) ||
          retained["idEncoding"] === "v1-decimal"
            ? semgrepPlatformLegacyFormat
            : "repositoryAliases" in retained
              ? semgrepPlatformFormat
              : semgrepSelectionFormat,
      }
    : retained;
  const legacy = data["format"] === semgrepPlatformLegacyFormat;
  const original = legacy && !Object.hasOwn(data, "semgrepPlatformFindingJson");
  if (original) data = upgradeOriginalSemgrepFinding(data, references);
  const { scope, aliases } = readScope(data, references);
  const repository = repositoryContext(scope.project.url, references);
  const row = parseSemgrepResponse(
    requiredText(data["semgrepPlatformFindingJson"], "Semgrep finding JSON"),
  );
  return { data, legacy, original, scope, aliases, repository, row };
}

/** Original v1 occurrences could keep only the observed repository label on a row. */
export function semgrepLegacyRepositoryWitnesses(
  findings: readonly ExternalFinding[],
  provider: string,
  references: SemgrepRepositoryReference = [],
): ReadonlyMap<string, string> {
  const witnesses = new Map<string, string>();
  // Current occurrences carry their own witness. Only original rows need a sibling lookup.
  if (
    !findings.some(({ evidence }) =>
      isRecord(evidence.source_data?.["finding"]),
    )
  )
    return witnesses;
  for (const finding of findings) {
    const data = finding.evidence.source_data;
    if (!data || !isSemgrepPlatformEvidence(finding, provider)) continue;
    const { scope, aliases, repository, row, legacy } = nativeOccurrence(
      data,
      references,
    );
    const repo = row["repository"];
    if (!isRecord(repo)) continue;
    const label = text(repo["name"]);
    if (!label || (repo["id"] == null && !text(repo["url"]))) continue;
    checkSemgrepPlatformRow(
      row,
      scope,
      aliases,
      repository,
      legacy ? semgrepV1Id : semgrepPlatformId,
    );
    witnesses.set(
      legacyWitnessKey(scope, repository.key(scope.project.url), label),
      JSON.stringify({ id: scope.project.id, name: label }),
    );
  }
  return witnesses;
}

/** Recheck the source repository when an SDK caller supplies normalized evidence directly. */
export function semgrepPlatformFindingRepository(
  finding: ExternalFinding,
  provider: string,
  references: SemgrepRepositoryReference = [],
  legacyWitnesses?: ReadonlyMap<string, string>,
): string | undefined {
  return semgrepPlatformFindingBinding(
    finding,
    provider,
    references,
    legacyWitnesses,
  )?.url;
}

function platformLocationPath(value: unknown) {
  const path = relativePath(value);
  return path && !path.endsWith("/.") && repositoryFilePath(path) ? path : null;
}

function platformSeverity(value: unknown, selectable: boolean) {
  const severity = text(value)?.toLowerCase();
  return scannerSeverity(
    selectable && severity === "informational" ? null : severity,
  );
}

/** Upgrade only values produced by the original object-row reader; keep SDK-authored evidence. */
function migrateLegacyProjection(
  evidence: ExternalFinding["evidence"],
  row: Record<string, unknown>,
  scope: SemgrepPlatformScope,
  selectable: boolean,
  references: SemgrepRepositoryReference,
) {
  const severity = text(row["severity"]);
  const oldSeverity = scannerSeverity(
    severity === "informational" ? null : severity,
  );
  const upgradeSeverity =
    evidence.severity === oldSeverity &&
    oldSeverity !== scannerSeverity(severity?.toLowerCase());
  const location = isRecord(row["location"]) ? row["location"] : {};
  const oldPath = hostedRepositoryPath(location["file_path"]);
  const first = evidence.locations?.[0];
  // Only replace the exact location and end line produced by the original object-row reader.
  const oldLocation =
    oldPath !== platformLocationPath(location["file_path"]) &&
    (oldPath
      ? evidence.locations?.length === 1 &&
        first?.path === oldPath &&
        matchesNativeInteger(location["line"], first.line)
      : evidence.locations?.length === 0) &&
    matchesNativeInteger(
      oldPath && scope.product !== "sca" && first?.line != null
        ? location["end_line"]
        : null,
      evidence.details?.code?.end_line,
    );
  if (!upgradeSeverity && !oldLocation) return;
  const projected = normalizePlatformRows(
    [{ finding: row, selectable }],
    scope,
    "local",
    {
      legacy: true,
      projectNames: projectAliases(
        scope.project.name,
        scope.project.url,
        references,
      ),
    },
  ).findings[0]?.evidence;
  if (!projected) return;
  return {
    ...(upgradeSeverity && { severity: projected.severity }),
    ...(oldLocation && { locations: projected.locations }),
    ...(oldLocation &&
      evidence.details?.code &&
      projected.details?.code && {
        details: {
          ...evidence.details,
          code: {
            ...evidence.details.code,
            end_line: projected.details.code.end_line,
          },
        },
      }),
  };
}

function qualifiedBranch(ref: string) {
  return ref.startsWith("refs/") ? ref : `refs/heads/${ref}`;
}

export function semgrepPlatformFindingBinding(
  finding: ExternalFinding,
  provider: string,
  references: SemgrepRepositoryReference = [],
  legacyWitnesses?: ReadonlyMap<string, string>,
  reportScope?: ReturnType<typeof semgrepPlatformReportScope>,
  projectedRepositoryUrl?: string,
) {
  const retained = finding.evidence.source_data;
  if (!isSemgrepPlatformEvidence(finding, provider)) {
    if (reportScope?.format && reportScope.format !== semgrepSelectionFormat) {
      const url =
        finding.evidence.details?.repository?.url ?? projectedRepositoryUrl;
      if (
        url &&
        !semgrepReferenceMatches(
          repositoryContext(reportScope.url, references).source,
          url,
        )
      )
        throw new Error(
          "The projected repository does not match the Semgrep report repository.",
        );
      const branch = finding.evidence.branch;
      if (
        branch &&
        qualifiedBranch(branch) !== qualifiedBranch(reportScope.ref)
      )
        throw new Error(
          "The projected branch does not match the Semgrep report ref.",
        );
    }
    return;
  }
  if (!retained)
    throw new Error("Missing the original Semgrep finding evidence.");
  const { data, legacy, original, scope, aliases, repository, row } =
    nativeOccurrence(retained, references);
  if (
    reportScope?.deployment !== undefined &&
    (scope.deployment !== reportScope.deployment ||
      scope.project.id !== reportScope.projectId ||
      scope.ref !== reportScope.ref ||
      scope.product !== reportScope.product)
  )
    throw new Error(
      "The Semgrep report repository scope does not match the finding's deployment, project ID, ref, or product.",
    );

  const selectable = checkSemgrepPlatformRow(
    row,
    scope,
    aliases,
    repository,
    legacy ? semgrepV1Id : semgrepPlatformId,
  );
  let occurrenceId = legacy ? semgrepV1Id : semgrepPlatformId;
  const nativeId = sourceId(scope, row, occurrenceId);
  if (
    generatedId.test(finding.source_finding_id) &&
    finding.source_finding_id !== nativeId
  ) {
    if (
      legacy ||
      finding.source_finding_id !== sourceId(scope, row, archivedPlatformId)
    )
      throw new Error(
        "The generated Semgrep finding ID does not match its native occurrence.",
      );
    occurrenceId = archivedPlatformId;
  }
  const { name, url } = scope.project;
  let namedOnly =
    aliases && repositoryWithOnlyAlias(row, projectAliases(name, url));
  const raw =
    namedOnly &&
    (original
      ? legacyWitnesses?.get(
          legacyWitnessKey(scope, repository.key(url), namedOnly),
        )
      : data["repositoryWitnessJson"]);
  // Only rely on the reader's platform hint when there is no independent proof.
  if (
    namedOnly &&
    raw === undefined &&
    projectAliases(name, url, references).has(namedOnly)
  )
    namedOnly = undefined;
  const legacyPath =
    original &&
    namedOnly &&
    legacyProjectAliases(name, url, references, scope.sourceRepositoryUrl).has(
      namedOnly,
    );
  if (namedOnly && !legacyPath) {
    const witness = parseSemgrepResponse(
      requiredText(raw, "Semgrep repository alias witness"),
    );
    if (
      witness["name"] !== namedOnly ||
      (witness["id"] == null && !text(witness["url"]))
    )
      throw new Error(
        "Semgrep repository alias lacks a matching project ID or URL.",
      );
    checkSemgrepPlatformRow(
      { repository: witness },
      scope,
      aliases,
      repository,
      legacy
        ? semgrepV1Id
        : (id) => semgrepPlatformId(wireJson.rawJSON(savedPlatformId(id))),
    );
  }
  const claimed = finding.evidence.details?.repository?.url;
  if (
    finding.evidence.branch !== scope.ref ||
    (!claimed && scope.product !== "sca") ||
    (!!claimed &&
      repository.key(
        hostedRepositoryUrl(claimed, "Semgrep evidence repository"),
      ) !== repository.key(scope.project.url))
  )
    throw new Error(
      "The normalized finding does not match its original Semgrep repository and ref.",
    );
  const canonical = platformSourceData(
    row,
    scope,
    selectable,
    aliases ? { legacy } : undefined,
    namedOnly,
    occurrenceId,
  );
  let migration = original
    ? migrateLegacyProjection(
        finding.evidence,
        row,
        scope,
        selectable,
        references,
      )
    : undefined;
  if (
    data["format"] === semgrepPlatformFormat &&
    canonical.format === semgrepSelectionFormat
  ) {
    const selectedSeverity = platformSeverity(row["severity"], true);
    if (
      selectedSeverity !== finding.evidence.severity &&
      finding.evidence.severity === platformSeverity(row["severity"], false)
    )
      migration = { severity: selectedSeverity };
  }
  // The original reader projected the HTTP mapping when the native project URL used SSH.
  const oldMappedUrl =
    original &&
    scope.product !== "sca" &&
    scope.nativeProjectUrl !== undefined &&
    claimed === scope.sourceRepositoryUrl &&
    claimed !== scope.project.url;
  const details = migration?.details ?? finding.evidence.details;
  return {
    url: scope.project.url,
    migration:
      oldMappedUrl && details?.repository
        ? {
            ...migration,
            details: {
              ...details,
              repository: { ...details.repository, url: scope.project.url },
            },
          }
        : migration,
    sourceData: canonicalSourceDataWithExtensions(
      retained,
      canonical,
      original,
    ),
  };
}

/** Normalize a saved selection or a scoped Platform project export for local replay. */
export function normalizeSemgrepPlatformFindings(
  report: unknown,
  options: string | Partial<SemgrepImportOptions> = {},
  target: ExternalImportTarget = "local",
  references: readonly ExternalSourceRepository[] = typeof options === "object"
    ? (options.sourceRepositories ?? [])
    : [],
) {
  if (target !== "local")
    throw new Error("Semgrep Platform findings require a local import.");
  const declaredUrl =
    typeof options === "string" ? options : options.sourceRepositoryUrl;
  const saved = record(report, "Semgrep Platform report");
  const sourceFormat = saved["format"];
  if (!isSemgrepPlatformFormat(sourceFormat))
    throw new Error("Expected a Semgrep Platform selection or project export.");
  const legacy = sourceFormat === semgrepPlatformLegacyFormat;
  const readId = legacy ? semgrepV1Id : semgrepPlatformId;
  const input = legacy
    ? upgradeSemgrepPlatformReport(
        saved,
        declaredUrl,
        referenceRepositoryKey(references),
        references,
      )
    : saved;
  const { scope, aliases } = readScope(input, references);
  const repository = selectionRepository(scope.project.url, references);
  if (
    declaredUrl &&
    repository.key(hostedRepositoryUrl(declaredUrl, "Semgrep")) !==
      repository.key(scope.project.url)
  )
    throw new Error(
      "Semgrep project does not match the declared source repository URL.",
    );
  const verifiedLabels = new Set<string>();
  const projectNames = projectAliases(
    scope.project.name,
    scope.project.url,
    references,
  );
  const entries = array(input["findings"], "Semgrep Platform findings");
  if (!aliases && !entries.length)
    throw new Error(
      "A saved Semgrep selection must contain at least one finding.",
    );
  const rows = entries.map((value) => {
    const raw = requiredText(value, "Semgrep finding JSON");
    const finding = parseSemgrepResponse(raw);
    const selectable = checkSemgrepPlatformRow(
      finding,
      scope,
      aliases,
      repository,
      readId,
    );
    if (aliases) {
      const repo = record(
        finding["repository"] ?? {},
        "Semgrep finding repository",
      );
      const label = text(repo["name"]);
      if (label && (repo["id"] != null || text(repo["url"])))
        verifiedLabels.add(label);
    }
    return { finding, selectable };
  });
  if (aliases && !matchesNativeInteger(input["findingCount"], rows.length))
    throw new Error(
      "Incomplete Semgrep Platform export: finding count does not match.",
    );
  if (aliases) {
    // v1 also accepted decodeURI path labels. Keep a witness for their current-format replay.
    const archiveNames = legacy
      ? legacyProjectAliases(
          scope.project.name,
          scope.project.url,
          references,
          scope.sourceRepositoryUrl,
        )
      : projectNames;
    for (const { finding } of rows) {
      const name = repositoryWithOnlyAlias(finding, archiveNames);
      if (name && !verifiedLabels.has(name))
        throw new Error(
          "Semgrep finding repository lacks a matching project name, ID or URL.",
        );
    }
  }
  const unhintedNames = projectAliases(scope.project.name, scope.project.url);
  const result = normalizePlatformRows(
    rows,
    scope,
    target,
    aliases
      ? {
          legacy,
          projectNames: {
            has: (name) =>
              (verifiedLabels.has(name) ? unhintedNames : projectNames).has(
                name,
              ),
          },
        }
      : undefined,
    aliases ? readId : archivedPlatformId,
  );
  return {
    ...result,
    sourceFormat,
    sourceRepositoryUrl: scope.project.url,
    semgrepPlatformScope: {
      deployment: scope.deployment,
      projectId: scope.project.id,
      ref: scope.ref,
      product: scope.product,
    },
  };
}

export function stringifySemgrepFinding(
  finding: Record<string, unknown>,
  idOf: (id: unknown) => string | undefined = semgrepPlatformIdOrUndefined,
): string {
  const repo = finding["repository"];
  const nativeIds = [finding["id"], isRecord(repo) ? repo["id"] : undefined];
  return JSON.stringify(finding, (_key, value: unknown) => {
    if (wireJson.isRawJSON(value)) {
      const id = nativeIds.includes(value) ? idOf(value) : undefined;
      return wireJson.rawJSON(id ?? canonicalNumber(value.rawJSON));
    }
    if (isRecord(value))
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [key, value[key]]),
      );
    return value;
  });
}

function platformSourceData(
  finding: Record<string, unknown>,
  scope: ResolvedScope,
  selectable: boolean,
  bulk?: { legacy: boolean },
  namedOnly?: string | null,
  idOf = semgrepPlatformId,
) {
  const repo = record(
    finding["repository"] ?? {},
    "Semgrep finding repository",
  );
  const label = text(repo["name"]);
  // Ordinary v1 and v2 rows share one stored representation on replay.
  // Preserve the legacy discriminator only when reopening the raw IDs needs it.
  const { nativeProjectUrl, ...evidenceScope } = scope;
  const nativeBulkScope =
    !selectable ||
    scope.sourceRepositoryUrl !== undefined ||
    nativeProjectUrl !== undefined;
  const needsLegacyId =
    bulk?.legacy &&
    [finding["id"], repo["id"]].some(
      (id) =>
        typeof id === "string" &&
        semgrepPlatformIdOrUndefined(id) === undefined,
    );
  // Native SAST rows with their own repository and ref replay identically in either import mode.
  const needsBulkScope = bulk && (nativeBulkScope || needsLegacyId);
  return {
    format: needsLegacyId
      ? semgrepPlatformLegacyFormat
      : needsBulkScope
        ? semgrepPlatformFormat
        : semgrepSelectionFormat,
    ...evidenceScope,
    project: {
      ...scope.project,
      url:
        nativeProjectUrl ??
        (scope.sourceRepositoryUrl ? null : scope.project.url),
    },
    ...(needsLegacyId && { idEncoding: "v1-decimal" }),
    ...(needsBulkScope && { repositoryAliases: label ? [label] : [] }),
    // Store the verified binding independently of the native fields retained on its proving row.
    ...(namedOnly && {
      repositoryWitnessJson: JSON.stringify({
        id: scope.project.id,
        name: namedOnly,
      }),
    }),
    semgrepPlatformFindingJson: stringifySemgrepFinding(finding, idOf),
  };
}

// Selected rows and complete captures share their evidence projection and identity tuple.
function normalizePlatformRows(
  rows: { finding: Record<string, unknown>; selectable: boolean }[],
  scope: ResolvedScope,
  target: ExternalImportTarget,
  bulk?: {
    legacy: boolean;
    projectNames: Pick<ReadonlySet<string>, "has">;
  },
  readId = bulk?.legacy ? semgrepV1Id : semgrepPlatformId,
) {
  const legacy = bulk?.legacy;
  return normalizeRecords(
    rows,
    ({ finding, selectable }) => {
      const rule = responseRecord(finding["rule"] ?? {}, "Semgrep rule");
      const name = text(rule["name"]) ?? text(finding["rule_name"]);
      const description =
        text(rule["message"]) ?? text(finding["rule_message"]);
      const location = responseRecord(
        finding["location"] ?? {},
        "Semgrep location",
      );
      const path = platformLocationPath(location["file_path"]);
      // The object-row reader never checked lines for paths it did not project.
      const coerceBulkLines =
        !!bulk &&
        (legacy ? !hostedRepositoryPath(location["file_path"]) : !selectable);
      const startLine = path
        ? sourceLine(location["line"], coerceBulkLines)
        : null;
      const namedOnly =
        bulk && repositoryWithOnlyAlias(finding, bulk.projectNames);
      const common = {
        description,
        severity: platformSeverity(finding["severity"], selectable),
        locations: path ? [{ path, line: startLine }] : [],
        branch: scope.ref,
        source_data: platformSourceData(
          finding,
          scope,
          selectable,
          bulk,
          namedOnly,
          readId,
        ),
      };
      const messageTitle =
        description ??
        (legacy || scope.product === "sast"
          ? null
          : `Semgrep finding ${readId(finding["id"])}`);
      if (scope.product === "sca") {
        const dependency = responseRecord(
          finding["found_dependency"] ?? {},
          "Semgrep found dependency",
        );
        const packages = [];
        if (dependency["package"] !== undefined) {
          const name = requiredText(
            dependency["package"],
            "Semgrep package name",
          );
          const fixes = array(
            finding["fix_recommendations"] ?? [],
            "Semgrep fix recommendations",
          );
          packages.push({
            name,
            ecosystem: text(dependency["ecosystem"]),
            installed_version: text(dependency["version"]),
            fixed_versions: strings(
              fixes.flatMap((fix) =>
                isRecord(fix) && fix["package"] === name
                  ? [fix["version"]]
                  : [],
              ),
            ),
          });
        }
        const advisory = text(finding["vulnerability_identifier"]);
        return validateExternalEvidence(
          {
            ...common,
            title: requiredText(
              name ?? advisory ?? packages[0]?.name ?? messageTitle,
              "Semgrep finding title",
            ),
            advisory_ids: advisory ? [advisory] : [],
            packages,
          },
          target,
        );
      }
      return validateExternalEvidence(
        {
          ...common,
          title: requiredText(name ?? messageTitle, "Semgrep finding title"),
          details: {
            kind: "sast",
            repository: { url: scope.project.url },
            scanner_origin: "Semgrep",
            rule: name ? { id: name } : null,
            source_status: text(finding["status"]),
            weakness_ids: weaknessIds(rule["cwe_names"]),
            code: {
              end_line:
                startLine !== null
                  ? sourceLine(location["end_line"], coerceBulkLines)
                  : null,
            },
          },
        },
        target,
      );
    },
    ({ finding }) => sourceId(scope, finding, readId),
    target,
  );
}
