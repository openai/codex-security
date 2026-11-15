import {
  DEFAULT_CLOUD_STRING_BYTES,
  canonicalNumber,
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
import { isGitHubCloudHost } from "./git-remote.js";
import { position, weaknessIds } from "./native-json-findings.js";
import {
  array,
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
  hostedNumberToken,
  hostedNativeRepositoryUrl,
  hostedRepositoryUrl,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";
import {
  declaredScannerRepositoryUrl,
  validScannerRepositoryUrl,
} from "./scanner-repository-url.js";
import type { SemgrepImportOptions } from "./semgrep-findings.js";

export const semgrepPlatformFormat = "semgrep-platform-findings/v2";
export const SEMGREP_PLATFORM_PRODUCTS = ["sast", "sca", "ai_sast"] as const;
export type SemgrepPlatformProduct = (typeof SEMGREP_PLATFORM_PRODUCTS)[number];
export const semgrepSelectionFormat = "semgrep-platform-selection/v1";

export function isSemgrepPlatformFormat(
  format: unknown,
): format is typeof semgrepSelectionFormat | typeof semgrepPlatformFormat {
  return format === semgrepSelectionFormat || format === semgrepPlatformFormat;
}

function selectedProjectUrl(value: unknown, label: string) {
  return declaredScannerRepositoryUrl(value, label, "local");
}

/** Recover the native collection scope, including when every row was excluded. */
export function semgrepPlatformReportScope(
  input: ExternalFindings,
  provider?: string,
  references: readonly ExternalSourceRepository[] = [],
) {
  const format = "sourceFormat" in input ? input.sourceFormat : undefined;
  if (
    "semgrepPlatformScope" in input &&
    input.semgrepPlatformScope !== undefined &&
    !isSemgrepPlatformFormat(format)
  )
    throw new Error(
      "A normalized Semgrep Platform report scope requires its source format.",
    );
  if (!isSemgrepPlatformFormat(format)) {
    if (
      provider === "semgrep" &&
      typeof format === "string" &&
      format.startsWith("semgrep-platform-")
    )
      throw new Error(
        "Unsupported Semgrep Platform format. Recollect the findings.",
      );
    return;
  }
  const scope = record(
    "semgrepPlatformScope" in input ? input.semgrepPlatformScope : undefined,
    "Normalized Semgrep report scope",
  );
  const readUrl =
    format === semgrepSelectionFormat
      ? selectedProjectUrl
      : hostedRepositoryUrl;
  const url = readUrl(
    "sourceRepositoryUrl" in input ? input.sourceRepositoryUrl : undefined,
    "Semgrep Platform",
  );
  if (format !== semgrepSelectionFormat && references.length)
    selectionRepository(url, references);

  return {
    format,
    deployment: requiredText(scope["deployment"], "Semgrep deployment"),
    projectId: savedPlatformId(
      requiredText(scope["projectId"], "Semgrep project ID"),
    ),
    ref: requiredText(scope["ref"], "Semgrep ref"),
    product: scopeProduct(scope["product"], format !== semgrepSelectionFormat),
    url,
  };
}

export function semgrepPlatformReportRepository(input: ExternalFindings) {
  return semgrepPlatformReportScope(input)?.url;
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

// These v1 Findings API response fields belong only to AI detections or Supply Chain.
const nonSastFields = [
  "ai_impact",
  "epss_score",
  "fix_recommendations",
  "found_dependency",
  "is_malicious",
  "reachability",
  "reachable_condition",
  "usage",
  "vulnerability_identifier",
];

function identifiesNonSastProduct(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    nonSastFields.some((field) => value[field] != null) ||
    [value["issue_type"], value["product"]].some(
      (product) =>
        typeof product === "string" &&
        /^(?:sca|ai_sast|secrets)$/iu.test(product),
    )
  );
}

// Node 22 supports JSON source text and raw values. The SDK targets the ES2022 type library.
const wireJson = JSON as JSON & {
  rawJSON(source: string): { rawJSON: string };
  isRawJSON(value: unknown): value is { rawJSON: string };
};

function sourceLine(value: unknown, coerceStrings: boolean): number | null {
  if (value == null) return null;
  const token = hostedNumberToken(value);
  // A long fraction can round to an integer if it is converted before checking its decimal value.
  if (token !== undefined)
    return position(
      Number(semgrepPlatformIdOrUndefined(wireJson.rawJSON(token))),
      "Semgrep source line",
    );
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
  return {
    has: (label: string) =>
      label === name || label === shortName || pathKeys.has(key(label)),
  };
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
  if (
    typeof value === "string" &&
    value.trim() === value &&
    typeof references !== "function" &&
    references.length
  ) {
    // Derive only a candidate from the native SSH spelling. The reader's Git fetch address must match.
    const candidate = normalizeHostedGitRepositoryUrl(value, undefined, true);
    if (
      candidate !== value &&
      references.some(
        ({ platform, url }) =>
          (platform === "github" || platform === "gitlab") &&
          semgrepReferenceMatches({ url: candidate, platform }, url),
      )
    )
      return hostedRepositoryUrl(candidate, label);
  }
  return hostedNativeRepositoryUrl(value, label);
}

function repositoryContext(
  projectUrl: string,
  references: SemgrepRepositoryReference = [],
  target: ExternalImportTarget = "local",
) {
  const source = semgrepPlatformRepositoryReference(
    projectUrl,
    typeof references === "function" ? [] : references,
  );
  const github = source.platform === "github";
  return {
    source,
    selectableProject: validScannerRepositoryUrl(projectUrl, "local"),
    key: (url: string) =>
      typeof references === "function"
        ? references(nativeHttp(url))
        : hostedRepositoryUrlKey(
            target === "cloud" ? url : nativeHttp(url),
            github,
            source.platform === "gitlab",
            target,
          ),
    name: (name: string) => (github ? name.toLowerCase() : name),
  };
}

export function selectionRepository(
  projectUrl: string,
  references: readonly ExternalSourceRepository[] = [],
  target: ExternalImportTarget = "local",
) {
  const repository = repositoryContext(projectUrl, references, target);
  if (
    !references.every(({ url }) => {
      if (target === "local")
        return semgrepReferenceMatches(repository.source, url);
      const mapped = normalizeHostedGitRepositoryUrl(
        url,
        projectUrl,
        repository.source.platform !== undefined,
      );
      return repository.key(mapped) === repository.key(projectUrl);
    })
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

function hasSemgrepScaEvidence(finding: Record<string, unknown>): boolean {
  return (
    finding["found_dependency"] != null ||
    finding["vulnerability_identifier"] != null
  );
}

/** Complete reports record the repository labels returned by the project-ID-scoped request. */
export function checkSemgrepPlatformRow(
  finding: Record<string, unknown>,
  scope: ResolvedScope,
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
  const hasUrl = repo["url"] != null && (!aliases || repo["url"] !== "");
  const name = repo["name"];
  const encodedPath = new URL(scope.project.url).pathname.replace(
    /^\/|\/$/gu,
    "",
  );
  const decodedPath = decodeURIComponent(encodedPath);
  // Archived captures may retain the encoded path spelling as their repository name.
  const matchesQualifiedName = (normalize: typeof repository.name) => {
    const label = typeof name === "string" ? normalize(name) : null;
    return (
      !!label?.includes("/") &&
      (label === normalize(decodedPath) ||
        (!capture && label === normalize(encodedPath)))
    );
  };
  const selectionRepositoryMatches =
    hasUrl ||
    (repo["url"] == null &&
      repositoryId !== undefined &&
      matchesQualifiedName(repository.name));
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
    (scope.product === "sast" &&
      !capture &&
      identifiesNonSastProduct(finding)) ||
    (scope.product === "ai_sast" && hasSemgrepScaEvidence(finding))
  )
    throw new Error("Select Semgrep Code (SAST) findings.");
  return (
    scope.product === "sast" &&
    repository.selectableProject &&
    // A replayable selection requires a repository on the native project response.
    (scope.sourceRepositoryUrl === undefined ||
      scope.nativeProjectUrl !== undefined) &&
    finding["ref"] === scope.ref &&
    selectionRepositoryMatches &&
    [finding["id"], repo["id"]].every(
      (id) => id == null || semgrepPlatformIdOrUndefined(id) !== undefined,
    ) &&
    // Before a reader hint promotes a backlog row, check its complete selected projection.
    (!aliases ||
      hasUrl ||
      matchesQualifiedName(repositoryContext(scope.project.url).name) ||
      normalizePlatformRows([{ finding, selectable: true }], scope, "local")
        .excluded.length === 0)
  );
}

interface SemgrepSelectionInput {
  deployment: string;
  ref: string;
  projectResponse: string;
  findingsResponses: Iterable<string>;
  findingIds: readonly string[];
}

export function requireSemgrepFullRef(ref: string) {
  // git-check-ref-format distinguishes literal branch/tag names from revision expressions.
  const refParts = ref.split("/");
  if (
    refParts[0] !== "refs" ||
    refParts.length < 2 ||
    refParts.some(
      (part) => !part || part.startsWith(".") || part.endsWith(".lock"),
    ) ||
    ref.endsWith(".") ||
    ref.includes("..") ||
    ref.includes("@{") ||
    /[\u0000-\u0020\u007f~^:?*\[\\]/u.test(ref)
  )
    throw new Error(
      "Use a fully qualified Semgrep ref such as refs/heads/topic.",
    );
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
    selectedProjectUrl,
  );
  requireSemgrepFullRef(scope.ref);
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
    const findings = array(
      parseSemgrepResponse(page)["findings"],
      "Semgrep findings",
    );
    const previousCount = selected.size;
    for (const finding of findings) {
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
    // The v1 findings endpoint returns a single product per response page.
    if (
      selected.size !== previousCount &&
      findings.some(identifiesNonSastProduct)
    )
      throw new Error("Select Semgrep Code (SAST) findings.");
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
) {
  const url = hostedRepositoryUrl(options.sourceRepositoryUrl, "Semgrep");
  const { scope, rows } = selectedRows(
    options,
    (scope) => {
      if (scope.project.url !== url)
        throw new Error(
          "Selected Semgrep project does not match the operator's source repository URL.",
        );
      const exact = (value: string) => value;
      return {
        source: { url },
        selectableProject: true,
        key: exact,
        name: exact,
      };
    },
    hostedRepositoryUrl,
  );
  return {
    ...normalizePlatformRows(
      rows.map((finding) => ({ finding, selectable: true })),
      scope,
      "local",
    ),
    ...reportScope(semgrepSelectionFormat, scope),
  };
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
    exact(semgrepPlatformId(wireJson.rawJSON(scope.project.id))),
    scope.product,
    scope.ref,
    exact(semgrepPlatformId(finding["id"])),
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
  target: ExternalImportTarget = "local",
) {
  const complete = input["format"] === semgrepPlatformFormat;
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
    const key = native && repositoryContext(native, references, target).key;
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
      complete ? hostedRepositoryUrl : selectedProjectUrl,
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
    : canonicalNumber(token) === String(expected);
}

const generatedId = /^semgrep-platform:[0-9a-f]{64}$/u;
/** Recognize reserved Platform IDs and native scope before accepting normalized evidence. */
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

function nativeOccurrence(
  data: Record<string, unknown>,
  references: SemgrepRepositoryReference,
  target: ExternalImportTarget,
) {
  if (!isSemgrepPlatformFormat(data["format"]))
    throw new Error(
      "Unsupported Semgrep finding format. Recollect the Platform findings.",
    );
  const { scope, aliases } = readScope(data, references, target);
  const repository = repositoryContext(scope.project.url, references, target);
  const row = parseSemgrepResponse(
    requiredText(data["semgrepPlatformFindingJson"], "Semgrep finding JSON"),
  );
  return { scope, aliases, repository, row };
}

/** Reproduce the native Cloud title fallback for an unmodified Platform message title. */
export function storedSemgrepCloudEvidence(
  finding: ExternalFinding,
  references: readonly ExternalSourceRepository[] = [],
): ExternalFinding["evidence"] | undefined {
  const { evidence } = finding;
  if (
    evidence.title !== evidence.description ||
    Buffer.byteLength(evidence.title) <= DEFAULT_CLOUD_STRING_BYTES ||
    !evidence.source_data ||
    !isSemgrepPlatformEvidence(finding, "semgrep")
  )
    return;
  const { row, scope, aliases, repository } = nativeOccurrence(
    evidence.source_data,
    references,
    "local",
  );
  if (sourceId(scope, row) !== finding.source_finding_id) return;
  const selectable = checkSemgrepPlatformRow(row, scope, aliases, repository);
  const projectNames =
    aliases &&
    projectAliases(scope.project.name, scope.project.url, references);
  const title = (target: ExternalImportTarget) =>
    normalizePlatformRows(
      [{ finding: row, selectable }],
      scope,
      target,
      projectNames,
    ).findings[0]?.evidence.title;
  if (title("local") !== evidence.title) return;
  const cloud = title("cloud");
  if (cloud && cloud !== evidence.title) return { ...evidence, title: cloud };
}

/** Recheck the source repository when an SDK caller supplies normalized evidence directly. */
export function semgrepPlatformFindingRepository(
  finding: ExternalFinding,
  provider: string,
  references: SemgrepRepositoryReference = [],
): string | undefined {
  return semgrepPlatformFindingBinding(finding, provider, references)?.url;
}

export function platformLocationPath(value: unknown) {
  const path = text(value);
  const relative = relativePath(path);
  return relative && !relative.endsWith("/.") && repositoryFilePath(relative)
    ? path
    : null;
}

function platformLocation(
  location: Record<string, unknown>,
  product: SemgrepPlatformScope["product"],
  coerceStrings: boolean,
) {
  const path = platformLocationPath(location["file_path"]);
  if (!path) return { locations: [], endLine: null };
  const line = sourceLine(location["line"], coerceStrings);
  const endLine =
    line !== null && product !== "sca"
      ? sourceLine(location["end_line"], coerceStrings)
      : null;
  return { locations: [{ path, line }], endLine };
}

function platformSeverity(
  value: unknown,
  selectable: boolean,
): ExternalFinding["evidence"]["severity"] {
  const severity = text(value)?.toLowerCase();
  return scannerSeverity(
    selectable && severity === "informational" ? null : severity,
  );
}

function qualifiedBranch(ref: string) {
  return ref.startsWith("refs/") ? ref : `refs/heads/${ref}`;
}

function checkProjectedProduct(
  finding: ExternalFinding,
  product?: SemgrepPlatformProduct,
  native = false,
) {
  const kind = finding.evidence.details?.kind;
  if (
    (product === "sca" && kind === "sast") ||
    (native && (kind === "secret" || kind === "iac"))
  )
    throw new Error(
      "The projected finding kind does not match the Semgrep report product.",
    );
}

/** A marked report reserves the v1 finding's repository, ref and product for Semgrep scope. */
export function hasRetainedSemgrepScope(finding: unknown): boolean {
  if (!isRecord(finding)) return false;
  const repository = finding["repository"];
  if (
    finding["ref"] !== undefined ||
    hasSemgrepScaEvidence(finding) ||
    (isRecord(repository) &&
      (repository["id"] != null ||
        !!text(repository["url"]) ||
        !!text(repository["name"])))
  )
    return true;
  return [finding["product"], finding["issue_type"]].some((value) => {
    if (typeof value !== "string") return false;
    const product = value.toLowerCase();
    return (
      product === "code" ||
      SEMGREP_PLATFORM_PRODUCTS.some((known) => known === product)
    );
  });
}

export function semgrepPlatformFindingBinding(
  finding: ExternalFinding,
  provider: string,
  references: SemgrepRepositoryReference = [],
  reportScope?: ReturnType<typeof semgrepPlatformReportScope>,
  projectedSources: readonly (
    { url?: string; branch?: string } | undefined
  )[] = [],
  target: ExternalImportTarget = "local",
) {
  const retained = finding.evidence.source_data;
  if (!isSemgrepPlatformEvidence(finding, provider)) {
    if (
      provider === "semgrep" &&
      reportScope?.format !== undefined &&
      hasRetainedSemgrepScope(retained?.["finding"])
    )
      throw new Error(
        "Retained Semgrep finding scope requires the original collection scope in a marked Platform report.",
      );
    if (reportScope && reportScope.format !== semgrepSelectionFormat) {
      const source = repositoryContext(reportScope.url, references).source;
      const claims = [
        {
          url: finding.evidence.details?.repository?.url,
          branch: finding.evidence.branch,
        },
        ...projectedSources,
      ];
      if (
        claims.some(
          (claim) => claim?.url && !semgrepReferenceMatches(source, claim.url),
        )
      )
        throw new Error(
          "The projected repository does not match the Semgrep report repository.",
        );
      const ref = reportScope.ref && qualifiedBranch(reportScope.ref);
      if (
        ref &&
        claims.some(
          (claim) => claim?.branch && qualifiedBranch(claim.branch) !== ref,
        )
      )
        throw new Error(
          "The projected branch does not match the Semgrep report ref.",
        );
      checkProjectedProduct(finding, reportScope.product);
    }
    return;
  }
  if (!retained)
    throw new Error("Missing the original Semgrep finding evidence.");
  const { scope, aliases, repository, row } = nativeOccurrence(
    retained,
    references,
    target,
  );
  checkProjectedProduct(finding, scope.product, true);
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

  const other = retained["finding"];
  if (isRecord(other) && Object.hasOwn(other, "id")) {
    const original = parseSemgrepResponse(JSON.stringify(other));
    if (
      semgrepPlatformIdOrUndefined(original["id"]) !== undefined &&
      stringifySemgrepFinding(original) !== stringifySemgrepFinding(row)
    )
      throw new Error("The retained Semgrep finding representations disagree.");
  }
  const selectable = checkSemgrepPlatformRow(row, scope, aliases, repository);
  if (reportScope?.format === semgrepSelectionFormat && !selectable)
    throw new Error(
      "Semgrep finding does not belong to the selected project and ref.",
    );
  const nativeId = sourceId(scope, row);
  if (
    generatedId.test(finding.source_finding_id) &&
    finding.source_finding_id !== nativeId
  )
    throw new Error(
      "The generated Semgrep finding ID does not match its native occurrence.",
    );
  const { name, url } = scope.project;
  let namedOnly =
    aliases && repositoryWithOnlyAlias(row, projectAliases(name, url));
  const raw = retained["repositoryWitnessJson"];
  // Only rely on the reader's platform hint when there is no independent proof.
  if (
    namedOnly &&
    raw === undefined &&
    projectAliases(name, url, references).has(namedOnly)
  )
    namedOnly = undefined;
  if (raw !== undefined || namedOnly) {
    const label = text(
      record(row["repository"], "Semgrep finding repository")["name"],
    );
    const witness = parseSemgrepResponse(
      requiredText(raw, "Semgrep repository alias witness"),
    );
    if (
      !label ||
      witness["name"] !== label ||
      (witness["id"] == null && !text(witness["url"]))
    )
      throw new Error(
        "Semgrep repository alias lacks a matching project ID or URL.",
      );
    checkSemgrepPlatformRow(
      { repository: witness },
      scope,
      aliases ?? new Set([label]),
      repository,
      (id) => semgrepPlatformId(wireJson.rawJSON(savedPlatformId(id))),
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
    aliases !== undefined,
    namedOnly,
  );
  const {
    repositoryAliases: _aliases,
    repositoryWitnessJson: _witness,
    nativeProjectUrl: _native,
    ...metadata
  } = retained;
  const selectedSeverity = platformSeverity(row["severity"], true);
  const previousSeverity = platformSeverity(row["severity"], false);
  return {
    url,
    nativeId,
    // A reader-provided repository binding can promote a backlog row to a selected SAST row.
    migration:
      retained["format"] === semgrepPlatformFormat &&
      canonical.format === semgrepSelectionFormat &&
      finding.evidence.severity === previousSeverity &&
      previousSeverity !== selectedSeverity
        ? { severity: selectedSeverity }
        : undefined,
    sourceData: {
      ...metadata,
      ...canonical,
      project: {
        ...record(retained["project"], "Semgrep project"),
        ...canonical.project,
      },
    },
  };
}

/** Normalize a saved selection or Platform project export. The default target is local. */
export function normalizeSemgrepPlatformFindings(
  report: unknown,
  options: string | Partial<SemgrepImportOptions> = {},
  target: ExternalImportTarget = "local",
  references: readonly ExternalSourceRepository[] = typeof options === "object"
    ? (options.sourceRepositories ?? [])
    : [],
) {
  const declaredUrl =
    typeof options === "string" ? options : options.sourceRepositoryUrl;
  const input = record(report, "Semgrep Platform report");
  const sourceFormat = input["format"];
  if (!isSemgrepPlatformFormat(sourceFormat))
    throw new Error("Expected a Semgrep Platform selection or project export.");
  const { scope, aliases } = readScope(input, references, target);
  const repository = selectionRepository(scope.project.url, references, target);
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
    for (const { finding } of rows) {
      const name = repositoryWithOnlyAlias(finding, projectNames);
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
    aliases && {
      has: (name) =>
        (verifiedLabels.has(name) ? unhintedNames : projectNames).has(name),
    },
  );
  return { ...result, ...reportScope(sourceFormat, scope) };
}

function reportScope(
  sourceFormat: typeof semgrepSelectionFormat | typeof semgrepPlatformFormat,
  scope: SemgrepPlatformScope,
) {
  return {
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
): string {
  const repo = finding["repository"];
  const nativeIds = [finding["id"], isRecord(repo) ? repo["id"] : undefined];
  return JSON.stringify(finding, (_key, value: unknown) => {
    if (wireJson.isRawJSON(value)) {
      const id = nativeIds.includes(value)
        ? semgrepPlatformIdOrUndefined(value)
        : undefined;
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
  bulk: boolean,
  namedOnly?: string | null,
) {
  const repo = record(
    finding["repository"] ?? {},
    "Semgrep finding repository",
  );
  const label = text(repo["name"]);
  const { nativeProjectUrl, ...evidenceScope } = scope;
  const nativeBulkScope =
    !selectable ||
    scope.sourceRepositoryUrl !== undefined ||
    nativeProjectUrl !== undefined;
  const needsBulkScope = bulk && nativeBulkScope;
  return {
    format: needsBulkScope ? semgrepPlatformFormat : semgrepSelectionFormat,
    ...evidenceScope,
    project: {
      ...scope.project,
      url:
        nativeProjectUrl ??
        (scope.sourceRepositoryUrl ? null : scope.project.url),
    },
    ...(needsBulkScope && { repositoryAliases: label ? [label] : [] }),
    // Store the verified binding independently of the native fields retained on its proving row.
    ...(namedOnly && {
      repositoryWitnessJson: JSON.stringify({
        id: scope.project.id,
        name: namedOnly,
      }),
    }),
    semgrepPlatformFindingJson: stringifySemgrepFinding(finding),
  };
}

// Selected rows and complete captures share their evidence projection and identity tuple.
function normalizePlatformRows(
  rows: { finding: Record<string, unknown>; selectable: boolean }[],
  scope: ResolvedScope,
  target: ExternalImportTarget,
  projectNames?: Pick<ReadonlySet<string>, "has">,
) {
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
      const { locations, endLine } = platformLocation(
        location,
        scope.product,
        !!projectNames && !selectable,
      );
      const namedOnly =
        projectNames && repositoryWithOnlyAlias(finding, projectNames);
      const common = {
        description,
        severity: platformSeverity(finding["severity"], selectable),
        locations,
        branch: scope.ref,
        source_data: platformSourceData(
          finding,
          scope,
          selectable,
          projectNames !== undefined,
          namedOnly,
        ),
      };
      let messageTitle =
        description ??
        (scope.product === "sast"
          ? null
          : `Semgrep finding ${semgrepPlatformId(finding["id"])}`);
      if (
        target === "cloud" &&
        description &&
        Buffer.byteLength(description) > DEFAULT_CLOUD_STRING_BYTES
      ) {
        const id = finding["id"];
        messageTitle = `Semgrep finding ${text(id) ?? semgrepPlatformId(id)}`;
      }
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
            code: { end_line: endLine },
          },
        },
        target,
      );
    },
    ({ finding }) => sourceId(scope, finding),
    target,
  );
}
