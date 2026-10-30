import { posix } from "node:path";
import { z } from "zod";
import validSemver from "semver/functions/valid.js";
import type {
  ExternalFinding,
  ExternalFindings,
  ExternalSourceRepository,
} from "./external-findings.js";
import {
  cloudRepositoryUrlKey,
  repositoryUrlKey,
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import { isGitHubCloudHost } from "./git-remote.js";
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { Provider } from "./external-import-models.js";
import { isRecord } from "./record.js";
import {
  normalizeRecords,
  readScannerJson,
  record,
  relativePath,
  requiredText,
  text,
} from "./scanner-import.js";

type Native = Record<string, unknown>;

const listFindings = z.strictObject({ findings: z.array(z.unknown()) });
const format = "aws-inspector2-list-findings/v1";
const findingArn =
  /^(arn:(aws[a-zA-Z-]*):inspector2:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12})):finding\/[a-f0-9]{32}$/u;
const integrationArn =
  /^arn:aws[a-zA-Z-]*:inspector2:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:codesecurity-integration\/[a-f0-9-]{36}$/u;
const projectSuffix =
  /^project-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/u;
const absoluteUrl = /^[a-z][a-z\d+.-]*:\/\//iu;

function repositoryUrl(value: unknown): string {
  const raw = requiredText(value, "Inspector --source-repository-url");
  const url = URL.parse(raw);
  const path = /^https?:\/\/[^/?#]+(\/[^?#]+)$/iu.exec(raw)?.[1];
  if (
    !url ||
    !path ||
    url.username ||
    url.password ||
    /[\s\\?#]|%(?:2f|5c)/iu.test(raw) ||
    path !== url.pathname ||
    !/^\/[^/]+(?:\/[^/]+)+\/?$/u.test(path)
  )
    throw new Error(
      "Use a complete HTTP(S) Inspector source repository URL with a namespace and repository, without credentials, query or fragment.",
    );
  return raw;
}

function projectIntegration(projectArn: string): string {
  const separator = projectArn.lastIndexOf("/");
  const parent = projectArn.slice(0, separator);
  if (
    !integrationArn.test(parent) ||
    !projectSuffix.test(projectArn.slice(separator + 1))
  )
    throw new Error("Expected a full Inspector repository project ARN.");
  return parent;
}

/** @internal Validate an operator-supplied project binding. */
export function validateInspectorProjectMapping(
  projectArn: string,
  canonicalUrl: unknown,
): string {
  projectIntegration(projectArn);
  return repositoryUrl(canonicalUrl);
}

function identity(finding: Native) {
  const arn = requiredText(finding["findingArn"], "Inspector finding ARN");
  const match = findingArn.exec(arn);
  if (!match) throw new Error("Expected an Inspector2 finding ARN.");
  if (finding["awsAccountId"] !== match[4])
    throw new Error("Inspector finding ARN and AWS account do not match.");
  return {
    arn,
    issuer: match[1]!,
    partition: match[2]!,
    region: match[3]!,
    account: match[4]!,
  };
}

function repositoryClaim(
  { issuer, partition, region, account }: ReturnType<typeof identity>,
  resource: Native,
) {
  for (const [field, expected] of Object.entries({
    partition,
    region,
    provider: "AWS",
    providerAccountId: account,
  })) {
    if (resource[field] !== undefined && resource[field] !== expected)
      throw new Error(
        "Inspector repository resource and finding scope do not match.",
      );
  }
  const { codeRepository } = record(
    resource["details"] ?? {},
    "Inspector resource details",
  );
  const repo = record(codeRepository ?? {}, "Inspector codeRepository");
  const optional = (field: string) =>
    repo[field] === undefined
      ? undefined
      : requiredText(repo[field], `Inspector codeRepository.${field}`);
  const nativeId = requiredText(
    resource["id"],
    "Inspector repository resource ID",
  );
  let integration = optional("integrationArn");
  if (
    integration !== undefined &&
    (!integration.startsWith(issuer + ":") || !integrationArn.test(integration))
  )
    throw new Error(
      "Inspector integration ARN does not match the finding scope.",
    );
  if (nativeId.startsWith("arn:")) {
    const parent = projectIntegration(nativeId);
    if (
      !parent.startsWith(issuer + ":") ||
      (integration !== undefined && parent !== integration)
    )
      throw new Error(
        "Inspector repository resource ARN does not match its project or integration.",
      );
    integration = parent;
  }
  return {
    project: JSON.stringify([issuer, nativeId]),
    integration,
    provider: optional("providerType"),
    nativeId,
    name: optional("projectName"),
  };
}

function checkRepositoryMapping(
  { nativeId, name }: ReturnType<typeof repositoryClaim>,
  source: string,
  provider: string | undefined,
  target: ExternalImportTarget,
  projectMap?: ReadonlyMap<string, string>,
) {
  const hostname = new URL(source).hostname;
  const knownGitHub = isGitHubCloudHost(hostname);
  const gitlab = provider === "GITLAB_SELF_MANAGED";
  const github = provider === "GITHUB" || knownGitHub;
  if (
    hostname === "gitlab.com" ||
    (gitlab && knownGitHub) ||
    (provider !== undefined && !gitlab && provider !== "GITHUB")
  )
    throw new Error(
      "Inspector repository provider does not match the selected mapping.",
    );
  if (target === "cloud" && !github)
    throw new Error(
      "Inspector Cloud requires a GitHub repository provider; self-managed GitLab is local only.",
    );
  const urls = [nativeId, name].filter(
    (url): url is string => !!url && absoluteUrl.test(url),
  );
  const key = github && !projectMap ? cloudRepositoryUrlKey : repositoryUrlKey;
  const path = new URL(
    (github ? cloudRepositoryUrlKey : repositoryUrlKey)(source),
  ).pathname.slice(1);
  const slug = github ? name?.toLowerCase() : name;
  const matchesSlug =
    !slug ||
    absoluteUrl.test(slug) ||
    slug === path ||
    slug === posix.basename(path) ||
    (gitlab && projectMap && path.endsWith("/" + slug));
  if (
    !matchesSlug ||
    urls.some((url) => key(repositoryUrl(url)) !== key(source))
  )
    throw new Error(
      "Inspector native repository does not match --source-repository-url.",
    );
  if (projectMap) {
    // repositoryClaim validated this ARN and its issuer before the lookup.
    const trustedUrl = nativeId.startsWith("arn:")
      ? projectMap.get(nativeId)
      : undefined;
    if (trustedUrl === undefined)
      throw new Error(
        "Inspector project ARN is missing from the trusted mapping.",
      );
    if (
      repositoryUrlKey(repositoryUrl(trustedUrl)) !== repositoryUrlKey(source)
    )
      throw new Error(
        "Inspector project ARN mapping does not match the source repository URL.",
      );
    return true;
  }
  return urls.length > 0;
}

function repositoryClaims(finding: unknown) {
  if (!isRecord(finding) || !Array.isArray(finding["resources"])) return [];
  const claims = [];
  let origin: ReturnType<typeof identity> | undefined;
  for (const resource of finding["resources"]) {
    if (!isRecord(resource) || resource["type"] !== "CODE_REPOSITORY") continue;
    origin ??= identity(finding);
    claims.push(repositoryClaim(origin, resource));
  }
  return claims;
}

/** Claims from the whole export must identify one project, including excluded rows. */
function checkReportScope<
  T extends { claims: ReturnType<typeof repositoryClaims>; source: string },
>(
  rows: readonly T[],
  target: ExternalImportTarget,
  projectMap?: ReadonlyMap<string, string>,
  exclude: (row: T, error: unknown) => void = (_, error) => {
    throw error;
  },
): string | undefined {
  const claims = rows.flatMap((row) => row.claims);
  function shared(field: "project" | "integration" | "provider") {
    const values = new Set(claims.map((claim) => claim[field]));
    values.delete(undefined);
    if (values.size > 1)
      throw new Error(
        "Inspector export identifies more than one repository project or integration.",
      );
    return values.values().next().value;
  }
  shared("project");
  shared("integration");
  const provider = shared("provider");
  type Claim = ReturnType<typeof repositoryClaim>;
  // A bare project ID can recur across integrations in the same account and Region.
  const sharedProvider = claims.find(
    (claim) => claim.integration && claim.provider,
  )?.provider;
  const providerFor = (claim: Claim) =>
    claim.provider ?? (claim.integration ? sharedProvider : undefined);
  const missingHost = () =>
    new Error(
      "Inspector needs a matching native repository URL or a trusted project ARN mapping to identify the Git host.",
    );
  const needHost = [];
  let sharedHost = false;
  for (const row of rows) {
    try {
      // Only a fully verified row can supply evidence to another row.
      const scopedMatches = row.claims.flatMap((claim) => {
        const proven = checkRepositoryMapping(
          claim,
          row.source,
          providerFor(claim),
          target,
          projectMap,
        );
        if (claim.integration) return [proven];
        if (!proven) throw missingHost();
        return [];
      });
      if (scopedMatches.includes(true)) sharedHost = true;
      else if (scopedMatches.length) needHost.push(row);
    } catch (error) {
      exclude(row, error);
    }
  }
  if (!sharedHost) for (const row of needHost) exclude(row, missingHost());
  return claims.every((claim) => providerFor(claim) === provider)
    ? provider
    : undefined;
}

const nonempty = z.string().regex(/\S/u, "Expected nonempty text.");
const optionalValue = z.unknown().optional();
const absent = z.never().optional();
const vulnerablePackage = z.object({
  name: nonempty,
  version: nonempty,
  packageManager: optionalValue,
  epoch: optionalValue,
  release: optionalValue,
  fixedInVersion: optionalValue,
  filePath: optionalValue,
  sourceLayerHash: absent,
  sourceLambdaLayerArn: absent,
});
const repositoryFinding = z.object({
  type: z.enum(["PACKAGE_VULNERABILITY", "CODE_VULNERABILITY"]),
  resources: z
    .array(
      z.object({
        type: z.literal("CODE_REPOSITORY"),
        details: z.strictObject({ codeRepository: optionalValue }).nullish(),
      }),
    )
    .min(1),
  networkReachabilityDetails: absent,
  packageVulnerabilityDetails: z
    .object({
      vulnerabilityId: nonempty,
      source: nonempty,
      sourceUrl: optionalValue,
      relatedVulnerabilities: z.array(nonempty).nullish(),
      vulnerablePackages: z.array(vulnerablePackage).nullish(),
    })
    .optional(),
  codeVulnerabilityDetails: z
    .object({
      detectorName: nonempty,
      detectorId: nonempty,
      cwes: z.array(z.unknown()),
      filePath: z.object({
        fileName: optionalValue,
        filePath: optionalValue,
        startLine: optionalValue,
      }),
      sourceLambdaLayerArn: absent,
    })
    .optional(),
});
function selectedFinding(value: unknown) {
  const native = record(value, "Inspector finding");
  const parsed = repositoryFinding.safeParse(native);
  if (!parsed.success)
    throw new Error(
      `Expected an Inspector vulnerability on CODE_REPOSITORY resources. ${z.prettifyError(parsed.error)}`,
    );
  const {
    type,
    packageVulnerabilityDetails: pkg,
    codeVulnerabilityDetails: code,
  } = parsed.data;
  if (
    (pkg && type !== "PACKAGE_VULNERABILITY") ||
    (code && type !== "CODE_VULNERABILITY")
  )
    throw new Error(
      "Inspector finding contains details for a different finding type.",
    );
  return { native, pkg, code };
}

function isInspectorFinding(value: unknown, occurrenceId?: string): boolean {
  return (
    isRecord(value) &&
    typeof value["findingArn"] === "string" &&
    findingArn.test(value["findingArn"]) &&
    (occurrenceId === undefined || value["findingArn"] === occurrenceId) &&
    Array.isArray(value["resources"])
  );
}

function hasInspectorEvidence(
  sourceData: unknown,
  occurrenceId?: string,
): boolean {
  return (
    isRecord(sourceData) &&
    (sourceData["format"] === format ||
      isInspectorFinding(sourceData["finding"], occurrenceId) ||
      isInspectorFinding(sourceData, occurrenceId))
  );
}

export function inspectorReportRepository(
  provider: Provider,
  findings: readonly ExternalFinding[],
  target: ExternalImportTarget,
  projectMap?: ReadonlyMap<string, string>,
): (ExternalSourceRepository & { findingId: string }) | undefined {
  if (provider !== "inspector") {
    if (
      findings.some(({ evidence, source_finding_id }) =>
        hasInspectorEvidence(evidence.source_data, source_finding_id),
      )
    )
      throw new CodexSecurityError(
        "Retained Inspector evidence requires the inspector provider.",
      );
    return undefined;
  }
  const retained = [];
  for (const { source_finding_id: id, evidence } of findings) {
    const data = evidence.source_data;
    if (!isRecord(data) || data["format"] !== format) {
      if (projectMap || hasInspectorEvidence(data) || findingArn.test(id))
        throw new Error(
          "Expected retained Inspector ListFindings evidence for the finding ARN.",
        );
      continue;
    }
    const source = repositoryUrl(data["sourceRepositoryUrl"]);
    const { native: finding } = selectedFinding(data["finding"]);
    if (finding["findingArn"] !== id)
      throw new Error(
        "Inspector source_finding_id does not match the retained finding ARN.",
      );
    retained.push({
      source,
      claims: repositoryClaims(finding),
      id,
      declared: evidence.details?.repository?.url,
    });
  }
  const first = retained[0];
  if (!first) return undefined;
  // A supplied map owns the path casing on custom hosts.
  const github =
    checkReportScope(retained, target, projectMap) === "GITHUB" && !projectMap;
  const key =
    github || target === "cloud" ? cloudRepositoryUrlKey : repositoryUrlKey;
  const repository = key(first.source);
  for (const { source, declared } of retained) {
    if (key(source) !== repository)
      throw new Error(
        "Inspector export identifies more than one source repository.",
      );
    if (declared && key(declared) !== repository)
      throw new Error(
        "Retained scanner repository does not match the normalized evidence repository.",
      );
  }
  return {
    findingId: first.id,
    url: first.source,
    ...(github && { platform: "github" }),
  };
}

function repoFile(value: unknown): string | null {
  const relative = relativePath(value);
  if (!relative) return null;
  const path = posix.normalize(relative);
  return path === "." ||
    path.endsWith("/") ||
    /^(?:[a-z][a-z\d+.-]*:|~[^/]*(?:\/|$)|[^/]+@[^/]+:)/iu.test(path)
    ? null
    : path;
}

function timestamp(value: unknown): number {
  const seconds =
    typeof value === "number"
      ? value
      : typeof value === "string" &&
          /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/u.test(
            value,
          )
        ? Date.parse(value) / 1000
        : NaN;
  if (!Number.isFinite(seconds))
    throw new Error("Invalid Inspector timestamp.");
  return Math.floor(seconds);
}

const ecosystems = new Map(
  Object.entries({
    BUNDLER: "rubygems",
    GEMSPEC: "rubygems",
    CARGO: "cargo",
    COMPOSER: "composer",
    NPM: "npm",
    YARN: "npm",
    NODEPKG: "npm",
    NUGET: "nuget",
    DOTNET_CORE: "nuget",
    GOBINARY: "go",
    GOMOD: "go",
    JAR: "java",
    POM: "maven",
    PIP: "pypi",
    PIPENV: "pypi",
    POETRY: "pypi",
    PYTHONPKG: "pypi",
  }),
);

const manifests = new Set([
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "Cargo.toml",
  "Cargo.lock",
  "composer.json",
  "composer.lock",
  "Gemfile",
  "Gemfile.lock",
  "go.mod",
  "go.sum",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "gradle.lockfile",
  "Pipfile",
  "Pipfile.lock",
  "poetry.lock",
  "pyproject.toml",
  "uv.lock",
  "packages.config",
  "packages.lock.json",
]);

function manifestPath(path: string | null): string | null {
  if (!path) return null;
  const name = posix.basename(path);
  return manifests.has(name) ||
    /^requirements(?:[-_.].*)?\.txt$/u.test(name) ||
    /\.(?:csproj|fsproj|vbproj|gemspec)$/u.test(name)
    ? path
    : null;
}

function concreteVersion(
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

function evidence(
  { native: finding, pkg, code }: ReturnType<typeof selectedFinding>,
  id: string,
  source: string,
  target: ExternalImportTarget,
) {
  const {
    description,
    severity,
    remediation,
    firstObservedAt,
    lastObservedAt,
    updatedAt,
    status,
  } = finding;
  const { recommendation } = record(remediation, "Inspector remediation");
  record(recommendation ?? {}, "Inspector recommendation");
  requiredText(status, "Inspector status");
  timestamp(firstObservedAt);
  timestamp(lastObservedAt);
  const level = requiredText(severity, "Inspector severity").toLowerCase();
  const paths = new Set<string>();
  const packages = (pkg?.vulnerablePackages ?? []).map((item) => {
    const path = repoFile(item.filePath);
    if (path) paths.add(path);
    const ecosystem = ecosystems.get(text(item.packageManager) ?? "") ?? null;
    const version = (value: unknown) =>
      concreteVersion(value, ecosystem, item.packageManager === "OS");
    const fixed = version(item.fixedInVersion);
    const splitVersion =
      item.packageManager === "OS" &&
      (item.epoch != null || item.release != null);
    return {
      name: item.name,
      ecosystem,
      installed_version: splitVersion ? null : version(item.version),
      manifest_path: manifestPath(path),
      fixed_versions: fixed ? [fixed] : [],
    };
  });
  const locations: { path: string; line: number | null }[] = [...paths].map(
    (path) => ({ path, line: null }),
  );
  if (code) {
    const { fileName, filePath, startLine } = code.filePath;
    const path = repoFile(filePath);
    if (path && posix.basename(path) === fileName)
      locations.push({
        path,
        line:
          typeof startLine === "number" &&
          Number.isSafeInteger(startLine) &&
          startLine > 0
            ? startLine
            : null,
      });
  }
  return validateExternalEvidence(
    {
      title:
        text(finding["title"]) ??
        pkg?.vulnerabilityId ??
        code?.detectorName ??
        id,
      description: requiredText(description, "Inspector description"),
      severity: ["critical", "high", "medium", "low", "informational"].includes(
        level,
      )
        ? level
        : "unknown",
      url: text(pkg?.sourceUrl),
      advisory_ids: pkg
        ? [
            ...new Set([
              pkg.vulnerabilityId,
              ...(pkg.relatedVulnerabilities ?? []),
            ]),
          ]
        : [],
      packages,
      locations,
      source_updated_at: updatedAt === undefined ? null : timestamp(updatedAt),
      source_data: {
        format,
        sourceRepositoryUrl: source,
        finding: structuredClone(finding),
      },
    },
    target,
  );
}

export function normalizeInspectorFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
  projectMap?: ReadonlyMap<string, string>,
): ExternalFindings {
  const source = repositoryUrl(sourceRepositoryUrl);
  if (
    isRecord(input) &&
    (Object.hasOwn(input, "NextToken") || Object.hasOwn(input, "nextToken"))
  )
    throw new Error(
      "Inspector export has a continuation key; supply the complete paginated CLI JSON output.",
    );
  const report = listFindings.safeParse(input);
  if (!report.success)
    throw new Error(
      "Expected only a complete native Inspector ListFindings response with a findings array.",
    );
  const rows = report.data.findings.map((finding, i) => ({
    finding,
    source,
    position: i + 1,
    claims: repositoryClaims(finding),
  }));
  checkReportScope(rows, target, projectMap);
  const result = normalizeRecords(
    rows,
    ({ finding }, id) => evidence(selectedFinding(finding), id, source, target),
    ({ finding }) => identity(record(finding, "Inspector finding")).arn,
    target,
  );
  if (result.excluded.length && result.findings.length) {
    // Only surviving rows can supply shared provider and host evidence on replay.
    const skipped = new Set(result.excluded.map((row) => row.position));
    const retained = rows.filter((row) => !skipped.has(row.position));
    checkReportScope(retained, target, projectMap, (row, error) => {
      skipped.add(row.position);
      result.excluded.push({
        position: row.position,
        source_finding_id: identity(record(row.finding, "Inspector finding"))
          .arn,
        reason: errorMessage(error),
      });
    });
    result.findings = result.findings.filter(
      (_, i) => !skipped.has(retained[i]!.position),
    );
    result.excluded.sort((a, b) => a.position - b.position);
  }
  return result;
}

export async function readInspectorFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
  projectMap?: ReadonlyMap<string, string>,
): Promise<ExternalFindings> {
  const mapping = projectMap && new Map(projectMap);
  return normalizeInspectorFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
    mapping,
  );
}
