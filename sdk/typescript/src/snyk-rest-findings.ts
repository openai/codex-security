import {
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import {
  snapshotSourceRepositories,
  type ExternalFinding,
  type ExternalFindings,
  type ExternalSourceRepository,
} from "./external-findings.js";
import type { ImportedPackage, Provider } from "./external-import-models.js";
import {
  SNYK_REST_ISSUES_FORMAT,
  encodeSnykV1File,
  isSnykRestFormat,
  SNYK_REST_ISSUES_V1,
  originalSnykEvidence,
  readSnykRestDocument,
} from "./snyk-rest-v1.js";
import { snykRepositoryUrls } from "./snyk-findings.js";
import { requireExternalImports } from "./external-imports-feature.js";
import { isGitHubCloudHost } from "./git-remote.js";
import {
  gitPathToHttpPath,
  ambiguousGitIpHost,
  gitServiceHostname,
  gitTransportBytes,
  hostedRepositoryMatches,
  hostedRepositoryUrlKey,
  isPublicGitHost,
  normalizeHostedGitRepositoryUrl,
} from "./hosted-git-repository.js";
import {
  hostedNumberToken,
  parseHostedScannerJson,
  stringifyHostedEvidence,
  hostedScannerHttp,
  hostedRepositoryUrl,
  type HostedScannerHttpOptions,
} from "./hosted-scanner-http.js";
import { isRecord } from "./record.js";
import { legacyDecimalInteger } from "./hosted-scanner-v1.js";
import { isSafeNonNegativeInteger } from "./value.js";
import { checkSnykTokenOrigin, snykApiToken } from "./snyk-token-origin.js";
import { regexes } from "zod/v4/core";
import {
  array,
  normalizeRecords,
  record,
  hostedRepositoryPath,
  requiredText,
  scannerSeverity,
  stableId,
  strings,
  text,
} from "./scanner-import.js";

export interface SnykIssuesFindings extends ExternalFindings {
  sourceRepositoryUrl: string;
  sourceRepositoryPlatform?: "github" | "other";
  snykRestContext?: Record<string, unknown>;
}
export { SNYK_REST_ISSUES_FORMAT, isSnykRestFormat } from "./snyk-rest-v1.js";
const issueTimestamp = new RegExp(
  regexes.datetime({ offset: true }).source,
  "i",
);
const apiVersion = "2026-03-25";
const formatVersion = { format: SNYK_REST_ISSUES_FORMAT, apiVersion } as const;
const defaultOrigin = "https://api.snyk.io";
const origins = new Set([
  defaultOrigin,
  "https://api.us.snyk.io",
  "https://api.eu.snyk.io",
  "https://api.au.snyk.io",
]);
const scmOrigins = new Set([
  "azure-repos",
  "bitbucket-cloud",
  "bitbucket-connect-app",
  "bitbucket-server",
  "github",
  "github-app",
  "github-cloud-app",
  "github-enterprise",
  "github-server-app",
  "gitlab",
]);
const openSourceProjects = new Set([
  "cargo",
  "cocoapods",
  "composer",
  "conan",
  "cpp",
  "golang",
  "golangdep",
  "gomodules",
  "govendor",
  "gradle",
  "hex",
  "maven",
  "npm",
  "nuget",
  "paket",
  "pip",
  "pipenv",
  "pnpm",
  "poetry",
  "pub",
  "rubygems",
  "sbt",
  "swift",
  "unmanaged",
  "uv",
  "yarn",
  "yarn-workspace",
]);
const issueTypes = {
  "open-source": "package_vulnerability",
  code: "code",
} as const;
export type SnykIssuesProduct = keyof typeof issueTypes;

interface SnykScope {
  organizationId: string;
  projectId: string;
  product: SnykIssuesProduct;
  sourceRepositoryUrl: string;
}

export interface CollectSnykIssuesOptions extends Omit<SnykScope, "product"> {
  product?: SnykIssuesProduct;
  token?: string;
  apiOrigin?: string;
  signal?: AbortSignal;
}

type Resource = Record<string, unknown>;

export interface SnykIssuesExport extends SnykScope {
  format: typeof SNYK_REST_ISSUES_FORMAT;
  apiVersion: typeof apiVersion;
  apiOrigin: string;
  complete: true;
  projectJson: string;
  targetJson: string;
  pages: { startingAfter: string | null; responseJson: string }[];
}

function isUuid(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[\da-f]{8}(?:-[\da-f]{4}){3}-[\da-f]{12}$/iu.test(value)
  );
}

function uuid(value: unknown, label: string): string {
  if (!isUuid(value)) throw new Error(`${label} must be a UUID.`);
  return value.toLowerCase();
}

type Scope = SnykScope & { apiOrigin: string };

function scope(
  input: Resource | CollectSnykIssuesOptions,
  origin: unknown,
  product: unknown = input["product"],
): Scope {
  const apiOrigin = requiredText(origin, "Snyk API origin").replace(/\/$/u, "");
  if (!origins.has(apiOrigin))
    throw new Error("Select a documented Snyk regional HTTPS API origin.");
  if (product !== "open-source" && product !== "code")
    throw new Error("Snyk product must be open-source or code.");
  return {
    apiOrigin,
    product,
    sourceRepositoryUrl: hostedRepositoryUrl(
      input["sourceRepositoryUrl"],
      "Snyk source repository URL",
    ),
    organizationId: uuid(input["organizationId"], "Snyk organization ID"),
    projectId: uuid(input["projectId"], "Snyk project ID"),
  };
}

function endpoint(selected: Scope, route: string) {
  const url = new URL(
    `/rest/orgs/${selected.organizationId}/${route}`,
    selected.apiOrigin,
  );
  url.searchParams.set("version", apiVersion);
  return url;
}

function issuesEndpoint(selected: Scope) {
  const url = endpoint(selected, "issues");
  url.searchParams.set("scan_item.type", "project");
  url.searchParams.set("scan_item.id", selected.projectId);
  url.searchParams.set("type", issueTypes[selected.product]);
  url.searchParams.set("status", "open,resolved");
  url.searchParams.set("limit", "100");
  if (selected.product === "code")
    url.searchParams.set("include_code_flows", "true");
  return url;
}

function jsonApi(input: unknown, label: string) {
  const document = record(input, label);
  if ("errors" in document)
    throw new Error(
      `${label}: JSON:API errors: ${JSON.stringify(document["errors"])}`,
    );
  return document;
}

function resourceId(resource: Resource, type: string) {
  if (resource["type"] !== type)
    throw new Error(`Expected a Snyk ${type} resource.`);
  return uuid(resource["id"], `Snyk ${type} ID`);
}

function relationship(relationships: Resource, name: string) {
  return record(
    record(relationships[name], `Snyk ${name} relationship`)["data"],
    `Snyk ${name} linkage`,
  );
}

function checkOrganization(
  relationships: Resource,
  selected: Scope,
  project = false,
) {
  const org = relationship(relationships, "organization");
  if (
    (org["type"] !== "organization" && !(project && org["type"] === "org")) ||
    uuid(org["id"], "Snyk organization relationship ID") !==
      selected.organizationId
  )
    throw new Error(
      "Snyk resource does not belong to the selected organization.",
    );
}

type RepositoryBinding = {
  url: string;
  platform?: "github" | "other";
  gitlab?: boolean;
  nativeUrl?: string;
};

function scmUrl(
  binding: RepositoryBinding,
  remote: string,
): string | undefined {
  try {
    const hostname = new URL(binding.url).hostname;
    if (hostname === "dev.azure.com") {
      const uri =
        /^(?:ssh|git\+ssh|ssh\+git):\/\/git@([^/:]+)(?::22)?\/(v3\/.+)$/u.exec(
          remote,
        );
      const address = uri ?? /^git@([^/:]+):(v3\/.+)$/u.exec(remote);
      if (address && address[1]!.toLowerCase() === "ssh.dev.azure.com") {
        // Azure clone paths may already contain URL escapes in the upload-pack path.
        const path = gitPathToHttpPath(
          gitTransportBytes(address[2]!, uri === null),
        ).replace(/%25(?=[\da-f]{2})/giu, "%");
        const parts = /^v3\/([^/]+)\/([^/]+)\/([^/]+)$/u.exec(path);
        if (parts)
          return hostedRepositoryUrl(
            `https://dev.azure.com/${parts[1]}/${parts[2]}/_git/${parts[3]}`,
            "Snyk target URL",
          );
      }
    }
    const url = normalizeHostedGitRepositoryUrl(
      remote,
      binding.url,
      binding.platform === "github" || binding.gitlab === true,
    );
    return hostedRepositoryUrl(url, "Snyk target URL");
  } catch {
    return undefined;
  }
}

export function snykRestRepositoryMatches(
  binding: RepositoryBinding,
  remote: string,
): boolean {
  const candidate = scmUrl(binding, remote);
  if (
    !candidate ||
    ambiguousGitIpHost(candidate) ||
    ambiguousGitIpHost(binding.url)
  )
    return false;
  const key = (url: string) =>
    hostedRepositoryUrlKey(url, binding.platform === "github", binding.gitlab);
  return key(binding.url) === key(candidate);
}

/** Git's HTTP checkout may use credentials or spell out the default port. */
export function snykRestCheckoutMatches(
  binding: RepositoryBinding,
  remote: string,
): boolean {
  const url = /^https?:\/\//iu.test(remote) ? remote : scmUrl(binding, remote);
  return url !== undefined && hostedRepositoryMatches(binding, url);
}

function reportedScm(url: string, origin: string) {
  const host = gitServiceHostname(new URL(url).hostname);
  const publicGitHub = isGitHubCloudHost(host);
  const custom =
    !isPublicGitHost(host) &&
    host !== "dev.azure.com" &&
    !/^[a-z\d-]+\.visualstudio\.com$/u.test(host);
  const enterprise =
    (custom || publicGitHub) &&
    (origin === "github-enterprise" || origin === "github-server-app");
  const gitlab = origin === "gitlab" && (custom || host === "gitlab.com");
  const github = origin.startsWith("github") && (custom || publicGitHub);
  return { custom, publicGitHub, enterprise, gitlab, github };
}

function trustedScmBinding(
  url: string,
  references: readonly ExternalSourceRepository[],
  allowGitHub: boolean,
  allowGitLab: boolean,
): RepositoryBinding {
  for (const hint of references) {
    const github = allowGitHub && hint.platform === "github";
    const gitlab = allowGitLab && hint.platform === "gitlab";
    if (github || gitlab) {
      const candidate: RepositoryBinding = {
        url,
        platform: github ? "github" : undefined,
        gitlab,
      };
      if (snykRestRepositoryMatches(candidate, hint.url)) return candidate;
    }
  }
  return { url };
}

function checkRemote(
  remote: unknown,
  selected: Scope,
  origin: string,
  references: readonly ExternalSourceRepository[],
) {
  if (remote === null || remote === "") return;
  const url = requiredText(remote, "Snyk target URL");
  // Snyk monitor can render a local path and a Git server as the same HTTP target.
  if (
    origin === "cli" &&
    selected.product === "open-source" &&
    /^http:\/\//iu.test(url)
  )
    throw new Error(
      "Snyk CLI HTTP target URL cannot verify a repository. Set an explicit HTTPS URL with snyk monitor --remote-repo-url.",
    );
  const { custom, publicGitHub, enterprise, gitlab, github } = reportedScm(
    selected.sourceRepositoryUrl,
    origin,
  );
  const platformNeutral = !scmOrigins.has(origin);
  const binding: RepositoryBinding =
    custom && (platformNeutral || references.length > 0)
      ? trustedScmBinding(
          selected.sourceRepositoryUrl,
          references,
          platformNeutral || github,
          platformNeutral || gitlab,
        )
      : {
          url: selected.sourceRepositoryUrl,
          platform: publicGitHub || enterprise ? "github" : undefined,
          gitlab,
        };
  if (!snykRestRepositoryMatches(binding, url))
    throw new Error(
      "Snyk target URL does not match the selected source repository URL.",
    );
  return {
    github,
    enterprise,
    gitlab,
    // Recheck the exact target with the caller's platform mapping at import time.
    nativeUrl: url,
  };
}

function projectContext(project: Resource, selected: Scope) {
  if (resourceId(project, "project") !== selected.projectId)
    throw new Error(
      "Snyk returned a different project from the selected project.",
    );
  const attributes = record(project["attributes"], "Snyk project attributes");
  const manager = requiredText(attributes["type"], "Snyk project type");
  const origin = requiredText(attributes["origin"], "Snyk project origin");
  const scm = scmOrigins.has(origin);
  if (
    (!scm && origin !== "cli" && origin !== "api") ||
    (selected.product === "code"
      ? manager !== "sast"
      : !openSourceProjects.has(manager))
  )
    throw new Error(
      `Snyk project type ${manager} from ${origin} is not a supported ${selected.product} project.`,
    );
  const context = {
    manager,
    scm,
    origin,
    manifest: scm ? hostedRepositoryPath(attributes["target_file"]) : null,
  };
  const relationships =
    project["relationships"] === undefined
      ? undefined
      : record(project["relationships"], "Snyk project relationships");
  if (relationships) checkOrganization(relationships, selected, true);
  const target = relationships?.["target"];
  const linkage =
    target === undefined
      ? null
      : record(target, "Snyk target relationship")["data"];
  if (linkage === null)
    return {
      ...context,
      lookupTargetId: undefined,
      expandedUrl: undefined,
      integrationId: undefined,
    };
  const link = record(linkage, "Snyk target linkage");
  const expandedUrl =
    link["attributes"] === undefined
      ? undefined
      : record(link["attributes"], "Snyk expanded target attributes")["url"];
  const targetId = resourceId(link, "target");
  const integrationId = checkTargetRelationships(link, selected, origin);
  return {
    integrationId,
    ...context,
    lookupTargetId:
      expandedUrl == null || expandedUrl === "" ? targetId : undefined,
    expandedUrl,
  };
}

function checkTarget(
  value: unknown,
  selected: Scope,
  {
    expandedUrl,
    lookupTargetId,
    origin,
    integrationId,
  }: ReturnType<typeof projectContext>,
  references: readonly ExternalSourceRepository[] = [],
) {
  if (lookupTargetId === undefined) {
    if (value !== null)
      throw new Error(
        "Unexpected separate Snyk target without a project target lookup.",
      );
    return expandedUrl == null
      ? undefined
      : checkRemote(expandedUrl, selected, origin, references);
  }
  const target = record(value, "Snyk target resource");
  if (resourceId(target, "target") !== lookupTargetId)
    throw new Error(
      "Snyk target does not match the selected project's target.",
    );
  const fetchedIntegrationId = checkTargetRelationships(
    target,
    selected,
    origin,
  );
  if (
    integrationId !== undefined &&
    fetchedIntegrationId !== undefined &&
    integrationId !== fetchedIntegrationId
  )
    throw new Error(
      "The fetched Snyk target names a different integration than the project's target.",
    );
  return checkRemote(
    record(target["attributes"], "Snyk target attributes")["url"],
    selected,
    origin,
    references,
  );
}

function checkTargetRelationships(
  target: Resource,
  selected: Scope,
  origin: string,
) {
  if (target["relationships"] === undefined) return;
  const relationships = record(
    target["relationships"],
    "Snyk target relationships",
  );
  if (relationships["organization"] !== undefined)
    checkOrganization(relationships, selected, true);
  if (relationships["integration"] === undefined) return;
  const linkage = record(
    relationships["integration"],
    "Snyk integration relationship",
  )["data"];
  if (linkage === null && !scmOrigins.has(origin)) return;
  const integration = record(linkage, "Snyk integration linkage");
  if (integration["type"] !== "integration")
    throw new Error("Expected a Snyk integration resource.");
  const attributes = integration["attributes"];
  // The Targets API allows a null ID on an expanded integration.
  const id =
    attributes === undefined || integration["id"] !== null
      ? uuid(integration["id"], "Snyk integration ID")
      : undefined;
  if (attributes === undefined) return id;
  const type = requiredText(
    record(attributes, "Snyk integration attributes")["integration_type"],
    "Snyk integration type",
  );
  if (
    scmOrigins.has(origin) &&
    (!scmOrigins.has(type) || origin.split("-")[0] !== type.split("-")[0])
  )
    throw new Error(
      `Snyk target integration ${type} must be a supported SCM integration for the project's ${origin} origin.`,
    );
  return id;
}

function pageLinkCursor(
  link: unknown,
  endpoint: URL,
  label: string,
  cursorName = "starting_after",
) {
  const href = requiredText(isRecord(link) ? link["href"] : link, label);
  const url = new URL(
    href.startsWith("/orgs/") ? `/rest${href}` : href,
    endpoint,
  );
  if (
    url.origin !== endpoint.origin ||
    url.pathname !== endpoint.pathname ||
    url.username ||
    url.password ||
    url.hash
  )
    throw new Error(`${label} leaves the selected Issues endpoint.`);
  for (const [key, value] of url.searchParams) {
    if (
      url.searchParams.getAll(key).length !== 1 ||
      (key !== cursorName && endpoint.searchParams.get(key) !== value)
    )
      throw new Error(`${label} changes the selected Issues query.`);
  }
  return url.searchParams.get(cursorName);
}

function nextCursor(value: unknown, endpoint: URL, current: string | null) {
  if (value === undefined) return null;
  const links = nativeRecord(value, "Snyk issue page links");
  if (links["prev"] != null) {
    if (current === null)
      throw new Error("The first Snyk issue page has a previous page link.");
    pageLinkCursor(
      links["prev"],
      endpoint,
      "Snyk previous page link",
      "ending_before",
    );
  }
  if (
    links["self"] != null &&
    pageLinkCursor(links["self"], endpoint, "Snyk self page link") !== current
  )
    throw new Error("Snyk self page link does not match the requested cursor.");
  if (links["next"] == null) return null;
  return requiredText(
    pageLinkCursor(links["next"], endpoint, "Snyk next page link"),
    "Snyk next page starting_after cursor",
  );
}

function scopedIssue(value: unknown, selected: Scope) {
  const issue = record(value, "Snyk issue");
  const relationships = record(
    issue["relationships"],
    "Snyk issue relationships",
  );
  checkOrganization(relationships, selected);
  const item = relationship(relationships, "scan_item");
  if (resourceId(item, "project") !== selected.projectId)
    throw new Error("Snyk issue does not belong to the selected project.");
  return issue;
}

function selectedIssue(issue: Resource, selected: Scope) {
  const id = resourceId(issue, "issue");
  const attributes = record(issue["attributes"], "Snyk issue attributes");
  if (attributes["type"] !== issueTypes[selected.product])
    throw new Error(
      `Only ${issueTypes[selected.product]} issues are supported for this Snyk project selection.`,
    );
  return { id, attributes };
}

function snykIssueId(
  attributes: Resource,
  source: Scope,
  retainedKey?: unknown,
): string {
  const key = requiredText(attributes["key"], "Snyk issue key");
  if (retainedKey !== undefined && retainedKey !== key)
    throw new Error(
      "The retained Snyk issue key does not match the original issue.",
    );
  return stableId("snyk-rest", [
    source.apiOrigin,
    source.organizationId,
    source.projectId,
    source.product,
    key,
  ]);
}

function issuePage(
  response: Resource,
  selected: Scope,
  url: URL,
  seen: Set<string>,
  current: string | null,
) {
  const issues = array(response["data"], "Snyk issue page data").map((value) =>
    scopedIssue(value, selected),
  );
  const next = nextCursor(response["links"], url, current);
  if (next !== null) {
    if (seen.has(next))
      throw new Error("Snyk Issues pagination repeated a cursor.");
    seen.add(next);
  }
  return { issues, next };
}

export async function collectSnykIssues(
  options: CollectSnykIssuesOptions,
  dependencies: HostedScannerHttpOptions & {
    sourceRepositories?: readonly ExternalSourceRepository[];
  } = {},
): Promise<SnykIssuesExport> {
  const environment = dependencies.environment ?? process.env;
  requireExternalImports(environment);
  const { getJson, signal } = hostedScannerHttp(dependencies, options.signal);
  const { product = "open-source" } = options;
  const selected = scope(options, options.apiOrigin ?? defaultOrigin, product);
  const references = snapshotSourceRepositories(
    dependencies.sourceRepositories,
  );
  const token = requiredText(
    snykApiToken(environment, selected.apiOrigin, options.token),
    "Snyk API token (SNYK_TOKEN)",
  );
  checkSnykTokenOrigin(token, selected.apiOrigin);
  const get = async (url: URL, label: string) =>
    jsonApi(await getJson(url, `token ${token}`), label);
  const getResource = async (url: URL, kind: string) =>
    record(
      (await get(url, `Snyk ${kind} response`))["data"],
      `Snyk ${kind} resource`,
    );
  const projectUrl = endpoint(selected, `projects/${selected.projectId}`);
  projectUrl.searchParams.set("expand", "target");
  const project = await getResource(projectUrl, "project");
  const context = projectContext(project, selected);
  const target =
    context.lookupTargetId === undefined
      ? null
      : await getResource(
          endpoint(selected, `targets/${context.lookupTargetId}`),
          "target",
        );
  checkTarget(target, selected, context, references);
  const pages: SnykIssuesExport["pages"] = [];
  const base = issuesEndpoint(selected);
  const cursors = new Set<string>();
  const issueIds = new Set<string>();
  let startingAfter: string | null = null;
  do {
    const url = new URL(base);
    if (startingAfter !== null)
      url.searchParams.set("starting_after", startingAfter);
    const response = await get(url, "Snyk issue page");
    const page = issuePage(response, selected, base, cursors, startingAfter);
    for (const issue of page.issues) {
      const { id } = selectedIssue(issue, selected);
      if (issueIds.has(id))
        throw new Error(
          "Snyk Issues returned overlapping issue IDs. Retry the collection.",
        );
      issueIds.add(id);
    }
    pages.push({
      startingAfter,
      responseJson: JSON.stringify(response),
    });
    startingAfter = page.next;
  } while (startingAfter !== null);
  signal?.throwIfAborted();
  return {
    ...formatVersion,
    ...selected,
    complete: true,
    projectJson: JSON.stringify(project),
    targetJson: JSON.stringify(target),
    pages,
  };
}

function savedContext(
  document: Resource,
  references: readonly ExternalSourceRepository[],
) {
  if (
    document["format"] !== SNYK_REST_ISSUES_FORMAT ||
    document["apiVersion"] !== apiVersion
  )
    throw new Error(
      `Expected ${SNYK_REST_ISSUES_FORMAT} for API version ${apiVersion}.`,
    );
  const selected = scope(document, document["apiOrigin"]);
  const project = record(
    parseHostedScannerJson(
      requiredText(document["projectJson"], "Snyk original project"),
    ),
    "Snyk project resource",
  );
  const context = projectContext(project, selected);
  const target = parseHostedScannerJson(
    requiredText(document["targetJson"], "Snyk original target"),
  );
  const remote = checkTarget(target, selected, context, references);
  const nativeUrl = remote?.nativeUrl;
  const gitlab =
    remote?.gitlab ??
    reportedScm(selected.sourceRepositoryUrl, context.origin).gitlab;
  const github = remote?.github ?? context.origin.startsWith("github");
  const platform: SnykIssuesFindings["sourceRepositoryPlatform"] =
    remote?.enterprise
      ? "github"
      : context.scm && !github
        ? "other"
        : undefined;
  return {
    project,
    target,
    source: {
      ...formatVersion,
      ...selected,
      projectJson: stringifyHostedEvidence(project),
      targetJson: stringifyHostedEvidence(target),
    },
    context,
    repository: {
      scope: selected,
      url: selected.sourceRepositoryUrl,
      platform,
      ...(gitlab && { gitlab: true }),
      ...(nativeUrl &&
        nativeUrl !== selected.sourceRepositoryUrl && { nativeUrl }),
    },
  };
}

const snykRestId = /^snyk-rest:[0-9a-f]{64}$/u;

/** A Snyk Issues resource carries its own product and links to both its organization and project. */
function linkedSnykResources(
  data: Resource,
  json: boolean,
  hosted: boolean,
): { issue?: Resource } | undefined {
  const original = (field: string) => {
    const value = data[field + (json ? "Json" : "")];
    if (!json) return isRecord(value) ? value : undefined;
    if (typeof value !== "string") return;
    try {
      const parsed = parseHostedScannerJson(value);
      return isRecord(parsed) ? parsed : undefined;
    } catch {
      return;
    }
  };
  const issue = original("issue");
  if (issue?.["type"] === "issue" && (hosted || isUuid(issue["id"]))) {
    const attributes = issue["attributes"];
    const links = issue["relationships"];
    const relationType = (name: string) => {
      const link = isRecord(links) ? links[name] : undefined;
      const resource = isRecord(link) ? link["data"] : undefined;
      return isRecord(resource) && (hosted || isUuid(resource["id"]))
        ? resource["type"]
        : undefined;
    };
    if (
      isRecord(attributes) &&
      "key" in attributes &&
      (hosted ||
        attributes["type"] === issueTypes.code ||
        attributes["type"] === issueTypes["open-source"]) &&
      relationType("organization") === "organization" &&
      relationType("scan_item") === "project"
    )
      return { issue };
  }
  const keyed = json && "snykRestIssueKey" in data;
  if (keyed || data["apiVersion"] === apiVersion) {
    const project = original("project");
    const attributes = project?.["attributes"];
    if (
      project?.["type"] === "project" &&
      "id" in project &&
      isRecord(attributes) &&
      "origin" in attributes &&
      "type" in attributes
    ) {
      if (!keyed) {
        // Saved v1 rows have no issue-key marker. Their project and complete monitor scope identify them.
        try {
          uuid(project["id"], "Snyk project ID");
          scope(data, data["apiOrigin"]);
        } catch {
          return;
        }
      }
      return {};
    }
  }
}

function snykRowEvidence(finding: ExternalFinding, hostedReport = false) {
  const retained = finding.evidence.source_data;
  const marked =
    snykRestId.test(finding.source_finding_id) ||
    isSnykRestFormat(retained?.["format"]);
  const hosted = hostedReport || marked;
  const v1 = retained && linkedSnykResources(retained, false, hosted);
  const v2 = retained && linkedSnykResources(retained, true, hosted);
  if (v1 || v2 || marked) return { v1, v2 };
}

export function isSnykRestFinding(finding: ExternalFinding): boolean {
  return snykRowEvidence(finding) !== undefined;
}

export function snykRestFindingRepository(
  finding: ExternalFinding,
  references: readonly ExternalSourceRepository[] = [],
) {
  return bindSnykFinding(finding, references, snykRowEvidence(finding));
}

function bindSnykFinding(
  finding: ExternalFinding,
  references: readonly ExternalSourceRepository[],
  originals: ReturnType<typeof snykRowEvidence>,
  report?: ReturnType<typeof savedContext>,
  retain?: (finding: ExternalFinding, source: Resource) => void,
) {
  const retained = record(
    finding.evidence.source_data,
    "Original Snyk REST issue evidence",
  );
  const format =
    retained["format"] === undefined
      ? originals?.v1
        ? SNYK_REST_ISSUES_V1
        : SNYK_REST_ISSUES_FORMAT
      : retained["format"];
  if (
    isSnykRestFormat(format) &&
    (format === SNYK_REST_ISSUES_V1 ? originals?.v2 : originals?.v1)
  )
    throw new Error(
      "A normalized Snyk row cannot claim both v1 and v2 native issue and project representations.",
    );
  const document = readSnykRestDocument({ ...retained, format });
  const issue =
    (format === SNYK_REST_ISSUES_FORMAT ? originals?.v2?.issue : undefined) ??
    parseHostedScannerJson(
      requiredText(document["issueJson"], "Snyk original issue"),
    );
  // A reader may omit a duplicated native project while retaining the original issue.
  const projected =
    report &&
    document["projectJson"] === undefined &&
    (originals?.v1?.issue || originals?.v2?.issue);
  const asset = savedContext(
    projected
      ? {
          ...report.source,
          ...document,
          projectJson: JSON.stringify(report.project),
          targetJson:
            document["targetJson"] === undefined
              ? JSON.stringify(report.target)
              : document["targetJson"],
        }
      : document,
    references,
  );
  const { source, repository } = asset;
  const { id: issueId, attributes } = selectedIssue(
    scopedIssue(issue, source),
    source,
  );
  const nativeId = snykIssueId(
    attributes,
    source,
    retained["snykRestIssueKey"],
  );
  if (nativeId !== finding.source_finding_id)
    throw new Error(
      "The normalized finding ID does not match the original Snyk issue key and project.",
    );
  projectSnykIssue(attributes, asset, { ...retained, format }, "local");
  if (retain && format === SNYK_REST_ISSUES_V1 && projected) {
    // The legacy witness stores the original decimal token, including its spelling.
    const context = encodeSnykV1File({
      ...repository.scope,
      apiVersion: source.apiVersion,
      format,
      project: asset.project,
      target: asset.target,
    });
    retain(finding, {
      ...context,
      ...retained,
      format,
      ...(isRecord(context["numericFields"]) && {
        numericFields: {
          ...context["numericFields"],
          ...(isRecord(retained["numericFields"]) && retained["numericFields"]),
        },
      }),
    });
  } else if (retain && format === SNYK_REST_ISSUES_FORMAT) {
    retain(finding, {
      ...(projected && { ...source, snykRestIssueKey: attributes["key"] }),
      ...retained,
      projectJson: source.projectJson,
      targetJson: source.targetJson,
      issueJson: stringifyHostedEvidence(issue),
    });
  }
  return { ...repository, issueId };
}

/** Recognize a retained hosted report before verifying its selected issues. */
export function isSnykRestReport(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
): boolean {
  return (
    input.snykRestContext !== undefined ||
    input.findings.some(isSnykRestFinding)
  );
}

function readIssues(document: Resource, selected: Scope) {
  if (document["complete"] !== true)
    throw new Error("Expected a complete Snyk REST Issues export.");
  const url = issuesEndpoint(selected);
  const pages = array(document["pages"], "Snyk issue pages");
  if (!pages.length)
    throw new Error("Incomplete Snyk collection: no issue page.");
  const seen = new Set<string>();
  let cursor: string | null = null;
  const issues = pages.flatMap((value, index) => {
    const page = record(value, "Snyk saved page");
    if ((index !== 0 && cursor === null) || page["startingAfter"] !== cursor)
      throw new Error("Incomplete or inconsistent Snyk issue page sequence.");
    const parsed = issuePage(
      jsonApi(
        parseHostedScannerJson(
          requiredText(page["responseJson"], "Snyk original issue page"),
        ),
        "Snyk issue page",
      ),
      selected,
      url,
      seen,
      cursor,
    );
    cursor = parsed.next;
    return parsed.issues;
  });
  if (cursor !== null)
    throw new Error("Incomplete Snyk collection: missing next issue page.");
  return issues;
}

// Lossless parsing preserves JSON numbers in raw token objects.
function nativeRecord(value: unknown, label: string): Resource {
  return record(hostedNumberToken(value) ?? value, label);
}

function records(parent: Resource, field: string) {
  const label = `Snyk ${field}`;
  return array(parent[field] ?? [], label).map((entry) =>
    nativeRecord(entry, label),
  );
}

function problemIds(entries: Resource[], type?: string) {
  const ids = new Set<string>();
  for (const entry of entries) {
    if (type === undefined || entry["type"] === type)
      ids.add(requiredText(entry["id"], "Snyk problem or class ID"));
  }
  return [...ids];
}

function packageEvidence(
  coordinates: Resource[],
  { manager, manifest }: ReturnType<typeof projectContext>,
) {
  const packages: ImportedPackage[] = [];
  for (const coordinate of coordinates) {
    const fixed = records(coordinate, "remedies").flatMap((remedy) => {
      const meta = remedy["meta"];
      return isRecord(meta) &&
        meta["schema_version"] === "package_vulnerability/v0"
        ? strings(record(meta["data"], "Snyk package remedy data")["fixed_in"])
        : [];
    });
    for (const representation of records(coordinate, "representations")) {
      if (!("dependency" in representation)) continue;
      const dependency = record(
        representation["dependency"],
        "Snyk dependency",
      );
      packages.push({
        name: requiredText(
          dependency["package_name"],
          "Snyk dependency package name",
        ),
        installed_version: requiredText(
          dependency["package_version"],
          "Snyk dependency package version",
        ),
        ecosystem: manager,
        manifest_path: manifest,
        fixed_versions: [...new Set(fixed)],
      });
    }
  }
  return packages;
}

function codeStartLine(region: unknown): number | null {
  const start = isRecord(region) ? region["start"] : undefined;
  const token = isRecord(start) ? hostedNumberToken(start["line"]) : undefined;
  const line = token && Number(legacyDecimalInteger(token));
  return isSafeNonNegativeInteger(line) && line > 0 ? line : null;
}

function codeEvidence(
  coordinates: Resource[],
  scm: boolean,
  includeLines: boolean,
) {
  const locations: { path: string; line?: number | null }[] = [];
  const revisions = new Set<string | null>();
  for (const coordinate of coordinates) {
    for (const representation of records(coordinate, "representations")) {
      const value =
        representation["sourceLocation"] ?? representation["source_location"];
      if (value === undefined) continue;
      const location = record(value, "Snyk source location");
      revisions.add(text(location["commit_id"]));
      const path = hostedRepositoryPath(location["file"]);
      if (scm && path)
        locations.push(
          includeLines
            ? { path, line: codeStartLine(location["region"]) }
            : { path },
        );
    }
  }
  return {
    locations,
    code_revision: revisions.size === 1 ? ([...revisions][0] ?? null) : null,
  };
}

function projectSnykIssue(
  attributes: Resource,
  { source, context }: ReturnType<typeof savedContext>,
  sourceData: Resource,
  target: ExternalImportTarget,
) {
  const code = source.product === "code";
  const status = attributes["status"];
  if (
    (status !== "open" && status !== "resolved") ||
    typeof attributes["ignored"] !== "boolean"
  )
    throw new Error(
      "Snyk issue must have a source status and an ignored flag.",
    );
  const updatedAt = requiredText(attributes["updated_at"], "Snyk updated_at");
  const updated = Date.parse(updatedAt);
  if (
    updatedAt.startsWith("0000") ||
    !issueTimestamp.test(updatedAt) ||
    !Number.isFinite(updated) ||
    updated < 0
  )
    throw new Error("Invalid Snyk issue updated_at.");
  const severity = requiredText(
    attributes["effective_severity_level"],
    "Snyk effective severity",
  );
  const problems = records(attributes, "problems");
  const rules = problemIds(problems, "rule");
  const activeCoordinates = records(attributes, "coordinates").filter(
    (coordinate) => status === "open" && coordinate["state"] === "open",
  );
  return validateExternalEvidence(
    {
      title: requiredText(attributes["title"], "Snyk issue title"),
      description: text(attributes["description"]),
      severity:
        severity === "info" ? "informational" : scannerSeverity(severity),
      advisory_ids: code ? [] : problemIds(problems),
      ...(code
        ? codeEvidence(
            activeCoordinates,
            context.scm,
            sourceData["format"] !== SNYK_REST_ISSUES_V1,
          )
        : {
            packages: packageEvidence(activeCoordinates, context),
          }),
      source_updated_at: Math.floor(updated / 1000),
      source_data: sourceData,
      ...(code && {
        details: {
          kind: "sast",
          repository: { url: source.sourceRepositoryUrl },
          scanner_origin: "Snyk Code",
          source_status: status,
          rule: rules.length === 1 ? { id: rules[0] } : null,
          weakness_ids: problemIds(records(attributes, "classes"), "weakness"),
        },
      }),
    },
    target,
  );
}

export function normalizeSnykIssues(
  input: unknown,
  target: ExternalImportTarget = "local",
  references: readonly ExternalSourceRepository[] = [],
): SnykIssuesFindings {
  if (target !== "local")
    throw new Error("Snyk REST issues currently support local import only.");
  const wire = record(input, "Snyk REST Issues export");
  const document = readSnykRestDocument(wire);
  const asset = savedContext(document, references);
  const { source, repository } = asset;
  const issues = readIssues(document, source);
  const legacy = originalSnykEvidence(wire, source);
  // normalizeRecords identifies every row before projecting any evidence.
  const resourceCounts = new Map<string, number>();
  const result = normalizeRecords(
    issues.map((issue, index) => ({ issue, original: legacy?.rows[index] })),
    ({ issue, original }) => {
      if (resourceCounts.get(resourceId(issue, "issue"))! > 1)
        throw new Error(
          "The saved Snyk report contains overlapping issue IDs.",
        );
      const attributes = record(issue["attributes"], "Snyk issue attributes");
      const sourceData = original
        ? structuredClone(original)
        : {
            ...source,
            snykRestIssueKey: attributes["key"],
            issueJson: stringifyHostedEvidence(issue),
          };
      return projectSnykIssue(attributes, asset, sourceData, target);
    },
    ({ issue }) => {
      const { id, attributes } = selectedIssue(issue, source);
      resourceCounts.set(id, (resourceCounts.get(id) ?? 0) + 1);
      return snykIssueId(attributes, source);
    },
    target,
  );
  return {
    ...result,
    sourceRepositoryUrl: source.sourceRepositoryUrl,
    ...(repository.platform && {
      sourceRepositoryPlatform: repository.platform,
    }),
    snykRestContext: legacy ? structuredClone(legacy.context) : source,
  };
}

/** Reconcile the original records, normalized projections, and reader or destination URLs. */
export function snykRestImportRepository(
  input: ExternalFindings & Partial<SnykIssuesFindings>,
  provider: Provider,
  urls: Iterable<string> = [],
  trustedSources: readonly ExternalSourceRepository[] = [],
  retain?: (finding: ExternalFinding, source: Resource) => void,
): RepositoryBinding | undefined {
  const project =
    input.snykRestContext !== undefined
      ? savedContext(
          readSnykRestDocument(
            record(input.snykRestContext, "Snyk report context"),
          ),
          trustedSources,
        )
      : undefined;
  const rows = input.findings.map((finding) => ({
    finding,
    originals: snykRowEvidence(finding, project !== undefined),
  }));
  if (!project && !rows.some(({ originals }) => originals)) return;
  const boundRows = rows.map(({ finding, originals }) =>
    bindSnykFinding(finding, trustedSources, originals, project, retain),
  );
  const selected = project?.repository.scope ?? boundRows[0]?.scope;
  const bindings = project ? [...boundRows, project.repository] : boundRows;
  const sourceBinding = bindings[0];
  if (!sourceBinding) return;
  if (provider !== "snyk")
    throw new Error("Use the snyk provider for Snyk REST issues.");

  if (
    selected &&
    boundRows.some(
      ({ scope }) =>
        scope.apiOrigin !== selected.apiOrigin ||
        scope.organizationId !== selected.organizationId ||
        scope.projectId !== selected.projectId ||
        scope.product !== selected.product,
    )
  )
    throw new Error(
      "The normalized finding does not match the retained Snyk project scope.",
    );

  const claims = new Set(bindings.map((binding) => binding.url));
  for (const binding of bindings)
    if (binding.nativeUrl) claims.add(binding.nativeUrl);
  if (input.sourceRepositoryUrl !== undefined)
    claims.add(input.sourceRepositoryUrl);
  for (const { evidence } of input.findings) {
    const typed = evidence.details?.repository?.url;
    if (typed) claims.add(typed);
    for (const native of snykRepositoryUrls(evidence.source_data, {
      normalizeGitRemote: false,
    }))
      claims.add(native);
  }
  if (
    new Set(boundRows.map(({ issueId }) => issueId)).size !== boundRows.length
  )
    throw new Error(
      "The normalized Snyk selection contains overlapping issue IDs.",
    );
  for (const url of urls) claims.add(url);
  // Saved SCM metadata can contradict a caller's mapping but cannot establish one.
  const source = trustedScmBinding(
    sourceBinding.url,
    trustedSources,
    input.sourceRepositoryPlatform !== "other" &&
      bindings.every(
        (binding) => binding.platform !== "other" && !binding.gitlab,
      ),
    input.sourceRepositoryPlatform !== "github" &&
      bindings.every(
        (binding) => binding.gitlab || binding.platform === undefined,
      ),
  );
  for (const url of claims)
    if (!snykRestRepositoryMatches(source, url))
      throw new Error(
        "The normalized repository does not match the original Snyk project.",
      );
  return source;
}
