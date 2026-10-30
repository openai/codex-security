import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import type { Provider } from "./external-import-models.js";
import {
  type ExternalImportTarget,
  validateExternalEvidence,
} from "./external-import-contract.js";
import type { ExternalFinding, ExternalFindings } from "./external-findings.js";
import { canonicalJson, isRecord } from "./record.js";
import {
  array,
  normalizeRecords,
  readScannerJson,
  record,
  requiredText,
  stableId,
  text,
} from "./scanner-import.js";
import { FailureSeveritySchema } from "./scan-settings.js";
import {
  declaredScannerRepositoryUrl,
  repositoryScopeValidator,
} from "./scanner-repository-url.js";

const format = "blackduck-bom-6";
const componentVersionPath = /^components\/[^/]+\/versions\/[^/]+$/u;
const nativeId = /^blackduck-bom:[a-f0-9]{64}$/u;

export function projectedBlackDuckRepositoryUrl(
  finding: ExternalFinding,
  target: ExternalImportTarget,
): string | undefined {
  if (!nativeId.test(finding.source_finding_id)) return;
  const url = finding.evidence.source_data?.["sourceRepositoryUrl"];
  if (typeof url === "string")
    return declaredScannerRepositoryUrl(url, "Black Duck", target);
  return finding.evidence.details?.repository?.url ?? undefined;
}

function hasBlackDuckEvidence(data: unknown): boolean {
  if (!isRecord(data)) return false;
  return (
    data["format"] === format ||
    [data, data["row"]].some((row) => {
      if (!isRecord(row) || !isRecord(row["vulnerabilityWithRemediation"]))
        return false;
      const resource = parseApiResource(text(row["componentVersion"]));
      return resource !== undefined && componentVersionPath.test(resource.path);
    })
  );
}

function retainedRepository(
  provider: Provider,
  finding: ExternalFinding,
  target: ExternalImportTarget,
): { url: string; scope?: string } | undefined {
  const {
    source_finding_id: id,
    evidence: { source_data: data },
  } = finding;
  const nativeEvidence = hasBlackDuckEvidence(data);
  if (provider !== "blackduck") {
    if (nativeEvidence)
      throw new CodexSecurityError(
        "Retained Black Duck evidence requires the blackduck provider.",
      );
    const url = projectedBlackDuckRepositoryUrl(finding, target);
    return url ? { url } : undefined;
  }
  const native = nativeEvidence || nativeId.test(id);
  if (native && (!isRecord(data) || !isRecord(data["row"])))
    throw new Error("Expected retained Black Duck BOM occurrence evidence.");
  if (!isRecord(data) || (!native && !("sourceRepositoryUrl" in data))) return;
  const url = declaredScannerRepositoryUrl(
    data["sourceRepositoryUrl"],
    "Black Duck",
    target,
  );
  if (!native) return { url };
  const resource = apiResource(
    data["projectVersionUrl"],
    "retained project-version URL",
  );
  if (
    !/^projects\/[^/]+\/versions\/[^/]+$/u.test(resource.path) ||
    resource.query.size
  )
    throw new Error("Invalid retained Black Duck project-version URL.");
  const projectVersion = `${resource.base}/${resource.path}`;
  const actual = occurrenceId(
    scopedRow(data["row"], projectVersion, false),
    projectVersion,
  );
  if (id !== actual)
    throw new Error(
      "Black Duck source finding ID contradicts the retained native occurrence.",
    );
  return { url, scope: projectVersion };
}

export const blackDuckReportRepositories = repositoryScopeValidator(
  { provider: "blackduck", label: "Black Duck", scope: "project version" },
  retainedRepository,
);

function parseApiResource(href: string | null) {
  const url = href && URL.parse(href);
  const parts = url && /^(.*\/api)\/(.+?)\/?$/u.exec(url.pathname);
  if (
    !url ||
    !parts ||
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.hash
  )
    return;
  return {
    base: url.origin + parts[1],
    path: parts[2]!,
    query: url.searchParams,
  };
}

function apiResource(href: unknown, label: string) {
  const resource = parseApiResource(requiredText(href, label));
  if (!resource)
    throw new Error(
      `Expected a credential-free Black Duck API URL for ${label}.`,
    );
  return resource;
}

function links(meta: unknown): Record<string, unknown>[] {
  if (meta === undefined) return [];
  const value = record(meta, "Black Duck _meta")["links"];
  return value === undefined
    ? []
    : array(value, "Black Duck _meta.links").map((entry) =>
        record(entry, "Black Duck link"),
      );
}

function collectionScope(collection: Record<string, unknown>) {
  const meta = record(collection["_meta"], "Black Duck collection _meta");
  const resource = apiResource(meta["href"], "collection href");
  const project =
    /^projects?\/([^/]+)\/versions\/([^/]+)\/vulnerable-bom-components$/u.exec(
      resource.path,
    );
  if (!project)
    throw new Error(
      "Expected a Black Duck project-version vulnerable-bom-components collection.",
    );
  if (
    resource.query.getAll("offset").some((offset) => !/^0+$/u.test(offset)) ||
    links(meta).some((link) =>
      ["next", "prev", "previous"].includes(String(link["rel"])),
    )
  )
    throw new Error(
      "Incomplete Black Duck collection page. Supply a complete export or explicitly selected rows.",
    );
  return `${resource.base}/projects/${project[1]}/versions/${project[2]}`;
}

function projectReference(
  href: unknown,
  relation: "remediation" | "matched-files",
) {
  const label =
    relation === "remediation" ? "remediation URL" : "matched-files link";
  const resource = apiResource(href, label);
  const match =
    /^(projects\/[^/]+\/versions\/[^/]+)\/(components\/[^/]+\/versions\/[^/]+)(?:\/origins\/([^/]+))?\/(matched-files|vulnerabilities\/[^/]+\/remediation)$/u.exec(
      resource.path,
    );
  if (!match || !match[4]!.endsWith(relation))
    throw new Error(`Invalid Black Duck project-version ${label}.`);
  return {
    scope: `${resource.base}/${match[1]}`,
    component: `${resource.base}/${match[2]}`,
    origin: match[3],
  };
}

const bomComponent = z.object(
  {
    vulnerabilityWithRemediation: z.custom<Record<string, unknown>>(
      isRecord,
      "Black Duck vulnerabilityWithRemediation must be an object.",
    ),
  },
  "Black Duck BOM component must be an object.",
);

function scopedRow(
  value: unknown,
  scope: string | undefined,
  selected: boolean,
) {
  const row = isRecord(value) ? value : {};
  const meta = row["_meta"];
  const declared = isRecord(meta) ? meta["links"] : undefined;
  const matched = (Array.isArray(declared) ? declared : [])
    .filter(
      (link): link is Record<string, unknown> =>
        isRecord(link) && link["rel"] === "matched-files",
    )
    .map((link) => projectReference(link["href"], "matched-files"));
  if (isRecord(meta) && meta["href"] !== undefined)
    matched.push(projectReference(meta["href"], "remediation"));
  if (selected && !matched.length)
    throw new Error(
      "Each selected Black Duck row must identify its project version with a remediation or matched-files link.",
    );
  for (const reference of matched) {
    if (scope !== undefined && scope !== reference.scope)
      throw new Error(
        "Black Duck rows must belong to the same project version and server as the collection or selection.",
      );
    scope = reference.scope;
  }
  const component = bomComponent.safeParse(value);
  return {
    row,
    matched,
    scope,
    // Shape errors are row exclusions; project-scope errors abort the report.
    get vulnerability() {
      if (!component.success)
        throw new Error(component.error.issues[0]!.message);
      return component.data.vulnerabilityWithRemediation;
    },
  };
}

function occurrenceId(
  { row, vulnerability, matched }: ReturnType<typeof scopedRow>,
  projectVersion: string,
) {
  const resource = apiResource(row["componentVersion"], "componentVersion");
  const component = `${resource.base}/${resource.path}`;
  if (
    !componentVersionPath.test(resource.path) ||
    resource.base !==
      projectVersion.slice(0, projectVersion.lastIndexOf("/projects/"))
  )
    throw new Error(
      "Black Duck componentVersion must identify a component version on the same server.",
    );
  const origins = new Set<string>();
  for (const reference of matched) {
    if (reference.component !== component)
      throw new Error(
        "Black Duck project-version link contradicts componentVersion.",
      );
    if (reference.origin) origins.add(reference.origin);
  }
  for (const link of links(row["_meta"]).filter(
    (entry) => entry["rel"] === "vulnerabilities",
  )) {
    const reference = apiResource(link["href"], "vulnerabilities link");
    const match =
      /^(components\/[^/]+\/versions\/[^/]+)(?:\/origin\/([^/]+))?\/vulnerabilities$/u.exec(
        reference.path,
      );
    if (!match) continue;
    if (`${reference.base}/${match[1]}` !== component)
      throw new Error(
        "Black Duck vulnerabilities link contradicts componentVersion.",
      );
    if (match[2]) origins.add(match[2]);
  }
  const [origin] = origins;
  if (!origin || origins.size !== 1)
    throw new Error(
      "Black Duck row must identify one unambiguous component-version origin.",
    );
  const source = requiredText(
    vulnerability["source"],
    "Black Duck advisory source",
  );
  if (source !== "BDSA" && source !== "NVD")
    throw new Error(`Unsupported Black Duck advisory source: ${source}.`);
  return stableId("blackduck-bom", [
    projectVersion,
    component,
    origin,
    source,
    requiredText(
      vulnerability["vulnerabilityName"],
      "Black Duck vulnerability name",
    ),
  ]);
}

const nameVersionForges = new Map([
  ["npmjs", "npm"],
  ["pypi", "pypi"],
  ["nuget", "nuget"],
  ["rubygems", "gem"],
  ["crates", "cargo"],
]);

function packageUrlName(ecosystem: string, parts: string[]) {
  if (parts.some((part) => !part || part.includes("/"))) return;
  if (ecosystem === "maven" || ecosystem === "composer")
    return parts.length === 2
      ? parts.join(ecosystem === "maven" ? ":" : "/")
      : undefined;
  if (
    parts.length === 1 ||
    ecosystem === "golang" ||
    ecosystem === "generic" ||
    (parts.length === 2 && ecosystem === "npm" && parts[0]!.startsWith("@"))
  )
    return parts.join("/");
}

function originPackage(row: Record<string, unknown>) {
  const origin = text(row["componentVersionOriginName"])?.toLowerCase();
  const id = text(row["componentVersionOriginId"]) ?? "";
  if (origin === "maven") {
    const coordinate = /^([^:\s/]+:[^:\s/]+):([^:\s/]+)$/u.exec(id);
    if (coordinate)
      return {
        name: coordinate[1]!,
        ecosystem: origin,
        installed_version: coordinate[2]!,
      };
  }
  const ecosystem = nameVersionForges.get(origin ?? "");
  if (ecosystem) {
    const coordinate = /^(?:(@[^/\s]+)\/)?([^/\s]+)\/([^/\s]+)$/u.exec(id);
    if (coordinate && (!coordinate[1] || ecosystem === "npm"))
      return {
        name: id.slice(0, id.lastIndexOf("/")),
        ecosystem,
        installed_version: coordinate[3]!,
      };
  }
}

function blackDuckPackages(row: Record<string, unknown>) {
  const origin = originPackage(row);
  const purl =
    /^pkg:([a-z][a-z0-9.+-]*)\/((?:@[^/@?#]+\/)?[^@?#]+)(?:@([^@?#]+))?(?:[?#].*)?$/iu.exec(
      text(row["packageUrl"]) ?? "",
    );
  if (purl) {
    try {
      const ecosystem = purl[1]!.toLowerCase();
      const name = packageUrlName(
        ecosystem,
        purl[2]!.split("/").map(decodeURIComponent),
      );
      if (name) {
        if (!purl[3] && origin?.ecosystem === ecosystem && origin.name === name)
          return [origin];
        return [
          {
            name,
            ecosystem,
            installed_version: purl[3]
              ? decodeURIComponent(purl[3])
              : text(row["componentVersionName"]),
          },
        ];
      }
    } catch {
      // A malformed escape does not invalidate the native origin coordinate.
    }
  }

  return origin ? [origin] : [];
}

export function normalizeBlackDuckFindings(
  input: unknown,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const repository = declaredScannerRepositoryUrl(
    sourceRepositoryUrl,
    "Black Duck",
    target,
  );
  const selected = Array.isArray(input);
  let scope: string | undefined;
  let items: unknown[];
  if (selected) {
    items = input;
  } else {
    const collection = record(input, "Black Duck collection");
    items = array(collection["items"], "Black Duck items");
    scope = collectionScope(collection);
    if (collection["totalCount"] !== items.length)
      throw new Error(
        "Incomplete Black Duck collection: totalCount must equal the number of items. Supply a complete export or explicitly selected rows.",
      );
  }

  const rows = items.map((value) => {
    const entry = scopedRow(value, scope, selected);
    scope = entry.scope;
    return entry;
  });
  if (!scope)
    throw new Error(
      "An empty Black Duck selection cannot identify a project version. Supply its complete collection envelope.",
    );
  const projectVersion = scope;
  const result = normalizeRecords(
    rows,
    ({ row, vulnerability }) => {
      const advisory = requiredText(
        vulnerability["vulnerabilityName"],
        "Black Duck vulnerability name",
      );
      const name = requiredText(
        row["componentName"],
        "Black Duck component name",
      );
      const severity = text(vulnerability["severity"])?.toLowerCase();
      const related = text(vulnerability["relatedVulnerability"]);
      return validateExternalEvidence(
        {
          title: `${advisory} in ${name}`,
          description: text(vulnerability["description"]),
          severity: FailureSeveritySchema.safeParse(severity).data ?? "unknown",
          advisory_ids:
            related && related !== advisory ? [advisory, related] : [advisory],
          packages: blackDuckPackages(row),
          source_data: {
            format,
            sourceRepositoryUrl: repository,
            projectVersionUrl: projectVersion,
            row: structuredClone(row),
          },
        },
        target,
      );
    },
    (entry) => occurrenceId(entry, projectVersion),
    target,
  );
  if (!selected) {
    // normalizeRecords excludes every collision. An unidentified row can also
    // repeat across pages, so compare its original JSON when it has no ID.
    const seen = new Set<string>();
    for (const excluded of result.excluded) {
      const key =
        excluded.source_finding_id ??
        canonicalJson(items[excluded.position - 1]);
      if (seen.has(key))
        throw new CodexSecurityError(
          "Duplicate row in a collection with a declared total; pages may overlap. Retrieve the complete export again.",
        );
      seen.add(key);
    }
  }
  return result;
}

export async function readBlackDuckFindings(
  path: string,
  sourceRepositoryUrl: string,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeBlackDuckFindings(
    await readScannerJson(path),
    sourceRepositoryUrl,
    target,
  );
}
