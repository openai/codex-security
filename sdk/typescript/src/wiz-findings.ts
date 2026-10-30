import { CodexSecurityError } from "./errors.js";
import { canonicalJson } from "./record.js";
import {
  repositoryUrlKey,
  validateExternalEvidence,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import { parseJsonOrJsonl, readScannerText } from "./scanner-import.js";
import { readWizCsv, wizCsvFinding } from "./wiz-csv.js";
import type {
  ExternalFinding as VendorFinding,
  ExternalFindings as VendorFindings,
  ExternalSourceRepository,
} from "./external-findings.js";

export type {
  ExternalFinding as VendorFinding,
  ExternalFindings as VendorFindings,
} from "./external-findings.js";

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function sourceFindingId(value: unknown, target: ExternalImportTarget): string {
  const id = text(value);
  if (
    !id ||
    id.includes("\0") ||
    (target === "cloud" && Buffer.byteLength(id) > 512)
  )
    throw new Error(
      target === "cloud"
        ? "Source finding id must contain 1–512 UTF-8 bytes and no NUL characters."
        : "Source finding id must be nonempty and contain no NUL characters.",
    );
  return id;
}

/** Keep a Wiz vulnerability occurrence intact; advisory names are not identities. */
function wizFinding(
  record: Record<string, unknown>,
  target: ExternalImportTarget,
): VendorFinding {
  if (record["detectionMethod"] === "EXTERNAL_NETWORK_SCAN")
    throw new Error(
      "Wiz external network findings are not supported by the package vulnerability mapping.",
    );
  const id = sourceFindingId(record["id"], target);
  const name = text(record["name"]);
  const packageName = text(record["detailedName"]);
  const version = text(record["version"]);
  const severity = (
    text(record["vendorSeverity"]) ?? text(record["severity"])
  )?.toLowerCase();
  const asset = object(record["vulnerableAsset"]);
  const artifact = object(record["artifactType"]);
  if (!name || !packageName || !text(asset?.["id"])) {
    throw new Error(
      "Expected a Wiz package vulnerability finding with name, detailedName, and vulnerableAsset.id. Other finding classes need a separate mapping.",
    );
  }
  const assetType = text(asset?.["type"]);
  const repositoryAsset =
    assetType === "REPOSITORY_BRANCH" ||
    asset?.["nativeType"] === "github#repositoryBranch";
  // Wiz repository reports prefix root-relative paths with '/'. Workload paths
  // are not source locations and must remain only in the original evidence.
  const locationPath = text(record["locationPath"]);
  const repositoryPath =
    repositoryAsset && locationPath ? locationPath.replace(/^\/+/, "") : null;
  const digest =
    text(asset?.["imageDigest"]) ??
    text(record["imageDigest"]) ??
    (assetType === null ||
    assetType === "CONTAINER_IMAGE" ||
    assetType === "CONTAINER"
      ? (text(asset?.["imageId"]) ??
        text(asset?.["containerImageId"]) ??
        text(asset?.["ImageExternalId"]))
      : null);
  // lastDetectedAt is not proof that the entire vendor record was updated.
  const evidence = {
    title:
      text(record["title"]) ??
      [packageName, version, name].filter(Boolean).join(" "),
    description: text(record["description"]),
    severity: severity === "none" ? "unknown" : severity,
    url: text(record["portalUrl"]),
    advisory_ids: [text(record["vulnerabilityExternalId"]) ?? name],
    packages: [
      {
        name: packageName,
        ecosystem:
          text(record["packageManager"]) ??
          text(artifact?.["osPackageManager"]) ??
          text(artifact?.["codeLibraryLanguage"]) ??
          text(record["codeLibraryLanguage"]),
        installed_version: version,
        manifest_path: repositoryPath,
        fixed_versions: text(record["fixedVersion"])
          ? [record["fixedVersion"]]
          : [],
      },
    ],
    locations: repositoryPath ? [{ path: repositoryPath }] : [],
    branch: null,
    code_revision: null,
    source_scan_id: null,
    image_digests: digest ? [digest] : [],
    source_updated_at: updatedAt(record["updatedAt"], "updatedAt"),
    source_data: record,
  };
  return {
    source_finding_id: id,
    evidence: validateExternalEvidence(evidence, target),
  };
}

type RepositoryFindingKind = "sast" | "secret" | "iac";

type InputRecord = {
  value: unknown;
  kind?: "sca" | "sca_csv" | RepositoryFindingKind | "cloud_configuration";
};

type RepositoryMetadata = {
  id: string | null;
  name: string | null;
  url: string;
};

type FindingInput = {
  records: InputRecord[];
  repositories: Map<string, RepositoryMetadata & { platform: string | null }>;
  legacyRepositories?: FindingInput["repositories"];
};

// Wiz's documented inventory platform establishes custom GitHub host semantics.
// Keep this context separate from the repository metadata published as evidence.
function inventoryRepositoryUrlKey(
  value: string,
  platform: string | null | undefined,
): string {
  const key = repositoryUrlKey(value);
  return platform === "GITHUB" ? key.toLowerCase() : key;
}

function sourceRepository(
  repository: Record<string, unknown> | undefined,
  repositories: FindingInput["repositories"],
): RepositoryMetadata {
  const id = text(repository?.["id"]);
  const inventory = id ? repositories.get(id) : undefined;
  const suppliedUrl = text(repository?.["url"]);
  if (
    suppliedUrl &&
    inventory &&
    inventoryRepositoryUrlKey(suppliedUrl, inventory.platform) !==
      inventoryRepositoryUrlKey(inventory.url, inventory.platform)
  )
    throw new Error(
      "The finding and repository inventory have conflicting repository URLs.",
    );
  const url = suppliedUrl ?? inventory?.url;
  if (!url)
    throw new Error(
      "A verified source repository URL is required. Include repository.url or the matching repository.id and repository.url from data.versionControlResources.nodes; names and Wiz IDs are not Cloud repository IDs.",
    );
  return {
    id,
    name: text(repository?.["name"]) ?? inventory?.name ?? null,
    url,
  };
}

function sourceBranch(
  branch: Record<string, unknown> | undefined,
  repository: RepositoryMetadata,
  legacy = false,
): string | null {
  const name = text(branch?.["name"]);
  if (!name) return null;
  // Repository names and URL paths can both be literal branch prefixes. Keep
  // the old mapping only for an already approved publication checkpoint.
  if (!legacy) return name;
  const qualifiers = repository.name ? [repository.name] : [];

  // Include the URL qualifier before selecting the longest repository prefix.
  // Keep URL normalization and the branch suffix's original case and slashes.
  const repositoryKey = repositoryUrlKey(repository.url).toLowerCase();
  const url = /^(https?:\/\/[^/?#]+)\/([^?#]+)$/iu.exec(repositoryKey);
  if (url) {
    const prefixParts = url[2]!.split("/").length;
    const parts = name.split("/");
    const qualifier = parts.slice(0, prefixParts).join("/");
    if (
      parts.length > prefixParts &&
      repositoryUrlKey(url[1] + "/" + qualifier).toLowerCase() === repositoryKey
    )
      qualifiers.push(qualifier);
  }
  for (const qualifier of qualifiers.sort(
    (left, right) => right.length - left.length,
  )) {
    const prefix = qualifier + "/";
    if (name.toLowerCase().startsWith(prefix.toLowerCase()))
      return name.slice(prefix.length) || null;
  }
  return url || repository.name ? name : null;
}

function updatedAt(value: unknown, field: string): number | null {
  const timestamp = text(value);
  if (!timestamp) return null;
  const seconds = Date.parse(timestamp) / 1000;
  if (!Number.isFinite(seconds) || seconds < 0)
    throw new Error(`Wiz ${field} is not a valid timestamp.`);
  return Math.floor(seconds);
}

// Empty code and configuration strings are meaningful vendor evidence.
function content(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/** Map only explicitly identified repository finding collections. */
function repositoryFinding(
  kind: RepositoryFindingKind,
  record: Record<string, unknown>,
  repositories: FindingInput["repositories"],
  legacy = false,
  target: ExternalImportTarget = "cloud",
): VendorFinding {
  const id = sourceFindingId(record["id"], target);
  const resource = object(record["resource"]);
  if (kind === "secret" && resource?.["type"] !== "REPOSITORY_BRANCH")
    throw new Error(
      "Only repository-branch secret findings can be published to a repository. Workload secrets require a resource-scoped import and are not supported.",
    );
  const suppliedRepository =
    kind === "secret"
      ? object(object(resource?.["typedProperties"])?.["repository"])
      : object(record["repository"]);
  const repository = sourceRepository(suppliedRepository, repositories);
  const branch =
    kind === "secret"
      ? resource
      : object(record[kind === "sast" ? "repositoryBranch" : "branch"]);
  const rule = object(record["rule"]);
  const path = text(record[kind === "secret" ? "path" : "filePath"]);
  const line = record[kind === "secret" ? "lineNumber" : "startLine"];
  const details = {
    kind,
    repository,
    source_status: text(record["status"]),
    scanner_origin: kind === "sast" ? text(record["origin"]) : null,
    scanner_verdict:
      kind === "sast" ? text(object(record["aiAnalysis"])?.["verdict"]) : null,
    rule: rule
      ? {
          id: text(rule["id"]),
          short_id: text(rule["shortId"]),
          name: text(rule["name"]),
        }
      : null,
    weakness_ids:
      kind === "sast" && Array.isArray(record["weaknesses"])
        ? record["weaknesses"].map((weakness) => object(weakness)?.["id"])
        : [],
    remediation_instructions:
      text(record["remediationInstructions"]) ??
      text(rule?.["remediationInstructions"]),
    code:
      path && kind !== "secret"
        ? {
            end_line: record["endLine"] ?? null,
            snippet: content(
              record[kind === "sast" ? "snippet" : "matchContent"],
            ),
          }
        : null,
    secret:
      kind === "secret"
        ? {
            type: text(record["type"]),
            confidence: text(record["confidence"]),
            validation_status: text(record["validationStatus"]),
            is_encrypted: record["isEncrypted"] ?? null,
            is_managed: record["isManaged"] ?? null,
            introduced_commit: text(
              object(record["vcsDetails"])?.["initialCommitHash"],
            ),
          }
        : null,
    configuration:
      kind === "iac"
        ? {
            platform: text(record["platform"]),
            cloud_platform: text(record["cloudPlatform"]),
            expected: content(record["expectedContent"]),
            actual: content(record["foundContent"]),
          }
        : null,
    file_url: text(record["fileURL"]),
  };
  return {
    // Existing package occurrence IDs remain unchanged. New families cannot
    // collide with one another when the same tenant source key is used.
    source_finding_id: sourceFindingId(`${kind}:${id}`, target),
    evidence: validateExternalEvidence(
      {
        title: text(record["name"]) ?? text(rule?.["name"]),
        severity: text(record["severity"])?.toLowerCase(),
        description: text(record["description"]) ?? text(rule?.["description"]),
        url: text(record["wizUrl"]) ?? text(record["portalUrl"]),
        locations: path ? [{ path, line: line ?? null }] : [],
        branch: sourceBranch(branch, repository, legacy),
        code_revision: null,
        source_scan_id: null,
        source_updated_at:
          kind === "secret"
            ? updatedAt(record["lastUpdatedAt"], "lastUpdatedAt")
            : kind === "iac"
              ? updatedAt(record["updatedAt"], "updatedAt")
              : null,
        source_data: record,
        details,
      },
      target,
    ),
  };
}

function records(payload: unknown): FindingInput {
  const repositories: FindingInput["repositories"] = new Map();
  const legacyRepositories: FindingInput["repositories"] = new Map();
  if (Array.isArray(payload))
    return { records: payload.map((value) => ({ value })), repositories };
  const envelope = object(payload);
  if (!envelope)
    throw new Error(
      "Expected finding objects or a named Wiz finding collection.",
    );
  if (
    object(envelope["scannersRunStatuses"]) &&
    object(envelope["codeAnalyzerDetails"])
  )
    throw new Error(
      "This is a Wiz Code & Build Scan event, which contains scan metadata rather than vulnerability records. In Vulnerability Findings, filter the repository and selection, then choose Save as → Report with JSON format and Detailed columns. Download that report instead of Raw Event.",
    );
  if (Array.isArray(envelope["errors"]) && envelope["errors"].length > 0)
    throw new Error(
      "Wiz returned GraphQL errors. Resolve them before publishing this response.",
    );
  if (
    envelope["source_finding_id"] !== undefined ||
    envelope["id"] !== undefined
  )
    return { records: [{ value: envelope }], repositories };
  const data = object(envelope["data"]) ?? envelope;
  const inventory = object(data["versionControlResources"]);
  if (object(inventory?.["pageInfo"])?.["hasNextPage"] === true)
    throw new Error(
      "Wiz repository inventory has another page. Finish the selected inventory before publishing.",
    );
  if (Array.isArray(inventory?.["nodes"])) {
    const entries = inventory["nodes"].flatMap((entry) => {
      const node = object(entry);
      const repository = object(node?.["repository"]);
      const id = text(repository?.["id"]);
      const url = text(repository?.["url"]);
      return id && url
        ? [
            {
              id,
              name: text(repository?.["name"]),
              url,
              platform: text(node?.["platform"]),
            },
          ]
        : [];
    });
    // Resolve provider hints before comparing URLs, so duplicate row order cannot
    // discard a known platform or reject a case variant before its GITHUB hint.
    for (const entry of entries) {
      const previous = repositories.get(entry.id);
      if (
        previous?.platform &&
        entry.platform &&
        previous.platform !== entry.platform
      )
        throw new Error(
          `Repository inventory contains conflicting platforms for ${JSON.stringify(entry.id)}.`,
        );
      repositories.set(entry.id, {
        ...entry,
        // Equivalent inventory aliases must produce the same evidence when the
        // export reorders its rows. Keep a stable supplied URL and nonempty name.
        url: previous && previous.url < entry.url ? previous.url : entry.url,
        name:
          previous?.name && (!entry.name || previous.name < entry.name)
            ? previous.name
            : entry.name,
        platform: entry.platform ?? previous?.platform ?? null,
      });
      legacyRepositories.set(entry.id, {
        ...entry,
        platform: entry.platform ?? previous?.platform ?? null,
      });
    }
    for (const entry of entries) {
      const resolved = repositories.get(entry.id)!;
      if (
        inventoryRepositoryUrlKey(entry.url, resolved.platform) !==
        inventoryRepositoryUrlKey(resolved.url, resolved.platform)
      )
        throw new Error(
          `Repository inventory contains conflicting URLs for ${JSON.stringify(entry.id)}.`,
        );
    }
  }
  const collections = {
    vulnerabilityFindings: "sca",
    sastFindings: "sast",
    secretInstances: "secret",
    iacFindings: "iac",
    configurationFindings: "cloud_configuration",
  } as const;
  const selected: InputRecord[] = [];
  let found = false;
  for (const [root, kind] of Object.entries(collections)) {
    const collection = object(data[root]);
    if (!collection) continue;
    found = true;
    if (!Array.isArray(collection["nodes"]))
      throw new Error(`Wiz ${root}.nodes must be an array.`);
    if (object(collection["pageInfo"])?.["hasNextPage"] === true)
      throw new Error(
        "Wiz response has another page. Complete the requested pages or save the explicitly selected records in their named collection before publishing.",
      );
    for (const value of collection["nodes"]) selected.push({ value, kind });
  }
  if (found)
    return {
      records: selected,
      repositories,
      legacyRepositories,
    };
  throw new Error(
    "Unsupported Wiz export. Supply repository vulnerability CSV, vulnerability finding objects, named sastFindings/secretInstances/iacFindings collections, or normalized JSONL. Other CSV reports need an explicit normalized JSONL mapping.",
  );
}

export async function readVendorFindings(
  path: string,
  target: ExternalImportTarget = "cloud",
): Promise<VendorFindings> {
  return normalizeFindings(await readFindingInput(path), target);
}

/** @internal Preserve older inventory projections only for saved publication replay. */
export async function readVendorFindingsForPublication(
  path: string,
  target: ExternalImportTarget = "cloud",
): Promise<{
  current: VendorFindings;
  legacy: VendorFindings;
  currentIdentity: unknown[];
  legacyIdentity: unknown[];
  sourceRepositories: ExternalSourceRepository[];
}> {
  const input = await readFindingInput(path);
  const normalized = new WeakSet<VendorFinding>();
  const current = normalizeFindings(input, target, normalized);
  const legacy = normalizeFindings(
    { ...input, repositories: input.legacyRepositories ?? input.repositories },
    target,
    normalized,
    true,
  );
  const identity = (parsed: VendorFindings) =>
    parsed.findings.map((finding) => {
      if (normalized.has(finding)) return finding;
      const repository = finding.evidence.details?.repository;
      return {
        source_finding_id: finding.source_finding_id,
        evidence: {
          // Raw vendor records retain every original branch/ref and source field.
          // Inventory display aliases must not change an outstanding request's identity.
          source_data: finding.evidence.source_data,
          repository: repository
            ? {
                id: repository.id,
                // Publication targets use Cloud's GitHub URL semantics. Input
                // joins above still require provenance for custom-host folding.
                url: repositoryUrlKey(repository.url).toLowerCase(),
              }
            : null,
        },
      };
    });
  return {
    current,
    legacy,
    currentIdentity: identity(current),
    legacyIdentity: identity(legacy),
    sourceRepositories: current.findings.flatMap(({ evidence }) => {
      const repository = evidence.details?.repository;
      const inventory = input.repositories.get(repository?.id ?? "");
      // Forward provenance only for selected findings that match the inventory.
      // Use the emitted spelling so typed evidence and reader hints share it.
      return repository &&
        inventory?.platform === "GITHUB" &&
        inventoryRepositoryUrlKey(repository.url, inventory.platform) ===
          inventoryRepositoryUrlKey(inventory.url, inventory.platform)
        ? [{ url: repository.url, platform: "github" as const }]
        : [];
    }),
  };
}

async function readFindingInput(path: string): Promise<FindingInput> {
  try {
    const contents = await readScannerText(path);
    let payload: unknown;
    try {
      payload = JSON.parse(contents);
    } catch {
      const csv = readWizCsv(contents);
      if (csv)
        return {
          records: csv.map((value) => ({ value, kind: "sca_csv" })),
          repositories: new Map(),
        };
      payload = parseJsonOrJsonl(contents);
    }
    return records(payload);
  } catch (cause) {
    throw new CodexSecurityError(
      `Could not read vendor findings as UTF-8 JSON, JSONL, or Wiz CSV: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
}

/** Apply Wiz's own reader to an occurrence that also retains another scanner's fields. */
export function isWizOccurrence(
  finding: VendorFinding,
  target: ExternalImportTarget,
): boolean {
  const { source_data: data, details } = finding.evidence;
  if (!data || typeof data["id"] !== "string") return false;
  const kind = details?.kind;
  const scoped = kind === "sast" || kind === "iac" || kind === "secret";
  if (
    finding.source_finding_id !==
    (scoped ? `${kind}:${data["id"]}` : data["id"])
  )
    return false;
  const input: FindingInput = {
    records: [{ value: data, kind: scoped ? kind : "sca" }],
    repositories: new Map(),
  };
  const repository = details?.repository;
  if (scoped && repository?.id)
    input.repositories.set(repository.id, {
      id: repository.id,
      name: repository.name ?? null,
      url: repository.url,
      platform: null,
    });
  // The raw record is the same. Check that Wiz produced the selected evidence,
  // including its own repository binding, before treating upstream fields as opaque.
  const selected = canonicalJson({
    ...validateExternalEvidence(finding.evidence, target),
    source_data: undefined,
  });
  const matches = (legacy: boolean) => {
    const [row] = normalizeFindings(input, target, undefined, legacy).findings;
    return (
      row !== undefined &&
      canonicalJson({ ...row.evidence, source_data: undefined }) === selected
    );
  };
  return matches(false) || (scoped && matches(true));
}

function normalizeFindings(
  input: FindingInput,
  target: ExternalImportTarget,
  normalized?: WeakSet<VendorFinding>,
  legacy = false,
): VendorFindings {
  const result: VendorFindings = {
    read: input.records.length,
    findings: [],
    excluded: [],
  };
  const identities = new Set<string>();
  for (const [index, item] of input.records.entries()) {
    const record = object(item.value);
    try {
      if (!record) throw new Error("Finding must be an object.");
      let finding: VendorFinding;
      if (item.kind === "sca_csv") {
        finding = wizCsvFinding(
          record,
          sourceFindingId(record["ID"], target),
          target,
        );
      } else if ("source_finding_id" in record) {
        if (
          Object.keys(record).some(
            (key) => !["source_finding_id", "evidence"].includes(key),
          )
        ) {
          throw new Error(
            "Normalized input permits only source_finding_id and evidence.",
          );
        }
        finding = {
          source_finding_id: sourceFindingId(
            record["source_finding_id"],
            target,
          ),
          evidence: validateExternalEvidence(record["evidence"], target),
        };
      } else if (item.kind === "cloud_configuration") {
        throw new Error(
          "Cloud configuration findings require a resource-scoped import and cannot be published to a repository.",
        );
      } else if (item.kind && item.kind !== "sca") {
        finding = repositoryFinding(
          item.kind,
          record,
          input.repositories,
          legacy,
          target,
        );
      } else {
        if (
          !item.kind &&
          (object(record["repository"]) ||
            object(record["repositoryBranch"]) ||
            object(record["resource"]))
        )
          throw new Error(
            "Raw SAST, secret, and IaC records require their named sastFindings, secretInstances, or iacFindings collection. Bare arrays do not identify the finding family; use normalized JSONL for an explicit mapping.",
          );
        finding = wizFinding(record, target);
      }
      if (identities.has(finding.source_finding_id)) {
        throw new CodexSecurityError(
          `Duplicate source finding id ${JSON.stringify(finding.source_finding_id)}. Select each vendor occurrence once.`,
        );
      }
      identities.add(finding.source_finding_id);
      result.findings.push(finding);
      if (item.kind !== "sca_csv" && "source_finding_id" in record)
        normalized?.add(finding);
    } catch (error) {
      if (error instanceof CodexSecurityError) throw error;
      result.excluded.push({
        position: index + 1,
        source_finding_id:
          item.kind === "sca_csv"
            ? text(record?.["ID"])
            : (text(record?.["source_finding_id"]) ?? text(record?.["id"])),
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return result;
}
