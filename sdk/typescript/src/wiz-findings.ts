import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { gunzip } from "node:zlib";
import { CodexSecurityError } from "./errors.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";

const decompressGzip = promisify(gunzip);

export interface VendorFinding {
  source_finding_id: string;
  evidence: ExternalFindingEvidence;
}

export interface VendorFindings {
  read: number;
  findings: VendorFinding[];
  excluded: {
    position: number;
    source_finding_id: string | null;
    reason: string;
  }[];
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function sourceFindingId(value: unknown): string {
  const id = text(value);
  if (!id || id.includes("\0") || Buffer.byteLength(id) > 512)
    throw new Error(
      "Source finding id must contain 1–512 UTF-8 bytes and no NUL characters.",
    );
  return id;
}

/** Keep a Wiz vulnerability occurrence intact; advisory names are not identities. */
function wizFinding(record: Record<string, unknown>): VendorFinding {
  if (record["detectionMethod"] === "EXTERNAL_NETWORK_SCAN")
    throw new Error(
      "Wiz external network findings are not supported by the package vulnerability mapping.",
    );
  const id = sourceFindingId(record["id"]);
  const name = text(record["name"]);
  const packageName = text(record["detailedName"]);
  const version = text(record["version"]);
  const severity = text(record["vendorSeverity"]) ?? text(record["severity"]);
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
  const updated = text(record["updatedAt"]);
  const updatedSeconds = updated ? Date.parse(updated) / 1000 : null;
  if (
    updatedSeconds !== null &&
    (!Number.isFinite(updatedSeconds) || updatedSeconds < 0)
  ) {
    throw new Error("Wiz updatedAt is not a valid timestamp.");
  }
  // lastDetectedAt is not proof that the entire vendor record was updated.
  const evidence = {
    title:
      text(record["title"]) ??
      [packageName, version, name].filter(Boolean).join(" "),
    description: text(record["description"]),
    severity: severity?.toLowerCase(),
    url: text(record["portalUrl"]),
    advisory_ids: [text(record["vulnerabilityExternalId"]) ?? name],
    packages: packageName
      ? [
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
        ]
      : [],
    locations: repositoryPath ? [{ path: repositoryPath }] : [],
    branch: null,
    code_revision: null,
    source_scan_id: null,
    image_digests: digest ? [digest] : [],
    source_updated_at:
      updatedSeconds === null ? null : Math.floor(updatedSeconds),
    source_data: record,
  };
  return {
    source_finding_id: id,
    evidence: validateExternalEvidence(evidence),
  };
}

type RepositoryFindingKind = "sast" | "secret" | "iac";

type InputRecord = {
  value: unknown;
  kind?: "sca" | RepositoryFindingKind | "cloud_configuration";
};

type RepositoryMetadata = {
  id: string | null;
  name: string | null;
  url: string;
};

type FindingInput = {
  records: InputRecord[];
  repositories: Map<string, RepositoryMetadata>;
};

function repositoryUrl(value: string): string {
  return value.replace(/\/$/u, "").replace(/\.git$/u, "");
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
    repositoryUrl(suppliedUrl) !== repositoryUrl(inventory.url)
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
  repositoryName: string | null,
): string | null {
  const name = text(branch?.["name"]);
  const prefix = repositoryName ? `${repositoryName}/` : null;
  return name && prefix && name.startsWith(prefix)
    ? name.slice(prefix.length) || null
    : name;
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
): VendorFinding {
  const id = sourceFindingId(record["id"]);
  const resource = object(record["resource"]);
  if (kind === "secret" && resource?.["type"] !== "REPOSITORY_BRANCH")
    throw new Error(
      "Only repository-branch secret findings can be published to a repository. Workload secrets require a resource-scoped import and are not supported.",
    );
  const repository = sourceRepository(
    kind === "secret"
      ? object(object(resource?.["typedProperties"])?.["repository"])
      : object(record["repository"]),
    repositories,
  );
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
    source_finding_id: sourceFindingId(`${kind}:${id}`),
    evidence: validateExternalEvidence({
      title: text(record["name"]) ?? text(rule?.["name"]),
      severity: text(record["severity"])?.toLowerCase(),
      description: text(record["description"]) ?? text(rule?.["description"]),
      url: text(record["wizUrl"]) ?? text(record["portalUrl"]),
      locations: path ? [{ path, line: line ?? null }] : [],
      branch: sourceBranch(branch, repository.name),
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
    }),
  };
}

function records(payload: unknown): FindingInput {
  const repositories: FindingInput["repositories"] = new Map();
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
    for (const entry of inventory["nodes"]) {
      const repository = object(object(entry)?.["repository"]);
      const id = text(repository?.["id"]);
      const url = text(repository?.["url"]);
      if (!id || !url) continue;
      const previous = repositories.get(id);
      if (previous && repositoryUrl(previous.url) !== repositoryUrl(url))
        throw new Error(
          `Repository inventory contains conflicting URLs for ${JSON.stringify(id)}.`,
        );
      repositories.set(id, { id, name: text(repository?.["name"]), url });
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
    selected.push(...collection["nodes"].map((value) => ({ value, kind })));
  }
  if (found) return { records: selected, repositories };
  throw new Error(
    "Unsupported Wiz export. Supply vulnerability finding objects, named sastFindings/secretInstances/iacFindings collections, or normalized JSONL. CSV reports must be converted to the documented normalized JSONL profile.",
  );
}

export async function readVendorFindings(
  path: string,
): Promise<VendorFindings> {
  let input: FindingInput;
  try {
    // Wiz's default report export is gzip, sometimes with a .json filename.
    // Inspect the bytes rather than requiring users to rename their download.
    const bytes = await readFile(path);
    const decoded =
      bytes[0] === 0x1f && bytes[1] === 0x8b
        ? await decompressGzip(bytes)
        : bytes;
    // A replacement character would change vendor identities and retained evidence.
    const contents = new TextDecoder("utf-8", { fatal: true }).decode(decoded);
    let payload: unknown;
    try {
      payload = JSON.parse(contents);
    } catch {
      payload = contents
        .split(/\r?\n/u)
        .filter((line) => line.trim())
        .map((line) => JSON.parse(line));
    }
    input = records(payload);
  } catch (cause) {
    throw new CodexSecurityError(
      `Could not read vendor findings as UTF-8 JSON or JSONL: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
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
      if ("source_finding_id" in record) {
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
          source_finding_id: sourceFindingId(record["source_finding_id"]),
          evidence: validateExternalEvidence(record["evidence"]),
        };
      } else if (item.kind === "cloud_configuration") {
        throw new Error(
          "Cloud configuration findings require a resource-scoped import and cannot be published to a repository.",
        );
      } else if (item.kind && item.kind !== "sca") {
        finding = repositoryFinding(item.kind, record, input.repositories);
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
        finding = wizFinding(record);
      }
      if (identities.has(finding.source_finding_id)) {
        throw new CodexSecurityError(
          `Duplicate source finding id ${JSON.stringify(finding.source_finding_id)}. Select each vendor occurrence once.`,
        );
      }
      identities.add(finding.source_finding_id);
      result.findings.push(finding);
    } catch (error) {
      if (error instanceof CodexSecurityError) throw error;
      result.excluded.push({
        position: index + 1,
        source_finding_id:
          text(record?.["source_finding_id"]) ?? text(record?.["id"]),
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return result;
}
