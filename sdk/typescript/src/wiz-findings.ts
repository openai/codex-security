import { readFile } from "node:fs/promises";
import { CodexSecurityError } from "./errors.js";
import { validateExternalEvidence } from "./external-import-contract.js";
import type { ExternalFindingEvidence } from "./external-import-models.js";

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

/** Keep a Wiz vulnerability occurrence intact; advisory names are not identities. */
function wizFinding(record: Record<string, unknown>): VendorFinding {
  const id = text(record["id"]);
  if (!id) throw new Error("Wiz vulnerability finding is missing its id.");
  const name = text(record["name"]);
  const packageName = text(record["detailedName"]);
  const version = text(record["version"]);
  const severity = text(record["vendorSeverity"]) ?? text(record["severity"]);
  const asset = object(record["vulnerableAsset"]);
  if (!name || !packageName || !text(asset?.["id"])) {
    throw new Error(
      "Expected a Wiz package vulnerability finding with name, detailedName, and vulnerableAsset.id. Other finding classes need a separate mapping.",
    );
  }
  const digest = text(asset?.["imageDigest"]) ?? text(record["imageDigest"]);
  const updated = text(record["updatedAt"]);
  const updatedSeconds = updated ? Date.parse(updated) / 1000 : null;
  if (
    updatedSeconds !== null &&
    (!Number.isFinite(updatedSeconds) || updatedSeconds < 0)
  ) {
    throw new Error("Wiz updatedAt is not a valid timestamp.");
  }
  // Container paths and lastDetectedAt are retained in source_data; neither is a
  // repository location or proof that the entire vendor record was updated.
  const evidence = {
    title:
      text(record["title"]) ??
      [packageName, version, name].filter(Boolean).join(" "),
    description: text(record["description"]),
    severity: severity?.toLowerCase(),
    url: text(record["portalUrl"]),
    advisory_ids: name ? [name] : [],
    packages: packageName
      ? [
          {
            name: packageName,
            ecosystem: text(record["packageManager"]),
            installed_version: version,
            manifest_path: null,
            fixed_versions: text(record["fixedVersion"])
              ? [record["fixedVersion"]]
              : [],
          },
        ]
      : [],
    locations: [],
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

function records(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload;
  const envelope = object(payload);
  if (!envelope)
    throw new Error(
      "Expected finding objects or a Wiz vulnerabilityFindings response.",
    );
  if (Array.isArray(envelope["errors"]) && envelope["errors"].length > 0) {
    throw new Error(
      "Wiz returned GraphQL errors. Resolve them before publishing this response.",
    );
  }
  if (
    envelope["source_finding_id"] !== undefined ||
    envelope["id"] !== undefined
  )
    return [envelope];
  const data = object(envelope["data"]) ?? envelope;
  const findings = object(data["vulnerabilityFindings"]);
  if (findings && Array.isArray(findings["nodes"])) {
    const page = object(findings["pageInfo"]);
    if (page?.["hasNextPage"] === true) {
      throw new Error(
        "Wiz response has another page. Save the explicitly selected records as an array before publishing.",
      );
    }
    return findings["nodes"];
  }
  throw new Error(
    "Unsupported Wiz export. Supply vulnerability finding objects or normalized JSONL.",
  );
}

export async function readVendorFindings(
  path: string,
): Promise<VendorFindings> {
  const contents = (await readFile(path, "utf8")).replace(/^\uFEFF/u, "");
  let input: unknown[];
  try {
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
      `Could not read vendor findings: ${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
  }
  const result: VendorFindings = {
    read: input.length,
    findings: [],
    excluded: [],
  };
  const identities = new Set<string>();
  for (const [index, item] of input.entries()) {
    const record = object(item);
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
        const id = text(record["source_finding_id"]);
        if (!id || Buffer.byteLength(id) > 512)
          throw new Error("Source finding id must contain 1–512 UTF-8 bytes.");
        finding = {
          source_finding_id: id,
          evidence: validateExternalEvidence(record["evidence"]),
        };
      } else {
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
