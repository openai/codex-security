import * as z from "zod/v4";
import { isAbsolute, posix } from "node:path";
import { isRecord as isObject } from "./record.js";
import { artifactSchemaDocuments } from "./artifact-contracts.js";
import { projectArtifactToolSchema } from "./artifact-schema-loader.js";
import {
  requireObject,
  validateFindingSemantics,
  type SemanticScan,
} from "../../../../sdk/typescript/src/scan-semantics.js";
type JsonObject = Record<string, unknown>;
type ScanDraftInput = SemanticScan;
// File-authored scan IDs are host-owned; findings use the current tool contract.
const fileScanDraftInputSchema = projectArtifactToolSchema(
  artifactSchemaDocuments["tools/scan-draft"].$defs.scanDraftInput,
).extend({ scanId: z.string().min(1) });

function safeRelativePath(value: string, context: string): string {
  const parts = value.split("/");
  if (
    value.length === 0 ||
    Buffer.from(value, "utf8").toString("utf8") !== value ||
    value === "." ||
    value.startsWith("/") ||
    /^[A-Za-z]:/.test(value) ||
    parts.includes("..") ||
    value.includes("\\") ||
    /[\u0000-\u001f]/u.test(value)
  ) {
    throw new Error(`${context}: expected a safe scan-relative POSIX path.`);
  }
  const normalized = posix.normalize(value).replace(/\/+$/, "");
  if (
    normalized === "." ||
    normalized.startsWith("../") ||
    isAbsolute(normalized)
  ) {
    throw new Error(`${context}: expected a safe scan-relative POSIX path.`);
  }
  return normalized;
}

export function parseCanonicalScanDraft(input: {
  scanId?: string;
  manifest: JsonObject;
  findings: JsonObject;
  coverage: JsonObject;
}): ScanDraftInput {
  const scan = requireObject(input.manifest.scan, "scan draft manifest.scan");
  for (const scanId of [
    scan.id,
    input.findings.scanId,
    input.coverage.scanId,
  ]) {
    if (scanId !== undefined && scanId !== input.scanId) {
      throw new Error(
        "scan draft: canonical documents belong to a different scan.",
      );
    }
  }
  return parseCanonicalCheckpoint({
    scanId: input.scanId,
    ...(scan.complete === undefined ? {} : { complete: scan.complete }),
    ...(scan.scope === undefined ? {} : { scope: scan.scope }),
    ...(scan.threatModel === undefined
      ? {}
      : { threatModel: scan.threatModel }),
    findings: input.findings.findings,
    coverage: input.coverage,
  });
}

export function parseCanonicalCheckpoint(
  input: Record<string, unknown>,
): ScanDraftInput {
  const parsed = parsePersistedCheckpoint(input);
  for (const [index, finding] of parsed.findings.entries()) {
    for (const field of ["locations", "codeEvidence"] as const) {
      for (const [locationIndex, location] of (
        (finding[field] as JsonObject[] | undefined) ?? []
      ).entries()) {
        safeRelativePath(
          location.path as string,
          `findings[${index}].${field}[${locationIndex}].path`,
        );
      }
    }
  }
  return parsed;
}

function parsePersistedCheckpoint(
  input: Record<string, unknown>,
): ScanDraftInput {
  const compatible = structuredClone(input);
  if (isObject(compatible.scope)) {
    delete compatible.scope.includePaths;
    delete compatible.scope.excludePaths;
    if (Object.keys(compatible.scope).length === 0) delete compatible.scope;
  }
  if (isObject(compatible.coverage)) {
    for (const field of [
      "documentType",
      "schemaVersion",
      "scanId",
      "mode",
      "includePaths",
      "excludePaths",
      "receiptRefs",
      "inventoryStrategy",
    ])
      delete compatible.coverage[field];
  }
  if (Array.isArray(compatible.findings)) {
    for (const finding of compatible.findings) {
      if (!isObject(finding)) continue;
      delete finding.findingId;
      delete finding.occurrenceId;
      delete finding.fingerprints;
    }
  }
  const parsed = fileScanDraftInputSchema.parse(compatible);
  validateFindingSemantics(parsed.findings);
  delete parsed.coverage.completeness;
  return parsed;
}
