import { normalizePersistedFindingDetails } from "./finding-normalization.js";
import type * as z from "zod/v4";
import { isAbsolute, posix } from "node:path";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import scanDraftDocument from "../../schemas/tools/scan-draft.schema.json";
import scanManifestDocument from "../../schemas/scan-manifest.schema.json";
import coverageDocument from "../../schemas/coverage.schema.json";
import findingsDocument from "../../schemas/findings.schema.json";
import { isRecord as isObject } from "./record.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";
import {
  requireObject,
  validateFindingSemantics,
  validateCoverageSemantics,
  type SemanticScan,
} from "../../../../sdk/typescript/src/scan-semantics.js";
type JsonObject = Record<string, unknown>;
type ScanDraftInput = SemanticScan;
const canonicalScanDraftInputSchema = loadArtifactZodSchema(
  [
    commonSchema,
    {
      ...scanDraftDocument,
      $defs: {
        ...scanManifestDocument.$defs,
        ...findingsDocument.$defs,
        ...scanDraftDocument.$defs,
        scanDraftInput: {
          ...scanDraftDocument.$defs.scanDraftInput,
          properties: {
            ...scanDraftDocument.$defs.scanDraftInput.properties,
            scanId: scanManifestDocument.properties.scan.properties.id,
          },
        },
        scope: {
          ...scanDraftDocument.$defs.scope,
          properties:
            scanManifestDocument.properties.scan.properties.scope.properties,
        },
        threatModel:
          scanManifestDocument.properties.scan.properties.threatModel,
        finding: {
          ...scanDraftDocument.$defs.finding,
          properties: findingsDocument.properties.findings.items.properties,
        },
        coverage: {
          ...scanDraftDocument.$defs.coverage,
          properties: {
            ...coverageDocument.properties,
            surfaces: {
              ...coverageDocument.properties.surfaces,
              items: {
                ...coverageDocument.properties.surfaces.items,
                required: scanDraftDocument.$defs.surface.required,
              },
            },
            deferred: {
              ...coverageDocument.properties.deferred,
              items: {
                ...coverageDocument.properties.deferred.items,
                required:
                  scanDraftDocument.$defs.coverage.properties.deferred.items
                    .required,
              },
            },
            // String questions are normalized by the finalizer after admission.
            openQuestions: {
              ...coverageDocument.properties.openQuestions,
              items: {
                anyOf: [
                  scanDraftDocument.$defs.coverage.properties.openQuestions
                    .items.anyOf[0],
                  coverageDocument.properties.openQuestions.items,
                ],
              },
            },
          },
        },
      },
    },
  ] as SchemaDocument[],
  scanDraftDocument.$id,
  "scanDraftInput",
) as z.ZodType<ScanDraftInput>;

function safeRelativePath(value: string, context: string): string {
  const parts = value.split("/");
  if (
    value.trim().length === 0 ||
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
  const parsed = parsePersistedCheckpoint(input, canonicalScanDraftInputSchema);
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
  schema = canonicalScanDraftInputSchema,
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
  if (Array.isArray(compatible.findings)) {
    for (const finding of compatible.findings) {
      if (isObject(finding)) normalizePersistedFindingDetails(finding, "draft");
    }
  }
  const parsed = schema.parse(compatible);
  validateFindingSemantics(parsed.findings, false);
  validateCoverageSemantics(parsed.coverage);
  return parsed;
}
