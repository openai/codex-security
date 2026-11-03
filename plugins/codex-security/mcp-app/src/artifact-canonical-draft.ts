import coverageDocument from "../../schemas/coverage.schema.json" with { type: "json" };
import findingsDocument from "../../schemas/findings.schema.json" with { type: "json" };
import scanManifestDocument from "../../schemas/scan-manifest.schema.json" with { type: "json" };
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

const draftDefinitions = artifactSchemaDocuments["tools/scan-draft"].$defs;

function canonicalFieldSchema(schema: object): z.ZodType {
  return z.fromJSONSchema(schema as Parameters<typeof z.fromJSONSchema>[0]);
}

const deferredFields = coverageDocument.properties.deferred.items.properties;
function provisionalPaths(schema: Record<string, unknown>) {
  const items = schema.items;
  if (!isObject(items) || !Array.isArray(items.oneOf)) return schema;
  return {
    ...schema,
    items: {
      ...items,
      oneOf: items.oneOf.map((branch) =>
        isObject(branch) && branch.$comment === "invalidSealedDeferredPath"
          ? false
          : branch,
      ),
    },
  };
}

// Canonical files can retain fields that the compact tool input does not accept.
const canonicalScanDraftInputSchema = z.lazy(
  () =>
    fileScanDraftInputSchema.extend({
      scope: canonicalFieldSchema({
        ...scanManifestDocument.properties.scan.properties.scope,
        $defs: scanManifestDocument.$defs,
        required:
          z.toJSONSchema(draftDefinitions.scope, { io: "input" }).required ??
          [],
      }).optional(),
      threatModel: canonicalFieldSchema({
        ...scanManifestDocument.properties.scan.properties.threatModel,
        $defs: scanManifestDocument.$defs,
      }).optional(),
      findings: canonicalFieldSchema({
        ...findingsDocument.properties.findings,
        $defs: findingsDocument.$defs,
        items: {
          ...findingsDocument.properties.findings.items,
          required: z.toJSONSchema(draftDefinitions.finding, { io: "input" })
            .required,
        },
      }),
      reviewState: draftDefinitions.reviewState.extend({
        surfaces: canonicalFieldSchema({
          ...coverageDocument.properties.surfaces,
          items: {
            ...coverageDocument.properties.surfaces.items,
            required: z.toJSONSchema(draftDefinitions.surface, { io: "input" })
              .required,
          },
        }),
        deferred: canonicalFieldSchema({
          ...coverageDocument.properties.deferred,
          items: {
            ...coverageDocument.properties.deferred.items,
            properties: {
              ...deferredFields,
              paths: provisionalPaths(deferredFields.paths),
            },
            required: z.toJSONSchema(
              draftDefinitions.reviewState.shape.deferred.element,
              { io: "input" },
            ).required,
          },
        }),
        openQuestions: z
          .array(
            z.union([
              z.string(),
              canonicalFieldSchema(
                coverageDocument.properties.openQuestions.items,
              ),
            ]),
          )
          .optional(),
      }),
    }) as z.ZodType<ScanDraftInput>,
);

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
  reviewState?: JsonObject;
}): ScanDraftInput {
  const scan = requireObject(input.manifest.scan, "scan draft manifest.scan");
  const reviewState = requireObject(
    input.reviewState ?? scan.reviewState ?? reviewStateFromSummary(scan),
    "scan draft review state",
  );
  for (const scanId of [scan.id, input.findings.scanId, reviewState.scanId]) {
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
    reviewState,
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

export function parsePersistedCheckpoint(
  input: Record<string, unknown>,
  schema: z.ZodType<ScanDraftInput> = fileScanDraftInputSchema,
): ScanDraftInput {
  const compatible = structuredClone(input);
  delete compatible.previousParentCheckpoints;
  delete compatible.canonicalParent;
  delete compatible.publication;
  if (
    compatible.reviewState === undefined &&
    compatible.coverage !== undefined
  ) {
    compatible.reviewState = compatible.coverage;
    delete compatible.coverage;
  }
  if (isObject(compatible.scope)) {
    delete compatible.scope.includePaths;
    delete compatible.scope.excludePaths;
    if (Object.keys(compatible.scope).length === 0) delete compatible.scope;
  }
  if (isObject(compatible.reviewState)) {
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
      delete compatible.reviewState[field];
  }
  if (Array.isArray(compatible.findings)) {
    for (const finding of compatible.findings) {
      if (!isObject(finding)) continue;
      delete finding.findingId;
      delete finding.occurrenceId;
      delete finding.fingerprints;
    }
  }
  const parsed = schema.parse(compatible);
  validateFindingSemantics(parsed.findings);
  delete parsed.reviewState.completeness;
  return parsed;
}

export function reviewStateFromSummary(scan: JsonObject): JsonObject {
  const review = requireObject(scan.review, "scan review summary");
  return {
    scanId: scan.id,
    surfaces: [],
    deferred: [],
    explicitExclusions: (review.excludedPaths as string[]).map((pattern) => ({
      pattern,
      reason: "Excluded from review",
    })),
  };
}
