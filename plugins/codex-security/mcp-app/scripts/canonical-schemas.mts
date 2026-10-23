import { surfaceDispositionSchema } from "../src/artifact-contracts.ts";
import { threatModelSchemas } from "../src/threat-model-schema.ts";
import * as z from "zod/v4";
import {
  patchRiskAssessment,
  patchRiskDefinitions,
} from "../src/patch-risk-schema.ts";
import { findingDetailSchemas } from "../src/finding-detail-schemas.ts";

// Generator-only definitions: canonical runtime validation uses the selected
// plugin's exported JSON Schemas in AJV and Python, including legacy type arrays.
function typeArray<T extends z.ZodType>(schema: T, types: string[]): T {
  z.globalRegistry.add(schema, { ...schema.meta(), type: types });
  return schema;
}
function pattern(source: string) {
  return z.string().regex(new RegExp(source)).meta({ pattern: source });
}

const text = z.string().min(1);
const line = z.number().int().min(1).meta({ maximum: undefined });
const {
  textList,
  slug,
  identity,
  severity,
  confidence,
  location,
  codeEvidence,
  findingAssessment,
  textOrSummary: sourceTextOrSummary,
  findingReachability: sourceFindingReachability,
  findingValidation,
  findingAttackPath,
} = findingDetailSchemas(text, text, line);
const legacyCodeEvidence = z.looseObject({ id: text, code: text });
const textOrSummary = z.union([
  text,
  sourceTextOrSummary.options[1].extend({ evidence_refs: textList.optional() }),
]);
const findingReachability = z.union([
  text,
  sourceFindingReachability.options[1].extend({
    evidence_refs: textList.optional(),
  }),
]);
// The flattened string-or-array contract needs inline items, not an array-only reference.
const validation = findingValidation.extend({
  evidence: z.union([text, z.array(text)]).optional(),
  evidence_refs: textList.optional(),
});
for (const schema of [findingAssessment, textOrSummary, findingReachability])
  typeArray(schema, ["string", "object"]);
for (const field of ["status", "disposition", "result"] as const)
  typeArray(validation.shape[field].unwrap(), ["string", "null"]);
typeArray(validation.shape.evidence.unwrap(), ["string", "array"]);
const assessment = typeArray(findingAttackPath.shape.impact.unwrap(), [
  "string",
  "object",
  "null",
]);
const attackPath = findingAttackPath.extend({
  dataFlow: textOrSummary.optional(),
  data_flow: textOrSummary.optional(),
  dataflow: textOrSummary.optional(),
  evidence_refs: textList.optional(),
  impact: assessment.optional(),
  likelihood: assessment.optional(),
  reachability: findingReachability.optional(),
});
const rootCause = z.looseObject({
  summary: text,
  evidenceRefs: textList.optional(),
  code: text.optional(),
  language: text.optional(),
});
const finding = z.looseObject({
  findingId: z.string().regex(/^csf_[a-f0-9]{24}$/),
  occurrenceId: z.string().regex(/^occ_[a-f0-9]{24}$/),
  ruleId: slug,
  identity,
  fingerprints: z.looseObject({
    algorithm: z.literal("codex-security/v1"),
    primary: pattern("^codex-security/v1:sha256:[a-f0-9]{64}$"),
  }),
  title: text,
  summary: text,
  severity,
  confidence,
  taxonomy: z.looseObject({ category: text, cwe: textList }),
  locations: z.array(location).min(1),
  writeup: z
    .looseObject({
      reportPath: pattern(
        "^findings/(?:[a-z0-9][a-z0-9._-]*/)+[a-z0-9][a-z0-9._-]*\\.md$",
      ),
    })
    .optional(),
  codeEvidence: z.array(codeEvidence).optional(),
  code_evidence: typeArray(z.array(legacyCodeEvidence).nullable(), [
    "array",
    "null",
  ]).optional(),
  rootCause: typeArray(z.union([rootCause, z.string()]), [
    "object",
    "string",
  ]).optional(),
  root_cause: typeArray(
    z.union([
      z.looseObject({
        summary: text.optional(),
        evidenceRefs: textList.optional(),
        evidence_refs: textList.optional(),
        code: text.optional(),
        language: text.optional(),
      }),
      z.string(),
      z.null(),
    ]),
    ["object", "string", "null"],
  ).optional(),
  remediation: text,
  validation: typeArray(validation.nullable(), ["object", "null"]).optional(),
  attackPath: typeArray(attackPath.nullable(), ["object", "null"]).optional(),
  remediationTests: textList.optional(),
  preventiveControls: textList.optional(),
  provenance: z.looseObject({ source: text }),
  extensions: z
    .looseObject({
      candidateId: text.optional(),
      ledgerRowId: text.optional(),
      reportId: text.optional(),
    })
    .optional(),
});

const findingsDocument = z.looseObject({
  documentType: z.literal("codex-security.findings"),
  schemaVersion: z.literal("1.0"),
  scanId: text,
  findings: z.array(finding),
});

const strings = z.array(z.string());
const timestamp = z.string().meta({ format: "date-time" });
const snapshotKinds = [
  "git_worktree",
  "git_diff",
  "directory_snapshot",
] as const;

const target = z
  .looseObject({
    kind: z.enum(["git_revision", ...snapshotKinds]),
    targetId: text,
    displayName: text,
    remote: pattern("^(?![^:/?#]+://[^/?#]*@)[^?#]+$").optional(),
    revision: z.string().optional(),
    baseRevision: z.string().optional(),
    headRevision: z.string().optional(),
    snapshotDigest: pattern(
      "^codex-security-snapshot/v1:sha256:[a-f0-9]{64}$",
    ).optional(),
  })
  .meta({
    allOf: [
      {
        if: { properties: { kind: { const: "git_revision" } } },
        then: { required: ["revision"] },
      },
      {
        if: { properties: { kind: { enum: snapshotKinds } } },
        then: { required: ["snapshotDigest"] },
      },
    ],
  });

const {
  schema: threatModel,
  markdown,
  scope,
} = threatModelSchemas(textList, text.regex(/^[\s\S]*\S[\s\S]*$/), textList);
for (const schema of [markdown, scope])
  z.globalRegistry.add(schema, {
    ...z.globalRegistry.get(schema),
    additionalProperties: true,
  });

const scanManifest = z.looseObject({
  documentType: z.literal("codex-security.scan-manifest"),
  schemaVersion: z.literal("1.0"),
  scan: z
    .looseObject({
      id: text,
      producer: z.looseObject({ name: text, version: text }),
      status: z.enum(["completed", "failed", "canceled", "interrupted"]),
      startedAt: timestamp,
      completedAt: timestamp,
      sealedAt: timestamp,
      target,
      scope: z.looseObject({
        includePaths: strings,
        excludePaths: strings,
        summary: text.optional(),
        artifactsReviewed: textList.optional(),
        runtimeStatus: text.optional(),
        validationMode: text.optional(),
        context: text.optional(),
        limitations: textList.optional(),
      }),
      threatModel: threatModel.optional(),
      hardening: z
        .looseObject({ portfolioPath: z.literal("hardening/hardening.md") })
        .optional(),
      coverageRef: z.literal("coverage.json"),
      findingsRef: z.literal("findings.json"),
      artifacts: z
        .array(
          z.looseObject({
            path: pattern("^(?!/)(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\).+$").min(
              1,
            ),
            sha256: z.string().regex(/^[a-f0-9]{64}$/),
            mediaType: text,
          }),
        )
        .min(1),
    })
    .meta({
      allOf: ["findings.json", "coverage.json"].map((path) => ({
        properties: {
          artifacts: {
            contains: {
              type: "object",
              required: ["path"],
              properties: { path: { const: path } },
            },
            minContains: 1,
            maxContains: 1,
          },
        },
      })),
    }),
});

const coverageDocument = z.looseObject({
  documentType: z.literal("codex-security.coverage"),
  schemaVersion: z.literal("1.0"),
  scanId: text,
  mode: z.enum([
    "repository",
    "scoped_path",
    "diff",
    "commit",
    "branch_diff",
    "working_tree",
    "deep_repository",
  ]),
  inventoryStrategy: z.enum([
    "repository",
    "scoped_path",
    "diff",
    "directory",
    "custom",
  ]),
  includePaths: strings,
  excludePaths: strings,
  surfaces: z.array(
    z.looseObject({
      id: text,
      label: text,
      disposition: surfaceDispositionSchema,
      receiptRefs: z.array(
        pattern("^(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\)artifacts/.+$").min(1),
      ),
      riskArea: text.optional(),
      notes: text.optional(),
    }),
  ),
  explicitExclusions: z.array(z.looseObject({ pattern: text, reason: text })),
  deferred: z.array(
    z.looseObject({
      id: text,
      reason: text,
      paths: textList.optional(),
      surfaceIds: textList.optional(),
    }),
  ),
  resolvedDeferred: z
    .array(z.strictObject({ id: text, reason: text }))
    .describe(
      "Completed generic review tasks, with their saved IDs and completion reasons.",
    )
    .optional(),
  openQuestions: z
    .array(z.looseObject({ question: text, followUpPrompt: text.optional() }))
    .optional(),
});

export const canonicalSchemaDocuments = {
  "patch-risk-assessment": {
    title: "Patch risk assessment",
    schema: patchRiskAssessment,
    definitions: patchRiskDefinitions,
  },
  findings: {
    title: "Codex Security findings",
    schema: findingsDocument,
    definitions: { dataFlow: textOrSummary, assessment, stringList: textList },
  },
  "scan-manifest": {
    title: "Codex Security sealed scan manifest",
    schema: scanManifest,
    definitions: { stringList: textList },
  },
  coverage: { title: "Codex Security scan coverage", schema: coverageDocument },
};
