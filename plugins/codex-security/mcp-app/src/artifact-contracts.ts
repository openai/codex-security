import { threatModelSchemas } from "./threat-model-schema.ts";
import { discoveryLocationRoles } from "./discovery-location-roles.js";
import * as z from "zod/v4";
import { findingDetailSchemas } from "./finding-detail-schemas.ts";

// JSON consumers historically apply formats and integer bounds differently from
// live tools. Keep compatibility-export metadata separate from tools/list.
export const artifactJsonMetadata = z.registry<Record<string, unknown>>();
function integer(minimum: number, maximum?: number) {
  const schema = z.number().int().min(minimum);
  return (maximum === undefined ? schema : schema.max(maximum)).register(
    artifactJsonMetadata,
    { maximum },
  );
}

function pattern(schema: z.ZodString, source: string) {
  return schema.regex(new RegExp(source)).register(artifactJsonMetadata, {
    pattern: source,
  });
}

// Match Python str.strip in both runtimes; \S differs on BOM and C0/NEL whitespace.
const nonEmptyText = z
  .string()
  .min(1)
  .regex(
    /[^\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/,
  );

const scanId = z
  .string()
  .check(z.uuid())
  .register(artifactJsonMetadata, { pattern: undefined });

const repositoryPath = pattern(
  z.string().min(1).max(4096),
  "^(?:\\./)?(?!/)(?![A-Za-z]:)(?![\\s\\S]*\\\\)(?![\\s\\S]*(?:^|/)\\.\\.?(/|$))(?![\\s\\S]*//)(?![\\s\\S]*[\\u0000-\\u001f\\u007f])(?![\\s\\S]*\\/$)[\\s\\S]+$",
);

const candidateId = z
  .string()
  .min(1)
  .max(512)
  .regex(
    new RegExp(
      "^(?!\\.{1,2}$)(?!.*[\\u0000-\\u001f\\u007f])(?=.*\\S)[^/\\\\]+$",
    ),
  );

const page = z.strictObject({
  cursor: z.string().regex(new RegExp("^(?:0|[1-9][0-9]*)$")).optional(),
  limit: integer(1, 1000).optional(),
});

const nonEmptyTextWithoutMinimum = z.string().regex(new RegExp("\\S"));

const cweId = z
  .string()
  .regex(new RegExp("^\\s*[Cc][Ww][Ee]-0*[1-9][0-9]*\\s*$"));

const locationRole = z.enum(discoveryLocationRoles);

const rawDiscoveryLocation = z.strictObject({
  path: nonEmptyTextWithoutMinimum,
  start_line: integer(1),
  end_line: integer(1).optional(),
  role: locationRole,
});

const normalizedDiscoveryLocation = rawDiscoveryLocation.extend({
  end_line: integer(1),
});

const rawDiscoveryCandidate = z.strictObject({
  cwe_ids: z.array(cweId),
  locations: z.array(rawDiscoveryLocation).min(1),
  summary: nonEmptyTextWithoutMinimum,
  evidence: nonEmptyTextWithoutMinimum,
  context: nonEmptyTextWithoutMinimum.optional(),
  instance: nonEmptyTextWithoutMinimum.optional(),
});

const discoveryCandidate = z.looseObject({
  candidate_id: z.string().regex(new RegExp("^(?!\\.{1,2}$)[^/\\\\]+$")),
  ...rawDiscoveryCandidate.shape,
  cwe_ids: z.array(z.string().regex(new RegExp("^CWE-[1-9][0-9]*$"))),
  locations: z.array(normalizedDiscoveryLocation).min(1),
});

const recordDiscoveryCandidatesInput = z.strictObject({
  candidates: z.array(rawDiscoveryCandidate),
});

const attackPath_attackPathFields = {
  dataflow: nonEmptyText,
  reachability: nonEmptyText,
  counterevidence: nonEmptyText,
  impact: z.enum(["high", "medium", "low", "ignore", "unknown"]),
  likelihood: z.enum(["high", "medium", "low", "ignore", "unknown"]),
  severity_rationale: nonEmptyText,
  change_conditions: nonEmptyText,
};
const { severity_rationale, change_conditions, ...attackPathEvidence } =
  attackPath_attackPathFields;

const attackPath_reportableAttackPath = z.looseObject({
  decision: z.literal("reportable"),
  ...attackPathEvidence,
  severity: z.enum(["critical", "high", "medium", "low"]),
  severity_rationale,
  change_conditions,
});
const attackPath_ignoredAttackPath = attackPath_reportableAttackPath.extend({
  decision: z.literal("ignore"),
  severity: z.literal("ignore"),
});
const attackPath_deferredAttackPath = attackPath_reportableAttackPath.extend({
  decision: z.literal("deferred"),
  severity: z.enum(["critical", "high", "medium", "low", "unknown"]),
  proof_gap: nonEmptyText,
});

const attackPath_attackPath = z.xor([
  attackPath_reportableAttackPath,
  attackPath_ignoredAttackPath,
  attackPath_deferredAttackPath,
]);

const attackPath_attackPathUpdate = z.strictObject({
  candidateId: candidateId,
  attackPath: attackPath_attackPath,
});

const validation_validationRecord = z.looseObject({
  disposition: z
    .enum(["reportable", "suppressed", "not_applicable", "deferred"])
    .register(artifactJsonMetadata, { type: "string" }),
  method: nonEmptyText,
  confidence: z
    .enum(["high", "medium", "low"])
    .register(artifactJsonMetadata, { type: "string" }),
  confidence_rationale: nonEmptyText,
  rubric: z.union([
    nonEmptyText,
    z.looseObject({}),
    z.array(z.union([nonEmptyText, z.looseObject({})])).min(1),
  ]),
  evidence: z.union([nonEmptyText, z.array(nonEmptyText).min(1)]),
  counterevidence_or_proof_gap: z.string(),
  remaining_uncertainty: z.string(),
  artifact_paths: z.array(nonEmptyText).optional(),
  source: nonEmptyText.optional(),
  control: nonEmptyText.optional(),
  sink: nonEmptyText.optional(),
  preconditions: z
    .union([nonEmptyText, z.array(nonEmptyText).min(1)])
    .optional(),
});

const validation_validationUpdate = z.strictObject({
  candidateId: candidateId,
  validation: validation_validationRecord,
});

const prepareInput = z.strictObject({
  scanId: scanId,
  handoffClaimToken: nonEmptyText.optional(),
});

const reviewItem = z.strictObject({
  path: repositoryPath,
});

const {
  textList: draft_textList,
  slug,
  identity: draft_identity,
  severity: draft_severity,
  confidence: draft_confidence,
  location: draft_location,
  codeEvidence,
  findingAssessment: draft_findingAssessment,
  textOrSummary: draft_textOrSummary,
  findingReachability: draft_findingReachability,
  findingValidation: draft_findingValidation,
  findingAttackPath: draft_findingAttackPath,
} = findingDetailSchemas(nonEmptyText, repositoryPath, integer(1));

const draft_handoffClaimToken = z
  .string()
  .regex(
    new RegExp(
      "^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|recovery_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$",
    ),
  );

const draft_taxonomy = z.looseObject({
  category: nonEmptyText.describe(
    "The actual primary broken security control, not a CWE identifier.",
  ),
  cwe: draft_textList.describe(
    "Copy the reviewed candidate's exact cwe_ids array. Use an empty array when no CWE is established; do not invent one.",
  ),
});

const draft_codeEvidence = codeEvidence.extend({
  code: nonEmptyText.describe(
    "The genuine, nonempty source snippet at this evidence location.",
  ),
});

// Zod applies uniqueItems to raw input before parsing each item.
const uniqueArray = z.fromJSONSchema({ type: "array", uniqueItems: true });

const draft_finding = z.looseObject({
  findingId: z.never().optional(),
  occurrenceId: z.never().optional(),
  fingerprints: z.never().optional(),
  ruleId: slug.describe(
    "A stable lowercase vulnerability-family slug, such as prototype-pollution.json-patch; a CWE is taxonomy, not a rule ID.",
  ),
  identity: draft_identity.optional(),
  title: nonEmptyText,
  summary: nonEmptyText,
  severity: draft_severity,
  confidence: draft_confidence,
  taxonomy: draft_taxonomy,
  locations: z.array(draft_location).min(1),
  writeup: z
    .looseObject({
      reportPath: pattern(
        z.string(),
        "^findings/(?:[a-z0-9][a-z0-9._-]*/)+[a-z0-9][a-z0-9._-]*\\.md$",
      ),
    })
    .optional(),
  codeEvidence: z.array(draft_codeEvidence).optional(),
  code_evidence: z.never().optional(),
  rootCause: z
    .union([
      nonEmptyText,
      z.looseObject({
        summary: nonEmptyText,
        code: z.never().optional(),
        language: z.never().optional(),
        evidenceRefs: draft_textList.optional(),
        evidence_refs: z.never().optional(),
      }),
    ])
    .optional(),
  root_cause: z.never().optional(),
  remediation: nonEmptyText,
  validation: z.union([draft_findingValidation, z.null()]).optional(),
  attackPath: z.union([draft_findingAttackPath, z.null()]).optional(),
  remediationTests: draft_textList.optional(),
  preventiveControls: draft_textList.optional(),
  provenance: z.looseObject({
    sourceFindingIds: z
      .transform((value, context) => {
        const result = uniqueArray.safeParse(value);
        if (!result.success)
          for (const issue of result.error.issues)
            context.addIssue({ ...issue });
        return value;
      })
      .pipe(
        z
          .array(nonEmptyText)
          .meta({ uniqueItems: true })
          .describe(
            "Host-provided source finding references represented by this Deep reduction. Preserve every assigned reference exactly once.",
          ),
      )
      .optional(),
    sourceFindings: z
      .array(z.strictObject({ id: nonEmptyText, finding: z.looseObject({}) }))
      .describe(
        "Original source payloads retained by the host for lossless semantic merges.",
      )
      .optional(),
    source: nonEmptyText.describe(
      "The actual finding producer. Use local_plugin only for a finding discovered by this plugin.",
    ),
  }),
  extensions: z.looseObject({}).optional(),
});

const draft_scope = z.looseObject({
  includePaths: z.never().optional(),
  excludePaths: z.never().optional(),
  summary: nonEmptyText.optional(),
  artifactsReviewed: draft_textList.optional(),
  runtimeStatus: nonEmptyText.optional(),
  validationMode: nonEmptyText.optional(),
  context: nonEmptyText.optional(),
  limitations: draft_textList.optional(),
});

const { schema: draft_threatModel } = threatModelSchemas(draft_textList);

export const surfaceDispositionSchema = z.enum([
  "reported",
  "no_issue_found",
  "rejected",
  "not_applicable",
  "needs_follow_up",
]);

const draft_surface = z.looseObject({
  id: z.string().regex(new RegExp("^[a-z0-9][a-z0-9._/-]*$")).optional(),
  label: nonEmptyText.describe(
    "The meaningful name of the reviewed security surface.",
  ),
  disposition: surfaceDispositionSchema.describe(
    "The evidence-supported review result for this surface.",
  ),
  receiptRefs: z
    .array(
      pattern(
        z.string().min(1),
        "^(?!.*(?:^|/)\\.\\.(?:/|$))(?!.*\\\\)artifacts/.+$",
      ),
    )
    .optional(),
  riskArea: nonEmptyText.optional(),
  notes: nonEmptyText.optional(),
});

const draft_coverage = z.looseObject({
  documentType: z.never().optional(),
  schemaVersion: z.never().optional(),
  scanId: z.never().optional(),
  mode: z.never().optional(),
  includePaths: z.never().optional(),
  excludePaths: z.never().optional(),
  receiptRefs: z.never().optional(),
  inventoryStrategy: z.never().optional(),
  surfaces: z.array(draft_surface),
  explicitExclusions: z.array(
    z.looseObject({ pattern: nonEmptyText, reason: nonEmptyText }),
  ),
  deferred: z
    .array(
      z.looseObject({
        id: nonEmptyText.optional(),
        candidateId: candidateId.optional(),
        reason: nonEmptyText,
        paths: draft_textList.optional(),
        surfaceIds: draft_textList.optional(),
      }),
    )
    .describe(
      "Each supplied id identifies one task and must be unique within this draft. Reuse saved IDs in later updates.",
    ),
  resolvedDeferred: z
    .array(z.strictObject({ id: nonEmptyText, reason: nonEmptyText }))
    .describe(
      "On final Standard or diff drafts, close generic tasks by saved ID and completion reason. Reuse saved surface IDs for updates. Candidate tasks need findings or dispositions; redundant closure entries for those outcomes are ignored.",
    )
    .optional(),
  openQuestions: z
    .array(
      z.union([
        nonEmptyText,
        z.looseObject({
          question: nonEmptyText,
          followUpPrompt: nonEmptyText.optional(),
        }),
      ]),
    )
    .optional(),
});

const draft_scanDraftInput = z.strictObject({
  complete: z
    .boolean()
    .describe(
      "Set false to save progress without declaring this worker or parent audit finished. Omit or set true only for the terminal result. Put provisional candidates in coverage.deferred, not findings.",
    )
    .optional(),
  scanId: scanId,
  handoffClaimToken: draft_handoffClaimToken.optional(),
  scope: draft_scope.optional(),
  threatModel: draft_threatModel.optional(),
  findings: z.array(draft_finding),
  coverage: draft_coverage,
});

/** Native tool contracts; JSON resources are generated compatibility exports. */
export const artifactSchemaDocuments = {
  "definitions/artifact-common": {
    $defs: {
      nonEmptyText: nonEmptyText,
      scanId: scanId,
      repositoryPath: repositoryPath,
      candidateId: candidateId,
    },
  },
  "definitions/discovery-candidate": {
    $defs: {
      nonEmptyText: nonEmptyTextWithoutMinimum,
      cweId: cweId,
      locationRole: locationRole,
      rawDiscoveryLocation: rawDiscoveryLocation,
      normalizedDiscoveryLocation: normalizedDiscoveryLocation,
      rawDiscoveryCandidate: rawDiscoveryCandidate,
      discoveryCandidate: discoveryCandidate,
    },
  },
  "tools/discovery-candidates": {
    $defs: {
      workbenchRecordDiscoveryCandidatesInput: z.strictObject({
        scanId: nonEmptyTextWithoutMinimum,
        ...recordDiscoveryCandidatesInput.shape,
      }),
      workbenchListCandidatesInput: z.strictObject({
        scanId: nonEmptyTextWithoutMinimum,
        ...page.shape,
      }),
    },
  },
  "tools/candidate-attack-paths": {
    title: "Record Codex Security candidate attack paths",
    $ref: "#/$defs/input",
    $defs: {
      input: z.strictObject({
        scanId: scanId,
        attackPaths: z.array(attackPath_attackPathUpdate),
      }),
      attackPathUpdate: attackPath_attackPathUpdate,
      attackPath: attackPath_attackPath,
      attackPathFields: attackPath_attackPathFields,
      reportableAttackPath: attackPath_reportableAttackPath,
      ignoredAttackPath: attackPath_ignoredAttackPath,
      deferredAttackPath: attackPath_deferredAttackPath,
    },
  },
  "tools/candidate-validations": {
    title: "Record compact Codex Security candidate validations",
    $ref: "#/$defs/input",
    $defs: {
      input: z.strictObject({
        scanId: scanId,
        validations: z.array(validation_validationUpdate),
      }),
      validationUpdate: validation_validationUpdate,
      validationRecord: validation_validationRecord,
    },
  },
  "tools/review-items": {
    $defs: {
      prepareInput: prepareInput,
      reviewItemsInput: prepareInput.extend(page.shape),
      reviewItem: reviewItem,
    },
  },
  "tools/scan-draft": {
    title: "Codex Security semantic scan draft",
    $ref: "#/$defs/scanDraftInput",
    $defs: {
      text: nonEmptyText,
      textList: draft_textList,
      scanId: scanId,
      handoffClaimToken: draft_handoffClaimToken,
      repositoryPath: repositoryPath,
      location: draft_location,
      identity: draft_identity,
      severity: draft_severity,
      confidence: draft_confidence,
      taxonomy: draft_taxonomy,
      codeEvidence: draft_codeEvidence,
      findingAssessment: draft_findingAssessment,
      textOrSummary: draft_textOrSummary,
      findingReachability: draft_findingReachability,
      findingValidation: draft_findingValidation,
      findingAttackPath: draft_findingAttackPath,
      finding: draft_finding,
      scope: draft_scope,
      threatModel: draft_threatModel,
      surface: draft_surface,
      coverage: draft_coverage,
      scanDraftInput: draft_scanDraftInput,
      completedScanInput: z.strictObject({
        scanId: scanId,
        handoffClaimToken: draft_handoffClaimToken.optional(),
      }),
    },
  },
};
