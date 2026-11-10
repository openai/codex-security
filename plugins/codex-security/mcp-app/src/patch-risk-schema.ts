import * as z from "zod/v4";

// Generator-only schema and static type. Runtime validation retains AJV's
// exported JSON Schema, including uniqueness and minimum-property constraints.
const text = z.string().min(1);
const stringList = z.array(text).meta({ uniqueItems: true });
const recommendation = z.enum([
  "merge",
  "revise",
  "no_op",
  "block",
  "hold_for_evidence",
]);
const rating = <const T extends [string, ...string[]]>(values: T) =>
  z.strictObject({
    rating: z.enum(values),
    rationale: text,
  });
const riskRating = rating(["low", "moderate", "high", "critical"]);
const recoveryRating = rating(["easy", "managed", "hard"]);
const confidenceRating = rating(["high", "moderate", "low"]);
const identifier = z.string().regex(/^[a-z0-9][a-z0-9_-]*$/);

export const patchRiskDefinitions = {
  nonEmptyString: text,
  identifier,
  stringList,
  recommendation,
  riskRating,
  recoveryRating,
  confidenceRating,
};

export const patchRiskAssessment = z.strictObject({
  schemaVersion: z.literal(1),
  patch: z.strictObject({
    repository: text,
    sourceType: z.enum(["pull_request_diff", "patch_file", "commit_range"]),
    base: text,
    head: text,
    changedFiles: stringList,
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
  }),
  recommendation,
  workflowLabel: z.enum([
    "auto_merge_candidate",
    "human_review_required",
    ...recommendation.exclude(["merge"]).options,
  ]),
  impact: riskRating,
  regressionLikelihood: riskRating,
  regressionProtection: z.strictObject({
    rating: z.enum(["strong", "partial", "none", "unknown"]),
    rationale: text,
    exactHeadChecksPassed: z.boolean(),
  }),
  recoverability: recoveryRating,
  confidence: confidenceRating,
  applicability: z.strictObject({
    status: z.enum([
      "confirmed",
      "no_live_effect",
      "wrong_owner",
      "duplicate",
      "superseded",
      "unknown",
    ]),
    rationale: text,
  }),
  statusQuoRisk: rating(["low", "moderate", "high", "critical", "unknown"]),
  autoMergeExclusions: z
    .array(
      z.enum([
        "privileged_boundary",
        "migration",
        "persistent_state",
        "public_contract",
        "architecture_specific_rollout",
        "broad_shared_default",
        "other",
      ]),
    )
    .meta({ uniqueItems: true }),
  affectedRuntimeRoots: stringList,
  importantCallers: stringList.optional(),
  riskDrivers: stringList.optional(),
  protectiveFactors: stringList.optional(),
  materialBoundaries: z.array(
    z.strictObject({
      id: identifier,
      invariant: text,
      runtimeRoot: text,
      counterexample: text,
      legitimateControl: text,
      result: z.enum(["supported", "contradicted", "unresolved"]),
    }),
  ),
  validation: z
    .array(
      z.strictObject({
        name: text,
        status: z.enum(["passed", "failed", "skipped", "unavailable"]),
        protects: text,
      }),
    )
    .min(1),
  unknowns: z.array(
    z.strictObject({ summary: text, decisionCritical: z.boolean() }),
  ),
  evidencePlan: z
    .array(
      z.strictObject({
        question: text,
        action: text,
        outcomes: z
          .record(z.string(), recommendation)
          .meta({ propertyNames: undefined, minProperties: 2 }),
      }),
    )
    .max(3),
});

export type PatchRiskAssessment = z.infer<typeof patchRiskAssessment>;
