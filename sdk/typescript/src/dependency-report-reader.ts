import { z } from "zod";
import { dependencyTargetSchema } from "./dependency-source-identity.js";
import { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import {
  reviewedDependencyUseSchema,
  reviewedDependencyCheckSchema as nativeCheck,
  dependencyCoverageDispositionSchema,
  dependencyPackageCheckOutputSchema,
  dependencyFindingDetailsShape,
  type DependencyReviewReference,
  type ReviewedDependencyUse,
} from "./dependency-reachability.js";
export type {
  ReviewedDependencyUse,
  DependencyReviewReference,
} from "./dependency-reachability.js";
export type {
  DependencyUse,
  DependencyVerdict,
} from "./dependency-stack-use.js";
export type DependencyCoverageDisposition = z.infer<
  typeof dependencyCoverageDispositionSchema
>;
export type DependencyFindingDetails = Pick<
  ReviewedDependencyUse,
  keyof typeof dependencyFindingDetailsShape
>;

export const dependencyInvestigationBlockedSchema = z.object({
  target: dependencyTargetSchema.optional(),
  status: z.literal("blocked"),
  code: z.literal("INVESTIGATION_BLOCKED"),
  reason: z.string(),
  cve: z.string().optional(),
  affectedScope: z.string().optional(),
  scopeImpact: z.string().optional(),
  unblockCondition: z.string().optional(),
});

// Inventory-based reports can cite an artifact without a repository line.
// Adapt saved data here. Live validation belongs to the investigation.
const evidence = z.array(reviewedDependencyUseSchema.shape.evidence.element);
const savedUse = reviewedDependencyUseSchema.safeExtend({ evidence });
export const reviewedDependencyCheckSchema = nativeCheck.extend({
  uses: z.array(savedUse),
  coverage: z
    .array(dependencyCoverageDispositionSchema.extend({ evidence }))
    .optional(),
  advisoryDetails: z
    .array(
      dependencyAdvisoryDetailsSchema.transform((data) => {
        const paragraph = data.body
          ?.trim()
          .replace(/^#{1,6}\s+[^\n]+\n+\s*/u, "")
          .split(/\r?\n\s*\r?\n/u)[0];
        if (
          data.overview ||
          !paragraph ||
          paragraph === data.summary ||
          /^[{<#]|^`{3}|^~{3}/u.test(paragraph)
        )
          return data;
        return { ...data, overview: paragraph };
      }),
    )
    .optional(),
});
const dependencyCheckOutputSchema = z.union([
  reviewedDependencyCheckSchema.extend({ cve: z.string() }),
  dependencyPackageCheckOutputSchema.extend({
    checks: z.array(
      reviewedDependencyCheckSchema.extend({
        advisoryId: z.string().nullable(),
      }),
    ),
  }),
]);
const verdict = savedUse.shape.verdict;
const dependencyUseSchema = z.strictObject({
  ...savedUse.shape,
  place: savedUse.shape.place.optional(),
  decidingEvidence: savedUse.shape.decidingEvidence.optional(),
});

// Saved v1 reports are readable without publishing their checkout-wide verdict.
const legacyCheck = reviewedDependencyCheckSchema
  .omit({ schemaVersion: true, assumptions: true, searches: true })
  .extend({ status: verdict, uses: z.array(dependencyUseSchema) });
const legacyReport = z.union([
  legacyCheck.extend({ cve: z.string() }),
  z.object({
    package: z.object({ ecosystem: z.string(), name: z.string() }),
    vulnDescription: z.string().optional(),
    checks: z.array(legacyCheck.extend({ advisoryId: z.string().nullable() })),
  }),
]);

function withReviewedPlace(
  use: z.infer<typeof dependencyUseSchema>,
  decidingEvidence: DependencyReviewReference[],
): ReviewedDependencyUse {
  return {
    ...use,
    place: use.place ?? {
      kind: "unknown",
      environment: null,
      revision: null,
      artifact: null,
      observationWindow: null,
      deploymentBasis:
        use.deployment === "confirmed" ? "observed" : use.deployment,
      deploymentDetail: null,
      dependencySelection: null,
      patch: null,
      unresolvedQuestions: use.verdict === "unknown" ? [use.reason] : [],
    },
    decidingEvidence,
  };
}

export function readDependencyCheckOutput(
  value: unknown,
): z.infer<typeof dependencyCheckOutputSchema> {
  const current = dependencyCheckOutputSchema.safeParse(value);
  if (current.success) return current.data;
  const saved = legacyReport.safeParse(value);
  if (!saved.success) throw current.error;
  function convert<T extends z.infer<typeof legacyCheck>>(check: T) {
    const { status: _status, uses, ...rest } = check;
    return {
      ...rest,
      schemaVersion: 2 as const,
      uses: uses.map((use) => withReviewedPlace(use, [])),
      assumptions: [],
      searches: [],
    };
  }
  return "cve" in saved.data
    ? convert(saved.data)
    : { ...saved.data, checks: saved.data.checks.map(convert) };
}
