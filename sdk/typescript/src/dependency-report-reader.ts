import {
  stackInvestigationReportSchema,
  type StackInvestigationReport,
} from "./dependency-stack-assessment.js";
import type { DependencyClaimReference } from "./dependency-stack-claims.js";
import { isRecord } from "./record.js";
import { z } from "zod";
import { dependencyTargetSchema } from "./dependency-source-identity.js";
import { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import {
  reviewedDependencyUseSchema,
  reviewedDependencyCheckSchema as nativeCheck,
  dependencyCoverageDispositionSchema,
  dependencyPackageCheckOutputSchema,
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

function legacyUse(
  use: z.infer<typeof dependencyUseSchema>,
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
    decidingEvidence: [],
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
      uses: uses.map(legacyUse),
      assumptions: [],
      searches: [],
    };
  }
  return "cve" in saved.data
    ? convert(saved.data)
    : { ...saved.data, checks: saved.data.checks.map(convert) };
}

export function claimKey(ref: DependencyClaimReference) {
  return JSON.stringify([ref.id, ref.revision, ref.hash]);
}

// Visit each exact reference once, roots before premises. Keep missing
// references in order so readers can show gaps alongside decisions.
export function* walkClaims<
  T extends { dependencies: DependencyClaimReference[] },
>(roots: readonly DependencyClaimReference[], claims: ReadonlyMap<string, T>) {
  const pending = [...roots];
  const seen = new Set<string>();
  for (const ref of pending) {
    const key = claimKey(ref);
    if (seen.has(key)) continue;
    seen.add(key);
    const claim = claims.get(key);
    yield { ref, claim };
    if (claim)
      for (const dependency of claim.dependencies) pending.push(dependency);
  }
}

// A claim payload may be free text or structured JSON. Only project readable
// statements here. Packet receipts are deliberately excluded from the viewer.
function statement(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}
function projectClaim({
  id,
  revision,
  hash,
  dependencies,
  sources,
  payload,
}: StackInvestigationReport["claims"][number]) {
  return {
    id,
    revision,
    hash,
    dependencies,
    sources,
    fact: isRecord(payload)
      ? (statement(payload["fact"]) ??
        statement(payload["statement"]) ??
        statement(payload["comparison"]))
      : statement(payload),
    limits: isRecord(payload)
      ? (statement(payload["limits"]) ?? statement(payload["limitations"]))
      : undefined,
  };
}
type Claim = ReturnType<typeof projectClaim>;
export type StackAssessment =
  StackInvestigationReport["assessments"][number] & {
    reviewReason: string | undefined;
    claims: Claim[];
    missingClaims: DependencyClaimReference[];
  };
export type StackReport = Omit<
  StackInvestigationReport,
  "claims" | "assessments"
> & {
  assessments: StackAssessment[];
};

export function readStackReport(value: unknown): StackReport | undefined {
  if (
    !isRecord(value) ||
    value["schemaVersion"] !==
      stackInvestigationReportSchema.shape.schemaVersion.value
  )
    return;
  const { claims, assessments, ...report } =
    stackInvestigationReportSchema.parse(value);
  const records = new Map<string, Claim>();
  for (const record of claims) {
    const id = claimKey(record);
    if (records.has(id))
      throw new Error("Duplicate stack claim reference: " + record.id);
    records.set(id, projectClaim(record));
  }
  const reasons = new Map(
    report.review?.decisions.map((d) => [d.workItemId, d.reason]),
  );
  const paths = assessments.map((item): StackAssessment => {
    const claims: Claim[] = [];
    const missingClaims: DependencyClaimReference[] = [];
    for (const { ref, claim } of walkClaims(item.supportingClaims, records)) {
      if (claim) claims.push(claim);
      else missingClaims.push(ref);
    }
    return {
      ...item,
      reviewReason: reasons.get(item.workItemId),
      claims,
      missingClaims,
    };
  });
  return { ...report, assessments: paths };
}
