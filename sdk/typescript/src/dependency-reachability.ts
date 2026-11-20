import { z } from "zod";
import { dependencyClaimReferenceSchema } from "./dependency-stack-claims.js";
import {
  dependencyGitCommitSchema,
  dependencyTargetSchema,
} from "./dependency-source-identity.js";
import {
  dependencyUseSchema,
  dependencyUseProofSchema,
} from "./dependency-stack-use.js";
import { stackJsonValue } from "./dependency-stack-evidence.js";

const identity = z.string().trim().min(1);
const inventoryFact = z.enum(["affected_copy", "running", "access"]);
// The first independently reviewed reports included only the server, quoted record and facts.
// Some saved reports additionally identified the receipt here. Keep those records readable.
const observation = z.strictObject({
  server: z
    .string()
    .trim()
    .min(1)
    .describe("Configured inventory MCP server that returned the observation."),
  record: z
    .string()
    .trim()
    .min(1)
    .describe(
      "Specific returned record, record identifier, or lookup result. For an empty result, identify the lookup and its scope. Identify the unit, revision, environment and observation time when supplied.",
    ),
  tool: z.string().optional(),
  sha256: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .optional(),
  supports: z
    .array(inventoryFact)
    .describe(
      "Facts this record establishes for the same affected use. affected_copy requires build evidence identifying the dependency version and applicable patch state in the same artifact proven to be running. running identifies the observed running revision. access requires actual access by the relevant caller. Use [] when the record establishes none of these facts.",
    ),
});
const placeText = z.string().trim().min(1).nullable();
const dependencyPlaceSchema = z.strictObject({
  kind: z
    .enum([
      "service",
      "job",
      "configured_build",
      "artifact",
      "library_caller",
      "unknown",
    ])
    .describe(
      "Kind of place supported by this item's evidence. Use unknown when the caller or consumer type is unresolved.",
    ),
  environment: placeText,
  revision: placeText,
  artifact: placeText.describe("Immutable artifact identity when established."),
  observationWindow: placeText.describe(
    "Exact timestamp or time window supported by the cited records. Specify whether the observation is historical. Use null without a bounded observation.",
  ),
  deploymentBasis: z
    .enum(["observed", "configured", "assumed_not_deployed", "unknown"])
    .describe(
      "A no-match or incomplete inventory response does not establish absence. Use assumed_not_deployed only for an explicit assumption in the supplied caller scope, and quote its boundary in deploymentDetail.",
    ),
  deploymentDetail: placeText.describe(
    "Workload, rollout, configuration or explicit caller assumption establishing this place's deployment scope.",
  ),
  dependencySelection: placeText.describe(
    "Material binding from this consumer/build/artifact to the actual dependency copy.",
  ),
  patch: placeText.describe(
    "Advisory-specific patch or override status for the selected copy. Use null when unresolved or immaterial to a source exclusion.",
  ),
  workload: z.string().trim().min(1).optional(),
  variant: z.string().trim().min(1).optional(),
  role: z.string().trim().min(1).optional(),
  platform: z.string().trim().min(1).optional(),
  imageIndex: z.string().trim().min(1).optional(),
  platformManifest: z.string().trim().min(1).optional(),
  unresolvedQuestions: z
    .array(z.string().trim().min(1))
    .describe(
      "Deciding questions still open for this place, including the missing fact or unavailable check. Use [] for a decisive scoped exclusion.",
    ),
});

const reviewReference = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("source"),
    path: z.string(),
    commit: dependencyGitCommitSchema.optional(),
    startLine: z.number().int().positive(),
    endLine: z.number().int().positive(),
  }),
  z.strictObject({
    kind: z.literal("receipt"),
    receiptId: z.string(),
    originalPayloadSha256: z.string(),
    selection: z
      .strictObject({
        textBlock: z.number().int().nonnegative().nullable(),
        record: z.array(z.union([z.string(), z.number().int().nonnegative()])),
      })
      .optional(),
  }),
]);
export type DependencyReviewReference = z.infer<typeof reviewReference>;

const findingText = z.string().trim().min(1);
const serviceAssociation = z.strictObject({
  id: findingText.describe(
    "Stable service identity from the identified mapping source.",
  ),
  name: findingText.describe(
    "Readable service name or verified display alias.",
  ),
  source: findingText.describe(
    "The catalog or other explicitly identified mapping source.",
  ),
  evidence: z
    .array(reviewReference)
    .min(1)
    .describe(
      "Original bound evidence that establishes this service association.",
    ),
});
const openCondition = z.strictObject({
  question: findingText,
  target: findingText.describe(
    "The caller, workload, artifact or environment to which this question applies.",
  ),
  decidingCheck: findingText.optional(),
  ruledOutIf: findingText.optional(),
  assignee: z
    .strictObject({
      name: findingText,
      evidence: z.array(reviewReference).min(1),
    })
    .optional(),
});
const inputSource = z.strictObject({
  exposure: z
    .enum(["internet", "not_internet", "unknown"])
    .describe(
      "Internet exposure of the actual input source for this caller, not of the source code or merely of the service.",
    ),
  endpoint: findingText
    .optional()
    .describe("Exact URL, route, or input endpoint when established."),
  evidence: z.array(reviewReference).min(1),
});
const runtimeContext = z.strictObject({
  launch: z
    .strictObject({
      command: findingText,
      basis: z.enum(["observed", "configured"]),
    })
    .optional(),
  mitigation: z
    .strictObject({
      state: z.enum(["enabled", "disabled", "unknown"]),
      basis: z.enum(["observed", "configured", "unknown"]),
      detail: findingText,
    })
    .optional(),
  containerUrl: findingText.optional(),
  traceUrl: findingText.optional(),
  evidence: z.array(reviewReference).min(1),
});
const findingTag = z.strictObject({
  name: findingText,
  evidence: z.array(reviewReference).min(1),
});
const inspectionTarget = z.strictObject({
  label: findingText,
  relationship: z.enum(["target", "shared_artifact", "comparison"]),
  environment: findingText.optional(),
  workload: findingText.optional(),
  variant: findingText.optional(),
  role: findingText.optional(),
  revision: findingText.optional(),
  artifact: findingText.optional(),
  imageIndex: findingText.optional(),
  platformManifest: findingText.optional(),
  platform: findingText.optional(),
  observationWindow: findingText.optional(),
});
const inspection = z
  .strictObject({
    question: findingText,
    target: inspectionTarget,
    source: findingText
      .optional()
      .describe(
        "The tool or source actually used, not a proposed future lookup.",
      ),
    outcome: z.enum([
      "succeeded",
      "denied",
      "unsupported",
      "timeout",
      "unavailable",
      "failed",
      "no_data",
      "zero_results",
      "partial",
      "insufficient_symbols",
      "not_attempted",
    ]),
    result: findingText
      .optional()
      .describe(
        "The scoped observation and what it establishes, without raw payloads or credentials.",
      ),
    evidence: z.array(reviewReference),
    completeness: z.enum(["complete", "partial", "not_reported"]).optional(),
    measurement: z
      .strictObject({
        unit: z.enum(["cpu_samples", "calls"]),
        count: z.number().int().nonnegative(),
        frameTypes: z.array(findingText).optional(),
      })
      .optional(),
    transferBasis: findingText
      .optional()
      .describe(
        "Why an immutable artifact observation can transfer to this target; never transfer workload-specific measurements.",
      ),
  })
  .superRefine((value, ctx) => {
    if (
      value.outcome !== "not_attempted" &&
      (!value.source || !value.evidence.length)
    )
      ctx.addIssue({
        code: "custom",
        path: ["evidence"],
        message:
          "An attempted inspection requires its actual source and original bound evidence.",
      });
    if (
      value.outcome === "not_attempted" &&
      (value.source || value.evidence.length || value.measurement)
    )
      ctx.addIssue({
        code: "custom",
        path: ["outcome"],
        message:
          "A check that was not attempted cannot claim an inspection source, evidence or measurement.",
      });
    if (value.target.relationship === "shared_artifact" && !value.transferBasis)
      ctx.addIssue({
        code: "custom",
        path: ["transferBasis"],
        message:
          "Shared artifact evidence requires its verified transfer basis.",
      });
    if (value.target.relationship === "shared_artifact" && value.measurement)
      ctx.addIssue({
        code: "custom",
        path: ["measurement"],
        message:
          "Workload-specific calls and CPU samples cannot be transferred as shared artifact evidence.",
      });
  });

const site = dependencyUseProofSchema.shape.sink
  .unwrap()
  .shape.callSite.extend({
    commit: dependencyGitCommitSchema.optional(),
  });
const argument = z
  .string()
  .trim()
  .min(1)
  .describe(
    "Exact single-line expression carrying the input at the cited site. Omit when ambiguous.",
  );
const label = z.string().trim().min(1);
export const dependencyTraceSchema = z
  .array(
    z.discriminatedUnion("kind", [
      z.strictObject({
        kind: z.enum(["source", "handoff"]),
        label,
        site,
        argument: argument.optional(),
      }),
      z.strictObject({ kind: z.literal("gap"), label }),
    ]),
  )
  .refine(
    (frames) =>
      frames.every((frame, index) => index === 0 || frame.kind !== "source"),
    "The source, if known, starts the trace.",
  );

export const repositoryUseProofSchema = dependencyUseProofSchema.extend({
  sink: dependencyUseProofSchema.shape.sink
    .unwrap()
    .extend({
      callSite: site,
      argument: argument.optional(),
    })
    .optional(),
});

/** Optional, independently reviewed context. Older saved reports omit it. */
export const dependencyFindingDetailsShape = {
  trace: dependencyTraceSchema
    .optional()
    .describe(
      "Ordered, cited input flow up to the sink or unresolved handoff. Mark missing links as gaps.",
    ),
  services: z.array(serviceAssociation).optional(),
  openConditions: z.array(openCondition).optional(),
  inspections: z.array(inspection).optional(),
  inputSource: inputSource.optional(),
  runtimeContext: runtimeContext.optional(),
  tags: z.array(findingTag).optional(),
};
export const dependencyCoverageHandoffSchema = z.strictObject({
  verified: findingText,
  missing: findingText,
});
export { dependencyPlaceSchema };

const reportUseSchema = dependencyUseSchema.safeExtend({
  proof: repositoryUseProofSchema.optional(),
  observations: z.array(observation).prefault([]),
  place: dependencyPlaceSchema.optional(),
  ...dependencyFindingDetailsShape,
});

export const dependencyTestScopeClassification = z.literal(
  "test_only_outside_scope",
);
export const dependencyCoverageDispositionSchema = z.strictObject({
  kind: z.enum(["dismissed", "unresolved"]),
  reason: z.string().min(1),
  location: findingText.optional(),
  place: dependencyPlaceSchema.optional(),
  handoff: dependencyCoverageHandoffSchema.optional(),
  ...dependencyFindingDetailsShape,
  evidence: dependencyUseSchema.shape.evidence,
  observations: reportUseSchema.shape.observations,
  decidingEvidence: z.array(reviewReference).optional(),
  conclusionClaim: dependencyClaimReferenceSchema.optional(),
  supportingClaims: z.array(dependencyClaimReferenceSchema).optional(),
  classification: dependencyTestScopeClassification.optional(),
  locations: z
    .array(
      z.strictObject({
        candidateId: z.string(),
        path: z.string(),
        line: z.number().int().positive().optional(),
      }),
    )
    .optional(),
});

export const dependencyApprovedClaimSchema =
  dependencyClaimReferenceSchema.extend({
    state: z.literal("approved"),
    contextHash: identity,
    payload: stackJsonValue,
    scope: stackJsonValue,
    dependencies: z.array(dependencyClaimReferenceSchema),
    application: z
      .strictObject({ assessmentId: identity, fingerprint: identity })
      .optional(),
    decision: z.strictObject({
      accepted: z.literal(true),
      reason: identity,
      evidenceKeys: z.array(identity),
      citedVersion: z.string().nullable().optional(),
    }),
    evidence: z.strictObject({
      sourceIds: z.array(identity),
      receiptIds: z.array(identity),
    }),
  });

export const dependencyClaimEvidenceSchema = z.strictObject({
  sources: z.record(identity, stackJsonValue),
  receipts: z.record(identity, stackJsonValue),
});

const tokens = z.number().int().nonnegative();
const dependencySearchSchema = z.strictObject({
  source: z.string(),
  tool: z.string(),
  scope: z.array(z.string()),
  startedAt: z.iso.datetime().nullable(),
  finishedAt: z.iso.datetime(),
  result: z.enum(["matches", "no_match", "returned", "unknown", "not_run"]),
  completeness: z.enum([
    "complete",
    "partial",
    "error",
    "unknown",
    "unavailable",
    "skipped",
  ]),
  details: z.array(z.string()),
  evidenceReferences: z.array(z.string()),
});
export type DependencySearch = z.infer<typeof dependencySearchSchema>;

export const reviewedDependencyUseSchema = reportUseSchema.safeExtend({
  place: dependencyPlaceSchema,
  decidingEvidence: z.array(reviewReference),
  conclusionClaim: dependencyClaimReferenceSchema.optional(),
  supportingClaims: z.array(dependencyClaimReferenceSchema).optional(),
});
export type ReviewedDependencyUse = z.infer<typeof reviewedDependencyUseSchema>;

export const dependencyReachabilityReportSchema = z
  .strictObject({ limitations: z.array(z.string()) })
  .extend({
    schemaVersion: z.literal(2),
    target: dependencyTargetSchema.optional(),
    uses: z.array(reviewedDependencyUseSchema),
    claims: z.array(dependencyApprovedClaimSchema).optional(),
    claimEvidence: dependencyClaimEvidenceSchema.optional(),
    assumptions: z.array(z.string()),
    searches: z.array(dependencySearchSchema),
    coverage: z.array(dependencyCoverageDispositionSchema).optional(),
    cve: z.string(),
    advisories: z.array(z.string()),
    advisoryDetails: z
      .array(
        z
          .object({ url: z.string(), affected: z.array(z.json()) })
          .passthrough(),
      )
      .optional(),
    usage: z
      .object({
        input_tokens: tokens,
        cached_input_tokens: tokens,
        cache_write_input_tokens: tokens,
        output_tokens: tokens,
        reasoning_output_tokens: tokens,
      })
      .nullable(),
  });

export const reviewedDependencyCheckSchema =
  dependencyReachabilityReportSchema.omit({ cve: true });

// The CVE form keeps its original result. A package can have zero or more
// independent issues, so each reviewed verdict belongs to a particular check.
export const dependencyPackageCheckOutputSchema = z.object({
  target: dependencyTargetSchema.optional(),
  package: z.object({ ecosystem: z.string(), name: z.string() }),
  vulnDescription: z.string().optional(),
  checks: z.array(
    reviewedDependencyCheckSchema.extend({
      advisoryId: z.string().nullable(),
    }),
  ),
});
export const dependencyCheckOutputSchema = z.union([
  dependencyReachabilityReportSchema,
  dependencyPackageCheckOutputSchema,
]);
