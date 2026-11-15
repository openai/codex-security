import { realpath } from "node:fs/promises";
import { join, relative } from "node:path";
import { z } from "zod";
import { portableRelativePath } from "./contract-values.js";
import { dependencyAdvisoryDetailsSchema } from "./dependency-advisory.js";
import {
  assertDependencyUseProofCitations,
  dependencyUseProofSchema,
} from "./dependency-report-proof.js";
import {
  createDependencySourceIdentityReader,
  type DependencySourceIdentity,
  type DependencySourceIdentityReader,
} from "./dependency-source-identity.js";
import { CodexSecurityError } from "./errors.js";
import { readRegularInputFileBytes } from "./prompt-files.js";
import { relativePathIsOutside } from "./targets.js";

const verdict = z.enum([
  "exploitable",
  "potentially_exploitable",
  "ruled_out",
  "unknown",
]);
const inventoryFact = z.enum(["affected_copy", "running", "access"]);
const fact = z.enum([...inventoryFact.options, "affected_use"]);
const evidence = z.strictObject({
  path: z.string().min(1).describe("Repository-relative source path."),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  supports: z
    .array(fact)
    .prefault([])
    .describe(
      "Facts these lines establish for this use. affected_copy identifies the affected build, including local patches; affected_use shows the operation and its advisory prerequisites in this code. running requires an observation of this deployed revision. access requires observed evidence that the relevant caller can reach that deployment under the advisory's conditions. A desired deployment or route alone cannot establish either runtime fact. Use [] for other citations.",
    ),
});
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
export const dependencyUseSchema = z
  .strictObject({
    location: z
      .string()
      .min(1)
      .describe("Consumer, service or build that uses this dependency."),
    component: z
      .string()
      .min(1)
      .describe("Name of the dependency covered by the advisory."),
    version: z
      .string()
      .nullable()
      .describe(
        "Version selected for this use by a bound import, package, build, artifact or runtime record, including a package revision when verified. A matching runtime record can establish the loaded dependency's upstream version even when package revision and patch are unknown. A bound configured selection does not require a live observation. Keep an unbound version declaration in reason and use null here. Explain packaging and patches in reason.",
      ),
    verdict: verdict.describe(
      "potentially_exploitable requires proof of the affected copy and source evidence of its applicable use. exploitable also requires confirmation of the running revision and relevant caller access. Use unknown if a deciding fact about the copy or use is missing.",
    ),
    deployment: z
      .enum(["confirmed", "configured", "unknown"])
      .describe(
        "Confirmed requires evidence that this use is running. Build or deployment configuration alone is configured.",
      ),
    reason: z.string().min(1),
    evidence: z
      .array(evidence)
      .min(1)
      .describe(
        "Cite the lines that tie the dependency to this use and support its version, deployment and verdict. Keep supporting build and package citations with the use they establish.",
      ),
    observations: z
      .array(observation)
      .prefault([])
      .describe(
        "Inventory observations for this use, including lookup results that establish no deciding fact. Use [] when no observations were obtained.",
      ),
    proof: dependencyUseProofSchema
      .optional()
      .describe(
        "The actual sink and advisory conditions for this use, checked against its own evidence. State each condition as met, unknown, or ruled_out with an explanation; do not infer statuses from the overall verdict. Every sink or condition reference must fall within this use's cited source ranges.",
      ),
    place: dependencyPlaceSchema
      .optional()
      .describe(
        "The reviewed scope of this use. Separate distinct service, job, build, artifact and library caller claims. Null fields represent facts the evidence does not establish. Keep verified exclusions scoped to the proven call, build or deployment.",
      ),
  })
  .superRefine((use, context) => {
    if (!use.proof) return;
    try {
      assertDependencyUseProofCitations(use.proof, use.evidence);
    } catch (error) {
      context.addIssue({
        code: "custom",
        path: ["proof"],
        message: error instanceof Error ? error.message : String(error),
      });
    }
  });

export const dependencyAssessmentSchema = z.strictObject({
  status: verdict.describe(
    "Overall checkout verdict. Use unknown when the evidence is insufficient to decide.",
  ),
  uses: z
    .array(dependencyUseSchema)
    .describe("One assessment per distinct use of the affected dependency."),
  limitations: z.array(z.string()),
});

export const dependencyTestScopeClassification = z.literal(
  "test_only_outside_scope",
);
export const dependencyCoverageDispositionSchema = z.strictObject({
  kind: z.enum(["dismissed", "unresolved"]),
  reason: z.string().min(1),
  evidence: dependencyUseSchema.shape.evidence,
  observations: dependencyUseSchema.shape.observations,
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

export type DependencyCoverageDisposition = z.infer<
  typeof dependencyCoverageDispositionSchema
>;
export type DependencyAssessment = z.infer<
  typeof dependencyAssessmentSchema
> & {
  /** Reviewed decisions about checked code that is not an assessed use. */
  coverage?: DependencyCoverageDisposition[];
};
export type DependencyUse = z.infer<typeof dependencyUseSchema>;
export type DependencyVerdict = DependencyUse["verdict"];

export interface DependencyAssessmentCoverage {
  /** Actual unresolved candidate/evidence gaps, not a descriptive scope note. */
  unresolved?: boolean;
}

/** Derive the report verdict from validated uses and explicit remaining gaps. */
export function aggregateDependencyVerdict(
  uses: readonly DependencyUse[],
  coverage: DependencyAssessmentCoverage = {},
): DependencyVerdict {
  if (uses.some((use) => use.verdict === "exploitable")) return "exploitable";
  if (uses.some((use) => use.verdict === "potentially_exploitable"))
    return "potentially_exploitable";
  if (
    coverage.unresolved ||
    uses.length === 0 ||
    uses.some((use) => use.verdict === "unknown")
  )
    return "unknown";
  return "ruled_out";
}

export interface DependencyExcerpt {
  path: string;
  startLine: number;
  endLine: number;
  text: string;
  sourceIdentity?: DependencySourceIdentity;
}

export async function readDependencyEvidence(
  evidence: readonly DependencyUse["evidence"][number][],
  repository: string,
  signal?: AbortSignal,
  onExcerpt?: (excerpt: DependencyExcerpt) => void,
  readSourceIdentity = createDependencySourceIdentityReader(repository),
  onShortSourceNote?: (
    path: string,
    startLine: number,
    requestedEnd: number,
    endLine: number,
  ) => void,
): Promise<void> {
  // Read each cited file once and retain only its submitted ranges.
  const citations = Map.groupBy(evidence, (cite) => cite.path);
  for (const [path, ranges] of citations) {
    signal?.throwIfAborted();
    const file = await realpath(
      join(repository, portableRelativePath(path, "Evidence path")),
    );
    if (relativePathIsOutside(relative(repository, file))) {
      throw new CodexSecurityError(
        `Evidence path leaves the checkout: ${path}`,
      );
    }
    const bytes = await readRegularInputFileBytes(file, repository);
    const source = bytes.toString("utf8");
    const sourceIdentity = onExcerpt
      ? await readSourceIdentity(file, bytes, signal)
      : undefined;
    // A trailing newline terminates the last line; it does not add a line.
    const lines = source ? source.replace(/\n$/u, "").split("\n") : [];
    for (const { startLine, endLine: requestedEnd } of ranges) {
      const endLine = onShortSourceNote
        ? Math.min(requestedEnd, lines.length)
        : requestedEnd;
      if (startLine > endLine || endLine > lines.length) {
        throw new CodexSecurityError(
          `Invalid evidence range ${path}:${startLine}-${requestedEnd} (file has ${lines.length} lines).`,
        );
      }
      if (endLine !== requestedEnd)
        onShortSourceNote?.(path, startLine, requestedEnd, endLine);
      onExcerpt?.({
        path,
        startLine,
        endLine,
        text: lines.slice(startLine - 1, endLine).join("\n"),
        sourceIdentity,
      });
    }
  }
}

export async function validateDependencyAssessment(
  value: unknown,
  repository: string,
  signal?: AbortSignal,
  observedInventoryServers: readonly string[] = [],
  onExcerpt?: (excerpt: DependencyExcerpt) => void,
  coverage?: DependencyAssessmentCoverage,
  readSourceIdentity?: DependencySourceIdentityReader,
): Promise<DependencyAssessment> {
  const assessment = dependencyAssessmentSchema.parse(value);
  await readDependencyEvidence(
    assessment.uses.flatMap((use) => use.evidence),
    repository,
    signal,
    onExcerpt,
    readSourceIdentity,
  );
  for (const use of assessment.uses) {
    for (const { server } of use.observations) {
      if (!observedInventoryServers.includes(server)) {
        throw new CodexSecurityError(
          `Inventory server did not return a successful result in this check: ${server}`,
        );
      }
    }
    const facts = new Set(
      [...use.evidence, ...use.observations].flatMap(
        (source) => source.supports,
      ),
    );
    const missingRunning =
      use.deployment === "confirmed" && !facts.has("running");
    if (missingRunning) {
      use.deployment = "unknown";
    }
    if (
      use.verdict !== "exploitable" &&
      use.verdict !== "potentially_exploitable"
    ) {
      if (missingRunning) {
        const gap =
          "Missing required evidence that this use is running in this deployment.";
        if (!use.reason.endsWith(gap)) use.reason += ` ${gap}`;
      }
      continue;
    }
    const missing: string[] = [];
    if (!facts.has("affected_copy"))
      missing.push("the affected dependency copy");
    if (!facts.has("affected_use")) missing.push("the applicable use in code");
    if (missing.length) {
      use.verdict = "unknown";
    } else {
      if (use.deployment !== "confirmed" || !facts.has("running"))
        missing.push("the affected revision running in this deployment");
      if (!facts.has("access"))
        missing.push("access to this deployment by the relevant caller");
      if (missing.length) use.verdict = "potentially_exploitable";
    }
    if (missing.length) {
      const gap = `Missing required evidence for ${missing.join(" and ")}.`;
      if (!use.reason.endsWith(gap)) use.reason += ` ${gap}`;
    }
  }
  signal?.throwIfAborted();

  // Without an independent coverage decision, reconciling individual uses
  // cannot turn an inconclusive report into a checkout-wide exclusion.
  assessment.status = aggregateDependencyVerdict(
    assessment.uses,
    coverage ?? { unresolved: assessment.status !== "ruled_out" },
  );
  return assessment;
}

/** Validate one item's citations and proof flags without invoking a reviewer. */
export async function validateDependencyUse(
  value: unknown,
  repository: string,
  signal?: AbortSignal,
  observedInventoryServers: readonly string[] = [],
  onExcerpt?: (excerpt: DependencyExcerpt) => void,
  readSourceIdentity?: DependencySourceIdentityReader,
): Promise<DependencyUse> {
  const assessment = await validateDependencyAssessment(
    { status: "unknown", uses: [value], limitations: [] },
    repository,
    signal,
    observedInventoryServers,
    onExcerpt,
    undefined,
    readSourceIdentity,
  );
  return assessment.uses[0]!;
}

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

export const reviewedDependencyUseSchema = dependencyUseSchema.safeExtend({
  place: dependencyPlaceSchema,
  decidingEvidence: z.array(reviewReference),
});
export type ReviewedDependencyUse = z.infer<typeof reviewedDependencyUseSchema>;

export const dependencyReachabilityReportSchema = dependencyAssessmentSchema
  .omit({ status: true })
  .extend({
    schemaVersion: z.literal(2),
    uses: z.array(reviewedDependencyUseSchema),
    assumptions: z.array(z.string()),
    searches: z.array(dependencySearchSchema),
    coverage: z.array(dependencyCoverageDispositionSchema).optional(),
    cve: z.string(),
    advisories: z.array(z.string()),
    advisoryDetails: z.array(dependencyAdvisoryDetailsSchema).optional(),
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

export function withReviewedPlace(
  use: DependencyUse,
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
