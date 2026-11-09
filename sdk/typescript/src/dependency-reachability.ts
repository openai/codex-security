import { realpath } from "node:fs/promises";
import { join, relative } from "node:path";
import { z } from "zod";
import { portableRelativePath } from "./contract-values.js";
import { CodexSecurityError } from "./errors.js";
import { readRegularInputFile } from "./prompt-files.js";
import { relativePathIsOutside } from "./targets.js";

const verdict = z.enum([
  "exploitable",
  "potentially_exploitable",
  "ruled_out",
  "unknown",
]);
const runtimeFact = z.enum(["running", "access"]);
const fact = z.enum(["affected_copy", "affected_use", ...runtimeFact.options]);
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
    .array(runtimeFact)
    .describe(
      "Which runtime facts this record establishes for the same affected use: observed running revision, or actual access by the relevant caller (including public access for an Internet-facing claim). Use [] to cite inventory evidence that establishes neither runtime fact.",
    ),
});
export const dependencyUseSchema = z.strictObject({
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
      "Resolved version of that dependency for this use, including any package revision. Use null if unknown. Explain packaging and patches in reason.",
    ),
  verdict: verdict.describe(
    "potentially_exploitable requires source evidence for both the affected copy and its applicable use. exploitable also requires confirmation of the running revision and relevant caller access. Use unknown if a deciding source-level fact is missing.",
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
      "Inventory observations for this use, including lookup results that establish no runtime fact. Use [] when no observations were obtained.",
    ),
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

export type DependencyAssessment = z.infer<typeof dependencyAssessmentSchema>;
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
}

export async function validateDependencyAssessment(
  value: unknown,
  repository: string,
  signal?: AbortSignal,
  observedInventoryServers: readonly string[] = [],
  onExcerpt?: (excerpt: DependencyExcerpt) => void,
  coverage?: DependencyAssessmentCoverage,
): Promise<DependencyAssessment> {
  const assessment = dependencyAssessmentSchema.parse(value);
  // Read each cited file once and retain only its submitted ranges.
  const citations = Map.groupBy(
    assessment.uses.flatMap((use) => use.evidence),
    (cite) => cite.path,
  );
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
    const source = await readRegularInputFile(file, repository);
    // A trailing newline terminates the last line; it does not add a line.
    const lines = source ? source.replace(/\n$/u, "").split("\n") : [];
    for (const { startLine, endLine } of ranges) {
      if (startLine > endLine || endLine > lines.length) {
        throw new CodexSecurityError(
          `Invalid evidence range ${path}:${startLine}-${endLine} (file has ${lines.length} lines).`,
        );
      }
      onExcerpt?.({
        path,
        startLine,
        endLine,
        text: lines.slice(startLine - 1, endLine).join("\n"),
      });
    }
  }
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
): Promise<DependencyUse> {
  const assessment = await validateDependencyAssessment(
    { status: "unknown", uses: [value], limitations: [] },
    repository,
    signal,
    observedInventoryServers,
    onExcerpt,
  );
  return assessment.uses[0]!;
}

const tokens = z.number().int().nonnegative();
export const dependencyReachabilityReportSchema =
  dependencyAssessmentSchema.extend({
    cve: z.string(),
    advisories: z.array(z.string()),
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
export const dependencyCheckOutputSchema = z.union([
  dependencyReachabilityReportSchema,
  z.object({
    package: z.object({ ecosystem: z.string(), name: z.string() }),
    vulnDescription: z.string().optional(),
    checks: z.array(
      reviewedDependencyCheckSchema.extend({
        advisoryId: z.string().nullable(),
      }),
    ),
  }),
]);
