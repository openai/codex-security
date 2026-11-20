import { z } from "zod";
import { dependencyGitCommitSchema } from "./dependency-source-identity.js";

const lineReference = z.strictObject({
  path: z.string().min(1),
  line: z.number().int().positive(),
});

const condition = z
  .strictObject({
    label: z.string().trim().min(1),
    status: z.enum(["met", "unknown", "ruled_out"]),
    explanation: z.string().trim().min(1),
    citations: z.array(lineReference),
  })
  .refine(
    ({ status, citations }) => status === "unknown" || citations.length > 0,
    {
      path: ["citations"],
      message: "A met or ruled-out condition requires at least one cited line.",
    },
  );

export const dependencyUseProofSchema = z.strictObject({
  sink: z
    .strictObject({
      function: z
        .string()
        .trim()
        .min(1)
        .describe(
          "Affected function or wrapper operation established for this use. Do not present an unresolved native target as established.",
        ),
      callSite: lineReference,
    })
    .optional(),
  conditions: z.array(condition),
});

export type DependencyUseProof = z.infer<typeof dependencyUseProofSchema>;

export function assertDependencyUseProofCitations(
  proof: DependencyUseProof,
  evidence: readonly {
    path: string;
    startLine: number;
    endLine: number;
    commit?: string;
  }[],
  context = "this use",
): void {
  const refs: { path: string; line: number; commit?: string }[] =
    proof.conditions.flatMap(({ citations }) => citations);
  if (proof.sink) refs.push(proof.sink.callSite);
  for (const { path, line, commit } of refs) {
    if (
      !evidence.some(
        (cite) =>
          cite.path === path &&
          (commit === undefined || cite.commit === commit) &&
          cite.startLine <= line &&
          line <= cite.endLine,
      )
    )
      throw new Error(
        `Proof line ${path}:${line} is outside the citations for ${context}.`,
      );
  }
}

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
  commit: dependencyGitCommitSchema.optional(),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  supports: z
    .array(fact)
    .prefault([])
    .describe(
      "Facts these lines establish for this use. affected_copy identifies the affected build, including local patches; affected_use shows the operation and its advisory prerequisites in this code. running requires an observation of this deployed revision. access requires observed evidence that the relevant caller can reach that deployment under the advisory's conditions. A desired deployment or route alone cannot establish either runtime fact. Use [] for other citations.",
    ),
});
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
    proof: dependencyUseProofSchema
      .optional()
      .describe(
        "The actual sink and advisory conditions for this use, checked against its own evidence. State each condition as met, unknown, or ruled_out with an explanation; do not infer statuses from the overall verdict. Every sink or condition reference must fall within this use's cited source ranges.",
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

export type DependencyUse = z.infer<typeof dependencyUseSchema>;
export type DependencyVerdict = DependencyUse["verdict"];

export interface DependencyAssessmentCoverage {
  /** Actual unresolved candidate/evidence gaps, not a descriptive scope note. */
  unresolved?: boolean;
}

/** Derive the report verdict from validated uses and explicit remaining gaps. */
export function aggregateDependencyVerdict(
  uses: readonly Pick<DependencyUse, "verdict">[],
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
