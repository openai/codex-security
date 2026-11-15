import { z } from "zod";
import type { DependencyUse } from "./dependency-reachability.js";

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

const reportProof = dependencyUseProofSchema.extend({
  useId: z.string().min(1),
  location: z.string().min(1),
});

export type DependencyReportProof = z.infer<typeof reportProof>;

export function assertDependencyUseProofCitations(
  proof: DependencyUseProof,
  evidence: readonly { path: string; startLine: number; endLine: number }[],
  context = "this use",
): void {
  const refs = proof.conditions.flatMap(({ citations }) => citations);
  if (proof.sink) refs.push(proof.sink.callSite);
  for (const { path, line } of refs) {
    if (
      !evidence.some(
        (cite) =>
          cite.path === path && cite.startLine <= line && line <= cite.endLine,
      )
    )
      throw new Error(
        `Proof line ${path}:${line} is outside the citations for ${context}.`,
      );
  }
}

/** Bind supplied proof only to citations already present for that saved use. */
export function parseDependencyReportProof(
  value: unknown,
  uses: ReadonlyMap<string, DependencyUse>,
): ReadonlyMap<string, DependencyReportProof> {
  const proof = new Map<string, DependencyReportProof>();
  for (const row of z.array(reportProof).parse(value)) {
    if (proof.has(row.useId))
      throw new Error(`Duplicate proof for report use ${row.useId}.`);
    const use = uses.get(row.useId);
    if (!use || use.location !== row.location)
      throw new Error(`Proof does not match report use ${row.useId}.`);

    assertDependencyUseProofCitations(
      row,
      use.evidence,
      `report use ${row.useId}`,
    );
    proof.set(row.useId, row);
  }
  return proof;
}
