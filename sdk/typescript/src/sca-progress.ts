import type { ScaMatch, ScaResult } from "./sca-types.js";

/** Observed dependency scan work, independent of the persisted result status. */
export type DependencyScanProgress =
  | { phase: "preparing" | "discovering" | "preparing_assessment" | "saving" }
  | {
      phase: "matching";
      inputsTotal: number;
      /** OSV invocations that have finished, including failed invocations. */
      inputsProcessed: number;
      /** Failed selected inputs, including failures before an invocation starts. */
      inputsFailed: number;
      currentInput: string | null;
      components: number;
      matches: number;
    }
  | {
      phase: "assessing";
      assessmentsTotal: number;
      /** Saved assessments, including needs_review verdicts. */
      assessmentsCompleted: number;
      assessmentsFailed: number;
      /** Completed assessments whose available evidence was inconclusive. */
      assessmentsInconclusive?: number;
      current: {
        matchId: string;
        componentId: string;
        packageName: string | null;
        packageVersion: string | null;
        advisoryIds: readonly string[];
      } | null;
    };

export function assessmentProgress(
  result: ScaResult,
  match: ScaMatch | null,
): DependencyScanProgress {
  let assessmentsCompleted = 0;
  let assessmentsFailed = 0;
  let assessmentsInconclusive = 0;
  for (const assessment of result.assessments) {
    if (assessment.status === "completed") {
      assessmentsCompleted++;
      if (assessment.verdict === "needs_review") assessmentsInconclusive++;
    } else if (assessment.status === "failed") assessmentsFailed++;
  }
  const component =
    match && result.components.find((item) => item.id === match.componentId);
  return {
    phase: "assessing",
    assessmentsTotal: result.matches.length,
    assessmentsCompleted,
    assessmentsFailed,
    assessmentsInconclusive,
    current: match && {
      matchId: match.id,
      componentId: match.componentId,
      packageName: component?.name ?? null,
      packageVersion: component?.version ?? null,
      advisoryIds: [...match.advisoryIds],
    },
  };
}
