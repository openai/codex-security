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
