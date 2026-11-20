import type { DependencyVerdict } from "./dependency-stack-use.js";

/** Human-facing labels; serialized verdict keys are unchanged. */
export const dependencyVerdictLabels = {
  exploitable: "Exploitable",
  potentially_exploitable: "Potentially exploitable",
  unknown: "Requires more information",
  ruled_out: "Ruled out",
} satisfies Record<DependencyVerdict, string>;
