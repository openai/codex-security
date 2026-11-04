import type {
  SemanticFinding,
  SemanticCoverage,
} from "../../src/semantic-models.js";

export function semanticFinding(
  overrides: Partial<SemanticFinding> = {},
): SemanticFinding {
  return {
    ruleId: "unsafe-output",
    title: "Unsafe output",
    summary: "A request value reaches an HTML response.",
    severity: { level: "high" },
    confidence: {
      level: "high",
      rationale: "Source establishes reachability.",
    },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: "src/render.js", startLine: 1 }],
    remediation: "Encode request values in HTML responses.",
    provenance: { source: "local_plugin" },
    ...overrides,
  };
}

export function semanticCoverage(
  overrides: Partial<SemanticCoverage> = {},
): SemanticCoverage {
  return {
    surfaces: [],
    explicitExclusions: [],
    deferred: [],
    ...overrides,
  };
}

export const sameReview = {
  pair: 0,
  decision: "same",
  reason: "One renderer",
  leftEvidence: 0,
  rightEvidence: 0,
};
export const sameSource = {
  id: 0,
  fixA: "encode in render",
  fixB: "encode in render",
  survivingPaths: [],
  same: true,
};
