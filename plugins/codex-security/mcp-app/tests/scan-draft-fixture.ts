export const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

export function workerDraft<Finding extends Record<string, unknown>>(
  findings: Finding[],
  extra = {},
) {
  return {
    scanId,
    findings,
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
    ...extra,
  };
}

export function finding(id: string, repositoryPath: string) {
  return {
    ruleId: "cross-site-scripting." + id,
    identity: { anchor: id },
    title: "Unsafe request output " + id,
    summary: "A request-controlled value reaches an HTML response.",
    severity: { level: "high" },
    confidence: {
      level: "high",
      rationale: "The source establishes reachability.",
    },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: repositoryPath, startLine: 1, endLine: 2 }],
    remediation: "Encode request-controlled values before emitting HTML.",
    provenance: { source: "local_plugin" },
  };
}
