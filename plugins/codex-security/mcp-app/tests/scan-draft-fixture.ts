export const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

export function workerDraft<Finding extends Record<string, unknown>>(
  findings: Finding[],
  extra = {},
) {
  return {
    scanId,
    findings,
    reviewState: {
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
    severity: { level: "high" as const },
    confidence: {
      level: "high" as const,
      rationale: "The source establishes reachability.",
    },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: repositoryPath, startLine: 1, endLine: 2 }],
    remediation: "Encode request-controlled values before emitting HTML.",
    provenance: { source: "local_plugin" },
  };
}

export function completedFinding(id: string, repositoryPath: string) {
  return {
    ...finding(id, repositoryPath),
    ...completedFindingEvidence(repositoryPath),
  };
}

export function completedFindingEvidence(repositoryPath: string) {
  return {
    codeEvidence: [
      {
        id: "request-output",
        label: "Request output",
        path: repositoryPath,
        startLine: 1,
        code: "return request.value",
        explanation: "The response includes the request-controlled value.",
      },
    ],
    rootCause: "Request-controlled output is returned without HTML encoding.",
    attackPath: { dataflow: "Request input flows into the returned response." },
    validation: {
      method: "Static source inspection",
      summary: "The output path does not encode the request value.",
      evidence: "The return statement uses the unencoded request value.",
    },
  };
}
