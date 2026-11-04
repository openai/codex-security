export const continuumRepository = "https://github.com/example/project";

export function continuumSummary(findingId = "one", environmentId = "example") {
  return {
    findingArn: `arn:aws:continuum:us-east-1:000000000000:environments/${environmentId}/code-findings/${findingId}`,
    findingId,
    environmentId,
    source: "example-scanner",
    sourceFindingId: "upstream-example",
    type: "CUSTOMER_CODE_VULN",
    reportedAt: "2026-01-02T00:00:00Z",
    createdAt: "2026-01-02T00:01:00Z",
    statusUpdatedAt: "2026-01-02T00:01:00Z",
    status: "SUBMITTED",
    severity: "FATAL",
    title: "Example code finding",
    filePath: "src/example.ts",
  };
}

export function continuumDetail() {
  const summary = continuumSummary();
  return {
    ...summary,
    status: "CONFIRMED",
    statusUpdatedAt: "2026-01-02T00:02:00Z",
    detailedDescription: "Example description",
    mitigation: "Use the checked example.",
    cweIds: ["CWE-20"],
    lineNumber: 3,
    endLine: 5,
    vulnerableCode: "readExample(input)",
    vulnerabilities: [
      {
        locations: [
          { filePath: summary.filePath, startLine: 3, endLine: 5 },
          { filePath: "src/other.ts", startLine: 12, endLine: 12 },
        ],
      },
    ],
    validation: {
      verdict: "TRUE_POSITIVE",
      evidence: [
        { file: summary.filePath, line: 3, snippet: "readExample(input)" },
      ],
    },
  };
}
