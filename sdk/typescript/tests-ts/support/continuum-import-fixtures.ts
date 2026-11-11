import { createHash } from "node:crypto";

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

export function continuumIssueExport() {
  const first = continuumDetail();
  const second = {
    ...continuumSummary("two"),
    filePath: "src/second.ts",
    lineNumber: 20,
    endLine: 24,
  };
  return {
    format: "aws-continuum-code-issues/v1" as const,
    environmentId: first.environmentId,
    issues: [
      {
        issue: {
          issueId: "issue1",
          issueArn: first.findingArn.replace(
            "/code-findings/one",
            "/code-issues/issue1",
          ),
          findingIds: [first.findingId, second.findingId],
          name: "Example issue",
          synopsis: "Example synopsis",
          severityReasoning: "Example severity reasoning",
          summary: "Example remediation summary",
          status: "COMPLETED",
          severity: "HIGH",
          statusUpdatedAt: first.statusUpdatedAt,
          updatedAt: "2026-01-02T00:03:00Z",
        },
        findings: [second, first],
      },
    ],
  };
}

export function continuumEvidenceArtifact(
  subjectRef: string,
  verdict = "EXPLOITABLE",
  artifactId = "evidence1",
) {
  return {
    artifactId,
    artifactType: "EVIDENCE",
    createdAt: "2026-01-02T00:02:00Z",
    mediaType: "application/json",
    producer: { agent: "ExamplePrioritization" },
    body: {
      prevalidationSignals: {
        producedBy: "ExamplePrioritization",
        signals: [
          {
            subjectRef,
            dimension: "EXPLOITABILITY",
            exploitability: {
              verdict,
              sourceValidationArtifactId: "validation1",
            },
            producerId: "ExampleValidator",
            confidence: 0.82,
          },
          {
            subjectRef,
            dimension: "LIKELIHOOD_ASSESSMENT",
            computed: { likelihoodBand: "MODERATE", barriers: 2 },
          },
          {
            subjectRef,
            dimension: "IMPACT_ASSESSMENT",
            conclusion: "Example impact assessment",
            computed: { impactBand: "LOW" },
          },
        ],
      },
    },
  };
}

export function patchArtifact(artifactId: string, patch: string) {
  return {
    artifactId,
    format: "GIT_DIFF",
    repositoryName: "project",
    patchSha256: createHash("sha256").update(patch).digest("hex"),
    sizeBytes: Buffer.byteLength(patch),
    patch,
  };
}
