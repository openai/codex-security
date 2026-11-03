export const inspectorRepositoryUrl = "https://github.com/example/project";
export const inspectorIntegrationArn =
  "arn:aws:inspector2:us-east-1:123456789012:codesecurity-integration/11111111-1111-4111-8111-111111111111";
export const inspectorProjectId =
  "project-22222222-2222-4222-8222-222222222222";

export function inspectorPackageFinding() {
  return {
    findingArn: `arn:aws:inspector2:us-east-1:123456789012:finding/${"a".repeat(32)}`,
    awsAccountId: "123456789012",
    type: "PACKAGE_VULNERABILITY",
    title: "Synthetic dependency finding",
    description: "A repository dependency was reported by Inspector.",
    severity: "HIGH",
    status: "ACTIVE",
    firstObservedAt: "2026-01-02T03:04:05Z",
    lastObservedAt: "2026-01-03T04:05:06Z",
    updatedAt: "2026-01-04T05:06:07Z",
    remediation: { recommendation: { text: "Review the dependency update." } },
    resources: [
      {
        id: `${inspectorIntegrationArn}/${inspectorProjectId}`,
        type: "CODE_REPOSITORY",
        partition: "aws",
        region: "us-east-1",
        details: {
          codeRepository: {
            projectName: inspectorRepositoryUrl,
            integrationArn: inspectorIntegrationArn,
            providerType: "GITHUB",
          },
        },
      },
    ],
    fixAvailable: "YES",
    packageVulnerabilityDetails: {
      vulnerabilityId: "CVE-2099-1234",
      source: "NVD",
      sourceUrl: "https://example.invalid/advisories/CVE-2099-1234",
      relatedVulnerabilities: ["GHSA-2345-6789-cfgh"],
      vulnerablePackages: [
        {
          name: "example-package",
          version: "1.0.0",
          fixedInVersion: "1.0.1",
          packageManager: "NPM",
          filePath: "apps/web/package.json",
        },
      ],
    },
  };
}

export function inspectorReport() {
  return { findings: [inspectorPackageFinding()] };
}
