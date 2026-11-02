// Synthetic records shaped after Endor's Finding model and its published SARIF sample.
export function endorFinding() {
  return {
    uuid: "finding-example-1",
    meta: {
      name: "Synthetic vulnerable dependency",
      update_time: "2026-01-01T00:00:00Z",
    },
    context: { type: "CONTEXT_TYPE_REF", id: "main" },
    spec: {
      project_uuid: "project-example",
      level: "FINDING_LEVEL_CRITICAL",
      summary: "Synthetic dependency finding",
      ecosystem: "ECOSYSTEM_NPM",
      target_dependency_name: "@example/package",
      target_dependency_version: "1.0.0",
      proposed_version: "2.0.0",
      dependency_file_paths: ["package.json", "package-lock.json"],
      finding_categories: ["FINDING_CATEGORY_VULNERABILITY"],
      finding_metadata: {
        vulnerability: {
          meta: { name: "CVE-2099-0001" },
          spec: { aliases: ["GHSA-2222-3333-4444"] },
        },
      },
      reachable_paths: [{ nodes: [{ function: "syntheticFunction" }] }],
      dismiss: false,
    },
  };
}

export function endorSarif() {
  return {
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "endorctl",
            semanticVersion: "1.0.0",
            rules: [
              {
                id: "synthetic-rule",
                shortDescription: { text: "Synthetic finding" },
                fullDescription: { text: "Synthetic explanation" },
                help: { text: "Synthetic remediation" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "synthetic-rule",
            message: { text: "Synthetic result" },
            properties: {
              "finding-uuid": "finding-example-1",
              "project-uuid": "project-example",
              categories: ["VULNERABILITY"],
              tags: ["REACHABLE_FUNCTION"],
              "cvss-score": 9.8,
              "finding-url":
                "https://example.invalid/findings/finding-example-1",
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "package.json" },
                  region: { startLine: 1 },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}
