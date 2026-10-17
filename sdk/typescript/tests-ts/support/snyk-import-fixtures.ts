// Synthetic field shapes from Snyk CLI's Open Source SARIF formatter.
export function snykSarif() {
  return {
    version: "2.1.0",
    runs: [
      {
        automationDetails: { id: "Snyk/Open Source/example/0/export-time" },
        tool: {
          driver: {
            name: "Snyk Open Source",
            semanticVersion: "1.0.0",
            rules: [
              {
                id: "SNYK-EXAMPLE-1",
                shortDescription: {
                  text: "Critical severity - synthetic vulnerability in @example/package",
                },
                fullDescription: {
                  text: "(CVE-2099-0001) @example/package@1.0.0",
                },
                help: {
                  markdown:
                    "* Package Manager: npm\n* Vulnerable module: @example/package\n* Introduced through: example\n#### Detailed paths\n* _Introduced through_: example › @example/package@1.0.0\nSynthetic evidence",
                },
                properties: {
                  tags: ["security", "npm"],
                  "security-severity": "9.8",
                  unknown_numeric: 40000,
                },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "SNYK-EXAMPLE-1",
            level: "error",
            message: { text: "Synthetic dependency vulnerability" },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: "package.json" },
                  region: { startLine: 1 },
                },
                logicalLocations: [
                  { fullyQualifiedName: "@example/package@1.0.0" },
                ],
              },
            ],
            fixes: [
              { description: { text: "Upgrade the introducing dependency" } },
            ],
          },
        ],
      },
    ],
  };
}
