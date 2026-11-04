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

// Synthetic example of the official snyk-findings-export/v1 bundle contract.
export function snykPluginExport() {
  return {
    format: "snyk-findings-export/v1",
    provider: "snyk",
    collection: {
      collector: { skill: "snyk-findings-export", pluginVersion: "0.1.0" },
      scanner: { name: "snyk-cli", version: "1.0.0", via: "snyk mcp -t stdio" },
      startedAt: "2026-01-01T00:00:00Z",
      finishedAt: "2026-01-01T00:01:00Z",
      target: {
        path: "/work/example",
        repository: "https://github.com/example/project.git",
        revision: "synthetic-revision",
        workingTreeDirty: false,
        changedPaths: [] as string[],
      },
      org: {
        state: "unknown",
        reason: "snyk_sca_scan does not report the org",
      },
      scans: [
        {
          category: "sca",
          tool: "snyk_sca_scan",
          outcome: "succeeded",
          issueCount: 1,
        },
      ],
      completeness: { collection: "complete", analysis: "SCA succeeded" },
      limitations: [
        "Local workspace scan; not a Snyk platform project export.",
      ],
    },
    findings: [
      {
        id: {
          value:
            "sca:SNYK-EXAMPLE-1|npm:@example/package@1.0.0|package.json|example@1.0.0 > @example/package@1.0.0",
          kind: "composite",
          basis: "sca composite",
          scope: "collection.target.repository",
        },
        category: "dependency_vulnerability",
        originatingScanner: "snyk-open-source",
        title: "Synthetic vulnerability",
        description: { text: "Partial scanner description" },
        rule: {
          id: "SNYK-EXAMPLE-1",
          aliases: { cve: ["CVE-2099-0001"], cwe: ["CWE-79"] },
        },
        severity: {
          value: "high",
          scale: "low | medium | high | critical",
          authority: "snyk",
        },
        status: {
          value: "ignored",
          meaning: "Suppressed by policy",
          authority: "snyk-cli",
        },
        asset: {
          type: "package_occurrence",
          package: {
            ecosystem: "npm",
            name: "@example/package",
            version: "1.0.0",
          },
          manifest: "package.json",
          transitive: true,
        },
        remediation: {
          fixedIn: ["1.0.1"],
          advice: "Upgrade the direct dependency",
        },
        evidence: {
          introducedThrough: ["example@1.0.0", "@example/package@1.0.0"],
        },
        observation: { scan: "sca", observedAt: "2026-01-01T00:01:00Z" },
        unavailable: {
          description: {
            state: "truncated",
            reason: "snyk_sca_scan truncates messages",
          },
        },
        nativeRecord: {
          id: "SNYK-EXAMPLE-1",
          packageName: "@example/package",
          version: "1.0.0",
          filePath: "/work/example/package.json",
          isIgnored: true,
          unknownField: "retained",
        },
      },
    ],
  };
}

// Synthetic fields from Snyk CLI's TestResult/AnnotatedIssue native JSON output.
export function snykJson() {
  return {
    ok: false,
    vulnerabilities: [
      {
        id: "SNYK-EXAMPLE-1",
        title: "Synthetic vulnerability",
        description: "Complete native advisory description",
        severity: "high",
        name: "@example/package",
        packageName: "@example/package",
        version: "1.0.0",
        identifiers: { CVE: ["CVE-2099-0001"], CWE: ["CWE-79"] },
        from: ["example@1.0.0", "@example/package@1.0.0"],
        upgradePath: [false, "@example/package@1.0.1"],
        fixedIn: ["1.0.1"],
        isUpgradable: true,
        isPatchable: false,
      },
    ],
    dependencyCount: 1,
    packageManager: "npm",
    targetFile: "package.json",
    displayTargetFile: "package.json",
    projectName: "example",
    path: "/work/example",
    policy: "synthetic policy context",
    summary: "1 vulnerability",
  };
}
