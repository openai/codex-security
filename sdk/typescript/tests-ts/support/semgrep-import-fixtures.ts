// Synthetic scanner output; no Semgrep rule implementations or real findings.
export function semgrepJson() {
  return {
    version: "1.100.0",
    errors: [],
    paths: { scanned: ["src/example.ts"] },
    results: [
      {
        check_id: "example.synthetic-rule",
        path: "src/example.ts",
        start: { line: 3, col: 1, offset: 20 },
        end: { line: 3, col: 9, offset: 28 },
        extra: {
          message: "Synthetic finding",
          severity: "CRITICAL",
          fingerprint: "synthetic-fingerprint",
          is_ignored: true,
          lines: "example()",
          metadata: {
            cwe: ["CWE-000"],
            references: ["https://example.invalid/rule"],
          },
        },
      },
    ],
  };
}

export function semgrepSarif() {
  return {
    version: "2.1.0",
    runs: [
      {
        invocations: [{ executionSuccessful: true }],
        tool: {
          driver: {
            name: "Semgrep OSS",
            rules: [
              {
                id: "example.synthetic-rule",
                defaultConfiguration: { level: "error" },
                help: { text: "Synthetic rule help" },
              },
            ],
          },
        },
        results: [
          {
            ruleId: "example.synthetic-rule",
            fingerprints: { "matchBasedId/v1": "synthetic-fingerprint" },
            message: { text: "Synthetic finding" },
            suppressions: [{ kind: "inSource" }],
            codeFlows: [{ message: { text: "Synthetic dataflow" } }],
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: "src/example.ts",
                    uriBaseId: "%SRCROOT%",
                  },
                  region: {
                    startLine: 3,
                    startColumn: 1,
                    endLine: 3,
                    endColumn: 9,
                  },
                },
              },
            ],
          },
        ],
      },
    ],
  };
}

export function semgrepPercentPathReports() {
  const paths = [
    "src/my file.ts",
    "src/my%20file.ts",
    "src/100%.ts",
    "src/100%25.ts",
  ];
  const json = semgrepJson();
  const jsonResult = json.results[0]!;
  const { fingerprint: _fingerprint, ...extra } = jsonResult.extra;
  const sarif = semgrepSarif();
  const run = sarif.runs[0]!;
  const { fingerprints: _fingerprints, ...sarifResult } = run.results[0]!;
  const results = paths.map((path) => {
    const result = structuredClone(sarifResult);
    result.locations[0]!.physicalLocation.artifactLocation.uri = path;
    return result;
  });
  return {
    paths,
    json: {
      ...json,
      results: paths.map((path) => ({ ...jsonResult, path, extra })),
    },
    sarif: { ...sarif, runs: [{ ...run, results }] },
  };
}
