// Synthetic native scanner output; no rule implementations or real findings.
export function opengrepJson() {
  const location = {
    path: "src/example.ts",
    start: { line: 3, col: 1, offset: 20 },
    end: { line: 3, col: 9, offset: 28 },
  };
  return {
    version: "1.32.0",
    errors: [
      {
        code: 2,
        level: "warn",
        type: "Timeout",
        rule_id: "example.other-rule",
        path: "src/skipped.ts",
        message: "Synthetic rule timeout",
      },
    ],
    paths: {
      scanned: ["src/example.ts", "src/skipped.ts"],
      skipped: [{ path: "src/skipped.ts", reason: "analysis_failed" }],
    },
    time: { total: 0.5 },
    configuration: { digest: "synthetic-config-digest" },
    results: [
      {
        check_id: "example.synthetic-rule",
        ...location,
        extra: {
          message: "Synthetic finding",
          severity: "WARNING",
          fingerprint: "synthetic-fingerprint_0",
          is_ignored: false,
          lines: "example()",
          validation_state: "NO_VALIDATOR",
          engine_kind: "OSS",
          metadata: {
            category: "security",
            confidence: "HIGH",
            cwe: ["CWE-000"],
            references: ["https://example.invalid/rule"],
          },
          metavars: { $VALUE: { abstract_content: "input" } },
          dataflow_trace: {
            taint_source: ["CliLoc", [structuredClone(location), "input"]],
            intermediate_vars: [],
            taint_sink: ["CliLoc", [structuredClone(location), "example()"]],
          },
        },
      },
    ],
  };
}

export function opengrepTraceJson() {
  const input = opengrepJson();
  const observation = structuredClone(input.results[0]!);
  observation.extra.dataflow_trace.taint_source = [
    "CliLoc",
    [
      {
        path: "src/input.ts",
        start: { line: 1, col: 1, offset: 0 },
        end: { line: 1, col: 6, offset: 5 },
      },
      "other",
    ],
  ];
  input.results.push(observation);
  return input;
}
