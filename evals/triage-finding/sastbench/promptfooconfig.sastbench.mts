import { readFileSync } from "node:fs";
import { parse } from "yaml";

type Scores = Record<string, number>;
type Metric = (scores: Scores) => number;

const metric = (name: string, value: Metric) => ({ name, value });
const ratio = (numerator: number, denominator: number) =>
  numerator / Math.max(denominator, 1);

function classification(prefix: "strict" | "decided", total: Metric) {
  const summarize = (
    name: string,
    value: (
      tp: number,
      tn: number,
      fp: number,
      fn: number,
      total: number,
    ) => number,
  ) =>
    metric(`${prefix}_${name}`, (s) =>
      value(
        s[`${prefix}_tp`],
        s[`${prefix}_tn`],
        s[`${prefix}_fp`],
        s[`${prefix}_fn`],
        total(s),
      ),
    );
  return [
    summarize("precision", (tp, _tn, fp) => ratio(tp, tp + fp)),
    summarize("recall", (tp, _tn, _fp, fn) => ratio(tp, tp + fn)),
    summarize("f1", (tp, _tn, fp, fn) => ratio(2 * tp, 2 * tp + fp + fn)),
    summarize("f2", (tp, _tn, fp, fn) => ratio(5 * tp, 5 * tp + fp + 4 * fn)),
    summarize("accuracy", (tp, tn, _fp, _fn, count) => ratio(tp + tn, count)),
    summarize("mcc", (tp, tn, fp, fn) =>
      ratio(
        tp * tn - fp * fn,
        Math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)),
      ),
    ),
  ];
}

const allCases = (s: Scores) => s.positive_cases + s.negative_cases;

export default {
  description: "Codex Security triage-finding SastBench v0.1 eval",
  tags: { suite: "sastbench-v0.1" },
  prompts: ["file://./prompts/sastbench-triage-request.txt"],
  providers: [
    parse(
      readFileSync(
        new URL("../providers/sastbench.yaml", import.meta.url),
        "utf8",
      ),
    ),
  ],
  extensions: ["file://./assertions/sastbench-metrics.mts:afterEach"],
  defaultTest: {
    assert: [
      {
        type: "contains-json",
        value: "file://../schemas/triage-result-v0.schema.json",
        metric: "schema_valid",
      },
      {
        type: "javascript",
        value: "file://./assertions/sastbench-verdict.mts",
        metric: "strict_case_correct",
      },
    ],
  },
  // afterEach emits additive counts, weighted for representative sample rows.
  derivedMetrics: [
    ...classification("strict", allCases),
    ...classification("decided", (s) => s.decided_cases),
    metric("decided_coverage", (s) => ratio(s.decided_cases, allCases(s))),
    metric("true_positive_retention", (s) =>
      ratio(s.retained_positive, s.positive_cases),
    ),
    metric("unsafe_closure_rate", (s) =>
      ratio(s.unsafe_closure, s.positive_cases),
    ),
    metric("false_alert_auto_closure_rate", (s) =>
      ratio(s.false_alert_auto_closure, s.negative_cases),
    ),
    metric("false_alert_escalation_rate", (s) =>
      ratio(s.false_alert_escalation, s.negative_cases),
    ),
    metric("confirmed_precision", (s) =>
      ratio(s.confirmed_true, s.confirmed_total),
    ),
    metric("abstention_rate", (s) => ratio(s.abstention, allCases(s))),
    metric("remaining_analyst_workload", (s) =>
      ratio(s.remaining_analyst_work, allCases(s)),
    ),
    metric("execution_or_parse_error_rate", (s) =>
      ratio(s.execution_or_parse_error, allCases(s)),
    ),
  ],
  tests: "file://./scripts/sastbench-lib.mts:generateTests",
};
