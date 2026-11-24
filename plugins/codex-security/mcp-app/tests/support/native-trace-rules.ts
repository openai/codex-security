// Explicit test-only fixtures. Production never synthesizes rules from a symbol.
import type {
  TraceStep,
  TraceEvidence,
  TraceScope,
  NativeMatch,
} from "../../src/dependency-trace/types.ts";
const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/u;
function leaf(scope: TraceScope) {
  return (scope.symbol ?? scope.package).split(/::|\./u).at(-1)!;
}
function fixtureConfig(scope: TraceScope, language: string) {
  const name = leaf(scope);
  const pkg = scope.package;
  const calls: object[] = [
    { pattern: `${name}(...)` },
    { pattern: `$RECEIVER.${name}(...)` },
  ];
  if (
    language === "python" &&
    pkg.split(".").every((part) => identifier.test(part))
  ) {
    calls.push({ pattern: `${pkg}.${name}(...)` });
  } else if (
    (language === "javascript" || language === "typescript") &&
    /^[@A-Za-z0-9._/-]+$/u.test(pkg)
  ) {
    calls.push({
      patterns: [
        {
          "pattern-inside": `import {${name} as $ALIAS} from ${JSON.stringify(pkg)};\n...`,
        },
        { pattern: "$ALIAS(...)" },
      ],
    });
  }
  const match = { "pattern-either": calls };
  const context =
    language === "python"
      ? ["def $CALLER(...):\n  ..."]
      : language === "go"
        ? ["func $CALLER(...) { ... }"]
        : [
            "function $CALLER(...) { ... }",
            "const $CALLER = (...) => ...",
            "class $CLASS { ... $CALLER(...) { ... } ... }",
          ];
  const base = {
    languages: [language],
    severity: "INFO",
    message: "Candidate call",
  };
  const withCaller = {
    patterns: [
      match,
      {
        "pattern-either": context.map((pattern) => ({
          "pattern-inside": pattern,
        })),
      },
    ],
  };
  if (scope.source_symbol) {
    return {
      rules: [
        {
          ...base,
          id: "flow",
          mode: "taint",
          message: "Candidate same-file flow",
          "pattern-sources": [
            { pattern: `${scope.source_symbol}(...)`, exact: true },
          ],
          // Disjoint sinks keep the enclosing caller when it is known, without
          // emitting a caller finding for every untainted call in the file.
          "pattern-sinks": [
            withCaller,
            {
              patterns: [
                match,
                ...context.map((pattern) => ({
                  "pattern-not-inside": pattern,
                })),
              ],
            },
          ],
        },
      ],
    };
  }
  return {
    rules: [
      { ...base, id: "fixture-caller", ...withCaller },
      {
        ...base,
        id: "fixture-top-level",
        patterns: [
          match,
          ...context.map((pattern) => ({ "pattern-not-inside": pattern })),
        ],
      },
    ],
  };
}

export function nativeRules(
  symbol: string,
  language = "python",
  sourceSymbol?: string,
  pkg = "image_lib",
): Record<string, unknown>[] {
  return fixtureConfig(
    { kind: "file", package: pkg, symbol, source_symbol: sourceSymbol },
    language,
  ).rules;
}

export function sourceStep({
  ruleExecutionId: _execution,
  nativeRuleId: _nativeId,
  ...step
}: TraceStep & {
  evidence?: { source: string; lines?: number[]; matches?: NativeMatch[] }[];
}) {
  return {
    ...step,
    ...(step.evidence && {
      evidence: step.evidence.map(({ matches: _matches, ...source }) => source),
    }),
  };
}
export function sourceEvidence(evidence: TraceEvidence[]) {
  return evidence.map(({ step, match: _match, ...item }) => ({
    ...item,
    step: sourceStep(step),
  }));
}
