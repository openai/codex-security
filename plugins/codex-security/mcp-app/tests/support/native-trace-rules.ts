// Explicit test-only fixtures. Production never synthesizes rules from a symbol.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
  TraceStep,
  TraceEvidence,
  NativeMatch,
} from "../../src/dependency-trace/types.ts";
const identifier = /^[A-Za-z_][A-Za-z0-9_]*$/u;
export function nativeRules(
  symbol: string,
  language = "python",
  sourceSymbol?: string,
  pkg = "image_lib",
): Record<string, unknown>[] {
  const name = (symbol ?? pkg).split(/::|\./u).at(-1)!;
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

  const topLevel = {
    patterns: [
      match,
      ...context.map((pattern) => ({ "pattern-not-inside": pattern })),
    ],
  };
  if (sourceSymbol) {
    return [
      {
        ...base,
        id: "flow",
        mode: "taint",
        message: "Candidate same-file flow",
        "pattern-sources": [{ pattern: `${sourceSymbol}(...)`, exact: true }],
        // Disjoint sinks keep the enclosing caller when it is known, without
        // emitting a caller finding for every untainted call in the file.
        "pattern-sinks": [withCaller, topLevel],
      },
    ];
  }
  return [
    { ...base, id: "fixture-caller", ...withCaller },
    { ...base, id: "fixture-top-level", ...topLevel },
  ];
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

export async function available(command: string) {
  return promisify(execFile)(command, ["--version"]).then(
    () => true,
    () => false,
  );
}
