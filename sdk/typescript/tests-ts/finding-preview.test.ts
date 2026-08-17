import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

function projectFindingDetails(original: Record<string, unknown>) {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();

  const program = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from finding_preview import bounded_finding_details",
    "original = json.loads(sys.stdin.read())",
    "projected = {name: bounded_finding_details(details) for name, details in original.items()}",
    "print(json.dumps({'projected': projected, 'original': original}))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python!, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
    {
      stdin: new TextEncoder().encode(JSON.stringify(original)),
      stdout: "pipe",
      stderr: "pipe",
    },
  );

  expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout));
}

describe("bundled finding previews", () => {
  test("normalizes attack-path assessments without changing stored finding details", () => {
    const original = {
      scalar: {
        attackPath: {
          impact: "Native memory corruption is possible.",
          likelihood: "medium",
        },
      },
      structured: {
        attackPath: {
          impact: { level: "low", rationale: "Synthetic assessment." },
          likelihood: null,
        },
      },
      absentAssessments: {
        attackPath: { narrative: "Synthetic attack path." },
      },
      absentAttackPath: {
        rootCause: { summary: "Synthetic root cause." },
      },
      bothEvidenceAliases: {
        codeEvidence: [{ id: "canonical", code: "canonical_source()" }],
        code_evidence: [{ id: "legacy", code: "legacy_source()" }],
        rootCause: { summary: "Synthetic root cause." },
      },
    };
    expect(projectFindingDetails(original)).toEqual({
      projected: {
        scalar: {
          attackPath: {
            impact: { rationale: "Native memory corruption is possible." },
            likelihood: { level: "medium" },
          },
        },
        structured: original.structured,
        absentAssessments: original.absentAssessments,
        absentAttackPath: original.absentAttackPath,
        bothEvidenceAliases: {
          codeEvidence: [
            { id: "canonical", code: "canonical_source()" },
            { id: "legacy", code: "legacy_source()" },
          ],
          rootCause: { summary: "Synthetic root cause." },
        },
      },
      original,
    });
  });

  test("preserves counter-evidence under the validation preview budget", () => {
    const original = {
      finding: {
        validation: {
          evidence: ["x".repeat(20_000)],
          summary: `The traversal was reproduced. ${"x".repeat(20_000)}`,
          method: "focused extraction test",
          evidenceRefs: ["evidence-0"],
          futureMetadata: "x".repeat(20_000),
          counterEvidence: ["Known mitigations remain unverified."],
        },
      },
    };

    const result = projectFindingDetails(original);

    expect(result.projected.finding.validation.counterEvidence).toEqual([
      "Known mitigations remain unverified.",
    ]);
    expect(result.original).toEqual(original);
  });
});
