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
      bothRootCauseAliases: {
        rootCause: { code: "SELECT * FROM users" },
        root_cause: {
          code: "os.system(user_input)",
          evidence_refs: ["legacy-source"],
          language: "python",
          summary: "The destination is not contained.",
        },
      },
      invalidLegacyEvidenceFields: {
        code_evidence: [
          {
            id: "legacy-source",
            code: "dangerous_call()",
            startLine: 0,
            endLine: "12",
            label: 7,
            role: { kind: "sink" },
          },
        ],
      },
      malformedCanonicalRootCause: {
        rootCause: { summary: 42 },
        root_cause: {
          summary: "The valid legacy root cause.",
          evidence_refs: ["legacy-root"],
        },
        code_evidence: [{ id: "legacy-root", code: "legacy_root()" }],
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
        bothRootCauseAliases: {
          rootCause: {
            code: "SELECT * FROM users",
            evidenceRefs: ["legacy-source"],
            summary: "The destination is not contained.",
          },
        },
        invalidLegacyEvidenceFields: {
          code_evidence: [{ id: "legacy-source", code: "dangerous_call()" }],
        },
        malformedCanonicalRootCause: {
          rootCause: {
            summary: "The valid legacy root cause.",
            evidenceRefs: ["legacy-root"],
          },
          code_evidence: [{ id: "legacy-root", code: "legacy_root()" }],
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

  test("deduplicates evidence before applying the preview limit", () => {
    const original = {
      finding: {
        codeEvidence: [
          { id: "shared", code: "canonical_shared()" },
          { id: "shared", code: "duplicate_shared()" },
          { id: "canonical-two", code: "canonical_two()" },
          { id: "canonical-three", code: "canonical_three()" },
        ],
        code_evidence: [
          { id: "shared", code: "legacy_shared()" },
          { id: "legacy-four", code: "legacy_four()" },
          { id: "legacy-five", code: "legacy_five()" },
        ],
      },
    };

    const result = projectFindingDetails(original);

    expect(
      result.projected.finding.codeEvidence.map(
        (item: { id: string }) => item.id,
      ),
    ).toEqual(["shared", "canonical-two", "canonical-three", "legacy-four"]);
    expect(result.projected.finding.codeEvidence[0].code).toBe(
      "canonical_shared()",
    );
    expect(result.original).toEqual(original);
  });

  test("filters malformed evidence before applying the preview limit", () => {
    const original = {
      finding: {
        code_evidence: [
          null,
          "junk",
          {},
          { id: "empty", code: "" },
          { id: "valid", code: "valid_source()" },
        ],
      },
    };

    const result = projectFindingDetails(original);

    expect(result.projected.finding.code_evidence).toEqual([
      { id: "valid", code: "valid_source()" },
    ]);
    expect(result.original).toEqual(original);
  });
});
