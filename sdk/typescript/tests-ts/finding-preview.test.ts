import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

describe("bundled finding previews", () => {
  test("normalizes attack-path assessments without changing stored finding details", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();

    const original = {
      scalar: {
        attackPath: { impact: "high", likelihood: "medium" },
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
    };
    const program = [
      "import json, sys",
      "sys.path.insert(0, sys.argv[1])",
      "from finding_preview import bounded_finding_details",
      "original = json.loads(sys.argv[2])",
      "projected = {name: bounded_finding_details(details) for name, details in original.items()}",
      "print(json.dumps({'projected': projected, 'original': original}))",
    ].join("\n");
    const result = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        "-c",
        program,
        join(PLUGIN_ROOT, "scripts"),
        JSON.stringify(original),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      projected: {
        scalar: {
          attackPath: {
            impact: { level: "high" },
            likelihood: { level: "medium" },
          },
        },
        structured: original.structured,
        absentAssessments: original.absentAssessments,
        absentAttackPath: original.absentAttackPath,
      },
      original,
    });
  });

  test("preserves nested attack-path string arrays without relaxing section depth", () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    expect(python).not.toBeNull();

    const original = {
      supported: {
        attackPath: {
          dataflow: { evidenceRefs: ["source-to-sink"] },
          reachability: { preconditions: ["The handler is reachable."] },
        },
      },
      tooDeep: {
        attackPath: {
          dataflow: {
            nested: { evidenceRefs: ["must remain depth-limited"] },
          },
        },
      },
    };
    const program = [
      "import json, sys",
      "sys.path.insert(0, sys.argv[1])",
      "from finding_preview import bounded_finding_details",
      "original = json.loads(sys.argv[2])",
      "projected = {name: bounded_finding_details(details) for name, details in original.items()}",
      "print(json.dumps(projected))",
    ].join("\n");
    const result = Bun.spawnSync(
      [
        python!,
        "-I",
        "-B",
        "-c",
        program,
        join(PLUGIN_ROOT, "scripts"),
        JSON.stringify(original),
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    expect(JSON.parse(new TextDecoder().decode(result.stdout))).toEqual({
      supported: original.supported,
      tooDeep: {
        attackPath: {
          dataflow: {
            nested: { evidenceRefs: [null] },
          },
        },
      },
    });
  });
});
