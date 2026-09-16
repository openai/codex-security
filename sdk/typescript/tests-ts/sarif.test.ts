import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "bun:test";
import type { Finding, FindingsDocument } from "../src/models.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const example = join(PLUGIN_ROOT, "examples", "completed-scan");
const manifest = JSON.parse(
  await readFile(join(example, "scan-manifest.json"), "utf8"),
);
const document = JSON.parse(
  await readFile(join(example, "findings.json"), "utf8"),
) as FindingsDocument;

function finding(overrides: Partial<Finding> = {}): Finding {
  return { ...document.findings[0]!, ...overrides };
}

function buildSarif(findings: Finding[]) {
  const python = Bun.which("python3") ?? Bun.which("python");
  expect(python).not.toBeNull();
  const result = spawnSync(
    python!,
    [
      "-I",
      "-B",
      "-c",
      [
        "import json, sys",
        "sys.path.insert(0, sys.argv[1])",
        "from finalize_scan_contract import build_sarif",
        "payload = json.load(sys.stdin)",
        "print(json.dumps(build_sarif(payload['manifest'], payload['findings'])['runs'][0]))",
      ].join("\n"),
      join(PLUGIN_ROOT, "scripts"),
    ],
    {
      encoding: "utf8",
      input: JSON.stringify({ manifest, findings: { ...document, findings } }),
    },
  );
  expect(result.status, result.stderr).toBe(0);
  return JSON.parse(result.stdout);
}

describe("SARIF presentation", () => {
  test("keeps rule names and alert identity independent of finding text", () => {
    const source = finding({
      extensions: { candidateId: "candidate-example" },
    });
    const run = buildSarif([source]);
    const rule = run.tool.driver.rules[0];
    const result = run.results[0];
    expect(rule.name).not.toBe(source.ruleId);
    expect(rule.shortDescription.text).toBe(rule.name);
    expect(rule.help.text).toContain(source.remediation);
    expect(result.properties).toMatchObject({
      findingId: source.findingId,
      occurrenceId: source.occurrenceId,
      candidateId: "candidate-example",
    });
    for (const text of [
      source.title,
      source.summary,
      ...source.remediationTests!,
      ...source.preventiveControls!,
    ]) {
      expect(result.message.text).toContain(text);
    }

    const changed = buildSarif([
      {
        ...source,
        title: "A new title",
        summary: "A changed summary",
        remediation: "A different fix.",
      },
    ]);
    expect(changed.tool.driver.rules[0].name).toBe(rule.name);
    for (const key of [
      "ruleId",
      "ruleIndex",
      "locations",
      "partialFingerprints",
      "properties",
    ]) {
      expect(changed.results[0][key]).toEqual(result[key]);
    }
  });

  test("merges shared rule metadata without mixing result remediation", () => {
    const first = finding({
      occurrenceId: `occ_${"1".repeat(24)}`,
      severity: { level: "low" },
      remediation: "Apply the first control.",
    });
    const second = finding({
      occurrenceId: `occ_${"2".repeat(24)}`,
      severity: { level: "critical", score: 9.7, scoringSystem: "CVSS:3.1" },
      taxonomy: {
        category: "archive-extraction",
        cwe: ["cwe-022", "CWE-23", "unknown"],
      },
      remediation: "Apply the second control.",
    });
    const run = buildSarif([first, second]);
    expect(buildSarif([second, first])).toEqual(run);
    expect(run.tool.driver.rules).toHaveLength(1);
    const rule = run.tool.driver.rules[0];
    expect(rule.properties).toEqual({
      "security-severity": "9.7",
      tags: [
        "archive-extraction",
        "external/cwe/cwe-022",
        "external/cwe/cwe-023",
        "path-traversal",
        "security",
      ],
    });
    expect(rule.help.markdown).toContain(first.remediation);
    expect(rule.help.markdown).toContain(second.remediation);
    for (const [index, own, other] of [
      [0, first, second],
      [1, second, first],
    ] as const) {
      const result = run.results[index];
      expect(result.ruleIndex).toBe(0);
      expect(result.message.text).toContain(own.remediation);
      expect(result.message.text).not.toContain(other.remediation);
      expect(result.properties.severity).toBe(own.severity.level);
    }
    expect(run.results[0].level).toBe("note");
  });

  test.each([
    ["critical", undefined, "9.5"],
    ["high", undefined, "8.0"],
    ["medium", undefined, "5.0"],
    ["low", undefined, "2.0"],
    ["informational", undefined, undefined],
    ["high", 0, undefined],
    ["high", 6.25, "6.25"],
    ["critical", 10, "10"],
  ] as const)("maps %s severity with score %p", (level, score, expected) => {
    const severity =
      score === undefined
        ? { level }
        : { level, score, scoringSystem: "CVSS:3.1" };
    const run = buildSarif([
      finding({ severity, taxonomy: { category: "sql-injection", cwe: [] } }),
    ]);
    expect(run.tool.driver.rules[0].properties).toEqual({
      tags: ["security", "sql-injection"],
      ...(expected === undefined ? {} : { "security-severity": expected }),
    });
  });
});
