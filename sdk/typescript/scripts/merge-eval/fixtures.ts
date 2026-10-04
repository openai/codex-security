import type { ScanAggregate, ScanMergeInput } from "../../src/scan-merge.js";
import type { SemanticFinding } from "../../src/semantic-models.js";
import { semanticCoverage } from "../../tests-ts/helpers/semantic-scan.js";

export const parentId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

export interface ExpectedGroup {
  refs: string[];
  severity: SemanticFinding["severity"]["level"];
  facts: Record<string, string[]>;
}

export interface MergeFixture {
  name: string;
  inputs: ScanMergeInput[];
  previous: ScanAggregate | null;
  expected: ExpectedGroup[];
  reference: Omit<ScanAggregate, "sourceFindings">;
  groups: string[][];
}

// Completed, synthetic observations only. No source code or reproduction steps.
function observation(
  anchor: string,
  repair: string,
  level: SemanticFinding["severity"]["level"] = "medium",
): SemanticFinding {
  return {
    ruleId: "security-misconfiguration.synthetic-record",
    identity: { anchor },
    title: "Configuration isolation needs correction",
    summary: `The completed assessment identifies configuration ${anchor}. Each named configuration is independently deployed and requires its own repair.`,
    severity: { level },
    confidence: { level: "high", rationale: "Completed synthetic assessment." },
    taxonomy: { category: "security-misconfiguration", cwe: ["CWE-16"] },
    locations: [{ path: `src/${anchor}.ts`, startLine: 1 }],
    remediation: `Correct configuration ${repair}.`,
    remediationTests: [`Verify ${repair}-test.`],
    preventiveControls: [`Maintain ${repair}-control.`],
    provenance: { source: "local_plugin" },
  };
}

function input(scanId: string, findings: SemanticFinding[]): ScanMergeInput {
  return {
    scanId,
    scanDir: scanId,
    sourceFindings: structuredClone(findings),
    draft: {
      scanId: parentId,
      findings: findings.map((finding, index) => ({
        ...structuredClone(finding),
        provenance: {
          source: "local_plugin",
          sourceFindingIds: [`${scanId}:${index}`],
        },
      })),
      coverage: semanticCoverage({
        completeness: "partial",
        deferred: [{ reason: "Synthetic outstanding work." }],
      }),
    },
  };
}

function group(
  refs: string[],
  repairs: string[],
  severity: SemanticFinding["severity"]["level"] = "medium",
): ExpectedGroup {
  return {
    refs,
    severity,
    facts: {
      remediation: repairs,
      remediationTests: repairs.map((repair) => `${repair}-test`),
      preventiveControls: repairs.map((repair) => `${repair}-control`),
    },
  };
}

function fixture(
  name: string,
  inputs: ScanMergeInput[],
  expected: ExpectedGroup[],
  previous: ScanAggregate | null = null,
): MergeFixture {
  const byRef = new Map<string, SemanticFinding>();
  for (const finding of previous?.findings ?? []) {
    for (const ref of finding.provenance.sourceFindingIds ?? [])
      byRef.set(ref, finding);
  }
  for (const child of inputs)
    child.draft.findings.forEach((finding, index) =>
      byRef.set(`${child.scanId}:${index}`, finding),
    );
  const reference = {
    scanId: parentId,
    findings: expected.map((expectedGroup) => ({
      ...structuredClone(byRef.get(expectedGroup.refs[0]!)!),
      severity: {
        level: expectedGroup.severity,
        rationale:
          "Retained the completed assessment of the shared configuration.",
        changeConditions: "Reassess if deployment isolation changes.",
      },
      remediation: expectedGroup.facts["remediation"]!.join("; "),
      remediationTests: expectedGroup.facts["remediationTests"],
      preventiveControls: expectedGroup.facts["preventiveControls"],
      provenance: {
        source: "local_plugin",
        sourceFindingIds: expectedGroup.refs,
      },
    })),
  };
  return {
    name,
    inputs,
    previous,
    expected,
    reference,
    groups: expected.map((group) => group.refs),
  };
}

export function mergeFixtures(): MergeFixture[] {
  const complementary = [
    observation("shared", "first-repair"),
    observation("shared", "second-repair"),
  ];
  for (const value of complementary) {
    value["summary"] =
      "Both assessments identify the same singleton configuration and root issue. Restoring its shared default corrects both observations. first-repair and second-repair are distinct documented procedures for performing that same correction.";
    value["remediation"] =
      `Restore the shared default using the documented procedure: ${value["remediation"]}`;
  }
  const independent = Array.from({ length: 48 }, (_, index) =>
    observation(`setting-${index}`, `repair-${index}`),
  );
  const aliasA = observation("primary-alias", "primary-repair");
  const aliasB = observation("secondary-alias", "secondary-repair");
  for (const value of [aliasA, aliasB])
    value["summary"] =
      "Both reports describe the same singleton configuration, called primary-alias and secondary-alias. Both proposed repairs reset its one shared default; either repair fixes both reports. Their separate procedure names, tests and controls describe the same correction from different operational perspectives.";
  const previous: ScanAggregate = {
    scanId: parentId,
    sourceFindings: {
      "old:0": structuredClone(aliasA),
      "old:1": structuredClone(aliasB),
    },
    findings: [aliasA, aliasB].map((value, index) => ({
      ...value,
      provenance: {
        source: "local_plugin",
        sourceFindingIds: [`old:${index}`],
      },
    })),
  };
  const corroboration = observation("primary-alias", "primary-repair");
  corroboration["summary"] = aliasA["summary"];
  const lower = observation("shared-setting", "shared-repair", "low");
  lower["summary"] =
    "The completed assessment assigned low under an explicit assumption that this singleton setting is isolated.";
  const higher = observation("shared-setting", "shared-repair", "high");
  higher["summary"] =
    "A later completed assessment explicitly disproved the isolation assumption for the same singleton setting and assigned high. Retain high while that deployment condition holds.";
  const historic = observation("historic-setting", "visible-repair");
  const tail = observation("historic-setting", "tail-repair");
  tail["summary"] =
    "Archived neutral observation. ".repeat(7_000) +
    "The mandatory additional correction is tail-repair; retain tail-repair-test and tail-repair-control.";
  const history: ScanAggregate = {
    scanId: parentId,
    sourceFindings: {
      "history:0": structuredClone(tail),
      "history:1": structuredClone(historic),
    },
    findings: [
      {
        ...historic,
        remediation: historic.remediation + "\n\n" + tail.remediation,
        remediationTests: [
          ...historic.remediationTests!,
          ...tail.remediationTests!,
        ],
        preventiveControls: [
          ...historic.preventiveControls!,
          ...tail.preventiveControls!,
        ],
        provenance: {
          source: "local_plugin",
          sourceFindingIds: ["history:0", "history:1"],
        },
      },
    ],
  };
  return [
    fixture("empty", [input("empty", [])], []),
    fixture(
      "independent-similar-titles",
      [input("wide", independent)],
      independent.map((_, index) =>
        group([`wide:${index}`], [`repair-${index}`]),
      ),
    ),
    fixture(
      "duplicate-with-distinct-repairs",
      [input("a", [complementary[0]!]), input("b", [complementary[1]!])],
      [group(["a:0", "b:0"], ["first-repair", "second-repair"])],
    ),
    fixture(
      "accepted-alias-convergence",
      [input("new", [corroboration])],
      [
        group(
          ["old:0", "old:1", "new:0"],
          ["primary-repair", "secondary-repair"],
        ),
      ],
      previous,
    ),
    fixture(
      "conflicting-severity",
      [input("lower", [lower]), input("higher", [higher])],
      [group(["lower:0", "higher:0"], ["shared-repair"], "high")],
    ),
    fixture(
      "large-field-and-retained-sources",
      [input("current", [historic])],
      [
        group(
          ["history:0", "history:1", "current:0"],
          ["visible-repair", "tail-repair"],
        ),
      ],
      history,
    ),
  ];
}
