import { expect, test } from "bun:test";
import { reconcileScanMerge } from "../src/scan-merge.js";
import { mergeFixtures, parentId } from "../scripts/merge-eval/fixtures.js";
import { gradeMerge } from "../scripts/merge-eval/grade.js";

test.each(mergeFixtures())("merge quality oracle: $name", (fixture) => {
  expect(gradeMerge(fixture.reference, fixture.expected)).toEqual([]);
  const actual = reconcileScanMerge(
    parentId,
    fixture.groups,
    fixture.inputs,
    fixture.previous,
  ).aggregate;
  expect(gradeMerge(actual, fixture.expected)).toEqual([]);
  if (!fixture.reference.findings.length) return;
  for (const field of [
    "remediation",
    "remediationTests",
    "preventiveControls",
    "severity",
  ]) {
    const bad = structuredClone(fixture.reference);
    bad.findings[0]![field] = field === "severity" ? { level: "critical" } : [];
    // Full originals in provenance must not satisfy a canonical repair requirement.
    (bad.findings[0]!["provenance"] as Record<string, unknown>)[
      "sourceFindings"
    ] = fixture.reference.findings;
    expect(gradeMerge(bad, fixture.expected).length).toBeGreaterThan(0);
  }
  const omitted = structuredClone(fixture.reference);
  omitted.findings.pop();
  expect(gradeMerge(omitted, fixture.expected).length).toBeGreaterThan(0);
  const duplicate = structuredClone(fixture.reference);
  duplicate.findings.push(duplicate.findings[0]!);
  expect(gradeMerge(duplicate, fixture.expected).length).toBeGreaterThan(0);
});

test("accounting for every source does not excuse collapsing independent findings", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "independent-similar-titles",
  )!;
  const collapsed = structuredClone(fixture.reference);
  collapsed.findings.splice(1);
  (collapsed.findings[0]!["provenance"] as Record<string, unknown>)[
    "sourceFindingIds"
  ] = fixture.expected.flatMap((group) => group.refs);
  const accepted = reconcileScanMerge(
    parentId,
    [fixture.expected.flatMap((group) => group.refs)],
    fixture.inputs,
    fixture.previous,
  ).aggregate;
  expect(gradeMerge(accepted, fixture.expected).length).toBeGreaterThan(0);
  expect(gradeMerge(collapsed, fixture.expected).length).toBeGreaterThan(0);
});

test("merge quality requires complete repair, test and control identifiers", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "independent-similar-titles",
  )!;
  for (const [field, wrong] of [
    ["remediation", "Correct configuration repair-10."],
    ["remediationTests", ["Verify repair-1-test-other."]],
    ["preventiveControls", ["Maintain other-repair-1-control."]],
  ] as const) {
    const bad = structuredClone(fixture.reference);
    Object.assign(bad.findings[1]!, { [field]: wrong });
    expect(gradeMerge(bad, fixture.expected)).toEqual([
      `Missing canonical ${field} fact ${fixture.expected[1]!.facts[field]![0]}: ["wide:1"].`,
    ]);
  }
});
