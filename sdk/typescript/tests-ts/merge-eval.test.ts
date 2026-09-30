import { expect, test } from "bun:test";
import { validateScanMerge } from "../src/scan-merge.js";
import { mergeFixtures } from "../scripts/merge-eval/fixtures.js";
import { gradeMerge } from "../scripts/merge-eval/grade.js";

test.each(mergeFixtures())("merge quality oracle: $name", (fixture) => {
  expect(gradeMerge(fixture.reference, fixture.expected)).toEqual([]);
  expect(() =>
    validateScanMerge(fixture.reference, fixture.inputs, fixture.previous),
  ).not.toThrow();
  if (!fixture.reference.groups.length) return;
  const omitted = structuredClone(fixture.reference);
  omitted.groups.pop();
  expect(gradeMerge(omitted, fixture.expected).length).toBeGreaterThan(0);
  const duplicate = structuredClone(fixture.reference);
  duplicate.groups.push(duplicate.groups[0]!);
  expect(gradeMerge(duplicate, fixture.expected).length).toBeGreaterThan(0);
  const unknown = structuredClone(fixture.reference);
  unknown.groups[0]!.canonicalSourceFindingId = "unknown:0";
  expect(gradeMerge(unknown, fixture.expected).length).toBeGreaterThan(0);
});

test("accounting for every source does not excuse collapsing independent findings", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "independent-similar-titles",
  )!;
  const collapsed = structuredClone(fixture.reference);
  collapsed.groups.splice(1);
  collapsed.groups[0]!.sourceFindingIds = fixture.expected.flatMap(
    (group) => group.refs,
  );
  expect(() =>
    validateScanMerge(collapsed, fixture.inputs, fixture.previous),
  ).not.toThrow();
  expect(gradeMerge(collapsed, fixture.expected).length).toBeGreaterThan(0);
});

test("canonical selection must reflect the supported severity assessment", () => {
  const fixture = mergeFixtures().find(
    (value) => value.name === "conflicting-severity",
  )!;
  const wrong = structuredClone(fixture.reference);
  wrong.groups[0]!.canonicalSourceFindingId = "lower:0";
  expect(() =>
    validateScanMerge(wrong, fixture.inputs, fixture.previous),
  ).not.toThrow();
  expect(gradeMerge(wrong, fixture.expected)).toEqual([
    'Wrong canonical source: ["higher:0","lower:0"].',
  ]);
});
