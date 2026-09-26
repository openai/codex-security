import { expect, test } from "bun:test";
import {
  exactUnion,
  preserveFindingDetails,
  type JsonObject,
} from "../src/scan-semantics.js";

const evidence = {
  severity: "high",
  locations: [{ path: "sample.ts", startLine: 3 }],
  opaque: ["a\u0000b", "z".repeat(8192)],
};
const source = { id: "saved:0", finding: evidence };
const other = { id: "saved:1", finding: evidence };
const changed = { id: source.id, finding: { ...evidence, severity: "low" } };

const cases: [unknown[], unknown[]][] = [
  [[source, other], [{ ...source }]],
  [[source], [other, source]],
  [
    [source, source],
    [other, other],
  ],
  [
    [changed, source],
    [structuredClone(source), structuredClone(changed)],
  ],
  [[source], [{ finding: evidence, id: source.id }]],
  [[source], [{ ...source, annotation: "retain" }]],
  [[source], [null, { finding: evidence }]],
];
test.each(
  cases.map(([current, previous], index) => ({ current, previous, index })),
)(
  "original union matches exact JSON equality and first-occurrence order (case $index)",
  ({ current, previous }) => {
    const saved: JsonObject = {
      summary: "saved",
      provenance: { sourceFindings: previous },
    };
    const next: JsonObject = {
      summary: "saved",
      provenance: { sourceFindings: current },
    };
    const before = structuredClone({ current, previous });
    preserveFindingDetails(next, saved);
    expect((next["provenance"] as JsonObject)["sourceFindings"]).toEqual(
      exactUnion(current, previous),
    );
    expect({ current, previous }).toEqual(before);
    expect(
      (next["provenance"] as JsonObject)["previousFindings"],
    ).toBeUndefined();
  },
);

test("source comparisons do not cache evidence across calls", () => {
  const original = structuredClone(source);
  const edited = structuredClone(source);
  const merge = () => {
    const next: JsonObject = { provenance: { sourceFindings: [edited] } };
    preserveFindingDetails(next, {
      provenance: { sourceFindings: [original] },
    });
    return (next["provenance"] as JsonObject)["sourceFindings"];
  };
  expect(merge()).toEqual([edited]);
  edited.finding.severity = "critical";
  expect(merge()).toEqual([edited, original]);
});
