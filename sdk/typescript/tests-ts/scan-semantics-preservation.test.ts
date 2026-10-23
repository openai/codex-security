import { expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import findingsSchema from "../../../plugins/codex-security/schemas/findings.schema.json";
import { semanticFinding } from "./helpers/semantic-scan.js";
import {
  prepareScanFindings,
  preserveFindingDetails,
  type JsonObject,
} from "../src/scan-semantics.js";

const validateIdentity = new Ajv2020().compile(
  findingsSchema.properties.findings.items.properties.identity,
);

test.each([
  [".env exposure", "env-exposure"],
  ["_internal request", "internal-request"],
  ["/route mismatch", "route-mismatch"],
  ["-._/", "finding-1"],
  ["control.", "control."],
  ["control_", "control_"],
  ["control/", "control/"],
])(
  "generated finding identities satisfy the canonical schema for %s",
  (source, anchor) => {
    for (const fromCandidate of [false, true]) {
      const finding = semanticFinding({
        title: fromCandidate ? "Original finding title" : source,
        extensions: {
          ...(fromCandidate ? { candidateId: source } : {}),
          ledgerRowId: ".ledger_entry/",
        },
      });
      const before = structuredClone(finding);
      const [prepared] = prepareScanFindings([finding]);
      expect(validateIdentity(prepared!.identity)).toBe(true);
      expect(prepared!.identity).toEqual({
        anchor,
        instance: "ledger_entry/",
      });
      expect(prepared!.title).toBe(before.title);
      expect(prepared!.extensions).toEqual(before.extensions);
      expect(finding).toEqual(before);
    }
  },
);

test("explicit finding identities and original diagnostic text remain unchanged", () => {
  const identity = {
    anchor: "authored/anchor.",
    instance: "authored_instance/",
  };
  const finding = semanticFinding({
    title: ".env exposure",
    identity,
    extensions: {
      candidateId: "_original-candidate",
      ledgerRowId: ".original",
    },
  });
  const before = structuredClone(finding);
  const [prepared] = prepareScanFindings([finding]);
  expect(prepared).toEqual({ ...before, identity });
  expect(validateIdentity(prepared!.identity)).toBe(true);
  expect(finding).toEqual(before);
});

const evidence = {
  severity: "high",
  locations: [{ path: "sample.ts", startLine: 3 }],
  opaque: ["a\u0000b", "z".repeat(8192)],
};
const source = { id: "saved:0", finding: evidence };
const other = { id: "saved:1", finding: evidence };
const changed = { id: source.id, finding: { ...evidence, severity: "low" } };

const cases: [unknown[], unknown[], unknown[]][] = [
  [[source, other], [{ ...source }], [source, other]],
  [[source], [other, source], [source, other]],
  [
    [source, source],
    [other, other],
    [source, other],
  ],
  [
    [changed, source],
    [structuredClone(source), structuredClone(changed)],
    [changed, source],
  ],
  [
    [source],
    [{ finding: evidence, id: source.id }],
    [source, { finding: evidence, id: source.id }],
  ],
  [
    [source],
    [{ ...source, annotation: "retain" }],
    [source, { ...source, annotation: "retain" }],
  ],
  [
    [source],
    [null, { finding: evidence }],
    [source, null, { finding: evidence }],
  ],
];
test.each(
  cases.map(([current, previous, expected], index) => ({
    current,
    previous,
    expected,
    index,
  })),
)(
  "original union matches exact JSON equality and first-occurrence order (case $index)",
  ({ current, previous, expected }) => {
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
      expected,
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
