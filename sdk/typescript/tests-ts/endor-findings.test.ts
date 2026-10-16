import { expect, test } from "bun:test";
import {
  normalizeEndorFindings,
  normalizeEndorSarif,
} from "../src/endor-findings.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";

test("Endor JSON preserves the complete source, UUID, severity, aliases and repository manifests", () => {
  const input = endorFinding();
  const original = structuredClone(input);
  const output = normalizeEndorFindings(input);
  expect(input).toEqual(original);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]).toMatchObject({
    source_finding_id: input.uuid,
    evidence: {
      title: input.meta.name,
      severity: "critical",
      branch: "main",
      source_updated_at: 1767225600,
      advisory_ids: ["CVE-2099-0001", "GHSA-2222-3333-4444"],
      locations: [
        { path: "package.json", line: null },
        { path: "package-lock.json", line: null },
      ],
      source_data: original,
    },
  });
  expect(output.findings[0]!.evidence.packages).toHaveLength(2);
  expect(output.findings[0]!.evidence.packages![0]).toMatchObject({
    name: "@example/package",
    installed_version: "1.0.0",
    fixed_versions: [],
  });
});

test("arrays and ListFindingsResponse use the same identities and empty lists are empty", () => {
  const input = endorFinding();
  expect(normalizeEndorFindings([input])).toEqual(
    normalizeEndorFindings({ list: { objects: [input] } }),
  );
  expect(normalizeEndorFindings({ list: { objects: [] } })).toEqual({
    read: 0,
    findings: [],
    excluded: [],
  });
});

test("changed severity, reachability, dismissal and dependency version retain UUID", () => {
  const input = endorFinding();
  const original = normalizeEndorFindings(input).findings[0]!;
  input.spec.level = "FINDING_LEVEL_LOW";
  input.spec.dismiss = true;
  input.spec.target_dependency_version = "1.1.0";
  input.spec.reachable_paths = [];
  const changed = normalizeEndorFindings(input).findings[0]!;
  expect(changed.source_finding_id).toBe(original.source_finding_id);
  expect(changed.evidence.severity).toBe("low");
  expect(changed.evidence.source_data).not.toEqual(
    original.evidence.source_data,
  );
});

test("unknown levels stay unknown and main-context default is not mistaken for a branch", () => {
  const input = endorFinding();
  input.spec.level = "FINDING_LEVEL_UNSPECIFIED";
  input.context = { type: "CONTEXT_TYPE_MAIN", id: "default" };
  expect(normalizeEndorFindings(input).findings[0]!.evidence).toMatchObject({
    severity: "unknown",
    branch: null,
  });
});

test("duplicate UUIDs, masked records, bad timestamps and oversized evidence are excluded", () => {
  const input = endorFinding();
  const duplicate = normalizeEndorFindings([input, input]);
  expect(duplicate.findings).toEqual([]);
  expect(duplicate.excluded).toHaveLength(2);
  for (const invalid of [
    { ...input, uuid: "" },
    { uuid: input.uuid },
    { ...input, meta: { ...input.meta, update_time: "invalid" } },
    { ...input, spec: { ...input.spec, summary: "é".repeat(65536) } },
  ]) {
    const output = normalizeEndorFindings([input, invalid]);
    expect(output.excluded.length).toBeGreaterThan(0);
  }
});

test("unsafe dependency paths remain in raw evidence", () => {
  const input = endorFinding();
  input.spec.dependency_file_paths = [
    "../outside",
    "/tmp/absolute",
    "C:\\private\\manifest",
    "safe/manifest.json",
  ];
  const evidence = normalizeEndorFindings(input).findings[0]!.evidence;
  expect(evidence.locations).toEqual([
    { path: "safe/manifest.json", line: null },
  ]);
  expect(evidence.source_data).toEqual(input);
});

test("Endor SARIF UUID matches JSON and retains all source assertions without promoting them to Cloud assessments", () => {
  const input = endorSarif();
  const output = normalizeEndorFindings(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.source_finding_id).toBe(
    normalizeEndorFindings(endorFinding()).findings[0]!.source_finding_id,
  );
  expect(output.findings[0]!.evidence).toMatchObject({
    severity: "unknown",
    locations: [{ path: "package.json", line: null }],
    source_data: {
      result: input.runs[0]!.results[0],
      rule: input.runs[0]!.tool.driver.rules[0],
    },
  });
});

test("SARIF requires vendor identity, producer and consistent rule references", () => {
  for (const mutate of [
    (r: any) => delete r.results[0].properties["finding-uuid"],
    (r: any) => delete r.results[0].properties["project-uuid"],
    (r: any) => (r.results[0].ruleIndex = 1),
    (r: any) => (r.results[0].rule = { id: "other" }),
    (r: any) =>
      r.tool.driver.rules.push(structuredClone(r.tool.driver.rules[0])),
  ]) {
    const input = endorSarif();
    mutate(input.runs[0]);
    expect(normalizeEndorSarif(input).findings).toEqual([]);
  }
  const input = endorSarif();
  input.runs[0]!.tool.driver.name = "other";
  expect(() => normalizeEndorSarif(input)).toThrow("endorctl");
});

test("500 findings with distinct UUIDs survive a reordered second export", () => {
  const input = Array.from({ length: 500 }, (_, i) => ({
    ...endorFinding(),
    uuid: `finding-example-${i}`,
  }));
  const first = normalizeEndorFindings(input);
  const second = normalizeEndorFindings(input.reverse());
  expect(first.findings).toHaveLength(500);
  expect(second.excluded).toEqual([]);
  expect(second.findings.map((f) => f.source_finding_id).sort()).toEqual(
    first.findings.map((f) => f.source_finding_id).sort(),
  );
});

test.each(["2026-01-01T00:00:00.123Z", "2026-01-01T00:00:00.123456789Z"])(
  "fractional Endor timestamps retain precise source evidence (%s)",
  (timestamp) => {
    const finding = endorFinding();
    finding.meta.update_time = timestamp;
    for (const input of [
      finding,
      [finding],
      { list: { objects: [finding], response: { next_page_token: 0 } } },
    ]) {
      const result = normalizeEndorFindings(input);
      expect(result.excluded).toEqual([]);
      expect(result.findings[0]!.evidence.source_updated_at).toBe(1767225600);
      expect(result.findings[0]!.evidence.source_data).toMatchObject({
        meta: { update_time: timestamp },
      });
    }
  },
);

test.each([1, "1", "opaque-next-page", -1, true])(
  "rejects unfinished or invalid Endor page tokens (%p)",
  (next_page_token) => {
    expect(() =>
      normalizeEndorFindings({
        list: { objects: [endorFinding()], response: { next_page_token } },
      }),
    ).toThrow("another page");
  },
);

test("rejects Endor cursor pages while accepting complete exports and selected arrays", () => {
  const finding = endorFinding();
  expect(() =>
    normalizeEndorFindings({
      list: { objects: [finding], response: { next_page_id: "next-finding" } },
    }),
  ).toThrow("another page");
  for (const next_page_token of [undefined, null, 0, "0", ""]) {
    expect(
      normalizeEndorFindings({
        list: {
          objects: [finding],
          response: { next_page_token, next_page_id: "" },
        },
      }).findings,
    ).toHaveLength(1);
  }
  expect(normalizeEndorFindings([finding]).findings).toHaveLength(1);
});
