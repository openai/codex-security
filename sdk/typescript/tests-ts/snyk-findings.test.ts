import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { normalizeSnykSarif, readSnykFindings } from "../src/snyk-findings.js";
import { snykSarif } from "./support/snyk-import-fixtures.js";

test("Snyk retains the full selected result, rule, producer and unknown context", () => {
  const input = snykSarif();
  const before = structuredClone(input);
  const output = normalizeSnykSarif(input);
  expect(input).toEqual(before);
  expect(output.read).toBe(1);
  expect(output.excluded).toEqual([]);
  const evidence = output.findings[0]!.evidence;
  expect(evidence).toMatchObject({
    severity: "critical",
    advisory_ids: ["SNYK-EXAMPLE-1", "CVE-2099-0001"],
    packages: [
      {
        name: "@example/package",
        installed_version: "1.0.0",
        ecosystem: "npm",
        fixed_versions: [],
        manifest_path: "package.json",
      },
    ],
    locations: [{ path: "package.json", line: null }],
    source_updated_at: null,
  });
  expect(evidence.source_data).toMatchObject({
    rule: before.runs[0]!.tool.driver.rules[0],
    result: before.runs[0]!.results[0],
    driver: { name: "Snyk Open Source", semanticVersion: "1.0.0" },
    run: { automationDetails: before.runs[0]!.automationDetails },
  });
  expect(evidence.description).toContain("Detailed paths");
});

test("severity and export time changes retain identity; manifests remain distinct", () => {
  const input = snykSarif();
  const original = normalizeSnykSarif(input).findings[0]!;
  input.runs[0]!.automationDetails.id = "Snyk/Open Source/project/4/new-export";
  input.runs[0]!.tool.driver.rules[0]!.shortDescription.text =
    "Low severity - synthetic vulnerability";
  const changed = normalizeSnykSarif(input).findings[0]!;
  expect(changed.source_finding_id).toBe(original.source_finding_id);
  expect(changed.evidence.severity).toBe("low");
  expect(changed.evidence.source_data).not.toEqual(
    original.evidence.source_data,
  );
  input.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri =
    "other/package.json";
  expect(normalizeSnykSarif(input).findings[0]!.source_finding_id).not.toBe(
    original.source_finding_id,
  );
});

test("unknown severity remains unknown, without inferring it from SARIF level or CVSS", () => {
  const input = snykSarif();
  input.runs[0]!.tool.driver.rules[0]!.shortDescription.text =
    "Synthetic vulnerability";
  expect(normalizeSnykSarif(input).findings[0]!.evidence.severity).toBe(
    "unknown",
  );
});

test.each(["Snyk Code", "Snyk Container", "Snyk IaC", "Other"])(
  "rejects unsupported producer %s",
  (producer) => {
    const input = snykSarif();
    input.runs[0]!.tool.driver.name = producer;
    expect(() => normalizeSnykSarif(input)).toThrow("Only Snyk Open Source");
  },
);

test("licenses, malformed rules, conflicting references and external property files are not imported", () => {
  const variants: Record<string, unknown>[] = [];
  for (const mutate of [
    (r: any) =>
      (r.tool.driver.rules[0].help.markdown =
        "* Package Manager: npm\n* Module: example"),
    (r: any) => (r.results[0].ruleIndex = 1),
    (r: any) => (r.results[0].rule = { id: "different" }),
    (r: any) => (r.results[0].rule = { index: true }),
    (r: any) => (r.results[0].rule = { toolComponent: { index: 0 } }),
    (r: any) =>
      r.tool.driver.rules.push(structuredClone(r.tool.driver.rules[0])),
  ]) {
    const input = snykSarif();
    mutate(input.runs[0]);
    variants.push(input);
  }
  for (const input of variants) {
    const result = normalizeSnykSarif(input);
    expect(result.findings).toHaveLength(0);
    expect(result.excluded).toHaveLength(1);
  }
  expect(() =>
    normalizeSnykSarif({ ...snykSarif(), version: "2.0.0" }),
  ).toThrow("2.1.0");
  const input = snykSarif() as any;
  input.runs[0].externalPropertyFileReferences = {
    results: [{ location: { uri: "https://example.invalid/data" } }],
  };
  expect(() => normalizeSnykSarif(input)).toThrow("self-contained");
});

test("every ambiguous duplicate is excluded instead of keeping an arbitrary project", () => {
  const input = snykSarif();
  input.runs.push(structuredClone(input.runs[0]!));
  const output = normalizeSnykSarif(input);
  expect(output.findings).toEqual([]);
  expect(output.excluded.map((e) => e.position)).toEqual([1, 2]);
});

test.each([
  "/tmp/package.json",
  "C:\\work\\package.json",
  "../package.json",
  "https://example.invalid/package.json",
])(
  "retains %s as evidence without treating it as a repository path",
  (path) => {
    const input = snykSarif();
    input.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri =
      path;
    const evidence = normalizeSnykSarif(input).findings[0]!.evidence;
    expect(evidence.locations).toEqual([]);
    expect(evidence.packages![0]!.manifest_path).toBeNull();
    expect(JSON.stringify(evidence.source_data)).toContain(
      JSON.stringify(path),
    );
  },
);

test("500 independent advisory groups survive normalization with stable identities after reordering", () => {
  const input = snykSarif();
  const run = input.runs[0]!;
  run.tool.driver.rules = Array.from({ length: 500 }, (_, i) => ({
    ...structuredClone(run.tool.driver.rules[0]!),
    id: `SNYK-EXAMPLE-${i}`,
  }));
  run.results = run.tool.driver.rules.map((rule) => ({
    ...structuredClone(run.results[0]!),
    ruleId: rule.id,
  }));
  const before = normalizeSnykSarif(input);
  run.tool.driver.rules.reverse();
  run.results.reverse();
  const after = normalizeSnykSarif(input);
  expect(before.findings).toHaveLength(500);
  expect(after.excluded).toEqual([]);
  expect(after.findings.map((f) => f.source_finding_id).sort()).toEqual(
    before.findings.map((f) => f.source_finding_id).sort(),
  );
});

test("BOM and gzip files use the same parser and malformed files fail", async () => {
  const dir = await mkdtemp(join(tmpdir(), "snyk-import-"));
  try {
    const path = join(dir, "report.sarif");
    await writeFile(path, gzipSync("\uFEFF" + JSON.stringify(snykSarif())));
    expect(await readSnykFindings(path)).toEqual(
      normalizeSnykSarif(snykSarif()),
    );
    await writeFile(path, "{");
    await expect(readSnykFindings(path)).rejects.toThrow("could not be parsed");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test.each([0xfe, 0xff])(
  "malformed UTF-8 byte %p cannot alter a finding identity",
  async (byte) => {
    const dir = await mkdtemp(join(tmpdir(), "snyk-invalid-utf8-"));
    try {
      const path = join(dir, "report.sarif");
      const report = JSON.stringify(snykSarif());
      const marker = report.indexOf("package.json");
      const bytes = Buffer.concat([
        Buffer.from(report.slice(0, marker)),
        Buffer.from([byte]),
        Buffer.from(report.slice(marker)),
      ]);
      for (const encoded of [bytes, gzipSync(bytes)]) {
        await writeFile(path, encoded);
        await expect(readSnykFindings(path)).rejects.toThrow("UTF-8");
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
);
test("an invalid duplicate cannot make its sibling eligible for publication", () => {
  for (const mutate of [
    (run: any) => (run.tool.driver.rules[0].help.markdown += "x".repeat(65536)),
    (run: any) => delete run.tool.driver.rules[0].shortDescription,
    (run: any) => (run.results[0].ruleIndex = 99),
  ]) {
    const input = snykSarif();
    input.runs.push(structuredClone(input.runs[0]!));
    mutate(input.runs[1]);
    const output = normalizeSnykSarif(input);
    expect(output.findings).toEqual([]);
    expect(output.excluded).toHaveLength(2);
    expect(
      output.excluded.every((item) => item.reason.includes("duplicate")),
    ).toBe(true);
  }
});
