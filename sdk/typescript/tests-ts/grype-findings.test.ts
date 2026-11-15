import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  grypeReportFormat,
  normalizeGrypeFindings,
  readGrypeFindings,
} from "../src/grype-findings.js";

const exampleReport = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "examples",
  "normalized-import",
  "grype-report.json",
);

function match() {
  return {
    vulnerability: {
      id: "CVE-2099-0001",
      dataSource: "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
      namespace: "nvd:cpe",
      severity: "High",
      urls: ["https://nvd.nist.gov/vuln/detail/CVE-2099-0001"],
      description: "A crafted length can cause excessive allocation.",
      fix: { versions: ["1.0.1"], state: "fixed" },
    },
    relatedVulnerabilities: [
      {
        id: "GHSA-2345-6789-cfgh",
        dataSource: "https://github.com/advisories/GHSA-2345-6789-cfgh",
        severity: "High",
      },
    ],
    matchDetails: [
      { type: "exact-direct-match", matcher: "javascript-matcher" },
    ],
    artifact: {
      id: "a1b2c3d4e5f60001",
      name: "@example/parser",
      version: "1.0.0",
      type: "npm",
      language: "javascript",
      locations: [{ path: "package-lock.json" }],
      purl: "pkg:npm/%40example/parser@1.0.0",
    },
  };
}

function report(...matches: unknown[]) {
  return {
    matches,
    source: { type: "directory", target: "." },
    descriptor: { name: "grype", version: "0.80.1" },
  };
}

test("normalizes a grype match into an SCA dependency finding", () => {
  const output = normalizeGrypeFindings(report(match()));
  expect(output).toMatchObject({ read: 1, excluded: [] });
  const finding = output.findings[0]!;
  expect(finding.evidence).toMatchObject({
    title: "CVE-2099-0001 in @example/parser",
    severity: "high",
    description: "A crafted length can cause excessive allocation.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2099-0001",
    advisory_ids: ["CVE-2099-0001", "GHSA-2345-6789-cfgh"],
    packages: [
      {
        name: "@example/parser",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
        manifest_path: "package-lock.json",
      },
    ],
    locations: [{ path: "package-lock.json", line: null }],
    source_data: { format: grypeReportFormat, grype_version: "0.80.1" },
  });
  expect(finding.evidence.source_data?.["match"]).toMatchObject({
    artifact: { name: "@example/parser" },
  });
  expect(finding.evidence.details).toBeUndefined();
});

test("maps negligible severity to informational and unknown severity to unknown", () => {
  const negligible = match();
  negligible.vulnerability.severity = "Negligible";
  const unknown = match();
  unknown.vulnerability.severity = "Unknown";
  expect(
    normalizeGrypeFindings(report(negligible)).findings[0]!.evidence.severity,
  ).toBe("informational");
  expect(
    normalizeGrypeFindings(report(unknown)).findings[0]!.evidence.severity,
  ).toBe("unknown");
});

test("identity is stable and ignores severity, version and fix changes", () => {
  const first = normalizeGrypeFindings(report(match())).findings[0]!;
  const changed = match();
  changed.vulnerability.severity = "Critical";
  changed.artifact.version = "1.0.2";
  changed.vulnerability.fix = { versions: ["1.0.3"], state: "fixed" };
  const next = normalizeGrypeFindings(report(changed)).findings[0]!;
  expect(next.source_finding_id).toBe(first.source_finding_id);
  expect(next.evidence.severity).toBe("critical");
});

test("a different advisory, package or manifest is a separate occurrence", () => {
  const base = match();
  const otherAdvisory = match();
  otherAdvisory.vulnerability.id = "CVE-2099-9999";
  const otherPackage = match();
  otherPackage.artifact.name = "@example/other";
  otherPackage.artifact.purl = "pkg:npm/%40example/other@1.0.0";
  const otherManifest = match();
  otherManifest.artifact.locations = [{ path: "nested/package-lock.json" }];
  const ids = new Set(
    normalizeGrypeFindings(
      report(base, otherAdvisory, otherPackage, otherManifest),
    ).findings.map((finding) => finding.source_finding_id),
  );
  expect(ids.size).toBe(4);
});

test("excludes ambiguous duplicate matches sharing an identity", () => {
  const output = normalizeGrypeFindings(report(match(), match()));
  expect(output.read).toBe(2);
  expect(output.findings).toEqual([]);
  expect(output.excluded.map(({ position }) => position)).toEqual([1, 2]);
  expect(output.excluded[0]!.reason).toMatch(/ambiguous duplicate/i);
});

test("keeps absolute image paths out of repository locations", () => {
  const image = match();
  image.artifact.locations = [
    { path: "/usr/lib/node_modules/parser/index.js" },
  ];
  const finding = normalizeGrypeFindings(report(image)).findings[0]!;
  expect(finding.evidence.locations).toEqual([]);
  expect(finding.evidence.packages![0]!.manifest_path).toBeNull();
  expect(finding.source_finding_id).toBeTruthy();
});

test("falls back to a plain advisory id and drops a non-HTTP data source", () => {
  const sparse = match();
  sparse.vulnerability = {
    id: "GHSA-aaaa-bbbb-cccc",
    severity: "Medium",
    dataSource: "nvd:cpe",
  } as (typeof sparse)["vulnerability"];
  sparse.relatedVulnerabilities = [];
  const finding = normalizeGrypeFindings(report(sparse)).findings[0]!;
  expect(finding.evidence).toMatchObject({
    severity: "medium",
    advisory_ids: ["GHSA-aaaa-bbbb-cccc"],
    url: null,
  });
  expect(finding.evidence.packages![0]!.fixed_versions).toEqual([]);
});

test("rejects a report that is not native grype JSON", () => {
  expect(() => normalizeGrypeFindings({ runs: [] })).toThrow(/matches/);
  expect(() => normalizeGrypeFindings({ SchemaVersion: 2 })).toThrow(/matches/);
});

test("reads native grype JSON and gzip from disk", async () => {
  const directory = await mkdtemp(join(tmpdir(), "grype-import-"));
  try {
    const parsed = JSON.parse(await readFile(exampleReport, "utf8"));
    const fromExample = normalizeGrypeFindings(parsed);
    expect(fromExample.read).toBe(2);
    expect(fromExample.excluded).toEqual([]);
    expect(
      fromExample.findings.map((finding) => finding.evidence.severity),
    ).toEqual(["high", "critical"]);
    const path = join(directory, "grype.json");
    await writeFile(path, JSON.stringify(parsed));
    expect(await readGrypeFindings(path)).toEqual(fromExample);
    await writeFile(path, gzipSync(JSON.stringify(parsed)));
    expect(await readGrypeFindings(path)).toEqual(fromExample);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
