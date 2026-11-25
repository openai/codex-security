import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import example from "../../../examples/normalized-import/grype-report.json";
import {
  grypeReportFormat,
  normalizeGrypeFindings,
  readGrypeFindings,
} from "../src/grype-findings.js";

function match() {
  return structuredClone(example.matches[0]!);
}

function report(...matches: unknown[]) {
  return { ...example, matches };
}

function findingFor(value: unknown) {
  return normalizeGrypeFindings(report(value)).findings[0]!;
}

test("normalizes a grype match into an SCA dependency finding", () => {
  const output = normalizeGrypeFindings(report(match()));
  expect(output).toMatchObject({ read: 1, excluded: [] });
  const finding = output.findings[0]!;
  expect(finding.evidence).toMatchObject({
    title: "CVE-2099-0001 in @example/parser",
    severity: "high",
    description: example.matches[0]!.vulnerability.description,
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
  expect(finding.evidence.source_data?.["match"]).toEqual(example.matches[0]);
  expect(finding.evidence.details).toBeUndefined();
});

test("maps negligible severity to informational and unknown severity to unknown", () => {
  const native = match();
  native.vulnerability.severity = "Negligible";
  expect(findingFor(native).evidence.severity).toBe("informational");
  native.vulnerability.severity = "Unknown";
  expect(findingFor(native).evidence.severity).toBe("unknown");
});

test("identity is stable and ignores severity, version and fix changes", () => {
  const first = findingFor(match());
  const changed = match();
  changed.vulnerability.severity = "Critical";
  changed.artifact.version = "1.0.2";
  changed.vulnerability.fix = { versions: ["1.0.3"], state: "fixed" };
  const next = findingFor(changed);
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
  const { findings } = normalizeGrypeFindings(
    report(base, otherAdvisory, otherPackage, otherManifest),
  );
  expect(
    new Set(findings.map((finding) => finding.source_finding_id)).size,
  ).toBe(4);
});

test("location order preserves identity and different location sets stay distinct", () => {
  const a = match();
  a.artifact.locations.push({ path: "a/lock.json" });
  const b = match();
  b.artifact.locations.push({ path: "b/lock.json" });
  const before = normalizeGrypeFindings(report(a, b));
  expect(before.excluded).toEqual([]);
  a.artifact.locations.reverse();
  const after = normalizeGrypeFindings(report(a, b));
  expect(after.findings.map((finding) => finding.source_finding_id)).toEqual(
    before.findings.map((finding) => finding.source_finding_id),
  );
});

test("excludes a malformed match and retains valid siblings", () => {
  const output = normalizeGrypeFindings(report(null, match()));
  expect(output.read).toBe(2);
  expect(output.findings).toHaveLength(1);
  expect(output.excluded).toEqual([
    {
      position: 1,
      source_finding_id: null,
      reason: "Grype match must be an object.",
    },
  ]);
});

test("excludes ambiguous duplicate matches sharing an identity", () => {
  const output = normalizeGrypeFindings(report(match(), match()));
  expect(output.read).toBe(2);
  expect(output.findings).toEqual([]);
  expect(output.excluded.map(({ position }) => position)).toEqual([1, 2]);
  expect(output.excluded[0]!.reason).toMatch(/ambiguous duplicate/i);
});

test("directory access paths resolve from the scan root and retain occurrence identity", () => {
  const native = match();
  const path = "nested/package-lock.json";
  const row = (location: { path: string; accessPath?: string }) =>
    findingFor({
      ...native,
      artifact: { ...native.artifact, locations: [location] },
    });
  const id = row({ path }).source_finding_id;
  for (const location of [
    { path: `/${path}`, accessPath: `/${path}` },
    { path: `/checkout/${path}`, accessPath: `./${path}` },
  ]) {
    const finding = row(location);
    expect(finding.source_finding_id).toBe(id);
    expect(finding.evidence.locations).toEqual([{ path, line: null }]);
    expect(finding.evidence.packages![0]!.manifest_path).toBe(path);
  }
  for (const accessPath of [undefined, "//host/file", "/../outside"]) {
    expect(
      row({ path: "/absolute/file", accessPath }).evidence.locations,
    ).toEqual([]);
  }
});

test("keeps relative and absolute image paths out of repository locations", () => {
  const image = match();
  const path = "/app/package-lock.json";
  const rooted = { path, accessPath: path };
  image.artifact.locations = [rooted, { path: "app/package-lock.json" }];
  const source = {
    type: "image",
    target: {
      imageID: "example",
      config: "config",
      manifest: "manifest",
      layers: [],
    },
  };
  const result = normalizeGrypeFindings({ ...report(image), source });
  const finding = result.findings[0]!;
  expect(result.report?.["source"]).toEqual(source);
  expect(finding.evidence.source_data?.["source"]).toEqual({
    type: "image",
    target: { imageID: "example" },
  });
  expect(finding.evidence.locations).toEqual([]);
  expect(finding.evidence.packages![0]!.manifest_path).toBeNull();
  expect(finding.source_finding_id).toBeTruthy();
});

test("keeps an installed file as a location and selects only an unambiguous manifest", () => {
  const input = match();
  input.artifact.locations = [{ path: "bin/tool" }];
  const evidence = () => findingFor(input).evidence;
  expect(evidence().locations).toEqual([{ path: "bin/tool", line: null }]);
  expect(evidence().packages![0]!.manifest_path).toBeNull();
  input.artifact.locations.push({ path: "package-lock.json" });
  expect(evidence().packages![0]!.manifest_path).toBe("package-lock.json");
  input.artifact.locations.push({ path: "other/package-lock.json" });
  expect(evidence().packages![0]!.manifest_path).toBeNull();
});

test("falls back to a plain advisory id and drops a non-HTTP data source", () => {
  const sparse = {
    artifact: match().artifact,
    vulnerability: {
      id: "GHSA-aaaa-bbbb-cccc",
      severity: "Medium",
      dataSource: "nvd:cpe",
      urls: ["nvd:cpe", "https://example.org/advisory"],
    },
  };
  const finding = findingFor(sparse);
  expect(finding.evidence).toMatchObject({
    severity: "medium",
    advisory_ids: ["GHSA-aaaa-bbbb-cccc"],
    url: "https://example.org/advisory",
  });
  sparse.vulnerability.urls.pop();
  expect(findingFor(sparse).evidence.url).toBeNull();
  expect(finding.evidence.packages![0]!.fixed_versions).toEqual([]);
});

test("rejects a report that is not native grype JSON", () => {
  expect(() => normalizeGrypeFindings({ runs: [] })).toThrow(/matches/);
  expect(() => normalizeGrypeFindings({ SchemaVersion: 2 })).toThrow(/matches/);
});

test("reads native grype JSON and gzip from disk", async () => {
  await using directory = await scopedTemporaryDirectory("grype-import-");
  const fromExample = normalizeGrypeFindings(example);
  expect(fromExample.read).toBe(2);
  expect(fromExample.excluded).toEqual([]);
  expect(
    fromExample.findings.map((finding) => finding.evidence.severity),
  ).toEqual(["high", "critical"]);
  const path = join(directory.path, "grype.json");
  const json = JSON.stringify(example);
  for (const contents of [json, gzipSync(json)]) {
    await writeFile(path, contents);
    expect(await readGrypeFindings(path)).toEqual(fromExample);
  }
});
