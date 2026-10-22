import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  normalizeSnykFindingsExport,
  normalizeSnykJson,
  normalizeSnykSarif,
  readSnykFindings,
  snykRepositoryUrls,
} from "../src/snyk-findings.js";
import {
  snykJson,
  snykPluginExport,
  snykSarif,
} from "./support/snyk-import-fixtures.js";

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
        manifest_path: null,
      },
    ],
    locations: [],
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
  input.runs[0]!.automationDetails.id = "Snyk/Open Source/example/4/new-export";
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

test("SARIF projects with the same advisory and manifest keep distinct, stable identities", () => {
  const input = snykSarif();
  input.runs = ["workspace/api", "@example/web"].map((project, index) => ({
    ...structuredClone(input.runs[0]!),
    automationDetails: {
      id: `Snyk/Open Source/${project}/${index}/2026-01-01T00:00:00.000Z`,
    },
  }));
  const original = structuredClone(input);
  const before = normalizeSnykSarif(input);
  expect(before.findings).toHaveLength(2);
  expect(before.excluded).toEqual([]);
  expect(new Set(before.findings.map((f) => f.source_finding_id)).size).toBe(2);
  expect(input).toEqual(original);

  input.runs.reverse();
  input.runs.forEach((run, index) => {
    run.automationDetails.id = run.automationDetails.id.replace(
      /\/\d+\/[^/]+$/u,
      `/${index}/2026-02-01T00:00:00.000Z`,
    );
  });
  const after = normalizeSnykSarif(input);
  expect(after.excluded).toEqual([]);
  expect(after.findings.map((f) => f.source_finding_id).sort()).toEqual(
    before.findings.map((f) => f.source_finding_id).sort(),
  );
});

test.each(["example/", ""])(
  "run indexes and export times do not distinguish duplicate project %j findings",
  (project) => {
    const input = snykSarif();
    input.runs = ["2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"].map(
      (timestamp, index) => ({
        ...structuredClone(input.runs[0]!),
        automationDetails: {
          id: `Snyk/Open Source/${project}${index}/${timestamp}`,
        },
      }),
    );
    const output = normalizeSnykSarif(input);
    expect(output.findings).toEqual([]);
    expect(output.excluded.map((e) => e.position)).toEqual([1, 2]);
    expect(output.excluded.every((e) => e.reason.includes("duplicate"))).toBe(
      true,
    );
  },
);

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
    (r: any) => (r.results[0].rule = { guid: "different" }),
    (r: any) => (r.results[0].ruleId = "SNYK-MISSING"),
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

test("rule references use original indexes and ignore unrelated duplicate or missing IDs", () => {
  const input = snykSarif();
  const run = input.runs[0]!;
  const rule = { ...run.tool.driver.rules[0]!, guid: "synthetic-guid" };
  const report = {
    ...input,
    runs: [
      {
        ...run,
        tool: {
          ...run.tool,
          driver: {
            ...run.tool.driver,
            rules: [{ id: "unrelated" }, rule, { id: "unrelated" }, {}],
          },
        },
        results: [
          {
            ...run.results[0]!,
            ruleIndex: 1,
            rule: { id: rule.id, index: 1, guid: rule.guid },
          },
        ],
      },
    ],
  };
  const original = structuredClone(report);
  const output = normalizeSnykSarif(report);
  expect(output.findings).toHaveLength(1);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({ rule });
  expect(report).toEqual(original);
});

test("every ambiguous duplicate is excluded instead of keeping an arbitrary project", () => {
  const input = snykSarif();
  input.runs.push(structuredClone(input.runs[0]!));
  const output = normalizeSnykSarif(input);
  expect(output.findings).toEqual([]);
  expect(output.excluded.map((e) => e.position)).toEqual([1, 2]);
});

test.each([
  { index: 0 },
  { uri: "package.json", index: 0 },
  { uri: "package.json", uriBaseId: "ROOT" },
])(
  "unresolved SARIF artifact references cannot identify a Snyk manifest: %p",
  (artifact) => {
    for (const manifest of ["one/package.json", "two/package.json"]) {
      const input: any = snykSarif();
      input.runs[0].artifacts = [{ location: { uri: manifest } }];
      input.runs[0].originalUriBaseIds = { ROOT: { uri: "file:///outside/" } };
      input.runs[0].results[0].locations[0].physicalLocation.artifactLocation =
        artifact;
      const original = structuredClone(input);
      const output = normalizeSnykSarif(input);
      expect(output.findings).toEqual([]);
      expect(output.excluded).toHaveLength(1);
      expect(output.excluded[0]!.reason).toContain("artifact references");
      expect(input).toEqual(original);
    }
  },
);

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

test.each([
  "packages/my%20app/package.json",
  "packages/name:variant/package.json",
  "packages/100%/package.json",
  "packages/%2e%2e/package.json",
  "packages/%ZZ/package.json",
  "packages/café/package.json",
  "packages/my app/package.json",
])("preserves the Snyk formatter's literal manifest path %s", (path) => {
  // getArtifactLocationUri in Snyk CLI returns displayTargetFile verbatim.
  // A percent sign belongs to the filename; it is not an encoded URI here.
  const input = snykSarif();
  input.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri =
    path;
  const original = structuredClone(input);
  const finding = normalizeSnykSarif(input).findings[0]!;
  expect(finding.evidence.locations).toEqual([]);
  expect(finding.evidence.packages![0]!.manifest_path).toBeNull();
  expect(finding.evidence.source_data).toMatchObject({
    result: original.runs[0]!.results[0],
  });
  expect(input).toEqual(original);
});

test("SARIF from a nested scan target retains manifest evidence without claiming a repository-root path", () => {
  const input = snykSarif();
  const run = input.runs[0]!;
  const nested = {
    ...input,
    runs: [{ ...run, properties: { path: "/work/example/services/api" } }],
  };
  const original = structuredClone(nested);
  const finding = normalizeSnykSarif(nested).findings[0]!;
  expect(finding.evidence.locations).toEqual([]);
  expect(finding.evidence.packages![0]!.manifest_path).toBeNull();
  expect(finding.evidence.source_data).toMatchObject({
    run: { properties: { path: "/work/example/services/api" } },
    result: run.results[0],
  });
  expect(finding.source_finding_id).toBe(
    normalizeSnykSarif(input).findings[0]!.source_finding_id,
  );
  expect(nested).toEqual(original);
});

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

test("official Snyk plugin SCA bundles preserve MCP evidence and source limitations", () => {
  const input = snykPluginExport();
  const before = structuredClone(input);
  const result = normalizeSnykFindingsExport(input);
  expect(result.excluded).toEqual([]);
  expect(result.findings[0]!.evidence).toMatchObject({
    title: "Synthetic vulnerability",
    severity: "high",
    advisory_ids: ["SNYK-EXAMPLE-1", "CVE-2099-0001"],
    packages: [
      {
        name: "@example/package",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
        manifest_path: null,
      },
    ],
    locations: [],
    code_revision: "synthetic-revision",
    source_updated_at: null,
    source_data: {
      format: input.format,
      collection: input.collection,
      finding: input.findings[0],
    },
  });
  expect(input).toEqual(before);
});

test("plugin finding identity ignores scan timestamps and preserves separate occurrences", () => {
  const input = snykPluginExport();
  const first = normalizeSnykFindingsExport(input).findings[0]!;
  input.collection.finishedAt = "2026-01-02T00:01:00Z";
  input.findings[0]!.severity.value = "Critical";
  const updated = normalizeSnykFindingsExport(input).findings[0]!;
  expect(updated.source_finding_id).toBe(first.source_finding_id);
  expect(updated.evidence.severity).toBe("critical");
  input.findings.push(structuredClone(input.findings[0]!));
  input.findings[1]!.id.value += "|different-occurrence";
  const distinct = normalizeSnykFindingsExport(input);
  expect(distinct.findings).toHaveLength(2);
  expect(
    new Set(distinct.findings.map((item) => item.source_finding_id)).size,
  ).toBe(2);
  input.findings[1]!.id.value = input.findings[0]!.id.value;
  const duplicate = normalizeSnykFindingsExport(input);
  expect(duplicate.findings).toEqual([]);
  expect(duplicate.excluded).toHaveLength(2);
});

test("mixed plugin bundles explicitly exclude other products and licenses", () => {
  const input = snykPluginExport();
  for (const [scanner, category, scan] of [
    ["snyk-code", "code_weakness", "code"],
    ["snyk-open-source", "license", "sca"],
    ["snyk-open-source", "dependency_vulnerability", "sbom"],
  ]) {
    const unsupported = structuredClone(input.findings[0]!);
    unsupported.id.value = `${scanner}/${category}/${scan}`;
    unsupported.originatingScanner = scanner!;
    unsupported.category = category!;
    unsupported.observation.scan = scan!;
    input.findings.push(unsupported);
  }
  const result = normalizeSnykFindingsExport(input);
  expect(result.findings).toHaveLength(1);
  expect(result.excluded.map((item) => item.position)).toEqual([2, 3, 4]);
  expect(
    result.excluded.every((item) =>
      item.reason.includes("Only Snyk Open Source SCA"),
    ),
  ).toBe(true);
});

test("plugin imports keep dirty workspace context without asserting an exact revision", () => {
  const input = snykPluginExport();
  input.collection.target.workingTreeDirty = true;
  input.collection.target.changedPaths = ["package.json"];
  const evidence = normalizeSnykFindingsExport(input).findings[0]!.evidence;
  expect(evidence.code_revision).toBeNull();
  expect(evidence.source_data).toMatchObject({
    collection: { target: input.collection.target },
  });
});

test("plugin imports retain unknown severity and unsafe paths only as original evidence", () => {
  const input = snykPluginExport();
  input.findings[0]!.severity.value = "urgent";
  input.findings[0]!.asset.manifest = "../package.json";
  const evidence = normalizeSnykFindingsExport(input).findings[0]!.evidence;
  expect(evidence.severity).toBe("unknown");
  expect(evidence.locations).toEqual([]);
  expect(evidence.packages![0]!.manifest_path).toBeNull();
  expect(evidence.source_data).toMatchObject({ finding: input.findings[0] });
});

test("saved official plugin bundles are detected through the existing Snyk reader", async () => {
  const dir = await mkdtemp(join(tmpdir(), "snyk-plugin-import-"));
  try {
    const input = snykPluginExport();
    const path = join(dir, "findings.json.gz");
    await writeFile(path, gzipSync(JSON.stringify(input)));
    expect(await readSnykFindings(path)).toEqual(
      normalizeSnykFindingsExport(input),
    );
    expect(() =>
      normalizeSnykFindingsExport({ ...input, provider: "other" }),
    ).toThrow("from Snyk");
    expect(() =>
      normalizeSnykFindingsExport({
        ...input,
        format: "snyk-findings-export/v2",
      }),
    ).toThrow("v1");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("nested plugin scan targets do not become root-relative repository paths", () => {
  const input = snykPluginExport();
  input.collection.target.path = "/work/example/services/api";
  input.findings[0]!.nativeRecord.filePath =
    "/work/example/services/api/package.json";
  const evidence = normalizeSnykFindingsExport(input).findings[0]!.evidence;
  expect(evidence.locations).toEqual([]);
  expect(evidence.packages![0]!.manifest_path).toBeNull();
  expect(evidence.source_data).toMatchObject({
    collection: { target: input.collection.target },
    finding: {
      asset: { manifest: "package.json" },
      nativeRecord: input.findings[0]!.nativeRecord,
    },
  });
});

test("native Snyk JSON retains advisory, dependency path, remediation and project context", () => {
  const input = snykJson();
  input.path = "/work/example/services/api";
  const original = structuredClone(input);
  const result = normalizeSnykJson(input);
  expect(result.excluded).toEqual([]);
  expect(result.read).toBe(1);
  const { vulnerabilities, ...project } = input;
  expect(result.findings[0]!.evidence).toMatchObject({
    title: "Synthetic vulnerability",
    description: "Complete native advisory description",
    severity: "high",
    advisory_ids: ["SNYK-EXAMPLE-1", "CVE-2099-0001"],
    packages: [
      {
        name: "@example/package",
        ecosystem: "npm",
        installed_version: "1.0.0",
        fixed_versions: ["1.0.1"],
        manifest_path: null,
      },
    ],
    locations: [],
    code_revision: null,
    source_data: { project, vulnerability: vulnerabilities[0] },
  });
  expect(input).toEqual(original);
});

test("native identities preserve dependency occurrences and projects across report ordering and machine paths", () => {
  const first = snykJson();
  const originalId = normalizeSnykJson(first).findings[0]!.source_finding_id;
  first.path = "/another/checkout";
  first.summary = "Updated summary";
  first.vulnerabilities[0]!.description = "Updated advisory";
  first.vulnerabilities.push(structuredClone(first.vulnerabilities[0]!));
  first.vulnerabilities[1]!.from.splice(1, 0, "another-parent@1.0.0");
  const second = structuredClone(first);
  second.displayTargetFile = "services/worker/package.json";
  const result = normalizeSnykJson([first, second]);
  expect(result.excluded).toEqual([]);
  expect(
    new Set(result.findings.map((finding) => finding.source_finding_id)).size,
  ).toBe(4);
  expect(result.findings[0]!.source_finding_id).toBe(originalId);
  const reordered = normalizeSnykJson([second, first]);
  expect(
    reordered.findings.map((finding) => finding.source_finding_id).sort(),
  ).toEqual(result.findings.map((finding) => finding.source_finding_id).sort());
  const duplicate = normalizeSnykJson([first, first]);
  expect(duplicate.findings).toEqual([]);
  expect(duplicate.excluded).toHaveLength(4);
});

test("native SCA JSON excludes license records and preserves the clean empty-result distinction", () => {
  const license = {
    ...snykJson().vulnerabilities[0]!,
    id: "snyk:lic:npm:example:license",
    type: "license",
  };
  const mixed = snykJson();
  mixed.vulnerabilities.push(license);
  const result = normalizeSnykJson(mixed);
  expect(result.findings).toHaveLength(1);
  expect(result.excluded).toHaveLength(1);
  expect(result.excluded[0]!.reason).toContain(
    "license findings are unsupported",
  );
  const licenseOnly = normalizeSnykJson({
    ...mixed,
    vulnerabilities: [license],
  });
  expect(licenseOnly.read).toBe(1);
  expect(licenseOnly.findings).toEqual([]);
  expect(licenseOnly.excluded).toHaveLength(1);
  expect(
    normalizeSnykJson({ ...snykJson(), ok: true, vulnerabilities: [] }),
  ).toEqual({ read: 0, findings: [], excluded: [] });
});

test("native project errors stop import, including partial all-projects output", () => {
  const failed = {
    ok: false,
    error: "Synthetic dependency resolution failed",
    path: "/work/example/worker",
  };
  for (const input of [failed, [snykJson(), failed]]) {
    expect(() => normalizeSnykJson(input)).toThrow(
      "Synthetic dependency resolution failed",
    );
  }
  for (const input of [
    { ...snykJson(), docker: { baseImage: "example-image" } },
    { ...snykJson(), docker: {} },
    { ...snykJson(), applications: [] },
    { infrastructureAsCodeIssues: [], ok: true },
    { version: "2.1.0", runs: [] },
    { data: [] },
  ]) {
    expect(() => normalizeSnykJson(input)).toThrow();
  }
});

test("native grouped JSON cannot silently collapse package occurrences", () => {
  const input = snykJson();
  const grouped = {
    ...input,
    vulnerabilities: input.vulnerabilities.map((item) => ({
      ...item,
      from: [item.from],
      name: [item.name],
    })),
  };
  expect(normalizeSnykJson(grouped).findings).toEqual([]);
  expect(normalizeSnykJson(grouped).excluded).toHaveLength(1);
});

test("native JSON object and array exports are read through the existing Snyk provider", async () => {
  const dir = await mkdtemp(join(tmpdir(), "snyk-native-import-"));
  try {
    const path = join(dir, "findings.json.gz");
    for (const input of [snykJson(), [snykJson()]]) {
      await writeFile(path, gzipSync("\uFEFF" + JSON.stringify(input)));
      expect(await readSnykFindings(path)).toEqual(normalizeSnykJson(input));
    }
    const ids = [
      normalizeSnykJson(snykJson()),
      normalizeSnykFindingsExport(snykPluginExport()),
      normalizeSnykSarif(snykSarif()),
    ].map((result) => result.findings[0]!.source_finding_id);
    expect(new Set(ids).size).toBe(3);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

function selfContainedSnykSarif() {
  const input: any = snykSarif();
  const run = input.runs[0];
  run.tool.driver.rules[0].help.text = run.tool.driver.rules[0].help.markdown;
  delete run.results[0].fixes;
  return input;
}

test("unrelated SARIF artifact inventories do not change direct-location findings", () => {
  const input = selfContainedSnykSarif();
  const expected = normalizeSnykSarif(input);
  input.runs[0].artifacts = Array.from({ length: 5000 }, (_, index) => ({
    location: { uri: `unrelated/project-${index}/package.json` },
  }));
  expect(
    Buffer.byteLength(JSON.stringify(input.runs[0].artifacts)),
  ).toBeGreaterThan(256 * 1024);
  const original = structuredClone(input);
  expect(normalizeSnykSarif(input)).toEqual(expected);
  expect(input).toEqual(original);
});

test.each([{}, { artifacts: [], results: [] }])(
  "self-contained SARIF permits empty external references %j",
  (externalPropertyFileReferences) => {
    const input = selfContainedSnykSarif();
    input.runs[0].externalPropertyFileReferences =
      externalPropertyFileReferences;
    const original = structuredClone(input);
    const output = normalizeSnykSarif(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings).toHaveLength(1);
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      run: { externalPropertyFileReferences },
      result: input.runs[0].results[0],
    });
    expect(input).toEqual(original);
  },
);

test.each(["code flow", "fix", "invocation"] as const)(
  "SARIF artifact indexes in retained %s evidence keep their original inventory",
  (context) => {
    const input = selfContainedSnykSarif();
    const run = input.runs[0];
    const result = run.results[0];
    run.artifacts = [
      { location: { uri: "parent" } },
      { location: { uri: "referenced/package.json" }, parentIndex: 0 },
    ];
    if (context === "code flow") {
      result.codeFlows = [
        {
          threadFlows: [
            {
              locations: [
                {
                  location: {
                    physicalLocation: {
                      artifactLocation: { index: 1 },
                      region: { startLine: 1 },
                    },
                  },
                },
              ],
            },
          ],
        },
      ];
    } else if (context === "fix") {
      result.fixes = [
        {
          description: { text: "Synthetic dependency update" },
          artifactChanges: [
            {
              artifactLocation: { index: 1 },
              replacements: [
                {
                  deletedRegion: { startLine: 1 },
                  insertedContent: { text: "synthetic update" },
                },
              ],
            },
          ],
        },
      ];
    } else {
      run.invocations = [
        { executionSuccessful: true, executableLocation: { index: 1 } },
      ];
    }
    const original = structuredClone(input);
    const output = normalizeSnykSarif(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings).toHaveLength(1);
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      run: {
        artifacts: run.artifacts,
        ...(run.invocations ? { invocations: run.invocations } : {}),
      },
      result,
      rule: run.tool.driver.rules[0],
    });
    expect(input).toEqual(original);
  },
);

test("direct SARIF manifest locations retain matching artifact metadata", () => {
  const input = selfContainedSnykSarif();
  const artifact = {
    location: { uri: "package.json" },
    contents: { text: '{"name":"synthetic-project"}' },
  };
  input.runs[0].artifacts = [artifact];
  const original = structuredClone(input);
  const output = normalizeSnykSarif(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    run: { artifacts: [artifact] },
    result: input.runs[0].results[0],
  });
  expect(input).toEqual(original);
});

const snykRepositoryContexts: [string, string][] = [
  [
    "git@git.example.test:example/project.git",
    "https://git.example.test/example/project",
  ],
  [
    "ssh://git@git.example.test/example/project.git",
    "https://git.example.test/example/project",
  ],
  [
    "ssh://git@git.example.test:22/example/project.git",
    "https://git.example.test/example/project",
  ],
  [
    "tenant@tenant.ghe.com:example/project.git",
    "https://tenant.ghe.com/example/project",
  ],
  [
    "ssh://tenant@tenant.ghe.com/example/project.git",
    "https://tenant.ghe.com/example/project",
  ],
  [
    "ssh://tenant@tenant.ghe.com:22/example/project.git",
    "https://tenant.ghe.com/example/project",
  ],
];

test.each(["\t", "\r", "\n"])(
  "SSH repository claims retain literal hostname and path bytes: %j",
  (control) => {
    const repository = `ssh://git@github.${control}com/example/pro${control}ject.git`;
    const input = snykPluginExport();
    input.collection.target.repository = repository;
    const source =
      normalizeSnykFindingsExport(input).findings[0]!.evidence.source_data;
    expect(
      snykRepositoryUrls(source, {
        cloudRepositoryUrl: "https://github.com/example/project",
      }),
    ).toEqual([repository]);
    expect(snykRepositoryUrls(source)).toEqual([repository]);
    expect(snykRepositoryUrls(source, { normalizeGitRemote: false })).toEqual([
      repository,
    ]);
    expect(source).toMatchObject({ collection: input.collection });
  },
);

test.each(snykRepositoryContexts)(
  "Plugin repository claims stay raw without Cloud context or when normalization is disabled: %s",
  (repository, cloudRepositoryUrl) => {
    const input = snykPluginExport();
    input.collection.target.repository = repository;
    const source =
      normalizeSnykFindingsExport(input).findings[0]!.evidence.source_data;
    expect(snykRepositoryUrls(source)).toEqual([repository]);
    expect(
      snykRepositoryUrls(source, {
        normalizeGitRemote: false,
        cloudRepositoryUrl,
      }),
    ).toEqual([repository]);
    expect(source).toMatchObject({ collection: input.collection });
  },
);

test.each(snykRepositoryContexts)(
  "SARIF repository claims stay raw without Cloud context or when normalization is disabled: %s",
  (repository, cloudRepositoryUrl) => {
    const sarif = snykSarif();
    const provenance = [{ repositoryUri: repository }];
    const input = {
      ...sarif,
      runs: sarif.runs.map((run) => ({
        ...run,
        versionControlProvenance: provenance,
      })),
    };
    const source = normalizeSnykSarif(input).findings[0]!.evidence.source_data;
    expect(snykRepositoryUrls(source)).toEqual([repository]);
    expect(
      snykRepositoryUrls(source, {
        normalizeGitRemote: false,
        cloudRepositoryUrl,
      }),
    ).toEqual([repository]);
    expect(source).toMatchObject({
      run: { versionControlProvenance: provenance },
    });
  },
);
