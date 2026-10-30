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
  for (const list of [{}, { response: { next_page_token: 0 } }]) {
    expect(normalizeEndorFindings({ list })).toEqual(
      normalizeEndorFindings([]),
    );
  }
});

test("an Endor response with no objects and unrecognized list data is not an empty export", () => {
  expect(() =>
    normalizeEndorFindings({ list: { response: { next_page_id: 2 } } }),
  ).toThrow("next_page_id");
  for (const list of [
    { items: [endorFinding()] },
    { response: { total_size: 13 } },
  ]) {
    expect(() => normalizeEndorFindings({ list })).toThrow(
      "Endor list.objects",
    );
  }
});

test("an Endor summary reporting matches cannot substitute for finding objects", () => {
  for (const summary of [
    { count_response: { count: 13 } },
    { count_response: { count: "13" } },
    {
      group_response: {
        groups: { example: { aggregation_count: { count: 2 } } },
      },
    },
  ]) {
    for (const list of [{}, { objects: [] }])
      expect(() => normalizeEndorFindings({ list, ...summary })).toThrow(
        "summary",
      );
  }
  expect(
    normalizeEndorFindings({
      list: {},
      count_response: { count: "0" },
      group_response: { groups: {} },
    }),
  ).toEqual(normalizeEndorFindings([]));
});

test.each(["sast_data", "ai_sast_data"])(
  "Endor %s preserves the primary source location and original evidence",
  (field) => {
    const base = endorFinding();
    const input = {
      ...base,
      spec: {
        ...base.spec,
        target_dependency_name: "",
        dependency_file_paths: ["src/example.ts", "package.json"],
        finding_metadata: {
          [field]: {
            location: {
              relative_path: "src/example.ts",
              start_line: 12,
              end_line: 14,
            },
          },
        },
      },
    };
    const original = structuredClone(input);
    const output = normalizeEndorFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.source_finding_id).toBe(input.uuid);
    expect(output.findings[0]!.evidence.locations).toEqual([
      { path: "package.json", line: null },
      { path: "src/example.ts", line: 12 },
    ]);
    expect(output.findings[0]!.evidence.source_data).toEqual(original);
    expect(input).toEqual(original);
  },
);

test.each([12, 24])(
  "Endor retains distinct code locations without duplicating identical locations (line %i)",
  (secondLine) => {
    const base = endorFinding();
    const location = { relative_path: "src/example.ts", start_line: 12 };
    const input = {
      ...base,
      spec: {
        ...base.spec,
        dependency_file_paths: [],
        finding_metadata: {
          sast_data: { location },
          ai_sast_data: { location: { ...location, start_line: secondLine } },
        },
      },
    };
    const expected = [{ path: "src/example.ts", line: 12 }];
    if (secondLine !== 12)
      expected.push({ path: "src/example.ts", line: secondLine });
    const output = normalizeEndorFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual(expected);
  },
);

test.each([null, 0, -1, 1.5, "12"])(
  "Endor retains a code path without inventing a line from %p",
  (start_line) => {
    const base = endorFinding();
    const input = {
      ...base,
      spec: {
        ...base.spec,
        dependency_file_paths: [],
        finding_metadata: {
          ai_sast_data: {
            location: { relative_path: "src/example.ts", start_line },
          },
        },
      },
    };
    const output = normalizeEndorFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([
      { path: "src/example.ts", line: null },
    ]);
    expect(output.findings[0]!.evidence.source_data).toEqual(input);
  },
);

test("unsafe code locations remain only in the original Endor evidence", () => {
  const base = endorFinding();
  const input = {
    ...base,
    spec: {
      ...base.spec,
      dependency_file_paths: [],
      finding_metadata: {
        sast_data: {
          location: { relative_path: "../outside.ts", start_line: 12 },
        },
        ai_sast_data: {
          location: { relative_path: "C:\\private\\source.ts", start_line: 24 },
        },
      },
    },
  };
  const output = normalizeEndorFindings(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.locations).toEqual([]);
  expect(output.findings[0]!.evidence.source_data).toEqual(input);
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

test("Endor imports the scanned commit while preserving identity across revisions", () => {
  const finding = {
    ...endorFinding(),
    spec: {
      ...endorFinding().spec,
      source_code_version: { ref: "release", sha: "a".repeat(40) },
    },
  };
  const first = normalizeEndorFindings(finding).findings[0]!;
  expect(first.evidence.code_revision).toBe("a".repeat(40));
  finding.spec.source_code_version.sha = "b".repeat(40);
  const updated = normalizeEndorFindings(finding).findings[0]!;
  expect(updated.source_finding_id).toBe(first.source_finding_id);
  expect(updated.evidence.code_revision).toBe("b".repeat(40));
  expect(updated.evidence.source_data).toEqual(finding);

  const withoutSha = {
    ...finding,
    spec: { ...finding.spec, source_code_version: { ref: "release" } },
  };
  expect(
    normalizeEndorFindings(withoutSha).findings[0]!.evidence.code_revision,
  ).toBeNull();
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
    { uuid: "invalid-finding" },
    {
      ...input,
      uuid: "invalid-finding",
      meta: { ...input.meta, update_time: "invalid" },
    },
    {
      ...input,
      uuid: "invalid-finding",
      spec: { ...input.spec, summary: "é".repeat(65536) },
    },
  ]) {
    const output = normalizeEndorFindings([input, invalid]);
    expect(output.findings.map((finding) => finding.source_finding_id)).toEqual(
      [input.uuid],
    );
    expect(output.excluded).toHaveLength(1);
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

test("native and SARIF Endor locations preserve repository filenames containing colons", () => {
  const native = endorFinding();
  native.spec.dependency_file_paths = ["src/schema:prod.ts"];
  const sarif = endorSarif();
  sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri =
    "src/schema%3Aprod.ts";
  const nativeResult = normalizeEndorFindings(native);
  const sarifResult = normalizeEndorFindings(sarif);
  expect(nativeResult.excluded).toEqual([]);
  expect(sarifResult.excluded).toEqual([]);
  expect(nativeResult.findings[0]!.evidence.locations).toEqual([
    { path: "src/schema:prod.ts", line: null },
  ]);
  expect(sarifResult.findings[0]!.evidence.locations).toEqual(
    nativeResult.findings[0]!.evidence.locations,
  );
  expect(nativeResult.findings[0]!.evidence.source_data).toEqual(native);
  expect(sarifResult.findings[0]!.evidence.source_data).toMatchObject({
    result: sarif.runs[0]!.results[0],
  });
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
    url: input.runs[0]!.results[0]!.properties["finding-url"],
    locations: [{ path: "package.json", line: null }],
    source_data: {
      result: input.runs[0]!.results[0],
      rule: input.runs[0]!.tool.driver.rules[0],
    },
  });
});

test("Endor SARIF does not duplicate unrelated artifact inventories into a direct-URI finding", () => {
  const input: any = endorSarif();
  const run = input.runs[0];
  run.artifacts = Array.from({ length: 5_000 }, (_, index) => ({
    location: { uri: `unrelated/source-file-${index}.ts` },
  }));
  run.versionControlProvenance = [
    { repositoryUri: "https://github.com/example/project" },
  ];
  const original = structuredClone(input);
  const output = normalizeEndorSarif(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence.locations).toEqual([
    { path: "package.json", line: null },
  ]);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    result: original.runs[0].results[0],
    rule: original.runs[0].tool.driver.rules[0],
    runContext: {
      versionControlProvenance: original.runs[0].versionControlProvenance,
    },
  });
  expect(
    output.findings[0]!.evidence.source_data!["runContext"],
  ).not.toHaveProperty("artifacts");
  expect(input).toEqual(original);
});

test("Endor SARIF retains artifact metadata for the selected direct-URI location", () => {
  const input: any = endorSarif();
  input.runs[0].artifacts = [
    { location: { uri: "unrelated.ts" } },
    {
      location: { uri: "package.json" },
      contents: { text: "synthetic package contents" },
    },
  ];
  const original = structuredClone(input);
  const output = normalizeEndorSarif(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    result: original.runs[0].results[0],
    runContext: { artifacts: original.runs[0].artifacts },
  });
  expect(input).toEqual(original);
});

test.each([
  {},
  { artifacts: [], results: [] },
  { properties: { producer: "synthetic-exporter" }, artifacts: [] },
])("Endor SARIF accepts an empty external-property map: %p", (references) => {
  const input: any = endorSarif();
  input.runs[0].externalPropertyFileReferences = references;
  const original = structuredClone(input);
  const output = normalizeEndorSarif(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    result: original.runs[0].results[0],
    runContext: { externalPropertyFileReferences: references },
  });
  expect(input).toEqual(original);
});

test.each(["artifacts", "results"])(
  "Endor SARIF still rejects external %s references",
  (property) => {
    const input: any = endorSarif();
    input.runs[0].externalPropertyFileReferences = {
      [property]: [{ location: { uri: "external-results.sarif" } }],
    };
    expect(() => normalizeEndorSarif(input)).toThrow("self-contained");
  },
);

test.each([
  ["packages/my%20app/package.json", "packages/my app/package.json"],
  ["packages/%E6%97%A5%E6%9C%AC/package.json", "packages/日本/package.json"],
  ["packages/my%23app/package.json", "packages/my#app/package.json"],
  ["packages/my%2520app/package.json", "packages/my%20app/package.json"],
  ["%2e%2e/outside/package.json", null],
  ["%2Ftmp/package.json", null],
  ["C%3A%5Cprivate%5Cpackage.json", null],
  ["file:src/package.json", null],
  ["https:src/package.json", null],
  ["packages/invalid%ZZ/package.json", null],
])("Endor SARIF decodes safe repository paths once (%s)", (uri, path) => {
  const input = endorSarif();
  const result = input.runs[0]!.results[0]!;
  result.locations[0]!.physicalLocation.artifactLocation.uri = uri!;
  const output = normalizeEndorFindings(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.locations).toEqual(
    path === null ? [] : [{ path, line: null }],
  );
  expect(output.findings[0]!.evidence.source_data).toMatchObject({ result });
  expect(result.locations[0]!.physicalLocation.artifactLocation.uri).toBe(uri);
});

test.each(["SAST", "SECRETS"])(
  "Endor SARIF retains distinct reported code lines for %s findings",
  (category) => {
    const input = endorSarif();
    const result = input.runs[0]!.results[0]!;
    result.properties.categories = [category];
    result.locations = [1, 42, 42].map((startLine) => ({
      physicalLocation: {
        artifactLocation: { uri: "src/my%20module.ts" },
        region: { startLine },
      },
    }));
    const output = normalizeEndorFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([
      { path: "src/my module.ts", line: 1 },
      { path: "src/my module.ts", line: 42 },
    ]);
    expect(output.findings[0]!.evidence.source_data).toMatchObject({ result });
  },
);

test.each([0, -1, 1.5, "42", null, undefined])(
  "Endor SARIF keeps unknown or invalid code lines as null (%p)",
  (startLine) => {
    const input = endorSarif();
    const result: any = input.runs[0]!.results[0]!;
    result.properties.categories = ["SAST"];
    result.locations[0].physicalLocation.region = { startLine };
    const output = normalizeEndorFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([
      { path: "package.json", line: null },
    ]);
    expect(output.findings[0]!.evidence.source_data).toMatchObject({ result });
  },
);

test("SARIF requires vendor identity, producer and consistent rule references", () => {
  for (const mutate of [
    (r: any) => delete r.results[0].properties["finding-uuid"],
    (r: any) => delete r.results[0].properties["project-uuid"],
    (r: any) => (r.results[0].ruleIndex = 1),
    (r: any) => (r.results[0].rule = { id: "other" }),
    (r: any) => (r.results[0].rule = { index: 1 }),
    (r: any) => (r.results[0].rule = { guid: "other" }),
    (r: any) => (r.tool.driver.rules = []),
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

test("Endor SARIF selects exact rule IDs and original indexes within each run", () => {
  const input = endorSarif();
  const originalRun = input.runs[0]!;
  const originalRule = originalRun.tool.driver.rules[0]!;
  const originalResult = originalRun.results[0]!;
  const runs = [0, 1].map((index) => {
    const rule = {
      ...originalRule,
      guid: `rule-guid-${index}`,
      shortDescription: { text: `Finding from run ${index}` },
    };
    const otherRule = { ...originalRule, id: ` ${originalRule.id} ` };
    return {
      ...originalRun,
      tool: {
        driver: {
          ...originalRun.tool.driver,
          rules: index === 0 ? [rule, otherRule] : [otherRule, rule],
        },
      },
      results: [
        {
          ...originalResult,
          ruleIndex: index,
          rule: { id: rule.id, index, guid: rule.guid },
          properties: {
            ...originalResult.properties,
            "finding-uuid": `finding-from-run-${index}`,
          },
        },
      ],
    };
  });
  const output = normalizeEndorSarif({ ...input, runs });
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(2);
  for (const [index, finding] of output.findings.entries()) {
    expect(finding.source_finding_id).toBe(`finding-from-run-${index}`);
    expect(finding.evidence.title).toBe(`Finding from run ${index}`);
    expect(finding.evidence.source_data!["rule"]).toEqual(
      runs[index]!.tool.driver.rules[index],
    );
  }
});

test("distinct finding UUIDs survive a reordered export", () => {
  const input = Array.from({ length: 3 }, (_, i) => ({
    ...endorFinding(),
    uuid: `finding-example-${i}`,
  }));
  const first = normalizeEndorFindings(input);
  const second = normalizeEndorFindings(input.reverse());
  expect(first.findings).toHaveLength(input.length);
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
    const result = normalizeEndorFindings({
      list: { objects: [finding], response: { next_page_token: 0 } },
    });
    expect(result.excluded).toEqual([]);
    expect(result.findings[0]!.evidence.source_updated_at).toBe(1767225600);
    expect(result.findings[0]!.evidence.source_data).toMatchObject({
      meta: { update_time: timestamp },
    });
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

test.each([
  {
    artifact: { uri: "src/query.ts", uriBaseId: "ROOT" },
    base: "file:///outside/",
  },
  { artifact: { uri: "src/query.ts", uriBaseId: "ROOT" }, base: "subproject/" },
  { artifact: { uri: "src/query.ts", index: 0 }, base: "subproject/" },
  { artifact: { index: 0 }, base: "subproject/" },
])(
  "Endor SARIF leaves unsupported artifact references unmapped: %p",
  ({ artifact, base }) => {
    const input: any = endorSarif();
    const run = input.runs[0];
    run.originalUriBaseIds = { ROOT: { uri: base } };
    run.artifacts = [{ location: { uri: "src/actual.ts" } }];
    const result = run.results[0];
    result.properties.categories = ["SAST"];
    result.locations = [
      {
        physicalLocation: {
          artifactLocation: artifact,
          region: { startLine: 42 },
        },
      },
      {
        physicalLocation: {
          artifactLocation: { uri: "src/direct.ts" },
          region: { startLine: 8 },
        },
      },
    ];
    const original = structuredClone(input);
    const output = normalizeEndorFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.source_finding_id).toBe(
      result.properties["finding-uuid"],
    );
    expect(output.findings[0]!.evidence.locations).toEqual([
      { path: "src/direct.ts", line: 8 },
    ]);
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      result: original.runs[0].results[0],
      runContext: {
        originalUriBaseIds: run.originalUriBaseIds,
        artifacts: run.artifacts,
      },
    });
    expect(input).toEqual(original);
  },
);
