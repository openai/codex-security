import { expect, test } from "bun:test";
import {
  normalizeSemgrepFindings as normalizeJson,
  normalizeSemgrepSarif as normalizeSarif,
} from "../src/semgrep-findings.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";

test("Semgrep JSON preserves source severity, findings, source assertions and report metadata", () => {
  const input = semgrepJson();
  const original = structuredClone(input);
  const output = normalizeSemgrepFindings(input);
  expect(input).toEqual(original);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence).toMatchObject({
    title: "example.synthetic-rule",
    severity: "critical",
    locations: [{ path: "src/example.ts", line: 3 }],
    source_data: {
      result: original.results[0],
      report: { version: original.version, errors: [] },
    },
  });
  expect(output.findings[0]!.evidence).not.toHaveProperty("assessment");
});

test("platform fingerprints survive line, severity and rule text updates", () => {
  const input = semgrepJson();
  const first = normalizeSemgrepFindings(input).findings[0]!;
  input.results[0]!.start.line = 9;
  input.results[0]!.end.line = 9;
  input.results[0]!.extra.severity = "LOW";
  input.results[0]!.extra.message = "Updated source message";
  const second = normalizeSemgrepFindings(input).findings[0]!;
  expect(second.source_finding_id).toBe(first.source_finding_id);
  expect(second.evidence).not.toEqual(first.evidence);
  expect(
    normalizeSemgrepSarif(semgrepSarif()).findings[0]!.source_finding_id,
  ).toBe(first.source_finding_id);
});

test("Community Edition fallback is stable for identical ranges and distinct for moved findings", () => {
  const input: any = semgrepJson();
  delete input.results[0].extra.fingerprint;
  const first = normalizeSemgrepFindings(input).findings[0]!;
  input.results[0].extra.message = "New message";
  expect(normalizeSemgrepFindings(input).findings[0]!.source_finding_id).toBe(
    first.source_finding_id,
  );
  input.results[0].start.line++;
  input.results[0].end.line++;
  expect(
    normalizeSemgrepFindings(input).findings[0]!.source_finding_id,
  ).not.toBe(first.source_finding_id);
});

test.each([
  ["ERROR", "high"],
  ["WARNING", "medium"],
  ["INFO", "low"],
  ["CRITICAL", "critical"],
  ["HIGH", "high"],
  ["MEDIUM", "medium"],
  ["LOW", "low"],
  ["EXPERIMENT", "unknown"],
] as const)("maps severity %s to %s", (inputLevel, expected) => {
  const input = semgrepJson();
  input.results[0]!.extra.severity = inputLevel!;
  expect(normalizeSemgrepFindings(input).findings[0]!.evidence.severity).toBe(
    expected,
  );
});

test("SARIF retains complete selected rule, suppressions and dataflow", () => {
  const input = semgrepSarif();
  const output = normalizeSemgrepFindings(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence).toMatchObject({
    severity: "high",
    source_data: {
      result: input.runs[0]!.results[0],
      rule: input.runs[0]!.tool.driver.rules[0],
    },
  });
});

test("failed scans and unrelated SARIF producers fail before publishing partial results", () => {
  const input: any = semgrepJson();
  input.errors = [{ message: "Scan incomplete" }];
  expect(() => normalizeSemgrepFindings(input)).toThrow("scan errors");
  const sarif = semgrepSarif();
  sarif.runs[0]!.invocations[0]!.executionSuccessful = false;
  expect(() => normalizeSemgrepFindings(sarif)).toThrow("unsuccessful");
  sarif.runs[0]!.tool.driver.name = "other";
  expect(() => normalizeSemgrepFindings(sarif)).toThrow(
    "Semgrep SARIF producer",
  );
});

test("all duplicate fingerprints are excluded even when one result is invalid", () => {
  const input = semgrepJson();
  input.results.push(structuredClone(input.results[0]!));
  input.results[1]!.extra.message = "x".repeat(65537);
  const output = normalizeSemgrepFindings(input);
  expect(output.findings).toEqual([]);
  expect(output.excluded).toHaveLength(2);
  const sarif: any = semgrepSarif();
  sarif.runs[0].results.push(structuredClone(sarif.runs[0].results[0]));
  delete sarif.runs[0].results[1].message;
  expect(normalizeSemgrepFindings(sarif).findings).toEqual([]);
});

test("unknown paths stay raw and invalid ranges are excluded", () => {
  const input = semgrepJson();
  input.results[0]!.path = "../outside.ts";
  expect(
    normalizeSemgrepFindings(input).findings[0]!.evidence.locations,
  ).toEqual([]);
  input.results[0]!.start.line = 0;
  expect(normalizeSemgrepFindings(input).findings).toEqual([]);
});

test("500 distinct fingerprints survive reordering", () => {
  const input = semgrepJson();
  const original = input.results[0]!;
  input.results = Array.from({ length: 500 }, (_, i) => ({
    ...structuredClone(original),
    extra: { ...original.extra, fingerprint: `synthetic-${i}` },
  }));
  const first = normalizeSemgrepFindings(input);
  input.results.reverse();
  const second = normalizeSemgrepFindings(input);
  expect(first.findings).toHaveLength(500);
  expect(second.excluded).toEqual([]);
  expect(first.findings.map((f) => f.source_finding_id).sort()).toEqual(
    second.findings.map((f) => f.source_finding_id).sort(),
  );
});

const options = { sourceRepositoryUrl: "https://github.com/example/project" };
const normalizeSemgrepFindings = (input: unknown) =>
  normalizeJson(input, options);
const normalizeSemgrepSarif = (input: unknown) =>
  normalizeSarif(input, options);

test("requires source identity and rejects conflicting SARIF repository provenance", () => {
  expect(() =>
    normalizeJson(semgrepJson(), { sourceRepositoryUrl: "" }),
  ).toThrow("sourceRepositoryUrl");
  const input: any = semgrepSarif();
  input.runs[0].versionControlProvenance = [
    { repositoryUri: "https://github.com/other/project" },
  ];
  expect(() => normalizeSemgrepFindings(input)).toThrow("does not match");
});

test.each([true, false])(
  "SARIF decodes source paths once and matches JSON identity (fingerprint=%s)",
  (fingerprint) => {
    for (const path of ["src/my file.ts", "src/my%20file.ts"]) {
      const json: any = semgrepJson();
      const sarif: any = semgrepSarif();
      json.results[0].path = path;
      sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri =
        path.split("/").map(encodeURIComponent).join("/");
      if (!fingerprint) {
        delete json.results[0].extra.fingerprint;
        delete sarif.runs[0].results[0].fingerprints;
      }
      const original = structuredClone(sarif);
      const finding = normalizeSemgrepSarif(sarif).findings[0]!;
      expect(finding.evidence.locations).toEqual([{ path, line: 3 }]);
      expect(finding.source_finding_id).toBe(
        normalizeSemgrepFindings(json).findings[0]!.source_finding_id,
      );
      expect(finding.evidence.source_data).toMatchObject({
        result: original.runs[0].results[0],
      });
      expect(sarif).toEqual(original);
    }
  },
);

test.each([
  "%2e%2e/outside.ts",
  "%2Foutside.ts",
  "C%3A%5Coutside.ts",
  "src/%00.ts",
])(
  "SARIF retains encoded unsafe URI %s without a repository location",
  (uri) => {
    const input = semgrepSarif();
    input.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri =
      uri;
    const output = normalizeSemgrepSarif(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([]);
    expect(output.findings[0]!.evidence.details?.code?.end_line).toBeNull();
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      result: input.runs[0]!.results[0],
    });
  },
);

test("SARIF matches custom GitHub Enterprise repository casing without merging ports or schemes", () => {
  const input: any = semgrepSarif();
  input.runs[0].versionControlProvenance = [
    { repositoryUri: "https://git.example.test/Example/Project.git" },
  ];
  expect(
    normalizeSarif(input, {
      sourceRepositoryUrl: "https://GIT.EXAMPLE.TEST/example/project/",
    }).findings,
  ).toHaveLength(1);
  for (const sourceRepositoryUrl of [
    "http://git.example.test/example/project",
    "https://git.example.test:443/example/project",
    "https://git.example.test/other/project",
  ]) {
    expect(() => normalizeSarif(input, { sourceRepositoryUrl })).toThrow(
      "does not match",
    );
  }
});

test.each([
  [
    "external base",
    { uri: "src/example.ts", uriBaseId: "ROOT" },
    { ROOT: { uri: "file:///outside/" } },
  ],
  [
    "subdirectory base",
    { uri: "src/example.ts", uriBaseId: "PACKAGE" },
    { PACKAGE: { uri: "project-a/", uriBaseId: "%SRCROOT%" } },
  ],
  [
    "redefined source root",
    { uri: "src/example.ts", uriBaseId: "%SRCROOT%" },
    { "%SRCROOT%": { uri: "project-a/", uriBaseId: "ROOT" } },
  ],
  [
    "explicit source-root URI",
    { uri: "src/example.ts", uriBaseId: "%SRCROOT%" },
    { "%SRCROOT%": { uri: "file:///repo/subproject/" } },
  ],
  ["indexed URI", { uri: "src/example.ts", index: 0 }, {}],
  ["index only", { index: 0 }, {}],
] as const)(
  "SARIF retains unsupported %s without inventing a path or CE identity",
  (_label, artifact, bases) => {
    const input: any = semgrepSarif();
    const expectedId =
      normalizeSemgrepSarif(input).findings[0]!.source_finding_id;
    const run = input.runs[0];
    run.originalUriBaseIds = structuredClone(bases);
    run.artifacts = [{ location: { uri: "nested/actual.ts" } }];
    run.results[0].locations[0].physicalLocation.artifactLocation =
      structuredClone(artifact);
    const original = structuredClone(input);
    const output = normalizeSemgrepSarif(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings).toHaveLength(1);
    expect(output.findings[0]!.source_finding_id).toBe(expectedId);
    expect(output.findings[0]!.evidence.locations).toEqual([]);
    expect(output.findings[0]!.evidence.details?.code?.end_line).toBeNull();
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      result: original.runs[0].results[0],
      runContext: {
        originalUriBaseIds: bases,
        artifacts: original.runs[0].artifacts,
      },
    });
    expect(input).toEqual(original);

    delete run.results[0].fingerprints;
    const ce = normalizeSemgrepSarif(input);
    expect(ce.findings).toEqual([]);
    expect(ce.excluded).toHaveLength(1);
    expect(ce.excluded[0]!.source_finding_id).toBeNull();
    expect(ce.excluded[0]!.reason).toContain("indexed or unresolved");
  },
);

test("SARIF unresolved bases cannot collide with a valid CE location", () => {
  const input: any = semgrepSarif();
  const run = input.runs[0];
  delete run.results[0].fingerprints;
  const expected = normalizeSemgrepSarif(input).findings[0]!;
  const first = structuredClone(run.results[0]);
  const second = structuredClone(run.results[0]);
  first.locations[0].physicalLocation.artifactLocation.uriBaseId = "A";
  second.locations[0].physicalLocation.artifactLocation.uriBaseId = "B";
  run.originalUriBaseIds = {
    A: { uri: "project-a/", uriBaseId: "%SRCROOT%" },
    B: { uri: "project-b/", uriBaseId: "%SRCROOT%" },
  };
  run.results.unshift(first, second);
  for (const results of [run.results, run.results.toReversed()]) {
    run.results = results;
    const output = normalizeSemgrepSarif(input);
    expect(output.findings).toHaveLength(1);
    expect(output.findings[0]!.source_finding_id).toBe(
      expected.source_finding_id,
    );
    expect(output.findings[0]!.evidence.locations).toEqual(
      expected.evidence.locations,
    );
    expect(output.excluded).toHaveLength(2);
    for (const excluded of output.excluded) {
      expect(excluded.source_finding_id).toBeNull();
      expect(excluded.reason).toContain("indexed or unresolved");
    }
  }
});

test.each([undefined, "%SRCROOT%"])(
  "SARIF native root %s preserves CE identity across JSON and SARIF",
  (base) => {
    const json: any = semgrepJson();
    const input: any = semgrepSarif();
    delete json.results[0].extra.fingerprint;
    delete input.runs[0].results[0].fingerprints;
    input.runs[0].originalUriBaseIds = { OTHER: { uri: "file:///outside/" } };
    const artifact =
      input.runs[0].results[0].locations[0].physicalLocation.artifactLocation;
    if (base === undefined) delete artifact.uriBaseId;
    else artifact.uriBaseId = base;
    const output = normalizeSemgrepSarif(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([
      { path: "src/example.ts", line: 3 },
    ]);
    expect(output.findings[0]!.source_finding_id).toBe(
      normalizeSemgrepFindings(json).findings[0]!.source_finding_id,
    );
  },
);

test("gated CE fingerprint placeholders use independent location identities", () => {
  const input: any = semgrepSarif();
  delete input.runs[0].tool.driver.rules;
  const first = input.runs[0]!.results[0]!;
  first.fingerprints["matchBasedId/v1"] = "requires login";
  const second = structuredClone(first);
  second.locations[0]!.physicalLocation.region.startLine = 6;
  second.locations[0]!.physicalLocation.region.endLine = 6;
  input.runs[0]!.results.push(second);
  const output = normalizeSemgrepFindings(input);
  expect(output.findings).toHaveLength(2);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.source_finding_id).not.toBe(
    output.findings[1]!.source_finding_id,
  );
});

test("does not relabel Supply Chain or Secrets findings as SAST", () => {
  for (const extra of [
    { sca_info: { reachable: true } },
    { validation_state: "CONFIRMED_VALID" },
  ]) {
    const input: any = semgrepJson();
    Object.assign(input.results[0].extra, extra);
    const output = normalizeSemgrepFindings(input);
    expect(output.findings).toEqual([]);
    expect(output.excluded[0]!.reason).toContain("separate qualification");
  }
});

test.each(["Semgrep PRO", "semgrep"])(
  "accepts the native %s SARIF producer name",
  (producer) => {
    const input = semgrepSarif();
    input.runs[0]!.tool.driver.name = producer;
    const output = normalizeSemgrepSarif(input);
    expect(output.findings).toHaveLength(1);
    expect(output.excluded).toEqual([]);
  },
);

test.each(["omitted", "empty"])(
  "accepts CE results with %s rule descriptors",
  (descriptors) => {
    const input: any = semgrepSarif();
    const run = input.runs[0];
    if (descriptors === "omitted") delete run.tool.driver.rules;
    else run.tool.driver.rules = [];
    run.results[0].fingerprints["matchBasedId/v1"] = "requires login";
    run.results[0].level = "warning";
    const known = normalizeSemgrepSarif(input);
    expect(known.excluded).toEqual([]);
    expect(known.findings).toHaveLength(1);
    expect(known.findings[0]!.evidence.severity).toBe("medium");
    expect(known.findings[0]!.evidence.source_data).not.toHaveProperty("rule");
    delete run.results[0].level;
    const unknown = normalizeSemgrepSarif(input);
    expect(unknown.excluded).toEqual([]);
    expect(unknown.findings[0]!.evidence.severity).toBe("unknown");
    expect(unknown.findings[0]!.source_finding_id).toBe(
      known.findings[0]!.source_finding_id,
    );
  },
);

test.each([
  { ruleIndex: 0 },
  { ruleIndex: -1 },
  { rule: { index: 0 } },
  { rule: { guid: "synthetic-rule-guid" } },
])(
  "rejects unresolved references when CE descriptors are absent (%p)",
  (reference) => {
    const input: any = semgrepSarif();
    delete input.runs[0].tool.driver.rules;
    Object.assign(input.runs[0].results[0], reference);
    const output = normalizeSemgrepSarif(input);
    expect(output.findings).toEqual([]);
    expect(output.excluded).toHaveLength(1);
  },
);

test.each([
  ["secrets", undefined],
  ["secrets", null],
  ["sca", undefined],
  ["sca", null],
  ["secrets", "NO_VALIDATOR"],
  ["sca", "NO_VALIDATOR"],
] as const)(
  "excludes explicit %s product without validator metadata (%p)",
  (product, validation) => {
    const input: any = semgrepJson();
    input.results[0].extra.metadata = { product };
    input.results[0].extra.validation_state = validation;
    const output = normalizeSemgrepFindings(input);
    expect(output.findings).toEqual([]);
    expect(output.excluded[0]!.reason).toContain("supports Semgrep SAST");
  },
);

test("accepts an explicit SAST product marker", () => {
  const input: any = semgrepJson();
  input.results[0].extra.metadata = { product: "sast" };
  expect(normalizeSemgrepFindings(input).findings).toHaveLength(1);
});

test.each(["error", "warning", "note", undefined])(
  "rejects native SARIF scan notifications even with executionSuccessful=true (%s)",
  (level) => {
    const input: any = semgrepSarif();
    input.runs[0].invocations = [
      {
        executionSuccessful: true,
        toolExecutionNotifications: [
          { level, message: { text: "A source file could not be analyzed" } },
        ],
      },
    ];
    expect(() => normalizeSemgrepSarif(input)).toThrow(
      "scan error notifications",
    );
  },
);

test("large scan inventories and timing tables do not exclude a small finding", () => {
  const input: any = semgrepJson();
  const paths = Array.from(
    { length: 10000 },
    (_, index) => `path-inventory-entry-${index}/ordinary-source-file.ts`,
  );
  input.paths = { scanned: paths };
  input.time = { targets: paths.map((path) => ({ path, parse_time: 0.001 })) };
  const output = normalizeSemgrepFindings(input);
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence.source_data).toMatchObject({
    result: input.results[0],
  });
  expect(
    JSON.stringify(output.findings[0]!.evidence.source_data),
  ).not.toContain("path-inventory-entry-");
  expect(input.paths.scanned).toHaveLength(10000);
});

test.each([undefined, "sast"])(
  "accepts the documented Code NO_VALIDATOR marker with product %p",
  (product) => {
    const input: any = semgrepJson();
    if (product) input.results[0].extra.metadata = { product };
    else delete input.results[0].extra.metadata;
    input.results[0].extra.validation_state = "NO_VALIDATOR";
    const output = normalizeSemgrepFindings(input);
    expect(output.findings).toHaveLength(1);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      result: { extra: { validation_state: "NO_VALIDATOR" } },
    });
  },
);

test.each(["json", "sarif"])(
  "preserves %s findings with empty native messages",
  (format) => {
    const input: any = format === "json" ? semgrepJson() : semgrepSarif();
    if (format === "json") input.results[0].extra.message = "";
    else input.runs[0].results[0].message = { text: "" };
    const output = normalizeSemgrepFindings(input);
    expect(output.excluded).toEqual([]);
    expect(output.findings).toHaveLength(1);
    expect(output.findings[0]!.evidence.description).toBeNull();
    expect(output.findings[0]!.evidence.source_data).toMatchObject({
      result:
        format === "json"
          ? { extra: { message: "" } }
          : { message: { text: "" } },
    });
  },
);

test.each(["json", "sarif"])(
  "still excludes %s findings with missing or non-string messages",
  (format) => {
    for (const message of [undefined, null, 42]) {
      const input: any = format === "json" ? semgrepJson() : semgrepSarif();
      if (format === "json") input.results[0].extra.message = message;
      else input.runs[0].results[0].message = { text: message };
      const output = normalizeSemgrepFindings(input);
      expect(output.findings).toEqual([]);
      expect(output.excluded).toHaveLength(1);
    }
  },
);
