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
