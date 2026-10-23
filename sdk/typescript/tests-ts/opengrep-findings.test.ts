import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  normalizeOpenGrepFindings as normalize,
  readOpenGrepFindings,
} from "../src/opengrep-findings.js";
import {
  opengrepJson,
  opengrepTraceJson,
} from "./support/opengrep-import-fixtures.js";

const options = { sourceRepositoryUrl: "https://github.com/example/project" };

test("OpenGrep keeps native evidence and incomplete-run metadata without an assessment", () => {
  const input = opengrepJson();
  const original = structuredClone(input);
  const output = normalize(input, options);
  expect(output.read).toBe(1);
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence).toMatchObject({
    title: "example.synthetic-rule",
    severity: "unknown",
    locations: [{ path: "src/example.ts", line: 3 }],
    details: {
      kind: "sast",
      scanner_origin: "OpenGrep",
      source_status: "open",
      repository: { url: options.sourceRepositoryUrl },
      code: { end_line: 3, snippet: "example()" },
      weakness_ids: ["CWE-000"],
    },
    source_data: {
      report: {
        version: input.version,
      },
      scan_error_count: input.errors.length,
      results: input.results,
    },
  });
  expect(output.findings[0]!.evidence).not.toHaveProperty("assessment");
  expect(output.findings[0]!.evidence.source_data!["report"]).toEqual({
    version: input.version,
  });
  const { results: _results, ...report } = original;
  expect(output.report).toEqual(report);
  expect(input).toEqual(original);
});

test.each(["INFO", "WARNING", "ERROR", "MEDIUM", "FUTURE_LEVEL"])(
  "scanner severity %s remains raw evidence rather than assessed risk",
  (severity) => {
    const input = opengrepJson();
    input.results[0]!.extra.severity = severity;
    const evidence = normalize(input, options).findings[0]!.evidence;
    expect(evidence.severity).toBe("unknown");
    expect(evidence.source_data).toMatchObject({ results: input.results });
  },
);

test("location identities survive fingerprint renumbering and result reordering", () => {
  const input = opengrepJson();
  input.results[0]!.start.line = 179;
  input.results[0]!.end.line = 179;
  const originalId = normalize(input, options).findings[0]!.source_finding_id;
  const earlier = structuredClone(input.results[0]!);
  earlier.start.line = 92;
  earlier.end.line = 92;
  input.results[0]!.extra.fingerprint = "synthetic-fingerprint_2";
  input.results[0]!.extra.message = "Updated rule message";
  input.results[0]!.start.offset = 500;
  input.results[0]!.end.offset = 508;
  input.results.unshift(earlier);
  const output = normalize(input, options);
  expect(
    new Set(output.findings.map((item) => item.source_finding_id)).size,
  ).toBe(2);
  expect(
    output.findings.find((item) => item.evidence.locations![0]!.line === 179)!
      .source_finding_id,
  ).toBe(originalId);
  input.results.reverse();
  expect(normalize(input, options)).toEqual(output);
});

test("relative path spellings share an identity while source moves and rules stay distinct", () => {
  const input = opengrepJson();
  const first = normalize(input, options).findings[0]!;
  input.results[0]!.path = ".\\src\\.\\example.ts";
  const equivalent = normalize(input, options).findings[0]!;
  expect(equivalent.source_finding_id).toBe(first.source_finding_id);
  expect(equivalent.evidence.locations).toEqual(first.evidence.locations);
  input.results[0]!.start.line++;
  input.results[0]!.end.line++;
  expect(normalize(input, options).findings[0]!.source_finding_id).not.toBe(
    first.source_finding_id,
  );
  input.results[0]!.start.line--;
  input.results[0]!.end.line--;
  input.results[0]!.check_id = "example.other-rule";
  expect(normalize(input, options).findings[0]!.source_finding_id).not.toBe(
    first.source_finding_id,
  );
});

test("one source occurrence retains every trace observation in deterministic order", () => {
  const input = opengrepTraceJson();
  const original = structuredClone(input);
  const output = normalize(input, options);
  expect(output.read).toBe(2);
  expect(output.findings).toHaveLength(1);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.source_data!["results"]).toHaveLength(2);
  expect(output.findings[0]!.evidence.source_data!["results"]).toEqual(
    expect.arrayContaining(input.results),
  );
  input.results.reverse();
  expect(normalize(input, options)).toEqual(output);
  expect(input.results.reverse()).toEqual(original.results);
});

test("an invalid observation does not hide a valid sibling at the same source range", () => {
  const input: any = opengrepJson();
  const valid = structuredClone(input.results[0]);
  const invalid = structuredClone(valid);
  invalid.extra.message = { text: "Invalid native message" };
  const backwards = structuredClone(valid);
  backwards.end.line = 1;
  input.results = [invalid, valid, null, backwards];
  const output = normalize(input, options);
  expect(output.read).toBe(4);
  expect(output.findings).toHaveLength(1);
  expect(output.findings[0]!.evidence.source_data!["results"]).toEqual([valid]);
  expect(output.excluded.map((item) => item.position)).toEqual([1, 3, 4]);
  expect(output.excluded[0]!.source_finding_id).toBe(
    output.findings[0]!.source_finding_id,
  );
  expect(output.excluded[0]!.reason).toContain("message string");
  expect(output.excluded[2]!.reason).toContain("ends before");
});

test("grouped observations still honor the existing Cloud evidence size contract", () => {
  const input: any = opengrepTraceJson();
  for (const result of input.results) {
    result.extra.context = "x".repeat(140_000);
    expect(
      normalize({ ...input, results: [result] }, options).excluded,
    ).toEqual([]);
  }
  const output = normalize(input, options);
  expect(output.findings).toEqual([]);
  expect(output.excluded.map((item) => item.position)).toEqual([1, 2]);
  expect(output.excluded.every((item) => item.reason.includes("256 KiB"))).toBe(
    true,
  );
});

test("large run diagnostics do not consume each finding's evidence budget", () => {
  const input = opengrepJson();
  input.errors = Array.from({ length: 2000 }, (_, index) => ({
    ...input.errors[0]!,
    path: `src/file-${index}.ts`,
  }));
  const output = normalize(input, options);
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(1);
  expect(output.report!["errors"]).toEqual(input.errors);
  const sourceData = output.findings[0]!.evidence.source_data!;
  expect(sourceData["report"]).not.toHaveProperty("errors");
  expect(sourceData["scan_error_count"]).toBe(2000);
});

test("scan-wide matching explanations stay outside each finding's evidence budget", () => {
  const input = {
    ...opengrepJson(),
    explanations: [
      {
        op: "pattern",
        children: [],
        matches: [],
        pattern: "x".repeat(300_000),
      },
    ],
  };
  const output = normalize(input, options);
  expect(output.excluded).toEqual([]);
  expect(output.findings).toHaveLength(1);
  expect(output.report!["explanations"]).toEqual(input.explanations);
  expect(output.findings[0]!.evidence.source_data!["report"]).toEqual({
    version: input.version,
  });
});

test("ignored matches remain visible as unassessed source evidence", () => {
  const input = opengrepJson();
  input.results[0]!.extra.is_ignored = true;
  const output = normalize(input, options);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.details!.source_status).toBe("ignored");
  expect(output.findings[0]!.evidence.source_data!["results"]).toEqual(
    input.results,
  );
  expect(output.findings[0]!.evidence).not.toHaveProperty("assessment");
});

test.each(["/tmp/example.ts", "C:\\repo\\example.ts", "../example.ts"])(
  "unattributed path %s stays raw and cannot become a repository location",
  (path) => {
    const input = opengrepJson();
    input.results[0]!.path = path;
    const output = normalize(input, options);
    expect(output.excluded).toEqual([]);
    expect(output.findings[0]!.evidence.locations).toEqual([]);
    expect(output.findings[0]!.evidence.details!.code!.end_line).toBeNull();
    expect(output.findings[0]!.evidence.source_data!["results"]).toEqual(
      input.results,
    );
  },
);

test("zero-result reports retain partial parsing, skipped paths and unknown run metadata", () => {
  const input: any = opengrepJson();
  input.results = [];
  input.errors.push({
    type: ["PartialParsing", [{ path: "src/skipped.ts", start: { line: 3 } }]],
    message: "Synthetic unsupported syntax",
  });
  const output = normalize(input, options);
  expect(output).toMatchObject({ read: 0, findings: [], excluded: [] });
  const { results: _results, ...report } = input;
  expect(output.report).toEqual(report);
});

test("missing result arrays and SARIF are not treated as empty native reports", () => {
  expect(() => normalize({ version: "1.32.0" }, options)).toThrow(
    "OpenGrep results must be an array",
  );
  expect(() => normalize({ version: "2.1.0", runs: [] }, options)).toThrow(
    "OpenGrep results must be an array",
  );
  expect(() => normalize(opengrepJson(), { sourceRepositoryUrl: "" })).toThrow(
    "OpenGrep sourceRepositoryUrl",
  );
});

test("reads native gzip JSON through the shared scanner reader", async () => {
  const directory = await mkdtemp(join(tmpdir(), "opengrep-import-"));
  try {
    const path = join(directory, "scanner-output.json.gz");
    const input = opengrepJson();
    await writeFile(path, gzipSync(`\uFEFF${JSON.stringify(input)}`));
    expect(await readOpenGrepFindings(path, options)).toEqual(
      normalize(input, options),
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
