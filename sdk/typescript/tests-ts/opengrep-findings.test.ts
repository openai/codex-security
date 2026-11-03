import { expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  normalizeOpenGrepFindings as normalize,
  readOpenGrepFindings,
} from "../src/opengrep-findings.js";
import { previousReaderSelection } from "../src/reader-selection.js";
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

test("redundant slash components share an identity while source moves and rules stay distinct", () => {
  const input = opengrepJson();
  const first = normalize(input, options).findings[0]!;
  input.results[0]!.path = "./src/./example.ts";
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

test("literal backslashes keep a distinct occurrence when both targets or either target is imported", () => {
  const input = opengrepJson();
  input.results.push({ ...input.results[0]!, path: "src\\example.ts" });
  const together = normalize(input, options);
  const separate = input.results.map(
    (result) =>
      normalize({ ...input, results: [result] }, options).findings[0]!,
  );
  expect(together.excluded).toEqual([]);
  expect(together.findings).toHaveLength(2);
  expect(together.findings).toEqual(expect.arrayContaining(separate));
  expect(
    separate.map((finding) => finding.evidence.locations![0]!.path),
  ).toEqual(input.results.map((result) => result.path));
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

test.each(["group", "trace"] as const)(
  "a size change affecting a %s keeps the unrelated occurrence proven",
  (changed) => {
    const input = opengrepTraceJson();
    const second = input.results[1]!;
    if (changed === "trace") second.extra.message = "x".repeat(140_000);
    // The released reader counted a boxed decimal by its JSON spelling.
    Object.assign(second.extra.metadata, {
      score: new Number(0.00001),
      pad: "",
    });
    const group = normalize(input, options).findings[0]!;
    const bytes = Buffer.byteLength(JSON.stringify(group.evidence));
    Object.assign(second.extra.metadata, { pad: "p".repeat(262_145 - bytes) });
    const unrelated = structuredClone(input.results[0]!);
    unrelated.check_id = "example.unrelated";
    input.results.push(unrelated);
    const current = normalize(input, options);
    expect(current.excluded).toEqual([]);
    expect(current.findings).toHaveLength(2);
    const known = current.findings.filter(
      (row) => row.source_finding_id !== group.source_finding_id,
    );
    expect(known).toHaveLength(1);
    const previous = previousReaderSelection(
      current,
      JSON.parse(JSON.stringify(current)),
    );
    expect(previous?.uncertainFindingIds).toEqual([group.source_finding_id]);
    expect(previous?.knownFindings).toEqual(known);
    const local = normalize(input, options, "local");
    expect(
      previousReaderSelection(local, JSON.parse(JSON.stringify(local))),
    ).toBeUndefined();
  },
);

test.each([
  { score: 0.00001, bytes: 262_145, freshCount: 2, priorCount: 1 },
  { score: 1e-7, bytes: 262_144, freshCount: 1, priorCount: 2 },
])(
  "retains exact singleton membership at $bytes bytes",
  ({ score, bytes, freshCount, priorCount }) => {
    const input = opengrepJson();
    const stable = normalize(input, options).findings[0]!;
    const candidate = {
      ...input.results[0]!,
      check_id: "example.boundary",
      score: new Number(score),
      padding: "",
    };
    const selected = normalize({ ...input, results: [candidate] }, options)
      .findings[0]!;
    candidate.padding = "x".repeat(
      bytes - Buffer.byteLength(JSON.stringify(selected.evidence)),
    );
    input.results.push(candidate);
    const current = normalize(input, options);
    expect(current.findings).toHaveLength(freshCount);
    const prior = previousReaderSelection(
      current,
      JSON.parse(JSON.stringify(current)),
    );
    const expectedIds =
      priorCount === 1
        ? [stable.source_finding_id]
        : [stable.source_finding_id, selected.source_finding_id].sort();
    expect(
      prior?.snapshot?.findings.map((row) => row.source_finding_id),
    ).toEqual(expectedIds);
    expect(prior?.uncertainFindingIds).toBeUndefined();
  },
);

test("an oversized trace leaves the publishable traces at its source occurrence", () => {
  const input = opengrepJson();
  const valid = input.results[0]!;
  const oversized = structuredClone(valid);
  Object.assign(oversized.extra.metadata, { padding: "" });
  const singleton = normalize({ ...input, results: [oversized] }, options);
  const bytes = Buffer.byteLength(
    JSON.stringify(singleton.findings[0]!.evidence),
  );
  Object.assign(oversized.extra.metadata, {
    padding: "x".repeat(256 * 1024 - bytes + 1),
  });
  const rawOnly = structuredClone(valid);
  rawOnly.extra.message = "x".repeat(66_000);
  for (const publishable of [[valid], [rawOnly, valid]]) {
    const expected = normalize({ ...input, results: publishable }, options);
    const results = [oversized, ...publishable];
    for (const position of [1, results.length]) {
      const output = normalize({ ...input, results }, options);
      expect(output.findings).toEqual(expected.findings);
      expect(output.excluded).toEqual([
        {
          position,
          source_finding_id: expected.findings[0]!.source_finding_id,
          reason: expect.stringContaining("256 KiB"),
        },
      ]);
      results.reverse();
    }
    const local = normalize({ ...input, results }, options, "local");
    expect(local.excluded).toEqual([]);
    expect(local.findings[0]!.evidence.source_data!["results"]).toHaveLength(
      results.length,
    );
  }
});

test("raw-only traces consume the space left by all independently publishable siblings", () => {
  const input = opengrepJson();
  const result = input.results[0]!;
  const padded = (tag: string) => {
    const trace = structuredClone(result);
    Object.assign(trace.extra.metadata, { padding: tag.repeat(70_000) });
    return trace;
  };
  const first = padded("a");
  const second = padded("b");
  const fits = structuredClone(result);
  fits.extra.message = "x".repeat(66_000);
  const tooLarge = structuredClone(result);
  tooLarge.extra.message = "y".repeat(130_000);
  const expected = normalize(
    { ...input, results: [first, second, fits] },
    options,
  );
  expect(expected.excluded).toEqual([]);
  expect(expected.findings[0]!.evidence.source_data!["results"]).toHaveLength(
    3,
  );

  const results = [tooLarge, first, fits, second];
  for (const position of [1, results.length]) {
    const output = normalize({ ...input, results }, options);
    expect(output.findings).toEqual(expected.findings);
    expect(output.excluded).toEqual([
      {
        position,
        source_finding_id: expected.findings[0]!.source_finding_id,
        reason: expect.stringContaining("256 KiB"),
      },
    ]);
    expect(output.excluded[0]!.reason).toContain("description");
    results.reverse();
  }
});

test.each([
  ["cloud", "x".repeat(66_000)],
  ["local", "a\0b"],
] as const)(
  "a %s group without a representative reports each trace's own rejected field",
  (target, invalidField) => {
    const input = opengrepJson();
    const message = structuredClone(input.results[0]!);
    message.extra.message = invalidField;
    const snippet = structuredClone(input.results[0]!);
    snippet.extra.lines = invalidField;
    const results = [message, snippet];
    const reasons = results.map(
      (result) =>
        normalize({ ...input, results: [result] }, options, target).excluded[0]!
          .reason,
    );
    const output = normalize({ ...input, results }, options, target);
    expect(output.findings).toEqual([]);
    expect(reasons[0]).toContain("description");
    expect(reasons[1]).toContain("snippet");
    expect(output.excluded.map((item) => item.reason)).toEqual(reasons);
  },
);

test("raw trace errors exclude only their own positions and keep the source occurrence ID", () => {
  const input = opengrepJson();
  const valid = input.results[0]!;
  const id = normalize(input, options).findings[0]!.source_finding_id;
  const deep = structuredClone(valid);
  let nested: unknown = "leaf";
  for (let level = 0; level < 20; level++) nested = { child: nested };
  Object.assign(deep.extra.metadata, { trace: nested });
  const unsafe = structuredClone(valid);
  Object.assign(unsafe.extra.metadata, { count: Number.MAX_SAFE_INTEGER + 1 });
  input.results = [deep, valid, unsafe];
  const cloud = normalize(input, options);
  expect(cloud.excluded).toEqual([
    {
      position: 1,
      source_finding_id: id,
      reason: expect.stringContaining("depth limit"),
    },
    {
      position: 3,
      source_finding_id: id,
      reason: expect.stringContaining("safe integer range"),
    },
  ]);
  expect(cloud.findings[0]!.evidence.source_data!["results"]).toEqual([valid]);
  const local = normalize(input, options, "local");
  expect(local.excluded).toEqual([cloud.excluded[1]!]);
  expect(local.findings[0]!.evidence.source_data!["results"]).toHaveLength(2);
  expect(local.findings[0]!.evidence.source_data!["results"]).toEqual(
    expect.arrayContaining([deep, valid]),
  );
});

test.each([
  ["typed description", 66_000, 0, 1],
  ["combined evidence", 60_000, 80_000, 0],
] as const)(
  "a representative that fits the Cloud %s limit retains every raw trace",
  (_, size, padding, singletonExclusions) => {
    const input = opengrepJson();
    const valid = input.results[0]!;
    Object.assign(valid.extra.metadata, { padding: "x".repeat(padding) });
    const trace = structuredClone(valid);
    trace.extra.message = "A".repeat(size);
    expect(
      normalize({ ...input, results: [trace] }, options).excluded,
    ).toHaveLength(singletonExclusions);
    input.results.push(trace);
    const output = normalize(input, options);
    expect(output.excluded).toEqual([]);
    expect(output.findings).toHaveLength(1);
    expect(output.findings[0]!.evidence.description).toBe(valid.extra.message);
    expect(output.findings[0]!.evidence.source_data!["results"]).toEqual([
      trace,
      valid,
    ]);
    input.results.reverse();
    expect(normalize(input, options)).toEqual(output);
  },
);

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

test.each([
  "/tmp/example.ts",
  "C:\\repo\\example.ts",
  "C:file.ts",
  "./C:file.ts",
  "./D:/other/file.ts",
  ".\\D:\\other\\file.ts",
  ".\\C:file.ts",
  "./\\example.ts",
  "../example.ts",
])(
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

test("SAST rules retain custom product metadata and literal source lines", () => {
  const input = opengrepJson();
  Object.assign(input.results[0]!.extra.metadata, { product: "website" });
  input.results[0]!.extra.lines = "requires login";
  const output = normalize(input, options);
  expect(output.excluded).toEqual([]);
  expect(output.findings[0]!.evidence.details?.code?.snippet).toBe(
    "requires login",
  );
  expect(output.findings[0]!.evidence.source_data?.["results"]).toEqual(
    input.results,
  );
  Object.assign(input.results[0]!.extra.metadata, { product: "secrets" });
  expect(normalize(input, options).excluded[0]?.reason).toContain("SAST");

  Object.assign(input.results[0]!.extra, { metadata: ["audit"], lines: "  " });
  const rule = normalize(input, options);
  expect(rule.excluded).toEqual([]);
  expect(rule.findings[0]!.evidence.details?.code?.snippet).toBe("  ");
  expect(rule.findings[0]!.evidence.source_data?.["results"]).toEqual(
    input.results,
  );
});

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
  for (const errors of [undefined, null]) {
    expect(() =>
      normalize({ version: "1.32.0", results: [], errors }, options),
    ).toThrow("OpenGrep errors must be an array");
  }
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

test("run metadata rejects integer tokens beyond JavaScript precision", async () => {
  const directory = await mkdtemp(join(tmpdir(), "opengrep-report-"));
  try {
    const path = join(directory, "report.json");
    await writeFile(
      path,
      '{"version":"1.32.0","results":[],"errors":[],"ruleMetadata":{"id":9007199254740993}}',
    );
    await expect(readOpenGrepFindings(path, options)).rejects.toThrow(
      "safe integer range",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
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
