import { expect, test } from "bun:test";
import { localReportFixture } from "./external-findings-local-helpers.js";
import {
  opengrepJson,
  opengrepTraceJson,
} from "./support/opengrep-import-fixtures.js";

const repositoryUrl = "https://github.com/example/project";

test("OpenGrep grouped traces survive SQLite import, replay, and evidence updates", async () => {
  await using fixture = await localReportFixture(
    "opengrep.json",
    {
      provider: "opengrep",
      sourceKey: "example-project:main:opengrep",
      sourceRepositoryUrl: repositoryUrl,
    },
    { remote: repositoryUrl },
  );
  const input = opengrepTraceJson();
  // Grouped observations can exceed Cloud's per-finding source data limit.
  for (const result of input.results)
    result.extra.metavars.$VALUE.abstract_content = "x".repeat(140_000);
  const { results, ...report } = input;
  await fixture.writeJson(input);
  const prepared = await fixture.prepare();
  expect(prepared.preview).toMatchObject({
    read: 2,
    excluded: [],
    report,
    source: { provider: "semgrep", source_key: fixture.sourceKey },
  });
  expect(prepared.preview.findings).toHaveLength(1);
  const imported = await prepared.import();
  expect(imported.counts).toEqual({ created: 1, updated: 0, unchanged: 0 });
  expect(imported.report).toEqual(report);

  const [stored] = await fixture.read();
  expect(stored).toMatchObject({
    provider: "semgrep",
    sourceKey: fixture.sourceKey,
    sourceFindingId: prepared.preview.findings[0]!.source_finding_id,
    assessment: { state: "not_assessed" },
    version: 1,
    evidence: {
      locations: [{ path: "src/example.ts", line: 3 }],
      details: { kind: "sast", scanner_origin: "OpenGrep" },
      source_data: { scan_error_count: input.errors.length },
    },
  });
  expect(stored!.evidence.source_data!["results"]).toHaveLength(2);
  expect(stored!.evidence.source_data!["results"]).toEqual(
    expect.arrayContaining(results),
  );
  expect(stored!.evidence).not.toHaveProperty("confidence");
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
  expect(await fixture.read()).toEqual([stored!]);

  input.results[0]!.extra.message = "Updated scanner evidence";
  input.results[0]!.extra.fingerprint = "new-scanner-fingerprint_9";
  await fixture.writeJson(input);
  const updated = await (await fixture.prepare()).import();
  expect(updated.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
  expect(updated.report).toEqual(report);
  const records = await fixture.read();
  expect(records).toHaveLength(1);
  expect(records[0]).toMatchObject({
    id: stored!.id,
    sourceFindingId: stored!.sourceFindingId,
    createdAt: stored!.createdAt,
    version: 2,
    assessment: { state: "not_assessed" },
    evidence: {
      details: { scanner_origin: "OpenGrep" },
    },
  });
  expect(records[0]!.evidence.source_data!["results"]).toHaveLength(2);
  expect(records[0]!.evidence.source_data!["results"]).toEqual(
    expect.arrayContaining(input.results),
  );
});

test("empty OpenGrep local imports retain scanner diagnostics without creating findings", async () => {
  await using fixture = await localReportFixture(
    "opengrep.json",
    {
      provider: "opengrep",
      sourceKey: "example-project:main:opengrep",
      sourceRepositoryUrl: "https://github.com/Example/PROJECT",
    },
    { remote: repositoryUrl },
  );
  const input = opengrepJson();
  input.results = [];
  const { results: _results, ...report } = input;
  await fixture.writeJson(input);
  await expect(
    fixture.prepare({
      sourceRepositoryUrl: "https://github.com/example/other",
    }),
  ).rejects.toThrow("does not match");
  const prepared = await fixture.prepare();
  expect(prepared.preview).toMatchObject({
    read: 0,
    findings: [],
    excluded: [],
    report,
  });
  expect(await prepared.import()).toMatchObject({
    read: 0,
    ready: 0,
    findings: [],
    report,
    counts: { created: 0, updated: 0, unchanged: 0 },
  });
  expect(await fixture.read()).toEqual([]);
});
