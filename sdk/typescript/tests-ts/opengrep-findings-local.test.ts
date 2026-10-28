import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  opengrepJson,
  opengrepTraceJson,
} from "./support/opengrep-import-fixtures.js";

const repositoryUrl = "https://github.com/example/project";

test("OpenGrep grouped traces survive SQLite import, replay, and evidence updates", async () => {
  const fixture = await localFindingsFixture({ remote: repositoryUrl });
  try {
    const input = opengrepTraceJson();
    // Grouped observations can exceed Cloud's per-finding source data limit.
    for (const result of input.results)
      result.extra.metavars.$VALUE.abstract_content = "x".repeat(140_000);
    const { results, ...report } = input;
    const file = join(fixture.root, "opengrep.json");
    await writeFile(file, JSON.stringify(input));
    const options = {
      repository: fixture.repository,
      provider: "opengrep" as const,
      sourceKey: "example-project:main:opengrep",
      sourceRepositoryUrl: repositoryUrl,
    };
    const dependencies = { environment: fixture.environment };
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview).toMatchObject({
      read: 2,
      excluded: [],
      report,
      source: { provider: "semgrep", source_key: options.sourceKey },
    });
    expect(prepared.preview.findings).toHaveLength(1);
    const imported = await prepared.import();
    expect(imported.counts).toEqual({ created: 1, updated: 0, unchanged: 0 });
    expect(imported.report).toEqual(report);

    const [stored] = await listLocalExternalFindings(options, dependencies);
    expect(stored).toMatchObject({
      provider: "semgrep",
      sourceKey: options.sourceKey,
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
    expect(
      (
        await (
          await prepareLocalExternalImport(file, options, dependencies)
        ).import()
      ).counts,
    ).toEqual({ created: 0, updated: 0, unchanged: 1 });
    expect(await listLocalExternalFindings(options, dependencies)).toEqual([
      stored!,
    ]);

    input.results[0]!.extra.message = "Updated scanner evidence";
    input.results[0]!.extra.fingerprint = "new-scanner-fingerprint_9";
    await writeFile(file, JSON.stringify(input));
    const updated = await (
      await prepareLocalExternalImport(file, options, dependencies)
    ).import();
    expect(updated.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
    expect(updated.report).toEqual(report);
    const records = await listLocalExternalFindings(options, dependencies);
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
  } finally {
    await fixture.dispose();
  }
});

test("empty OpenGrep local imports retain scanner diagnostics without creating findings", async () => {
  const fixture = await localFindingsFixture({ remote: repositoryUrl });
  try {
    const input = opengrepJson();
    input.results = [];
    const { results: _results, ...report } = input;
    const file = join(fixture.root, "opengrep.json");
    await writeFile(file, JSON.stringify(input));
    const options = {
      repository: fixture.repository,
      provider: "opengrep" as const,
      sourceKey: "example-project:main:opengrep",
      sourceRepositoryUrl: "https://github.com/Example/PROJECT",
    };
    const dependencies = { environment: fixture.environment };
    await expect(
      prepareLocalExternalImport(
        file,
        { ...options, sourceRepositoryUrl: "https://github.com/example/other" },
        dependencies,
      ),
    ).rejects.toThrow("does not match");
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
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
    expect(await listLocalExternalFindings(options, dependencies)).toEqual([]);
  } finally {
    await fixture.dispose();
  }
});
