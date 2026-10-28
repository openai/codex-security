import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  listLocalExternalFindings,
  normalizeSnykJson,
  prepareLocalExternalImport,
} from "../src/index.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { snykJson, snykPluginExport } from "./support/snyk-import-fixtures.js";

test("plugin imports version collection evidence without changing occurrence identities", async () => {
  const bundle = snykPluginExport();
  const first = bundle.findings[0]!;
  for (const advisory of ["SNYK-EXAMPLE-2", "SNYK-EXAMPLE-3"]) {
    const other = structuredClone(first);
    other.id.value = other.id.value.replace(other.rule.id, advisory);
    other.rule.id = advisory;
    other.nativeRecord.id = advisory;
    bundle.findings.push(other);
  }
  const scan = bundle.collection.scans[0]!;
  scan.issueCount = 3;
  const fixture = await localFindingsFixture({
    remote: bundle.collection.target.repository,
  });
  try {
    const path = join(fixture.root, "snyk.json");
    const options = {
      repository: fixture.repository,
      provider: "snyk" as const,
      sourceKey: "example/plugin-sca",
    };
    const dependencies = { environment: fixture.environment };
    const importBundle = async () => {
      await writeFile(path, JSON.stringify(bundle));
      const prepared = await prepareLocalExternalImport(
        path,
        options,
        dependencies,
      );
      const result = await prepared.import();
      const { findings, ...context } = bundle;
      expect(result.excluded).toEqual([]);
      expect(result.findings.map((row) => row.evidence.source_data)).toEqual(
        findings.map((finding) => ({ ...context, finding })),
      );
      return result;
    };

    const created = await importBundle();
    expect(created.counts).toEqual({ created: 3, updated: 0, unchanged: 0 });

    bundle.findings.pop();
    first.nativeRecord.unknownField = "Revised vendor detail";
    expect((await importBundle()).counts).toEqual({
      created: 0,
      updated: 1,
      unchanged: 1,
    });

    scan.issueCount = 2;
    expect((await importBundle()).counts).toEqual({
      created: 0,
      updated: 2,
      unchanged: 0,
    });

    const stored = await listLocalExternalFindings(options, dependencies);
    expect(
      Object.fromEntries(
        stored.map((row) => [row.sourceFindingId, row.version]),
      ),
    ).toEqual({
      [created.findings[0]!.sourceFindingId]: 3,
      [created.findings[1]!.sourceFindingId]: 2,
      [created.findings[2]!.sourceFindingId]: 1,
    });
  } finally {
    await fixture.dispose();
  }
});

test("native JSON retains one advisory count across distinct dependency paths", () => {
  const { packageManager, targetFile, vulnerabilities } = snykJson();
  const retained = vulnerabilities[0]!;
  const retainedPaths = [
    retained,
    {
      ...retained,
      from: ["example@1.0.0", "transitive@1.0.0", "@example/package@1.0.0"],
    },
  ];
  const project = { ok: false, packageManager, targetFile };
  const before = normalizeSnykJson({
    ...project,
    vulnerabilities: [...retainedPaths, { ...retained, id: "SNYK-EXAMPLE-2" }],
    uniqueCount: 2,
  });
  const after = normalizeSnykJson({
    ...project,
    vulnerabilities: retainedPaths,
    uniqueCount: 1,
  });
  expect(before.findings).toHaveLength(3);
  const retainedIds = after.findings.map(
    (finding) => finding.source_finding_id,
  );
  expect(new Set(retainedIds).size).toBe(2);
  expect(retainedIds).toEqual(
    before.findings.slice(0, 2).map((finding) => finding.source_finding_id),
  );
  for (const [selection, uniqueCount] of [
    [before, 2],
    [after, 1],
  ] as const) {
    expect(
      selection.findings
        .slice(0, 2)
        .map((finding) => finding.evidence.source_data),
    ).toEqual(
      retainedPaths.map((vulnerability) => ({
        project: { ...project, uniqueCount },
        vulnerability,
      })),
    );
  }
});
