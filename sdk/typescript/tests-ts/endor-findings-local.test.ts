import { expect, test } from "bun:test";
import { localReportFixture } from "./external-findings-local-helpers.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";

test("switching Endor JSON and SARIF replaces the same local source snapshot without merging evidence", async () => {
  await using fixture = await localReportFixture("endor.json", {
    provider: "endor",
    sourceKey: "endor-project-example",
  });
  const finding = endorFinding();
  const native = {
    ...finding,
    spec: {
      ...finding.spec,
      source_code_version: { sha: "a".repeat(40) },
    },
  };
  const sarif = endorSarif();
  const importAndRead = async (input: unknown) => {
    await fixture.writeJson(input);
    const prepared = await fixture.prepare();
    const result = await prepared.import();
    const records = await fixture.read();
    expect(prepared.preview.excluded).toEqual([]);
    expect(records).toHaveLength(1);
    expect(records[0]!.evidence).toEqual(
      prepared.preview.findings[0]!.evidence,
    );
    expect(records[0]!.assessment).toEqual({ state: "not_assessed" });
    return { record: records[0]!, counts: result.counts };
  };

  const original = await importAndRead({ list: { objects: [native] } });
  expect(original.counts).toEqual({ created: 1, updated: 0, unchanged: 0 });
  expect(original.record).toMatchObject({
    repository: fixture.repository,
    provider: "endor",
    sourceKey: fixture.sourceKey,
    sourceFindingId: native.uuid,
    version: 1,
  });
  expect(original.record.evidence).toMatchObject({
    severity: "critical",
    code_revision: native.spec.source_code_version.sha,
    advisory_ids: ["CVE-2099-0001", "GHSA-2222-3333-4444"],
    source_data: native,
  });
  expect(original.record.evidence.packages).toHaveLength(2);
  expect(original.record.evidence.packages![0]).toMatchObject({
    name: "@example/package",
    installed_version: "1.0.0",
  });

  expect(await importAndRead(native)).toEqual({
    record: original.record,
    counts: { created: 0, updated: 0, unchanged: 1 },
  });
  const replaced = await importAndRead(sarif);
  expect(replaced.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
  expect(replaced.record).toMatchObject({
    id: original.record.id,
    sourceFindingId: native.uuid,
    sourceKey: fixture.sourceKey,
    createdAt: original.record.createdAt,
    version: 2,
  });
  expect(replaced.record.evidence.severity).toBe("unknown");
  expect(replaced.record.evidence.code_revision).toBeNull();
  expect(replaced.record.evidence.advisory_ids).toEqual([]);
  expect(replaced.record.evidence.packages).toEqual([]);
  expect(replaced.record.evidence.source_data).not.toHaveProperty("spec");
  expect(replaced.record.evidence.source_data).toMatchObject({
    result: sarif.runs[0]!.results[0],
    rule: sarif.runs[0]!.tool.driver.rules[0],
  });

  expect(await importAndRead(sarif)).toEqual({
    record: replaced.record,
    counts: { created: 0, updated: 0, unchanged: 1 },
  });
  const restored = await importAndRead(native);
  expect(restored.counts).toEqual({ created: 0, updated: 1, unchanged: 0 });
  expect(restored.record).toMatchObject({
    id: original.record.id,
    createdAt: original.record.createdAt,
    version: 3,
    evidence: original.record.evidence,
  });
  expect(restored.record.evidence.source_data).not.toHaveProperty("result");
});

test("sparse Endor findings remain unassessed without invented locations or remediation", async () => {
  await using fixture = await localReportFixture("endor.json", {
    provider: "endor",
    sourceKey: "endor-project-example",
  });
  const input = {
    uuid: "sparse-finding",
    meta: { name: "Synthetic sparse finding" },
    spec: { project_uuid: "project-example" },
  };
  await fixture.writeJson({ list: { objects: [input] } });
  const prepared = await fixture.prepare();
  expect(await fixture.read()).toEqual([]);
  expect((await prepared.import()).counts.created).toBe(1);
  const records = await fixture.read();
  expect(records).toHaveLength(1);
  expect(records[0]!.assessment).toEqual({ state: "not_assessed" });
  expect(records[0]!.evidence).toMatchObject({
    severity: "unknown",
    description: null,
    locations: [],
    packages: [],
    code_revision: null,
    source_data: input,
  });
  expect(records[0]!.evidence).not.toHaveProperty("confidence");
  expect(records[0]!.evidence).not.toHaveProperty("remediation");
});

test("Endor SARIF repository provenance cannot be imported into a different local checkout", async () => {
  await using fixture = await localReportFixture(
    "endor.json",
    { provider: "endor", sourceKey: "endor-project-example" },
    {
      remote: "https://github.com/example/other",
    },
  );
  const sarif = endorSarif();
  const input = {
    ...sarif,
    runs: sarif.runs.map((run) => ({
      ...run,
      versionControlProvenance: [
        { repositoryUri: "https://github.com/example/project" },
      ],
    })),
  };
  await fixture.writeJson(input);
  await expect(fixture.prepare()).rejects.toThrow(/repository/iu);
  expect(await fixture.read()).toEqual([]);
});
