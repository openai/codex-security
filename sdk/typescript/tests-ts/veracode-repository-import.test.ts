import { expect, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  veracodePolicyPage,
  veracodePolicyRow,
} from "./support/veracode-import-fixtures.js";

test("replaying a Veracode policy flaw tracks evidence without assessing another build or repository", async () => {
  const url = "https://github.com/example/project";
  const fixture = await localFindingsFixture({ remote: url });
  try {
    const path = join(fixture.root, "veracode.json.gz");
    const options = {
      provider: "veracode" as const,
      repository: fixture.repository,
      sourceRepositoryUrl: url,
      sourceKey: "veracode/example/static",
    };
    const dependencies = { environment: fixture.environment };
    const prepare = async (rows: ReturnType<typeof veracodePolicyRow>[]) => {
      await writeFile(path, gzipSync(JSON.stringify(veracodePolicyPage(rows))));
      return prepareLocalExternalImport(path, options, dependencies);
    };
    const row = veracodePolicyRow(1);
    const first = await prepare([row, veracodePolicyRow(2)]);
    expect((await first.import()).counts.created).toBe(2);
    expect((await (await prepare([row])).import()).counts.unchanged).toBe(1);
    expect(
      (
        await (
          await prepare([
            {
              ...row,
              build_id: 13,
              finding_status: { ...row.finding_status, status: "CLOSED" },
            },
          ])
        ).import()
      ).counts.updated,
    ).toBe(1);
    expect((await (await prepare([])).import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 0,
    });
    const records = await listLocalExternalFindings(options, dependencies);
    expect(records.map(({ version }) => version).sort()).toEqual([1, 2]);
    expect(
      records.every(({ assessment }) => assessment.state === "not_assessed"),
    ).toBe(true);
    await expect(
      prepareLocalExternalImport(
        path,
        { ...options, sourceRepositoryUrl: "https://github.com/example/other" },
        dependencies,
      ),
    ).rejects.toThrow(/remote|repository/i);
    const mixed = structuredClone(first.preview);
    const typed = mixed.findings[1]!;
    typed.source_finding_id = "sdk-id";
    delete typed.evidence.source_data;
    typed.evidence.details!.repository!.url =
      "git@github.com:example/mirror.git";
    const prepareMixed = () =>
      prepareNormalizedLocalImport(mixed, options, dependencies);
    await expect(prepareMixed()).rejects.toThrow(/configured remote/);
    fixture.git("remote", "add", "mirror", "https://github.com/example/mirror");
    expect((await prepareMixed()).preview.findings).toHaveLength(2);
    const wrong = structuredClone(first.preview);
    wrong.findings[0]!.evidence.details!.repository!.url =
      "https://github.com/example/other";
    await expect(
      prepareNormalizedLocalImport(wrong, options, dependencies),
    ).rejects.toThrow(/retained scanner repository/i);
    const relabeled = structuredClone(first.preview);
    relabeled.findings.splice(1);
    relabeled.findings[0]!.source_finding_id =
      first.preview.findings[1]!.source_finding_id;
    await expect(
      prepareNormalizedLocalImport(relabeled, options, dependencies),
    ).rejects.toThrow(/source finding ID|occurrence/i);
    const otherApplication = JSON.stringify(
      veracodePolicyPage([row]),
    ).replaceAll(row.context_guid, "00000000-0000-4000-8000-000000000002");
    await writeFile(path, gzipSync(otherApplication));
    const other = await prepareLocalExternalImport(path, options, dependencies);
    const findings = [...first.preview.findings, ...other.preview.findings];
    await expect(
      prepareNormalizedLocalImport(
        { ...first.preview, findings, read: findings.length },
        options,
        dependencies,
      ),
    ).rejects.toThrow(/same application/i);
    fixture.git(
      "remote",
      "set-url",
      "origin",
      "ssh://git@github.com/example/project?other",
    );
    await expect(prepareMixed()).rejects.toThrow(/configured remote/);
  } finally {
    await fixture.dispose();
  }
});

test("a mixed SDK batch recognizes the repository retained by each Veracode row", async () => {
  await using fixture = await localFindingsFixture();
  const projected = "https://github.com/example/project";
  const typed = "https://github.com/example/other";
  const findings = (
    [
      [`blackduck-bom:${"a".repeat(64)}`, projected],
      ["sdk-id", typed],
    ] as const
  ).map(([source_finding_id, sourceRepositoryUrl]) => ({
    source_finding_id,
    evidence: {
      title: "Example",
      severity: "unknown" as const,
      source_data: { sourceRepositoryUrl },
    },
  }));
  const prepare = (url: string) =>
    prepareNormalizedLocalImport(
      { findings, read: 2, excluded: [] },
      {
        provider: "veracode",
        sourceKey: "example",
        repository: fixture.repository,
      },
      {
        environment: fixture.environment,
        sourceRepositories: [{ url: projected }, { url }],
      },
    );
  expect((await prepare(typed)).preview.findings).toHaveLength(2);
  await expect(prepare("https://github.com/example/third")).rejects.toThrow(
    /Reader repository does not match/,
  );
});
