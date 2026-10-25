import { access, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { expect, test } from "bun:test";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { listLocalExternalFindings } from "../src/external-findings-local.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

const repositoryUrl = "https://github.com/example/project";
const row: Record<string, string> = {
  ID: "csv-occurrence-1",
  WizURL: "https://vendor.example.test/findings/csv-occurrence-1",
  Name: "CVE-2026-0001",
  DetailedName: "example-package",
  AssetID: "synthetic-repository-branch",
  CloudPlatform: "GitHub",
  CloudProviderURL: `${repositoryUrl}/tree/main`,
  Severity: "HIGH",
  Description: 'Synthetic "description", with a comma.\r\nAnother line.',
  LocationPath: "/package-lock.json",
  Version: "1.0.0",
  FixedVersion: "2.0.0",
};

function csvReport(source: Record<string, string>): string {
  const quote = (value: string) => '"' + value.replaceAll('"', '""') + '"';
  return [Object.keys(source), Object.values(source)]
    .map((cells) => cells.map(quote).join(","))
    .join("\r\n");
}

test.each(["CSV", "CSV gzip", "normalized JSONL", "normalized JSONL gzip"])(
  "Wiz %s matches GitHub Enterprise repository names without changing evidence",
  async (format) => {
    const fixture = await localFindingsFixture({
      remote: "git@git.example.test:example/project.git",
    });
    try {
      const file = join(fixture.root, "wiz-report");
      const options = {
        repository: fixture.repository,
        provider: "wiz" as const,
        sourceKey: "example-project:main",
      };
      const dependencies = { environment: fixture.environment };
      const database = join(fixture.stateDirectory, "workbench.sqlite3");
      const writeReport = async (source: Record<string, string>) => {
        let contents = csvReport(source);
        if (format.startsWith("normalized")) {
          await writeFile(file, contents);
          contents = (await readVendorFindings(file)).findings
            .map((finding) => JSON.stringify(finding))
            .join("\n");
        }
        await writeFile(
          file,
          format.endsWith("gzip") ? gzipSync(contents) : contents,
        );
      };

      for (const url of [
        "https://Git.Example.test/Example/Other/tree/main",
        "https://other.example.test/Example/Project/tree/main",
      ]) {
        await writeReport({ ...row, CloudProviderURL: url });
        await expect(
          prepareLocalExternalImport(file, options, dependencies),
        ).rejects.toThrow("does not match");
        await expect(access(database)).rejects.toThrow();
      }

      const source = {
        ...row,
        CloudProviderURL:
          "https://Git.Example.test/Example/Project/tree/feature/imports",
      };
      await writeReport(source);
      const parsed = await readVendorFindings(file);
      const prepared = await prepareLocalExternalImport(
        file,
        options,
        dependencies,
      );
      expect(prepared.preview.findings).toEqual(parsed.findings);
      expect((await prepared.import()).counts).toEqual({
        created: 1,
        updated: 0,
        unchanged: 0,
      });
      const stored = await listLocalExternalFindings(options, dependencies);
      expect(stored).toHaveLength(1);
      expect(stored[0]!.evidence).toEqual(parsed.findings[0]!.evidence);
      expect(stored[0]!.evidence.source_data).toEqual({
        format: "wiz-code-vulnerability-csv",
        row: source,
      });

      const before = await readFile(database);
      await writeReport({
        ...source,
        CloudProviderURL: "https://Git.Example.test/Example/Other/tree/main",
      });
      await expect(
        prepareLocalExternalImport(file, options, dependencies),
      ).rejects.toThrow("does not match");
      expect(await readFile(database)).toEqual(before);
      expect(await listLocalExternalFindings(options, dependencies)).toEqual(
        stored,
      );
    } finally {
      await fixture.dispose();
    }
  },
);

test("Wiz CSV imports into SQLite and updates the same source finding", async () => {
  const fixture = await localFindingsFixture({ remote: repositoryUrl });
  try {
    const file = join(fixture.root, "wiz.csv");
    const options = {
      repository: fixture.repository,
      provider: "wiz" as const,
      sourceKey: "example-project:main",
    };
    const dependencies = { environment: fixture.environment };
    await writeFile(file, csvReport(row));
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect(prepared.preview.excluded).toEqual([]);
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const [stored] = await listLocalExternalFindings(options, dependencies);
    expect(stored).toMatchObject({
      provider: "wiz",
      sourceKey: options.sourceKey,
      sourceFindingId: row["ID"],
      evidence: prepared.preview.findings[0]!.evidence,
      assessment: { state: "not_assessed" },
      version: 1,
    });
    expect(stored!.evidence).toMatchObject({
      locations: [{ path: "package-lock.json", line: null }],
      source_data: { format: "wiz-code-vulnerability-csv", row },
      branch: null,
      code_revision: null,
    });
    expect(stored!.evidence).not.toHaveProperty("confidence");

    const repeated = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect((await repeated.import()).counts).toEqual({
      created: 0,
      updated: 0,
      unchanged: 1,
    });
    expect(await listLocalExternalFindings(options, dependencies)).toEqual([
      stored!,
    ]);

    const updatedRow = { ...row, Description: "Updated scanner evidence" };
    await writeFile(file, csvReport(updatedRow));
    const changed = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect((await changed.import()).counts).toEqual({
      created: 0,
      updated: 1,
      unchanged: 0,
    });
    const records = await listLocalExternalFindings(options, dependencies);
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      id: stored!.id,
      sourceFindingId: stored!.sourceFindingId,
      evidence: changed.preview.findings[0]!.evidence,
      assessment: { state: "not_assessed" },
      version: 2,
      createdAt: stored!.createdAt,
    });
    expect(records[0]!.evidence.source_data).toEqual({
      format: "wiz-code-vulnerability-csv",
      row: updatedRow,
    });
  } finally {
    await fixture.dispose();
  }
});

test("Wiz CSV retains a package advisory without fabricated locations, fixes or confidence", async () => {
  const fixture = await localFindingsFixture({ remote: repositoryUrl });
  try {
    const file = join(fixture.root, "wiz.csv");
    const sparse = {
      ...row,
      Severity: "UNKNOWN",
      Description: "",
      LocationPath: "",
      Version: "",
      FixedVersion: "",
    };
    await writeFile(file, csvReport(sparse));
    const options = {
      repository: fixture.repository,
      provider: "wiz" as const,
      sourceKey: "example-project:main",
    };
    const dependencies = { environment: fixture.environment };
    const prepared = await prepareLocalExternalImport(
      file,
      options,
      dependencies,
    );
    expect((await prepared.import()).counts.created).toBe(1);
    const [stored] = await listLocalExternalFindings(options, dependencies);
    expect(stored!.evidence).toEqual(prepared.preview.findings[0]!.evidence);
    expect(stored!.evidence).toMatchObject({
      description: null,
      severity: "unknown",
      locations: [],
      packages: [
        {
          name: "example-package",
          installed_version: null,
          manifest_path: null,
          fixed_versions: [],
        },
      ],
      source_data: { format: "wiz-code-vulnerability-csv", row: sparse },
    });
    expect(stored!.evidence).not.toHaveProperty("confidence");
    expect(stored!.evidence).not.toHaveProperty("remediation");
    expect(stored!.assessment).toEqual({ state: "not_assessed" });
  } finally {
    await fixture.dispose();
  }
});
