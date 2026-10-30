import { access, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { expect, test } from "bun:test";
import { readVendorFindings } from "../src/wiz-findings.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";

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
    await using fixture = await localReportFixture(
      "wiz-report",
      { provider: "wiz", sourceKey: "example-project:main" },
      { remote: "git@git.example.test:example/project.git" },
    );
    const database = join(fixture.stateDirectory, "workbench.sqlite3");
    const writeReport = async (source: Record<string, string>) => {
      let contents = csvReport(source);
      if (format.startsWith("normalized")) {
        await writeFile(fixture.file, contents);
        contents = (await readVendorFindings(fixture.file)).findings
          .map((finding) => JSON.stringify(finding))
          .join("\n");
      }
      await writeFile(
        fixture.file,
        format.endsWith("gzip") ? gzipSync(contents) : contents,
      );
    };

    for (const url of [
      "https://Git.Example.test/Example/Other/tree/main",
      "https://other.example.test/Example/Project/tree/main",
    ]) {
      await writeReport({ ...row, CloudProviderURL: url });
      await expect(fixture.prepare()).rejects.toThrow("does not match");
      await expect(access(database)).rejects.toThrow();
    }

    const source = {
      ...row,
      CloudProviderURL:
        "https://Git.Example.test/Example/Project/tree/feature/imports",
    };
    await writeReport(source);
    const parsed = await readVendorFindings(fixture.file);
    const prepared = await fixture.prepare();
    expect(prepared.preview.findings).toEqual(parsed.findings);
    expect((await prepared.import()).counts).toEqual({
      created: 1,
      updated: 0,
      unchanged: 0,
    });
    const stored = await fixture.read();
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
    await expect(fixture.prepare()).rejects.toThrow("does not match");
    expect(await readFile(database)).toEqual(before);
    expect(await fixture.read()).toEqual(stored);
  },
);

test("Wiz CSV imports into SQLite and updates the same source finding", async () => {
  await using fixture = await localReportFixture(
    "wiz.csv",
    { provider: "wiz", sourceKey: "example-project:main" },
    { remote: repositoryUrl },
  );
  await writeFile(fixture.file, csvReport(row));
  const stored = await createAndReplayFinding(fixture);
  expect(stored).toMatchObject({ provider: "wiz", sourceFindingId: row["ID"] });
  expect(stored.evidence).toMatchObject({
    locations: [{ path: "package-lock.json", line: null }],
    source_data: { format: "wiz-code-vulnerability-csv", row },
    branch: null,
    code_revision: null,
  });
  const updatedRow = { ...row, Description: "Updated scanner evidence" };
  await writeFile(fixture.file, csvReport(updatedRow));
  const updated = await updateStoredFinding(fixture, stored);
  expect(updated.evidence.source_data).toEqual({
    format: "wiz-code-vulnerability-csv",
    row: updatedRow,
  });
});

test("Wiz CSV retains a package advisory without fabricated locations, fixes or confidence", async () => {
  await using fixture = await localReportFixture(
    "wiz.csv",
    { provider: "wiz", sourceKey: "example-project:main" },
    { remote: repositoryUrl },
  );
  const sparse = {
    ...row,
    Severity: "UNKNOWN",
    Description: "",
    LocationPath: "",
    Version: "",
    FixedVersion: "",
  };
  await writeFile(fixture.file, csvReport(sparse));
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts.created).toBe(1);
  const [stored] = await fixture.read();
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
});
