import { expect, mock, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { main } from "../src/cli.js";
import {
  type NormalizedExternalPublicationOptions,
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
} from "../src/external-findings-publish.js";
import { dependencies as cliDependencies } from "./cli-fixtures.js";
import { localReportFixture } from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";

const source = {
  provider: "grype",
  sourceKey: "example/project/main",
} as const;

const exampleReport = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "examples",
  "normalized-import",
  "grype-report.json",
);

async function report() {
  return JSON.parse(await readFile(exampleReport, "utf8"));
}

test("the CLI previews the saved report without a repository or credentials", async () => {
  await using fixture = await localReportFixture("grype-report.json", source);
  await fixture.writeJson(await report());
  const cli = createCliTest(main);
  const code = await cli.runCli(
    [
      "publish",
      "findings",
      fixture.file,
      "--provider=grype",
      "--to=local",
      `--repository=${fixture.repository}`,
      `--source-key=${source.sourceKey}`,
      "--dry-run",
      "--format=json",
    ],
    cliDependencies({ environment: fixture.environment }),
  );
  expect(code, cli.stderr.text() || cli.stdout.text()).toBe(0);
  const preview = JSON.parse(cli.stdout.text());
  expect(preview.dryRun).toBe(true);
  expect(preview.source).toEqual({
    provider: "grype",
    source_key: source.sourceKey,
  });
  expect(preview.findings).toHaveLength(2);
  expect(preview.findings[0].evidence).toMatchObject({
    severity: "high",
    advisory_ids: ["CVE-2099-0001", "GHSA-2345-6789-cfgh"],
    packages: [{ ecosystem: "npm", manifest_path: "package-lock.json" }],
  });
});

test("previews, imports, and leaves a second import unchanged", async () => {
  await using fixture = await localReportFixture("grype-report.json", source);
  await fixture.writeJson(await report());
  const prepared = await fixture.prepare();
  expect(prepared.preview.excluded).toEqual([]);
  expect(prepared.preview.findings).toHaveLength(2);
  expect(prepared.matchesRepositoryRemote).toBe(false);
  expect(await fixture.read()).toEqual([]);
  expect((await prepared.import()).counts).toEqual({
    created: 2,
    updated: 0,
    unchanged: 0,
  });
  const stored = await fixture.read();
  expect(stored).toHaveLength(2);
  expect(stored.every((finding) => finding.provider === "grype")).toBe(true);
  expect(stored.every((finding) => finding.version === 1)).toBe(true);
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 2,
  });
  expect(await fixture.read()).toEqual(stored);
});

test("a changed severity updates the same occurrence", async () => {
  await using fixture = await localReportFixture("grype-report.json", source);
  await fixture.writeJson(await report());
  await (await fixture.prepare()).import();
  const raised = await report();
  raised.matches[0].vulnerability.severity = "Low";
  await fixture.writeJson(raised);
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 1,
  });
  const byAdvisory = (id: string) =>
    fixture
      .read()
      .then((rows) =>
        rows.find((finding) => finding.evidence.advisory_ids?.includes(id))!,
      );
  const updated = await byAdvisory("CVE-2099-0001");
  expect(updated.version).toBe(2);
  expect(updated.evidence.severity).toBe("low");
  expect((await byAdvisory("CVE-2099-0002")).version).toBe(1);
});

test("the reader rejects a source repository URL grype cannot corroborate", async () => {
  await using fixture = await localReportFixture("grype-report.json", source);
  await fixture.writeJson(await report());
  await expect(
    fixture.prepare({
      sourceRepositoryUrl: "https://github.com/example/project",
    }),
  ).rejects.toThrow(/source repository/i);
});

test("Cloud rejects grype findings before file access or credential lookup", async () => {
  await using fixture = await localReportFixture("grype-report.json", source);
  const unexpected = mock(async () => {
    throw new Error("Unexpected Cloud call");
  });
  const deps = {
    environment: fixture.environment,
    fetch: unexpected,
    credentials: unexpected,
  };
  const options = { ...source, repository: fixture.repository };
  const cloudOptions =
    options as unknown as NormalizedExternalPublicationOptions;
  await expect(
    prepareExternalPublication(fixture.file, cloudOptions, deps),
  ).rejects.toThrow(/local/i);
  await expect(
    prepareNormalizedExternalPublication(
      { read: 0, findings: [], excluded: [] },
      cloudOptions,
      deps,
    ),
  ).rejects.toThrow(/local/i);
  expect(unexpected).not.toHaveBeenCalled();
});
