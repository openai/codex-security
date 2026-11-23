import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { readTenableFindings } from "../src/tenable-findings.js";
import { dependencies as cliDependencies } from "./cli-fixtures.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";
import {
  tenableFinding as row,
  tenableReport as report,
} from "./support/tenable-import-fixtures.js";

const repositoryUrl = report.repository_url;
const asset = report.asset;
const source = {
  provider: "tenable",
  sourceKey: "example/tenable/code-repository",
  sourceRepositoryUrl: repositoryUrl,
} as const;

function checkout() {
  return localReportFixture("tenable.json", source, {
    remote: repositoryUrl + ".git",
  });
}

test("the reader preserves vendor state and optional severity and locations", async () => {
  await using fixture = await checkout();
  await fixture.writeJson({
    ...report,
    findings: [
      {
        ...row,
        severity: "INFO",
        state: "FIXED",
        description: "Outdated dependency",
        solution: "Update the dependency",
      },
      {
        ...row,
        finding_id: "00018",
        severity: "unrated",
        description: "  ",
        code_file_path: "src/app.ts",
      },
    ],
  });
  const { findings } = await readTenableFindings(fixture.file, repositoryUrl);
  expect(findings[0]!.evidence).toMatchObject({
    severity: "informational",
    description: "Outdated dependency",
    locations: [],
    source_data: {
      finding: { state: "FIXED", solution: "Update the dependency" },
    },
  });
  const cloud = await readTenableFindings(fixture.file, repositoryUrl, "cloud");
  expect(cloud.excluded).toEqual([]);
  expect(cloud.findings).toEqual(findings);
  expect(findings[1]!.evidence.description).toBeNull();
  expect(findings[1]!.evidence).toMatchObject({
    source_data: { finding: { description: "  " } },
    severity: "unknown",
    locations: [{ path: "src/app.ts", line: null }],
  });
});

test("Cloud excludes an oversized Tenable row and retains the other findings", async () => {
  await using fixture = await checkout();
  await fixture.writeJson({
    ...report,
    findings: [
      { ...row, description: "x".repeat(65_537) },
      { ...row, finding_id: "00018" },
    ],
  });
  const result = await readTenableFindings(
    fixture.file,
    repositoryUrl,
    "cloud",
  );
  expect(result.read).toBe(2);
  expect(result.findings.map((item) => item.source_finding_id)).toEqual([
    "00018",
  ]);
  expect(result.excluded).toMatchObject([
    { position: 1, source_finding_id: row.finding_id },
  ]);
});

test("the reader rejects ambiguous assets, findings and locations", async () => {
  await using fixture = await checkout();
  for (const override of [
    { asset: { ...asset, asset_class: "DEVICE" } },
    { findings: [row, row] },
    {
      findings: [{ ...row, asset_id: "20000000-0000-4000-8000-000000000002" }],
    },
    { findings: [{ ...row, code_file_path: "../unrelated" }] },
    {
      findings: [
        { ...report.findings[0], code_line_number: "9007199254740993" },
      ],
    },
  ]) {
    await fixture.writeJson({ ...report, ...override });
    await expect(
      readTenableFindings(fixture.file, repositoryUrl),
    ).rejects.toThrow();
  }
});

test("the CLI preview can be saved, replayed and updated with its original identity", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(report);
  const cli = createCliTest(main);
  const code = await cli.runCli(
    [
      "publish",
      "findings",
      fixture.file,
      "--provider=tenable",
      "--to=local",
      `--repository=${fixture.repository}`,
      `--source-repository-url=${repositoryUrl}`,
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
    provider: "tenable",
    source_key: source.sourceKey,
  });
  const saved = await createAndReplayFinding(fixture, preview);
  expect(saved.provider).toBe("tenable");
  expect(saved.sourceFindingId).toBe(row.finding_id);
  expect(saved.evidence).toMatchObject({
    title: row.finding_name,
    severity: "high",
    locations: [{ path: "src/app.ts", line: 7 }],
  });
  await fixture.writeJson({
    ...report,
    findings: [{ ...report.findings[0], finding_name: "Revised finding" }],
  });
  expect((await updateStoredFinding(fixture, saved)).evidence.title).toBe(
    "Revised finding",
  );
});

test("file and normalized imports verify repository and finding identity, even for empty selections", async () => {
  await using fixture = await checkout();
  await fixture.writeJson(report);
  await expect(
    fixture.prepare({ sourceRepositoryUrl: undefined }),
  ).rejects.toThrow(/repository/i);
  const otherUrl = "https://github.com/example/other";
  const { preview } = await fixture.prepare();
  const wrongReport = structuredClone(preview);
  wrongReport.report!["repositoryUrl"] = otherUrl;
  await expect(fixture.prepareNormalized(wrongReport)).rejects.toThrow(
    /repository/i,
  );
  const wrongRow = structuredClone(preview);
  wrongRow.findings[0]!.evidence.source_data!["repository_url"] = otherUrl;
  await expect(fixture.prepareNormalized(wrongRow)).rejects.toThrow(
    /repository/i,
  );
  const wrongId = structuredClone(preview);
  wrongId.findings[0]!.source_finding_id = "17";
  await expect(fixture.prepareNormalized(wrongId)).rejects.toThrow(
    /finding ID|identity/i,
  );
  fixture.git("remote", "set-url", "origin", otherUrl);
  for (const findings of [report.findings, []]) {
    await fixture.writeJson({ ...report, findings });
    await expect(fixture.prepare()).rejects.toThrow(/remote|checkout/i);
  }
  fixture.git("remote", "set-url", "origin", repositoryUrl);
  const runWorkbench = mock(async () => {
    throw new Error("Unexpected workbench call");
  });
  const empty = await prepareLocalExternalImport(
    fixture.file,
    { ...source, repository: fixture.repository },
    { environment: fixture.environment, runWorkbench },
  );
  expect((await empty.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  expect(runWorkbench).not.toHaveBeenCalled();
});
