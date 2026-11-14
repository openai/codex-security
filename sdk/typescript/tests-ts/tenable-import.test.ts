import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  type NormalizedExternalPublicationOptions,
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
} from "../src/external-findings-publish.js";
import { readTenableFindings } from "../src/tenable-findings.js";
import { dependencies as cliDependencies } from "./cli-fixtures.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";

const repositoryUrl = "https://github.com/example/repo";
const asset = {
  asset_id: "10000000-0000-4000-8000-000000000001",
  asset_class: "CODE_REPOSITORY",
  asset_name: "example/repo",
};
const row = {
  asset_id: asset.asset_id,
  finding_id: "00017",
  finding_name: "Example finding",
  severity: "High",
  state: "ACTIVE",
};
const report = {
  format: "tenable-one-code-repository/v1",
  asset,
  repository_url: repositoryUrl,
  findings: [{ ...row, code_file_path: "src/app.ts", code_line_number: "7" }],
};
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
  expect(findings[1]!.evidence).toMatchObject({
    severity: "unknown",
    locations: [{ path: "src/app.ts", line: null }],
  });
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

test("Cloud rejects local Tenable findings before file access or credential lookup", async () => {
  await using fixture = await checkout();
  const options = { ...source, repository: fixture.repository };
  const unexpected = mock(async () => {
    throw new Error("Unexpected Cloud call");
  });
  const deps = {
    environment: fixture.environment,
    fetch: unexpected,
    credentials: unexpected,
  };
  // JavaScript callers may supply a local provider despite the SDK's Cloud types.
  const cloudOptions =
    options as unknown as NormalizedExternalPublicationOptions;
  const empty = { read: 0, findings: [], excluded: [] };
  await expect(
    prepareExternalPublication(fixture.file, cloudOptions, deps),
  ).rejects.toThrow(/local/i);
  await expect(
    prepareNormalizedExternalPublication(empty, cloudOptions, deps),
  ).rejects.toThrow(/local/i);
  await fixture.writeJson(report);
  const { preview } = await fixture.prepare();
  const relabeled = { ...options, provider: "wiz" as const };
  await expect(
    prepareNormalizedExternalPublication(preview, relabeled, deps),
  ).rejects.toThrow(/local/i);
  expect(unexpected).not.toHaveBeenCalled();
});
