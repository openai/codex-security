import { expect, mock, test } from "bun:test";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { main } from "../src/cli.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
} from "../src/external-findings-local.js";
import {
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
} from "../src/external-findings-publish.js";
import { dependencies as cliDependencies } from "./cli-fixtures.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";
import { readTenableFindings } from "../src/tenable-findings.js";

const repositoryUrl = "https://github.com/example/repo";
const assetId = "10000000-0000-4000-8000-000000000001";

async function exampleReport(root: string, findingName = "Example finding") {
  const file = join(root, "tenable.json");
  await writeFile(
    file,
    JSON.stringify({
      format: "tenable-one-code-repository/v1",
      asset: {
        asset_id: assetId,
        asset_class: "CODE_REPOSITORY",
        asset_name: "example/repo",
      },
      repository_url: repositoryUrl,
      findings: [
        {
          asset_id: assetId,
          finding_id: "00017",
          finding_name: findingName,
          severity: "High",
          state: "ACTIVE",
          code_file_path: "src/app.ts",
          code_line_number: "7",
        },
      ],
    }),
  );
  return file;
}

function importOptions(repository: string) {
  return {
    repository,
    provider: "tenable" as const,
    sourceRepositoryUrl: repositoryUrl,
    sourceKey: "example/tenable/code-repository",
  };
}

test("the Tenable reader preserves vendor state and leaves unknown locations and severity unspecified", async () => {
  await using fixture = await localFindingsFixture();
  const file = await exampleReport(fixture.root);
  const selection = JSON.parse(await readFile(file, "utf8"));
  const row = selection.findings[0];
  delete row.code_file_path;
  delete row.code_line_number;
  row.severity = "INFO";
  row.state = "FIXED";
  selection.findings.push({
    ...row,
    finding_id: "00018",
    severity: "unrated",
    code_file_path: "src/app.ts",
  });
  await writeFile(file, JSON.stringify(selection));
  const { findings } = await readTenableFindings(file, repositoryUrl);
  expect(findings[0]).toMatchObject({
    source_finding_id: "00017",
    evidence: {
      severity: "informational",
      locations: [],
      source_data: { finding: { state: "FIXED" } },
    },
  });
  expect(findings[1]!.evidence).toMatchObject({
    severity: "unknown",
    locations: [{ path: "src/app.ts", line: null }],
  });
});

test("ambiguous Tenable identities and paths fail before any rows are admitted", async () => {
  await using fixture = await localFindingsFixture();
  const file = await exampleReport(fixture.root);
  const selection = JSON.parse(await readFile(file, "utf8"));
  const row = selection.findings[0];
  for (const invalid of [
    { ...selection, asset: { ...selection.asset, asset_class: "DEVICE" } },
    { ...selection, findings: [row, row] },
    {
      ...selection,
      findings: [{ ...row, asset_id: "20000000-0000-4000-8000-000000000002" }],
    },
    { ...selection, findings: [{ ...row, code_file_path: "../unrelated" }] },
    {
      ...selection,
      findings: [{ ...row, code_line_number: "9007199254740993" }],
    },
  ]) {
    await writeFile(file, JSON.stringify(invalid));
    await expect(readTenableFindings(file, repositoryUrl)).rejects.toThrow();
  }
});

test("a Tenable CLI preview can be saved locally and replayed with its original identity", async () => {
  await using fixture = await localFindingsFixture({
    remote: repositoryUrl + ".git",
  });
  const file = await exampleReport(fixture.root);
  const options = importOptions(fixture.repository);
  const deps = { environment: fixture.environment };
  const cli = createCliTest(main);
  const code = await cli.runCli(
    [
      "publish",
      "findings",
      file,
      "--provider",
      "tenable",
      "--to",
      "local",
      "--repository",
      fixture.repository,
      "--source-repository-url",
      repositoryUrl,
      "--source-key",
      options.sourceKey,
      "--dry-run",
      "--format",
      "json",
    ],
    cliDependencies(deps),
  );
  expect(code, cli.stderr.text() || cli.stdout.text()).toBe(0);
  const preview = JSON.parse(cli.stdout.text());
  expect(preview).toMatchObject({
    dryRun: true,
    source: { provider: "tenable", source_key: options.sourceKey },
    findings: [
      {
        source_finding_id: "00017",
        evidence: { title: "Example finding", severity: "high" },
      },
    ],
    excluded: [],
  });
  expect(await listLocalExternalFindings(options, deps)).toEqual([]);
  const first = await prepareNormalizedLocalImport(preview, options, deps);
  expect((await first.import()).counts.created).toBe(1);
  const repeated = await prepareLocalExternalImport(file, options, deps);
  expect((await repeated.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
  const records = await listLocalExternalFindings(options, deps);
  expect(records).toHaveLength(1);
  expect(records[0]).toMatchObject({
    sourceFindingId: "00017",
    provider: "tenable",
    assessment: { state: "not_assessed" },
    sourceKey: options.sourceKey,
    version: 1,
    evidence: preview.findings[0].evidence,
  });
  await exampleReport(fixture.root, "Revised finding");
  const updated = await (
    await prepareLocalExternalImport(file, options, deps)
  ).import();
  expect(updated.counts.updated).toBe(1);
  expect(updated.findings[0]).toMatchObject({
    id: records[0]!.id,
    sourceFindingId: "00017",
    version: 2,
    evidence: { title: "Revised finding" },
  });
});

test("Tenable file and normalized imports require consistent repository provenance", async () => {
  await using fixture = await localFindingsFixture({ remote: repositoryUrl });
  const file = await exampleReport(fixture.root);
  const options = importOptions(fixture.repository);
  const deps = { environment: fixture.environment };
  const { preview } = await prepareLocalExternalImport(file, options, deps);
  await expect(
    prepareLocalExternalImport(
      file,
      { ...options, sourceRepositoryUrl: undefined },
      deps,
    ),
  ).rejects.toThrow(/repository/i);
  const otherUrl = "https://github.com/example/other";
  for (const change of ["report", "row"] as const) {
    const inconsistent = structuredClone(preview);
    if (change === "report") inconsistent.report!["repositoryUrl"] = otherUrl;
    else
      inconsistent.findings[0]!.evidence.source_data!["repository_url"] =
        otherUrl;
    await expect(
      prepareNormalizedLocalImport(inconsistent, options, deps),
    ).rejects.toThrow(/repository|checkout/i);
  }
  const substituted = structuredClone(preview);
  substituted.findings[0]!.source_finding_id = "17";
  await expect(
    prepareNormalizedLocalImport(substituted, options, deps),
  ).rejects.toThrow(/finding ID|identity/i);
  fixture.git("remote", "set-url", "origin", otherUrl);
  await expect(prepareLocalExternalImport(file, options, deps)).rejects.toThrow(
    /repository|remote|checkout/i,
  );
  const emptyCapture = JSON.parse(await readFile(file, "utf8"));
  emptyCapture.findings = [];
  await writeFile(file, JSON.stringify(emptyCapture));
  await expect(prepareLocalExternalImport(file, options, deps)).rejects.toThrow(
    /repository|remote|checkout/i,
  );
  fixture.git("remote", "set-url", "origin", repositoryUrl);
  const runWorkbench = mock(async () => {
    throw new Error("An empty import must not open the workbench");
  });
  const empty = await prepareLocalExternalImport(file, options, {
    ...deps,
    runWorkbench,
  });
  expect((await empty.import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  expect(runWorkbench).not.toHaveBeenCalled();
});

test("Tenable import requires the opt-in and refuses Cloud before reading files or requesting credentials", async () => {
  await using fixture = await localFindingsFixture();
  const missing = join(fixture.root, "missing.json");
  const options = importOptions(fixture.repository);
  await expect(
    prepareLocalExternalImport(missing, options, { environment: {} }),
  ).rejects.toThrow("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1");
  const unexpected = mock(async () => {
    throw new Error("Unexpected Cloud call");
  });
  const dependencies = {
    environment: fixture.environment,
    fetch: unexpected,
    credentials: unexpected,
  };
  // Exercise JavaScript callers as well as the typed SDK. Tenable is local-only.
  await expect(
    prepareExternalPublication(
      missing,
      options as unknown as Parameters<typeof prepareExternalPublication>[1],
      dependencies,
    ),
  ).rejects.toThrow(/local/i);
  await expect(
    prepareNormalizedExternalPublication(
      { read: 0, findings: [], excluded: [] },
      options as unknown as Parameters<
        typeof prepareNormalizedExternalPublication
      >[1],
      dependencies,
    ),
  ).rejects.toThrow(/local/i);
  const file = await exampleReport(fixture.root);
  fixture.git("remote", "add", "origin", repositoryUrl);
  const { preview } = await prepareLocalExternalImport(
    file,
    options,
    dependencies,
  );
  await expect(
    prepareNormalizedExternalPublication(
      preview,
      { ...options, provider: "wiz" },
      dependencies,
    ),
  ).rejects.toThrow(/local/i);
  expect(unexpected).not.toHaveBeenCalled();
});
