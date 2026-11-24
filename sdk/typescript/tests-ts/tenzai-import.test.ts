import { expect, mock, test } from "bun:test";
import exampleFindings from "../../../examples/tenzai/findings.json";
import { main } from "../src/cli.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import {
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
  type NormalizedExternalPublicationOptions,
} from "../src/external-findings-publish.js";
import { readTenzaiFindings } from "../src/tenzai-findings.js";
import { dependencies as cliDependencies } from "./cli-fixtures.js";
import {
  createAndReplayFinding,
  localReportFixture,
  updateStoredFinding,
} from "./external-findings-local-helpers.js";
import { createCliTest } from "./support/cli-run.js";

const repositoryUrl = "https://github.com/example/project";
const source = {
  provider: "tenzai",
  sourceKey: "example/application/test",
  sourceRepositoryUrl: repositoryUrl,
} as const;
const finding = exampleFindings[0]!;

function checkout() {
  return localReportFixture("tenzai.json", source, { remote: repositoryUrl });
}

test("Tenzai retains runtime evidence without inventing checkout locations", async () => {
  await using fixture = await checkout();
  await fixture.writeJson([finding]);
  const result = await readTenzaiFindings(fixture.file, repositoryUrl);
  expect(result.excluded).toEqual([]);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({
    source_finding_id: finding.id,
    evidence: {
      title: finding.name,
      severity: "high",
      source_scan_id: finding.testId,
      locations: [],
      source_data: { finding },
    },
  });
  expect(result.findings[0]!.evidence.description).toContain(finding.impact);
  expect(result.findings[0]!.evidence.description).toContain(
    "Check ownership.",
  );
});

test("Tenzai accepts a single finding and complete page; incomplete pages require a full export", async () => {
  await using fixture = await checkout();
  for (const report of [
    finding,
    { items: [finding], total: 1, page: 1, size: 50, pages: 1 },
  ]) {
    await fixture.writeJson(report);
    expect(
      (await fixture.prepare()).preview.findings[0]!.source_finding_id,
    ).toBe(finding.id);
  }
  for (const report of [
    { items: [finding], total: 2, page: 1, size: 1, pages: 2 },
    { items: [finding], total: 2, page: 2, size: 1, pages: 2 },
    { items: [finding] },
    { error: "HTTP 403" },
  ]) {
    await fixture.writeJson(report);
    await expect(fixture.prepare()).rejects.toThrow(/Tenzai|paginate/u);
  }
});

test("Tenzai requires one Test and application, and excludes ambiguous finding identities", async () => {
  await using fixture = await checkout();
  for (const other of [
    { ...finding, testId: "another-test" },
    { ...finding, appId: "another-application" },
    { ...finding, testId: undefined, state: "OPEN" },
  ]) {
    await fixture.writeJson([finding, { ...other, id: "another-finding" }]);
    await expect(fixture.prepare()).rejects.toThrow(/Test|application/u);
  }
  await fixture.writeJson([
    finding,
    finding,
    { ...finding, id: "unique", name: "" },
  ]);
  const result = await readTenzaiFindings(fixture.file, repositoryUrl);
  expect(result.findings).toEqual([]);
  expect(result.excluded.map(({ position }) => position)).toEqual([1, 2, 3]);
});

test("Tenzai keeps informational and unknown severities and does not substitute CVSS for severity", async () => {
  await using fixture = await checkout();
  await fixture.writeJson([
    {
      ...finding,
      severity: "INFORMATIONAL",
      status: "FIXED",
      cve: "CVE-2026-12345",
    },
    { ...finding, id: "unknown", severity: "UNRATED", cvss: { score: 9.8 } },
  ]);
  const { findings } = await readTenzaiFindings(fixture.file, repositoryUrl);
  expect(findings[0]!.evidence).toMatchObject({
    severity: "informational",
    advisory_ids: ["CVE-2026-12345"],
    source_data: { finding: { status: "FIXED" } },
  });
  expect(findings[1]!.evidence.severity).toBe("unknown");
});

test("the CLI imports Tenzai and updates the same native finding on replay", async () => {
  await using fixture = await checkout();
  await fixture.writeJson([finding]);
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      [
        "publish",
        "findings",
        fixture.file,
        "--provider=tenzai",
        "--to=local",
        `--repository=${fixture.repository}`,
        `--source-repository-url=${repositoryUrl}`,
        `--source-key=${source.sourceKey}`,
        "--dry-run",
        "--format=json",
      ],
      cliDependencies({ environment: fixture.environment }),
    ),
    cli.stderr.text(),
  ).toBe(0);
  const preview = JSON.parse(cli.stdout.text());
  expect(preview.source).toEqual({
    provider: "tenzai",
    source_key: source.sourceKey,
  });
  const saved = await createAndReplayFinding(fixture, preview);
  expect(saved.provider).toBe("tenzai");
  await fixture.writeJson([
    { ...finding, name: "Revised finding", severity: "MEDIUM" },
  ]);
  expect((await updateStoredFinding(fixture, saved)).evidence).toMatchObject({
    title: "Revised finding",
    severity: "medium",
  });
});

test("Tenzai verifies the declared checkout even for empty reports and normalized replay", async () => {
  await using fixture = await checkout();
  await fixture.writeJson([finding]);
  await expect(
    fixture.prepare({ sourceRepositoryUrl: undefined }),
  ).rejects.toThrow(/source-repository-url/u);
  const { preview } = await fixture.prepare();
  const wrongId = structuredClone(preview);
  wrongId.findings[0]!.source_finding_id = "different-id";
  await expect(fixture.prepareNormalized(wrongId)).rejects.toThrow(/identity/u);
  const wrongRepository = structuredClone(preview);
  wrongRepository.report!["repositoryUrl"] = "https://github.com/example/other";
  await expect(fixture.prepareNormalized(wrongRepository)).rejects.toThrow(
    /repository/u,
  );
  fixture.git(
    "remote",
    "set-url",
    "origin",
    "https://github.com/example/other",
  );
  for (const rows of [[finding], []]) {
    await fixture.writeJson(rows);
    await expect(fixture.prepare()).rejects.toThrow(/fetch remote/u);
  }
  fixture.git("remote", "set-url", "origin", repositoryUrl);
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 0,
  });
  await expect(
    prepareNormalizedLocalImport(
      preview,
      { ...source, provider: "wiz", repository: fixture.repository },
      { environment: fixture.environment },
    ),
  ).rejects.toThrow(/tenzai provider/u);
});

test("Cloud rejects native and relabeled Tenzai evidence before credentials or network access", async () => {
  await using fixture = await checkout();
  await fixture.writeJson([finding]);
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
  ).rejects.toThrow(/local/u);
  const { preview } = await fixture.prepare();
  await expect(
    prepareNormalizedExternalPublication(preview, cloudOptions, deps),
  ).rejects.toThrow(/local/u);
  await expect(
    prepareNormalizedExternalPublication(
      preview,
      { ...options, provider: "wiz" },
      deps,
    ),
  ).rejects.toThrow(/local/u);
  expect(unexpected).not.toHaveBeenCalled();
});
