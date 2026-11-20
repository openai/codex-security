import { existsSync } from "node:fs";
import { expect, test } from "bun:test";
import {
  listLocalExternalImports,
  prepareNormalizedLocalImport,
  selectLocalExternalFindings,
  type ExternalFindings,
} from "../src/index.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";

const source = {
  provider: "example-scanner",
  sourceKey: "project/main",
  sourceRepositoryUrl: "https://github.com/example/project",
};

function report(): ExternalFindings {
  return {
    read: 2,
    findings: [
      {
        source_finding_id: "9007199254740993",
        evidence: { title: "Unsafe subprocess", severity: "high" },
      },
    ],
    excluded: [
      { position: 2, source_finding_id: null, reason: "Missing vendor ID" },
    ],
    report: { job: "example-run" },
  };
}

test("a parser-defined provider stores its reviewed selection and can retrieve it by import ID", async () => {
  await using fixture = await localFindingsFixture({
    remote: "git@github.com:example/project.git",
  });
  const { repository, environment } = fixture;
  const input = report();
  const prepare = () =>
    prepareNormalizedLocalImport(
      input,
      { ...source, repository },
      { environment },
    );
  const prepared = await prepare();
  expect(prepared.matchesRepositoryRemote).toBe(true);
  expect(existsSync(fixture.stateDirectory)).toBe(false);

  prepared.preview.findings[0]!.evidence.title = "Edited preview";
  const first = await prepared.import();
  const repeat = await (await prepare()).import();
  expect(repeat.counts.unchanged).toBe(1);
  const imports = await listLocalExternalImports(
    { repository },
    { environment },
  );
  expect(imports.map((i) => i.importId)).toEqual([
    repeat.importId!,
    first.importId!,
  ]);

  const select = () =>
    selectLocalExternalFindings(
      { repository, importId: repeat.importId! },
      { environment },
    );
  expect(await select()).toMatchObject({
    read: input.read,
    report: input.report,
    excluded: input.excluded,
    findings: [
      {
        sourceFindingId: "9007199254740993",
        evidence: input.findings[0]!.evidence,
        version: 1,
        provenance: {
          sourceRepositories: [{ url: source.sourceRepositoryUrl }],
        },
      },
    ],
  });
  input.findings[0]!.evidence.title = "New evidence";
  await (await prepare()).import();
  await expect(select()).rejects.toThrow(/changed/);
});

test("agent inputs account for every occurrence and validate identities and evidence", async () => {
  await using fixture = await localFindingsFixture();
  const prepare = (input: ExternalFindings, options = source) =>
    prepareNormalizedLocalImport(
      input,
      { ...options, repository: fixture.repository },
      { environment: fixture.environment },
    );
  const input = report();
  const [row] = input.findings;
  const [excluded] = input.excluded;
  await expect(prepare(input, { ...source, provider: "" })).rejects.toThrow();
  await expect(
    prepare(input, { ...source, sourceKey: String.fromCharCode(0xd800) }),
  ).rejects.toThrow();
  for (const invalid of [
    { ...input, read: 3 },
    { ...input, findings: [row, row], read: 3 },
    { ...input, excluded: [{ ...excluded, position: 3 }] },
    { ...input, read: 3, excluded: [excluded, excluded] },
  ])
    await expect(prepare(invalid as ExternalFindings)).rejects.toThrow();
  const missingSeverity = {
    ...input,
    findings: [{ ...row, evidence: { title: "Missing severity" } }],
  };
  for (const provider of [source.provider, "wiz"])
    await expect(
      prepare(missingSeverity as ExternalFindings, { ...source, provider }),
    ).rejects.toThrow();
});

test("a custom parser binds all declared sources to one repository", async () => {
  await using fixture = await localFindingsFixture({
    remote: source.sourceRepositoryUrl,
  });
  const input = report();
  const prepare = (sourceRepositoryUrl?: string, provider = source.provider) =>
    prepareNormalizedLocalImport(
      input,
      {
        ...source,
        provider,
        repository: fixture.repository,
        sourceRepositoryUrl,
      },
      { environment: fixture.environment },
    );
  expect((await prepare()).matchesRepositoryRemote).toBe(false);
  const other = "https://github.com/example/other";
  await expect(prepare(other)).rejects.toThrow(/does not match/u);
  for (const provider of ["wiz", "snyk"])
    await expect(prepare(other, provider)).rejects.toThrow(/does not match/u);
  fixture.git("remote", "add", "upstream", other);
  const details = {
    kind: "sast" as const,
    repository: { url: source.sourceRepositoryUrl },
  };
  input.findings[0]!.evidence.details = details;
  await expect(prepare(other)).rejects.toThrow(/conflicting/u);
  await expect(prepare(other, "wiz")).rejects.toThrow(/does not match/u);
  delete input.findings[0]!.evidence.details;
  input.findings[0]!.evidence.source_data = {
    vulnerableAsset: {
      nativeType: "github#repositoryBranch",
      cloudProviderURL: source.sourceRepositoryUrl + "/tree/main",
    },
  };
  await expect(prepare(other, "wiz")).rejects.toThrow(/does not match/u);
  input.findings[0]!.evidence.details = details;
  details.repository.url += "/../other";
  await expect(prepare()).rejects.toThrow();
  expect(existsSync(fixture.stateDirectory)).toBe(false);
});
