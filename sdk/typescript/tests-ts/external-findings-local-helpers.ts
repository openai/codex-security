import { expect } from "bun:test";
import type { ExternalFindings } from "../src/external-findings.js";
import { EXTERNAL_FINDINGS_PROVIDERS } from "../src/external-findings-read.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import {
  listLocalExternalFindings,
  prepareNormalizedLocalImport,
  type StoredExternalFinding,
} from "../src/external-findings-local.js";
import type { ExternalPublicationOptions } from "../src/external-findings-publish.js";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Real Git checkout and separate state, shared by normalized and vendor import tests. */
type Checkout = {
  remote?: string;
  environment?: NodeJS.ProcessEnv;
  isolatedGit?: boolean;
};

export async function localFindingsFixture(options: Checkout = {}) {
  const root = await mkdtemp(
    join(await realpath(tmpdir()), "codex-security-external-local-"),
  );
  let environment = options.environment ?? process.env;
  if (options.isolatedGit) {
    const config = join(root, "global.gitconfig");
    await writeFile(config, "");
    environment = {
      ...Object.fromEntries(
        Object.entries(environment).filter(
          ([name]) => !name.toUpperCase().startsWith("GIT_"),
        ),
      ),
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: config,
    };
  }
  const repository = join(root, "repository");
  await mkdir(repository);
  execFileSync("git", ["init", "--quiet", repository], { env: environment });
  if (options.remote !== undefined)
    execFileSync(
      "git",
      ["-C", repository, "remote", "add", "origin", options.remote],
      { env: environment },
    );
  const stateDirectory = join(root, "state");
  const dispose = () => rm(root, { recursive: true, force: true });
  return {
    root,
    repository,
    stateDirectory,
    environment: {
      ...Object.fromEntries(
        Object.entries(environment).filter(
          ([name]) =>
            name.toUpperCase() !== "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS",
        ),
      ),
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
    },
    dispose,
    [Symbol.asyncDispose]: dispose,
  };
}

export async function localReportFixture(
  filename: string,
  source: Omit<ExternalPublicationOptions, "repository">,
  checkout: Checkout = {},
) {
  const fixture = await localFindingsFixture(checkout);
  const file = join(fixture.root, filename);
  const options = { ...source, repository: fixture.repository };
  const normalizedOptions = {
    ...options,
    provider: EXTERNAL_FINDINGS_PROVIDERS[source.provider],
  };
  const dependencies = { environment: fixture.environment };
  return {
    ...fixture,
    file,
    sourceKey: source.sourceKey,
    writeJson: (report: unknown) => writeFile(file, JSON.stringify(report)),
    prepare: (overrides: Pick<typeof source, "sourceRepositoryUrl"> = {}) =>
      prepareLocalExternalImport(
        file,
        { ...options, ...overrides },
        dependencies,
      ),
    prepareNormalized: (input: ExternalFindings) =>
      prepareNormalizedLocalImport(input, normalizedOptions, dependencies),
    read: () => listLocalExternalFindings(options, dependencies),
  };
}

export function isolatedGitReportFixture(
  filename: string,
  source: Omit<ExternalPublicationOptions, "repository">,
  checkout: Checkout = {},
) {
  return localReportFixture(filename, source, {
    ...checkout,
    isolatedGit: true,
  });
}

type LocalReportFixture = Awaited<ReturnType<typeof localReportFixture>>;

export async function createAndReplayFinding(fixture: LocalReportFixture) {
  const prepared = await fixture.prepare();
  expect(prepared.preview.excluded).toEqual([]);
  expect(prepared.preview.findings).toHaveLength(1);
  expect(await fixture.read()).toEqual([]);
  expect((await prepared.import()).counts).toEqual({
    created: 1,
    updated: 0,
    unchanged: 0,
  });
  const records = await fixture.read();
  expect(records).toHaveLength(1);
  const stored = records[0]!;
  expect(stored).toMatchObject({
    repository: fixture.repository,
    sourceKey: fixture.sourceKey,
    sourceFindingId: prepared.preview.findings[0]!.source_finding_id,
    version: 1,
  });
  expect(stored.evidence).toEqual(prepared.preview.findings[0]!.evidence);
  expect(stored.assessment).toEqual({ state: "not_assessed" });
  expect(stored.evidence).not.toHaveProperty("confidence");
  expect((await (await fixture.prepare()).import()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
  expect(await fixture.read()).toEqual(records);
  return stored;
}

export async function updateStoredFinding(
  fixture: LocalReportFixture,
  previous: StoredExternalFinding,
) {
  const prepared = await fixture.prepare();
  expect((await prepared.import()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  const records = await fixture.read();
  expect(records).toHaveLength(1);
  const updated = records[0]!;
  expect(updated).toMatchObject({
    id: previous.id,
    sourceFindingId: previous.sourceFindingId,
    createdAt: previous.createdAt,
    version: 2,
  });
  expect(updated.assessment).toEqual({ state: "not_assessed" });
  expect(updated.evidence).toEqual(prepared.preview.findings[0]!.evidence);
  return updated;
}
