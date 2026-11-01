import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { appendFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { normalizeSnykIssues } from "../src/snyk-rest-findings.js";
import {
  snykLocalFixture,
  snykOptions,
  snykRestFixture,
} from "./support/snyk-rest-fixtures.js";

function prepare(
  fixture: Awaited<ReturnType<typeof snykLocalFixture>>,
  sourceRepositoryUrl: string,
  overrides: NodeJS.ProcessEnv = {},
) {
  return prepareNormalizedLocalImport(
    normalizeSnykIssues(
      snykRestFixture("open-source", { sourceRepositoryUrl }),
    ),
    { repository: fixture.repository, provider: "snyk", sourceKey: "project" },
    { environment: { ...fixture.environment, ...overrides } },
  );
}

test("Snyk checks the remote helper used by fetch when GIT_CONFIG selects a different file", async () => {
  const remote = snykOptions.sourceRepositoryUrl;
  await using fixture = await snykLocalFixture({ remote });
  const config = join(fixture.root, "empty-config");
  await writeFile(config, "");
  for (const helper of ["other", ""]) {
    execFileSync("git", ["config", "remote.origin.vcs", helper], {
      cwd: fixture.repository,
      env: fixture.environment,
    });
    await expect(
      prepare(fixture, remote, { GIT_CONFIG: config }),
    ).rejects.toThrow("configured remote");
  }
});

test.skipIf(process.platform === "win32")(
  "invalid UTF-8 in a Git URL cannot alias a Snyk project containing the replacement character",
  async () => {
    const prefix = "https://github.com/example/repo";
    const reported = prefix + "%EF%BF%BD";
    await using fixture = await snykLocalFixture();
    await appendFile(
      join(fixture.repository, ".git", "config"),
      Buffer.concat([
        Buffer.from('\n[remote "origin"]\n\turl = ' + prefix),
        Buffer.from([0xff, 0x0a]),
      ]),
    );
    await expect(prepare(fixture, reported)).rejects.toThrow(
      "configured remote",
    );
    execFileSync("git", ["remote", "add", "upstream", reported], {
      cwd: fixture.repository,
      env: fixture.environment,
    });
    expect((await prepare(fixture, reported)).preview.findings).toHaveLength(1);
  },
);

test("a later fetch URL on the same Git remote cannot bind a Snyk project", async () => {
  const selected = snykOptions.sourceRepositoryUrl;
  await using fixture = await snykLocalFixture({
    remote: selected + "-different",
  });
  execFileSync("git", ["config", "--add", "remote.origin.url", selected], {
    cwd: fixture.repository,
    env: fixture.environment,
  });
  await expect(prepare(fixture, selected)).rejects.toThrow("configured remote");
});
