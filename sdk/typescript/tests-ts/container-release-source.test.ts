import { readFileSync } from "node:fs";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { bashCommand, runCommand } from "./support/shell.js";

const verifier = readFileSync(
  new URL(
    "../../../docker/verify-container-release-source.sh",
    import.meta.url,
  ),
  "utf8",
);
const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) {
    await rm(root, { recursive: true, force: true });
  }
});

async function repository() {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "container-release-")),
  );
  roots.push(root);
  async function git(...args: string[]): Promise<string> {
    const result = await runCommand(
      "git",
      [
        "-c",
        "user.name=Release Fixture",
        "-c",
        "user.email=release@example.test",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "tag.gpgsign=false",
        ...args,
      ],
      { cwd: root, timeout: 10_000 },
    );
    expect(result.status, result.stderr).toBe(0);
    return result.stdout.trim();
  }
  await git("init", "--initial-branch=main");
  await writeFile(join(root, "package.json"), '{"version":"0.2.0"}\n');
  await git("add", "package.json");
  await git("commit", "-m", "Release fixture");
  const releaseCommit = await git("rev-parse", "HEAD");
  return {
    git,
    releaseCommit,
    verify: (commit: string) =>
      runCommand(bashCommand(), ["-s", "--", "0.2.0", commit], {
        cwd: root,
        input: verifier,
        timeout: 10_000,
      }),
  };
}

test.each([false, true])(
  "accepts the npm release commit (annotated tag: %s)",
  async (annotated) => {
    const fixture = await repository();
    await fixture.git(
      "tag",
      ...(annotated ? ["-a", "-m", "Release fixture"] : []),
      "npm-v0.2.0",
    );
    const result = await fixture.verify(fixture.releaseCommit);
    expect(result.status, result.stderr).toBe(0);
  },
);

test("rejects a later commit even when its package version is unchanged", async () => {
  const fixture = await repository();
  await fixture.git("tag", "npm-v0.2.0");
  await fixture.git("commit", "--allow-empty", "-m", "Later source commit");
  const result = await fixture.verify(await fixture.git("rev-parse", "HEAD"));
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("same commit as npm-v0.2.0");
});

test("requires the matching npm release tag", async () => {
  const fixture = await repository();
  const result = await fixture.verify(fixture.releaseCommit);
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("npm-v0.2.0 before publishing its container");
});
