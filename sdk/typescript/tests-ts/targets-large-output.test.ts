import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  DiffTarget,
  normalizeTarget,
  validateCommittedDiffCheckout,
} from "../src/targets.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function git(repo: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd: repo,
    encoding: "utf8",
    maxBuffer: Infinity,
  }).trim();
}

test("validates committed diffs with tracked-file output larger than 1 MB", async () => {
  if (process.platform === "win32") return;

  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-large-targets-")),
  );
  temporaryDirectories.push(root);
  const repo = join(root, "repo");
  await mkdir(repo);

  git(repo, "init", "-b", "main");
  git(repo, "config", "user.email", "test@example.com");
  git(repo, "config", "user.name", "Test");

  const longDirectory = join(
    repo,
    "a".repeat(200),
    "b".repeat(200),
    "c".repeat(200),
  );
  await mkdir(longDirectory, { recursive: true });
  await Promise.all(
    Array.from({ length: 1_500 }, (_, index) =>
      writeFile(
        join(
          longDirectory,
          `${index.toString().padStart(4, "0")}-${"x".repeat(180)}.ts`,
        ),
        "",
      ),
    ),
  );

  git(repo, "add", ".");
  git(repo, "commit", "--quiet", "-m", "large tracked tree");

  const tracked = git(repo, "ls-files", "-t", "-z");
  expect(Buffer.byteLength(tracked, "utf8")).toBeGreaterThan(1024 * 1024);

  const target = await normalizeTarget(
    repo,
    DiffTarget.refs({ base: "HEAD" }),
  );
  await expect(validateCommittedDiffCheckout(repo, target)).resolves.toBeUndefined();
});
