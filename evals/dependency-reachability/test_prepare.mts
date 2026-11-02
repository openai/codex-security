import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  readlink,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { prepareSnapshot, snapshotDigest } from "./prepare.mts";
import type { StageFile } from "./cases.mts";

test("exports the pinned tree and independently pinned overlays without exposing history or touching the source clone", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "reachability fixture "));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clone = join(root, "caller checkout");
  await mkdir(clone);
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: clone, encoding: "utf8" }).trim();
  git("init", "-q");
  git("config", "user.name", "Test");
  git("config", "user.email", "test@example.invalid");
  git("config", "core.autocrlf", "false");
  await writeFile(join(clone, ".gitattributes"), "parser.bin filter=test\n");
  await writeFile(join(clone, "parser.bin"), Buffer.from([0, 1, 255]));
  await writeFile(join(clone, "run.sh"), "#!/bin/sh\n");
  if (process.platform !== "win32")
    await symlink("run.sh", join(clone, "run-link"));
  git("add", ".");
  git("update-index", "--chmod=+x", "run.sh");
  git("commit", "-qm", "first");
  const original = git("rev-parse", "HEAD");
  await writeFile(join(clone, "parser.bin"), Buffer.from([0, 2, 255]));
  git("add", "parser.bin");
  git("commit", "-qm", "second");
  const backport = git("rev-parse", "HEAD");
  await writeFile(join(clone, "parser.bin"), "uncommitted work");
  await writeFile(join(clone, "grader.txt"), "untracked gold");
  git("config", "filter.test.smudge", "exit 1");
  git("config", "filter.test.required", "true");
  const stage: StageFile[] = [
    {
      kind: "git",
      repository: "nodemailer/nodemailer",
      revision: backport,
      source: "parser.bin",
      destination: "installed/parser.bin",
    },
    {
      kind: "json",
      destination: "installed/config.json",
      value: { enabled: true },
    },
  ];
  const repo = await prepareSnapshot(
    root,
    { repository: "nodemailer/mailparser", revision: original, stage },
    {
      "nodemailer/mailparser": clone,
      "nodemailer/nodemailer": clone,
    },
  );
  assert.deepEqual(
    await readFile(join(repo, "parser.bin")),
    Buffer.from([0, 1, 255]),
  );
  assert.deepEqual(
    await readFile(join(repo, "installed/parser.bin")),
    Buffer.from([0, 2, 255]),
  );
  assert.deepEqual(
    JSON.parse(await readFile(join(repo, "installed/config.json"), "utf8")),
    { enabled: true },
  );
  assert.ok(!(await readdir(repo)).includes(".git"));
  assert.ok(!(await readdir(repo)).includes("grader.txt"));
  if (process.platform !== "win32") {
    assert.equal(await readlink(join(repo, "run-link")), "run.sh");
    assert.ok((await lstat(join(repo, "run.sh"))).mode & 0o111);
  }
  assert.equal(git("rev-parse", "HEAD"), backport);
  assert.equal(
    await readFile(join(clone, "parser.bin"), "utf8"),
    "uncommitted work",
  );
  const input = {
    repository: "nodemailer/mailparser",
    revision: original,
    stage,
  } as const;
  const digest = await snapshotDigest(repo, input);
  await writeFile(join(repo, "installed/config.json"), '{"enabled":false}\n');
  assert.notEqual(await snapshotDigest(repo, input), digest);
});

test("a tracked symlink cannot redirect a deployed overlay", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "reachability-overlay-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const clone = join(root, "clone");
  await mkdir(clone);
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: clone, encoding: "utf8" }).trim();
  git("init", "-q");
  const outside = join(root, "outside");
  await mkdir(outside);
  const linkBlob = execFileSync("git", ["hash-object", "-w", "--stdin"], {
    cwd: clone,
    encoding: "utf8",
    input: outside,
  }).trim();
  git("update-index", "--add", "--cacheinfo", `120000,${linkBlob},service`);
  git(
    "-c",
    "user.name=Test",
    "-c",
    "user.email=test@example.invalid",
    "commit",
    "-qm",
    "service symlink",
  );
  const revision = git("rev-parse", "HEAD");
  await assert.rejects(
    prepareSnapshot(
      root,
      {
        repository: "nodemailer/mailparser",
        revision,
        stage: [
          { kind: "json", destination: "service/deploy.json", value: {} },
        ],
      },
      { "nodemailer/mailparser": clone },
    ),
    { code: "EEXIST" },
  );
  assert.deepEqual(await readdir(outside), []);
});
