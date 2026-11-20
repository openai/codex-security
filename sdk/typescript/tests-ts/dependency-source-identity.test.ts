import { expect, test } from "bun:test";
import { hash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import {
  readDependencySourceCitation,
  readDependencyTarget,
} from "../src/dependency-source-identity.js";
import { git } from "./git-fixture.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("source citations bind an exact regular Git blob and report the actual covered lines", async () => {
  await using directory = await scopedTemporaryDirectory("source-identity-");
  const repo = directory.path;
  git(repo, "init", "-q");
  const source = "\uFEFFfirst\r\nsecond\nlast";
  await writeFile(join(repo, "source.txt"), source);
  git(repo, "-c", "core.autocrlf=false", "add", "source.txt");
  const blob = git(repo, "rev-parse", ":source.txt");
  git(repo, "update-index", "--add", "--cacheinfo", `120000,${blob},link`);
  git(repo, "commit", "-qm", "Add example source");
  const commit = git(repo, "rev-parse", "HEAD");
  await writeFile(join(repo, "source.txt"), "different worktree bytes\n");

  const range = { path: "source.txt", startLine: 1, endLine: 2 };
  expect(await readDependencySourceCitation(repo, commit, range)).toEqual({
    ...range,
    commit,
    blob,
    contentSha256: hash("sha256", source),
    excerpt: "\uFEFFfirst\r\nsecond\n",
  });
  expect(
    await readDependencySourceCitation(repo, commit, {
      ...range,
      startLine: 3,
      endLine: 9,
    }),
  ).toMatchObject({
    startLine: 3,
    endLine: 3,
    excerpt: "last",
  });
  for (const [revision, path] of [
    [commit, "../source.txt"],
    [commit, "link"],
    [blob, "source.txt"],
    ["HEAD", "source.txt"],
  ] as const)
    await expect(
      readDependencySourceCitation(repo, revision, { ...range, path }),
    ).rejects.toThrow();
  await expect(
    readDependencySourceCitation(repo, commit, {
      ...range,
      startLine: 4,
      endLine: 5,
    }),
  ).rejects.toThrow(/end of the Git file/);
});

test("validates only the cited bytes as UTF-8 and hashes the entire source blob", async () => {
  await using directory = await scopedTemporaryDirectory("source-encoding-");
  const repo = directory.path;
  const bytes = Buffer.from(
    "# coding: latin-1\n# caf\u00e9\nprint(1)\r\n# derni\u00e8re",
    "latin1",
  );
  git(repo, "init", "-q");
  await writeFile(join(repo, "example.py"), bytes);
  git(repo, "-c", "core.autocrlf=false", "add", "example.py");
  git(repo, "commit", "-qm", "Add mixed-encoding source");
  const commit = git(repo, "rev-parse", "HEAD");
  const cite = (startLine: number, endLine: number) =>
    readDependencySourceCitation(repo, commit, {
      path: "example.py",
      startLine,
      endLine,
    });
  expect(await cite(3, 3)).toMatchObject({
    startLine: 3,
    endLine: 3,
    excerpt: "print(1)\r\n",
    contentSha256: hash("sha256", bytes),
  });
  await expect(cite(2, 3)).rejects.toThrow();
  await expect(cite(3, 9)).rejects.toThrow();
});

test("report targets identify the checkout without URL credentials or local paths", async () => {
  await using directory = await scopedTemporaryDirectory("source-identity-");
  const repo = directory.path;
  git(repo, "init", "-q");
  expect(await readDependencyTarget(repo)).toBeUndefined();
  git(repo, "commit", "--allow-empty", "-qm", "Initial checkout");
  const sha = git(repo, "rev-parse", "HEAD");
  expect(await readDependencyTarget(repo)).toEqual({
    repository: basename(repo),
    sha,
  });
  git(
    repo,
    "remote",
    "add",
    "origin",
    "https://user:secret@example.invalid/team/reader.git?auth=key",
  );
  expect(await readDependencyTarget(repo)).toEqual({
    repository: "team/reader",
    sha,
  });
  git(
    repo,
    "remote",
    "set-url",
    "origin",
    "git@example.invalid:team/core/reader.git",
  );
  expect(await readDependencyTarget(repo)).toEqual({
    repository: "team/core/reader",
    sha,
  });
  git(repo, "remote", "set-url", "origin", "file:///fixtures/reader.git");
  expect(await readDependencyTarget(repo)).toEqual({
    repository: basename(repo),
    sha,
  });
});
