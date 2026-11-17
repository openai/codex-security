import { expect, test } from "bun:test";
import { hash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { readDependencySourceCitation } from "../src/dependency-source-identity.js";
import { git } from "./git-fixture.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("source citations bind an exact regular Git blob and report the actual covered lines", async () => {
  await using directory = await scopedTemporaryDirectory("source-identity-");
  const repo = directory.path;
  git(repo, "init", "-q");
  const source = "first\r\nsecond\nlast";
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
    excerpt: "first\r\nsecond\n",
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
