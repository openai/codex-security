import { execFileSync, spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryRoots: string[] = [];

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function git(repository: string, ...args: string[]): string {
  return execFileSync(
    "git",
    [
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      ...args,
    ],
    { cwd: repository, encoding: "utf8" },
  ).trim();
}

test("diff previews stay inside the selected repository", () => {
  const root = realpathSync(
    mkdtempSync(join(tmpdir(), "codex-security-diff-rank-")),
  );
  temporaryRoots.push(root);
  const repository = join(root, "repository");
  const nested = join(repository, "src", "nested");
  mkdirSync(nested, { recursive: true });
  git(repository, "init", "-q");
  writeFileSync(join(repository, "src", "handler.py"), "value = 1\n");
  writeFileSync(join(repository, "src", "deleted.py"), "removed = True\n");
  writeFileSync(join(repository, "src", "entry.py"), "handler.py");
  writeFileSync(join(nested, "linked.py"), "value = 1\n");
  git(repository, "add", ".");
  const originalLink = git(repository, "hash-object", "src/entry.py");
  git(
    repository,
    "update-index",
    "--cacheinfo",
    `120000,${originalLink},src/entry.py`,
  );
  git(repository, "commit", "-qm", "base");
  const base = git(repository, "rev-parse", "HEAD");

  writeFileSync(join(repository, "src", "handler.py"), "value = 2\n");
  writeFileSync(join(repository, "src", "entry.py"), "nested/linked.py");
  writeFileSync(join(nested, "linked.py"), "value = 2\n");
  rmSync(join(repository, "src", "deleted.py"));
  git(repository, "add", ".");
  const updatedLink = git(repository, "hash-object", "src/entry.py");
  git(
    repository,
    "update-index",
    "--cacheinfo",
    `120000,${updatedLink},src/entry.py`,
  );
  git(repository, "commit", "-qm", "selected changes");
  const head = git(repository, "rev-parse", "HEAD");

  const externalFixture = join(root, "synthetic-fixture");
  mkdirSync(externalFixture);
  writeFileSync(join(externalFixture, "linked.py"), "synthetic = True\n");
  rmSync(nested, { recursive: true });
  symlinkSync(externalFixture, nested, "junction");

  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  const output = join(root, "rank-input.jsonl");
  const result = spawnSync(
    python!,
    [
      "-B",
      join(PLUGIN_ROOT, "scripts", "generate_rank_input.py"),
      "make-diff-rank-input",
      "--repo",
      repository,
      "--base",
      base,
      "--head",
      head,
      "--mode",
      "local-patch",
      "--out",
      output,
    ],
    { encoding: "utf8" },
  );

  expect(result.status, result.stderr).toBe(0);
  const rows = readFileSync(output, "utf8")
    .trim()
    .split("\n")
    .map((row) => JSON.parse(row) as { path: string; preview: string });
  expect(rows.map((row) => row.path)).toEqual([
    "src/deleted.py",
    "src/entry.py",
    "src/handler.py",
    "src/nested/linked.py",
  ]);
  expect(rows.find((row) => row.path === "src/handler.py")?.preview).toBe(
    "value = 2",
  );
  expect(rows.find((row) => row.path === "src/nested/linked.py")?.preview).toBe(
    "",
  );
});
