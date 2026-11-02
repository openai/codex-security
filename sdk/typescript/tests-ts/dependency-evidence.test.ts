import { execFileSync } from "node:child_process";
import { mkdir, symlink, truncate, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { collectDependencyEvidence } from "../src/dependency-evidence.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "dependency-evidence-",
);
afterEach(cleanup);

test("selects package references, context and related build descriptors in an unpacked checkout", async () => {
  const root = await temporaryDirectory();
  await mkdir(join(root, "api"));
  await mkdir(join(root, "other"));
  await mkdir(join(root, "node_modules"));
  await writeFile(
    join(root, "api", "app.js"),
    [
      'import format from "test-format";',
      "",
      "export const render = (value) => format(value);",
      ...Array(20).fill(""),
      "const unrelated = true;",
    ].join("\n"),
  );
  await writeFile(
    join(root, "api", "package-lock.json"),
    '{"test-format":"2.0"}',
  );
  await writeFile(
    join(root, "compose.yaml"),
    "services:\n  api:\n    build: ./api\n    environment:\n      TOKEN: private\n",
  );
  await writeFile(join(root, "other", "Dockerfile"), "FROM node");
  await writeFile(join(root, "node_modules", "copied.js"), "test-format");
  await writeFile(join(root, ".env"), "test-format");

  const { files, limitations } = await collectDependencyEvidence(root, [
    "TEST-FORMAT",
  ]);
  expect(files.map(({ path }) => path).sort()).toEqual([
    "api/app.js",
    "api/package-lock.json",
    "compose.yaml",
  ]);
  const source = files.find(({ path }) => path === "api/app.js")!;
  expect(source.lines).toContainEqual({
    number: 3,
    text: "export const render = (value) => format(value);",
  });
  expect(JSON.stringify(files)).not.toContain("unrelated");
  expect(JSON.stringify(files)).not.toContain("private");
  expect(limitations).toEqual([]);
});

test("inspects the current worktree and excludes ignored files and external links", async () => {
  const root = await temporaryDirectory();
  const outside = await temporaryDirectory();
  const git = (...args: string[]) => execFileSync("git", ["-C", root, ...args]);
  git("init", "--quiet");
  await writeFile(join(root, "package.json"), "{}");
  git("add", "package.json");
  await writeFile(join(root, "package.json"), '{"name":"test-package"}');
  await writeFile(join(root, "fresh.ts"), "import 'test-package';");
  await writeFile(join(root, ".gitignore"), "ignored.ts\n");
  await writeFile(join(root, "ignored.ts"), "test-package");
  await writeFile(join(outside, "private.ts"), "test-package");
  await symlink(
    outside,
    join(root, "linked"),
    process.platform === "win32" ? "junction" : "dir",
  );

  const { files } = await collectDependencyEvidence(root, ["test-package"]);
  expect(files.map(({ path }) => path).sort()).toEqual([
    "fresh.ts",
    "package.json",
  ]);
});

test("reports evidence omissions and incomplete package discovery", async () => {
  const root = await temporaryDirectory();
  await writeFile(
    join(root, "app.js"),
    'import "review-pkg";\n' + "x".repeat(100_000),
  );
  const { files, limitations } = await collectDependencyEvidence(root, [
    "review-pkg",
  ]);
  expect(files[0]?.lines).toEqual([
    { number: 1, text: 'import "review-pkg";' },
  ]);
  expect(limitations.length).toBeGreaterThan(0);
  const missing = await collectDependencyEvidence(root, ["different-package"]);
  expect(missing.files).toEqual([]);
  expect(missing.limitations.length).toBeGreaterThan(0);
});

test("surfaces gaps even when smaller non-vendored files match", async () => {
  const root = await temporaryDirectory();
  await mkdir(join(root, "vendor"));
  await writeFile(join(root, "vendor", "copy.js"), "dependency");
  await writeFile(join(root, "app.js"), "dependency");
  await writeFile(join(root, "generated.js"), "");
  await truncate(join(root, "generated.js"), 17 * 1024 * 1024);
  const { files, limitations } = await collectDependencyEvidence(root, [
    "dependency",
  ]);
  expect(files.map(({ path }) => path)).toEqual(["app.js"]);
  expect(limitations).toHaveLength(2);
});

test("claims complete coverage only while the reviewer receives the whole checkout", async () => {
  const root = await temporaryDirectory();
  await writeFile(
    join(root, "package.json"),
    '{"dependencies":{"known":"2.0"}}\n',
  );
  expect((await collectDependencyEvidence(root, ["known"])).complete).toBe(
    true,
  );

  await writeFile(join(root, "worker.js"), "startBackgroundWork();");
  expect((await collectDependencyEvidence(root, ["known"])).complete).toBe(
    false,
  );

  await writeFile(
    join(root, "worker.js"),
    "require('known');\n" + "other();\n".repeat(15),
  );
  expect((await collectDependencyEvidence(root, ["known"])).complete).toBe(
    false,
  );
  await writeFile(join(root, "worker.js"), "require('known');\n");
  expect((await collectDependencyEvidence(root, ["known"])).complete).toBe(
    true,
  );

  const outside = await temporaryDirectory();
  await symlink(
    outside,
    join(root, "external"),
    process.platform === "win32" ? "junction" : "dir",
  );
  expect((await collectDependencyEvidence(root, ["known"])).complete).toBe(
    false,
  );
});
