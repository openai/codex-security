import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);

test("loads the draft fixture from a checkout path containing spaces", async (t) => {
  const checkout = await mkdtemp(path.join(tmpdir(), "test module paths "));
  t.after(() => rm(checkout, { recursive: true, force: true }));
  const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
  const application = path.join(
    checkout,
    "plugins",
    "codex-security",
    "mcp-app",
  );
  const tests = path.join(application, "tests");
  await mkdir(tests, { recursive: true });
  await symlink(
    path.resolve(applicationRoot, "../../../sdk"),
    path.join(checkout, "sdk"),
    "junction",
  );
  for (const entry of ["schemas", "native"])
    await symlink(
      path.resolve(applicationRoot, "..", entry),
      path.join(application, "..", entry),
      "junction",
    );
  for (const entry of [
    "scan-draft-recovery-fixture.ts",
    "import-module.ts",
    "support",
  ]) {
    await cp(
      path.join(applicationRoot, "tests", entry),
      path.join(tests, entry),
      { recursive: true },
    );
  }
  for (const entry of ["src", "node_modules"]) {
    await symlink(
      path.join(applicationRoot, entry),
      path.join(application, entry),
      "junction",
    );
  }
  const fixture = pathToFileURL(
    path.join(tests, "scan-draft-recovery-fixture.ts"),
  );
  const { stdout } = await exec(process.execPath, [
    "--experimental-strip-types",
    "--input-type=module",
    "-e",
    'const fixture = await import(process.argv[1]); if (typeof fixture.draftFixture !== "function") throw new Error("Draft fixture was not loaded.");',
    fixture.href,
  ]);
  assert.equal(stdout, "");
});
