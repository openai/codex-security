import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";

const exec = promisify(execFile);

test("loads the coordinator fixture from a checkout path containing spaces", async (t) => {
  const checkout = await mkdtemp(path.join(tmpdir(), "test module paths "));
  t.after(() => rm(checkout, { recursive: true, force: true }));
  const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
  const tests = path.join(checkout, "tests");
  await mkdir(tests);
  for (const entry of [
    "deep_scan_coordinator_fixture.ts",
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
      path.join(checkout, entry),
      "junction",
    );
  }
  const fixture = pathToFileURL(
    path.join(tests, "deep_scan_coordinator_fixture.ts"),
  );
  const { stdout } = await exec(process.execPath, [
    "--experimental-strip-types",
    "--input-type=module",
    "-e",
    'const fixture = await import(process.argv[1]); if (typeof fixture.DeepScanCoordinator !== "function") throw new Error("Coordinator fixture was not loaded.");',
    fixture.href,
  ]);
  assert.equal(stdout, "");
});
