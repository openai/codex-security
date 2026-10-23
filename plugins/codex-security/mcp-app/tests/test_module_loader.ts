import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
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

for (const [loader, entryPoint] of [
  ["test_artifact_scan_draft.ts", "artifact-scan-draft.ts"],
  ["test_candidate_inventory.ts", "helpers/normalize-candidates.ts"],
  ["test_scan_handoff.mjs", "scan-handoff.ts"],
] as const) {
  test(`bundles ${loader} from a checkout path containing spaces`, async (t) => {
    const checkout = await mkdtemp(path.join(tmpdir(), "test loader paths "));
    t.after(() => rm(checkout, { recursive: true, force: true }));
    const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
    const tests = path.join(checkout, "tests");
    await mkdir(tests);
    for (const entry of [loader, "import-module.ts", "support"])
      await cp(
        path.join(applicationRoot, "tests", entry),
        path.join(tests, entry),
        { recursive: true },
      );
    await symlink(
      path.join(applicationRoot, "node_modules"),
      path.join(checkout, "node_modules"),
      "junction",
    );
    const source = path.join(checkout, "src", entryPoint);
    await mkdir(path.dirname(source), { recursive: true });
    // The real loader must bundle and evaluate its entrypoint before the test body runs.
    const marker = "Synthetic loader entrypoint evaluated";
    await writeFile(source, `throw new Error(${JSON.stringify(marker)});\n`);
    const { stdout } = await exec(process.execPath, [
      "--experimental-strip-types",
      "--input-type=module",
      "-e",
      `try { await import(process.argv[1]); throw new Error("Entrypoint was not evaluated."); }
       catch (error) { if (error.message !== process.argv[2]) throw error; console.log(error.message); }`,
      pathToFileURL(path.join(tests, loader)).href,
      marker,
    ]);
    assert.equal(stdout, `${marker}\n`);
  });
}
