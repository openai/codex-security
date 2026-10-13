import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterEach, expect, test } from "bun:test";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-replay-home-",
);
afterEach(cleanup);

test("Node CLI replay preserves symlink/.. homes for resume and rerun", async () => {
  if (
    runTestInSubprocess(
      import.meta.path,
      "Node CLI replay preserves symlink/.. homes for resume and rerun",
    )
  )
    return;
  // Bun's realpath collapses these components; exercise the supported Node runtime.
  const bundle = await mkdtemp(join(import.meta.dir, "..", ".replay-home-"));
  const root = await temporaryDirectory();
  try {
    const built = await Bun.build({
      entrypoints: [
        join(import.meta.dir, "support", "replay-profile-home.mts"),
      ],
      outdir: bundle,
      target: "node",
      packages: "external",
    });
    expect(built.success).toBe(true);
    const { stdout } = await promisify(execFile)(
      "node",
      [
        "--input-type=module",
        "--eval",
        `await import(${JSON.stringify(pathToFileURL(built.outputs[0]!.path).href)})`,
        "synthetic-launcher",
        root,
      ],
      { encoding: "utf8" },
    );
    const proof = JSON.parse(stdout);
    expect(proof.canonicalControl).toEqual(proof.privateConfig);
    expect(proof.results).toHaveLength(6);
    for (const result of proof.results) {
      expect(
        result.code,
        `${result.command}/${result.spelling}: ${result.error}`,
      ).toBe(0);
      expect(result.launches).toBe(1);
      expect(result.observed).toMatchObject(proof.privateConfig);
      expect(result.profileUnchanged).toBe(true);
      expect(result.environmentUnchanged).toBe(true);
    }
  } finally {
    await rm(bundle, { recursive: true, force: true });
  }
});
