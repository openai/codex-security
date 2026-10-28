import { expect } from "bun:test";
import { fileURLToPath, pathToFileURL } from "node:url";

export async function buildPatchGitControlsForNode(
  directory: string,
): Promise<string> {
  // Node's type stripping does not resolve the source's .js imports to .ts.
  // Bundle those imports while retaining Node's filesystem implementation.
  const built = await Bun.build({
    entrypoints: [
      fileURLToPath(
        new URL("../../src/patch-git-controls.ts", import.meta.url),
      ),
    ],
    outdir: directory,
    naming: "[name].mjs",
    target: "node",
  });
  expect(built.success).toBe(true);
  return pathToFileURL(built.outputs[0]!.path).href;
}
