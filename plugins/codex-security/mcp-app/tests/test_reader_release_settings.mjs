import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  nodePaths: [fileURLToPath(new URL("../node_modules", import.meta.url))],
  entryPoints: [fileURLToPath(new URL("../src/deep-scan/recovery-settings.ts", import.meta.url))],
  platform: "node",
  format: "esm",
  write: false,
});
const { loadDeepScanExecutionSettings } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

for (const state of ["absent", "saved", "unsupported"]) {
  test(`reader release uses ${state} settings without persisting new metadata`, async () => {
    const root = await mkdtemp(join(tmpdir(), "reader-settings-"));
    const path = join(root, "artifacts", "deep_discovery", "execution-settings.json");
    try {
      let contextReads = 0;
      const readLegacyContext = async () => { contextReads++; return { config: {} }; };
      const original = { workflowVersion: "deep-security-scan/v1", model: "original-model", reasoningEffort: "high", createdAt: "2026-01-01T00:00:00Z", usageOwner: null };
      let bytes;
      if (state !== "absent") {
        await mkdir(join(root, "artifacts", "deep_discovery"), { recursive: true });
        bytes = JSON.stringify({ version: state === "unsupported" ? 99 : 1, settings: { codexPath: join(root, "codex"), codexHome: root, parentSandbox: { filesystemDenies: [] } } });
        await writeFile(path, bytes);
      }
      const loaded = await loadDeepScanExecutionSettings(root, original, readLegacyContext);
      assert.equal(loaded.model, "original-model");
      assert.equal(loaded.reasoningEffort, "high");
      assert.equal(loaded.codexPath, undefined);
      assert.equal(loaded.codexHome, undefined);
      assert.equal(contextReads, 1, "legacy recovery ignores planted execution artifacts");
      if (state === "absent") await assert.rejects(stat(path), { code: "ENOENT" });
      else assert.equal(await readFile(path, "utf8"), bytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
