import assert from "node:assert/strict";
import {
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const modules = ["artifact-worker-scan-draft.ts"];
for (const name of modules) {
  const bundle = await build({
    absWorkingDir: path.dirname(fileURLToPath(import.meta.url)),
    entryPoints: [`../src/${name}`],
    bundle: true,
    format: "esm",
    platform: "node",
    write: false,
  });
  const { saveScanDraftCheckpoint } = await import(
    `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`
  );
  for (const layout of ["scan", "reducer", "worker"]) {
    const root = await realpath(
      await mkdtemp(path.join(tmpdir(), "codex-checkpoint-compat-")),
    );
    try {
      const context = { root, repoRoot: root, layout };
      const snapshot = {
        scanId: "7b95abf2-dc04-47a9-9950-53b5c2057f49",
        findings: [],
        scope: { summary: "Synthetic saved scope." },
      };
      await saveScanDraftCheckpoint(context, snapshot);
      const checkpoint = (await readdir(path.join(root, "checkpoints"))).find(
        (entry) => entry.endsWith(".json"),
      );
      const checkpointPath = path.join(root, "checkpoints", checkpoint);
      const legacyBytes = JSON.stringify(snapshot, null, 2) + "\n";
      await writeFile(checkpointPath, legacyBytes);
      await saveScanDraftCheckpoint(context, snapshot);
      assert.equal(
        await readFile(checkpointPath, "utf8"),
        legacyBytes,
        "retry retains the original checkpoint bytes",
      );
      const changedBytes =
        JSON.stringify(
          { ...snapshot, findings: [{ title: "Changed checkpoint" }] },
          null,
          2,
        ) + "\n";
      await writeFile(checkpointPath, changedBytes);
      await assert.rejects(
        saveScanDraftCheckpoint(context, snapshot),
        /existing content does not match its digest/,
      );
      assert.equal(
        await readFile(checkpointPath, "utf8"),
        changedBytes,
        "a rejected retry does not rewrite the existing evidence",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }
}
console.log("legacy checkpoint serialization retries passed");
