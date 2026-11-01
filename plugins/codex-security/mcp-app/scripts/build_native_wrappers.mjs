import { randomUUID } from "node:crypto";
import { rename, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { build } from "esbuild";

export async function buildNativeWrappers() {
  const root = resolve(import.meta.dirname, "../../native");
  const result = await build({
    absWorkingDir: root,
    entryPoints: ["*.mts"],
    outdir: root,
    outExtension: { ".js": ".mjs" },
    format: "esm",
    platform: "node",
    target: "node20",
    write: false,
  });
  // Concurrent runtime builds must never import a partially written wrapper.
  await Promise.all(
    result.outputFiles.map(async (file) => {
      const temporary = `${file.path}.${randomUUID()}.tmp`;
      try {
        await writeFile(temporary, file.contents);
        await rename(temporary, file.path);
      } finally {
        await rm(temporary, { force: true });
      }
    }),
  );
}
