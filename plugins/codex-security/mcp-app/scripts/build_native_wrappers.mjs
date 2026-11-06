import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";

const windowsRenameDelays = [10, 25, 50, 100, 200, 400];

async function replaceWrapper(temporary, destination) {
  for (let attempt = 0; ; attempt++) {
    try {
      await fs.rename(temporary, destination);
      return;
    } catch (error) {
      // A concurrent reader can temporarily deny delete sharing on Windows.
      const wait = windowsRenameDelays[attempt];
      if (
        process.platform !== "win32" ||
        wait === undefined ||
        !["EPERM", "EACCES", "EBUSY"].includes(error.code)
      )
        throw error;
      await delay(wait);
    }
  }
}

export async function buildNativeWrappers(
  root = resolve(import.meta.dirname, "../../native"),
) {
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
  const publications = await Promise.allSettled(
    result.outputFiles.map(async (file) => {
      const temporary = `${file.path}.${randomUUID()}.tmp`;
      try {
        await fs.writeFile(temporary, file.contents);
        await replaceWrapper(temporary, file.path);
      } finally {
        await fs.rm(temporary, { force: true });
      }
    }),
  );
  // A build process may exit as soon as its caller sees an error. Let every
  // in-flight wrapper finish publishing or cleaning up its own staged file.
  for (const publication of publications)
    if (publication.status === "rejected") throw publication.reason;
}
