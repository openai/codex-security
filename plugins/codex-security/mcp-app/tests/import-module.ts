import { build, type BuildOptions } from "esbuild";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const moduleDirectory = mkdtempSync(
  join(tmpdir(), "codex-security-test-modules-"),
);
const writtenModules = new Set<string>();
process.once("exit", () =>
  rmSync(moduleDirectory, { recursive: true, force: true }),
);

export async function importModule(options: BuildOptions) {
  const result = await build({
    bundle: true,
    format: "esm",
    platform: "node",
    nodePaths: [resolve(import.meta.dirname, "../node_modules")],
    write: false,
    ...options,
  });
  const contents = result.outputFiles![0].contents;
  // Keep content-based module identity without embedding the bundle in stacks.
  const digest = createHash("sha256").update(contents).digest("hex");
  const modulePath = join(moduleDirectory, `${digest}.mjs`);
  if (!writtenModules.has(modulePath)) {
    writeFileSync(modulePath, contents);
    writtenModules.add(modulePath);
  }
  return import(pathToFileURL(modulePath).href);
}

export function importSource(entryPoint: string, options: BuildOptions = {}) {
  return importModule({ entryPoints: [entryPoint], ...options });
}
