import { build, type BuildOptions } from "esbuild";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const moduleDirectory = mkdtempSync(
  join(tmpdir(), "codex-security-test-modules-"),
);
const writtenModules = new Set<string>();
process.once("exit", () =>
  rmSync(moduleDirectory, { recursive: true, force: true }),
);

export async function importModule(options: BuildOptions) {
  const result = await build({
    // Bundled CommonJS dependencies such as yaml load Node builtins.
    banner: {
      js: 'const require = process.getBuiltinModule("node:module").createRequire(import.meta.url);',
    },
    bundle: true,
    format: "esm",
    platform: "node",
    write: false,
    ...options,
  });
  const contents = result.outputFiles![0]!.contents;
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

export async function importCoordinatorServer(fixture: string) {
  const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
  const server = new URL("../server.ts", import.meta.url);
  const source = await readFile(server, "utf8");
  return importModule({
    stdin: {
      contents: source
        .replace(
          "const deepScanCoordinators = new DeepScanCoordinatorRegistry();",
          `const deepScanCoordinators = globalThis.${fixture}.registry;`,
        )
        .replace(
          'import { PLUGIN_ROOT, runWorkbench, scanRoot } from "./src/workbench-client.js";',
          `import { PLUGIN_ROOT, scanRoot } from "./src/workbench-client.js";\nconst runWorkbench = (...args) => globalThis.${fixture}.workbench(...args);`,
        ),
      loader: "ts",
      resolveDir: applicationRoot,
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(server.href),
    },
    loader: { ".md": "text" },
  });
}
