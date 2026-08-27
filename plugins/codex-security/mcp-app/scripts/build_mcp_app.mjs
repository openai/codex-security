#!/usr/bin/env node
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { brotliCompressSync, constants as zlibConstants } from "node:zlib";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
const maxChunkBytes = 140_000;

export async function buildMcpApp({ output }) {
  const mcpDir = resolve(output);

  execFileSync(process.execPath, ["--run", "build"], {
    cwd: root,
    stdio: "inherit"
  });
  await rm(mcpDir, { recursive: true, force: true });
  await mkdir(mcpDir, { recursive: true });

  await writeRuntime("server", "main.ts");

  async function writeRuntime(name, entryPoint) {
    const bundle = join(mcpDir, name + ".bundle.cjs");
    try {
      await build({
        bundle: true,
        define: { "import.meta.url": "__filename" },
        entryPoints: [join(root, entryPoint)],
        external: ["fsevents"],
        format: "cjs",
        loader: { ".md": "text" },
        logLevel: "info",
        logOverride: { "empty-import-meta": "silent" },
        outfile: bundle,
        platform: "node",
        target: "node20"
      });
      const runtime = brotliCompressSync(await readFile(bundle), {
        params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 10 }
      });
      const chunkPrefix = name + ".mjs.br.part-";
      await writeFile(join(mcpDir, name + ".mjs"), loader(chunkPrefix), "utf8");
      for (
        let offset = 0, index = 0;
        offset < runtime.length;
        offset += maxChunkBytes, index += 1
      ) {
        await writeFile(
          join(mcpDir, chunkPrefix + String(index).padStart(3, "0")),
          runtime.subarray(offset, offset + maxChunkBytes)
        );
      }
    } finally {
      await rm(bundle, { force: true });
    }
  }
}

const invokedPath = process.argv[1];
if (
  invokedPath !== undefined
  && pathToFileURL(resolve(invokedPath)).href === import.meta.url
) {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--output") {
    console.error("Usage: node scripts/build_mcp_app.mjs --output <directory>");
    process.exitCode = 1;
  } else {
    buildMcpApp({ output: args[1] }).catch((error) => {
      console.error(error instanceof Error ? error.message : error);
      process.exitCode = 1;
    });
  }
}

function loader(chunkPrefix) {
  return `import { Buffer } from "node:buffer";
import { readFile, readdir } from "node:fs/promises";
import { dirname } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync } from "node:zlib";

const runtimeChunkNames = (await readdir(new URL("./", import.meta.url)))
  .filter((name) => name.startsWith("${chunkPrefix}"))
  .sort();
if (!runtimeChunkNames.length) {
  throw new Error("Missing compressed Codex Security MCP server runtime chunks.");
}
const compressedRuntime = Buffer.concat(
  await Promise.all(runtimeChunkNames.map((name) => readFile(new URL(\`./\${name}\`, import.meta.url))))
);
const runtimeSource = brotliDecompressSync(compressedRuntime).toString("utf8");
const require = createRequire(import.meta.url);
const Module = require("node:module");
const loaderPath = fileURLToPath(import.meta.url);
const runtimeModule = new Module(loaderPath);
runtimeModule.filename = loaderPath;
runtimeModule.paths = Module._nodeModulePaths(dirname(loaderPath));
runtimeModule._compile(runtimeSource, loaderPath);
`;
}
