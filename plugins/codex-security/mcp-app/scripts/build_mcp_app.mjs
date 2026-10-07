#!/usr/bin/env node
import { realpathSync } from "node:fs";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { brotliCompressSync, constants as zlibConstants } from "node:zlib";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";
import { buildNativeWrappers } from "./build_native_wrappers.mjs";

const root = resolve(import.meta.dirname, "..");
const maxChunkBytes = 140_000;

export async function buildMcpApp({ output, native = "universal" }) {
  if (native !== "universal" && native !== "host") {
    throw new Error("Native packaging must be universal or host.");
  }
  await buildNativeWrappers();
  const mcpDir = resolve(output);
  const nativeRoot = join(
    root,
    "../native",
    native === "host" ? "dist" : "prebuilt",
  );
  const hostTarget =
    native === "host"
      ? (await import("../../native/platform.mjs")).nativeTarget
      : undefined;
  const contract = JSON.parse(
    await readFile(join(root, "../plugin-files.json"), "utf8"),
  );
  const nativeFiles = contract.shippedExact.filter((path) =>
    path.startsWith("mcp/native/"),
  );
  if (
    hostTarget &&
    !nativeFiles.some(
      (path) =>
        path.startsWith(`mcp/native/${hostTarget}/`) && path.endsWith(".node"),
    )
  ) {
    throw new Error(`Unsupported native target: ${hostTarget}.`);
  }

  execFileSync(process.execPath, ["--run", "build"], {
    cwd: root,
    stdio: "inherit",
  });
  await rm(mcpDir, { recursive: true, force: true });
  await mkdir(mcpDir, { recursive: true });

  await writeRuntime("server", "main.ts");
  for (const file of nativeFiles) {
    const path = file.slice("mcp/native/".length);
    if (
      hostTarget &&
      path.endsWith(".node") &&
      !path.startsWith(`${hostTarget}/`)
    ) {
      continue;
    }
    const destination = join(mcpDir, "native", path);
    await mkdir(dirname(destination), { recursive: true });
    try {
      await copyFile(join(nativeRoot, path), destination);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const preparation =
        native === "host"
          ? "Run node plugins/codex-security/mcp-app/scripts/build_native.mjs first."
          : "Download a source-matched native-universal artifact as described in plugins/codex-security/native/README.md before running SDK tests or universal builds.";
      throw new Error(
        `Missing native payload ${path}. ${preparation} ${error.message}`,
        {
          cause: error,
        },
      );
    }
  }
  await writeRuntime("helpers", "helpers-main.ts");
  await build({
    bundle: true,
    entryPoints: [join(root, "src/deep-scan/permission-profile-preflight.ts")],
    format: "esm",
    outfile: join(mcpDir, "permission-profile-preflight.mjs"),
    platform: "node",
    target: "node20",
  });

  async function writeRuntime(name, entryPoint) {
    const bundle = join(mcpDir, name + ".bundle.cjs");
    const result = await build({
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
      plugins: [
        {
          name: "native-typescript-source",
          setup(builder) {
            builder.onResolve({ filter: /\.mjs$/ }, (args) => {
              const source = resolve(args.resolveDir, args.path);
              if (dirname(source) === resolve(root, "../native")) {
                return { path: source.slice(0, -4) + ".mts" };
              }
            });
          },
        },
      ],
      target: "node20",
      write: false,
    });
    const runtime = brotliCompressSync(result.outputFiles[0].contents, {
      params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 10 },
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
        runtime.subarray(offset, offset + maxChunkBytes),
      );
    }
  }
}

function isMain() {
  if (
    process.execArgv.some(
      (argument) =>
        /^(?:--(?:eval|print)(?:=|$)|-(?:e|p|pe)$)/u.test(argument) ||
        (process.versions["bun"] !== undefined && /^-[ep]/u.test(argument)),
    )
  )
    return false;
  try {
    return (
      process.argv[1] !== undefined &&
      process.argv[1] !== "-" &&
      realpathSync(process.argv[1]) === realpathSync(new URL(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isMain()) {
  const args = process.argv.slice(2);
  if (
    args[0] !== "--output" ||
    (args.length !== 2 && !(args.length === 4 && args[2] === "--native"))
  ) {
    console.error(
      "Usage: node scripts/build_mcp_app.mjs --output <directory> [--native universal|host]",
    );
    process.exitCode = 1;
  } else {
    buildMcpApp({ output: args[1], native: args[3] }).catch((error) => {
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
