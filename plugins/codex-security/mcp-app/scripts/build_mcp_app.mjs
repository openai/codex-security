#!/usr/bin/env node
import { realpathSync, statSync } from "node:fs";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { delimiter, dirname, join, resolve } from "node:path";
import { brotliCompressSync, constants as zlibConstants } from "node:zlib";
import { execFileSync, execSync } from "node:child_process";
import { build } from "esbuild";
import { buildNativeWrappers } from "./build_native_wrappers.mjs";

const root = resolve(import.meta.dirname, "..");

async function runAppBuild() {
  const options = { cwd: root, stdio: "inherit" };
  const binDirectory = join("node_modules", ".bin");
  if (process.platform !== "win32" || join(root, binDirectory).length < 260) {
    execFileSync(process.execPath, ["--run", "build"], options);
    return;
  }
  if (process.versions.bun) {
    // Bun reserves `build` for its bundler unless `run` is explicit.
    execFileSync(process.execPath, ["run", "build"], options);
    return;
  }

  // Node's Windows task runner can skip a long package.json or .bin directory
  // and select an ancestor's script or compiler.
  const manifest = join(root, "package.json");
  const { scripts } = JSON.parse(await readFile(manifest, "utf8"));
  const bins = [];
  for (let dir = root; dir !== dirname(dir); dir = dirname(dir)) {
    const bin = join(dir, binDirectory);
    if (statSync(bin, { throwIfNoEntry: false })?.isDirectory()) bins.push(bin);
  }
  const env = { ...process.env };
  const pathKey = Object.keys(env).find((key) => key.toLowerCase() === "path");
  if (pathKey !== undefined)
    env[pathKey] = [...bins, env[pathKey]].join(delimiter);
  execSync(scripts.build, {
    ...options,
    env: {
      ...env,
      NODE_RUN_SCRIPT_NAME: "build",
      NODE_RUN_PACKAGE_JSON_PATH: manifest,
    },
  });
}

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
  const nativeFiles = contract.shippedExact.filter(
    (file) =>
      file.startsWith("mcp/native/") &&
      (!hostTarget ||
        !file.endsWith(".node") ||
        file.startsWith(`mcp/native/${hostTarget}/`)),
  );
  if (hostTarget && !nativeFiles.some((file) => file.endsWith(".node"))) {
    throw new Error(`Unsupported native target: ${hostTarget}.`);
  }

  await runAppBuild();
  await rm(mcpDir, { recursive: true, force: true });
  await mkdir(mcpDir, { recursive: true });
  // A standalone plugin can live on a UNC share. End Node's package lookup
  // here before it probes for package.json above the share root.
  await writeFile(join(mcpDir, "package.json"), '{"private":true}\n');

  await writeRuntime("server", "main.ts");
  for (const file of nativeFiles) {
    const path = file.slice("mcp/native/".length);
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
    entryPoints: [join(root, "src/session-decompression.ts")],
    format: "esm",
    outfile: join(mcpDir, "session-decompression.mjs"),
    platform: "node",
    target: "node20",
  });
  await copyFile(
    join(root, "node_modules/fzstd/LICENSE"),
    join(mcpDir, "fzstd-LICENSE.txt"),
  );
  await build({
    bundle: true,
    entryPoints: [join(root, "src/deep-scan/permission-profile-preflight.ts")],
    format: "esm",
    outfile: join(mcpDir, "permission-profile-preflight.mjs"),
    platform: "node",
    target: "node20",
  });

  await build({
    bundle: true,
    entryPoints: [
      join(root, "../../../sdk/typescript/scripts/plugin-scan-owners.mts"),
    ],
    format: "esm",
    outfile: join(mcpDir, "scan-owners.mjs"),
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
    const payload = name + ".mjs.br";
    await writeFile(join(mcpDir, payload), runtime);
    await writeFile(join(mcpDir, name + ".mjs"), loader(payload), "utf8");
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

function loader(payload) {
  return `import { readFile } from "node:fs/promises";
import { dirname } from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { brotliDecompressSync } from "node:zlib";

const compressedRuntime = await readFile(new URL("./${payload}", import.meta.url));
const runtimeSource = brotliDecompressSync(compressedRuntime).toString("utf8");
const require = createRequire(import.meta.url);
const Module = require("node:module");
const loaderPath = fileURLToPath(import.meta.url);
const runtimeModule = new Module(loaderPath);
runtimeModule.filename = loaderPath;
runtimeModule.paths = Module._nodeModulePaths(dirname(loaderPath));
runtimeModule._compile(runtimeSource, loaderPath);
export default runtimeModule.exports;
`;
}
