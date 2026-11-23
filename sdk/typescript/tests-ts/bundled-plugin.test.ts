import { execFile } from "node:child_process";
import { mkdir, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const directories = createTemporaryDirectories(false);
afterEach(directories.cleanup);

test.each([
  [
    "plugin CommonJS entrypoint",
    "cjs",
    ["plugin with spaces", "mcp"],
    ["plugin with spaces"],
  ],
  ["SDK ESM entrypoint", "esm", ["sdk", "dist"], ["sdk", "_bundled_plugin"]],
  [
    "SDK ESM entrypoint with colocated plugin",
    "esm",
    ["sdk", "dist"],
    ["sdk", "dist", "_bundled_plugin"],
  ],
] as const)(
  "resolves the plugin from a built %s",
  async (_name, format, moduleParts, pluginParts) => {
    const root = await directories.create("codex-security-bundled-plugin-");
    const plugin = join(root, ...pluginParts);
    await mkdir(join(plugin, ".codex-plugin"), { recursive: true });
    await writeFile(
      join(plugin, ".codex-plugin", "plugin.json"),
      JSON.stringify({ name: "synthetic-plugin" }),
    );
    const entrypoint = join(
      root,
      ...moduleParts,
      format === "cjs" ? "runtime.cjs" : "runtime.mjs",
    );
    await build({
      entryPoints: [
        fileURLToPath(new URL("../src/bundled-plugin.ts", import.meta.url)),
      ],
      outfile: entrypoint,
      bundle: true,
      platform: "node",
      format,
      target: "node20",
      ...(format === "cjs"
        ? { define: { "import.meta.url": "__filename" } }
        : {}),
    });
    const { stdout } = await promisify(execFile)(
      "node",
      [
        "--input-type=module",
        "--eval",
        `const runtime = await import(process.argv[1]); process.stdout.write(await ${format === "cjs" ? "runtime.default" : "runtime"}.bundledPluginRoot());`,
        pathToFileURL(entrypoint).href,
      ],
      { encoding: "utf8", windowsHide: true },
    );
    expect(stdout).toBe(await realpath(plugin));
  },
);
