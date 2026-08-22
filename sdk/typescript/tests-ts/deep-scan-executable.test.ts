import { existsSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

async function bundledCodexPathResolver() {
  const runtime = await loadBundledRuntime();
  const source = ["resolveCodexPath", "resolveWindowsPackageBinary"]
    .map((name) => {
      const definition = new RegExp(
        `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
        "u",
      ).exec(runtime)?.[0];
      if (!definition) throw new Error(`Missing bundled function: ${name}.`);
      return definition;
    })
    .join("\n");
  const fsImport = /\b(import_node_fs\d*)\.existsSync/u.exec(source)?.[1];
  const pathImport = /\b(import_node_path\d*)\.join/u.exec(source)?.[1];
  const moduleImport = /\b(import_node_module\d*)\.createRequire/u.exec(
    source,
  )?.[1];
  if (!fsImport || !pathImport || !moduleImport) {
    throw new Error("Bundled Codex resolver imports were not found.");
  }
  return new Function(
    fsImport,
    pathImport,
    moduleImport,
    `${source}\nreturn resolveCodexPath;`,
  )({ existsSync }, { delimiter, dirname, join }, { createRequire }) as (
    environment: NodeJS.ProcessEnv,
    platform: NodeJS.Platform,
    architecture: NodeJS.Architecture,
  ) => string;
}

test.each([
  ["x64", "x86_64-pc-windows-msvc"],
  ["arm64", "aarch64-pc-windows-msvc"],
] as const)(
  "resolves a managed Windows %s worker through the packaged MCP environment",
  async (architecture, targetTriple) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-managed-cli-")),
    );
    try {
      const packages = join(root, "managed CLI", "node_modules", "@openai");
      const packageRoot = join(packages, "codex");
      const platformPackage = join(packages, `codex-win32-${architecture}`);
      const executable = join(
        platformPackage,
        "vendor",
        targetTriple,
        "bin",
        "codex.exe",
      );
      await mkdir(packageRoot, { recursive: true });
      await mkdir(dirname(executable), { recursive: true });
      await writeFile(join(packageRoot, "package.json"), "{}\n");
      await writeFile(join(platformPackage, "package.json"), "{}\n");
      await writeFile(executable, "synthetic executable\n");

      const configuration = JSON.parse(
        await readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
      ) as { mcpServers: Record<string, { env_vars: string[] }> };
      const allowed = new Set(
        configuration.mcpServers["codex-security"]!.env_vars,
      );
      const environment = Object.fromEntries(
        Object.entries({
          PATH: "",
          CODEX_MANAGED_PACKAGE_ROOT: ` ${packageRoot} `,
        }).filter(([name]) => name === "PATH" || allowed.has(name)),
      );
      const resolveCodexPath = await bundledCodexPathResolver();

      expect(resolveCodexPath(environment, "win32", architecture)).toBe(
        executable,
      );
      const configured = join(root, "custom CLI", "codex.exe");
      expect(
        resolveCodexPath(
          { ...environment, CODEX_CLI_PATH: configured },
          "win32",
          architecture,
        ),
      ).toBe(configured);
      expect(resolveCodexPath(environment, "linux", architecture)).toBe(
        "codex",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
