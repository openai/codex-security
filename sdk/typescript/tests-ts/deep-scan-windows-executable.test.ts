import * as fs from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import * as module from "node:module";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { expect, test } from "bun:test";
import { loadBundledRuntime, PLUGIN_ROOT } from "./plugin-root.js";

async function bundledResolver() {
  const runtime = await loadBundledRuntime();
  const start = runtime.indexOf("function resolveCodexPath(");
  const end = runtime.indexOf("\n// server.ts", start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const source = runtime.slice(start, end);
  const imports = [
    ...new Set(source.match(/import_node_(?:fs|path|module)\d*/gu)),
  ];
  return new Function(...imports, `${source}\nreturn resolveCodexPath;`)(
    ...imports.map((name) =>
      name.startsWith("import_node_fs")
        ? fs
        : name.startsWith("import_node_path")
          ? path
          : module,
    ),
  ) as (
    env: NodeJS.ProcessEnv,
    platform: NodeJS.Platform,
    architecture: NodeJS.Architecture,
  ) => string;
}

test("uses the newest relocated Windows executable when WindowsApps is inaccessible", async () => {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "codex-security-executable-")),
  );
  try {
    const older = path.join(
      root,
      "OpenAI",
      "Codex",
      "bin",
      "11111111",
      "codex.exe",
    );
    const newer = path.join(
      root,
      "OpenAI",
      "Codex",
      "bin",
      "22222222",
      "codex.exe",
    );
    const empty = path.join(
      root,
      "OpenAI",
      "Codex",
      "bin",
      "33333333",
      "codex.exe",
    );
    for (const executable of [older, newer, empty]) {
      await mkdir(path.dirname(executable), { recursive: true });
      await writeFile(
        executable,
        executable === empty ? "" : "synthetic executable",
      );
    }
    await utimes(older, 1, 1);
    await utimes(newer, 2, 2);
    const resolve = await bundledResolver();
    const environment = {
      PATH: "",
      LOCALAPPDATA: root,
      CODEX_CLI_PATH: "C:\\Program Files\\WindowsApps\\Codex\\codex.exe",
    };
    expect(resolve(environment, "win32", "x64")).toBe(newer);
    expect(
      resolve(
        { ...environment, CODEX_CLI_PATH: "C:\\Tools\\codex.exe" },
        "win32",
        "x64",
      ),
    ).toBe("C:\\Tools\\codex.exe");
    expect(resolve({ PATH: "" }, "win32", "x64")).toBe(
      path.resolve("codex.exe"),
    );
    expect(resolve({}, "linux", "x64")).toBe(path.resolve("codex"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  ["x64", "x86_64-pc-windows-msvc"],
  ["arm64", "aarch64-pc-windows-msvc"],
] as const)(
  "resolves a managed Windows %s worker through the packaged MCP environment",
  async (architecture, targetTriple) => {
    const root = await realpath(
      await mkdtemp(path.join(tmpdir(), "codex-security-managed-cli-")),
    );
    try {
      const packages = path.join(
        root,
        "managed CLI",
        "node_modules",
        "@openai",
      );
      const packageRoot = path.join(packages, "codex");
      const platformPackage = path.join(
        packages,
        `codex-win32-${architecture}`,
      );
      const executable = path.join(
        platformPackage,
        "vendor",
        targetTriple,
        "bin",
        "codex.exe",
      );
      await mkdir(packageRoot, { recursive: true });
      await mkdir(path.dirname(executable), { recursive: true });
      await writeFile(path.join(packageRoot, "package.json"), "{}\n");
      await writeFile(path.join(platformPackage, "package.json"), "{}\n");
      await writeFile(executable, "synthetic executable\n");

      const configuration = JSON.parse(
        await readFile(path.join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
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
      const resolve = await bundledResolver();

      expect(resolve(environment, "win32", architecture)).toBe(executable);
      const configured = path.join(root, "custom CLI", "codex.exe");
      expect(
        resolve(
          { ...environment, CODEX_CLI_PATH: configured },
          "win32",
          architecture,
        ),
      ).toBe(configured);
      expect(resolve(environment, "linux", architecture)).toBe(
        path.resolve("codex"),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("does not retry Windows executable permission failures", async () => {
  const runtime = await loadBundledRuntime();
  const source =
    /function classifyCodexWorkerError\([^\n]*\) \{[\s\S]*?\n\}/u.exec(
      runtime,
    )?.[0];
  expect(source).toBeDefined();
  class NonRetryableError extends Error {}
  const classify = new Function(
    "DeepScanNonRetryableError",
    `${source}\nreturn classifyCodexWorkerError;`,
  )(NonRetryableError) as (error: Error) => Error;
  const original = Object.assign(new Error("spawn codex EPERM"), {
    code: "EPERM",
  });
  const result = classify(original);
  expect(result).toBeInstanceOf(NonRetryableError);
  expect(result.cause).toBe(original);
});
