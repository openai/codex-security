import * as fs from "node:fs";
import { EventEmitter } from "node:events";
import {
  mkdir,
  mkdtemp,
  realpath,
  rm,
  utimes,
  writeFile,
} from "node:fs/promises";
import * as module from "node:module";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createInterface } from "node:readline";
import { PassThrough } from "node:stream";
import { expect, test } from "bun:test";
import { loadBundledRuntime } from "./plugin-root.js";

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
    const accessible = path.join(root, "WindowsApps", "Codex", "codex.exe");
    await mkdir(path.dirname(accessible), { recursive: true });
    await writeFile(accessible, "synthetic executable", { mode: 0o700 });
    expect(
      resolve({ ...environment, CODEX_CLI_PATH: accessible }, "win32", "x64"),
    ).toBe(accessible);
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

test("preserves preflight failure diagnostics until stderr closes", async () => {
  const runtime = await loadBundledRuntime();
  const source = /var AppServerPreflightClient = class \{[\s\S]*?\n\};/u.exec(
    runtime,
  )![0];
  const child = Object.assign(new EventEmitter(), {
    stdin: new PassThrough(),
    stdout: new PassThrough(),
    stderr: new PassThrough(),
    exitCode: null as number | null,
    signalCode: null,
    kill: () => {},
  });
  const helpers = [
    "codexExecutableExitError",
    "codexExecutableFailureError",
    "codexExecutableFailureMessage",
    "quotedExecutable",
  ]
    .map(
      (name) =>
        new RegExp(
          `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
          "u",
        ).exec(runtime)![0],
    )
    .join("\n");
  const Client = new Function(
    /\b(import_node_child_process\d*)\.spawn/u.exec(source)![1]!,
    /\b(import_node_readline\d*)\.createInterface/u.exec(source)![1]!,
    "DeepScanNonRetryableError",
    `${source}\n${helpers}\nreturn AppServerPreflightClient;`,
  )({ spawn: () => child }, { createInterface }, Error) as new (options: {
    codexPath: string;
    cwd: string;
    configOverrides: string[];
    signal: AbortSignal;
  }) => { request(method: string): Promise<unknown>; close(): Promise<void> };
  const client = new Client({
    codexPath: "synthetic-codex",
    cwd: process.cwd(),
    configOverrides: [],
    signal: new AbortController().signal,
  });
  const pending = client.request("initialize");
  child.stderr.write("Invalid configuration.\n");
  child.exitCode = 1;
  child.emit("exit", 1, null);
  child.stderr.end("Check synthetic.toml.\n");
  child.stdout.end();
  child.emit("close", 1, null);
  try {
    await expect(pending).rejects.toThrow(
      "Invalid configuration.\nCheck synthetic.toml.",
    );
  } finally {
    await client.close();
  }
});
