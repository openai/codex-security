import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runCommand } from "./support/shell.js";

const repository = fileURLToPath(new URL("../../..", import.meta.url));
let root: string;
let linkedRepository: string;
let compiled: string;
let preload: string;
let environment: NodeJS.ProcessEnv;

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "script entrypoints "));
  linkedRepository = join(root, "linked checkout");
  compiled = join(root, "compiled");
  preload = join(root, "stop-main.mjs");
  environment = {
    ...process.env,
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_EVENT_PATH: join(root, "event.json"),
    GITHUB_REPOSITORY: "example/project",
    GITHUB_SHA: "1".repeat(40),
    GITHUB_OUTPUT: join(root, "output"),
    GITHUB_STEP_SUMMARY: "",
    PR_NUMBER: undefined,
  };
  await mkdir(compiled);
  await symlink(repository, linkedRepository, "junction");
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({ name: "@openai/codex-security", version: "99.1.2" }),
  );
  await writeFile(join(root, "event.json"), "{}");
  await writeFile(
    preload,
    `
    import childProcess from "node:child_process";
    import syncFs from "node:fs";
    import fs from "node:fs/promises";
    import http from "node:http";
    import { syncBuiltinESMExports } from "node:module";
    function entered() { throw new Error("SCRIPT_MAIN_REACHED"); }
    globalThis.fetch = entered;
    childProcess.execFile = entered;
    childProcess.execFileSync = entered;
    http.createServer = entered;
    fs.mkdtemp = entered;
    const readFile = fs.readFile;
    fs.readFile = (path, ...args) => String(path).endsWith("plugin-files.json")
      ? entered() : readFile(path, ...args);
    const readFileSync = syncFs.readFileSync;
    syncFs.readFileSync = (path, ...args) => String(path).endsWith(".node")
      ? entered() : readFileSync(path, ...args);
    syncBuiltinESMExports();
  `,
  );
  const build = await runCommand(
    "node",
    ["--run", "build:examples", "--", "--outDir", compiled],
    {
      cwd: join(repository, "sdk", "typescript"),
      timeout: 30_000,
    },
  );
  expect(build.status, build.stderr).toBe(0);
  const native = await runCommand(
    "node",
    ["--run", "build:ci", "--", "--outDir", compiled],
    {
      cwd: join(repository, "sdk", "typescript"),
      timeout: 30_000,
    },
  );
  expect(native.status, native.stdout + native.stderr).toBe(0);
  await symlink(compiled, join(root, "linked compiled"), "junction");
  await symlink(
    join(compiled, "app.mjs"),
    join(root, "linked app.mjs"),
    "file",
  );
});

afterAll(async () => {
  await rm(root, { recursive: true, force: true });
});

const scripts = {
  "sdk/typescript/scripts/release-automation.mjs": "releaseVersion",
  "sdk/typescript/scripts/release-pr.mjs": null,
  "sdk/typescript/scripts/check-plugin-source.mjs": null,
  "sdk/typescript/scripts/build-plugin.mjs": "buildBundledPlugin",
  "sdk/typescript/scripts/smoke-published-package.mjs": null,
  "plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs": "buildMcpApp",
  "plugins/codex-security/native/check.mjs": "checkPrivatePaths",
  ".github/scripts/invoice-desk-source.mjs": null,
  ".github/scripts/invoice-desk-target.mjs": null,
  "app.mjs": null,
};

function linkedScript(script: string) {
  if (script === "app.mjs") return join(root, "linked app.mjs");
  if (script === "plugins/codex-security/native/check.mjs")
    return join(root, "linked compiled", script);
  return join(linkedRepository, script);
}

test("imports maintainer scripts and their exports from Node stdin and eval", async () => {
  const modules = Object.entries(scripts).map(([script, exported]) => [
    pathToFileURL(linkedScript(script)).href,
    exported,
  ]);
  const source = `
    for (const [url, name] of ${JSON.stringify(modules)}) {
      const module = await import(url);
      if (name && typeof module[name] !== "function")
        throw new Error(url + " must export " + name);
    }
    console.log("Imported all scripts");
  `;
  for (const mode of [
    ["-"],
    ["--eval", source],
    ["--eval", source, "unrelated argument"],
  ]) {
    const result = await runCommand(
      "node",
      ["--import", pathToFileURL(preload).href, "--input-type=module", ...mode],
      {
        input: mode[0] === "-" ? source : undefined,
        env: environment,
        timeout: 30_000,
      },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toBe("Imported all scripts\n");
    expect(result.stderr).toBe("");
  }
});

test.each(Object.keys(scripts))("runs %s through symlinks", async (script) => {
  const native = script === "plugins/codex-security/native/check.mjs";
  const pluginScript = native || script.endsWith("build_mcp_app.mjs");
  const direct =
    script === "app.mjs" || native
      ? join(compiled, script)
      : join(repository, script);
  const linked = linkedScript(script);
  const version = script.endsWith("release-automation.mjs");
  const target = script.endsWith("invoice-desk-target.mjs");
  const args = version
    ? ["version", join(root, "package.json")]
    : script.endsWith("build_mcp_app.mjs")
      ? ["--output", join(root, "mcp")]
      : [];

  for (const invocation of [
    [direct],
    [linked],
    ["--preserve-symlinks-main", linked],
    ...(pluginScript
      ? [
          ["-predictable", direct],
          ["-expose-gc", direct],
        ]
      : []),
  ]) {
    const result = await runCommand(
      "node",
      ["--import", pathToFileURL(preload).href, ...invocation, ...args],
      {
        env: environment,
        timeout: 30_000,
      },
    );
    expect(result.status, result.stderr).toBe(version || target ? 0 : 1);
    if (version) expect(result.stdout).toBe("99.1.2\n");
    else if (target)
      expect(result.stdout).toContain(
        `Main baseline at ${environment["GITHUB_SHA"]}`,
      );
    else expect(result.stderr).toContain("SCRIPT_MAIN_REACHED");
  }
  if (pluginScript) {
    const url = JSON.stringify(pathToFileURL(linked).href);
    const evalModule = [
      "--input-type=module",
      "--eval",
      `await import(${url})`,
    ];
    const expression = `void import(${url})`;
    for (const [command, mode, argument, stdout] of [
      ["node", evalModule, direct, ""],
      ["node", evalModule, linked, ""],
      ["node", ["-pe", expression], direct, "undefined\n"],
      [process.execPath, [`-e${expression}`], direct, ""],
      [process.execPath, [`-p${expression}`], direct, "undefined\n"],
    ] as const) {
      const result = await runCommand(
        command,
        [
          "--import",
          command === "node" ? pathToFileURL(preload).href : preload,
          ...mode,
          argument,
        ],
        { env: environment, timeout: 30_000 },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(stdout);
      expect(result.stderr).toBe("");
    }
  }
});
