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

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "script entrypoints "));
  linkedRepository = join(root, "linked checkout");
  compiled = join(root, "compiled");
  preload = join(root, "stop-main.mjs");
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

test.each([
  "sdk/typescript/scripts/release-automation.mjs",
  "sdk/typescript/scripts/release-pr.mjs",
  "sdk/typescript/scripts/check-plugin-source.mjs",
  "sdk/typescript/scripts/build-plugin.mjs",
  "sdk/typescript/scripts/smoke-published-package.mjs",
  "plugins/codex-security/mcp-app/scripts/build_mcp_app.mjs",
  "plugins/codex-security/native/check.mjs",
  ".github/scripts/invoice-desk-source.mjs",
  ".github/scripts/invoice-desk-target.mjs",
  "app.mjs",
])("runs %s through symlinks and stays inert when imported", async (script) => {
  const native = script === "plugins/codex-security/native/check.mjs";
  const pluginScript = native || script.endsWith("build_mcp_app.mjs");
  const direct =
    script === "app.mjs" || native
      ? join(compiled, script)
      : join(repository, script);
  const linked =
    script === "app.mjs"
      ? join(root, "linked app.mjs")
      : native
        ? join(root, "linked compiled", script)
        : join(linkedRepository, script);
  const version = script.endsWith("release-automation.mjs");
  const target = script.endsWith("invoice-desk-target.mjs");
  const args = version
    ? ["version", join(root, "package.json")]
    : script.endsWith("build_mcp_app.mjs")
      ? ["--output", join(root, "mcp")]
      : [];
  const environment = {
    ...process.env,
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_EVENT_PATH: join(root, "event.json"),
    GITHUB_REPOSITORY: "example/project",
    GITHUB_SHA: "1".repeat(40),
    GITHUB_OUTPUT: join(root, "output"),
    GITHUB_STEP_SUMMARY: "",
    PR_NUMBER: undefined,
  };
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
        `Main baseline at ${environment.GITHUB_SHA}`,
      );
    else expect(result.stderr).toContain("SCRIPT_MAIN_REACHED");
  }
  for (const argument of [
    [],
    ["unrelated argument"],
    ...(pluginScript ? [[direct], [linked]] : []),
  ]) {
    const result = await runCommand(
      "node",
      [
        "--import",
        pathToFileURL(preload).href,
        "--input-type=module",
        "--eval",
        `await import(${JSON.stringify(pathToFileURL(linked).href)})`,
        ...argument,
      ],
      { env: environment, timeout: 30_000 },
    );
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout + result.stderr).toBe("");
  }
  if (pluginScript) {
    const expression = `void import(${JSON.stringify(pathToFileURL(linked).href)})`;
    for (const [command, mode, stdout] of [
      ["node", ["-pe", expression], "undefined\n"],
      [process.execPath, [`-e${expression}`], ""],
      [process.execPath, [`-p${expression}`], "undefined\n"],
    ] as const) {
      const result = await runCommand(
        command,
        [
          "--import",
          command === "node" ? pathToFileURL(preload).href : preload,
          ...mode,
          direct,
        ],
        { env: environment, timeout: 30_000 },
      );
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe(stdout);
      expect(result.stderr).toBe("");
    }
  }
});
