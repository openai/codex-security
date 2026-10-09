import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  readdir,
  readFile,
  symlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { nativeTarget } from "../../native/platform.mts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const directories = createTemporaryDirectories(true);
after(() => directories.cleanup());
const sourcePluginRoot = path.resolve(import.meta.dirname, "../..");
const pluginRoot = process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT
  ? path.resolve(process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT)
  : path.resolve(sourcePluginRoot, "../../sdk/typescript/_bundled_plugin");

function shellQuote(value: string): string {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

async function fixture(rejectManaged: boolean, rejectOrdinary = false) {
  const root = await directories.create("codex-security-node-launcher-");
  const launcher = path.join(root, "scripts", "launch_codex_security_mcp");
  const mcp = path.join(root, "mcp");
  const addon = path.join(mcp, "native", `darwin-${process.arch}`, "unix.node");
  const log = path.join(root, "loads.jsonl");
  const launchLog = path.join(root, "launches.jsonl");
  const repo = path.join(root, "repo");
  await Promise.all(
    [
      path.dirname(launcher),
      path.dirname(addon),
      repo,
      path.join(root, "preflight"),
    ].map((directory) => mkdir(directory, { recursive: true })),
  );
  // Keep host-installed Node runtimes out of the simulated macOS runtime set.
  const tools = path.join(root, "shell-tools");
  await mkdir(tools);
  for (const name of ["dirname", "od", "tr"]) {
    const executable = spawnSync("/bin/sh", ["-c", `command -v ${name}`], {
      encoding: "utf8",
    }).stdout.trim();
    await symlink(executable, path.join(tools, name));
  }
  const source = await readFile(
    path.join(sourcePluginRoot, "scripts", path.basename(launcher)),
    "utf8",
  );
  await writeFile(
    launcher,
    source.replace(/^PATH=.*$/m, `PATH="\${PATH}:"${shellQuote(tools)}`),
  );
  for (const entry of await readdir(path.join(pluginRoot, "mcp"), {
    withFileTypes: true,
  })) {
    if (entry.isFile())
      await copyFile(
        path.join(pluginRoot, "mcp", entry.name),
        path.join(mcp, entry.name),
      );
  }
  await copyFile(
    path.join(pluginRoot, "mcp", "native", nativeTarget, "unix.node"),
    addon,
  );
  await copyFile(
    path.join(sourcePluginRoot, "preflight", "capability-profiles.toml"),
    path.join(root, "preflight", "capability-profiles.toml"),
  );
  await writeFile(
    path.join(repo, "SECURITY.md"),
    "Synthetic repository policy.\n",
  );
  await writeFile(path.join(root, "config.toml"), "");

  async function runtime(label: string, executable: string, reject: boolean) {
    const preload = path.join(root, `${label}.cjs`);
    await mkdir(path.dirname(executable), { recursive: true });
    await writeFile(
      preload,
      `
const { appendFileSync } = require("node:fs");
appendFileSync(${JSON.stringify(launchLog)}, JSON.stringify({ runtime: ${JSON.stringify(label)}, argv: process.argv.slice(1) }) + "\\n");
Object.defineProperty(process, "platform", { value: "darwin" });
const dlopen = process.dlopen;
process.dlopen = function(module, filename, ...args) {
  appendFileSync(${JSON.stringify(log)}, JSON.stringify({ runtime: ${JSON.stringify(label)}, filename, argv: process.argv.slice(1) }) + "\\n");
  ${reject ? 'throw new Error("dlopen: mapping process and mapped file have different Team IDs");' : "return dlopen.call(this, module, filename, ...args);"}
};
`,
    );
    await writeFile(
      executable,
      `#!/bin/sh\nexec ${shellQuote(process.execPath)} --require ${shellQuote(preload)} "$@"\n`,
      { mode: 0o755 },
    );
    return executable;
  }

  const managed = await runtime(
    "managed",
    path.join(
      root,
      "codex-runtimes/codex-primary-runtime/dependencies/node/bin/node",
    ),
    rejectManaged,
  );
  const ordinary = await runtime(
    "ordinary",
    path.join(root, "bin", "node"),
    rejectOrdinary,
  );
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: root,
    CODEX_HOME: root,
    PATH: path.dirname(ordinary),
    XDG_CACHE_HOME: root,
  };
  for (const name of [
    "CODEX_MCP_NODE_PATH",
    "CODEX_BROWSER_USE_NODE_PATH",
    "CODEX_ELECTRON_RESOURCES_PATH",
    "CODEX_CLI_PATH",
    "CODEX_SECURITY_CONFIG_PATH",
  ])
    delete env[name];
  return {
    root,
    repo,
    addon,
    managed,
    ordinary,
    async addPathRuntime() {
      const executable = await runtime(
        "later",
        path.join(root, "later-bin", "node"),
        false,
      );
      env.PATH += path.delimiter + path.dirname(executable);
    },
    run(args: string[], override?: string) {
      return spawnSync("/bin/sh", [launcher, "--helper", ...args], {
        cwd: root,
        env: {
          ...env,
          ...(override === undefined ? {} : { CODEX_MCP_NODE_PATH: override }),
        },
        encoding: "utf8",
        input: "preserved helper input\n",
      });
    },
    async loads() {
      return (await readFile(log, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
    },
    async launches() {
      return (await readFile(launchLog, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
    },
  };
}

test(
  "macOS helpers skip managed runtimes that reject the packaged addon",
  { skip: process.platform === "win32" },
  async () => {
    for (const command of ["config-preflight", "resolve-security-md"]) {
      const setup = await fixture(true);
      const result = setup.run(
        command === "config-preflight"
          ? [command, "--profile", "deep_security_scan", "--cwd", setup.repo]
          : [command, "--repo", setup.repo, "--list"],
      );
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      if (command === "config-preflight")
        assert.equal(JSON.parse(result.stdout).status, "ready");
      else assert.deepEqual(JSON.parse(result.stdout), ["SECURITY.md"]);
      const loads = await setup.loads();
      assert.deepEqual(
        loads.slice(0, 2).map((entry) => entry.runtime),
        ["managed", "ordinary"],
      );
      assert.equal(loads[0].filename, setup.addon);
      assert.equal(loads[1].filename, setup.addon);
      assert.equal(
        loads.filter((entry) => entry.runtime === "managed").length,
        1,
        "Rejected runtimes must only probe; helpers must not start in them.",
      );
      if (command === "config-preflight")
        assert.ok(
          loads.length > 2,
          "Config preflight must load the actual packaged addon.",
        );
    }
  },
);

test(
  "macOS helpers try later PATH runtimes after an incompatible first runtime",
  { skip: process.platform === "win32" },
  async () => {
    const setup = await fixture(true, true);
    await setup.addPathRuntime();
    const result = setup.run([
      "config-preflight",
      "--profile",
      "deep_security_scan",
      "--cwd",
      setup.repo,
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).status, "ready");
    assert.deepEqual(
      (await setup.loads()).slice(0, 3).map((entry) => entry.runtime),
      ["managed", "ordinary", "later"],
    );
    assert.deepEqual(
      (await setup.launches())
        .filter((entry) => entry.argv.includes("--helper"))
        .map((entry) => entry.runtime),
      ["later"],
    );
  },
);

test(
  "compatible managed runtimes retain priority over PATH",
  { skip: process.platform === "win32" },
  async () => {
    const setup = await fixture(false);
    const result = setup.run([
      "resolve-security-md",
      "--repo",
      setup.repo,
      "--list",
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.ok(
      (await setup.loads()).every((entry) => entry.runtime === "managed"),
    );
  },
);

test(
  "explicit runtime selection remains authoritative",
  { skip: process.platform === "win32" },
  async () => {
    const setup = await fixture(true);
    const result = setup.run(
      [
        "config-preflight",
        "--profile",
        "deep_security_scan",
        "--cwd",
        setup.repo,
      ],
      setup.managed,
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stdout, /different Team IDs/);
    const loads = await setup.loads();
    assert.ok(loads.every((entry) => entry.runtime === "managed"));
    assert.ok(
      loads[0].argv.includes("--helper"),
      "Explicit runtimes launch directly.",
    );
  },
);

test(
  "helper failures are reported without trying another runtime",
  { skip: process.platform === "win32" },
  async () => {
    const setup = await fixture(false);
    const result = setup.run([
      "resolve-security-md",
      "--repo",
      path.join(setup.root, "missing"),
      "--list",
    ]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /missing/);
    assert.ok(
      (await setup.loads()).every((entry) => entry.runtime === "managed"),
    );
  },
);

test(
  "helpers without native dependencies still run when all runtimes reject the addon",
  { skip: process.platform === "win32" },
  async () => {
    for (const command of [
      "validate-patch-risk-assessment",
      "resolve-security-md",
    ]) {
      const setup = await fixture(true, true);
      const result = setup.run(
        command === "resolve-security-md"
          ? [command, "--repo", setup.repo, "--list"]
          : [command, "--help"],
      );
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      if (command === "resolve-security-md")
        assert.deepEqual(JSON.parse(result.stdout), ["SECURITY.md"]);
      else assert.match(result.stdout, /usage:/i);
      assert.deepEqual(
        (await setup.loads()).map((entry) => entry.runtime),
        ["managed", "ordinary"],
      );
      const helpers = (await setup.launches()).filter((entry) =>
        entry.argv.includes("--helper"),
      );
      assert.deepEqual(
        helpers.map((entry) => entry.runtime),
        ["managed"],
        "The original default must launch the command exactly once.",
      );
    }
  },
);

test(
  "native commands retain their error when no compatible runtime exists",
  { skip: process.platform === "win32" },
  async () => {
    const setup = await fixture(true, true);
    const result = setup.run([
      "config-preflight",
      "--profile",
      "deep_security_scan",
      "--cwd",
      setup.repo,
    ]);
    assert.equal(result.status, 2);
    assert.equal(result.stderr, "");
    const report = JSON.parse(result.stdout);
    assert.equal(report.status, "error");
    assert.match(report.error, /different Team IDs/);
    assert.deepEqual(
      (await setup.loads()).map((entry) => entry.runtime),
      ["managed", "ordinary", "managed"],
    );
    const helpers = (await setup.launches()).filter((entry) =>
      entry.argv.includes("--helper"),
    );
    assert.deepEqual(
      helpers.map((entry) => entry.runtime),
      ["managed"],
      "A failing command must not retry in another runtime.",
    );
  },
);
