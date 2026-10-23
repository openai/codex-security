import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const bundledPlugin =
  process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
  path.resolve(
    import.meta.dirname,
    "../../../../sdk/typescript/_bundled_plugin",
  );
const owner = "synthetic-state-owner";

async function copyPlugin(root) {
  const plugin = path.join(root, "plugin");
  await cp(bundledPlugin, plugin, { recursive: true });
  await chmod(plugin, 0o700);
  return plugin;
}

async function startHost({
  root,
  plugin,
  caller,
  home,
  configuredState,
  state,
  pythonCommand,
}) {
  const repository = path.join(root, "repository");
  const scanRoot = path.join(root, "scans");
  await Promise.all([
    mkdir(caller, { recursive: true, mode: 0o700 }),
    mkdir(repository, { mode: 0o700 }),
    mkdir(scanRoot, { mode: 0o700 }),
  ]);
  await writeFile(
    path.join(repository, "app.py"),
    "print('synthetic fixture')\n",
  );
  const environment = {
    ...process.env,
    CODEX_SECURITY_PLUGIN_ROOT: plugin,
    CODEX_SECURITY_SCAN_ROOT: scanRoot,
    CODEX_HOME: home,
    CODEX_SECURITY_KNOWLEDGE_BASE: "",
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: path.join(
      root,
      "absent-deep-config.toml",
    ),
    // Register the public request, then stop at real executable preflight.
    CODEX_CLI_PATH: path.join(root, "missing-codex"),
    CODEX_API_KEY: "",
    OPENAI_API_KEY: "",
  };
  if (configuredState === undefined)
    delete environment.CODEX_SECURITY_STATE_DIR;
  else environment.CODEX_SECURITY_STATE_DIR = configuredState;
  if (pythonCommand !== undefined) {
    environment.PYTHON = pythonCommand;
    delete environment.CODEX_SECURITY_PYTHON_COMMAND;
  }
  let client;
  const connect = async () => {
    client = new Client({
      name: "native-state-directory-test",
      version: "1.0.0",
    });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [path.join(plugin, "mcp/server.mjs"), "--stdio"],
        cwd: caller,
        env: environment,
      }),
    );
  };
  await connect();
  const workbench = (args, input) =>
    JSON.parse(
      execFileSync(
        process.env.PYTHON ?? "python3",
        [path.join(plugin, "scripts/workbench_db.py"), ...args],
        {
          cwd: plugin,
          env: environment,
          encoding: "utf8",
          ...(input === undefined ? {} : { input: JSON.stringify(input) }),
        },
      ),
    );
  const call = (name, arguments_) =>
    client.callTool({
      name,
      arguments: arguments_,
      _meta: {
        "openai/threadId": owner,
        "codex/sandbox-state-meta": {
          permissionProfile: {
            type: "managed",
            file_system: {
              type: "restricted",
              entries: [
                {
                  path: { type: "special", value: { kind: "root" } },
                  access: "read",
                },
              ],
            },
            network: "restricted",
          },
          sandboxCwd: pathToFileURL(repository).href,
        },
      },
    });
  const fresh = async (targetPath = repository) => {
    const result = await call("start_codex_security_deep_scan", { targetPath });
    assert.equal(result.isError, true);
    assert.match(result.content[0].text, /Codex executable/i);
    const scans = workbench(["list-scans"]).scans;
    const matches = scans.filter((scan) => scan.targetPath === targetPath);
    assert.equal(
      matches.length,
      1,
      "the public request registers in the selected state directory",
    );
    return workbench(["get-scan", "--scan-id", matches[0].scanId]).scan;
  };
  return {
    repository,
    state,
    workbench,
    call,
    fresh,
    async restart() {
      await client.close();
      await connect();
    },
    async close() {
      await client.close();
    },
  };
}

function successful(result) {
  assert.notEqual(result.isError, true, result.content?.[0]?.text);
  return result.structuredContent;
}

for (const variant of [
  "absolute",
  "relative",
  "relative symlink parent",
  "literal-space state",
  "whitespace-only state",
  "named-user state",
  "empty fallback",
  "literal-space home",
  "symlink parent home",
]) {
  test(
    `native MCP shares state for fresh, resumed and stopped scans: ${variant}`,
    {
      skip:
        [
          "literal-space home",
          "literal-space state",
          "whitespace-only state",
        ].includes(variant) && process.platform === "win32"
          ? "Windows does not support a trailing-space directory component."
          : variant === "named-user state" && process.platform === "win32"
            ? "Named-user expansion uses the POSIX user database."
            : false,
    },
    async () => {
      const root = await realpath(
        await mkdtemp(path.join(tmpdir(), "native-state-directory-")),
      );
      let host;
      try {
        const plugin = await copyPlugin(root);
        const caller = path.join(root, "caller");
        let home = path.join(
          root,
          variant === "literal-space home" ? " codex home " : "home",
        );
        await mkdir(home, { mode: 0o700 });
        let physicalHome = home;
        if (variant === "symlink parent home") {
          physicalHome = path.join(root, "physical-home");
          const nested = path.join(physicalHome, "nested");
          await mkdir(nested, { recursive: true, mode: 0o700 });
          const link = path.join(root, "home-link");
          await symlink(
            nested,
            link,
            process.platform === "win32" ? "junction" : "dir",
          );
          home = `${link}${path.sep}..`;
          physicalHome = await realpath(home);
        }
        let state = path.join(root, "selected-state");
        let configuredState = state;
        if (variant === "relative") {
          configuredState = "selected-state";
          state = path.join(plugin, configuredState);
        } else if (variant === "relative symlink parent") {
          const physicalParent = path.join(root, "physical-state-parent");
          const nested = path.join(physicalParent, "nested");
          await mkdir(nested, { recursive: true, mode: 0o700 });
          const link = path.join(plugin, "state-link");
          await symlink(
            nested,
            link,
            process.platform === "win32" ? "junction" : "dir",
          );
          configuredState = `state-link${path.sep}..${path.sep}selected-state`;
          state = path.join(
            await realpath(`${link}${path.sep}..`),
            "selected-state",
          );
        } else if (variant === "literal-space state") {
          state = path.join(root, " selected state ");
          configuredState = state;
        } else if (variant === "whitespace-only state") {
          configuredState = "   ";
          state = path.join(plugin, configuredState);
        } else if (variant === "named-user state") {
          const account = userInfo();
          configuredState = `~${account.username}/${path.relative(await realpath(account.homedir), state)}`;
        } else if (
          [
            "empty fallback",
            "literal-space home",
            "symlink parent home",
          ].includes(variant)
        ) {
          configuredState = variant === "empty fallback" ? "" : undefined;
          state = path.join(physicalHome, "state", "plugins", "codex-security");
        }
        host = await startHost({
          root,
          plugin,
          caller,
          home,
          configuredState,
          state,
        });
        const scan = await host.fresh();
        const { scanId, scanDir, handoffClaimToken } = scan;
        host.workbench(
          [
            "register-cli-scan",
            "--repository",
            host.repository,
            "--scan-dir",
            scanDir,
            "--registration-json-stdin",
          ],
          {
            scanId,
            threadId: owner,
            claimToken: handoffClaimToken,
            recipe: {
              repository: host.repository,
              mode: "deep",
              target: { kind: "repository", paths: [] },
              config: {},
            },
          },
        );
        host.workbench([
          "set-scan-thread",
          "--scan-id",
          scanId,
          "--claim-token",
          handoffClaimToken,
          "--thread-id",
          "synthetic-merge",
        ]);
        host.workbench(
          [
            "save-scan-artifact",
            "--scan-id",
            scanId,
            "--claim-token",
            handoffClaimToken,
            "--artifact-path",
            "artifacts/deep-scan/checkpoint.json",
          ],
          {
            version: 2,
            passes: [],
            mergedScanIds: [],
            aggregate: null,
            terminalReason: "capped",
          },
        );
        successful(
          await host.call("record_codex_security_scan_draft", {
            scanId,
            handoffClaimToken,
            findings: [],
            coverage: {
              completeness: "complete",
              surfaces: [
                { label: "Synthetic fixture", disposition: "rejected" },
              ],
              explicitExclusions: [],
              deferred: [],
            },
          }),
        );
        host.workbench([
          "prepare-scan-completion",
          "--scan-id",
          scanId,
          "--claim-token",
          handoffClaimToken,
        ]);
        await host.restart();
        const completed = successful(
          await host.call("start_codex_security_deep_scan", {
            scanId,
            handoffClaimToken,
          }),
        );
        assert.equal(completed.scanId, scanId);
        assert.equal(
          host.workbench(["get-scan", "--scan-id", scanId]).scan.progress
            .status,
          "complete",
        );
        assert.ok((await readFile(completed.reportPath, "utf8")).length > 0);

        const canceledRepository = path.join(root, "canceled-repository");
        await mkdir(canceledRepository, { mode: 0o700 });
        await writeFile(
          path.join(canceledRepository, "app.py"),
          "print('cancel fixture')\n",
        );
        const canceled = await host.fresh(canceledRepository);
        successful(
          await host.call("cancel_codex_security_scan", {
            scanId: canceled.scanId,
          }),
        );
        assert.equal(
          host.workbench(["get-scan", "--scan-id", canceled.scanId]).scan
            .progress.status,
          "canceled",
        );
        const lockKey = createHash("sha256")
          .update(await realpath(canceled.scanDir))
          .digest("hex");
        assert.equal(
          (
            await stat(path.join(state, "scan-execution", `${lockKey}.lock`))
          ).isFile(),
          true,
        );
        assert.equal(host.workbench(["list-scans"]).scans.length, 2);
      } finally {
        await host?.close();
        await rm(root, { recursive: true, force: true });
      }
    },
  );
}

test("concurrent native MCP hosts isolate the same relative state setting", async () => {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "native-state-isolation-")),
  );
  const hosts = [];
  try {
    for (const name of ["first", "second"]) {
      const hostRoot = path.join(root, name);
      const caller = path.join(hostRoot, "caller");
      const home = path.join(hostRoot, "home");
      await mkdir(home, { recursive: true, mode: 0o700 });
      const plugin = await copyPlugin(hostRoot);
      hosts.push(
        await startHost({
          root: hostRoot,
          plugin,
          caller,
          home,
          configuredState: "state",
          state: path.join(plugin, "state"),
        }),
      );
    }
    const scans = await Promise.all(hosts.map((host) => host.fresh()));
    assert.notEqual(scans[0].scanId, scans[1].scanId);
    for (const [index, host] of hosts.entries()) {
      assert.deepEqual(
        host.workbench(["list-scans"]).scans.map((scan) => scan.scanId),
        [scans[index].scanId],
      );
      assert.equal(
        host.workbench(["get-scan", "--scan-id", scans[index].scanId]).scan
          .targetPath,
        host.repository,
      );
    }
  } finally {
    await Promise.all(hosts.map((host) => host.close()));
    await rm(root, { recursive: true, force: true });
  }
});

test("explicit native MCP state does not inspect an unused Codex home", async () => {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "native-state-unused-home-")),
  );
  let host;
  try {
    const plugin = await copyPlugin(root);
    const home = path.join(root, "unused-home");
    await symlink(
      home,
      home,
      process.platform === "win32" ? "junction" : "dir",
    );
    const state = path.join(root, "selected-state");
    host = await startHost({
      root,
      plugin,
      caller: path.join(root, "caller"),
      home,
      configuredState: state,
      state,
    });
    const result = successful(await host.call("list_codex_security_scans", {}));
    assert.deepEqual(result.scans, []);
    assert.equal(
      (await stat(path.join(state, "workbench.sqlite3"))).isFile(),
      true,
    );
  } finally {
    await host?.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("native MCP state selection recovers when its Python helper becomes available", async () => {
  const root = await realpath(
    await mkdtemp(path.join(tmpdir(), "native-state-late-python-")),
  );
  let host;
  try {
    const plugin = await copyPlugin(root);
    const home = path.join(root, "home");
    await mkdir(home, { mode: 0o700 });
    const interpreter = execFileSync(
      process.env.PYTHON ?? "python3",
      ["-c", "import sys; print(sys.executable)"],
      { encoding: "utf8" },
    ).trim();
    const lateRuntime = path.join(root, "late-python");
    const pythonCommand = path.join(lateRuntime, path.basename(interpreter));
    const state = path.join(root, "selected-state");
    host = await startHost({
      root,
      plugin,
      caller: path.join(root, "caller"),
      home,
      configuredState: state,
      state,
      pythonCommand,
    });
    const missing = await host.call("list_codex_security_scans", {});
    assert.equal(missing.isError, true);
    assert.match(
      missing.content[0].text,
      /could not start its Python 3 helper/i,
    );
    assert.ok(missing.content[0].text.includes(pythonCommand));
    await symlink(
      path.dirname(interpreter),
      lateRuntime,
      process.platform === "win32" ? "junction" : "dir",
    );
    const recovered = successful(
      await host.call("list_codex_security_scans", {}),
    );
    assert.deepEqual(recovered.scans, []);
    assert.equal(
      (await stat(path.join(state, "workbench.sqlite3"))).isFile(),
      true,
    );
  } finally {
    await host?.close();
    await rm(root, { recursive: true, force: true });
  }
});
