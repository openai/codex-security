import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveNpm } from "./package-smoke-npm.mjs";
import { packageSmokeTimeouts } from "./package-smoke-timeouts.mjs";

const packageName = "@openai/codex-security";
const { commandTimeoutMs, installTimeoutMs } = packageSmokeTimeouts();

function run(command, args, options) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: "pipe",
    timeout: commandTimeoutMs,
    killSignal: "SIGKILL",
    windowsHide: true,
    ...options,
  });
}

export async function verifyInstalledPackage(consumer, environment) {
  const installedRoot = join(
    consumer,
    "node_modules",
    ...packageName.split("/"),
  );
  const manifest = JSON.parse(
    await readFile(join(installedRoot, "package.json"), "utf8"),
  );
  assert.equal(manifest.name, packageName);
  console.log(
    `Checking ${packageName}@${manifest.version} on ${process.platform}/${process.arch}, Node ${process.version}.`,
  );
  const options = { cwd: consumer, env: environment };
  const shim = join(
    consumer,
    "node_modules",
    ".bin",
    process.platform === "win32" ? "codex-security.cmd" : "codex-security",
  );
  function cli(argument) {
    return process.platform === "win32"
      ? run(
          environment.ComSpec ?? "cmd.exe",
          ["/d", "/s", "/c", `""${shim}" ${argument}"`],
          { ...options, windowsVerbatimArguments: true },
        )
      : run(shim, [argument], options);
  }
  assert.equal(cli("--version").trim(), manifest.version);
  assert.match(cli("--help"), /Usage: codex-security\b/u);

  // Resolve the public entrypoint from the consumer, without importing checkout code.
  const codex = JSON.parse(
    run(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `
    import assert from "node:assert/strict";
    import { CodexSecurity, resolveCodexCommand } from "${packageName}";
    const client = new CodexSecurity();
    assert.equal(typeof client.run, "function");
    await client.close();
    console.log(JSON.stringify(resolveCodexCommand({})));
  `,
      ],
      options,
    ),
  );
  assert.match(run(codex.command, ["--version"], options), /^codex-cli\s+\d/u);

  const pluginRoot = join(installedRoot, "_bundled_plugin");
  const configuration = JSON.parse(
    await readFile(join(pluginRoot, ".mcp.json"), "utf8"),
  );
  const server = configuration.mcpServers["codex-security"];
  const launcher = join(pluginRoot, server.command);
  const initialized = run(
    process.platform === "win32"
      ? (environment.ComSpec ?? "cmd.exe")
      : launcher,
    process.platform === "win32"
      ? ["/d", "/s", "/c", "call", `${launcher}.cmd`, ...server.args]
      : server.args,
    {
      ...options,
      cwd: pluginRoot,
      input: `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "published-install-smoke", version: "1.0.0" },
        },
      })}\n`,
    },
  );
  const response = JSON.parse(initialized.trim());
  assert.equal(response.id, 1);
  assert.equal(response.result.serverInfo.name, "codex-security");
  console.log(
    `Validated published ${packageName}@${manifest.version}: npm CLI shim, public SDK, bundled Codex, and plugin initialization.`,
  );
}

async function smokePublishedPackage() {
  const consumer = await mkdtemp(join(tmpdir(), "codex-security-published-"));
  try {
    await writeFile(
      join(consumer, "package.json"),
      JSON.stringify({
        name: "published-install-smoke",
        private: true,
        type: "module",
      }),
    );
    const npm = await resolveNpm();
    run(
      npm.command,
      [
        ...npm.args,
        "install",
        "--include=optional",
        "--package-lock=false",
        "--no-audit",
        "--no-fund",
        "--registry=https://registry.npmjs.org",
        `${packageName}@latest`,
      ],
      {
        cwd: consumer,
        timeout: installTimeoutMs,
        stdio: "inherit",
      },
    );

    const smokeHome = join(consumer, "home");
    await mkdir(smokeHome);
    await verifyInstalledPackage(consumer, {
      ...process.env,
      HOME: smokeHome,
      USERPROFILE: smokeHome,
      XDG_CONFIG_HOME: join(smokeHome, ".config"),
      XDG_CACHE_HOME: join(smokeHome, ".cache"),
      APPDATA: join(smokeHome, "AppData", "Roaming"),
      LOCALAPPDATA: join(smokeHome, "AppData", "Local"),
      CODEX_HOME: join(smokeHome, ".codex"),
      CODEX_SECURITY_STATE_DIR: join(smokeHome, ".codex-security"),
      CODEX_MCP_NODE_PATH: process.execPath,
    });
  } finally {
    await rm(consumer, {
      recursive: true,
      force: true,
      maxRetries: 10,
      retryDelay: 100,
    });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await smokePublishedPackage();
}
