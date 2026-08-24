import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test("starts the packaged MCP server with managed Node and an empty PATH", async () => {
  const node = Bun.which("node");
  if (node === null)
    throw new Error("Node is required for the MCP smoke test.");
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-node-")),
  );
  try {
    const config = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
    ).mcpServers["codex-security"] as {
      command: string;
      args: string[];
      env_vars: string[];
    };
    expect(config.env_vars).toContain("CODEX_MCP_NODE_PATH");
    let managedNode = node;
    const marker = join(root, "managed-node-used");
    if (process.platform !== "win32") {
      managedNode = join(root, "managed-node");
      const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
      await writeFile(
        managedNode,
        `#!/bin/sh\nprintf used > ${quote(marker)}\nexec ${quote(node)} "$@"\n`,
      );
      await chmod(managedNode, 0o700);
    }
    const launcher = join(PLUGIN_ROOT, config.command);
    const windows = process.platform === "win32";
    const result = spawnSync(
      windows ? process.env["ComSpec"] ?? "cmd.exe" : launcher,
      windows
        ? ["/d", "/s", "/c", `""${launcher}.cmd" ${config.args.join(" ")}"`]
        : config.args,
      {
        cwd: PLUGIN_ROOT,
        env: {
          PATH: "",
          HOME: root,
          USERPROFILE: root,
          LOCALAPPDATA: root,
          XDG_CACHE_HOME: root,
          ...(process.env["SystemRoot"] === undefined
            ? {}
            : { SystemRoot: process.env["SystemRoot"] }),
          CODEX_MCP_NODE_PATH: managedNode,
        },
        encoding: "utf8",
        // Bun 1.3.14 can report an immediate ETIMEDOUT for synchronous
        // Windows .cmd launches. The enclosing test timeout still bounds it.
        ...(windows ? {} : { timeout: 10_000 }),
        windowsHide: true,
        windowsVerbatimArguments: windows,
        input:
          JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2025-11-25",
              capabilities: {},
              clientInfo: { name: "launcher-test", version: "1.0.0" },
            },
          }) + "\n",
      },
    );
    expect(result.status, result.stderr || result.error?.message).toBe(0);
    expect(JSON.parse(result.stdout).result.serverInfo.name).toBe(
      "codex-security",
    );
    if (!windows) expect(await readFile(marker, "utf8")).toBe("used");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
