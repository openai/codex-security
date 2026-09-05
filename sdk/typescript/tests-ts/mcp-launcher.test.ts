import { spawnSync } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test.skipIf(process.platform !== "win32")(
  "launches the PATH Node executable independently of command extensions and the caller directory",
  async () => {
    const node = Bun.which("node");
    if (node === null)
      throw new Error("Node is required for the launcher test.");
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-launch-")),
    );
    try {
      const caller = join(root, "caller");
      const runtime = join(root, "Node runtime");
      const scripts = join(root, "plugin", "scripts");
      const server = join(root, "plugin", "mcp", "server.mjs");
      await Promise.all(
        [caller, runtime, scripts, join(root, "plugin", "mcp")].map(
          (directory) => mkdir(directory, { recursive: true }),
        ),
      );
      const launcher = join(scripts, "launch_codex_security_mcp.cmd");
      await copyFile(
        join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp.cmd"),
        launcher,
      );
      await copyFile(node, join(runtime, "node.exe"));
      await writeFile(
        server,
        `console.log(JSON.stringify({ executable: process.execPath, cwd: process.cwd(), args: process.argv.slice(2) }));\nprocess.exitCode = 23;\n`,
      );
      const marker = join(root, "command-used");
      for (const directory of [caller, runtime]) {
        for (const name of ["node.cmd", "where.cmd"]) {
          await writeFile(
            join(directory, name),
            `@echo off\n> "${marker}" echo used\nexit /b 0\n`,
          );
        }
      }
      // Native candidates in the caller directory must not participate either.
      await copyFile(node, join(caller, "node.exe"));
      await copyFile(node, join(caller, "where.exe"));
      for (const path of [
        runtime,
        `"${runtime}"`,
        `;.;;relative-bin;${runtime};`,
      ]) {
        const result = spawnSync(
          join(process.env["SystemRoot"]!, "System32", "cmd.exe"),
          ["/d", "/s", "/c", `""${launcher}" --stdio "argument with spaces""`],
          {
            cwd: caller,
            env: {
              SystemRoot: process.env["SystemRoot"],
              PATH: path,
              PATHEXT: ".CMD;.EXE;.BAT;.COM",
            },
            encoding: "utf8",
            windowsHide: true,
            windowsVerbatimArguments: true,
          },
        );
        expect(
          result.status,
          `PATH=${path}\n${result.stderr || result.error?.message || ""}`,
        ).toBe(23);
        expect(JSON.parse(result.stdout)).toEqual({
          executable: join(runtime, "node.exe"),
          cwd: parse(launcher).root,
          args: ["--stdio", "argument with spaces"],
        });
        await expect(readFile(marker)).rejects.toMatchObject({
          code: "ENOENT",
        });
      }
      const missing = spawnSync(
        join(process.env["SystemRoot"]!, "System32", "cmd.exe"),
        ["/d", "/s", "/c", `""${launcher}" --stdio"`],
        {
          cwd: caller,
          env: {
            SystemRoot: process.env["SystemRoot"],
            PATH: ";.;relative-bin;",
          },
          encoding: "utf8",
          windowsHide: true,
          windowsVerbatimArguments: true,
        },
      );
      expect(missing.status, missing.stderr || missing.error?.message).toBe(
        127,
      );
      expect(missing.stdout).toBe("");
      expect(missing.stderr).toContain("could not find a Node runtime");
      await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

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
