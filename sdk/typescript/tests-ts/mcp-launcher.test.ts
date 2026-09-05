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
import { join } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

test.each(["server", "helper"] as const)(
  "starts the packaged %s with managed Node and an empty PATH",
  async (mode) => {
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
        managedNode = join(root, "managed node");
        const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
        await writeFile(
          managedNode,
          `#!/bin/sh\nprintf used > ${quote(marker)}\nexec ${quote(node)} "$@"\n`,
        );
        await chmod(managedNode, 0o700);
      } else {
        const directory = join(root, "%RUNTIME%");
        await mkdir(directory);
        managedNode = join(directory, "node.cmd");
        await writeFile(
          managedNode,
          `@echo used>"${marker}"\r\n@"${node}" %*\r\n`,
        );
      }
      const launcher = join(PLUGIN_ROOT, config.command);
      const windows = process.platform === "win32";
      const args =
        mode === "helper"
          ? [
              "--helper",
              "resolve-security-md",
              "--repo",
              "repository with spaces",
              "--scope",
              ".",
              "--out",
              "output with spaces/guidance.md",
            ]
          : config.args;
      if (mode === "helper") {
        await mkdir(join(root, "repository with spaces"));
        await writeFile(
          join(root, "repository with spaces", "SECURITY.md"),
          "helper policy\n",
        );
      }
      const result = spawnSync(
        windows ? process.env["ComSpec"] ?? "cmd.exe" : launcher,
        windows
          ? [
              "/d",
              "/s",
              "/c",
              `""${launcher}.cmd" ${args.map((arg) => `"${arg}"`).join(" ")}"`,
            ]
          : args,
        {
          cwd: mode === "helper" ? root : PLUGIN_ROOT,
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
            RUNTIME: "other-runtime",
          },
          encoding: "utf8",
          // Bun 1.3.14 can report an immediate ETIMEDOUT for synchronous
          // Windows .cmd launches. The enclosing test timeout still bounds it.
          ...(windows ? {} : { timeout: 10_000 }),
          windowsHide: true,
          windowsVerbatimArguments: windows,
          input:
            mode === "server"
              ? JSON.stringify({
                  jsonrpc: "2.0",
                  id: 1,
                  method: "initialize",
                  params: {
                    protocolVersion: "2025-11-25",
                    capabilities: {},
                    clientInfo: { name: "launcher-test", version: "1.0.0" },
                  },
                }) + "\n"
              : undefined,
        },
      );
      expect(result.status, result.stderr || result.error?.message).toBe(0);
      if (mode === "helper") {
        expect(result.stdout).toBe("");
        expect(
          await readFile(
            join(root, "output with spaces", "guidance.md"),
            "utf8",
          ),
        ).toContain("helper policy");
      } else {
        expect(JSON.parse(result.stdout).result.serverInfo.name).toBe(
          "codex-security",
        );
      }
      expect((await readFile(marker, "utf8")).trim()).toBe("used");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.skipIf(process.platform !== "win32")(
  "returns helper status to a calling batch file and ignores repository Node candidates",
  async () => {
    const node = Bun.which("node");
    if (node === null)
      throw new Error("Node is required for the launcher test.");
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "helper-caller-")),
    );
    try {
      const runtime = join(root, "runtime with spaces");
      const repository = join(root, "repository with spaces");
      await mkdir(runtime);
      await mkdir(repository);
      const managedNode = join(runtime, "node.exe");
      await copyFile(node, managedNode);
      const batchNode = join(runtime, "managed-node.cmd");
      await writeFile(batchNode, `@"${managedNode}" %*\r\n`);
      await writeFile(join(repository, "SECURITY.md"), "repository policy\n");
      await mkdir(join(repository, "%POLICY%"));
      await writeFile(
        join(repository, "%POLICY%", "SECURITY.md"),
        "literal percent policy\n",
      );
      await mkdir(join(repository, "other"));
      await writeFile(
        join(repository, "other", "SECURITY.md"),
        "wrong policy\n",
      );
      await writeFile(join(repository, "node.exe"), "repository executable");
      await writeFile(
        join(repository, "node.cmd"),
        "@echo repository-node-executed\r\n@exit /b 99\r\n",
      );
      const caller = join(root, "caller.cmd");
      const launcher = join(
        PLUGIN_ROOT,
        "scripts",
        "launch_codex_security_mcp.cmd",
      );
      await writeFile(
        caller,
        [
          "@echo off",
          `call "${launcher}" --helper resolve-security-md --repo . --scope . --out "../guidance.md"`,
          "echo first-returned:%errorlevel%",
          `call "${launcher}" --helper resolve-security-md --repo . --scope missing`,
          "echo second-returned:%errorlevel%",
          'set "literal_scope=%%POLICY%%"',
          'set "literal_output=../%%OUTPUT%%.md"',
          `call "${launcher}" --helper resolve-security-md --repo . --scope "%%literal_scope%%" --out "%%literal_output%%"`,
          "echo percent-returned:%errorlevel%",
          "exit /b 0",
          "",
        ].join("\r\n"),
      );
      for (const mode of ["managed", "PATH", "batch"]) {
        await rm(join(root, "%OUTPUT%.md"), { force: true });
        const result = spawnSync(
          process.env["ComSpec"] ?? "cmd.exe",
          ["/d", "/s", "/c", `""${caller}""`],
          {
            cwd: repository,
            env: {
              SystemRoot: process.env["SystemRoot"],
              PATH: mode === "PATH" ? runtime : "",
              PATHEXT: ".CMD;.EXE;.BAT;.COM",
              HOME: root,
              USERPROFILE: root,
              LOCALAPPDATA: root,
              XDG_CACHE_HOME: root,
              POLICY: "other",
              OUTPUT: "wrong",
              ...(mode === "managed"
                ? { CODEX_MCP_NODE_PATH: managedNode }
                : mode === "batch"
                  ? { CODEX_MCP_NODE_PATH: batchNode }
                  : {}),
            },
            encoding: "utf8",
            windowsHide: true,
            windowsVerbatimArguments: true,
          },
        );
        expect(result.status, result.stderr || result.error?.message).toBe(0);
        expect(result.stdout).toBe(
          "first-returned:0\r\nsecond-returned:2\r\npercent-returned:0\r\n",
        );
        expect(result.stderr).toContain("scan scope does not exist");
        expect(await readFile(join(root, "guidance.md"), "utf8")).toContain(
          "repository policy",
        );
        expect(await readFile(join(root, "%OUTPUT%.md"), "utf8")).toContain(
          "literal percent policy",
        );
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
