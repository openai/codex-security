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
import { dirname, join, parse } from "node:path";
import { expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { removeTemporaryDirectory } from "./support/temporary-directories.js";

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
      await removeTemporaryDirectory(root);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "preserves helper argument bytes, stdin, and exit status",
  async () => {
    const node = Bun.which("node");
    if (node === null)
      throw new Error("Node is required for the launcher test.");
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-helper-pipe-")),
    );
    try {
      const scripts = join(root, "plugin with spaces", "scripts");
      const mcp = join(root, "plugin with spaces", "mcp");
      await mkdir(scripts, { recursive: true });
      await mkdir(mcp);
      const launcher = join(scripts, "launch_codex_security_mcp");
      await copyFile(
        join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
        launcher,
      );
      await chmod(launcher, 0o700);
      await writeFile(
        join(mcp, "helpers.mjs"),
        `import { readFileSync } from "node:fs";
const payload = Buffer.from(readFileSync(3, "ascii").trim(), "hex");
console.log(JSON.stringify({
  args: process.argv.slice(2),
  payload: payload.toString("hex"),
  stdin: readFileSync(0).toString("hex"),
}));
process.exitCode = 23;
`,
      );
      const argument = 'space "quote" back\\slash\nline\t雪';
      const largeArgument = "x".repeat(70_000);
      const input = Buffer.from("original stdin\n\0tail");
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          'exec "$1" --helper probe "$2" "" "raw-$(printf \'\\377\')" "$3"',
          "helper-test",
          launcher,
          argument,
          largeArgument,
        ],
        {
          input,
          encoding: "utf8",
          env: { ...process.env, CODEX_MCP_NODE_PATH: node },
          maxBuffer: Infinity,
        },
      );
      expect(result.status, result.stderr || result.error?.message).toBe(23);
      expect(result.stderr).toBe("");
      const expectedPayload = Buffer.concat([
        Buffer.from(
          [
            process.env["HOME"] === undefined ? "" : "x",
            process.env["HOME"] ?? "",
            "probe",
            argument,
            "",
            "raw-",
          ].join("\0"),
        ),
        Buffer.from([0xff, 0]),
        Buffer.from(largeArgument + "\0"),
      ]);
      expect(JSON.parse(result.stdout)).toEqual({
        args: ["--helper"],
        payload: expectedPayload.toString("hex"),
        stdin: input.toString("hex"),
      });
    } finally {
      await removeTemporaryDirectory(root);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "launches argument-only helpers with closed stdin",
  async () => {
    const node = Bun.which("node");
    if (node === null)
      throw new Error("Node is required for the launcher test.");
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-helper-closed-stdin-")),
    );
    try {
      const scripts = join(root, "plugin with spaces", "scripts");
      const mcp = join(root, "plugin with spaces", "mcp");
      await mkdir(scripts, { recursive: true });
      await mkdir(mcp);
      const launcher = join(scripts, "launch_codex_security_mcp");
      await copyFile(
        join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
        launcher,
      );
      await chmod(launcher, 0o700);
      await writeFile(
        join(mcp, "helpers.mjs"),
        `import { readFileSync } from "node:fs";
const payload = Buffer.from(readFileSync(3, "ascii").trim(), "hex");
console.log(JSON.stringify({ payload: payload.toString("hex") }));
process.exitCode = 23;
`,
      );
      const result = spawnSync(
        "/bin/sh",
        [
          "-c",
          'exec 0<&-; exec "$1" --helper probe "argument with spaces"',
          "helper-test",
          launcher,
        ],
        {
          encoding: "utf8",
          env: { ...process.env, CODEX_MCP_NODE_PATH: node },
        },
      );
      expect(result.status, result.stderr || result.error?.message).toBe(23);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout)).toEqual({
        payload: Buffer.from(
          [
            process.env["HOME"] === undefined ? "" : "x",
            process.env["HOME"] ?? "",
            "probe",
            "argument with spaces",
            "",
          ].join("\0"),
        ).toString("hex"),
      });
    } finally {
      await removeTemporaryDirectory(root);
    }
  },
);

for (const mode of ["managed", "PATH"] as const) {
  test.skipIf(process.platform !== "darwin")(
    `resolves security policy with ${mode} Node and filesystem writes denied`,
    async () => {
      const node = Bun.which("node");
      if (node === null)
        throw new Error("Node is required for the launcher test.");
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-read-only-helper-")),
      );
      try {
        const repository = join(root, "repository with spaces");
        await mkdir(join(repository, "service"), { recursive: true });
        await writeFile(join(repository, "SECURITY.md"), "root policy\n");
        await writeFile(
          join(repository, "service", "SECURITY.md"),
          "scoped policy\n",
        );
        const result = spawnSync(
          "/usr/bin/sandbox-exec",
          [
            "-p",
            "(version 1) (allow default) (deny file-write*)",
            join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
            "--helper",
            "resolve-security-md",
            "--repo",
            repository,
            "--scope",
            "service",
            "--out",
            "-",
          ],
          {
            encoding: "utf8",
            env: {
              ...process.env,
              CODEX_MCP_NODE_PATH: mode === "managed" ? node : "",
              CODEX_BROWSER_USE_NODE_PATH: "",
              CODEX_ELECTRON_RESOURCES_PATH: "",
              CODEX_CLI_PATH: "",
              XDG_CACHE_HOME: join(root, "unused cache"),
              PATH: dirname(node),
            },
          },
        );
        expect(result.status, result.stderr || result.error?.message).toBe(0);
        expect(result.stderr).toBe("");
        expect(result.stdout).toContain("root policy\n");
        expect(result.stdout).toContain("scoped policy\n");
      } finally {
        await removeTemporaryDirectory(root);
      }
    },
  );
}

for (const [signal, exitCode] of [
  ["SIGTERM", 23],
  ["SIGINT", 130],
  ["SIGHUP", 129],
] as const) {
  test.skipIf(process.platform === "win32")(
    `forwards ${signal} and waits for the helper`,
    async () => {
      const node = Bun.which("node");
      if (node === null)
        throw new Error("Node is required for the launcher test.");
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-helper-signal-")),
      );
      try {
        const scripts = join(root, "scripts");
        const mcp = join(root, "mcp");
        await mkdir(scripts);
        await mkdir(mcp);
        const launcherPath = join(scripts, "launch_codex_security_mcp");
        await copyFile(
          join(PLUGIN_ROOT, "scripts", "launch_codex_security_mcp"),
          launcherPath,
        );
        await chmod(launcherPath, 0o700);
        await writeFile(
          join(mcp, "helpers.mjs"),
          `import { readFileSync } from "node:fs";
readFileSync(3);
process.on("SIGTERM", () => process.exit(23));
console.log(JSON.stringify({ pid: process.pid }));
setInterval(() => {}, 1000);
`,
        );
        const launcher = Bun.spawn([launcherPath, "--helper", "probe"], {
          env: { ...process.env, CODEX_MCP_NODE_PATH: node },
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
        });
        let helperPid: number | undefined;
        let deadline: ReturnType<typeof setTimeout> | undefined;
        try {
          const reader = launcher.stdout.getReader();
          const ready = await reader.read();
          reader.releaseLock();
          expect(ready.done).toBe(false);
          helperPid = JSON.parse(new TextDecoder().decode(ready.value)).pid;
          launcher.kill(signal);
          const result = await Promise.race([
            launcher.exited,
            new Promise<never>((_, reject) => {
              deadline = setTimeout(
                () => reject(new Error("The helper did not terminate.")),
                5000,
              );
            }),
          ]);
          expect(result).toBe(exitCode);
          expect(() => process.kill(helperPid!, 0)).toThrow("ESRCH");
          expect(await new Response(launcher.stderr).text()).toBe("");
        } finally {
          if (deadline !== undefined) clearTimeout(deadline);
          if (launcher.exitCode === null) launcher.kill("SIGKILL");
          if (helperPid !== undefined) {
            try {
              process.kill(helperPid, "SIGKILL");
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ESRCH")
                throw error;
            }
          }
          await launcher.exited;
        }
      } finally {
        await removeTemporaryDirectory(root);
      }
    },
  );
}

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
      let managedNode: string;
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
        windows ? (process.env["ComSpec"] ?? "cmd.exe") : launcher,
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
      await removeTemporaryDirectory(root);
    }
  },
);
