import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Writable } from "node:stream";
import { expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { readSkillCommandOutput } from "../src/cli.js";
import { writeCodexConfig } from "../src/config.js";
import { resolveCodexCommand } from "../src/runtime.js";

test.each([
  [undefined, "patch"],
  ["untrusted", "patch"],
  ["trusted", "patch"],
  ["trusted", "verify-fix"],
  ["trusted", "conflicting-user-server"],
] as const)(
  "preserves project trust and protects verification (%s, %s)",
  async (trust, mode) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-patch-trust-")),
    );
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const marker = join(root, "mcp-started");
    const userMarker = join(root, "user-mcp-started");
    const projects =
      trust === undefined
        ? undefined
        : { [repository]: { trust_level: trust } };
    try {
      await mkdir(repository);
      execFileSync("git", ["init", "--quiet", repository]);
      await writeCodexConfig(join(repository, ".codex", "config.toml"), {
        analytics: { enabled: true },
        mcp_servers: {
          synthetic: {
            command: process.execPath,
            args: [
              "-e",
              `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "started")`,
            ],
          },
        },
      });
      const configPath = join(codexHome, "config.toml");
      await writeCodexConfig(configPath, {
        analytics: { enabled: true },
        model: "synthetic-model",
        model_provider: "synthetic",
        model_providers: {
          synthetic: {
            name: "Synthetic",
            base_url: "http://127.0.0.1:9/v1",
            wire_api: "responses",
            requires_openai_auth: false,
          },
        },
        ...(mode === "patch"
          ? {}
          : {
              mcp_servers: {
                [mode === "verify-fix" ? "user-configured" : "synthetic"]: {
                  command: process.execPath,
                  args: [
                    "-e",
                    `require("node:fs").writeFileSync(${JSON.stringify(userMarker)}, "started")`,
                  ],
                  startup_timeout_sec: 1,
                },
              },
            }),
        ...(projects === undefined ? {} : { projects }),
      });
      const child = spawn(
        resolveCodexCommand({}).command,
        [
          "app-server",
          "--disable",
          "plugins",
          "--config",
          "analytics.enabled=false",
        ],
        {
          cwd: repository,
          env: {
            ...Object.fromEntries(
              Object.entries(process.env).filter(([name]) =>
                /^(path|systemroot|comspec|temp|tmp|tmpdir)$/iu.test(name),
              ),
            ),
            CODEX_HOME: codexHome,
          },
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        },
      );
      child.stderr.resume();
      const closed = once(child, "close");
      let servers: string[] | undefined;
      let analyticsEnabled: boolean | undefined;
      let inspectedThreadId: string | undefined;
      const input = new Writable({
        final(callback) {
          if (child.stdin.writableEnded) {
            callback();
          } else {
            child.stdin.end(callback);
          }
        },
        write(chunk, _encoding, callback) {
          const request = JSON.parse(chunk.toString());
          // Inspect the native task without making a model request.
          if (request.method === "turn/start") {
            inspectedThreadId = request.params.threadId;
            child.stdin.write(
              `${JSON.stringify({
                id: 6,
                method: "config/read",
                params: { cwd: repository },
              })}\n`,
              callback,
            );
          } else {
            child.stdin.write(chunk, callback);
          }
        },
      });
      async function* events(): AsyncGenerator<string> {
        for await (const line of createInterface({ input: child.stdout })) {
          const event = JSON.parse(line);
          if (event.id === 6) {
            analyticsEnabled = event.result?.config?.analytics?.enabled;
            child.stdin.write(
              `${JSON.stringify({
                id: 5,
                method: "mcpServerStatus/list",
                params: { threadId: inspectedThreadId },
              })}\n`,
            );
          }
          if (event.id === 5) {
            servers = event.result?.data.map(
              (server: { name: string }) => server.name,
            );
            child.stdin.end();
          }
          yield `${line}\n`;
        }
      }
      try {
        const output = await readSkillCommandOutput(events(), {
          directory: repository,
          prompt: "Synthetic finding",
          threadSource:
            mode === "patch" ? "security_remediation" : "security_validation",
          input,
          ...(mode === "patch" ? {} : { sandbox: "read-only" }),
        });
        expect(output).toMatchObject({
          completed: false,
          ...(mode === "conflicting-user-server"
            ? {
                error:
                  'Repository-local MCP server "synthetic" overrides a configured integration; remove the repository override before verifying fixes.',
              }
            : {}),
        });
        expect(await closed).toEqual([0, null]);
        expect(analyticsEnabled).toBe(
          mode === "conflicting-user-server" ? undefined : false,
        );
        expect(
          parseToml(await readFile(configPath, "utf8"))["analytics"],
        ).toEqual({ enabled: true });
        expect(
          parseToml(await readFile(configPath, "utf8"))["projects"],
        ).toEqual(projects);
        expect(servers?.sort()).toEqual(
          mode === "conflicting-user-server"
            ? undefined
            : mode === "verify-fix"
              ? ["synthetic", "user-configured"]
              : trust === "trusted"
                ? ["synthetic"]
                : [],
        );
        expect(existsSync(marker)).toBe(
          trust === "trusted" && mode === "patch",
        );
        expect(existsSync(userMarker)).toBe(mode === "verify-fix");
      } finally {
        input.end();
        child.stdin.end();
        if (child.exitCode === null && child.signalCode === null) child.kill();
        await closed;
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
