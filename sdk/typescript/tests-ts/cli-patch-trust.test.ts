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

test.each([undefined, "untrusted", "trusted"] as const)(
  "preserves project trust when starting a patch (%s)",
  async (trust) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-patch-trust-")),
    );
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const marker = join(root, "mcp-started");
    const projects =
      trust === undefined
        ? undefined
        : { [repository]: { trust_level: trust } };
    try {
      await mkdir(repository);
      execFileSync("git", ["init", "--quiet", repository]);
      await writeCodexConfig(join(repository, ".codex", "config.toml"), {
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
        ...(projects === undefined ? {} : { projects }),
      });
      const child = spawn(
        resolveCodexCommand({}).command,
        ["app-server", "--disable", "plugins"],
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
      const input = new Writable({
        write(chunk, _encoding, callback) {
          const request = JSON.parse(chunk.toString());
          // Inspect the native task without making a model request.
          if (request.method === "turn/start") {
            child.stdin.write(
              `${JSON.stringify({
                id: 4,
                method: "mcpServerStatus/list",
                params: { threadId: request.params.threadId },
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
          if (event.id === 4) {
            servers = event.result?.data.map(
              (server: { name: string }) => server.name,
            );
            child.stdin.end();
          }
          yield `${line}\n`;
        }
      }
      try {
        expect(
          await readSkillCommandOutput(events(), {
            prompt: "Synthetic finding",
            input,
          }),
        ).toMatchObject({ completed: false });
        expect(await closed).toEqual([0, null]);
        expect(
          parseToml(await readFile(configPath, "utf8"))["projects"],
        ).toEqual(projects);
        expect(servers).toEqual(trust === "trusted" ? ["synthetic"] : []);
        expect(existsSync(marker)).toBe(trust === "trusted");
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
