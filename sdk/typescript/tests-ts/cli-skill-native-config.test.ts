import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { runCodexSkillCommand } from "../src/cli.js";
import { writeCodexConfig } from "../src/config.js";
import {
  prepareCodexSecurityCredentialHome,
  resolveCodexCommand,
} from "../src/runtime.js";
import { capture } from "./cli-fixtures.js";

test.each([
  ["trusted", undefined, "patch", ""],
  ["untrusted", undefined, "patch", ""],
  [undefined, undefined, "patch", ""],
  ["trusted", "openai", "patch", ""],
  ["trusted", undefined, "verify-fix", ""],
  ["trusted", undefined, "patch", "component"],
] as const)(
  "stored-auth commands preserve native project configuration (%s, provider: %s, command: %s, subdirectory: %s)",
  async (trust, modelProvider, command, subdirectory) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-native-config-")),
    );
    const repository = join(root, "repository");
    const directory = join(repository, subdirectory);
    const ambientHome = join(root, "ambient");
    const environment = {
      ...Object.fromEntries(
        Object.entries(process.env).filter(([name]) =>
          /^(path|systemroot|comspec|temp|tmp|tmpdir)$/iu.test(name),
        ),
      ),
      CODEX_HOME: ambientHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      SYNTHETIC_NATIVE_CODEX: resolveCodexCommand({}).command,
    };
    try {
      await mkdir(directory, { recursive: true });
      execFileSync("git", ["init", "--quiet", repository]);
      await writeCodexConfig(join(repository, ".codex", "config.toml"), {
        mcp_servers: {
          synthetic: { command: "synthetic-unused-command", enabled: false },
        },
      });
      await writeCodexConfig(join(ambientHome, "config.toml"), {
        cli_auth_credentials_store: "file",
        ...(trust === undefined
          ? {}
          : { projects: { [repository]: { trust_level: trust } } }),
      });
      const sharedHome = await prepareCodexSecurityCredentialHome(environment);
      await writeCodexConfig(join(sharedHome, "config.toml"), {
        projects: {
          [repository]: {
            trust_level: trust === "trusted" ? "untrusted" : "trusted",
          },
        },
      });
      await writeFile(
        join(sharedHome, "auth.json"),
        JSON.stringify({
          auth_mode: "apikey",
          OPENAI_API_KEY: "SYNTHETIC_KEY",
        }),
        { mode: 0o600 },
      );
      const stdout = capture();
      const stderr = capture();
      const status = await runCodexSkillCommand(
        [
          fileURLToPath(
            new URL("./fixtures/skill-native-config.mjs", import.meta.url),
          ),
          "app-server",
          "--disable",
          "plugins",
          "--config",
          "analytics.enabled=false",
        ],
        {
          command,
          auth: "chatgpt",
          modelProvider,
          directory,
          stdout: stdout.stream,
          stderr: stderr.stream,
          appServer: {
            directory,
            prompt: "Synthetic finding",
            threadSource:
              command === "patch"
                ? "security_remediation"
                : "security_validation",
            ...(command === "verify-fix"
              ? { sandbox: "read-only" as const }
              : {}),
          },
        },
        { command: process.execPath },
        environment,
      );
      expect(status, stderr.text()).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual({
        modelProvider: "openai",
        projectServerConfigured: trust === "trusted",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
