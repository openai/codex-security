import { expect, test } from "bun:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "smol-toml";
import { runCodexSkillCommand } from "../src/cli.js";
import { prepareCodexSecurityCredentialHome } from "../src/runtime.js";
import { capture } from "./cli-fixtures.js";
import { git } from "./git-fixture.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("the dependency investigator inherits the selected provider without ambient integrations or credential files", async () => {
  await using temp = await scopedTemporaryDirectory("dependency-home-");
  const ambient = join(temp.path, "ambient");
  const repo = join(temp.path, "checkout");
  await mkdir(ambient);
  await mkdir(repo);
  git(repo, "init", "--quiet");
  const result = join(temp.path, "result.json");
  const child = join(temp.path, "child.cjs");
  await writeFile(join(ambient, "auth.json"), "{}");
  await writeFile(
    join(ambient, "config.toml"),
    [
      'model_provider = "private"',
      'developer_instructions = "ambient marker"',
      "[model_providers.private]",
      'env_key = "SYNTHETIC_PROVIDER_KEY"',
      'base_url = "https://provider.invalid/v1"',
      "[mcp_servers.unrelated]",
      'command = "never-invoke"',
    ].join("\n"),
  );
  await writeFile(
    child,
    `
    const fs = require("node:fs");
    const path = require("node:path");
    const home = process.env.CODEX_HOME;
    fs.writeFileSync(process.argv[2], JSON.stringify({
      home,
      config: fs.readFileSync(path.join(home, "config.toml"), "utf8"),
      credentials: fs.existsSync(path.join(home, "auth.json")),
      hasProviderKey: Boolean(process.env.SYNTHETIC_PROVIDER_KEY)
    }));
    process.stdin.once("data", () => process.exit(0));
  `,
  );
  await runCodexSkillCommand(
    [child, result],
    {
      command: "exploitability check",
      auth: "auto",
      directory: repo,
      stdout: capture().stream,
      stderr: capture().stream,
      appServer: {
        directory: repo,
        prompt: "inspect",
        threadSource: "security_validation",
        dependencyReport: {
          submit: async () => ({ accepted: false, feedback: "unsubmitted" }),
          recordInventory: () => {},
          recordGraphEvent: () => {},
          continuationPrompt: () => undefined,
        },
      },
    },
    { command: process.execPath },
    {
      PATH: process.env["PATH"],
      CODEX_HOME: ambient,
      SYNTHETIC_PROVIDER_KEY: "fixture",
    },
  );
  const observed = JSON.parse(await readFile(result, "utf8"));
  expect(observed.home).not.toBe(ambient);
  expect(parse(observed.config)).toEqual({
    model_provider: "private",
    model_providers: {
      private: {
        env_key: "SYNTHETIC_PROVIDER_KEY",
        base_url: "https://provider.invalid/v1",
      },
    },
  });
  expect(observed.credentials).toBe(false);
  expect(observed.hasProviderKey).toBe(true);
  expect(await Bun.file(join(observed.home, "config.toml")).exists()).toBe(
    false,
  );
});

test("stored sign-in refuses a credential home with a hook before starting the investigator", async () => {
  await using temp = await scopedTemporaryDirectory("dependency-home-hook-");
  const repo = join(temp.path, "checkout");
  await mkdir(repo);
  git(repo, "init", "--quiet");
  const environment = {
    PATH: process.env["PATH"],
    CODEX_HOME: join(temp.path, "ambient"),
    CODEX_SECURITY_STATE_DIR: join(temp.path, "state"),
  };
  const managed = await prepareCodexSecurityCredentialHome(environment);
  await writeFile(join(managed, "hooks.json"), "{}");
  await expect(
    runCodexSkillCommand(
      [],
      {
        command: "exploitability check",
        auth: "chatgpt",
        directory: repo,
        stdout: capture().stream,
        stderr: capture().stream,
        appServer: {
          directory: repo,
          prompt: "inspect",
          threadSource: "security_validation",
          dependencyReport: {
            submit: async () => ({ accepted: false, feedback: "unsubmitted" }),
            recordInventory: () => {},
            recordGraphEvent: () => {},
            continuationPrompt: () => undefined,
          },
        },
      },
      { command: process.execPath },
      environment,
    ),
  ).rejects.toThrow('cannot isolate "hooks.json"');
});
