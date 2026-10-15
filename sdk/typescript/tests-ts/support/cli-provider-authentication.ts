import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect } from "bun:test";
import { main, runCodexSkillCommand } from "../../src/cli.js";
import type { JsonObject } from "../../src/index.js";
import { dependencies as cliDependencies } from "../cli-fixtures.js";
import { createCliTest } from "./cli-run.js";
import { readJsonLines } from "./json.js";

export async function runProviderSkill(
  stateDirectory: string,
  {
    command = "patch",
    auth = "api-key",
    overrides,
    environment,
    ambientConfig,
    storedCredentials = false,
  }: {
    command?: "validate" | "patch" | "verify-fix";
    auth?: "auto" | "chatgpt" | "api-key";
    overrides: readonly string[] | JsonObject;
    environment?: NodeJS.ProcessEnv;
    ambientConfig?: string;
    storedCredentials?: boolean;
  },
) {
  const repository = join(stateDirectory, "repository");
  const ambientHome = join(stateDirectory, "ambient");
  const log = join(stateDirectory, "provider.jsonl");
  await mkdir(repository);
  await mkdir(ambientHome);
  if (ambientConfig !== undefined) {
    await writeFile(join(ambientHome, "config.toml"), ambientConfig);
  }
  if (storedCredentials) {
    await writeFile(
      join(ambientHome, "auth.json"),
      JSON.stringify({
        auth_mode: "apikey",
        OPENAI_API_KEY: "SYNTHETIC_STORED_KEY",
      }),
      { mode: 0o600 },
    );
  }
  const { stderr, runCli } = createCliTest(main);

  const status = await runCli(
    [
      command,
      "Synthetic issue",
      "--auth",
      auth,
      ...(Array.isArray(overrides)
        ? overrides.flatMap((value) => ["--codex", value])
        : []),
    ],
    cliDependencies({
      currentDirectory: repository,
      environment: {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        ...environment,
        CODEX_HOME: ambientHome,
        SYNTHETIC_PROVIDER_LOG: log,
        SYNTHETIC_SKILL_COMMAND: command,
      },
      onCodex: async (args, output, environment, input) => {
        if (!Array.isArray(overrides) && output !== undefined)
          output = { ...output, codexOverrides: overrides as JsonObject };
        const originalOverrides = structuredClone(output?.codexOverrides);
        const result = await runCodexSkillCommand(
          [
            fileURLToPath(
              new URL("../fixtures/skill-provider-auth.mjs", import.meta.url),
            ),
            ...args,
          ],
          output,
          { command: process.execPath },
          environment,
          input,
        );
        expect(output?.codexOverrides).toEqual(originalOverrides);
        return result;
      },
    }),
  );
  const records = existsSync(log) ? await readJsonLines(log) : [];
  if (ambientConfig !== undefined) {
    expect(await readFile(join(ambientHome, "config.toml"), "utf8")).toBe(
      ambientConfig,
    );
  }
  return {
    status,
    stderr: stderr.text(),
    launch: records[0],
    requests: records.slice(1),
  };
}
