import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { runCodexSkillCommand } from "../src/cli.js";
import {
  inlineToml,
  writeCodexConfig,
  type JsonObject,
} from "../src/config.js";
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
      expect(JSON.parse(stdout.text())).toMatchObject({
        modelProvider: "openai",
        projectServerConfigured: trust === "trusted",
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

const disabledDaybreakFeatures = {
  cli_daybreak: false,
  api_key_cyber_access_programs: false,
  api_key_model_discovery: false,
};

async function withStoredApiKey(
  command: "patch" | "verify-fix",
  check: (fixture: {
    ambientHome: string;
    sharedHome: string;
    repository: string;
    run: (overrides?: JsonObject) => Promise<{
      daybreak: boolean | null;
      daybreakEnabled: boolean | null;
      daybreakFeatures: Record<string, boolean | null>;
    }>;
  }) => Promise<void>,
): Promise<void> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-stored-daybreak-")),
  );
  const repository = join(root, "repository");
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
    await mkdir(repository);
    execFileSync("git", ["init", "--quiet", repository]);
    const sharedHome = await prepareCodexSecurityCredentialHome(environment);
    await writeFile(
      join(sharedHome, "auth.json"),
      JSON.stringify({
        auth_mode: "apikey",
        OPENAI_API_KEY: "SYNTHETIC_KEY",
      }),
      { mode: 0o600 },
    );
    await check({
      ambientHome,
      sharedHome,
      repository,
      run: async (overrides = {}) => {
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
            ...Object.entries(overrides).flatMap(([key, value]) => [
              "--config",
              `${key}=${inlineToml(value)}`,
            ]),
          ],
          {
            command,
            auth: "auto",
            codexOverrides: overrides,
            directory: repository,
            stdout: stdout.stream,
            stderr: stderr.stream,
            appServer: {
              directory: repository,
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
        return JSON.parse(stdout.text());
      },
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test.each(
  (["patch", "verify-fix"] as const).flatMap((command) =>
    [true, false].map((daybreak) => [command, daybreak] as const),
  ),
)(
  "%s preserves ambient Daybreak %p with a stored API key",
  async (command, daybreak) => {
    await withStoredApiKey(
      command,
      async ({ ambientHome, sharedHome, run }) => {
        await writeCodexConfig(join(ambientHome, "config.toml"), { daybreak });
        await writeCodexConfig(join(sharedHome, "config.toml"), {
          daybreak: !daybreak,
        });
        expect(await run()).toMatchObject({
          daybreak,
          daybreakEnabled: daybreak ? true : null,
        });
      },
    );
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s preserves the Daybreak opt-out with an explicit toggle and a stored API key",
  async (command) => {
    await withStoredApiKey(command, async ({ ambientHome, run }) => {
      await writeCodexConfig(join(ambientHome, "config.toml"), {
        daybreak: false,
        features: { cli_daybreak: false },
      });
      expect(await run({ daybreak: true })).toMatchObject({
        daybreak: true,
        daybreakEnabled: true,
        daybreakFeatures: { cli_daybreak: false },
      });
    });
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s forwards wrapper-resolved ambient Daybreak profiles with a stored API key",
  async (command) => {
    await withStoredApiKey(command, async ({ ambientHome, run }) => {
      await writeCodexConfig(join(ambientHome, "config.toml"), {
        daybreak: false,
        features: { cli_daybreak: true },
        profile: "selected",
        profiles: {
          selected: { daybreak: true, features: disabledDaybreakFeatures },
        },
      });
      expect(await run()).toMatchObject({
        daybreak: true,
        daybreakEnabled: true,
        daybreakFeatures: disabledDaybreakFeatures,
      });
    });
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s clears removed ambient Daybreak settings on the next stored API-key launch",
  async (command) => {
    await withStoredApiKey(command, async ({ ambientHome, run }) => {
      const configPath = join(ambientHome, "config.toml");
      await writeCodexConfig(configPath, {});
      const baseline = await run();
      await writeCodexConfig(configPath, {
        daybreak: true,
        features: disabledDaybreakFeatures,
      });
      expect(await run()).toMatchObject({
        daybreak: true,
        daybreakEnabled: true,
        daybreakFeatures: disabledDaybreakFeatures,
      });
      await writeCodexConfig(configPath, {});
      expect(await run()).toEqual(baseline);
    });
  },
);

test.each(["patch", "verify-fix"] as const)(
  "%s preserves native project and explicit Daybreak precedence with a stored API key",
  async (command) => {
    await withStoredApiKey(
      command,
      async ({ ambientHome, repository, run }) => {
        await writeCodexConfig(join(ambientHome, "config.toml"), {
          daybreak: true,
          features: { cli_daybreak: true },
          projects: { [repository]: { trust_level: "trusted" } },
        });
        await writeCodexConfig(join(repository, ".codex", "config.toml"), {
          daybreak: false,
          features: { cli_daybreak: false },
        });
        expect(await run()).toMatchObject({
          daybreak: false,
          daybreakEnabled: null,
          daybreakFeatures: { cli_daybreak: false },
        });
        expect(await run({ daybreak: true })).toMatchObject({
          daybreak: true,
          daybreakEnabled: true,
          daybreakFeatures: { cli_daybreak: false },
        });
      },
    );
  },
);
