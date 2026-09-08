import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurityError, type ScanOptions } from "../src/index.js";
import {
  codexSecurityCredentialAllowsAmbientImport,
  prepareCodexSecurityCredentialHome,
  setCodexSecurityCredentialLogout,
} from "../src/runtime.js";
import {
  capture,
  dependencies as cliDependencies,
  FakeSignals,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";

let stateDirectory: string;

beforeEach(async () => {
  stateDirectory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-cli-authentication-")),
  );
});

afterEach(async () => {
  await rm(stateDirectory, { recursive: true, force: true });
});

function dependencies(
  options: Parameters<typeof cliDependencies>[0] = {},
): ReturnType<typeof cliDependencies> {
  return cliDependencies({
    ...options,
    environment: {
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      ...options.environment,
    },
  });
}

describe("CLI authentication", () => {
  test("delegates login and logout without overriding managed credential storage", async () => {
    const cases = [
      ["login"],
      ["login", "--device-auth"],
      ["login", "--with-api-key"],
      ["login", "--with-access-token"],
      ["login", "status"],
      ["logout"],
    ] as const;
    for (const argv of cases) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.prepareAuthenticationHome = async () =>
        join(stateDirectory, "codex-home");
      let forwarded: readonly string[] | undefined;
      deps.createSecurity = () => {
        throw new Error("must not initialize Codex Security");
      };
      deps.runCodex = async (args) => {
        forwarded = args;
        return 17;
      };
      expect(await main(argv, stdout.stream, stderr.stream, deps)).toBe(17);
      expect(forwarded).toEqual([argv[0], ...argv.slice(1)]);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toBe("");
    }
  });

  test("uses the same stable credential home for login, status, and logout", async () => {
    const expectedHome = await realpath(
      await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      }),
    );

    for (const argv of [["login"], ["login", "status"], ["logout"]] as const) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({
        environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
      });
      let forwarded: readonly string[] | undefined;
      let environment: NodeJS.ProcessEnv | undefined;
      deps.runCodex = async (args, _output, authEnvironment) => {
        forwarded = args;
        environment = authEnvironment;
        return 0;
      };

      expect(await main(argv, stdout.stream, stderr.stream, deps)).toBe(0);
      expect(forwarded).toEqual([...argv]);
      expect(environment?.["CODEX_HOME"]).toBe(expectedHome);
      expect(environment?.["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
    }
  });

  test.skipIf(process.platform === "win32")(
    "validates and canonicalizes the credential home for status and logout",
    async () => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-cli-managed-auth-")),
      );
      try {
        const actualState = join(root, "actual-state");
        const linkedState = join(root, "linked-state");
        await mkdir(actualState, { mode: 0o700 });
        await symlink(actualState, linkedState, "dir");
        const expectedHome = join(actualState, "codex-home");

        for (const argv of [["login", "status"], ["logout"]] as const) {
          const stdout = capture();
          const stderr = capture();
          const deps = dependencies({
            environment: { CODEX_SECURITY_STATE_DIR: linkedState },
          });
          deps.prepareAuthenticationHome = prepareCodexSecurityCredentialHome;
          let forwardedHome: string | undefined;
          deps.runCodex = async (_args, _output, environment) => {
            forwardedHome = environment?.["CODEX_HOME"];
            return 0;
          };

          expect(await main(argv, stdout.stream, stderr.stream, deps)).toBe(0);
          expect(forwardedHome).toBe(expectedHome);
        }

        expect(
          await codexSecurityCredentialAllowsAmbientImport(expectedHome),
        ).toBe(false);

        const stdout = capture();
        const stderr = capture();
        const deps = dependencies({
          environment: { CODEX_SECURITY_STATE_DIR: linkedState },
        });
        deps.prepareAuthenticationHome = prepareCodexSecurityCredentialHome;
        deps.runCodex = async () => 0;
        expect(await main(["login"], stdout.stream, stderr.stream, deps)).toBe(
          0,
        );
        expect(
          await codexSecurityCredentialAllowsAmbientImport(expectedHome),
        ).toBe(true);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("explains when an environment API key overrides the stored login", async () => {
    for (const [environment, expectedSource] of [
      [{ OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" }, "OPENAI_API_KEY"],
      [{ Codex_Api_Key: "sk-proj-SYNTHETIC_SECRET_456" }, "CODEX_API_KEY"],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["login", "status"],
          stdout.stream,
          stderr.stream,
          dependencies({ environment }),
        ),
      ).toBe(0);
      expect(stderr.text()).toContain(
        `Effective scan authentication: API key from ${expectedSource}.`,
      );
      expect(stderr.text()).toContain(
        "To use a ChatGPT sign-in, remove OPENAI_API_KEY and CODEX_API_KEY from the environment.",
      );
      expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
    }
  });

  test("explains interactive choice and how to unset every shadowing key after ChatGPT login", async () => {
    for (const [argv, environment, source, removalGuidance] of [
      [
        ["login"],
        { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
        "OPENAI_API_KEY",
        "remove OPENAI_API_KEY from the environment",
      ],
      [
        ["login", "--device-auth"],
        { Codex_Api_Key: "sk-proj-SYNTHETIC_SECRET_456" },
        "CODEX_API_KEY",
        "remove Codex_Api_Key from the environment",
      ],
      [
        ["login"],
        {
          OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123",
          CODEX_API_KEY: "sk-proj-SYNTHETIC_SECRET_456",
        },
        "OPENAI_API_KEY",
        "remove OPENAI_API_KEY and CODEX_API_KEY from the environment",
      ],
    ] as const) {
      const stdout = capture();
      const stderr = capture();

      expect(
        await main(
          argv,
          stdout.stream,
          stderr.stream,
          dependencies({ environment }),
        ),
      ).toBe(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        "ChatGPT login succeeded. Interactive scans will ask which account to use;",
      );
      expect(stderr.text()).toContain(
        `noninteractive scans will use ${source}.`,
      );
      expect(stderr.text()).toContain("--auth chatgpt");
      expect(stderr.text()).toContain(removalGuidance);
      expect(stderr.text()).not.toContain("unset ");
      expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
    }
  });

  test("warns when an environment API key overrides a successful access-token login", async () => {
    for (const [environment, source, removalGuidance] of [
      [
        { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
        "OPENAI_API_KEY",
        "remove OPENAI_API_KEY from the environment",
      ],
      [
        { Codex_Api_Key: "sk-proj-SYNTHETIC_SECRET_456" },
        "CODEX_API_KEY",
        "remove Codex_Api_Key from the environment",
      ],
      [
        {
          OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123",
          CODEX_API_KEY: "sk-proj-SYNTHETIC_SECRET_456",
        },
        "OPENAI_API_KEY",
        "remove OPENAI_API_KEY and CODEX_API_KEY from the environment",
      ],
    ] as const) {
      const stdout = capture();
      const stderr = capture();

      expect(
        await main(
          ["login", "--with-access-token"],
          stdout.stream,
          stderr.stream,
          dependencies({ environment }),
        ),
      ).toBe(0);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(
        `Access-token login succeeded, but noninteractive scans will use ${source}.`,
      );
      expect(stderr.text()).toContain(
        `To use your stored credentials, pass '--auth chatgpt' or ${removalGuidance}.`,
      );
      expect(stderr.text()).not.toContain("unset ");
      expect(stderr.text()).not.toContain("ChatGPT login succeeded");
      expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
    }
  });

  test("does not report a ChatGPT login warning for failed or API-key logins", async () => {
    const environment = { OPENAI_API_KEY: "synthetic-private-key" };

    for (const [argv, exitCode] of [
      [["login"], 2],
      [["login", "--with-api-key"], 0],
      [["login", "--with-access-token"], 2],
    ] as const) {
      const stderr = capture();

      expect(
        await main(
          argv,
          capture().stream,
          stderr.stream,
          dependencies({ environment, onCodex: () => exitCode }),
        ),
      ).toBe(exitCode);
      expect(stderr.text()).not.toContain("ChatGPT login succeeded");
      expect(stderr.text()).not.toContain("Access-token login succeeded");
      expect(stderr.text()).not.toContain("synthetic-private-key");
    }
  });

  test("does not warn after access-token login without an overriding API key", async () => {
    const stdout = capture();
    const stderr = capture();

    expect(
      await main(
        ["login", "--with-access-token"],
        stdout.stream,
        stderr.stream,
        dependencies({ environment: {} }),
      ),
    ).toBe(0);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe("");
  });

  test("forwards explicit and automatic scan authentication selection", async () => {
    for (const [argv, expected] of [
      [["scan", "--auth", "chatgpt"], "chatgpt"],
      [["scan", "--auth", "api-key"], "api-key"],
      [["scan", "--auth", "auto"], "auto"],
      [["scan"], "auto"],
    ] as const) {
      let selected: ScanOptions["auth"];
      const stderr = capture();

      expect(
        await main(
          argv,
          capture().stream,
          stderr.stream,
          dependencies({
            environment: { OPENAI_API_KEY: "synthetic-private-key" },
            onTurn: (_repository, options) => {
              selected = (options as ScanOptions).auth;
            },
          }),
        ),
      ).toBe(0);
      expect(selected).toBe(expected);
      expect(stderr.text()).not.toContain("synthetic-private-key");
    }
  });

  test("reports Amazon Bedrock authentication without exposing AWS credentials", async () => {
    for (const [environment, source] of [
      [
        { AWS_BEARER_TOKEN_BEDROCK: "synthetic-bedrock-bearer" },
        "AWS_BEARER_TOKEN_BEDROCK",
      ],
      [
        {
          AWS_ACCESS_KEY_ID: "synthetic-aws-access-key",
          AWS_SECRET_ACCESS_KEY: "synthetic-aws-secret-key",
        },
        "AWS_ACCESS_KEY_ID",
      ],
      [{ AWS_PROFILE: "synthetic-bedrock-profile" }, "AWS_PROFILE"],
      [{}, "default_credential_chain"],
    ] as const) {
      const stdout = capture();
      const stderr = capture(false);
      const deps = dependencies({ environment });
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
          options?.onAuthentication?.({
            method: "aws_credentials",
            source,
            verified: false,
          });
          return fakeResult();
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(
        await main(
          [
            "scan",
            "--provider",
            "amazon-bedrock",
            "--model",
            "openai.gpt-5.6-luna",
            "--json",
            "--verbose",
          ],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
      expect(stderr.text()).toContain(
        `Authentication: AWS credentials from ${source}.`,
      );
      expect(stderr.text()).toContain(
        `method="aws_credentials" source="${source}"`,
      );
      expect(stderr.text()).not.toContain("synthetic-");
      expect(stderr.text()).not.toContain("stored Codex credentials");
      expect(stderr.text()).not.toContain("--auth chatgpt");
    }
  });

  test("provides provider-aware Amazon Bedrock authentication failure guidance", async () => {
    for (const [detail, expected] of [
      [
        "401 invalid credentials for org-private",
        "Check your Amazon Bedrock bearer token",
      ],
      [
        "403 model access denied for org-private",
        "Check your AWS identity and Bedrock model permissions",
      ],
    ] as const) {
      const stderr = capture(false);
      const deps = dependencies({
        environment: { AWS_BEARER_TOKEN_BEDROCK: "synthetic-bedrock-bearer" },
      });
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
          options?.onAuthentication?.({
            method: "aws_credentials",
            source: "AWS_BEARER_TOKEN_BEDROCK",
            verified: false,
          });
          throw new CodexSecurityError(detail);
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(
        await main(
          ["scan", "--codex", 'model_provider="amazon-bedrock"'],
          capture().stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).toContain("AWS_BEARER_TOKEN_BEDROCK");
      expect(stderr.text()).not.toContain("synthetic-");
      expect(stderr.text()).not.toContain("org-private");
      expect(stderr.text()).not.toContain("--auth chatgpt");
    }
  });

  test("offers the existing interactive prompt when both sign-ins are available", async () => {
    for (const [argv, selection] of [
      [["scan"], "chatgpt"],
      [["scan"], "api-key"],
      [["scans", "rerun", "scan-original", "--verbose", "--json"], "chatgpt"],
      [
        ["scans", "rerun", "scan-original", "--verbose", "--format", "jsonl"],
        "chatgpt",
      ],
    ] as const) {
      const stderr = capture(true);
      let selected: ScanOptions["auth"];
      let question = "";
      let choices: readonly { label: string; value: string }[] = [];
      const deps = dependencies({
        environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
        onTurn: (_repository, options) => {
          selected = (options as ScanOptions).auth;
        },
        onWorkbench: () => ({
          recipe: {
            repository: "/original/repository",
            target: { kind: "repository", paths: [] },
            mode: "standard",
            config: {},
          },
        }),
      });
      deps.hasStoredChatGPTSignIn = async () => true;
      deps.scanAuthenticationPrompt = {
        isInteractive: () => true,
        select: async <Value extends string>(
          message: string,
          options: readonly { label: string; value: Value }[],
        ): Promise<Value> => {
          question = message;
          choices = options;
          return options.find((option) => option.value === selection)!.value;
        },
      };

      expect(await main(argv, capture().stream, stderr.stream, deps)).toBe(0);
      expect(selected).toBe(selection);
      expect(question).toBe("How would you like to authenticate this scan?");
      expect(choices).toEqual([
        { label: "ChatGPT subscription", value: "chatgpt" },
        { label: "API key from OPENAI_API_KEY", value: "api-key" },
      ]);
      expect(stderr.text()).toContain(
        "Both a ChatGPT sign-in and an API key from OPENAI_API_KEY are available.",
      );
      expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
    }
  });

  test("cancels sign-in discovery and authentication prompts before starting a scan", async () => {
    for (const stage of ["status", "prompt"] as const) {
      const signals = new FakeSignals();
      const signalName = stage === "status" ? "SIGTERM" : "SIGINT";
      let observedSignal: AbortSignal | undefined;
      let initialized = false;
      const deps = dependencies({
        signals,
        environment: { OPENAI_API_KEY: "synthetic-private-key" },
      });
      deps.createSecurity = () => {
        initialized = true;
        throw new Error("must not initialize a cancelled scan");
      };
      const interrupt = <Value>(signal?: AbortSignal): Promise<Value> => {
        observedSignal = signal;
        signals.emit(signalName);
        return new Promise(() => {});
      };
      deps.hasStoredChatGPTSignIn = (signal) =>
        stage === "status" ? interrupt<boolean>(signal) : Promise.resolve(true);
      deps.scanAuthenticationPrompt = {
        isInteractive: () => true,
        select: <Value extends string>(
          _message: string,
          _options: readonly { label: string; value: Value }[],
          _presentation?: { header?: string },
          signal?: AbortSignal,
        ) => interrupt<Value>(signal),
      };

      expect(
        await main(["scan"], capture().stream, capture(true).stream, deps),
      ).toBe(signalName === "SIGTERM" ? 143 : 130);
      expect(observedSignal?.aborted).toBe(true);
      expect(initialized).toBe(false);
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    }
  });

  test("does not hide or relabel a failed ChatGPT login", async () => {
    const stdout = capture();
    const stderr = capture();

    expect(
      await main(
        ["login"],
        stdout.stream,
        stderr.stream,
        dependencies({
          environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
          onCodex: () => 17,
        }),
      ),
    ).toBe(17);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toBe("");
  });

  test("never prompts during automation, explicit selection, or unavailable credentials", async () => {
    for (const scenario of [
      { argv: ["scan", "--json"], terminal: true, stored: true, key: true },
      {
        argv: ["scan", "--format", "jsonl"],
        terminal: true,
        stored: true,
        key: true,
      },
      {
        argv: ["scan", "--dry-run"],
        terminal: true,
        stored: true,
        key: true,
      },
      {
        argv: ["scan", "--auth", "chatgpt"],
        terminal: true,
        stored: true,
        key: true,
      },
      {
        argv: ["scan", "--auth", "api-key"],
        terminal: true,
        stored: true,
        key: true,
      },
      { argv: ["scan"], terminal: false, stored: true, key: true },
      { argv: ["scan"], terminal: true, stored: false, key: true },
      { argv: ["scan"], terminal: true, stored: true, key: false },
      {
        argv: ["scan"],
        terminal: true,
        stored: true,
        key: true,
        inputInteractive: false,
      },
    ]) {
      const stderr = capture(scenario.terminal);
      let selected: ScanOptions["auth"];
      let prompts = 0;
      const deps = dependencies({
        environment: scenario.key
          ? { OPENAI_API_KEY: "synthetic-private-key" }
          : {},
        onTurn: (_repository, options) => {
          selected = (options as ScanOptions).auth;
        },
      });
      deps.hasStoredChatGPTSignIn = async () => scenario.stored;
      deps.scanAuthenticationPrompt = {
        isInteractive: () => scenario.inputInteractive !== false,
        select: async <Value extends string>(
          _message: string,
          options: readonly { label: string; value: Value }[],
        ): Promise<Value> => {
          prompts += 1;
          return options[0]!.value;
        },
      };

      expect(
        await main(scenario.argv, capture().stream, stderr.stream, deps),
      ).toBe(0);
      expect(prompts).toBe(0);
      if (!scenario.argv.includes("--dry-run")) {
        expect(selected).toBe(
          scenario.argv.includes("chatgpt")
            ? "chatgpt"
            : scenario.argv.includes("api-key")
              ? "api-key"
              : "auto",
        );
      }
      expect(stderr.text()).not.toContain("synthetic-private-key");
    }
  });

  test("rejects explicit API-key authentication before initializing a scan when no key is set", async () => {
    const stderr = capture();
    const deps = dependencies();
    deps.createSecurity = () => {
      throw new Error("must not initialize Codex Security");
    };

    expect(
      await main(
        ["scan", "--auth", "api-key"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "API-key authentication requires OPENAI_API_KEY or CODEX_API_KEY.",
    );
    expect(stderr.text()).toContain("--auth chatgpt");
    expect(stderr.text()).not.toContain("must not initialize");
  });

  test("keeps stored-login status unchanged when no environment key is set", async () => {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["login", "status"],
        stdout.stream,
        stderr.stream,
        dependencies({ environment: { OPENAI_API_KEY: "   " } }),
      ),
    ).toBe(0);
    expect(stderr.text()).toBe("");
  });

  test("reports effective environment credentials without a stored sign-in", async () => {
    const stdout = capture();
    const stderr = capture();
    const environment: NodeJS.ProcessEnv = {
      OPENAI_API_KEY: "synthetic-primary-key",
      CODEX_API_KEY: "synthetic-secondary-key",
    };
    expect(
      await main(
        ["login", "status"],
        stdout.stream,
        stderr.stream,
        dependencies({ environment, onCodex: () => 1 }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("API key from OPENAI_API_KEY");
    expect(stderr.text()).not.toContain("synthetic");

    delete environment["OPENAI_API_KEY"];
    const rotated = capture();
    expect(
      await main(
        ["login", "status"],
        capture().stream,
        rotated.stream,
        dependencies({ environment, onCodex: () => 1 }),
      ),
    ).toBe(0);
    expect(rotated.text()).toContain("API key from CODEX_API_KEY");

    expect(
      await main(
        ["login", "status"],
        capture().stream,
        capture().stream,
        dependencies({ environment: {}, onCodex: () => 1 }),
      ),
    ).toBe(1);

    expect(
      await main(
        ["login", "status"],
        capture().stream,
        capture().stream,
        dependencies({
          environment: { OPENAI_API_KEY: "synthetic-key" },
          onCodex: () => 17,
        }),
      ),
    ).toBe(17);
  });

  test("keeps delegated credentials in the configured Codex home", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-login-home-"));
    const repository = join(root, "repository");
    const relativeHome = join(repository, ".codex-security-home");
    const tildeHome = join(root, ".codex-security-home");
    const mountedHome = join(root, "mounted-codex-home");
    const defaultHome = join(root, ".codex");
    await mkdir(repository, { mode: 0o700 });
    await mkdir(relativeHome, { mode: 0o700 });
    await mkdir(tildeHome, { mode: 0o700 });
    await mkdir(mountedHome, { mode: 0o700 });
    await mkdir(defaultHome, { mode: 0o700 });
    try {
      for (const [configuredHome, expectedHome, userHome] of [
        [".codex-security-home", relativeHome, root],
        ["~/.codex-security-home", tildeHome, root],
        [mountedHome, mountedHome, join(root, "missing-home")],
        ...(process.platform === "win32"
          ? []
          : ([
              ["", defaultHome, root],
              ["   ", defaultHome, root],
            ] as const)),
      ] as const) {
        const credentialAncestors = [
          join(expectedHome, "state"),
          join(expectedHome, "state", "plugins"),
          join(expectedHome, "state", "plugins", "codex-security"),
          join(
            expectedHome,
            "state",
            "plugins",
            "codex-security",
            "codex-home",
          ),
        ];
        const credentialHome = credentialAncestors.at(-1)!;
        await mkdir(credentialHome, { recursive: true, mode: 0o700 });
        if (process.platform !== "win32") {
          for (const path of [expectedHome, ...credentialAncestors]) {
            await chmod(path, 0o700);
          }
        }
        await writeFile(
          join(credentialHome, "config.toml"),
          'cli_auth_credentials_store = "file"\n',
        );
        const environment = {
          PATH: process.env["PATH"],
          HOME: userHome,
          USERPROFILE: userHome,
          CODEX_HOME: configuredHome,
        };
        const run = (args: string[], input?: string): number | null =>
          spawnSync(
            process.execPath,
            [join(import.meta.dir, "../src/cli.ts"), ...args],
            {
              cwd: repository,
              env: environment,
              input,
              encoding: "utf8",
            },
          ).status;
        expect(run(["login", "--with-api-key"], "synthetic-key\n")).toBe(0);
        expect(await stat(join(credentialHome, "auth.json"))).toBeDefined();
        await expect(stat(join(repository, "auth.json"))).rejects.toThrow();
        expect(run(["login", "status"])).toBe(0);
        expect(run(["logout"])).toBe(0);
      }
      expect(
        spawnSync(
          process.execPath,
          [join(import.meta.dir, "../src/cli.ts"), "login", "--help"],
          {
            cwd: repository,
            env: {
              PATH: process.env["PATH"],
              HOME: root,
              USERPROFILE: root,
              Codex_Home: "   ",
            },
            encoding: "utf8",
          },
        ).status,
      ).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 60_000);

  test("reports selected scan credentials without contaminating JSON output", async () => {
    const stdout = capture();
    const stderr = capture(true);
    const deps = dependencies();
    deps.createSecurity = () => ({
      run: async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        options?.onScanStarted?.();
        return fakeResult();
      },
      preflight: async () => fakePreflight(),
      close: async () => {},
    });

    expect(
      await main(["scan", "--json"], stdout.stream, stderr.stream, deps),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain(
      "Authentication: API key from OPENAI_API_KEY.",
    );
    expect(stderr.text()).toContain(
      "To use your ChatGPT sign-in, retry with --auth chatgpt.",
    );
  });

  test("identifies overriding API keys in noninteractive scan auth failures", async () => {
    for (const [environment, source] of [
      [{ OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" }, "OPENAI_API_KEY"],
      [{ CODEX_API_KEY: "sk-proj-SYNTHETIC_SECRET_456" }, "CODEX_API_KEY"],
    ] as const) {
      for (const [detail, expected] of [
        ["401 invalid API key for org-private", "Authentication failed"],
        [
          "403 model access denied for org-private",
          "cannot access the configured model",
        ],
      ] as const) {
        const stdout = capture();
        const stderr = capture(false);
        const deps = dependencies({ environment });
        deps.createSecurity = () => ({
          run: async (_repository, options) => {
            options?.onAuthentication?.({
              method: "api_key",
              source,
              verified: false,
            });
            throw new CodexSecurityError(detail);
          },
          preflight: async () => fakePreflight(),
          close: async () => {},
        });

        expect(await main(["scan"], stdout.stream, stderr.stream, deps)).toBe(
          2,
        );
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain(expected);
        expect(stderr.text()).toContain(source);
        expect(stderr.text()).toContain("--auth chatgpt");
        expect(stderr.text()).not.toContain("ChatGPT sign-in was not used");
        expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
        expect(stderr.text()).not.toContain("org-private");
      }
    }
  });

  test("replaces permanent stored sign-in refresh details with recovery steps", async () => {
    for (const auth of ["chatgpt", "api-key"] as const) {
      for (const detail of [
        "Your access token could not be refreshed.",
        "Your access token could not be refreshed because your refresh token has expired.",
        "Your access token could not be refreshed because your refresh token was already used.",
        "Your access token could not be refreshed because your refresh token was revoked.",
      ]) {
        const stdout = capture();
        const stderr = capture(false);
        const deps = dependencies({
          environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
          onRun: () => {
            throw new CodexSecurityError(
              `Codex Exec exited with code 1: Error: ${detail} Please log out and sign in again. PRIVATE_UPSTREAM_DETAIL`,
            );
          },
        });

        expect(
          await main(
            ["scan", ".", "--auth", auth, "--json"],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        expect(stdout.text()).toBe("");
        expect(stderr.text()).toContain("workspace-managed policies");
        expect(stderr.text()).toContain(
          "API key is selected for model authentication",
        );
        expect(stderr.text()).toContain(
          "npx @openai/codex-security login status",
        );
        expect(stderr.text()).toContain(
          "npx @openai/codex-security logout', then 'npx @openai/codex-security login",
        );
        expect(stderr.text()).not.toContain("provide a valid API key");
        expect(stderr.text()).not.toContain("PRIVATE_UPSTREAM_DETAIL");
      }
    }
  });

  test("leaves other sign-in recovery messages unchanged", async () => {
    for (const message of [
      "Your access token could not be refreshed because you have since logged out or signed in to another account. Please sign in again.",
      "Your authentication session could not be refreshed automatically. Please log out and sign in again.",
    ]) {
      const stdout = capture();
      const stderr = capture(false);
      const deps = dependencies({
        onRun: () => {
          throw new CodexSecurityError(
            `Codex Exec exited with code 1: ${message} PRIVATE_UPSTREAM_DETAIL`,
          );
        },
      });

      expect(
        await main(["scan", "--json"], stdout.stream, stderr.stream, deps),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(`${message}\n`);
      expect(stderr.text()).not.toContain("PRIVATE_UPSTREAM_DETAIL");
      expect(stderr.text()).not.toContain("npx @openai/codex-security logout");
    }
  });

  test("prints the ChatGPT recovery hint on noninteractive scan output", async () => {
    const stdout = capture();
    const stderr = capture(false);
    const deps = dependencies();
    deps.createSecurity = () => ({
      run: async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        return fakeResult();
      },
      preflight: async () => fakePreflight(),
      close: async () => {},
    });

    expect(
      await main(["scan", "--json"], stdout.stream, stderr.stream, deps),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    expect(stderr.text()).toContain("API key from OPENAI_API_KEY");
    expect(stderr.text()).toContain("retry with --auth chatgpt");
  });

  test("identifies the rejected API-key source without exposing its value", async () => {
    for (const [environment, source, message] of [
      [
        { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
        "OPENAI_API_KEY",
        "401 invalid API key for org-private",
      ],
      [
        { Codex_Api_Key: "sk-proj-SYNTHETIC_SECRET_456" },
        "CODEX_API_KEY",
        "403 model access denied for org-private",
      ],
    ] as const) {
      const stderr = capture(false);
      const deps = dependencies({ environment });
      deps.createSecurity = () => ({
        run: async () => {
          throw new CodexSecurityError(message);
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(await main(["scan"], capture().stream, stderr.stream, deps)).toBe(
        2,
      );
      expect(stderr.text()).toContain(source);
      expect(stderr.text()).toContain("--auth chatgpt");
      expect(stderr.text()).not.toContain("SYNTHETIC_SECRET");
      expect(stderr.text()).not.toContain("org-private");
    }
  });

  test("reports stored and secondary-key scan authentication on stderr", async () => {
    for (const [authentication, expected] of [
      [
        { method: "stored_credentials", verified: false },
        "Authentication: stored Codex credentials.",
      ],
      [
        { method: "api_key", source: "CODEX_API_KEY", verified: false },
        "Authentication: API key from CODEX_API_KEY.",
      ],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies();
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
          options?.onAuthentication?.(authentication);
          return fakeResult();
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(
        await main(["scan", "--json"], stdout.stream, stderr.stream, deps),
      ).toBe(0);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).not.toContain("env -u");
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    }
  });

  test("keeps selected dry-run authentication metadata safe and machine readable", async () => {
    const stdout = capture();
    const stderr = capture();
    const authentication = {
      method: "api_key" as const,
      source: "CODEX_API_KEY" as const,
      verified: false as const,
    };
    expect(
      await main(
        ["scan", "repo", "--dry-run", "--json"],
        stdout.stream,
        stderr.stream,
        dependencies({
          environment: { CODEX_API_KEY: "synthetic-private-key" },
          preflight: { ...fakePreflight("repo"), authentication },
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({ authentication });
    expect(`${stdout.text()}${stderr.text()}`).not.toContain("synthetic");
  });

  test("recognizes existing ambient Codex authentication on a fresh state directory during login status", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-cli-ambient-auth-")),
    );
    try {
      const ambientHome = join(root, "ambient-codex");
      await mkdir(ambientHome, { mode: 0o700 });
      await writeFile(
        join(ambientHome, "auth.json"),
        '{"auth_mode":"chatgpt"}\n',
      );

      const stdout = capture();
      const stderr = capture();
      let forwardedHome: string | undefined;
      const deps = dependencies({
        environment: {
          CODEX_HOME: ambientHome,
          CODEX_SECURITY_STATE_DIR: stateDirectory,
        },
      });
      deps.runCodex = async (_args, _output, authEnvironment) => {
        forwardedHome = authEnvironment?.["CODEX_HOME"];
        return 0;
      };

      expect(
        await main(["login", "status"], stdout.stream, stderr.stream, deps),
      ).toBe(0);
      expect(forwardedHome).toBe(join(stateDirectory, "codex-home"));
      expect(existsSync(join(stateDirectory, "codex-home", "auth.json"))).toBe(
        true,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("does not import ambient Codex authentication during login status after explicit logout", async () => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "codex-security-cli-ambient-logout-")),
    );
    try {
      const ambientHome = join(root, "ambient-codex");
      await mkdir(ambientHome, { mode: 0o700 });
      await writeFile(
        join(ambientHome, "auth.json"),
        '{"auth_mode":"chatgpt"}\n',
      );

      const credentialHome = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      });
      await setCodexSecurityCredentialLogout(credentialHome, true);

      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({
        environment: {
          CODEX_HOME: ambientHome,
          CODEX_SECURITY_STATE_DIR: stateDirectory,
        },
      });
      deps.runCodex = async () => 0;

      expect(
        await main(["login", "status"], stdout.stream, stderr.stream, deps),
      ).toBe(0);
      expect(existsSync(join(credentialHome, "auth.json"))).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
