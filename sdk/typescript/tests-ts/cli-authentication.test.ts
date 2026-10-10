import { readJsonLines } from "./support/json.js";
import { runProviderSkill } from "./support/cli-provider-authentication.js";
import { resolving } from "./support/promises.js";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  realpath,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, test, mock } from "bun:test";
import { parse as parseToml } from "smol-toml";
import {
  main,
  runCodexSkillCommand as executeSkillCommand,
} from "../src/cli.js";
import {
  CodexSecurityError,
  type JsonObject,
  type ScanOptions,
} from "../src/index.js";
import {
  codexSecurityCredentialAllowsAmbientImport,
  prepareCodexSecurityCredentialHome,
  resolveCodexCommand,
  setCodexSecurityCredentialLogout,
} from "../src/runtime.js";
import {
  savedRecipe,
  capture,
  dependencies as cliDependencies,
  FakeSignals,
  fakePreflight,
  fakeResult,
  fakeSecurity,
  failingSecurity,
} from "./cli-fixtures.js";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";

import {
  selectionPrompt,
  createCliTest,
  captureCli,
  runCapturedCli,
} from "./support/cli-run.js";

const GATEWAY_CONFIGURATION = [
  'model_provider="gateway"',
  "[model_providers.gateway]",
  'name="Synthetic gateway"',
  'base_url="https://gateway.example.test/v1"',
  'wire_api="responses"',
  'env_key="GATEWAY_API_KEY"',
  "requires_openai_auth=true",
].join("\n");

let stateDirectory: string;

beforeEach(async () => {
  stateDirectory = await realpath(
    await temporaryDirectory("codex-security-cli-authentication-"),
  );
  await mkdir(join(stateDirectory, "skill-working-directory"));
});

afterEach(async () => {
  await rm(stateDirectory, { recursive: true, force: true });
});

function runCodexSkillCommand(
  ...[args, output, ...rest]: Parameters<typeof executeSkillCommand>
) {
  return executeSkillCommand(
    args,
    output === undefined
      ? undefined
      : {
          ...output,
          directory:
            output.directory ??
            output.appServer?.directory ??
            join(stateDirectory, "skill-working-directory"),
        },
    ...rest,
  );
}

function dependencies(
  options: Parameters<typeof cliDependencies>[0] = {},
): ReturnType<typeof cliDependencies> {
  return cliDependencies({
    ...options,
    environment: {
      CODEX_HOME: join(stateDirectory, "ambient"),
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
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      const runCodex = mock<typeof deps.runCodex>(resolving(17));
      deps.createSecurity = throwing("must not initialize Codex Security");
      deps.runCodex = runCodex;
      expect(await runCli(argv, deps)).toBe(17);
      expect(runCodex.mock.lastCall?.[0]).toEqual([argv[0], ...argv.slice(1)]);
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
      const { runCli } = createCliTest(main);

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

      expect(await runCli(argv, deps)).toBe(0);
      expect(forwarded).toEqual([...argv]);
      expect(environment?.["CODEX_HOME"]).toBe(expectedHome);
      expect(environment?.["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
      expect(
        await codexSecurityCredentialAllowsAmbientImport(expectedHome),
      ).toBe(argv[0] !== "logout");
    }
  });

  test.skipIf(process.platform === "win32")(
    "validates and canonicalizes the credential home for status and logout",
    async () => {
      const root = await realpath(
        await temporaryDirectory("codex-security-cli-managed-auth-"),
      );
      try {
        const actualState = join(root, "actual-state");
        const linkedState = join(root, "linked-state");
        await mkdir(actualState, { mode: 0o700 });
        await symlink(actualState, linkedState, "dir");
        const expectedHome = join(actualState, "codex-home");

        for (const argv of [["login", "status"], ["logout"]] as const) {
          const { runCli } = createCliTest(main);

          const deps = dependencies({
            environment: { CODEX_SECURITY_STATE_DIR: linkedState },
          });
          let forwardedHome: string | undefined;
          deps.runCodex = async (_args, _output, environment) => {
            forwardedHome = environment?.["CODEX_HOME"];
            return 0;
          };

          expect(await runCli(argv, deps)).toBe(0);
          expect(forwardedHome).toBe(expectedHome);
        }

        expect(
          await codexSecurityCredentialAllowsAmbientImport(expectedHome),
        ).toBe(false);

        const { runCli } = createCliTest(main);

        const deps = dependencies({
          environment: { CODEX_SECURITY_STATE_DIR: linkedState },
        });
        deps.runCodex = async () => 0;
        expect(await runCli(["login"], deps)).toBe(0);
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
      const { stderr, runCli } = createCliTest(main);

      expect(
        await runCli(["login", "status"], dependencies({ environment })),
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
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(argv, dependencies({ environment }))).toBe(0);
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
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["login", "--with-access-token"],
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
      const stderr = captureCli(main, "stderr");

      expect(
        await stderr.run(
          argv,
          dependencies({ environment, onCodex: () => exitCode }),
        ),
      ).toBe(exitCode);
      expect(stderr.text()).not.toContain("ChatGPT login succeeded");
      expect(stderr.text()).not.toContain("Access-token login succeeded");
      expect(stderr.text()).not.toContain("synthetic-private-key");
    }
  });

  test("does not warn after access-token login without an overriding API key", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["login", "--with-access-token"],
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
      const onTurn = mock((_repository: string, { auth }: ScanOptions) => auth);
      const stderr = captureCli(main, "stderr");

      expect(
        await stderr.run(
          argv,
          dependencies({
            environment: { OPENAI_API_KEY: "synthetic-private-key" },
            onTurn,
          }),
        ),
      ).toBe(0);
      expect(onTurn.mock.results.at(-1)?.value).toBe(expected);
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
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: false });

      const deps = dependencies({ environment });
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onAuthentication?.({
            method: "aws_credentials",
            source,
            verified: false,
          });
          return fakeResult();
        });

      expect(
        await runCli(
          [
            "scan",
            "--provider",
            "amazon-bedrock",
            "--model",
            "openai.gpt-5.6-luna",
            "--json",
            "--verbose",
          ],
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
      expect(stderr.text()).toContain(
        "OpenAI sign-in is not required for model access or local results",
      );
      expect(stderr.text()).not.toContain("synthetic-");
      expect(stderr.text()).not.toContain("stored Codex credentials");
      expect(stderr.text()).not.toContain("--auth chatgpt");
    }
  });

  test.each([
    [
      "401 invalid credentials for org-private",
      "Check your Amazon Bedrock bearer token",
      "unauthorized",
    ],
    [
      "403 model access denied for org-private",
      "Check your AWS identity and Bedrock model permissions",
      "forbidden",
    ],
    [
      "403 ExpiredTokenException: The security token included in the request has expired.",
      "Refresh AWS_BEARER_TOKEN_BEDROCK",
      "unauthorized",
    ],
    [
      "UnrecognizedClientException: The security token included in the request is invalid.",
      "Refresh AWS_BEARER_TOKEN_BEDROCK",
      "unauthorized",
    ],
    [
      "AccessDeniedException: Not authorized to invoke the selected model.",
      "configured AWS region, and model ID",
      "forbidden",
    ],
    [
      "400 ThrottlingException: Too many tokens, please wait before trying again.",
      "Check the model quota in the configured AWS region",
      "rate_limited",
    ],
  ] as const)(
    "preserves Bedrock failure details and recovery advice: %s",
    async (detail, expected, classification) => {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: false });

      const deps = dependencies({
        environment: { AWS_BEARER_TOKEN_BEDROCK: "synthetic-bedrock-bearer" },
      });
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onAuthentication?.({
            method: "aws_credentials",
            source: "AWS_BEARER_TOKEN_BEDROCK",
            verified: false,
          });
          throw new CodexSecurityError(detail);
        });

      expect(
        await runCli(
          [
            "scan",
            "--codex",
            'model_provider="amazon-bedrock"',
            "--json",
            "--verbose",
            "--full-output",
          ],
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).toContain(detail);
      expect(stderr.text()).toContain(`classification="${classification}"`);
      expect(JSON.parse(stdout.text()).error.message).toContain(detail);
      expect(JSON.parse(stdout.text()).error.message).toContain(expected);
      expect(stderr.text()).toContain("AWS_BEARER_TOKEN_BEDROCK");
      expect(stderr.text()).not.toContain("synthetic-");
      expect(stderr.text()).not.toContain("--auth chatgpt");
    },
  );

  test("explains refreshing temporary AWS profile credentials without a stored OpenAI login", async () => {
    const stderr = captureCli(main, "stderr", false);
    const deps = dependencies({
      environment: { AWS_PROFILE: "synthetic-profile" },
    });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onAuthentication?.({
          method: "aws_credentials",
          source: "AWS_PROFILE",
          verified: false,
        });
        throw new CodexSecurityError(
          "403 ExpiredTokenException: security token has expired",
        );
      });
    expect(
      await stderr.run(
        ["scan", "--codex", 'model_provider="amazon-bedrock"'],
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("ExpiredTokenException");
    expect(stderr.text()).toContain("AWS_PROFILE");
    expect(stderr.text()).toContain("AWS_SESSION_TOKEN");
    expect(stderr.text()).not.toContain(
      "cannot access the configured Amazon Bedrock model",
    );
    expect(stderr.text()).not.toContain("codex-security login");
  });

  test.each([
    [
      "UnrecognizedClientException: The security token included in the request is invalid.",
      "Check the configured provider auth command",
      "unauthorized",
    ],
    [
      "403 ExpiredTokenException: The security token included in the request has expired.",
      "Check the configured provider auth command",
      "unauthorized",
    ],
    [
      "401 NotAuthorized: You do not have permission to perform this action.",
      "AWS identity and Bedrock model permissions, configured AWS region, and model ID",
      "forbidden",
    ],
    [
      "AccessDeniedException: Not authorized to invoke the selected model.",
      "Check the configured provider auth command",
      "forbidden",
    ],
    [
      "400 ThrottlingException: Too many tokens, please wait before trying again.",
      "Check the model quota in the configured AWS region",
      "rate_limited",
    ],
  ] as const)(
    "preserves command-authenticated Bedrock diagnostics in stderr and JSON: %s",
    async (detail, expected, classification) => {
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: false });

      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onAuthentication?.({ method: "command", verified: false });
          throw new CodexSecurityError(detail);
        });
      expect(
        await runCli(
          [
            "scan",
            "--codex",
            'model_provider="amazon-bedrock"',
            "--codex",
            'model_providers.amazon-bedrock.auth={command="synthetic-auth"}',
            "--json",
            "--verbose",
            "--full-output",
          ],
          deps,
        ),
      ).toBe(2);

      const message = JSON.parse(stdout.text()).error.message;
      for (const output of [stderr.text(), message]) {
        expect(output).toContain(detail);
        expect(output).toContain(expected);
        expect(output).not.toContain("--auth chatgpt");
        expect(output).not.toContain("codex-security login");
        expect(output).not.toContain("stored ChatGPT credentials");
        expect(output).not.toContain("AWS_BEARER_TOKEN_BEDROCK");
        expect(output).not.toContain("AWS_SESSION_TOKEN");
      }
      expect(stderr.text()).toContain(`classification="${classification}"`);
      expect(stderr.text()).toContain("Authentication: native Codex command");
      expect(stderr.text()).toContain(
        "OpenAI sign-in is not required for model access or local results",
      );
    },
  );

  test("offers the existing interactive prompt when both sign-ins are available", async () => {
    for (const [argv, selection] of [
      [["scan"], "chatgpt"],
      [["scan"], "api-key"],
      [["scans", "rerun", "scan-original", "--verbose"], "chatgpt"],
      [["scans", "rerun", "scan-original", "--verbose"], "api-key"],
    ] as const) {
      const stderr = captureCli(main, "stderr", true);
      const onTurn = mock((_repository: string, { auth }: ScanOptions) => auth);
      let question = "";
      let choices: readonly { label: string; value: string }[] = [];
      const deps = dependencies({
        environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
        onTurn,
        onWorkbench: () => savedRecipe(),
      });
      deps.hasStoredChatGPTSignIn = async () => true;
      deps.scanAuthenticationPrompt = selectionPrompt(
        async (message, options) => {
          question = message;
          choices = options;
          return options.find((option) => option.value === selection)!.value;
        },
      );

      expect(await stderr.run(argv, deps)).toBe(0);
      expect(onTurn.mock.results.at(-1)?.value).toBe(selection);
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
      const interrupt = mock((_signal?: AbortSignal) => {
        signals.emit(signalName);
        return new Promise<never>(() => {});
      });
      const createSecurity = mock(
        throwing("must not initialize a cancelled scan"),
      );
      const deps = dependencies({
        signals,
        environment: { OPENAI_API_KEY: "synthetic-private-key" },
      });
      deps.createSecurity = createSecurity;
      deps.hasStoredChatGPTSignIn = (signal) =>
        stage === "status" ? interrupt(signal) : Promise.resolve(true);
      deps.scanAuthenticationPrompt = selectionPrompt(
        (_message, _options, _presentation, signal) => interrupt(signal),
      );

      expect(
        await main(["scan"], capture().stream, capture(true).stream, deps),
      ).toBe(signalName === "SIGTERM" ? 143 : 130);
      expect(interrupt.mock.lastCall?.[0]?.aborted).toBe(true);
      expect(createSecurity).not.toHaveBeenCalled();
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    }
  });

  test("does not hide or relabel a failed ChatGPT login", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["login"],
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
        argv: ["scans", "rerun", "scan-original", "--verbose", "--json"],
        terminal: true,
        stored: true,
        key: true,
      },
      {
        argv: ["scans", "rerun", "--format", "jsonl"],
        terminal: true,
        stored: true,
        key: true,
      },
      {
        argv: ["scans", "rerun", "scan-original", "--json"],
        terminal: true,
        stored: true,
        key: true,
        recipeAuth: "chatgpt" as const,
      },
      {
        argv: ["scans", "rerun", "scan-original", "--json"],
        terminal: true,
        stored: true,
        key: true,
        recipeAuth: "api-key" as const,
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
        expectedAuth: "chatgpt" as const,
      },
      {
        argv: ["scan", "--auth", "api-key"],
        terminal: true,
        stored: true,
        key: true,
        expectedAuth: "api-key" as const,
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
      const { stdout, stderr, runCli } = createCliTest(main, {
        stderr: scenario.terminal,
      });

      const onTurn = mock((_repository: string, { auth }: ScanOptions) => auth);
      let prompts = 0;
      const hasStoredChatGPTSignIn = mock(resolving(scenario.stored));
      const deps = dependencies({
        environment: scenario.key
          ? { OPENAI_API_KEY: "synthetic-private-key" }
          : {},
        onTurn,
        onWorkbench: (args): JsonObject =>
          args[0] === "list-scans"
            ? { scans: [{ scanId: "scan-original" }] }
            : {
                recipe: {
                  repository: "/original/repository",
                  target: { kind: "repository", paths: [] },
                  mode: "standard",
                  ...(scenario.recipeAuth === undefined
                    ? {}
                    : { auth: scenario.recipeAuth }),
                  config: {},
                },
              },
      });
      deps.hasStoredChatGPTSignIn = hasStoredChatGPTSignIn;
      deps.scanAuthenticationPrompt = selectionPrompt(
        async (_message, options) => {
          prompts += 1;
          return options[0]!.value;
        },
        () => scenario.inputInteractive !== false,
      );

      expect(await runCli(scenario.argv, deps)).toBe(0);
      expect(prompts).toBe(0);
      if (scenario.argv.includes("--json") || scenario.argv.includes("jsonl")) {
        expect(hasStoredChatGPTSignIn).toHaveBeenCalledTimes(0);
        expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
        expect(stderr.text()).not.toMatch(/\x1b\[/u);
      }
      if (!scenario.argv.includes("--dry-run")) {
        expect(onTurn.mock.results.at(-1)?.value).toBe(
          scenario.recipeAuth ?? scenario.expectedAuth ?? "auto",
        );
      }
      expect(stderr.text()).not.toContain("synthetic-private-key");
    }
  });

  test("rejects explicit API-key authentication before initializing a scan when no key is set", async () => {
    const stderr = captureCli(main, "stderr");
    const deps = dependencies();
    deps.createSecurity = throwing("must not initialize Codex Security");

    expect(await stderr.run(["scan", "--auth", "api-key"], deps)).toBe(2);
    expect(stderr.text()).toContain(
      "API-key authentication requires OPENAI_API_KEY or CODEX_API_KEY.",
    );
    expect(stderr.text()).toContain("--auth chatgpt");
    expect(stderr.text()).not.toContain("must not initialize");
  });

  test("keeps stored-login status unchanged when no environment key is set", async () => {
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["login", "status"],
        dependencies({ environment: { OPENAI_API_KEY: "   " } }),
      ),
    ).toBe(0);
    expect(stderr.text()).toBe("");
  });

  test("reports effective environment credentials without a stored sign-in", async () => {
    const { stderr, runCli } = createCliTest(main);

    const environment: NodeJS.ProcessEnv = {
      OPENAI_API_KEY: "synthetic-primary-key",
      CODEX_API_KEY: "synthetic-secondary-key",
    };
    expect(
      await runCli(
        ["login", "status"],
        dependencies({ environment, onCodex: () => 1 }),
      ),
    ).toBe(0);
    expect(stderr.text()).toContain("API key from OPENAI_API_KEY");
    expect(stderr.text()).not.toContain("synthetic");

    delete environment["OPENAI_API_KEY"];
    const rotated = captureCli(main, "stderr");
    expect(
      await rotated.run(
        ["login", "status"],
        dependencies({ environment, onCodex: () => 1 }),
      ),
    ).toBe(0);
    expect(rotated.text()).toContain("API key from CODEX_API_KEY");

    expect(
      await runCapturedCli(
        main,
        ["login", "status"],
        dependencies({ environment: {}, onCodex: () => 1 }),
      ),
    ).toBe(1);

    expect(
      await runCapturedCli(
        main,
        ["login", "status"],
        dependencies({
          environment: { OPENAI_API_KEY: "synthetic-key" },
          onCodex: () => 17,
        }),
      ),
    ).toBe(17);
  });

  test("keeps delegated credentials in the configured Codex home", async () => {
    const root = await temporaryDirectory("codex-security-login-home-");
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
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        options?.onScanStarted?.();
        return fakeResult();
      });

    expect(await runCli(["scan", "--json"], deps)).toBe(0);
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
        const { stdout, stderr, runCli } = createCliTest(main, {
          stderr: false,
        });

        const deps = dependencies({ environment });
        deps.createSecurity = () =>
          fakeSecurity(async (_repository, options) => {
            options?.onAuthentication?.({
              method: "api_key",
              source,
              verified: false,
            });
            throw new CodexSecurityError(detail);
          });

        expect(await runCli(["scan"], deps)).toBe(2);
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
        const { stdout, stderr, runCli } = createCliTest(main, {
          stderr: false,
        });

        const deps = dependencies({
          environment: { OPENAI_API_KEY: "sk-proj-SYNTHETIC_SECRET_123" },
          onRun: () => {
            throw new CodexSecurityError(
              `Codex Exec exited with code 1: Error: ${detail} Please log out and sign in again. PRIVATE_UPSTREAM_DETAIL`,
            );
          },
        });

        expect(
          await runCli(["scan", ".", "--auth", auth, "--json"], deps),
        ).toBe(2);
        expect(JSON.parse(stdout.text())).toMatchObject({
          status: "failed",
          code: "SCAN_FAILED",
        });
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
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: false });

      const deps = dependencies({
        onRun: () => {
          throw new CodexSecurityError(
            `Codex Exec exited with code 1: ${message} PRIVATE_UPSTREAM_DETAIL`,
          );
        },
      });

      expect(await runCli(["scan", "--json"], deps)).toBe(2);
      expect(JSON.parse(stdout.text())).toMatchObject({
        status: "failed",
        code: "SCAN_FAILED",
        message,
      });
      expect(stderr.text()).toContain(`${message}\n`);
      expect(stderr.text()).not.toContain("PRIVATE_UPSTREAM_DETAIL");
      expect(stderr.text()).not.toContain("npx @openai/codex-security logout");
    }
  });

  test("prints the ChatGPT recovery hint on noninteractive scan output", async () => {
    const { stdout, stderr, runCli } = createCliTest(main, { stderr: false });

    const deps = dependencies();
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        return fakeResult();
      });

    expect(await runCli(["scan", "--json"], deps)).toBe(0);
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
      const stderr = captureCli(main, "stderr", false);
      const deps = dependencies({ environment });
      deps.createSecurity = () => failingSecurity(message);

      expect(await stderr.run(["scan"], deps)).toBe(2);
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
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity(async (_repository, options) => {
          options?.onAuthentication?.(authentication);
          return fakeResult();
        });

      expect(await runCli(["scan", "--json"], deps)).toBe(0);
      expect(stderr.text()).toContain(expected);
      expect(stderr.text()).not.toContain("env -u");
      expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
    }
  });

  test("keeps selected dry-run authentication metadata safe and machine readable", async () => {
    const { stdout, stderr, runCli } = createCliTest(main);

    const authentication = {
      method: "api_key" as const,
      source: "CODEX_API_KEY" as const,
      verified: false as const,
    };
    expect(
      await runCli(
        ["scan", "repo", "--dry-run", "--json"],
        dependencies({
          environment: { CODEX_API_KEY: "synthetic-private-key" },
          preflight: { ...fakePreflight("repo"), authentication },
        }),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toMatchObject({ authentication });
    expect(`${stdout.text()}${stderr.text()}`).not.toContain("synthetic");
  });

  test.skipIf(process.platform === "win32" || process.geteuid?.() === 0)(
    "reports unreadable ambient credentials during login status",
    async () => {
      const ambientHome = join(stateDirectory, "ambient-codex");
      const authPath = join(ambientHome, "auth.json");
      await mkdir(ambientHome);
      await writeFile(authPath, '{"auth_mode":"chatgpt"}\n', { mode: 0o000 });
      const deps = dependencies({ environment: { CODEX_HOME: ambientHome } });
      deps.runCodex = async () => {
        throw new Error("Must not query Codex after an import failure");
      };
      const stderr = capture();
      try {
        expect(
          await main(
            ["login", "status"],
            capture().stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        expect(stderr.text()).toContain(
          "Unable to copy ambient Codex authentication.",
        );
      } finally {
        await chmod(authPath, 0o600);
      }
      deps.runCodex = async () => 0;
      expect(
        await main(["login", "status"], capture().stream, stderr.stream, deps),
      ).toBe(0);
    },
  );

  test.each([false, true])(
    "recognizes existing ambient Codex authentication on a fresh state directory during login status (home-relative: %p)",
    async (homeRelative) => {
      const root = await realpath(
        await temporaryDirectory("codex-security-cli-ambient-auth-"),
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
            HOME: root,
            USERPROFILE: root,
            CODEX_HOME: homeRelative ? "~/ambient-codex" : ambientHome,
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
        expect(
          existsSync(join(stateDirectory, "codex-home", "auth.json")),
        ).toBe(true);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test("does not import ambient Codex authentication during login status after explicit logout", async () => {
    const root = await realpath(
      await temporaryDirectory("codex-security-cli-ambient-logout-"),
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

      const { runCli } = createCliTest(main);

      const deps = dependencies({
        environment: {
          CODEX_HOME: ambientHome,
          CODEX_SECURITY_STATE_DIR: stateDirectory,
        },
      });
      deps.runCodex = async () => 0;

      expect(await runCli(["login", "status"], deps)).toBe(0);
      expect(existsSync(join(credentialHome, "auth.json"))).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("skill authentication", () => {
  test.each(["patch", "verify-fix"] as const)(
    "%s inherits ambient command authentication through a null optional override",
    async (command) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        overrides: { model_providers: { gateway: { auth: null } } },
        ambientConfig: [
          'model_provider="gateway"',
          "[model_providers.gateway]",
          'name="Synthetic gateway"',
          'base_url="https://gateway.example.test/v1"',
          'wire_api="responses"',
          "[model_providers.gateway.auth]",
          'command="synthetic-auth"',
        ].join("\n"),
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch).toBeDefined();
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
    },
  );

  test.each([
    ["validate", "auto", "gateway"],
    ["validate", "api-key", "gateway"],
    ["patch", "auto", "gateway"],
    ["patch", "api-key", "gateway"],
    ["verify-fix", "auto", "gateway"],
    ["verify-fix", "api-key", "gateway"],
    ["patch", "api-key", "openrouter"],
  ] as const)(
    "%s uses the custom provider env_key with %s auth (%s)",
    async (command, auth, provider) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        auth,
        overrides: [
          `model_provider=${JSON.stringify(provider)}`,
          `model_providers.${provider}.name="Synthetic gateway"`,
          `model_providers.${provider}.base_url="https://gateway.example.test/v1"`,
          `model_providers.${provider}.wire_api="responses"`,
          `model_providers.${provider}.env_key="GATEWAY_API_KEY"`,
        ],
        environment: { GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY",
      });
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
      if (command !== "validate") {
        expect(
          result.requests.find((request) => request.method === "thread/start")
            .params.modelProvider,
        ).toBe(provider);
      }
    },
  );

  for (const nullAuth of [false, true]) {
    test.each(["validate", "patch", "verify-fix"] as const)(
      `%s forwards a provider's OpenAI-named key (null auth: ${nullAuth})`,
      async (command) => {
        const stdout = capture();
        const stderr = capture();
        const status = await runCodexSkillCommand(
          [
            "-e",
            'console.log(JSON.stringify({type:"item.completed",item:{type:"agent_message",text:JSON.stringify({key:process.env.OPENAI_API_KEY})}}))',
          ],
          {
            command,
            auth: "api-key",
            modelProvider: "gateway",
            codexOverrides: {
              model_provider: "gateway",
              model_providers: {
                gateway: {
                  env_key: "OPENAI_API_KEY",
                  ...(nullAuth ? { auth: null } : {}),
                },
              },
            },
            stdout: stdout.stream,
            stderr: stderr.stream,
          },
          { command: process.execPath },
          {
            CODEX_HOME: join(stateDirectory, "ambient"),
            OPENAI_API_KEY: "SYNTHETIC_PROVIDER_KEY",
          },
        );
        expect(status, stderr.text()).toBe(0);
        expect(JSON.parse(stdout.text())).toEqual({
          key: "SYNTHETIC_PROVIDER_KEY",
        });
      },
    );
  }

  test("rejects a missing custom provider API key before launch", async () => {
    const result = await runProviderSkill(stateDirectory, {
      overrides: [
        'model_provider="gateway"',
        'model_providers.gateway.env_key="GATEWAY_API_KEY"',
      ],
    });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("GATEWAY_API_KEY");
    expect(result.launch).toBeUndefined();
  });

  test.each(["patch", "verify-fix"] as const)(
    "%s preserves valid names in unrelated ambient configuration",
    async (command) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        overrides: [],
        ambientConfig: [
          'model_provider="gateway"',
          "[model_providers.gateway]",
          'name="Synthetic gateway"',
          'base_url="https://gateway.example.test/v1"',
          'wire_api="responses"',
          'env_key="GATEWAY_API_KEY"',
          "[mcp_servers.prototype]",
          'command="synthetic-mcp"',
          "enabled=false",
        ].join("\n"),
        environment: { GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY",
      });
    },
  );

  test.each([true, false])(
    "patch uses a custom provider table override with ambient selection (new key present: %p)",
    async (hasSelectedKey) => {
      const result = await runProviderSkill(stateDirectory, {
        overrides: ['model_providers.gateway.env_key="GATEWAY_API_KEY"'],
        ambientConfig: [
          'model_provider="gateway"',
          "[model_providers.gateway]",
          'name="Synthetic gateway"',
          'base_url="https://gateway.example.test/v1"',
          'wire_api="responses"',
          'env_key="OLD_GATEWAY_API_KEY"',
        ].join("\n"),
        environment: hasSelectedKey
          ? { GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" }
          : { OLD_GATEWAY_API_KEY: "SYNTHETIC_OLD_KEY" },
      });
      if (hasSelectedKey) {
        expect(result.status, result.stderr).toBe(0);
        expect(result.launch.environment).toEqual({
          GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY",
        });
      } else {
        expect(result.status).toBe(2);
        expect(result.stderr).toMatch(/\bGATEWAY_API_KEY\b/u);
        expect(result.launch).toBeUndefined();
      }
    },
  );

  test.each([
    ["patch", false, false],
    ["patch", true, false],
    ["verify-fix", false, false],
    ["verify-fix", true, false],
    ["patch", true, true],
  ] as const)(
    "%s keeps ambient provider authentication with explicit selection (partial override: %p, profile: %p)",
    async (command, partialOverride, profile) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        overrides: [
          'model_provider="gateway"',
          ...(partialOverride
            ? [
                'model_providers.gateway.base_url="https://alternate.example.test/v1"',
              ]
            : []),
        ],
        ambientConfig: [
          ...(profile ? ['profile="ambient"'] : []),
          'model_provider="gateway"',
          ...(profile ? ["[profiles.ambient]", 'model_provider="other"'] : []),
          "[model_providers.gateway]",
          'name="Synthetic gateway"',
          'base_url="https://gateway.example.test/v1"',
          'wire_api="responses"',
          "requires_openai_auth=true",
          ...(profile
            ? [
                "[model_providers.other]",
                'name="Other gateway"',
                'base_url="https://other.example.test/v1"',
                'wire_api="responses"',
                'env_key="OTHER_API_KEY"',
              ]
            : []),
        ].join("\n"),
        environment: { OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY" },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        CODEX_API_KEY: "SYNTHETIC_OPENAI_KEY",
      });
      expect(result.launch.args).toContain(
        'cli_auth_credentials_store="ephemeral"',
      );
      expect(
        result.requests
          .filter((request) => request.method === "account/login/start")
          .map((request) => request.params),
      ).toEqual([{ type: "apiKey", apiKey: "SYNTHETIC_OPENAI_KEY" }]);
    },
  );

  test.each([
    ["ollama", "auto"],
    ["ollama", "api-key"],
    ["lmstudio", "auto"],
    ["lmstudio", "api-key"],
  ] as const)(
    "patch ignores replacement authentication for native provider %s with %s auth",
    async (provider, auth) => {
      const result = await runProviderSkill(stateDirectory, {
        auth,
        overrides: [`model_provider=${JSON.stringify(provider)}`],
        ambientConfig: [
          `model_provider=${JSON.stringify(provider)}`,
          `[model_providers.${provider}]`,
          'name="Synthetic override"',
          'base_url="https://ignored.example.test/v1"',
          'wire_api="responses"',
          'env_key="IGNORED_KEY"',
          "requires_openai_auth=true",
        ].join("\n"),
        environment: { OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY" },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY",
      });
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
    },
  );

  test.each(["patch", "verify-fix"] as const)(
    "%s keeps native OpenAI authentication despite a provider table override",
    async (command) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        overrides: ['model_provider="openai"'],
        ambientConfig: [
          'model_provider="openai"',
          "[model_providers.openai]",
          'name="Synthetic override"',
          'base_url="https://ignored.example.test/v1"',
          'wire_api="responses"',
          'env_key="OPENAI_API_KEY"',
        ].join("\n"),
        environment: { OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY" },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        CODEX_API_KEY: "SYNTHETIC_OPENAI_KEY",
      });
      expect(result.launch.args).toContain(
        'cli_auth_credentials_store="ephemeral"',
      );
      expect(
        result.requests
          .filter((request) => request.method === "account/login/start")
          .map((request) => request.params),
      ).toEqual([{ type: "apiKey", apiKey: "SYNTHETIC_OPENAI_KEY" }]);
    },
  );

  test.each([
    ["patch", "auto"],
    ["patch", "api-key"],
    ["verify-fix", "auto"],
    ["verify-fix", "api-key"],
  ] as const)(
    "%s uses the custom provider key before OpenAI login with %s auth",
    async (command, auth) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        auth,
        overrides: ['model_provider="gateway"'],
        ambientConfig: GATEWAY_CONFIGURATION,
        environment: { GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY",
      });
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
    },
  );

  test.each(["patch", "verify-fix"] as const)(
    "%s keeps ambient provider credentials out of process arguments",
    async (command) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        auth: "chatgpt",
        overrides: [
          'model_provider="gateway"',
          'model_providers.gateway.env_key="GATEWAY_API_KEY"',
          "model_providers.gateway.requires_openai_auth=false",
          'model_providers.gateway.http_headers.X-Explicit="SYNTHETIC_CLI_HEADER"',
        ],
        ambientConfig: [
          'model_provider="gateway"',
          "[model_providers.gateway]",
          'name="Synthetic gateway"',
          'base_url="https://gateway.example.test/v1"',
          'wire_api="responses"',
          'env_key="GATEWAY_API_KEY"',
          "[model_providers.gateway.http_headers]",
          'Authorization="Bearer SYNTHETIC_SELECTED_CREDENTIAL"',
          "[model_providers.other]",
          'name="Other gateway"',
          'base_url="https://other.example.test/v1"',
          'wire_api="responses"',
          'experimental_bearer_token="SYNTHETIC_UNSELECTED_CREDENTIAL"',
        ].join("\n"),
        environment: { GATEWAY_API_KEY: "SYNTHETIC_GATEWAY_KEY" },
        storedCredentials: true,
      });
      expect(result.status, result.stderr).toBe(0);
      const argumentsText = JSON.stringify(result.launch.args);
      expect(argumentsText).not.toContain("SYNTHETIC_SELECTED_CREDENTIAL");
      expect(argumentsText).not.toContain("SYNTHETIC_UNSELECTED_CREDENTIAL");
      expect(argumentsText).toContain("SYNTHETIC_CLI_HEADER");
      expect(parseToml(result.launch.config)["model_providers"]).toEqual({
        gateway: {
          name: "Synthetic gateway",
          base_url: "https://gateway.example.test/v1",
          wire_api: "responses",
          requires_openai_auth: true,
          http_headers: {
            Authorization: "Bearer SYNTHETIC_SELECTED_CREDENTIAL",
            "X-Explicit": "SYNTHETIC_CLI_HEADER",
          },
        },
      });
    },
  );

  test.each(["patch", "verify-fix"] as const)(
    "%s rejects a missing custom provider key despite an available OpenAI key",
    async (command) => {
      const result = await runProviderSkill(stateDirectory, {
        command,
        overrides: ['model_provider="gateway"'],
        ambientConfig: GATEWAY_CONFIGURATION,
        environment: { OPENAI_API_KEY: "SYNTHETIC_UNRELATED_OPENAI_KEY" },
      });
      expect(result.status).toBe(2);
      expect(result.stderr).toMatch(/\bGATEWAY_API_KEY\b/u);
      expect(result.launch).toBeUndefined();
    },
  );

  test.each([
    ["patch", "OPENAI_API_KEY"],
    ["patch", "CODEX_API_KEY"],
    ["verify-fix", "OPENAI_API_KEY"],
    ["verify-fix", "CODEX_API_KEY"],
  ] as const)(
    "%s preserves provider key %s without OpenAI login",
    async (command, envKey) => {
      const configuredEnvKey =
        process.platform === "win32" ? envKey.toLowerCase() : envKey;
      const result = await runProviderSkill(stateDirectory, {
        command,
        overrides: ['model_provider="gateway"'],
        ambientConfig: [
          'model_provider="gateway"',
          "[model_providers.gateway]",
          'name="Synthetic gateway"',
          'base_url="https://gateway.example.test/v1"',
          'wire_api="responses"',
          `env_key=${JSON.stringify(configuredEnvKey)}`,
          "requires_openai_auth=true",
        ].join("\n"),
        environment: {
          OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY",
          CODEX_API_KEY: "SYNTHETIC_CODEX_KEY",
        },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
      expect(result.launch.environment[envKey]).toBe(
        envKey === "OPENAI_API_KEY"
          ? "SYNTHETIC_OPENAI_KEY"
          : "SYNTHETIC_CODEX_KEY",
      );
    },
  );

  test("resolves custom provider key casing according to the platform", async () => {
    const result = await runProviderSkill(stateDirectory, {
      overrides: [
        'model_provider="gateway"',
        'model_providers.gateway.env_key="GATEWAY_API_KEY"',
      ],
      environment: { gateway_api_key: "SYNTHETIC_GATEWAY_KEY" },
    });
    if (process.platform === "win32") {
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment.GATEWAY_API_KEY).toBe(
        "SYNTHETIC_GATEWAY_KEY",
      );
    } else {
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("GATEWAY_API_KEY");
      expect(result.launch).toBeUndefined();
    }
  });

  test.each([
    ["openrouter", "api-key"],
    ["fireworks", "api-key"],
    ["openrouter", "chatgpt"],
    ["fireworks", "chatgpt"],
  ] as const)(
    "preserves OPENAI_API_KEY when configured as the %s provider key with %s auth",
    async (provider, auth) => {
      const result = await runProviderSkill(stateDirectory, {
        auth,
        overrides: [
          `model_provider=${JSON.stringify(provider)}`,
          `model_providers.${provider}.name="Synthetic gateway"`,
          `model_providers.${provider}.base_url="https://gateway.example.test/v1"`,
          `model_providers.${provider}.wire_api="responses"`,
          `model_providers.${provider}.env_key="OPENAI_API_KEY"`,
          `model_providers.${provider}.requires_openai_auth=${auth === "chatgpt"}`,
        ],
        environment: {
          OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY",
          CODEX_API_KEY: "SYNTHETIC_CODEX_KEY",
        },
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({
        OPENAI_API_KEY: "SYNTHETIC_OPENAI_KEY",
      });
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
    },
  );

  test.each([
    ["validate", "override"],
    ["patch", "override"],
    ["verify-fix", "override"],
    ["patch", "ambient"],
    ["verify-fix", "ambient"],
  ] as const)(
    "%s uses native provider bearer authentication from %s without an OpenAI login",
    async (command, source) => {
      const providerConfig = {
        name: "Synthetic gateway",
        base_url: "https://gateway.example.test/v1",
        wire_api: "responses",
        experimental_bearer_token: "SYNTHETIC_BEARER_TOKEN",
        requires_openai_auth: true,
      };
      const settings = Object.entries(providerConfig).map(
        ([key, value]) => `${key}=${JSON.stringify(value)}`,
      );
      const result = await runProviderSkill(stateDirectory, {
        command,
        auth: "auto",
        overrides: [
          'model_provider="gateway"',
          ...(source === "override"
            ? settings.map((setting) => `model_providers.gateway.${setting}`)
            : []),
        ],
        ...(source === "ambient"
          ? {
              ambientConfig: ["[model_providers.gateway]", ...settings].join(
                "\n",
              ),
            }
          : {}),
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.launch.environment).toEqual({});
      if (source === "override") {
        const override = result.launch.args.findLast((arg: string) =>
          arg.startsWith("model_providers="),
        );
        expect(parseToml(override)["model_providers"]).toEqual({
          gateway: providerConfig,
        });
      } else {
        expect(parseToml(result.launch.config)["model_providers"]).toEqual({
          gateway: providerConfig,
        });
      }
      expect(result.requests.map((request) => request.method)).not.toContain(
        "account/login/start",
      );
    },
  );

  test.each(["validate", "patch", "verify-fix"])(
    "%s advertises scan auth modes",
    async (command) => {
      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(
          [command, "--schema", "--format", "json"],
          dependencies(),
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text()).options.properties.auth).toMatchObject({
        enum: ["auto", "chatgpt", "api-key"],
        default: "auto",
      });
      const help = captureCli(main, "stdout");
      expect(await help.run([command, "--help"], dependencies())).toBe(0);
      expect(help.text()).toContain("--auth");
    },
  );

  test.each(["validate", "patch", "verify-fix"] as const)(
    "%s reads the login credential home",
    async (command) => {
      const environment = {
        CODEX_HOME: join(stateDirectory, "ambient"),
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      };
      const credentialHome =
        await prepareCodexSecurityCredentialHome(environment);
      await writeFile(
        join(credentialHome, "auth.json"),
        JSON.stringify({
          auth_mode: "apikey",
          OPENAI_API_KEY: "SYNTHETIC_STORED_KEY",
        }),
        { mode: 0o600 },
      );
      const stdout = capture();
      const stderr = capture();
      const script = `console.log(JSON.stringify({type:"item.completed",item:{type:"agent_message",text:JSON.stringify({home:process.env.CODEX_HOME,state:process.env.CODEX_SECURITY_STATE_DIR})}}))`;
      expect(
        await runCodexSkillCommand(
          ["-e", script],
          {
            command,
            auth: "auto",
            stdout: stdout.stream,
            stderr: stderr.stream,
          },
          { command: process.execPath },
          environment,
        ),
      ).toBe(0);
      expect(JSON.parse(stdout.text())).toEqual({
        home: credentialHome,
        state: stateDirectory,
      });
    },
  );

  test.each(["validate", "patch", "verify-fix"])(
    "%s rejects missing explicit API-key authentication before launch",
    async (command) => {
      const stderr = captureCli(main, "stderr");
      expect(
        await stderr.run(
          [command, "Synthetic issue", "--auth", "api-key"],
          dependencies({
            onCodex: (_args, output, environment, input) =>
              runCodexSkillCommand(
                ["-e", 'throw new Error("must not launch")'],
                output,
                { command: process.execPath },
                environment,
                input,
              ),
          }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(
        "API-key authentication requires OPENAI_API_KEY or CODEX_API_KEY",
      );
    },
  );
  test.each([
    ["auto", false, undefined, false],
    ["chatgpt", false, undefined, false],
    ["chatgpt", true, undefined, false],
    ["chatgpt", false, "synthetic", false],
    ["api-key", false, undefined, false],
    ["api-key", true, undefined, false],
    ["auto", false, "synthetic", false],
    ["api-key", false, "synthetic", false],
    ["api-key", false, "synthetic", true],
    ["chatgpt", false, "synthetic", true],
  ] as const)(
    "patch uses %s auth without replacing a saved login (failure: %p, provider: %s, explicit: %p)",
    async (auth, loginFailure, provider, explicitProvider) => {
      const repository = join(stateDirectory, "repository");
      await mkdir(repository);
      const ambientHome = join(stateDirectory, "ambient");
      await mkdir(ambientHome);
      const credentialHome = await prepareCodexSecurityCredentialHome({
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      });
      await writeFile(
        join(credentialHome, "config.toml"),
        [
          'model_provider = "stale"',
          'profile = "stale"',
          "[profiles.stale]",
          'model_provider = "stale"',
          "[model_providers.stale]",
          'name = "Stale provider"',
          'base_url = "https://example.com/v1"',
          'env_key = "STALE_API_KEY"',
        ].join("\n"),
      );
      const stored = JSON.stringify({
        auth_mode: "apikey",
        OPENAI_API_KEY: "SYNTHETIC_STORED_KEY",
      });
      await writeFile(join(credentialHome, "auth.json"), stored, {
        mode: 0o600,
      });
      await writeFile(join(ambientHome, "auth.json"), stored, { mode: 0o600 });
      if (auth === "chatgpt") {
        await writeFile(
          join(ambientHome, "config.toml"),
          'forced_login_method = "api"',
        );
      }
      const providerConfiguration = {
        name: "Synthetic provider",
        base_url: "https://example.test/v1",
        wire_api: "responses",
        env_key: "OPENAI_API_KEY",
        requires_openai_auth: auth === "chatgpt",
      };
      if (provider !== undefined && !explicitProvider) {
        await writeFile(
          join(ambientHome, "config.toml"),
          [
            ...(auth === "chatgpt" ? ['forced_login_method = "api"'] : []),
            'model_provider = "synthetic"',
            "[model_providers.synthetic]",
            'name = "Synthetic provider"',
            'base_url = "https://example.com/v1"',
            'env_key = "OPENAI_API_KEY"',
            `requires_openai_auth = ${auth === "chatgpt"}`,
          ].join("\n"),
        );
      }
      const usesSessionKey = auth !== "chatgpt" && provider === undefined;
      const requestLog = join(stateDirectory, "requests.jsonl");
      const { stdout, stderr, runCli } = createCliTest(main);

      const environment = {
        CODEX_HOME: ambientHome,
        ...(provider === undefined || auth === "chatgpt"
          ? {
              OpenAI_API_KEY: "  SYNTHETIC_OPENAI_KEY  ",
              CODEX_API_KEY: "SYNTHETIC_CODEX_KEY",
            }
          : {
              OPENAI_API_KEY: "SYNTHETIC_CUSTOM_KEY",
              SYNTHETIC_EXPECTED_CUSTOM_KEY: "SYNTHETIC_CUSTOM_KEY",
            }),
        SYNTHETIC_REQUEST_LOG: requestLog,
        ...(auth === "chatgpt"
          ? { SYNTHETIC_EXPECTED_PROVIDER: provider ?? "" }
          : {}),
        ...(auth === "chatgpt" && provider === undefined
          ? { SYNTHETIC_CHECK_STARTUP_LOCK: "1" }
          : {}),
        ...(loginFailure ? { SYNTHETIC_LOGIN_FAILURE: "1" } : {}),
        SYNTHETIC_EXPECTED_HOME:
          auth === "chatgpt" ? credentialHome : ambientHome,
        ...(usesSessionKey
          ? { SYNTHETIC_EXPECTED_KEY: "SYNTHETIC_OPENAI_KEY" }
          : {}),
      };
      expect(
        await runCli(
          [
            "patch",
            "Synthetic issue",
            "--auth",
            auth,
            ...(explicitProvider
              ? [
                  "--codex",
                  `model_provider=${JSON.stringify(provider)}`,
                  ...Object.entries(providerConfiguration).flatMap(
                    ([key, value]) => [
                      "--codex",
                      `model_providers.${provider}.${key}=${JSON.stringify(value)}`,
                    ],
                  ),
                ]
              : []),
          ],
          dependencies({
            environment,
            currentDirectory: repository,
            onCodex: (args, output, environment, input) =>
              runCodexSkillCommand(
                [
                  fileURLToPath(
                    new URL("./fixtures/skill-auth.mjs", import.meta.url),
                  ),
                  ...args,
                ],
                output,
                { command: process.execPath },
                environment,
                input,
              ),
          }),
        ),
      ).toBe(loginFailure ? 1 : 0);
      expect(stdout.text()).toBe(
        loginFailure ? "" : "Synthetic patch complete\n",
      );
      if (loginFailure)
        expect(stderr.text()).toContain(
          auth === "chatgpt"
            ? "Authentication failed using a stored API key"
            : "Authentication failed using OPENAI_API_KEY",
        );
      else expect(stderr.text()).toBe("Patch applied. Files changed: 1.\n");
      const requests = await readJsonLines(requestLog);
      const methods = requests.map((request) => request.method);
      if (!loginFailure) {
        expect(
          requests.find((request) => request.method === "thread/start").params
            .modelProvider,
        ).toBe(explicitProvider ? provider : undefined);
      }
      expect(methods).toEqual([
        "initialize",
        "initialized",
        ...(usesSessionKey ? ["account/login/start"] : []),
        ...(loginFailure && usesSessionKey ? [] : ["thread/start"]),
        ...(loginFailure ? [] : ["command/exec", "turn/start"]),
      ]);
      expect(await readFile(join(credentialHome, "auth.json"), "utf8")).toBe(
        stored,
      );
      expect(await readFile(join(ambientHome, "auth.json"), "utf8")).toBe(
        stored,
      );
      if (auth === "chatgpt") {
        expect(
          existsSync(join(credentialHome, ".codex-security-scan.lock")),
        ).toBe(false);
        expect(
          parseToml(
            await readFile(join(credentialHome, "config.toml"), "utf8"),
          ),
        ).toMatchObject({ forced_login_method: "api" });
      }
    },
  );

  test("imports an ambient login once and respects logout", async () => {
    const ambientHome = join(stateDirectory, "ambient");
    const environment = {
      CODEX_HOME: ambientHome,
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    };
    await mkdir(ambientHome);
    const credentialHome =
      await prepareCodexSecurityCredentialHome(environment);
    const stored = JSON.stringify({
      auth_mode: "apikey",
      OPENAI_API_KEY: "SYNTHETIC_STORED_KEY",
    });
    await writeFile(join(ambientHome, "auth.json"), stored, { mode: 0o600 });
    const run = () =>
      runCodexSkillCommand(
        [
          "-e",
          'console.log(JSON.stringify({type:"item.completed",item:{type:"agent_message",text:"done"}}))',
        ],
        {
          command: "validate",
          auth: "auto",
          stdout: capture().stream,
          stderr: capture().stream,
        },
        { command: process.execPath },
        environment,
      );
    expect(await run()).toBe(0);
    expect(await readFile(join(credentialHome, "auth.json"), "utf8")).toBe(
      stored,
    );
    await rm(join(credentialHome, "auth.json"));
    await setCodexSecurityCredentialLogout(credentialHome, true);
    await expect(run()).rejects.toThrow("No credentials were found");
    expect(existsSync(join(credentialHome, "auth.json"))).toBe(false);
  });
  test.each([
    ["shared", "auto"],
    ["ambient", "auto"],
    ["ambient", "api-key"],
  ] as const)(
    "validation honors %s credential storage and login restrictions with %s auth",
    async (authSource, auth) => {
      const environment = {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        CODEX_HOME: join(stateDirectory, "ambient"),
        ...(auth === "api-key"
          ? { OPENAI_API_KEY: "SYNTHETIC_SESSION_KEY" }
          : {}),
      };
      const home = await prepareCodexSecurityCredentialHome(environment);
      const sourceHome =
        authSource === "shared" ? home : environment.CODEX_HOME;
      await mkdir(environment.CODEX_HOME, { recursive: true });
      await writeFile(join(home, "config.toml"), 'model = "existing-model"');
      await writeFile(
        join(environment.CODEX_HOME, "config.toml"),
        [
          'cli_auth_credentials_store = "keyring"',
          'forced_login_method = "chatgpt"',
          'forced_chatgpt_workspace_id = "synthetic-workspace"',
          'model = "unrelated-model"',
        ].join("\n"),
      );
      await writeFile(
        join(sourceHome, "auth.json"),
        JSON.stringify({
          auth_mode: "apikey",
          OPENAI_API_KEY: "SYNTHETIC_KEY",
        }),
        { mode: 0o600 },
      );
      const run = async () => {
        const stdout = capture();
        const source =
          'console.log(JSON.stringify({type:"item.completed",item:{type:"agent_message",text:JSON.stringify({args:process.argv,home:process.env.CODEX_HOME})}}))';
        expect(
          await runCodexSkillCommand(
            ["-e", source, "--"],
            {
              command: "validate",
              auth,
              stdout: stdout.stream,
              stderr: capture().stream,
            },
            { command: process.execPath },
            environment,
          ),
        ).toBe(0);
        return JSON.parse(stdout.text());
      };
      const { args, home: runtimeHome } = await run();
      expect(runtimeHome).toBe(
        auth === "api-key" ? environment.CODEX_HOME : home,
      );
      expect(args).toContain('cli_auth_credentials_store="keyring"');
      expect(args).toContain('forced_login_method="chatgpt"');
      expect(args).toContain(
        'forced_chatgpt_workspace_id="synthetic-workspace"',
      );
      expect(args).not.toContain('model="unrelated-model"');
      expect(
        parseToml(await readFile(join(runtimeHome, "config.toml"), "utf8")),
      ).toMatchObject({
        cli_auth_credentials_store: "keyring",
        forced_login_method: "chatgpt",
        forced_chatgpt_workspace_id: "synthetic-workspace",
        model: auth === "auto" ? "existing-model" : "unrelated-model",
      });
      await writeFile(
        join(environment.CODEX_HOME, "config.toml"),
        'model = "unrelated-model"',
      );
      expect((await run()).args).toEqual([process.execPath]);
      expect(
        parseToml(await readFile(join(runtimeHome, "config.toml"), "utf8")),
      ).toEqual({
        model: auth === "auto" ? "existing-model" : "unrelated-model",
      });
    },
  );
  test.each(["patch", "verify-fix"] as const)(
    "%s requires the selected external provider key",
    async (command) => {
      for (const [provider, key] of [
        ["fireworks", "FIREWORKS_API_KEY"],
        ["openrouter", "OPENROUTER_API_KEY"],
      ] as const) {
        for (const auth of ["api-key", "auto", "chatgpt"] as const) {
          await expect(
            runCodexSkillCommand(
              ["-e", "process.exit(0)"],
              {
                command,
                auth,
                modelProvider: provider,
                stdout: capture().stream,
                stderr: capture().stream,
              },
              { command: process.execPath },
              {
                CODEX_HOME: join(stateDirectory, "ambient"),
                CODEX_SECURITY_STATE_DIR: stateDirectory,
              },
            ),
          ).rejects.toThrow(key);
        }
      }
    },
  );

  test.each(["validate", "patch", "verify-fix"] as const)(
    "%s stops before starting a model command without a stored login",
    async (command) => {
      for (const auth of ["auto", "chatgpt"] as const) {
        await expect(
          runCodexSkillCommand(
            ["invalid-synthetic-command"],
            {
              command,
              auth,
              stdout: capture().stream,
              stderr: capture().stream,
            },
            resolveCodexCommand({}),
            {
              CODEX_HOME: join(stateDirectory, "ambient"),
              CODEX_SECURITY_STATE_DIR: stateDirectory,
            },
          ),
        ).rejects.toThrow("No credentials were found");
      }
    },
  );

  test.each(["ChatGPT", "an API key"])(
    "checks native login status without a credential file (%s)",
    async (credentialLabel) => {
      const environment = {
        CODEX_HOME: join(stateDirectory, "ambient"),
        CODEX_SECURITY_STATE_DIR: stateDirectory,
      };
      const home = await prepareCodexSecurityCredentialHome(environment);
      const preload = join(stateDirectory, "native-status.mjs");
      const marker = join(home, "status-home");
      await writeFile(
        preload,
        `
import { basename, join } from "node:path";
import { writeFileSync } from "node:fs";
if (basename(process.argv[1] ?? "") === "login" && process.argv[2] === "status") {
  writeFileSync(join(process.env.CODEX_HOME, "status-home"), process.env.CODEX_HOME);
  console.log(${JSON.stringify("Logged in using " + credentialLabel)});
  process.exit(0);
}
`,
      );
      const node = spawnSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      });
      expect(node.status, node.stderr).toBe(0);
      const stderr = capture();
      const unauthorized = credentialLabel === "an API key";
      expect(
        await runCodexSkillCommand(
          [
            "-e",
            unauthorized
              ? 'console.error("401 Unauthorized"); process.exit(1)'
              : 'console.log(JSON.stringify({type:"item.completed",item:{type:"agent_message",text:"done"}}))',
          ],
          {
            command: "validate",
            auth: "chatgpt",
            stdout: capture().stream,
            stderr: stderr.stream,
          },
          { command: node.stdout.trim() },
          {
            ...environment,
            NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
          },
        ),
      ).toBe(unauthorized ? 1 : 0);
      if (unauthorized) {
        expect(stderr.text()).toContain(
          "Authentication failed using stored credentials",
        );
        expect(stderr.text()).not.toContain("ChatGPT");
      }
      expect(await readFile(marker, "utf8")).toBe(home);
      expect(existsSync(join(home, "auth.json"))).toBe(false);
    },
  );
  test.each(["validate", "patch", "verify-fix"] as const)(
    "%s keeps imported credentials outside enclosing worktrees, including subdirectories and aliases",
    async (command) => {
      const repository = join(stateDirectory, "repository");
      const ambientHome = join(stateDirectory, "ambient");
      const alias = join(stateDirectory, "repository-alias");
      const component = join(repository, "component");
      const nestedRepository = join(repository, "nested");
      await mkdir(component, { recursive: true });
      await mkdir(nestedRepository);
      for (const root of [repository, nestedRepository]) {
        expect(spawnSync("git", ["init", "--quiet", root]).status).toBe(0);
      }
      await mkdir(ambientHome);
      await symlink(
        repository,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
      await writeFile(
        join(ambientHome, "auth.json"),
        JSON.stringify({
          auth_mode: "apikey",
          OPENAI_API_KEY: "SYNTHETIC_STORED_KEY",
        }),
        { mode: 0o600 },
      );
      for (const target of [
        repository,
        alias,
        component,
        join(alias, "component"),
        nestedRepository,
      ]) {
        const stderr = captureCli(main, "stderr");
        const status = await stderr.run(
          [command, "Synthetic issue", "--auth", "chatgpt"],
          dependencies({
            currentDirectory: target,
            environment: {
              CODEX_HOME: ambientHome,
              CODEX_SECURITY_STATE_DIR: join(repository, "state"),
            },
            onCodex: (_args, output, environment) => {
              if (output === undefined)
                throw new Error("Missing model-command output");
              expect(output.directory).toBe(target);
              return runCodexSkillCommand(
                ["-e", "process.exit(0)"],
                { ...output, appServer: undefined },
                { command: process.execPath },
                environment,
              );
            },
          }),
        );
        expect(
          existsSync(join(repository, "state", "codex-home", "auth.json")),
        ).toBe(false);
        expect(status).toBe(2);
        expect(stderr.text()).toContain("outside");
      }
    },
  );
});
