import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, win32 } from "node:path";
import { parse, stringify } from "smol-toml";
import {
  Codex,
  type CodexOptions,
  type ThreadOptions,
  type TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { resolveCodexCommand, runCodexCommand } from "../src/runtime.js";
import {
  comparisonForScan,
  comparisonEnvironment,
  matchCompletedScan,
  matchScanFindings,
  matchScanFindingsInternal,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
} from "../src/scan-comparison.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(async (path) => {
      // Bun 1.3.13 ignores fs.rm's retry options.
      for (let attempt = 0; ; attempt++) {
        try {
          await rm(path, { recursive: true, force: true });
          return;
        } catch (error) {
          if (
            (error as NodeJS.ErrnoException).code !== "EBUSY" ||
            attempt === 10
          )
            throw error;
          await Bun.sleep(100 * (attempt + 1));
        }
      }
    }),
  );
});

function finding(occurrenceId: string): ScanComparisonInput["before"][number] {
  return { occurrenceId };
}

function fakeCodex(response: unknown) {
  const calls: {
    prompt?: string;
    threadOptions?: ThreadOptions;
    turnOptions?: TurnOptions;
  } = {};
  const codex: NonNullable<ScanComparisonOptions["codex"]> = {
    startThread(options) {
      calls.threadOptions = options;
      return {
        async run(prompt, turnOptions) {
          calls.prompt = prompt;
          calls.turnOptions = turnOptions;
          return {
            finalResponse:
              typeof response === "string"
                ? response
                : JSON.stringify(response),
          };
        },
      };
    },
  };
  return { codex, calls };
}

describe("semantic scan comparison", () => {
  test("uses comparison attribution for CLI comparison turns", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    await matchScanFindingsInternal(
      { before: [finding("before")], after: [finding("after")] },
      { codex },
      { surface: "cli" },
    );
    expect(calls.threadOptions?.threadSource).toBe("security_scan_comparison");
  });

  test.each([
    [
      "OPENAI_API_KEY",
      { OPENAI_API_KEY: "synthetic-openai-key" },
      "synthetic-openai-key",
    ],
    [
      "CODEX_API_KEY",
      { CODEX_API_KEY: "synthetic-codex-key" },
      "synthetic-codex-key",
    ],
    [
      "OPENAI_API_KEY precedence",
      {
        OPENAI_API_KEY: "synthetic-openai-key",
        CODEX_API_KEY: "synthetic-codex-key",
      },
      "synthetic-openai-key",
    ],
    [
      "blank OPENAI_API_KEY fallback",
      { OPENAI_API_KEY: " \t ", CODEX_API_KEY: "synthetic-codex-key" },
      "synthetic-codex-key",
    ],
    ["no environment key", {}, undefined],
  ] as const)(
    "supplies %s authentication to Codex matching",
    async (_name, keys, expected) => {
      const home = await mkdtemp(
        join(tmpdir(), "codex-security-matcher-auth-"),
      );
      temporaryDirectories.push(home);
      let captured: CodexOptions | undefined;
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        captured = (this as unknown as { options: CodexOptions }).options;
        return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment: {
              PATH: process.env["PATH"],
              SystemRoot: process.env["SystemRoot"],
              CODEX_HOME: home,
              CODEX_SECURITY_STATE_DIR: join(home, "state"),
              ...keys,
            },
            workingDirectory: home,
          },
        );
        expect(startThread).toHaveBeenCalledTimes(1);
        expect(captured?.apiKey).toBe(expected);
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test.each(["home", "profile", "overrides", "override-away"])(
    "preserves native command auth selection from %s",
    async (selection) => {
      const home = await mkdtemp(
        join(tmpdir(), "codex-security-command-comparison-"),
      );
      temporaryDirectories.push(home);
      const commandAuth = selection !== "override-away";
      const provider = {
        name: "Synthetic",
        wire_api: "responses",
        base_url: "https://provider.example/v1",
        auth: {
          command: "./synthetic-auth",
          args: ["original"],
          refresh_interval_ms: 1234,
        },
      };
      const config = {
        model_provider:
          selection === "overrides" || selection === "profile"
            ? "openai"
            : "synthetic.provider",
        model_providers: { "synthetic.provider": provider },
      };
      const contents = stringify(config);
      await writeFile(join(home, "config.toml"), contents);
      const environment = {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: relative(process.cwd(), home),
        OPENAI_API_KEY: "synthetic-ambient-key",
        CODEX_API_KEY: "synthetic-other-key",
      };
      let captured: CodexOptions | undefined;
      let threadOptions: ThreadOptions | undefined;
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(function (this: Codex, options) {
        captured = (this as unknown as { options: CodexOptions }).options;
        threadOptions = options;
        return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
      });
      try {
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          {
            environment,
            workingDirectory: home,
            ...(selection === "overrides"
              ? {
                  config: {
                    codexOverrides: {
                      model_provider: "synthetic.provider",
                      model_providers: {
                        "synthetic.provider": {
                          auth: { args: ["override"], cwd: "~/helpers" },
                        },
                      },
                    },
                  },
                }
              : selection === "override-away"
                ? { config: { codexOverrides: { model_provider: "openai" } } }
                : selection === "profile"
                  ? {
                      config: {
                        codexOverrides: {
                          profile: "review",
                          profiles: {
                            review: { model_provider: "synthetic.provider" },
                          },
                        },
                      },
                    }
                  : {}),
          },
        );
        expect(captured?.env?.["CODEX_HOME"]).toBe(home);
        if (selection === "profile")
          expect(captured?.config?.["profile"]).toBe("review");
        if (commandAuth) {
          expect(captured?.env).not.toHaveProperty("OPENAI_API_KEY");
          expect(captured?.env).not.toHaveProperty("CODEX_API_KEY");
          expect(captured?.apiKey).toBeUndefined();
          expect(parse(captured!.configOverrides![0]!)).toEqual({
            model_providers: {
              "synthetic.provider": {
                ...provider,
                auth: {
                  ...provider.auth,
                  cwd: selection === "overrides" ? "~/helpers" : home,
                  args: selection === "overrides" ? ["override"] : ["original"],
                },
              },
            },
          });
        } else {
          expect(captured?.env?.["OPENAI_API_KEY"]).toBe(
            "synthetic-ambient-key",
          );
          expect(captured?.configOverrides).toBeUndefined();
        }
        expect(threadOptions).toMatchObject({
          workingDirectory: home,
          sandboxMode: "read-only",
          approvalPolicy: "never",
          networkAccessEnabled: false,
        });
        expect(await readFile(join(home, "config.toml"), "utf8")).toBe(
          contents,
        );
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test("does not substitute managed login for an explicitly configured command provider", async () => {
    const home = await mkdtemp(join(tmpdir(), "codex-security-command-login-"));
    temporaryDirectories.push(home);
    const state = join(home, "state");
    await mkdir(join(state, "codex-home"), { recursive: true });
    // Invalid auth remains native Codex's responsibility, without login fallback.
    await writeFile(
      join(home, "config.toml"),
      'model_provider="openai"\nprofile="review"\n[profiles.review]\nmodel_provider="synthetic"\n[model_providers.synthetic.auth]\ncommand=""\n',
    );
    const environment = { CODEX_HOME: home, CODEX_SECURITY_STATE_DIR: state };
    expect(
      await comparisonEnvironment(environment, async () => {
        throw new Error("Must not probe managed login");
      }),
    ).toEqual(environment);
  });

  test.each(["chatgpt", "api-key"] as const)(
    "rejects ambient command auth that conflicts with explicit %s authentication",
    async (auth) => {
      const home = await mkdtemp(
        join(tmpdir(), "codex-security-auth-conflict-"),
      );
      temporaryDirectories.push(home);
      const provider = {
        name: "Synthetic",
        base_url: "https://provider.example/v1",
        wire_api: "responses",
        auth: { command: "./synthetic-auth" },
      };
      const config = {
        model_provider: "synthetic",
        model_providers: { synthetic: provider },
      };
      await writeFile(join(home, "config.toml"), stringify(config));
      const options = {
        auth,
        config: {},
        environment: {
          PATH: process.env["PATH"],
          SystemRoot: process.env["SystemRoot"],
          CODEX_HOME: home,
          OPENAI_API_KEY: "synthetic-selected-key",
        },
        workingDirectory: home,
      };
      const { codex } = fakeCodex({ matches: [], uncertain: [] });
      const startThread = spyOn(
        Codex.prototype,
        "startThread",
      ).mockImplementation(
        (options) =>
          codex.startThread(options!) as ReturnType<Codex["startThread"]>,
      );
      try {
        await expect(
          matchScanFindings(
            { before: [finding("before")], after: [finding("after")] },
            options,
          ),
        ).rejects.toThrow("conflicts with command authentication");
        expect(startThread).not.toHaveBeenCalled();

        // A complete command provider selected by the caller keeps scan precedence.
        await matchScanFindings(
          { before: [finding("before")], after: [finding("after")] },
          { ...options, config: { codexOverrides: config } },
        );
        expect(startThread).toHaveBeenCalledTimes(1);
        startThread.mockClear();

        // An ambient profile must not replace that explicitly selected provider.
        await writeFile(
          join(home, "config.toml"),
          stringify({
            profile: "ambient",
            profiles: { ambient: { model_provider: "other" } },
            model_providers: { other: provider },
          }),
        );
        await expect(
          matchScanFindings(
            { before: [finding("before")], after: [finding("after")] },
            { ...options, config: { codexOverrides: config } },
          ),
        ).rejects.toThrow("conflicts with command authentication");
        expect(startThread).not.toHaveBeenCalled();
      } finally {
        startThread.mockRestore();
      }
    },
  );

  test("disables explicit and inherited MCP servers for read-only helper turns", async () => {
    const home = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(home);
    await writeFile(
      join(home, "config.toml"),
      '[mcp_servers.inherited]\ncommand = "synthetic-inherited"\n',
    );
    const executable = join(
      home,
      process.platform === "win32" ? "custom-codex.exe" : "custom-codex",
    );
    await copyFile(resolveCodexCommand({}).command, executable);
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: home,
      CODEX_CLI_PATH: executable,
      OPENAI_API_KEY: "synthetic-key",
    };
    const { codex } = fakeCodex({ matches: [], uncertain: [] });
    let config: CodexOptions["config"];
    let codexPath: string | undefined;
    let codexEnvironment: CodexOptions["env"];
    const startThread = spyOn(
      Codex.prototype,
      "startThread",
    ).mockImplementation(function (this: Codex, options) {
      config = (this as unknown as { options: CodexOptions }).options.config;
      codexPath = (this as unknown as { options: CodexOptions }).options
        .codexPathOverride;
      codexEnvironment = (this as unknown as { options: CodexOptions }).options
        .env;
      return codex.startThread(options!) as ReturnType<Codex["startThread"]>;
    });
    try {
      await matchScanFindings(
        { before: [finding("before")], after: [finding("after")] },
        {
          environment,
          workingDirectory: home,
          config: {
            codexOverrides: {
              mcp_servers: {
                synthetic: { command: "synthetic-integration", enabled: true },
              },
            },
          },
        },
      );
      expect(config?.["mcp_servers"]).toEqual({
        synthetic: { command: "synthetic-integration", enabled: false },
        inherited: { enabled: false },
      });
      expect(codexPath).toBe(
        process.platform === "win32"
          ? win32.toNamespacedPath(executable)
          : executable,
      );
      expect(codexEnvironment?.["CODEX_CLI_PATH"]).toBe(executable);
      const effective = await runCodexCommand(
        resolveCodexCommand(environment),
        [
          "-C",
          home,
          "-c",
          'mcp_servers.synthetic.command="synthetic-integration"',
          ...Object.keys(config!["mcp_servers"]!).flatMap((name) => [
            "-c",
            `mcp_servers.${name}.enabled=false`,
          ]),
          "mcp",
          "list",
          "--json",
        ],
        environment,
      );
      expect(effective.success).toBe(true);
      expect(
        JSON.parse(effective.stdout).map(
          (server: { name: string; enabled: boolean }) => ({
            name: server.name,
            enabled: server.enabled,
          }),
        ),
      ).toEqual([
        { name: "inherited", enabled: false },
        { name: "synthetic", enabled: false },
      ]);
    } finally {
      startThread.mockRestore();
    }
  });

  test("preserves environment API-key precedence over managed credentials", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let statusProbed = false;
    const account = async () => {
      statusProbed = true;
      return { authenticated: true, details: "Logged in using ChatGPT" };
    };

    const environment = await comparisonEnvironment(
      {
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-key-must-not-be-used",
        CODEX_API_KEY: "synthetic-secondary-must-not-be-used",
      },
      account,
    );

    expect(environment["CODEX_SECURITY_STATE_DIR"]).toBe(stateDirectory);
    expect(environment["OPENAI_API_KEY"]).toBe(
      "synthetic-key-must-not-be-used",
    );
    expect(environment["CODEX_API_KEY"]).toBe(
      "synthetic-secondary-must-not-be-used",
    );
    expect(environment["CODEX_HOME"]).toBeUndefined();
    const provider = {
      CODEX_SECURITY_STATE_DIR: stateDirectory,
      CODEX_SECURITY_SCAN_ID: "scan",
      CODEX_HOME: join(root, "provider-home"),
      CODEX_CLI_PATH: "/compatible-codex",
      CODEX_SAFETY_IDENTIFIER: "synthetic-user",
      FIREWORKS_API_KEY: "provider-key",
    };
    expect(await comparisonEnvironment(provider, account)).toEqual(provider);
    expect(statusProbed).toBe(false);
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes provider scan variables regardless of Windows casing",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const stateDirectory = join(root, "state");
      const providerHome = join(root, "provider-home");
      await mkdir(join(stateDirectory, "codex-home"), {
        recursive: true,
        mode: 0o700,
      });
      let statusProbed = false;
      const provider = {
        codex_security_scan_id: "scan",
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        codex_home: providerHome,
        FIREWORKS_API_KEY: "synthetic-provider-key",
      };

      const environment = await comparisonEnvironment(provider, async () => {
        statusProbed = true;
        return { authenticated: true, details: "Logged in using ChatGPT" };
      });

      expect(environment).toEqual(provider);
      expect(statusProbed).toBe(false);
    },
  );

  test.skipIf(process.platform !== "win32")(
    "replaces differently cased Windows CODEX_HOME variables",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });

      const environment = await comparisonEnvironment(
        {
          CODEX_SECURITY_STATE_DIR: stateDirectory,
          codex_home: join(root, "ambient-home"),
        },
        async () => ({
          authenticated: true,
          details: "Logged in using ChatGPT",
        }),
        undefined,
        async () => await realpath(credentialHome),
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(environment["codex_home"]).toBeUndefined();
    },
  );

  test("reuses managed keyring credentials when no environment key is present", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(credentialHome, { recursive: true, mode: 0o700 });
    let probedHome: string | undefined;

    const environment = await comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, storedEnvironment) => {
        probedHome = storedEnvironment["CODEX_HOME"];
        return { authenticated: true, details: "Logged in using ChatGPT" };
      },
    );

    expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
    expect(probedHome).toBe(await realpath(credentialHome));
  });

  test.skipIf(process.platform === "win32")(
    "uses the canonical keyring identity when the state parent is symlinked",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const actualState = join(root, "actual-state");
      const linkedState = join(root, "linked-state");
      const credentialHome = join(actualState, "codex-home");
      await mkdir(credentialHome, { recursive: true, mode: 0o700 });
      await symlink(actualState, linkedState, "dir");
      let probedHome: string | undefined;

      const environment = await comparisonEnvironment(
        { CODEX_SECURITY_STATE_DIR: linkedState },
        async (_command, storedEnvironment) => {
          probedHome = storedEnvironment["CODEX_HOME"];
          return { authenticated: true, details: "Logged in using ChatGPT" };
        },
      );

      expect(environment["CODEX_HOME"]).toBe(await realpath(credentialHome));
      expect(probedHome).toBe(await realpath(credentialHome));
    },
  );

  test("forwards cancellation to managed credential-status checks", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });
    const controller = new AbortController();
    let observedSignal: AbortSignal | undefined;
    let statusStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      statusStarted = resolve;
    });

    const waiting = comparisonEnvironment(
      { CODEX_SECURITY_STATE_DIR: stateDirectory },
      async (_command, _environment, signal) => {
        observedSignal = signal;
        statusStarted();
        return await new Promise((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason), {
            once: true,
          });
        });
      },
      controller.signal,
    );
    await started;
    controller.abort(new DOMException("canceled", "AbortError"));

    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
    expect(observedSignal).toBe(controller.signal);
  });

  test("retains API-key authentication when the managed home is not signed in", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
    temporaryDirectories.push(root);
    const stateDirectory = join(root, "state");
    const ambientHome = join(root, "ambient-codex-home");
    await mkdir(ambientHome, { mode: 0o700 });
    await mkdir(join(stateDirectory, "codex-home"), {
      recursive: true,
      mode: 0o700,
    });

    const environment = await comparisonEnvironment(
      {
        CODEX_HOME: ambientHome,
        CODEX_SECURITY_STATE_DIR: stateDirectory,
        OPENAI_API_KEY: "synthetic-comparison-key",
      },
      async () => ({ authenticated: false, details: "Not logged in" }),
    );

    expect(environment["OPENAI_API_KEY"]).toBe("synthetic-comparison-key");
    expect(environment["CODEX_HOME"]).toBe(ambientHome);
  });

  test.skipIf(process.platform !== "win32")(
    "recognizes stored credentials under a backslash home-relative path",
    async () => {
      const root = await mkdtemp(join(tmpdir(), "codex-security-comparison-"));
      temporaryDirectories.push(root);
      const ambientHome = join(root, "ambient-codex-home");
      await mkdir(ambientHome);
      await writeFile(join(ambientHome, "auth.json"), "{}");
      const environment = await comparisonEnvironment({
        CODEX_HOME: "~\\ambient-codex-home",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        OPENAI_API_KEY: "",
        USERPROFILE: root,
      });

      expect(environment["OPENAI_API_KEY"]).toBeUndefined();
    },
  );

  test("compares small inputs with one restricted structured-output turn", async () => {
    const input: ScanComparisonInput = {
      before: [finding("before-1"), finding("before-2")],
      after: [finding("after-1"), finding("after-2"), finding("after-3")],
    };
    const result = {
      matches: [
        {
          beforeOccurrenceIds: ["before-1"],
          afterOccurrenceIds: ["after-1", "after-2"],
          confidence: "high",
          reason: "The later scan split the same vulnerable extractor.",
        },
      ],
      uncertain: [
        {
          beforeOccurrenceId: "before-2",
          afterOccurrenceId: "after-3",
          reason: "A second entry point might be independently exploitable.",
        },
      ],
    } satisfies ScanComparisonResult;
    const { codex, calls } = fakeCodex(result);
    const controller = new AbortController();

    expect(
      await matchScanFindings(input, {
        codex,
        model: "comparison-model",
        reasoningEffort: "high",
        signal: controller.signal,
        workingDirectory: "/tmp/comparison",
      }),
    ).toEqual(result);
    expect(calls.threadOptions).toEqual({
      threadSource: "security_scan_comparison",
      model: "comparison-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      workingDirectory: "/tmp/comparison",
      skipGitRepoCheck: true,
    });
    expect(calls.turnOptions).toMatchObject({ signal: controller.signal });
    expect(calls.turnOptions?.outputSchema).toMatchObject({
      required: ["matches", "uncertain", "related", "request"],
    });
    const strictObjects = (schema: unknown): void => {
      if (schema === null || typeof schema !== "object") return;
      const object = schema as Record<string, unknown>;
      if (object["type"] === "object") {
        expect(object["required"]).toEqual(
          Object.keys(object["properties"] as object),
        );
        expect(object["additionalProperties"]).toBe(false);
      }
      for (const value of Object.values(object)) strictObjects(value);
    };
    strictObjects(calls.turnOptions?.outputSchema);
    expect(JSON.stringify(calls.turnOptions?.outputSchema)).toContain(
      '"type":"null"',
    );
    expect(calls.prompt).toContain(
      "same underlying root cause and remediation",
    );
    expect(calls.prompt).toContain(
      "same vulnerable helper share one root cause",
    );
    expect(calls.prompt).toContain("every earlier occurrence in one group");
    expect(calls.prompt).toContain("untrusted data");
    expect(calls.prompt).toContain(JSON.stringify(input));
  });

  test("uses the requested scan model and effort for component matching", async () => {
    const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
    const input = {
      before: [finding("before")],
      after: [finding("after")],
    };
    const config = {
      codexOverrides: {
        model: "configured-model",
        model_reasoning_effort: "high",
        model_provider: "synthetic-provider",
      },
    };
    await matchScanFindings(input, { config, codex });
    expect(calls.threadOptions).toMatchObject({
      model: "configured-model",
      modelReasoningEffort: "high",
      sandboxMode: "read-only",
      networkAccessEnabled: false,
    });
    await matchScanFindings(input, {
      config,
      codex,
      model: "explicit-model",
      reasoningEffort: "max",
    });
    expect(calls.threadOptions).toMatchObject({
      model: "explicit-model",
      modelReasoningEffort: "max",
    });
  });

  test("rejects a confirmed match with conflicting same-scan uncertainty", async () => {
    const open = { findingId: "open", occurrenceId: "old-open" };
    const dismissed = { findingId: "dismissed", occurrenceId: "old-dismissed" };
    const after = { findingId: "renamed", occurrenceId: "new-renamed" };
    const commands: Array<{ args: readonly string[]; input?: string }> = [];
    let input: ScanComparisonInput | undefined;
    await expect(
      matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: [open],
        falsePositives: [{ findingId: "dismissed", sourceScanId: "prior" }],
        findings: [after],
        environment: {
          CODEX_HOME: "/provider-home",
          CODEX_SECURITY_SCAN_ID: "current",
          FIREWORKS_API_KEY: "synthetic-provider-key",
        },
        async workbench(args, commandInput) {
          commands.push({ args, input: commandInput });
          return args[0] === "list-unmatched-scan-pairs"
            ? {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    knownFindingGroups: [["dismissed", "historical-alias"]],
                    beforeScans: [
                      {
                        scanId: "another-target",
                        findings: [{ ...dismissed, occurrenceId: "foreign" }],
                      },
                      { scanId: "prior", findings: [open, dismissed] },
                    ],
                  },
                ],
              }
            : {};
        },
        async matchFindings(value, options) {
          input = value;
          expect(options).toMatchObject({
            environment: {
              CODEX_HOME: "/provider-home",
              CODEX_SECURITY_SCAN_ID: "current",
            },
          });
          const response = {
            matches: [
              {
                beforeOccurrenceIds: ["old-dismissed"],
                afterOccurrenceIds: ["new-renamed"],
                confidence: "high",
                reason: "Same dismissed root cause.",
              },
            ],
            uncertain: [
              {
                beforeOccurrenceId: "old-open",
                afterOccurrenceId: "new-renamed",
                reason: "Possible match.",
              },
            ],
          };
          return await matchScanFindings(value, {
            ...options,
            codex: fakeCodex(response).codex,
          });
        },
      }),
    ).rejects.toThrow("conflicting confirmed and uncertain findings");
    expect(input).toEqual({
      before: [open, dismissed],
      after: [after],
      knownFindingGroups: [["dismissed", "historical-alias"]],
    });
    expect(commands.map(({ args: [command] }) => command)).toEqual([
      "list-unmatched-scan-pairs",
    ]);
  });

  test("compares complete selected scans before caching automatic matches", async () => {
    const firstShared = { findingId: "shared", occurrenceId: "first-shared" };
    const firstOther = { findingId: "other", occurrenceId: "first-other" };
    const latestShared = { findingId: "shared", occurrenceId: "latest-shared" };
    const unselected = { findingId: "unselected", occurrenceId: "unselected" };
    const after = { findingId: "renamed", occurrenceId: "current-renamed" };
    const saved = new Map<string, ScanComparisonResult>();
    let observed: ScanComparisonInput | undefined;
    const model = fakeCodex({
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: latestShared.occurrenceId,
          afterOccurrenceId: after.occurrenceId,
          reason: "The synthetic control may have moved.",
        },
      ],
    });

    await matchCompletedScan({
      scanId: "current",
      repository: "/repository",
      previousFindings: [firstOther, latestShared],
      falsePositives: [],
      findings: [after],
      async workbench(args, commandInput) {
        if (args[0] === "list-unmatched-scan-pairs") {
          return {
            batches: [
              {
                afterScanId: "current",
                afterFindings: [after],
                beforeScans: [
                  { scanId: "unselected", findings: [unselected] },
                  { scanId: "first", findings: [firstShared, firstOther] },
                  { scanId: "latest", findings: [latestShared] },
                ],
              },
            ],
          };
        }
        saved.set(args[2]!, JSON.parse(commandInput!) as ScanComparisonResult);
        return {};
      },
      matchFindings(input, options) {
        observed = input;
        return matchScanFindings(input, { ...options, codex: model.codex });
      },
    });

    expect(observed).toEqual({
      before: [firstShared, firstOther, latestShared],
      after: [after],
    });
    expect([...saved.keys()]).toEqual(["first", "latest"]);
    for (const [scanId, occurrenceId] of [
      ["first", firstShared.occurrenceId],
      ["latest", latestShared.occurrenceId],
    ] as const) {
      expect(saved.get(scanId)).toEqual({
        matches: [],
        uncertain: [
          {
            beforeOccurrenceId: occurrenceId,
            afterOccurrenceId: after.occurrenceId,
            reason: "The synthetic control may have moved.",
          },
        ],
      });
    }
  });

  test.each([
    ["no history", false, false, false, 0, false],
    ["a stable identity", true, false, true, 2, false],
    ["a renamed dismissed identity", false, true, false, 2, true],
  ] as const)(
    "only starts a model turn when needed for %s",
    async (
      _scenario,
      open,
      dismissed,
      stable,
      expectedCalls,
      expectedModel,
    ) => {
      const before = { findingId: "previous", occurrenceId: "old" };
      const after = {
        findingId: stable ? "previous" : "new",
        occurrenceId: "new",
      };
      let calls = 0;
      const model = fakeCodex({ matches: [], uncertain: [] });
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: open ? [before] : [],
        falsePositives: dismissed
          ? [{ findingId: "previous", sourceScanId: "prior" }]
          : [],
        findings: [after],
        async workbench(args) {
          calls += 1;
          return args[0] === "list-unmatched-scan-pairs"
            ? {
                batches: [
                  {
                    afterScanId: "current",
                    afterFindings: [after],
                    beforeScans: [{ scanId: "prior", findings: [before] }],
                  },
                ],
              }
            : {};
        },
        matchFindings: (input, options) =>
          matchScanFindings(input, { ...options, codex: model.codex }),
      });
      expect(calls).toBe(expectedCalls);
      expect(model.calls.prompt !== undefined).toBe(expectedModel);
    },
  );

  test.each(["split", "combined", "confirmed alias"] as const)(
    "retains known identities when a later finding is %s",
    async (scenario) => {
      const oldA = { findingId: "identity-a", occurrenceId: "old-a" };
      const oldB = { findingId: "identity-b", occurrenceId: "old-b" };
      const newA = { findingId: "identity-a", occurrenceId: "new-a" };
      const newB = { findingId: "identity-b", occurrenceId: "new-b" };
      const before = scenario === "combined" ? [oldA, oldB] : [oldA];
      const after =
        scenario === "split"
          ? [newA, newB]
          : scenario === "combined"
            ? [newA]
            : [newB];
      const knownFindingGroups =
        scenario === "confirmed alias"
          ? [["identity-a", "identity-b"]]
          : undefined;
      const model = fakeCodex({
        matches: [
          {
            beforeOccurrenceIds: before.map(({ occurrenceId }) => occurrenceId),
            afterOccurrenceIds: after.map(({ occurrenceId }) => occurrenceId),
            confidence: "high",
            reason: "The scan split or combined the same defective control.",
          },
        ],
        uncertain: [],
      });
      const saved: ScanComparisonResult[] = [];
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: before,
        falsePositives: [],
        findings: after,
        async workbench(args, commandInput) {
          if (args[0] === "list-unmatched-scan-pairs") {
            return {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: after,
                  beforeScans: [{ scanId: "prior", findings: before }],
                  knownFindingGroups,
                },
              ],
            };
          }
          saved.push(JSON.parse(commandInput!) as ScanComparisonResult);
          return {};
        },
        async matchFindings(input, options) {
          expect(input).toEqual({
            before,
            after,
            ...(knownFindingGroups === undefined ? {} : { knownFindingGroups }),
          });
          return await matchScanFindings(input, {
            ...options,
            codex: model.codex,
          });
        },
      });
      expect(model.calls.prompt !== undefined).toBe(
        scenario !== "confirmed alias",
      );
      expect(saved).toEqual([
        {
          matches: [
            expect.objectContaining({
              beforeOccurrenceIds: before.map(
                ({ occurrenceId }) => occurrenceId,
              ),
              afterOccurrenceIds: after.map(({ occurrenceId }) => occurrenceId),
            }),
          ],
          uncertain: [],
        },
      ]);
    },
  );

  test.each(["new", "resolved", "split", "combined"] as const)(
    "preserves deterministic matches while reconciling a %s issue",
    async (scenario) => {
      const oldA = { findingId: "identity-a", occurrenceId: "old-a" };
      const oldB = { findingId: "identity-b", occurrenceId: "old-b" };
      const newA = { findingId: "identity-a", occurrenceId: "new-a" };
      const newB = { findingId: "identity-b", occurrenceId: "new-b" };
      const before =
        scenario === "resolved" || scenario === "combined"
          ? [oldA, oldB]
          : [oldA];
      const after =
        scenario === "new" || scenario === "split" ? [newA, newB] : [newA];
      const extendsKnown = scenario === "split" || scenario === "combined";
      const saved: ScanComparisonResult[] = [];
      await matchCompletedScan({
        scanId: "current",
        repository: "/repository",
        previousFindings: before,
        falsePositives: [],
        findings: after,
        async workbench(args, commandInput) {
          if (args[0] === "list-unmatched-scan-pairs")
            return {
              batches: [
                {
                  afterScanId: "current",
                  afterFindings: after,
                  beforeScans: [{ scanId: "prior", findings: before }],
                },
              ],
            };
          saved.push(JSON.parse(commandInput!) as ScanComparisonResult);
          return {};
        },
        async matchFindings(input, options) {
          const response = {
            matches: extendsKnown
              ? [
                  {
                    beforeOccurrenceIds: [
                      scenario === "split"
                        ? oldA.occurrenceId
                        : oldB.occurrenceId,
                    ],
                    afterOccurrenceIds: [
                      scenario === "split"
                        ? newB.occurrenceId
                        : newA.occurrenceId,
                    ],
                    confidence: "high",
                    reason: "The same control was split or combined.",
                  },
                ]
              : [],
            uncertain: extendsKnown
              ? []
              : [
                  {
                    beforeOccurrenceId: oldA.occurrenceId,
                    afterOccurrenceId: newA.occurrenceId,
                    reason: "The model omitted the proven identity.",
                  },
                ],
            related:
              scenario === "resolved"
                ? []
                : [
                    {
                      beforeOccurrenceId: oldA.occurrenceId,
                      afterOccurrenceId:
                        scenario === "new"
                          ? newB.occurrenceId
                          : newA.occurrenceId,
                      reason: "A related control.",
                    },
                  ],
          };
          return await matchScanFindings(input, {
            ...options,
            codex: fakeCodex(response).codex,
          });
        },
      });
      expect(saved).toHaveLength(1);
      expect(saved[0]!.matches).toHaveLength(1);
      expect(new Set(saved[0]!.matches[0]!.beforeOccurrenceIds)).toEqual(
        new Set(
          (extendsKnown ? before : [oldA]).map(
            ({ occurrenceId }) => occurrenceId,
          ),
        ),
      );
      expect(new Set(saved[0]!.matches[0]!.afterOccurrenceIds)).toEqual(
        new Set(
          (extendsKnown ? after : [newA]).map(
            ({ occurrenceId }) => occurrenceId,
          ),
        ),
      );
      expect(saved[0]!.uncertain).toEqual([]);
      expect(saved[0]!.related).toHaveLength(scenario === "new" ? 1 : 0);
    },
  );

  test("rejects malformed model JSON", async () => {
    const { codex } = fakeCodex("not-json");
    await expect(
      matchScanFindings(
        { before: [finding("before")], after: [finding("after")] },
        { codex },
      ),
    ).rejects.toThrow("invalid JSON");
  });

  test("does not start Codex when either scan has no findings", async () => {
    const codex: NonNullable<ScanComparisonOptions["codex"]> = {
      startThread() {
        throw new Error("No model is needed.");
      },
    };
    for (const input of [
      { before: [], after: [finding("after")] },
      { before: [finding("before")], after: [] },
    ]) {
      expect(await matchScanFindings(input, { codex })).toEqual({
        matches: [],
        uncertain: [],
      });
    }
  });

  test.each([
    ["empty", { before: [finding(" ")], after: [] }],
    [
      "same-scan duplicate",
      { before: [finding("duplicate"), finding("duplicate")], after: [] },
    ],
    [
      "cross-scan duplicate",
      {
        before: [finding("duplicate")],
        after: [finding("duplicate")],
      },
    ],
  ])("rejects %s occurrence IDs before matching", async (_, input) => {
    const codex: NonNullable<ScanComparisonOptions["codex"]> = {
      startThread() {
        throw new Error("No model should start for invalid input.");
      },
    };

    await expect(matchScanFindings(input, { codex })).rejects.toThrow(
      "must be nonempty and globally unique",
    );
  });

  test("allows cross-history uncertainty without relaxing two-scan matching", async () => {
    const input: ScanComparisonInput = {
      before: [
        { occurrenceId: "before-confirmed", findingId: "shared" },
        { occurrenceId: "before-uncertain", findingId: "other" },
      ],
      after: [{ occurrenceId: "after-shared", findingId: "shared" }],
    };
    const modelResponse = {
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: "before-uncertain",
          afterOccurrenceId: "after-shared",
          reason: "Uncertain in another historical scan.",
        },
      ],
    } satisfies ScanComparisonResult;

    await expect(
      matchScanFindings(input, { codex: fakeCodex(modelResponse).codex }),
    ).rejects.toThrow("invalid uncertain pair");
    const response = await matchScanFindings(input, {
      codex: fakeCodex(modelResponse).codex,
      allowHistoricalUncertainty: true,
    });
    expect(response).toEqual({
      matches: [
        {
          beforeOccurrenceIds: ["before-confirmed"],
          afterOccurrenceIds: ["after-shared"],
          confidence: "high",
          reason:
            "The findings share a stable identity or a previously confirmed link.",
        },
      ],
      uncertain: modelResponse.uncertain,
    });
    expect(comparisonForScan(response, [input.before[0]!])).toEqual({
      matches: response.matches,
      uncertain: [],
    });
    expect(comparisonForScan(response, [input.before[1]!])).toEqual({
      matches: [],
      uncertain: modelResponse.uncertain,
    });
    expect(() => comparisonForScan(response, input.before)).toThrow(
      "conflicting confirmed and uncertain findings",
    );
  });

  test("honors confirmed historical groups and preserves distinct related findings", async () => {
    const input = {
      before: [
        { occurrenceId: "before-known", findingId: "known-a" },
        { occurrenceId: "before-related", findingId: "related-a" },
      ],
      after: [
        { occurrenceId: "after-known", findingId: "known-b" },
        { occurrenceId: "after-related", findingId: "related-b" },
      ],
      knownFindingGroups: [["known-a", "known-b"]],
    };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["before-known"],
          afterOccurrenceIds: ["after-known"],
          confidence: "high" as const,
          reason: "Previously confirmed root cause.",
        },
      ],
      uncertain: [],
      related: [
        {
          beforeOccurrenceId: "before-related",
          afterOccurrenceId: "after-related",
          reason: "Related controls remain independently vulnerable.",
        },
      ],
    };
    const { codex, calls } = fakeCodex(response);

    expect(await matchScanFindings(input, { codex })).toEqual(response);
    expect(JSON.parse(calls.prompt!.split("\n").at(-1)!)).toMatchObject({
      findings: {
        before: [
          { occurrenceId: "before-known", issueId: "known-a" },
          { occurrenceId: "before-related", issueId: "related-a" },
        ],
      },
    });
  });

  test.each([
    ["confirmed aliases", ["a"], ["b"], [["a", "b"]]],
    [
      "overlapping aliases",
      ["a"],
      ["c"],
      [
        ["a", "b"],
        ["b", "c"],
      ],
    ],
    ["repeated stable identities", ["same", "same"], ["same", "same"], []],
  ] as const)(
    "confirms %s without starting Codex",
    async (_scenario, before, after, knownFindingGroups) => {
      const input = {
        before: before.map((findingId, index) => ({
          occurrenceId: `before-${index}`,
          findingId,
        })),
        after: after.map((findingId, index) => ({
          occurrenceId: `after-${index}`,
          findingId,
        })),
        knownFindingGroups,
      };
      const { codex, calls } = fakeCodex({ matches: [], uncertain: [] });
      expect(await matchScanFindings(input, { codex })).toEqual({
        matches: [
          {
            beforeOccurrenceIds: input.before.map(
              ({ occurrenceId }) => occurrenceId,
            ),
            afterOccurrenceIds: input.after.map(
              ({ occurrenceId }) => occurrenceId,
            ),
            confidence: "high",
            reason: expect.any(String),
          },
        ],
        uncertain: [],
      });
      expect(calls.prompt).toBeUndefined();
    },
  );

  test("never accepts uncertainty between occurrences of the same stable finding", async () => {
    const input = {
      before: [{ occurrenceId: "before", findingId: "shared-identity" }],
      after: [{ occurrenceId: "after", findingId: "shared-identity" }],
    };
    const response = {
      matches: [],
      uncertain: [
        {
          beforeOccurrenceId: "before",
          afterOccurrenceId: "after",
          reason: "Incorrectly treats the same stable identity as uncertain.",
        },
      ],
    };

    const requiringModel = {
      before: [
        ...input.before,
        { occurrenceId: "other-before", findingId: "other-before" },
      ],
      after: [
        ...input.after,
        { occurrenceId: "other-after", findingId: "other-after" },
      ],
    };
    const contradictory = fakeCodex(response);
    expect(
      await matchScanFindings(requiringModel, { codex: contradictory.codex }),
    ).toEqual({
      matches: [
        {
          beforeOccurrenceIds: ["before"],
          afterOccurrenceIds: ["after"],
          confidence: "high",
          reason:
            "The findings share a stable identity or a previously confirmed link.",
        },
      ],
      uncertain: [],
    });
    expect(contradictory.calls.prompt).toBeDefined();
  });

  test("never lets a model split a confirmed historical group", async () => {
    const input = {
      before: [
        { occurrenceId: "before-a", findingId: "known-a" },
        { occurrenceId: "before-b", findingId: "known-b" },
      ],
      after: [{ occurrenceId: "after", findingId: "new" }],
      knownFindingGroups: [["known-a", "known-b"]],
    };
    const response = {
      matches: [
        {
          beforeOccurrenceIds: ["before-a"],
          afterOccurrenceIds: ["after"],
          confidence: "high" as const,
          reason: "Incorrectly separates a confirmed identity.",
        },
      ],
      uncertain: [],
    };

    const invalid = fakeCodex(response);

    await expect(
      matchScanFindings(input, { codex: invalid.codex }),
    ).rejects.toThrow("unknown before occurrence");
    expect(JSON.parse(invalid.calls.prompt!.split("\n").at(-1)!)).toMatchObject(
      {
        findings: {
          before: [
            {
              occurrenceId: "before-b",
              occurrenceCount: 2,
              issueId: "known-a",
            },
          ],
        },
      },
    );

    const valid = {
      ...response,
      matches: [
        {
          ...response.matches[0]!,
          beforeOccurrenceIds: ["before-b"],
        },
      ],
    };
    expect(
      await matchScanFindings(input, { codex: fakeCodex(valid).codex }),
    ).toMatchObject({
      matches: [
        {
          beforeOccurrenceIds: ["before-a", "before-b"],
          afterOccurrenceIds: ["after"],
          confidence: "high",
        },
      ],
      uncertain: [],
    });
  });

  const match = (beforeOccurrenceIds = ["before-1"]) => ({
    beforeOccurrenceIds,
    afterOccurrenceIds: ["after-1"],
    confidence: "high" as const,
    reason: "Same root cause.",
  });
  const uncertain = (afterOccurrenceId = "after-1") => ({
    beforeOccurrenceId: "before-1",
    afterOccurrenceId,
    reason: "Possible root cause.",
  });

  test.each([
    {
      label: "missing arrays",
      result: {},
      error: "invalid match result",
    },
    {
      label: "unexpected result fields",
      result: { matches: [], uncertain: [], unexpected: true },
      error: "invalid match result",
    },
    {
      label: "blank match reasons",
      result: { matches: [{ ...match(), reason: " " }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "malformed related pairs",
      result: {
        matches: [],
        uncertain: [],
        related: [{ ...uncertain(), beforeOccurrenceId: 1 }],
      },
      error: "invalid match result",
    },
    {
      label: "low confidence",
      result: { matches: [{ ...match(), confidence: "low" }], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "empty groups",
      result: { matches: [match([])], uncertain: [] },
      error: "invalid match result",
    },
    {
      label: "invented occurrences",
      result: { matches: [match(["invented"])], uncertain: [] },
      error: "unknown before occurrence",
    },
    {
      label: "repeated occurrences",
      result: { matches: [match(), match()], uncertain: [] },
      error: "before occurrence more than once",
    },
    {
      label: "invented uncertain occurrences",
      result: { matches: [], uncertain: [uncertain("invented")] },
      error: "invalid uncertain pair",
    },
    {
      label: "uncertainty already matched with confidence",
      result: { matches: [match()], uncertain: [uncertain()] },
      error: "invalid uncertain pair",
    },
    {
      label: "duplicate uncertain pairs",
      result: { matches: [], uncertain: [uncertain(), uncertain()] },
      error: "duplicate uncertain pair",
    },
    {
      label: "invented related occurrences",
      result: {
        matches: [],
        uncertain: [],
        related: [uncertain("invented")],
      },
      error: "invalid related pair",
    },
    {
      label: "duplicate related pairs",
      result: {
        matches: [],
        uncertain: [],
        related: [uncertain(), uncertain()],
      },
      error: "invalid related pair",
    },
    {
      label: "related pairs that contradict confirmed matches",
      result: {
        matches: [match()],
        uncertain: [],
        related: [uncertain()],
      },
      error: "invalid related pair",
    },
    {
      label: "related pairs that duplicate uncertainty",
      result: {
        matches: [],
        uncertain: [uncertain()],
        related: [uncertain()],
      },
      error: "invalid related pair",
    },
  ])("rejects $label", async ({ result, error }) => {
    const { codex } = fakeCodex(result);
    await expect(
      matchScanFindings(
        { before: [finding("before-1")], after: [finding("after-1")] },
        { codex },
      ),
    ).rejects.toThrow(error);
  });
});
