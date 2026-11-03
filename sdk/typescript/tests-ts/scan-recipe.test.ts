import { createCliTest } from "./support/cli-run.js";
import { writeSession } from "./support/usage-rollout.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { workbenchCommand } from "./support/workbench-command.js";
import {
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { scanPreflightCodexConfig } from "../src/api.js";
import { main } from "../src/cli.js";
import { codexSecurityCredentialHome, runWorkbench } from "../src/runtime.js";
import { restoreProviderProfile } from "../src/provider-profile.js";
import { dependencies } from "./cli-fixtures.js";
import { mockWorkbench, TestClient } from "./support/api-client.js";
import {
  completedCodex,
  preparedRuntime,
  scanRuntimeDependencies,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import {
  EXTERNAL_CODEX_PROVIDERS,
  mergedCodexConfig,
  resolveCodexProfile,
  type JsonObject,
} from "../src/config.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each(
  [true, false].flatMap((rejected) =>
    [true, false].map((providers) => ({ rejected, providers })),
  ),
)(
  "private replay lifetime follows registration: %j",
  async ({ rejected, providers }) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "profile-home");
    const runtimeHome = join(root, "runtime-home");
    const scanDir = join(root, "scan");
    await Promise.all([mkdir(repository), mkdir(home), mkdir(runtimeHome)]);
    await mkdir(scanDir, { mode: 0o700 });
    await writeFile(join(repository, "source.py"), "value = 1\n");
    await writeFile(
      join(home, "review.config.toml"),
      'model="synthetic-model"\nmodel_provider="openrouter"\n[model_providers.openrouter]\nname="Synthetic"\nwire_api="responses"\n',
    );
    const environment = {
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENROUTER_API_KEY: "synthetic-launch-key",
      PATH: process.env["PATH"],
    };
    const savedHome = codexSecurityCredentialHome(environment);
    let completed = false;
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: {
          profile: "review",
          ...(providers
            ? {
                model_providers: {
                  openrouter: { base_url: "https://custom.example.invalid/" },
                },
              }
            : { model_instructions_file: null }),
        },
      },
      {
        environment,
        ...scanRuntimeDependencies(runtimeHome, scanDir),
        createCodex: completedCodex(root),
        runWorkbench: async (_runtime, args, input) => {
          if (args[0] === "register-cli-scan") {
            expect(
              (await readdir(savedHome)).filter((name) =>
                name.endsWith(".config.json"),
              ),
            ).toHaveLength(1);
            if (rejected) throw new Error("Synthetic registration rejected");
          }
          if (args[0] === "complete-scan") completed = true;
          if (args[0] === "list-scans") return { scans: [] };
          return mockWorkbench(args, input);
        },
      },
    );
    try {
      if (rejected) {
        await expect(client.run(repository)).rejects.toThrow(
          "Synthetic registration rejected",
        );
      } else {
        await client.run(repository);
        expect(completed).toBe(true);
      }
      await client.close();
      expect(
        (await readdir(savedHome)).filter((name) =>
          name.endsWith(".config.json"),
        ),
      ).toHaveLength(rejected ? 0 : 1);
    } finally {
      await client.close();
    }
  },
);

test.each(
  (["openrouter", "fireworks", "gateway"] as const).flatMap((provider) =>
    (["standard", "deep"] as const).flatMap((mode) =>
      [
        "partial",
        "different-key",
        "model-only",
        "clear-fields",
        "clear-agent",
        "clear-table",
      ].map((profileKind) => ({
        provider,
        mode,
        profileKind,
      })),
    ),
  ),
)(
  "saved launches retain explicit provider refinements: %j",
  async ({ provider, mode, profileKind }) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "profile-home");
    const runtimeHome = join(root, "runtime-home");
    await Promise.all([mkdir(repository), mkdir(home), mkdir(runtimeHome)]);
    await writeFile(join(repository, "fixture.py"), "value = 1\n");
    await writeFile(
      join(home, "review.config.toml"),
      `model="synthetic-model"\nmodel_provider="${provider}"\n` +
        (profileKind === "model-only"
          ? ""
          : `[model_providers.${provider}]\n` +
            (profileKind === "partial"
              ? "request_max_retries=4\n"
              : 'env_key="SYNTHETIC_OLD_PROVIDER_KEY"\n')) +
        (profileKind.startsWith("clear-")
          ? `[model_providers.${provider}.http_headers]\nX-Inherited="synthetic-inherited-header"\n` +
            `[model_providers.${provider}.auth]\ncommand="synthetic-auth"\n` +
            '[model_providers.agent]\nname="Inherited agent"\nwire_api="responses"\n'
          : ""),
    );
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const standard =
      provider === "gateway"
        ? {
            name: "Synthetic gateway",
            env_key: "SYNTHETIC_PROVIDER_KEY",
            wire_api: "responses",
          }
        : EXTERNAL_CODEX_PROVIDERS[provider];
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      SYNTHETIC_PROVIDER_KEY: "synthetic-launch-key",
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const header = "synthetic-provider-header";
    const customEndpoint = "https://provider.example.invalid/custom";
    const explicitProvider = {
      ...standard,
      env_key: "SYNTHETIC_PROVIDER_KEY",
      base_url: customEndpoint,
      http_headers:
        profileKind === "clear-fields"
          ? null
          : { "X-Synthetic-Credential": header },
      ...(profileKind.startsWith("clear-") ? { auth: null } : {}),
    };
    const alternateProvider = {
      name: "Synthetic agent provider",
      base_url: "https://agent.example.invalid/v1",
      env_key: "SYNTHETIC_AGENT_KEY",
      wire_api: "responses",
    };
    const explicitProviders =
      profileKind === "clear-table"
        ? null
        : {
            [provider]: explicitProvider,
            agent: profileKind === "clear-agent" ? null : alternateProvider,
          };
    const overrides = {
      profile: "review",
      model_provider: profileKind === "clear-table" ? "openai" : provider,
      model_providers: explicitProviders,
    };
    const initial = await mergedCodexConfig(
      { codexOverrides: overrides },
      home,
    );
    let providerProfilePath: string | undefined;
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: overrides,
      },
      {
        environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(runtimeHome),
          deepScanConfigPath: join(runtimeHome, "deep-scan-config.toml"),
        }),
        resolvePluginPython: async () => python,
        runWorkbench: async (_runtime, args, input) => {
          if (mode === "deep" && args[0] === "fail-scan")
            throw new Error("Synthetic disconnected workbench");
          return command(args, input);
        },
        createCodex: async (options) => {
          if (profileKind === "clear-table") {
            expect(options.nativeProfile).toBeUndefined();
          } else {
            expect(typeof options.nativeProfile).toBe("string");
            providerProfilePath = join(
              options.env!["CODEX_HOME"]!,
              `${options.nativeProfile}.config.toml`,
            );
            expect<unknown>(
              parseToml(await readFile(providerProfilePath, "utf8")),
            ).toEqual({
              model_providers: resolveCodexProfile(initial)["model_providers"],
            });
          }
          return {
            startThread: () => ({
              id: "synthetic-recipe-thread",
              async runStreamed() {
                return {
                  events: (async function* () {
                    yield {
                      type: "thread.started" as const,
                      thread_id: "synthetic-recipe-thread",
                    };
                    throw new Error("Synthetic stop after registration");
                  })(),
                };
              },
            }),
          };
        },
      },
    );
    try {
      await expect(
        client.run(repository, { mode, outputDir: join(root, "scan") }),
      ).rejects.toThrow("Synthetic stop after registration");
      const scans = (await command(["list-scans", "--repository", repository]))[
        "scans"
      ] as Array<{ scanId: string }>;
      expect(scans).toHaveLength(1);
      const recipe = (
        await command(["get-scan-recipe", "--scan-id", scans[0]!.scanId])
      )["recipe"] as {
        config: JsonObject;
        providerProfile: { name: string; home: string };
      };
      expect(recipe.config).toMatchObject({ profile: "review" });
      expect(recipe.config).not.toHaveProperty("model_providers");
      expect(recipe.providerProfile.home).toBe("managed");
      const savedProfilePath = join(
        codexSecurityCredentialHome(environment),
        `${recipe.providerProfile.name}.config.json`,
      );
      if (process.platform !== "win32")
        expect((await stat(savedProfilePath)).mode & 0o777).toBe(0o600);
      await client.close();
      expect(JSON.parse(await readFile(savedProfilePath, "utf8"))).toEqual({
        model_providers: explicitProviders,
      });
      const replay = await mergedCodexConfig(
        {
          codexOverrides: await restoreProviderProfile(
            recipe.config,
            recipe.providerProfile,
            environment,
          ),
        },
        home,
      );
      expect(replay["model_providers"]).toEqual(initial["model_providers"]);
      const { runCli, stderr } = createCliTest(main);
      let replayOverrides: JsonObject | undefined;
      for (const operation of mode === "deep"
        ? ["rerun", "resume"]
        : ["rerun"]) {
        expect(
          await runCli(["scans", operation, scans[0]!.scanId, "--json"], {
            ...dependencies({
              environment,
              currentDirectory: root,
              onConfig: ({ codexOverrides }) => {
                replayOverrides = codexOverrides;
              },
            }),
            runWorkbench: command,
          }),
          `${operation}: ${stderr.text()}`,
        ).toBe(0);
        expect(replayOverrides).toBeDefined();
        expect(
          (await mergedCodexConfig({ codexOverrides: replayOverrides }, home))[
            "model_providers"
          ],
        ).toEqual(initial["model_providers"]);
      }
      await writeFile(
        join(home, "review.config.toml"),
        `model="synthetic-model"\nmodel_provider="${provider}"\n[model_providers.${provider}]\nrequest_max_retries=8\nbase_url="https://changed.example.invalid/"\n`,
      );
      expect(
        (await mergedCodexConfig({ codexOverrides: replayOverrides }, home))[
          "model_providers"
        ],
      ).toEqual(
        explicitProviders === null
          ? null
          : {
              [provider]: { ...explicitProvider, request_max_retries: 8 },
              agent: profileKind === "clear-agent" ? null : alternateProvider,
            },
      );
      expect(JSON.stringify(recipe)).not.toContain(header);
      expect(JSON.stringify(recipe)).not.toContain(customEndpoint);
      expect(
        JSON.stringify(
          await command(["get-scan", "--scan-id", scans[0]!.scanId]),
        ),
      ).not.toContain(header);
      expect(JSON.stringify(recipe)).not.toContain("synthetic-launch-key");
      expect(JSON.stringify(recipe)).not.toContain(
        "SYNTHETIC_OLD_PROVIDER_KEY",
      );
    } finally {
      await client.close();
      if (providerProfilePath !== undefined) {
        await expect(readFile(providerProfilePath)).rejects.toMatchObject({
          code: "ENOENT",
        });
      }
    }
  },
);

const selected = {
  model: "synthetic-selected-model",
  model_reasoning_effort: "high",
  model_provider: "amazon-bedrock",
  features: { goals: false },
};
const selectedProviders = {
  "amazon-bedrock": {
    aws: { region: "us-east-2", profile: "scan-profile" },
  },
};
function profileConfig(profile: string) {
  return {
    model: "synthetic-root-model",
    model_reasoning_effort: "low",
    model_provider: "openai",
    model_providers: {
      "amazon-bedrock": {
        aws: { region: "us-west-2", profile: "ambient-profile" },
      },
    },
    profile,
    profiles: {
      [profile]: { ...selected, model_providers: selectedProviders },
    },
  };
}

test.each(["review", "review.v2", "review mode", "分析"])(
  "preserves effective settings for profile %s in the recipe configuration",
  (profile) => {
    const recipeConfig = scanPreflightCodexConfig(profileConfig(profile));
    expect(resolveCodexProfile(recipeConfig)).toMatchObject({
      ...selected,
      model_providers: selectedProviders,
    });
  },
);

test.each([
  ["standard", "review"],
  ["deep", "分析"],
])(
  "%s scans save prompts and replay the selected %s profile",
  async (mode, profile) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "state", "codex-home");
    await mkdir(repository);
    await mkdir(codexHome, { recursive: true });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const promptFile = join(root, "post-scan.md");
    const postScanPrompt =
      "Review the completed scan and its evidence.\n".repeat(10_000);
    expect(Buffer.byteLength(postScanPrompt)).toBeGreaterThan(256 * 1024);
    await writeFile(promptFile, postScanPrompt);
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-launch-key",
      AWS_BEARER_TOKEN_BEDROCK: "synthetic-bedrock-key",
      AWS_REGION: "us-east-2",
    };
    const command = workbenchCommand(python, () => environment);
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      [
        "scan",
        repository,
        "--mode",
        mode,
        "--output-dir",
        join(root, "scan"),
        "--post-scan-prompt-file",
        promptFile,
        "--json",
      ],
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(
            {
              ...config,
              codexOverrides: profileConfig(profile),
            },
            {
              environment,
              prepareRuntime: async () => ({
                ...preparedRuntime(codexHome),
                deepScanConfigPath: join(root, "deep.toml"),
              }),
              resolvePluginPython: async () => python,
              runWorkbench,
              createCodex: ({ config }) => {
                expect(config).toMatchObject(selected);
                throw new Error("Synthetic stop after registration");
              },
            },
          ),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Synthetic stop after registration");
    await rm(promptFile);
    const scans = (await command(["list-scans", "--repository", repository]))[
      "scans"
    ] as Array<{ scanId: string }>;
    expect(scans).toHaveLength(1);
    const saved = await command([
      "get-scan-recipe",
      "--scan-id",
      scans[0]!.scanId,
    ]);
    expect(saved["recipe"]).toMatchObject({
      mode,
      postScanPrompt,
      config: { model_providers: selectedProviders },
    });
    expect(JSON.stringify(saved)).not.toContain(promptFile);
    expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
    expect(JSON.stringify(saved)).not.toContain("synthetic-bedrock-key");
    expect(
      await runCli(["scans", "rerun", scans[0]!.scanId, "--json"], {
        ...dependencies({
          environment,
          currentDirectory: root,
          onConfig: ({ codexOverrides }) => {
            expect(resolveCodexProfile(codexOverrides!)).toMatchObject({
              ...selected,
              model_providers: selectedProviders,
            });
          },
        }),
        runWorkbench: command,
      }),
    ).toBe(0);
  },
);

const modelFileRecipeKeys = [
  "model_instructions_file",
  "model_catalog_json",
  "experimental_compact_prompt_file",
] as const;
test.each(
  modelFileRecipeKeys.flatMap((key) => [
    ...["root-relative", "inline-relative", "root-absolute"].map((kind) => ({
      key,
      kind,
      mode: "standard" as const,
    })),
    ...(["standard", "deep"] as const).map((mode) => ({
      key,
      kind: "file-cleared",
      mode,
    })),
  ]),
)(
  "saved launch retains model file paths and explicit clears: %j",
  async ({ key, kind, mode }) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "codex-home");
    const originalOutput = join(root, "original-output");
    const rerunOutput = join(root, "reruns", "next-output");
    const modelFiles = join(root, "model-files");
    await Promise.all(
      [repository, home, modelFiles, rerunOutput].map((path) =>
        mkdir(path, { recursive: true }),
      ),
    );
    await writeFile(join(repository, "fixture.py"), "value = 1\n");
    const modelFile = join(modelFiles, key + ".txt");
    const contents =
      key === "model_catalog_json"
        ? '{"models":[]}\n'
        : `Synthetic saved model file ${key}\n`;
    await writeFile(modelFile, contents);
    const value =
      kind === "root-absolute"
        ? modelFile
        : relative(originalOutput, modelFile);
    const cleared = kind === "file-cleared";
    if (cleared) {
      await writeFile(
        join(home, "review.config.toml"),
        `model="synthetic-model"\n${key}="inherited.txt"\n[analytics]\nenabled=true\n[agents.reviewer]\nconfig_file="reviewer.toml"\ndescription="initial reviewer"\n`,
      );
    }
    const overrides: JsonObject = cleared
      ? {
          profile: "review",
          [key]: null,
          analytics: null,
          agents: { reviewer: { config_file: null } },
        }
      : kind === "inline-relative"
        ? {
            profile: "active",
            profiles: {
              active: { [key]: value },
              unused: { [key]: "keep-unused-relative.txt" },
            },
          }
        : { [key]: value };
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-launch-key",
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    let launches = 0;
    const runtimeDependencies = {
      environment,
      prepareRuntime: async () => ({
        ...preparedRuntime(home),
        deepScanConfigPath: join(home, "deep-scan-config.toml"),
      }),
      resolvePluginPython: async () => python,
      runWorkbench: async (
        _options: unknown,
        args: readonly string[],
        input?: string,
      ) => {
        if (mode === "deep" && args[0] === "fail-scan")
          throw new Error("Synthetic disconnected workbench");
        return command(args, input);
      },
      createCodex: ({ config }: { config?: JsonObject }) => {
        launches++;
        if (cleared) {
          expect(config).not.toHaveProperty(key);
          expect(config).not.toHaveProperty("analytics");
          expect(config).not.toHaveProperty("agents.reviewer.config_file");
        }
        const thread = (id: string, cwd?: string) => ({
          id,
          async runStreamed() {
            await writeSession(home, id, {}, { cwd });
            return {
              events: (async function* () {
                yield {
                  type: "thread.started" as const,
                  thread_id: id,
                };
                throw new Error("Synthetic stop after registration");
              })(),
            };
          },
        });
        return {
          startThread: (options?: { workingDirectory?: string }) =>
            thread(
              `synthetic-model-file-thread-${launches}`,
              options?.workingDirectory,
            ),
          resumeThread: (id: string, options?: { workingDirectory?: string }) =>
            thread(id, options?.workingDirectory),
        };
      },
    };
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, codexOverrides: overrides },
      runtimeDependencies,
    );
    try {
      await expect(
        client.run(repository, { mode, outputDir: originalOutput }),
      ).rejects.toThrow("Synthetic stop after registration");
      const scans = (await command(["list-scans", "--repository", repository]))[
        "scans"
      ] as Array<{ scanId: string }>;
      expect(scans).toHaveLength(1);
      const recipe = (
        await command(["get-scan-recipe", "--scan-id", scans[0]!.scanId])
      )["recipe"] as { config: JsonObject; providerProfile?: unknown };
      const replayOverrides = await restoreProviderProfile(
        recipe.config,
        recipe.providerProfile,
        environment,
      );
      const replay = resolveCodexProfile(
        await mergedCodexConfig({ codexOverrides: replayOverrides }, home),
      );
      if (cleared) {
        await client.close();
        await writeFile(
          join(home, "review.config.toml"),
          `model="synthetic-model"\n${key}="changed.txt"\n[analytics]\nenabled=false\n[agents.reviewer]\nconfig_file="changed-reviewer.toml"\ndescription="updated reviewer"\n`,
        );
        for (const operation of mode === "deep"
          ? ["rerun", "resume"]
          : ["rerun"]) {
          const { runCli, stderr } = createCliTest(main);
          expect(
            await runCli(["scans", operation, scans[0]!.scanId, "--json"], {
              ...dependencies({ environment, currentDirectory: root }),
              runWorkbench: command,
              createSecurity: (config) =>
                new TestClient(config, runtimeDependencies),
            }),
          ).toBe(2);
          expect(stderr.text()).toContain("Synthetic stop after registration");
          const reloaded = resolveCodexProfile(
            await mergedCodexConfig({ codexOverrides: replayOverrides }, home),
          );
          expect(reloaded).toMatchObject({
            agents: { reviewer: { description: "updated reviewer" } },
          });
        }
        expect(launches).toBe(mode === "deep" ? 3 : 2);
        expect(replay).not.toHaveProperty(key);
        expect(replay).not.toHaveProperty("analytics");
        expect(replay).not.toHaveProperty("agents.reviewer.config_file");
        return;
      }
      expect(replay[key]).toBe(modelFile);
      expect(
        await readFile(resolve(rerunOutput, replay[key] as string), "utf8"),
      ).toBe(contents);
      if (kind === "inline-relative") {
        expect(recipe.config["profile"]).toBe("active");
        expect(recipe.config["profiles"]).toMatchObject({
          unused: { [key]: "keep-unused-relative.txt" },
        });
      }
    } finally {
      await client.close();
    }
  },
);
