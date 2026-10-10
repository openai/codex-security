import { createCliTest } from "./support/cli-run.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { workbenchCommand } from "./support/workbench-command.js";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { main } from "../src/cli.js";
import { runWorkbench } from "../src/runtime.js";
import { dependencies } from "./cli-fixtures.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
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
  (["openrouter", "fireworks"] as const).flatMap((provider) =>
    (["standard", "deep"] as const).flatMap((mode) =>
      ["partial", "different-key"].map((profileKind) => ({
        provider,
        mode,
        profileKind,
      })),
    ),
  ),
)(
  "saved launches retain explicit standard provider refinements: %j",
  async ({ provider, mode, profileKind }) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "profile-home");
    const runtimeHome = join(root, "runtime-home");
    await Promise.all([mkdir(repository), mkdir(home), mkdir(runtimeHome)]);
    await writeFile(join(repository, "fixture.py"), "value = 1\n");
    await writeFile(
      join(home, "review.config.toml"),
      `model="synthetic-model"\nmodel_provider="${provider}"\n[model_providers.${provider}]\n` +
        (profileKind === "partial"
          ? "request_max_retries=4\n"
          : 'env_key="SYNTHETIC_OLD_PROVIDER_KEY"\n'),
    );
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const standard = EXTERNAL_CODEX_PROVIDERS[provider];
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      [standard.env_key]: "synthetic-launch-key",
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const overrides = {
      profile: "review",
      model_provider: provider,
      model_providers: { [provider]: standard },
    };
    const header = "synthetic-provider-header";
    let providerProfilePath: string | undefined;
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: {
          ...overrides,
          model_providers: {
            [provider]: {
              ...standard,
              http_headers: { "X-Synthetic-Credential": header },
            },
          },
        },
      },
      {
        environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(runtimeHome),
          deepScanConfigPath: join(runtimeHome, "deep-scan-config.toml"),
        }),
        resolvePluginPython: async () => python,
        runWorkbench: async (_runtime, args, input) => command(args, input),
        createCodex: async (options) => {
          expect(typeof options.nativeProfile).toBe("string");
          providerProfilePath = join(
            options.env!["CODEX_HOME"]!,
            `${options.nativeProfile}.config.toml`,
          );
          expect(
            parseToml(await readFile(providerProfilePath, "utf8")),
          ).toMatchObject({
            model_providers: {
              [provider]: {
                http_headers: { "X-Synthetic-Credential": header },
              },
            },
          });
          throw new Error("Synthetic stop after registration");
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
      )["recipe"] as { config: JsonObject };
      expect(recipe.config).toMatchObject({
        profile: "review",
        model_providers: { [provider]: standard },
      });
      const initial = await mergedCodexConfig(
        { codexOverrides: overrides },
        home,
      );
      const replay = await mergedCodexConfig(
        { codexOverrides: recipe.config },
        home,
      );
      expect(replay["model_providers"]).toEqual(initial["model_providers"]);
      expect(JSON.stringify(recipe)).not.toContain(header);
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

test.each(
  ["standard", "deep"].flatMap((mode) =>
    ["review", "review.v2", "review mode", "分析"].map(
      (profile) => [mode, profile] as const,
    ),
  ),
)(
  "%s scans save prompts and replay the selected %s profile",
  async (mode, profile) => {
    const selected = {
      model: "synthetic-selected-model",
      model_reasoning_effort: "high",
      model_provider: "amazon-bedrock",
      features: { goals: false },
    };
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
              codexOverrides: {
                model: "synthetic-root-model",
                model_reasoning_effort: "low",
                model_provider: "openai",
                profile,
                profiles: { [profile]: selected },
              },
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
    expect(saved["recipe"]).toMatchObject({ mode, postScanPrompt });
    expect(JSON.stringify(saved)).not.toContain(promptFile);
    expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
    expect(JSON.stringify(saved)).not.toContain("synthetic-bedrock-key");
    expect(
      await runCli(["scans", "rerun", scans[0]!.scanId, "--json"], {
        ...dependencies({
          environment,
          currentDirectory: root,
          onConfig: ({ codexOverrides }) => {
            expect(resolveCodexProfile(codexOverrides!)).toMatchObject(
              selected,
            );
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
  modelFileRecipeKeys.flatMap((key) =>
    ["root-relative", "inline-relative", "root-absolute"].map((kind) => ({
      key,
      kind,
    })),
  ),
)(
  "saved launch retains its original model file bytes: %j",
  async ({ key, kind }) => {
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
    const overrides: JsonObject =
      kind === "inline-relative"
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
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT, codexOverrides: overrides },
      {
        environment,
        prepareRuntime: async () => preparedRuntime(home),
        resolvePluginPython: async () => python,
        runWorkbench: async (_options, args, input) => command(args, input),
        createCodex: () => {
          throw new Error("Synthetic stop after registration");
        },
      },
    );
    try {
      await expect(
        client.run(repository, { mode: "standard", outputDir: originalOutput }),
      ).rejects.toThrow("Synthetic stop after registration");
      const scans = (await command(["list-scans", "--repository", repository]))[
        "scans"
      ] as Array<{ scanId: string }>;
      expect(scans).toHaveLength(1);
      const recipe = (
        await command(["get-scan-recipe", "--scan-id", scans[0]!.scanId])
      )["recipe"] as { config: JsonObject };
      const replay = resolveCodexProfile(
        await mergedCodexConfig({ codexOverrides: recipe.config }, home),
      );
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
