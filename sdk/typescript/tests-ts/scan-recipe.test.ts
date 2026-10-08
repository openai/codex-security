import { createCliTest } from "./support/cli-run.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { EXTERNAL_CODEX_PROVIDERS, type JsonObject } from "../src/config.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each(["standard", "deep"])(
  "%s scans save large post-scan prompts before starting Codex",
  async (mode) => {
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
    };
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
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
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: throwing("Synthetic stop after registration"),
          }),
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
  },
);

test.each(
  (["minimax", "minimax-cn"] as const).flatMap((provider) =>
    (["standard", "deep"] as const).flatMap((mode) =>
      [false, true].map((tuned) => [provider, mode, tuned] as const),
    ),
  ),
)(
  "replays registered %s %s recipes with provider tuning=%p",
  async (provider, mode, tuned) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    const scanDir = join(root, "scan");
    for (const directory of [repository, home, scanDir])
      await mkdir(directory, { mode: 0o700 });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const environment = {
      PATH: process.env["PATH"],
      MINIMAX_API_KEY: "synthetic-recipe-key",
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    let recipe: JsonObject | undefined;
    const deps = dependencies({ environment, currentDirectory: repository });
    deps.createSecurity = (config) =>
      new TestClient(config, {
        environment,
        prepareRuntime: async () => ({
          ...preparedRuntime(home),
          deepScanConfigPath: join(home, "deep.toml"),
        }),
        resolvePluginPython: async () => process.execPath,
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => null,
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "register-cli-scan") {
            recipe = JSON.parse(input!).recipe;
            throw new Error("Synthetic stop after recipe registration");
          }
          return {};
        },
      });
    const args = [
      "scan",
      repository,
      "--provider",
      provider,
      "--model",
      "MiniMax-M3",
      "--auth",
      "api-key",
      "--mode",
      mode,
      "--json",
    ];
    if (tuned)
      for (const [key, value] of Object.entries({
        request_max_retries: 5,
        stream_max_retries: 4,
        stream_idle_timeout_ms: 12345,
        supports_websockets: false,
      }))
        args.push("--codex", `model_providers.${provider}.${key}=${value}`);
    const initialError = capture();
    expect(await main(args, capture().stream, initialError.stream, deps)).toBe(
      2,
    );
    expect(initialError.text()).toContain(
      "Synthetic stop after recipe registration",
    );
    if (recipe === undefined)
      throw new Error("Registration did not save a recipe.");
    const savedRecipe = recipe;
    const definition = {
      ...EXTERNAL_CODEX_PROVIDERS[provider],
      ...(tuned
        ? {
            request_max_retries: 5,
            stream_max_retries: 4,
            stream_idle_timeout_ms: 12345,
            supports_websockets: false,
          }
        : {}),
    };
    expect(recipe?.["config"]).toHaveProperty("model_providers", {
      [provider]: definition,
    });
    expect(JSON.stringify(recipe)).not.toContain("synthetic-recipe-key");
    for (const command of mode === "deep" ? ["rerun", "resume"] : ["rerun"]) {
      let reachedRun = false;
      const stderr = capture();
      const replay = dependencies({
        environment,
        currentDirectory: repository,
        onWorkbench: () => ({
          scanId: "synthetic-scan",
          scanDir,
          recipe: savedRecipe,
        }),
        onConfig: (config) =>
          expect(config.codexOverrides?.["model_providers"]).toEqual({
            [provider]: definition,
          }),
        onRun: () => {
          reachedRun = true;
        },
      });
      expect(
        await main(
          ["scans", command, "synthetic-scan", "--json"],
          capture().stream,
          stderr.stream,
          replay,
        ),
        stderr.text(),
      ).toBe(0);
      expect(reachedRun).toBe(true);
    }
  },
);
