import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type { CodexOptions } from "@openai/codex-sdk";
import type { JsonObject } from "../src/config.js";
import { prepareAmbientExecution } from "../src/execution-preparation.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([
  ["synthetic", "env_key"],
  ["synthetic", "bearer"],
  ["openrouter", "env_key"],
  ["openrouter", "bearer"],
  ["fireworks", "env_key"],
  ["fireworks", "bearer"],
] as const)(
  "native %s %s authentication reaches the SDK run without OpenAI credentials",
  async (providerName, kind) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    await Promise.all(
      ["first", "second"].map(async (id) => {
        const home = join(root, id);
        await mkdir(home, { mode: 0o700 });
        const key = `synthetic-${id}`;
        const provider: JsonObject = {
          name: "Synthetic provider",
          base_url: "https://example.invalid/v1",
          ...(kind === "env_key"
            ? { env_key: "SYNTHETIC_PROVIDER_KEY" }
            : { experimental_bearer_token: key }),
        };
        const config: JsonObject = {
          model: "gpt-5.6-sol",
          model_provider: providerName,
          model_providers: { [providerName]: provider },
        };
        const environment = {
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(root, `state-${id}`),
          SYNTHETIC_PROVIDER_KEY: key,
        };
        const ambientExecution = await prepareAmbientExecution({
          command: { command: process.execPath },
          configuration: config,
          environment,
          pluginRoot: PLUGIN_ROOT,
          auth: "api-key",
        });
        expect(ambientExecution.preserveProviderEnvironment).toBe(true);
        expect(ambientExecution.auth).toBe("api-key");
        environment.SYNTHETIC_PROVIDER_KEY = "synthetic-later";
        provider["experimental_bearer_token"] = "synthetic-later";
        const callerConfig = structuredClone(config);
        const callerEnvironment = { ...environment };
        const preparedConfig = structuredClone(ambientExecution.configuration);
        const preparedEnvironment = { ...ambientExecution.environment };
        const observations: CodexOptions[] = [];
        const recipes: JsonObject[] = [];
        await using client = new TestClient(
          { codexOverrides: ambientExecution.configuration },
          {
            environment: ambientExecution.environment,
            ambientExecution,
            resolvePluginPython: async () => process.execPath,
            repositoryRevision: async () => "deadbeef",
            runWorkbench: async (_options, args, input) => {
              if (args[0] === "register-cli-scan")
                recipes.push(JSON.parse(input!).recipe);
              return mockWorkbench(args, input);
            },
            createCodex: (options) => {
              observations.push(options);
              return {
                startThread: () => ({
                  id: null,
                  async runStreamed() {
                    throw new Error("Synthetic native execution reached");
                  },
                }),
              };
            },
          },
        );
        await expect(
          client.run(repository, {
            mode: "standard",
            auth: ambientExecution.auth,
            preserveProviderEnvironment:
              ambientExecution.preserveProviderEnvironment,
            outputDir: join(root, `scan-${id}`),
          }),
        ).rejects.toThrow("Synthetic native execution reached");
        expect(observations).toHaveLength(1);
        expect(observations[0]!.apiKey).toBeUndefined();
        expect(observations[0]!.env).toMatchObject({
          SYNTHETIC_PROVIDER_KEY: key,
        });
        expect(observations[0]!.env).not.toHaveProperty("OPENAI_API_KEY");
        expect(observations[0]!.env).not.toHaveProperty("CODEX_API_KEY");
        const runtimeProviders = observations[0]!.config?.[
          "model_providers"
        ] as JsonObject;
        const environmentKey = (runtimeProviders[providerName] as JsonObject)[
          "env_key"
        ] as string;
        expect(typeof environmentKey).toBe("string");
        expect(observations[0]!.env?.[environmentKey]).toBe(key);
        expect(Object.values(observations[0]!.env!)).not.toContain(
          `synthetic-${id === "first" ? "second" : "first"}`,
        );
        expect(runtimeProviders).toEqual({
          [providerName]: {
            name: "Synthetic provider",
            base_url: "https://example.invalid/v1",
            env_key:
              kind === "env_key" ? "SYNTHETIC_PROVIDER_KEY" : environmentKey,
          },
        });
        expect(JSON.stringify(observations[0]!.config)).not.toContain(key);
        expect(recipes[0]?.["auth"]).toBe("api-key");
        expect(recipes[0]?.["config"]).not.toHaveProperty("model_providers");
        expect(JSON.stringify(recipes)).not.toContain(key);
        expect(config).toEqual(callerConfig);
        expect(environment).toEqual(callerEnvironment);
        expect(ambientExecution.configuration).toEqual(preparedConfig);
        expect(ambientExecution.environment).toEqual(preparedEnvironment);
      }),
    );
  },
);
