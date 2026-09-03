import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { CodexSecurity } from "../src/api.js";
import {
  mergedCodexConfig,
  scanModelConfiguration,
  type CodexSecurityConfig,
  type JsonObject,
} from "../src/config.js";
import { ScanInterruptedError } from "../src/errors.js";
import type { ScanModelSelector } from "../src/scan-model-selection.js";
import { mockWorkbench } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const fixtures = createApiTestFixtures();
afterEach(fixtures.cleanup);

const originalSelection = { model: "gpt-5.4", reasoningEffort: "medium" };
const acceptedSelection = { model: "gpt-5.5", reasoningEffort: "xhigh" };
const guidanceMarker =
  "The launcher has already handled model and reasoning guidance.";

async function createScan(
  configuration: CodexSecurityConfig,
  selectScanModel?: ScanModelSelector,
) {
  const root = await fixtures.temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const ambientHome = join(root, "ambient-home");
  const scanDir = join(root, "scan");
  await Promise.all([
    mkdir(repository),
    mkdir(codexHome),
    mkdir(ambientHome),
    mkdir(scanDir, { mode: 0o700 }),
  ]);
  const savedConfig = 'model = "gpt-5.4"\nmodel_reasoning_effort = "medium"\n';
  const ambientConfigPath = join(ambientHome, "config.toml");
  const sharedConfigPath = join(codexHome, "config.toml");
  const configPath = join(root, "scan-launch-config.toml");
  await Promise.all([
    writeFile(ambientConfigPath, savedConfig),
    writeFile(sharedConfigPath, savedConfig),
  ]);
  const effectiveConfig = await mergedCodexConfig(configuration);
  const runtime = {
    ...preparedRuntime(codexHome),
    effectiveConfig,
    configPath,
    environment: { CODEX_HOME: codexHome },
  };
  const observed: {
    codexOptions?: CodexOptions;
    recipe?: JsonObject;
    prompt?: string;
    runtimePreparations: number;
    threadsStarted: number;
  } = { runtimePreparations: 0, threadsStarted: 0 };
  const client = new CodexSecurity(
    configuration,
    {
      environment: { CODEX_HOME: ambientHome },
      prepareRuntime: async () => {
        observed.runtimePreparations += 1;
        return runtime;
      },
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      prepareScanArtifactRestorer: async () => ({ restore: async () => {} }),
      repositoryRevision: async () => "deadbeef",
      runWorkbench: async (_options, args, input) => {
        if (args[0] === "register-cli-scan") {
          observed.recipe = (
            JSON.parse(input!) as { recipe: JsonObject }
          ).recipe;
        }
        return mockWorkbench(args, input);
      },
      createCodex: (options) => {
        observed.codexOptions = options;
        return {
          startThread: () => {
            observed.threadsStarted += 1;
            return {
              id: null,
              async runStreamed(prompt: string) {
                observed.prompt = prompt;
                await fixtures.copyCompletedScan(root);
                return { events: completedEvents() };
              },
            };
          },
        };
      },
    },
    { surface: "cli", ...(selectScanModel ? { selectScanModel } : {}) },
  );
  return {
    client,
    repository,
    codexHome,
    runtime,
    effectiveConfig,
    observed,
    configPath,
    ambientConfigPath,
    sharedConfigPath,
    savedConfig,
  };
}

describe("CLI scan model selection integration", () => {
  test.each(["direct", "profile"])(
    "applies accepted settings to %s runtime configuration and scan recipe only",
    async (selection) => {
      const profile = selection === "profile";
      const configuration: CodexSecurityConfig = {
        codexOverrides: {
          model: "gpt-5.4",
          model_reasoning_effort: "medium",
          ...(profile
            ? {
                profile: "scan",
                profiles: {
                  scan: { model: "gpt-5.4", model_reasoning_effort: "medium" },
                  other: { model: "gpt-5.4", model_reasoning_effort: "high" },
                },
              }
            : {}),
        },
      };
      const originalConfiguration = structuredClone(configuration);
      let selectorCalls = 0;
      const scan = await createScan(
        configuration,
        async (current, _loadModels, signal) => {
          selectorCalls += 1;
          expect(current).toEqual(originalSelection);
          expect(signal.aborted).toBe(false);
          return acceptedSelection;
        },
      );
      const originalEffectiveConfig = structuredClone(scan.effectiveConfig);
      try {
        await scan.client.run(scan.repository);
        const runtimeConfig = scan.observed.codexOptions?.config as JsonObject;
        const recipeConfig = scan.observed.recipe?.["config"] as JsonObject;
        const preflightConfig = parseToml(
          await readFile(scan.configPath, "utf8"),
        ) as JsonObject;
        for (const config of [runtimeConfig, recipeConfig, preflightConfig]) {
          expect(scanModelConfiguration(config)).toEqual(acceptedSelection);
          if (profile) {
            expect(config["model"]).toBe("gpt-5.4");
            expect(config["model_reasoning_effort"]).toBe("medium");
            expect(config["profiles"]).toMatchObject({
              scan: { model: "gpt-5.5", model_reasoning_effort: "xhigh" },
              other: { model: "gpt-5.4", model_reasoning_effort: "high" },
            });
          }
        }
        expect(selectorCalls).toBe(1);
        expect(scan.observed.threadsStarted).toBe(1);
        expect(scan.observed.prompt).toContain(guidanceMarker);
        expect(
          scan.observed.codexOptions?.env?.["CODEX_SECURITY_CONFIG_PATH"],
        ).toBe(scan.configPath);
        expect(configuration).toEqual(originalConfiguration);
        expect(scan.client.config).toEqual(originalConfiguration);
        expect(scan.runtime.effectiveConfig).toBe(scan.effectiveConfig);
        expect(scan.runtime.effectiveConfig).toEqual(originalEffectiveConfig);
        expect(await readFile(scan.ambientConfigPath, "utf8")).toBe(
          scan.savedConfig,
        );
        expect(await readFile(scan.sharedConfigPath, "utf8")).toBe(
          scan.savedConfig,
        );
      } finally {
        await scan.client.close();
      }
    },
  );

  test("dry preflight does not invoke the selector or initialize a runtime", async () => {
    const scan = await createScan(
      {
        codexOverrides: { model: "gpt-5.4", model_reasoning_effort: "medium" },
      },
      async () => {
        throw new Error("A dry preflight must not select a model");
      },
    );
    try {
      expect(await scan.client.preflight(scan.repository)).toMatchObject(
        originalSelection,
      );
      expect(scan.observed.runtimePreparations).toBe(0);
      expect(scan.observed.threadsStarted).toBe(0);
      expect(existsSync(scan.configPath)).toBe(false);
    } finally {
      await scan.client.close();
    }
  });

  test("leaves model guidance to the plugin when there is no selector", async () => {
    const scan = await createScan({
      codexOverrides: { model: "gpt-5.4", model_reasoning_effort: "medium" },
    });
    try {
      await scan.client.run(scan.repository);
      expect(scan.observed.prompt).not.toContain(guidanceMarker);
      expect(
        scanModelConfiguration(
          scan.observed.codexOptions?.config as JsonObject,
        ),
      ).toEqual(originalSelection);
    } finally {
      await scan.client.close();
    }
  });

  test("cancellation during model selection starts no scan and closes the runtime", async () => {
    const controller = new AbortController();
    let selectorCalls = 0;
    const scan = await createScan(
      {
        codexOverrides: { model: "gpt-5.4", model_reasoning_effort: "medium" },
      },
      async (_current, _loadModels, signal) => {
        selectorCalls += 1;
        controller.abort();
        expect(signal.aborted).toBe(true);
        return acceptedSelection;
      },
    );
    try {
      await expect(
        scan.client.run(scan.repository, { signal: controller.signal }),
      ).rejects.toBeInstanceOf(ScanInterruptedError);
      expect(selectorCalls).toBe(1);
      expect(scan.observed.threadsStarted).toBe(0);
      expect(scan.observed.codexOptions).toBeUndefined();
      expect(scan.observed.recipe).toBeUndefined();
    } finally {
      await scan.client.close();
    }
    expect(existsSync(scan.codexHome)).toBe(false);
  });
});
