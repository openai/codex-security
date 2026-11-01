import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions, ThreadEvent, TurnOptions } from "@openai/codex-sdk";
import { afterEach, expect, test, mock } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { codexFactory, preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const fixtures = createApiTestFixtures();
afterEach(fixtures.cleanup);

const denied = "403: API key is not entitled to the requested Cyber program";
async function* deniedEvents(): AsyncGenerator<ThreadEvent> {
  yield { type: "turn.failed", error: { message: denied } };
}

function programGateProfile(root: boolean, selected: boolean | null) {
  return {
    profile: "selected",
    features: { api_key_cyber_access_programs: root },
    profiles: {
      selected: { features: { api_key_cyber_access_programs: selected } },
    },
  };
}

test.each([
  [undefined, {}, undefined],
  ["standard", {}, true],
  ["daybreak_blue", {}, true],
  ["daybreak_red", {}, true],
  [undefined, { daybreak: true }, undefined],
  [undefined, { daybreak: false }, undefined],
  ["standard", { daybreak: true }, true],
  ["daybreak_blue", { daybreak: false }, true],
  [undefined, { daybreak: true, features: { cli_daybreak: false } }, undefined],
  [
    undefined,
    {
      daybreak: true,
      features: { cli_daybreak: true },
      profile: "selected",
      profiles: { selected: { features: { cli_daybreak: false } } },
    },
    undefined,
  ],
  [
    undefined,
    {
      daybreak: false,
      features: { cli_daybreak: false },
      profile: "selected",
      profiles: { selected: { features: { cli_daybreak: true } } },
    },
    undefined,
  ],
  [
    undefined,
    {
      daybreak: false,
      profile: "selected",
      profiles: { selected: { daybreak: true } },
    },
    undefined,
  ],
  [
    "daybreak_blue",
    { features: { api_key_cyber_access_programs: false } },
    false,
  ],
  ["daybreak_blue", programGateProfile(true, false), false],
  ["daybreak_blue", programGateProfile(false, true), true],
  ["daybreak_blue", programGateProfile(false, null), false],
  [
    "daybreak_blue",
    {
      profile: "selected",
      features: { api_key_model_discovery: true },
      profiles: { selected: { features: { api_key_model_discovery: false } } },
    },
    true,
  ],
] as const)(
  "forwards %s and preserves API-key gates %j",
  async (program, overrides, expectedGate) => {
    const root = await fixtures.temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await mkdir(codexHome);
    await mkdir(scanDir, { mode: 0o700 });
    const runtime = {
      ...preparedRuntime(codexHome),
      configPath: join(root, "runtime.toml"),
      environment: { OPENAI_API_KEY: "synthetic-api-key" },
    };
    let clientOptions: CodexOptions | undefined;
    const runStreamed = mock(async (_input: string, _options: TurnOptions) => {
      return { events: deniedEvents() };
    });
    let recipe: JsonObject | undefined;
    const client = new TestClient(
      { codexOverrides: overrides as JsonObject },
      {
        environment: { OPENAI_API_KEY: "synthetic-api-key" },
        prepareRuntime: async () => runtime,
        resolvePluginPython: async () =>
          Bun.which("python3") ?? Bun.which("python")!,
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "register-cli-scan")
            recipe = JSON.parse(input!).recipe;
          return mockWorkbench(args, input);
        },
        createCodex: (options) => {
          clientOptions = options;
          return codexFactory(runStreamed)();
        },
      },
    );
    try {
      await expect(
        client.run(repository, {
          auth: "api-key",
          cyberAccessProgram: program,
        }),
      ).rejects.toThrow(denied);
      expect(runStreamed.mock.lastCall?.[1]?.cyberAccessProgram).toBe(program);
      expect(recipe?.["cyberAccessProgram"]).toBe(program);
      expect(clientOptions?.apiKey).toBe("synthetic-api-key");
      const config = parseToml(await readFile(runtime.configPath, "utf8"));
      const resolved = resolveCodexProfile(overrides as JsonObject);
      const requestedFeatures = resolved["features"] as JsonObject | undefined;
      for (const snapshot of [
        config,
        clientOptions?.config,
        recipe?.["config"] as JsonObject,
      ]) {
        expect(snapshot?.["daybreak"]).toBe(resolved["daybreak"]);
        expect(
          (snapshot?.["features"] as JsonObject | undefined)?.["cli_daybreak"],
        ).toBe(requestedFeatures?.["cli_daybreak"]);
      }
      for (const snapshot of [config, clientOptions?.config]) {
        const features = snapshot?.["features"] as JsonObject;
        expect(features["api_key_cyber_access_programs"]).toBe(expectedGate);
        expect(features["api_key_model_discovery"]).toBe(
          requestedFeatures?.["api_key_model_discovery"],
        );
      }
      if (program === undefined) {
        expect(config).not.toHaveProperty("codex_security");
      } else {
        expect(config["codex_security"]).toEqual({
          cyber_access_program: program,
        });
      }
      expect(recipe?.["config"]).not.toHaveProperty("codex_security");
    } finally {
      await client.close();
    }
  },
);
