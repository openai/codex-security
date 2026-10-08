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

test.each([
  [undefined, {}],
  ["standard", {}],
  ["daybreak_blue", {}],
  ["daybreak_red", {}],
  ["daybreak_blue", { features: { api_key_cyber_access_programs: false } }],
  [
    "daybreak_blue",
    {
      profile: "selected",
      features: { api_key_model_discovery: true },
      profiles: { selected: { features: { api_key_model_discovery: false } } },
    },
  ],
] as const)(
  "forwards %s and preserves API-key gates %j",
  async (program, overrides) => {
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
      if (program === undefined) {
        expect(config).not.toHaveProperty("codex_security");
        expect(config["features"]).not.toHaveProperty(
          "api_key_cyber_access_programs",
        );
        expect(clientOptions?.config?.["features"]).not.toHaveProperty(
          "api_key_cyber_access_programs",
        );
      } else {
        const expected = {
          api_key_cyber_access_programs: !(
            "features" in overrides &&
            "api_key_cyber_access_programs" in overrides.features
          ),
          ...("profile" in overrides ? { api_key_model_discovery: false } : {}),
        };
        expect(config["codex_security"]).toEqual({
          cyber_access_program: program,
        });
        expect(config["features"]).toMatchObject(expected);
        expect(
          resolveCodexProfile(clientOptions!.config as JsonObject)["features"],
        ).toMatchObject(expected);
        if (!("profile" in overrides)) {
          expect(config["features"]).not.toHaveProperty(
            "api_key_model_discovery",
          );
        }
        expect(recipe?.["config"]).not.toHaveProperty("codex_security");
      }
    } finally {
      await client.close();
    }
  },
);
