import {
  cp,
  mkdir,
  readFile,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/api-events.js";
import { prepareAmbientRuntime } from "../src/execution-preparation.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test("scoped ambient scans use the isolated bootstrap workspace for target metadata", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const home = join(root, "existing-home", "codex-home");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(home, { recursive: true });
  await mkdir(scanDir, { mode: 0o700 });
  await writeFile(join(repository, "app.py"), "print(1)\n");
  const runtime = await prepareAmbientRuntime({
    command: { command: process.execPath },
    configuration: {},
    environment: { CODEX_HOME: home },
    preserveProviderEnvironment: false,
    pluginRoot: PLUGIN_ROOT,
  });
  let metadata: string | undefined;
  await using client = new TestClient(
    {},
    {
      environment: { OPENAI_API_KEY: "synthetic-test-key" },
      prepareRuntime: async () => runtime,
      resolvePluginPython: async () => "/managed/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      createCodex: (options) => ({
        startThread: () => ({
          id: null,
          async runStreamed() {
            metadata = options.env?.["CODEX_SECURITY_TARGET_PATHS_FILE"];
            expect(metadata).toBeDefined();
            expect(dirname(metadata!)).toBe(runtime.bootstrapWorkspace!);
            expect(JSON.parse(await readFile(metadata!, "utf8"))).toEqual([
              "app.py",
            ]);
            throw new Error("Synthetic scoped scan started");
          },
        }),
      }),
    },
  );
  await expect(
    client.run(repository, { target: ["app.py"], mode: "standard" }),
  ).rejects.toThrow("Synthetic scoped scan started");
  expect(metadata).toBeDefined();
  await expect(stat(metadata!)).rejects.toHaveProperty("code", "ENOENT");
});

test("a reused client applies changed model settings to the next operation", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  await mkdir(repository);
  await mkdir(scanDir, { mode: 0o700 });
  const models: unknown[] = [];
  await using client = new TestClient(
    {
      pluginPath: await realpath(PLUGIN_ROOT),
      codexOverrides: { model: "synthetic-first" },
    },
    {
      environment: {
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        OPENAI_API_KEY: "synthetic-fixture-key",
      },
      resolvePluginPython: async () => "/synthetic/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      createCodex(options) {
        models.push(options.config?.["model"]);
        throw new Error("Synthetic stop after preparation");
      },
    },
  );
  for (const model of ["synthetic-first", "synthetic-second"]) {
    client.config.codexOverrides!["model"] = model;
    await expect(client.run(repository)).rejects.toThrow(
      "Synthetic stop after preparation",
    );
  }
  expect(models).toEqual(["synthetic-first", "synthetic-second"]);
});

test("a reused client refreshes edited local plugin files before execution", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const scanDir = join(root, "scan");
  const plugin = join(root, "plugin");
  const state = join(root, "state");
  await mkdir(repository);
  await mkdir(scanDir, { mode: 0o700 });
  await cp(await realpath(PLUGIN_ROOT), plugin, { recursive: true });
  const reference = join("references", "scan-artifacts.md");
  await using client = new TestClient(
    { pluginPath: plugin },
    {
      environment: {
        CODEX_SECURITY_STATE_DIR: state,
        OPENAI_API_KEY: "synthetic-fixture-key",
      },
      resolvePluginPython: async () => "/synthetic/python",
      prepareOutputDir: async () => scanDir,
      repositoryRevision: async () => "deadbeef",
      createCodex() {
        throw new Error("Synthetic stop after preparation");
      },
    },
  );
  for (const contents of [
    "Synthetic reference one\n",
    "Synthetic reference two\n",
  ]) {
    await writeFile(join(plugin, reference), contents);
    await expect(client.run(repository)).rejects.toThrow(
      "Synthetic stop after preparation",
    );
    const config = parseToml(
      await readFile(join(state, "codex-home", "config.toml"), "utf8"),
    );
    const marketplace = Object.values(
      config["marketplaces"] as Record<string, { source: string }>,
    )[0]!;
    const installed = JSON.parse(
      await readFile(join(marketplace.source, "installed-plugin.json"), "utf8"),
    );
    expect(
      await readFile(join(installed.installedPath, reference), "utf8"),
    ).toBe(contents);
  }
});
