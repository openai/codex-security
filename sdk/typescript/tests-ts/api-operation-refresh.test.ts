import { cp, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

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
