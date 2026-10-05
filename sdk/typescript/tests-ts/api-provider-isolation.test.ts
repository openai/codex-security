import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import { executablePathForSpawn, resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function effectiveProvider(
  environment: Record<string, string>,
  cwd: string,
  overrides: string[],
) {
  const child = spawn(
    executablePathForSpawn(resolveCodexCommand({}).command),
    [...overrides.flatMap((value) => ["-c", value]), "app-server", "--stdio"],
    {
      cwd,
      env: { PATH: process.env["PATH"], ...environment },
      windowsHide: true,
    },
  );
  const closed = once(child, "close");
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const timer = setTimeout(() => child.kill(), 15_000);
  const lines = createInterface({ input: child.stdout });
  const send = (id: number, method: string, params: unknown) =>
    child.stdin.write(JSON.stringify({ id, method, params }) + "\n");
  try {
    send(1, "initialize", {
      clientInfo: { name: "synthetic_provider_test", version: "1" },
      capabilities: { experimentalApi: true },
    });
    for await (const line of lines) {
      const response = JSON.parse(line);
      if (response.error) throw new Error(JSON.stringify(response.error));
      if (response.id === 1)
        send(2, "config/read", { cwd, includeLayers: false });
      if (response.id === 2) {
        const config = response.result.config;
        return config.model_providers?.[config.model_provider];
      }
    }
    throw new Error(`Native configuration read did not finish: ${stderr}`);
  } finally {
    clearTimeout(timer);
    lines.close();
    child.kill();
    await closed;
  }
}

test("concurrent provider snapshots do not inherit another scan's credentials", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const state = join(root, "state");
  const sharedHome = join(state, "codex-home");
  await mkdir(repository);
  await mkdir(sharedHome, { recursive: true, mode: 0o700 });
  // Initialize native state before the mocked primary scans start concurrently.
  await effectiveProvider({ CODEX_HOME: sharedHome }, repository, []);

  const executor = fileURLToPath(
    new URL(
      "../../../plugins/codex-security/mcp-app/src/deep-scan/executor.ts",
      import.meta.url,
    ),
  );
  const bundled = await build({
    bundle: true,
    format: "esm",
    platform: "node",
    write: false,
    define: { "import.meta.url": JSON.stringify(pathToFileURL(executor).href) },
    stdin: {
      contents:
        (await readFile(executor, "utf8")) +
        "\nexport { workerRuntimeSettings };",
      loader: "ts",
      resolveDir: dirname(executor),
      sourcefile: executor,
    },
  });
  const bundledPath = join(root, "worker-settings.mjs");
  await writeFile(bundledPath, bundled.outputFiles[0]!.contents);
  const { workerRuntimeSettings } = (await import(
    pathToFileURL(bundledPath).href
  )) as {
    workerRuntimeSettings: (environment: Record<string, string>) => Promise<{
      providerOverrides: string[];
    }>;
  };

  const ready = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
  const clients: TestClient[] = [];
  const runs: Promise<unknown>[] = [];
  try {
    for (let index = 0; index < 2; index++) {
      const scan = join(root, `scan-${index}`);
      await mkdir(scan, { mode: 0o700 });
      const provider = {
        name: `Synthetic ${index}`,
        base_url: `https://provider-${index}.example.test/v1`,
        wire_api: "responses",
        env_key: "OPENROUTER_API_KEY",
        ...(index === 1
          ? { http_headers: { "X-Gateway-Token": "synthetic-key-B" } }
          : {}),
      };
      clients.push(
        new TestClient(
          {
            pluginPath: PLUGIN_ROOT,
            codexOverrides: {
              model_provider: "openrouter",
              model_providers: { openrouter: provider },
            },
          },
          {
            environment: {
              CODEX_SECURITY_STATE_DIR: state,
              OPENROUTER_API_KEY:
                index === 0 ? "synthetic-key-A" : "synthetic-key-B",
            },
            resolvePluginPython: async () => "/managed/python",
            prepareOutputDir: async () => scan,
            repositoryRevision: async () => "deadbeef",
            createCodex: (options) => ({
              startThread: () => ({
                id: null,
                async runStreamed() {
                  ready[index]!.resolve();
                  await ready[1]!.promise;
                  const environment = options.env!;
                  const settings = await workerRuntimeSettings(environment);
                  const actual = await effectiveProvider(
                    environment,
                    repository,
                    settings.providerOverrides,
                  );
                  expect(actual).toMatchObject(provider);
                  expect(actual.http_headers ?? {}).toEqual(
                    provider.http_headers ?? {},
                  );
                  expect(environment["OPENROUTER_API_KEY"]).toBe(
                    index === 0 ? "synthetic-key-A" : "synthetic-key-B",
                  );
                  const saved = await readFile(
                    join(sharedHome, "config.toml"),
                    "utf8",
                  );
                  expect(saved).not.toContain("model_providers");
                  expect(saved).not.toContain("synthetic-key-");
                  throw new Error("synthetic provider configuration checked");
                },
              }),
            }),
          },
        ),
      );
    }
    // A's snapshot exists before B updates the shared credential home.
    runs.push(clients[0]!.run(repository));
    await Promise.race([ready[0]!.promise, runs[0]]);
    runs.push(clients[1]!.run(repository).finally(() => ready[1]!.resolve()));
    const outcomes = await Promise.allSettled(runs);
    for (const outcome of outcomes) {
      expect(outcome).toMatchObject({
        status: "rejected",
        reason: expect.objectContaining({
          message: "synthetic provider configuration checked",
        }),
      });
    }
  } finally {
    ready.forEach((entry) => entry.resolve());
    await Promise.allSettled(runs);
    await Promise.all(clients.map((client) => client.close()));
  }
}, 30_000);
