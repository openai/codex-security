import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { JsonObject } from "../src/config.js";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { cp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
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
  nativeProfile?: string,
) {
  const privateConfig =
    nativeProfile === undefined
      ? undefined
      : parseToml(
          await readFile(
            join(environment["CODEX_HOME"]!, `${nativeProfile}.config.toml`),
            "utf8",
          ),
        );
  const child = spawn(
    executablePathForSpawn(resolveCodexCommand({}).command),
    [
      ...(privateConfig === undefined ? overrides : []).flatMap((value) => [
        "-c",
        value,
      ]),
      "app-server",
      "--stdio",
    ],
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
      if (response.id === 1) {
        if (privateConfig === undefined)
          send(2, "config/read", { cwd, includeLayers: false });
        else
          send(2, "thread/start", {
            cwd,
            ephemeral: true,
            // This no-turn configuration check never executes model commands.
            sandbox: "danger-full-access",
            threadSource: "security_scan",
            config: { ...privateConfig, ...parseToml(overrides.join("\n")) },
          });
      }
      if (response.id === 2) {
        if (privateConfig !== undefined)
          return (
            privateConfig["model_providers"] as Record<string, unknown>
          )?.[response.result.modelProvider];
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

async function loadWorkerSettings(root: string) {
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
      configOverrides?: string[];
      nativeProfile?: string;
      environment?: Record<string, string>;
    }>;
  };

  return workerRuntimeSettings;
}

test("concurrent provider snapshots do not inherit another scan's credentials", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const state = join(root, "state");
  const sharedHome = join(state, "codex-home");
  const sourceHome = join(root, "source-home");
  await mkdir(repository);
  await mkdir(sourceHome, { mode: 0o700 });
  await mkdir(sharedHome, { recursive: true, mode: 0o700 });
  // Initialize native state before the mocked primary scans start concurrently.
  await effectiveProvider({ CODEX_HOME: sharedHome }, repository, []);

  const workerRuntimeSettings = await loadWorkerSettings(root);

  const ready = [Promise.withResolvers<void>(), Promise.withResolvers<void>()];
  const clients: TestClient[] = [];
  const runs: Promise<unknown>[] = [];
  const snapshots: string[] = [];
  const filesystems: Array<Record<string, unknown>> = [];
  try {
    for (let index = 0; index < 2; index++) {
      const scan = join(root, `scan-${index}`);
      await mkdir(scan, { mode: 0o700 });
      const provider = {
        name: `Synthetic ${index}`,
        base_url: `https://provider-${index}.example.test/v1`,
        wire_api: "responses",
        env_key: "SYNTHETIC_CUSTOM_API_KEY",
        env_http_headers: {
          "X-Synthetic-Token": "SYNTHETIC_CUSTOM_HEADER",
          "X-Synthetic-Missing": "SYNTHETIC_UNSET",
        },
        ...(index === 1
          ? { http_headers: { "X-Gateway-Token": "synthetic-key-B" } }
          : {}),
      };
      const providerEnvironment = {
        SYNTHETIC_CUSTOM_API_KEY: ` synthetic-key-${index} `,
        SYNTHETIC_CUSTOM_HEADER: ` synthetic-header-${index} `,
        SYNTHETIC_REQUIRED_KEY: `synthetic-required-${index}`,
      };
      clients.push(
        new TestClient(
          {
            pluginPath: PLUGIN_ROOT,
            codexOverrides: {
              model_provider: "openrouter",
              model_providers: {
                openrouter: provider,
                "required.gateway": {
                  name: "Managed selection",
                  wire_api: "responses",
                  env_key: "SYNTHETIC_REQUIRED_KEY",
                },
              },
            },
          },
          {
            environment: {
              CODEX_HOME: sourceHome,
              CODEX_SECURITY_STATE_DIR: state,
              OPENAI_API_KEY: "synthetic-account-key",
              OPENROUTER_API_KEY: "synthetic-sdk-account-key",
              ...providerEnvironment,
              SYNTHETIC_UNUSED_KEY: "synthetic-unused-key",
            },
            resolvePluginPython: async () => "/managed/python",
            prepareOutputDir: async () => scan,
            repositoryRevision: async () => "deadbeef",
            createCodex: (options) => ({
              startThread: () => ({
                id: null,
                async runStreamed() {
                  const environment = options.env!;
                  snapshots[index] =
                    environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!;
                  const permission = parseToml(
                    options.configOverrides!.find((value) =>
                      value.startsWith(
                        "permissions.codex_security_scan.filesystem=",
                      ),
                    )!,
                  )["permissions"] as Record<string, Record<string, unknown>>;
                  filesystems[index] = permission["codex_security_scan"]![
                    "filesystem"
                  ] as Record<string, unknown>;
                  ready[index]!.resolve();
                  await ready[1]!.promise;
                  expect(snapshots[0]).not.toBe(snapshots[1]);
                  for (const snapshot of snapshots) {
                    expect(dirname(dirname(snapshot))).toBe(sharedHome);
                    for (const filesystem of filesystems) {
                      // The same denied home protects both concurrent snapshots.
                      expect(filesystem[sharedHome]).toEqual({ ".": "deny" });
                    }
                  }
                  const preflight = await readFile(
                    environment["CODEX_SECURITY_CONFIG_PATH"]!,
                    "utf8",
                  );
                  expect(preflight).not.toContain("synthetic-key-");
                  expect(preflight).not.toContain("synthetic-header-");
                  const workerSnapshotPath =
                    environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!;
                  const workerSnapshot = parseToml(
                    await readFile(workerSnapshotPath, "utf8"),
                  );
                  expect(workerSnapshot["worker_runtime"]).toMatchObject({
                    environment: providerEnvironment,
                  });
                  expect(
                    (workerSnapshot["worker_runtime"] as JsonObject)[
                      "environment"
                    ],
                  ).toEqual(providerEnvironment);
                  if (process.platform !== "win32") {
                    expect((await stat(workerSnapshotPath)).mode & 0o777).toBe(
                      0o600,
                    );
                  }
                  expect(
                    JSON.stringify({
                      config: options.config,
                      overrides: options.configOverrides,
                    }),
                  ).not.toContain("synthetic-key-");
                  const settings = await workerRuntimeSettings(environment);
                  expect(settings.environment).toEqual(providerEnvironment);
                  const actual = await effectiveProvider(
                    environment,
                    repository,
                    settings.configOverrides ?? [],
                    settings.nativeProfile,
                  );
                  expect(actual).toMatchObject(provider);
                  expect(actual.http_headers ?? {}).toEqual(
                    provider.http_headers ?? {},
                  );
                  expect(environment["SYNTHETIC_CUSTOM_API_KEY"]).toBe(
                    providerEnvironment.SYNTHETIC_CUSTOM_API_KEY,
                  );
                  const saved = await readFile(
                    join(sharedHome, "config.toml"),
                    "utf8",
                  );
                  expect(saved).not.toContain("model_providers");
                  expect(saved).not.toContain("synthetic-key-");
                  expect(saved).not.toContain("synthetic-header-");
                  throw new Error("synthetic provider configuration checked");
                },
              }),
            }),
          },
        ),
      );
    }
    // A's snapshot exists before B updates the shared credential home.
    runs.push(clients[0]!.run(repository, { mode: "deep" }));
    await Promise.race([ready[0]!.promise, runs[0]]);
    runs.push(
      clients[1]!
        .run(repository, { mode: "deep" })
        .finally(() => ready[1]!.resolve()),
    );
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
  for (const snapshot of snapshots) {
    expect(existsSync(dirname(snapshot))).toBe(false);
  }
  expect(existsSync(sharedHome)).toBe(true);
}, 30_000);

test("workers preserve native provider inheritance without an explicit selection", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "native-home");
  await mkdir(home, { mode: 0o700 });
  const provider = {
    name: "Inherited gateway",
    base_url: "https://inherited.example.test/v1",
    wire_api: "responses",
  };
  await writeFile(
    join(home, "config.toml"),
    stringifyToml({
      model_provider: "inherited.gateway",
      model_providers: { "inherited.gateway": provider },
    }),
  );
  const snapshot = join(root, "snapshot.toml");
  const workerSnapshot = join(root, "worker-snapshot.toml");
  const environment = {
    CODEX_HOME: home,
    CODEX_SECURITY_CONFIG_PATH: snapshot,
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: workerSnapshot,
  };
  const workerRuntimeSettings = await loadWorkerSettings(root);
  for (const providers of [
    undefined,
    {
      "inherited.gateway": {
        ...provider,
        base_url: "https://selected.example.test/v1",
      },
    },
  ]) {
    await writeFile(snapshot, stringifyToml({}));
    if (providers)
      await writeFile(
        join(home, "synthetic.config.toml"),
        stringifyToml({ model_providers: providers }),
      );
    await writeFile(
      workerSnapshot,
      stringifyToml({
        worker_runtime: providers ? { native_profile: "synthetic" } : {},
      }),
    );
    const settings = await workerRuntimeSettings(environment);
    expect(
      settings.configOverrides?.some((value) =>
        value.startsWith("model_provider="),
      ),
    ).not.toBe(true);
    expect(
      await effectiveProvider(
        environment,
        root,
        settings.configOverrides ?? [],
        settings.nativeProfile,
      ),
    ).toMatchObject(providers?.["inherited.gateway"] ?? provider);
  }
});

const legacyProviders: Array<[string, JsonObject]> = [
  [
    "explicit gateway",
    {
      model_provider: "openrouter",
      model_providers: {
        openrouter: {
          name: "Synthetic gateway",
          base_url: "https://gateway.example.test/v1",
          wire_api: "responses",
          env_key: "OPENROUTER_API_KEY",
        },
      },
    },
  ],
  ["explicit OpenAI", { model_provider: "openai" }],
  [
    "profile-selected OpenAI",
    {
      profile: "selected",
      profiles: { selected: { model_provider: "openai" } },
    },
  ],
  [
    "inherited provider definition",
    {
      model_providers: {
        "amazon-bedrock": {
          aws: { region: "us-east-1" },
          base_url: "https://gateway.example.test/v1",
        },
      },
    },
  ],
];
test.each(legacyProviders)(
  "checks older custom worker compatibility before launching %s",
  async (_name, overrides) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    const plugin = join(root, "custom-plugin");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    await cp(PLUGIN_ROOT, plugin, { recursive: true });
    const manifestPath = join(plugin, ".codex-plugin", "plugin.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    manifest.codexSecurity = { workerProviderSnapshot: 3 };
    await writeFile(manifestPath, JSON.stringify(manifest));
    let launched = false;
    const client = new TestClient(
      { pluginPath: plugin, codexOverrides: overrides },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-openai-key",
          OPENROUTER_API_KEY: "synthetic-gateway-key",
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: () => {
          launched = true;
          throw new Error("unexpected model launch");
        },
      },
    );
    try {
      await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
        "Update the custom plugin or use the bundled plugin",
      );
      expect(launched).toBe(false);
    } finally {
      await client.close();
    }
  },
);

test.each(["standard", "deep", "standard with explicit provider"] as const)(
  "keeps older custom plugins working for %s scans",
  async (scenario) => {
    const mode = scenario === "deep" ? "deep" : "standard";
    const explicitProvider = scenario === "standard with explicit provider";
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    const plugin = join(root, "custom-plugin");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    await cp(PLUGIN_ROOT, plugin, { recursive: true });
    const manifestPath = join(plugin, ".codex-plugin", "plugin.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    delete manifest.codexSecurity;
    await writeFile(manifestPath, JSON.stringify(manifest));
    const client = new TestClient(
      {
        pluginPath: plugin,
        ...(explicitProvider ? { codexOverrides: legacyProviders[0]![1] } : {}),
      },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-openai-key",
          OPENROUTER_API_KEY: "synthetic-gateway-key",
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              const config = parseToml(
                await readFile(
                  options.env!["CODEX_SECURITY_CONFIG_PATH"]!,
                  "utf8",
                ),
              );
              expect(config["model_provider"]).toBe(
                explicitProvider ? "openrouter" : undefined,
              );
              throw new Error("synthetic compatible scan started");
            },
          }),
        }),
      },
    );
    try {
      await expect(client.run(repository, { mode })).rejects.toThrow(
        "synthetic compatible scan started",
      );
    } finally {
      await client.close();
    }
  },
);
