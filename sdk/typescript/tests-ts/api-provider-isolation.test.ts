import { codexFactory, completedEvents } from "./support/api-events.js";
import { afterEach, expect, mock, test } from "bun:test";
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
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function nativeRequest(
  environment: Record<string, string>,
  cwd: string,
  args: string[],
  method: string,
  params: unknown,
) {
  const child = spawn(
    executablePathForSpawn(resolveCodexCommand({}).command),
    [...args, "app-server", "--stdio"],
    {
      cwd,
      env: { PATH: process.env["PATH"], ...environment },
      windowsHide: true,
    },
  );
  const closed = once(child, "close");
  const lines = createInterface({ input: child.stdout });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const timer = setTimeout(() => child.kill(), 15_000);
  const send = (message: unknown) =>
    child.stdin.write(JSON.stringify(message) + "\n");
  try {
    send({
      id: 1,
      method: "initialize",
      params: {
        clientInfo: { name: "synthetic_provider_test", version: "1" },
        capabilities: { experimentalApi: true },
      },
    });
    for await (const line of lines) {
      const response = JSON.parse(line);
      if (response.error) throw new Error(JSON.stringify(response.error));
      if (response.id === 1) {
        send({ method: "initialized", params: {} });
        send({ id: 2, method, params });
      }
      if (response.id === 2) return response.result;
    }
    throw new Error(`Native ${method} probe did not finish: ${stderr}`);
  } finally {
    clearTimeout(timer);
    lines.close();
    child.kill();
    await closed;
  }
}

async function effectiveProvider(
  environment: Record<string, string>,
  cwd: string,
  overrides: string[],
  nativeProfile?: string,
) {
  if (nativeProfile !== undefined) {
    const config = parseToml(
      await readFile(
        join(environment["CODEX_HOME"]!, `${nativeProfile}.config.toml`),
        "utf8",
      ),
    );
    const result = await nativeRequest(environment, cwd, [], "thread/start", {
      cwd,
      ephemeral: true,
      // This no-turn configuration check never executes model commands.
      sandbox: "danger-full-access",
      threadSource: "security_scan",
      config: { ...config, ...parseToml(overrides.join("\n")) },
    });
    return (config["model_providers"] as Record<string, unknown>)?.[
      result.modelProvider
    ];
  }
  const { config } = await nativeRequest(
    environment,
    cwd,
    overrides.flatMap((value) => ["-c", value]),
    "config/read",
    { cwd, includeLayers: false },
  );
  return config.model_providers?.[config.model_provider];
}

test("native worker override tables retain inherited features and MCP servers", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  await mkdir(home, { mode: 0o700 });
  const original = stringifyToml({
    features: { shell_tool: false, view_image: false },
    mcp_servers: {
      "inherited.server": { command: "node", args: ["inherited-argument"] },
      "codex-security": { command: "node", enabled: true },
    },
  });
  await writeFile(join(home, "config.toml"), original);
  const { config } = await nativeRequest(
    { CODEX_HOME: home },
    root,
    profileConfigOverrides({
      features: { api_key_model_discovery: false },
      mcp_servers: { "codex-security": { command: "node", enabled: false } },
    }).flatMap((value) => ["--config", value]),
    "config/read",
    { cwd: root, includeLayers: false },
  );
  expect(config.features).toMatchObject({
    shell_tool: false,
    view_image: false,
    api_key_model_discovery: false,
  });
  expect(config.mcp_servers["inherited.server"]).toMatchObject({
    command: "node",
    args: ["inherited-argument"],
    enabled: true,
  });
  expect(config.mcp_servers["codex-security"].enabled).toBe(false);
  expect(await readFile(join(home, "config.toml"), "utf8")).toBe(original);
});

test("native patch overrides disable repository MCP while preserving host MCP", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const markerRoot = join(root, "Repository.V1 With Spaces Ü");
  const repository = join(markerRoot, "packages", "app");
  const projectTrustKey =
    process.platform === "win32"
      ? repository.replace(/[A-Z]/g, (letter) => letter.toLowerCase())
      : repository;
  await mkdir(home, { mode: 0o700 });
  await mkdir(join(repository, ".codex"), { recursive: true });
  await writeFile(join(markerRoot, "package.json"), "{}\n");
  const hostConfig = stringifyToml({
    project_root_markers: ["package.json"],
    projects: {
      [markerRoot]: { trust_level: "trusted" },
      [projectTrustKey]: { trust_level: "trusted" },
    },
    mcp_servers: { host: { command: "node", args: ["host-server.js"] } },
  });
  const repositoryConfig = stringifyToml({
    mcp_servers: {
      repository: { command: "node", args: ["repository-server.js"] },
    },
  });
  await writeFile(join(home, "config.toml"), hostConfig);
  await writeFile(join(repository, ".codex", "config.toml"), repositoryConfig);
  const environment = { CODEX_HOME: home };
  const { config: trusted } = await nativeRequest(
    environment,
    repository,
    ["--cd", repository],
    "config/read",
    { cwd: repository, includeLayers: false },
  );
  expect(trusted.mcp_servers).toHaveProperty("repository");

  await using client = new TestClient(
    {},
    {
      prepareRuntime: async () => preparedRuntime(home),
      resolvePluginPython: async () => "/managed/python",
      createCodex: async (options) => {
        // Exercise CLI parsing: parsing these arguments as a TOML document
        // incorrectly treats quoted path components as literal keys.
        const { config } = await nativeRequest(
          environment,
          repository,
          [
            "--cd",
            repository,
            ...[
              ...profileConfigOverrides(options.config ?? {}),
              ...(options.configOverrides ?? []),
            ].flatMap((value) => ["--config", value]),
          ],
          "config/read",
          { cwd: repository, includeLayers: false },
        );
        expect(config.mcp_servers).not.toHaveProperty("repository");
        expect(config.projects[projectTrustKey]).toEqual({
          trust_level: "untrusted",
        });
        expect(config.project_root_markers).toEqual([]);
        expect(config.mcp_servers.host).toMatchObject({
          command: "node",
          args: ["host-server.js"],
          enabled: true,
        });
        return codexFactory(async () => ({
          events: completedEvents(
            "patch-thread",
            (async function* () {
              yield {
                type: "item.completed" as const,
                item: {
                  id: "result",
                  type: "agent_message" as const,
                  text: JSON.stringify({
                    status: "no_change",
                    changedFiles: [],
                    verificationReport: "Synthetic patch result",
                    reason: null,
                  }),
                },
              };
            })(),
          ),
        }))();
      },
    },
  );
  await client.patch({
    repositoryPath: repository,
    finding: "Synthetic finding",
  });
  expect(await readFile(join(home, "config.toml"), "utf8")).toBe(hostConfig);
  expect(
    await readFile(join(repository, ".codex", "config.toml"), "utf8"),
  ).toBe(repositoryConfig);
});

async function bundleWorkerSettings(root: string) {
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
  return bundledPath;
}

async function loadWorkerSettings(root: string) {
  const { workerRuntimeSettings } = (await import(
    pathToFileURL(await bundleWorkerSettings(root)).href
  )) as {
    workerRuntimeSettings: (environment: Record<string, string>) => Promise<{
      config: JsonObject;
      nativeProfile?: string;
      environment?: Record<string, string>;
    }>;
  };

  return workerRuntimeSettings;
}

test.each([
  "root",
  "selected profile",
  "null profile",
  "profile override",
  "profile only",
] as const)(
  "concurrent provider snapshots preserve %s credentials",
  async (selection) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const state = join(root, "state");
    const sharedHome = join(state, "codex-home");
    const sourceHome = join(root, "source-home");
    await mkdir(repository);
    await mkdir(sourceHome, { mode: 0o700 });
    await mkdir(sharedHome, { recursive: true, mode: 0o700 });
    const workerRuntimeSettings = await loadWorkerSettings(root);

    const ready = [
      Promise.withResolvers<void>(),
      Promise.withResolvers<void>(),
    ];
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
        const webSearch = index === 0 ? "disabled" : "cached";
        const featureOverrides = {
          shell_tool: index === 1,
          unified_exec: false,
          view_image: index === 0,
        };
        const shellPolicy = {
          inherit: "none",
          set: { SYNTHETIC_WORKER_VALUE: `shell-value-${index}` },
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
                web_search: selection === "root" ? webSearch : "live",
                shell_environment_policy:
                  selection === "root" ? shellPolicy : { inherit: "all" },
                features: selection === "root" ? featureOverrides : {},
                ...(selection === "profile only"
                  ? {}
                  : {
                      model_providers: {
                        openrouter:
                          selection === "profile override"
                            ? {
                                ...provider,
                                env_key: "SYNTHETIC_UNUSED_KEY",
                              }
                            : provider,
                        "required.gateway": {
                          name: "Managed selection",
                          wire_api: "responses",
                          env_key: "SYNTHETIC_REQUIRED_KEY",
                        },
                      },
                    }),
                ...(selection === "root"
                  ? {}
                  : {
                      profile: "selected",
                      profiles: {
                        selected: {
                          features: featureOverrides,
                          web_search: webSearch,
                          shell_environment_policy: shellPolicy,
                          ...(selection === "null profile"
                            ? {
                                model_provider: null,
                                model: null,
                                model_reasoning_effort: null,
                              }
                            : selection === "selected profile"
                              ? {}
                              : {
                                  model_provider: "openrouter",
                                  model_providers: {
                                    openrouter: provider,
                                    "required.gateway": {
                                      name: "Managed selection",
                                      wire_api: "responses",
                                      env_key: "SYNTHETIC_REQUIRED_KEY",
                                    },
                                  },
                                }),
                        },
                      },
                    }),
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
              createCodex: (options) =>
                codexFactory(async function runStreamed() {
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
                  expect(preflight).not.toContain("shell-value-");
                  const workerSnapshotPath =
                    environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!;
                  const workerSnapshot = parseToml(
                    await readFile(workerSnapshotPath, "utf8"),
                  );
                  expect(workerSnapshot["worker_runtime"]).toMatchObject({
                    environment: providerEnvironment,
                    shell_environment_policy: shellPolicy,
                    features: featureOverrides,
                    web_search: webSearch,
                  });
                  expect(options.config!["web_search"]).toBe(webSearch);
                  expect(options.config!["shell_environment_policy"]).toEqual(
                    shellPolicy,
                  );
                  expect(options.config!["features"]).toMatchObject(
                    featureOverrides,
                  );
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
                  expect(settings.config["features"]).toMatchObject(
                    featureOverrides,
                  );
                  expect(settings.config["web_search"]).toBe(webSearch);
                  expect(settings.config["shell_environment_policy"]).toEqual(
                    shellPolicy,
                  );
                  expect(settings.config["model_provider"]).toBe("openrouter");
                  expect(settings.nativeProfile).toBeDefined();
                  expect(settings.nativeProfile).toBe(options.nativeProfile);
                  expect(
                    (workerSnapshot["worker_runtime"] as JsonObject)[
                      "native_profile"
                    ],
                  ).toBe(settings.nativeProfile);
                  // Read A's private profile after B updates the shared home.
                  // Native profile loading is covered by the inheritance tests.
                  const nativeConfig = parseToml(
                    await readFile(
                      join(sharedHome, `${settings.nativeProfile}.config.toml`),
                      "utf8",
                    ),
                  );
                  const actual = (
                    nativeConfig["model_providers"] as JsonObject
                  )["openrouter"] as JsonObject;
                  expect(actual).toMatchObject(provider);
                  expect(actual["http_headers"] ?? {}).toEqual(
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
                })(),
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
  },
);

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
    expect(settings.config["model_provider"]).toBeUndefined();
    expect(
      await effectiveProvider(
        environment,
        root,
        profileConfigOverrides(settings.config),
        settings.nativeProfile,
      ),
    ).toMatchObject(providers?.["inherited.gateway"] ?? provider);
  }
});

for (const resume of [false, true]) {
  test.each([
    {
      name: "missing direct engine",
      capabilities: { workerProviderSnapshot: 4 },
      isolated: true,
    },
    {
      name: "old worker snapshot",
      capabilities: { directDeepScanEngine: 1, workerProviderSnapshot: 3 },
      isolated: true,
    },
    {
      name: "missing isolated snapshot",
      capabilities: { directDeepScanEngine: 1, workerProviderSnapshot: 4 },
      isolated: false,
    },
  ])(
    `rejects $name before ${resume ? "resuming" : "starting"} Deep Scan`,
    async ({ capabilities, isolated }) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scan = join(root, "scan");
      const plugin = join(root, "custom-plugin");
      const home = join(root, "codex-home");
      await mkdir(repository);
      await mkdir(scan, { mode: 0o700 });
      await mkdir(home, { mode: 0o700 });
      await cp(PLUGIN_ROOT, plugin, { recursive: true });
      const manifestPath = join(plugin, ".codex-plugin", "plugin.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.codexSecurity = capabilities;
      await writeFile(manifestPath, JSON.stringify(manifest));
      const runtime = preparedRuntime(home);
      const createCodex = mock(() => {
        throw new Error("Model execution must not begin.");
      });
      const runWorkbench = mock(async () => {
        throw new Error("Scan registration or resume must not begin.");
      });
      const client = TestClient.withDependencies({
        prepareRuntime: async () => ({
          ...runtime,
          deepScanConfigPath: isolated ? runtime.deepScanConfigPath : undefined,
          plugin: {
            ...runtime.plugin,
            pluginRoot: plugin,
            installedRoot: plugin,
          },
        }),
        createCodex,
        runWorkbench,
      });
      try {
        await expect(
          client.run(repository, {
            mode: "deep",
            outputDir: scan,
            ...(resume ? { resumeScanId: "saved-scan" } : {}),
          }),
        ).rejects.toThrow("Update the custom plugin or use the bundled plugin");
        expect(createCodex).not.toHaveBeenCalled();
        expect(runWorkbench).not.toHaveBeenCalled();
      } finally {
        await client.close();
      }
    },
  );
}

test("standard scans do not require Deep Scan plugin capabilities", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const plugin = join(root, "custom-plugin");
  const home = join(root, "codex-home");
  await mkdir(repository);
  await mkdir(home, { mode: 0o700 });
  await cp(PLUGIN_ROOT, plugin, { recursive: true });
  const manifestPath = join(plugin, ".codex-plugin", "plugin.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  delete manifest.codexSecurity;
  await writeFile(manifestPath, JSON.stringify(manifest));
  const runtime = preparedRuntime(home);
  const client = TestClient.withDependencies({
    prepareRuntime: async () => ({
      ...runtime,
      deepScanConfigPath: undefined,
      plugin: { ...runtime.plugin, pluginRoot: plugin, installedRoot: plugin },
    }),
    resolvePluginPython: async () => "/managed/python",
    createCodex: codexFactory(async () => {
      throw new Error("standard scan started");
    }),
  });
  try {
    await expect(
      client.run(repository, { outputDir: join(root, "scan") }),
    ).rejects.toThrow("standard scan started");
  } finally {
    await client.close();
  }
});

test.each(["root", "profile"])(
  "current Deep workers inherit the %s endpoint",
  async (selection) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    const endpoint = "https://endpoint.example.test/v1";
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides:
          selection === "root"
            ? { openai_base_url: endpoint }
            : {
                profile: "selected",
                profiles: {
                  selected: {
                    model_provider: "openai",
                    openai_base_url: endpoint,
                  },
                },
              },
      },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-openai-key",
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) =>
          codexFactory(async function runStreamed() {
            expect(options.config?.["openai_base_url"]).toBe(endpoint);
            const worker = parseToml(
              await readFile(
                options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!,
                "utf8",
              ),
            );
            expect(
              (worker["worker_runtime"] as JsonObject)["openai_base_url"],
            ).toBe(endpoint);
            throw new Error("synthetic endpoint inherited");
          })(),
      },
    );
    try {
      await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
        "synthetic endpoint inherited",
      );
    } finally {
      await client.close();
    }
  },
);

async function createPluginProbe(root: string, report: string) {
  const plugin = join(root, "plugin");
  await cp(PLUGIN_ROOT, plugin, { recursive: true });
  await bundleWorkerSettings(plugin);
  const probe = join(plugin, "environment-probe.mjs");
  await writeFile(
    probe,
    `import { writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import { workerRuntimeSettings } from "./worker-settings.mjs";
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.id === undefined) continue;
  let result = {};
  if (request.method === "initialize") {
    result = { protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} }, serverInfo: { name: "synthetic-environment", version: "1" } };
  } else if (request.method === "tools/list") {
    const settings = await workerRuntimeSettings(process.env);
    await writeFile(process.argv[2], JSON.stringify({
      inherited: Object.fromEntries([
        "SYNTHETIC_CUSTOM_API_KEY", "SYNTHETIC_CUSTOM_HEADER",
        "SYNTHETIC_REQUIRED_KEY", "SYNTHETIC_UNUSED_KEY",
      ].map((name) => [name, process.env[name] ?? null])),
      recovered: settings.environment,
    }));
    result = { tools: [{ name: "synthetic_environment",
      description: "Synthetic provider environment probe",
      inputSchema: { type: "object", properties: {} } }] };
  }
  console.log(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }));
}
`,
  );
  const manifestPath = join(plugin, ".mcp.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const server = manifest.mcpServers["codex-security"];
  expect(server.env_vars).not.toContain("SYNTHETIC_CUSTOM_API_KEY");
  expect(server.env_vars).not.toContain("SYNTHETIC_CUSTOM_HEADER");
  // Keep the plugin registration and production environment allowlist. Only
  // replace its MCP implementation with a no-turn observation tool.
  server.command = process.execPath;
  server.args = [probe, report];
  await writeFile(manifestPath, JSON.stringify(manifest));
  return plugin;
}

test.each([
  "SYNTHETIC_CUSTOM_API_KEY",
  "CODEX_API_KEY",
  "OPENROUTER_API_KEY",
  "FIREWORKS_API_KEY",
])(
  "native plugin workers recover the selected %s and other provider variables",
  async (providerKey) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    const sourceHome = join(root, "source-home");
    const report = join(root, "environment.json");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    await mkdir(sourceHome, { mode: 0o700 });
    const plugin = await createPluginProbe(root, report);
    const external = ["OPENROUTER_API_KEY", "FIREWORKS_API_KEY"].includes(
      providerKey,
    );
    const providerId = external
      ? providerKey.split("_")[0]!.toLowerCase()
      : "synthetic.gateway";
    const headerKey =
      process.platform === "win32"
        ? "synthetic_custom_header"
        : "SYNTHETIC_CUSTOM_HEADER";
    const providerEnvironment = {
      [providerKey]: external
        ? " synthetic-custom-key\n"
        : " synthetic-custom-key ",
      [headerKey]: " synthetic-custom-header ",
      SYNTHETIC_REQUIRED_KEY: "synthetic-required-key",
    };
    const client = new TestClient(
      {
        pluginPath: plugin,
        codexOverrides: {
          model_provider: providerId,
          model_providers: {
            [providerId]: {
              name: "Synthetic gateway",
              wire_api: "responses",
              base_url: "https://provider.example.test/v1",
              env_key: providerKey,
              env_http_headers: {
                "X-Synthetic-Token": headerKey,
                "X-Synthetic-Missing": "SYNTHETIC_UNSET_KEY",
              },
            },
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
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-account-key",
          ...providerEnvironment,
          ...(process.platform === "win32"
            ? { SYNTHETIC_CUSTOM_HEADER: " synthetic-child-header " }
            : {}),
          SYNTHETIC_UNUSED_KEY: "synthetic-unused-key",
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) =>
          codexFactory(async function runStreamed() {
            expect(options.apiKey).toBe(
              external ? undefined : "synthetic-account-key",
            );
            const status = await nativeRequest(
              {
                ...options.env!,
                ...(options.apiKey === undefined
                  ? {}
                  : { CODEX_API_KEY: options.apiKey }),
              },
              repository,
              [],
              // Tool enumeration starts the real MCP child without a model turn.
              "mcpServerStatus/list",
              { serverName: "codex-security", detail: "toolsAndAuthOnly" },
            );
            expect(status.data).toHaveLength(1);
            expect(status.data[0].name).toBe("codex-security");
            expect(status.data[0].toolsError).toBeNull();
            expect(status.data[0].tools).toHaveProperty(
              "synthetic_environment",
            );
            expect(JSON.parse(await readFile(report, "utf8"))).toEqual({
              inherited: {
                SYNTHETIC_CUSTOM_API_KEY: null,
                SYNTHETIC_CUSTOM_HEADER: null,
                SYNTHETIC_REQUIRED_KEY: null,
                SYNTHETIC_UNUSED_KEY: null,
              },
              recovered: {
                ...providerEnvironment,
                ...(process.platform === "win32"
                  ? { [headerKey]: " synthetic-child-header " }
                  : {}),
                ...(external ? { [providerKey]: "synthetic-custom-key" } : {}),
                ...(providerKey === "CODEX_API_KEY"
                  ? { CODEX_API_KEY: "synthetic-account-key" }
                  : {}),
              },
            });
            for (const text of [
              await readFile(
                options.env!["CODEX_SECURITY_CONFIG_PATH"]!,
                "utf8",
              ),
              await readFile(
                join(options.env!["CODEX_HOME"]!, "config.toml"),
                "utf8",
              ),
              JSON.stringify({
                config: options.config,
                overrides: options.configOverrides,
              }),
            ]) {
              for (const marker of Object.values(providerEnvironment)) {
                expect(text).not.toContain(marker);
              }
            }
            throw new Error("synthetic native plugin environment checked");
          })(),
      },
    );
    try {
      await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
        "synthetic native plugin environment checked",
      );
    } finally {
      await client.close();
    }
  },
);
