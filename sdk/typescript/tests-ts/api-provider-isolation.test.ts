import { nativeRequest } from "./support/native-request.js";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import { existsSync } from "node:fs";
import { cp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createProviderProfile } from "../src/provider-profile.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

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
    // Initialize native state before the mocked primary scans start concurrently.
    await effectiveProvider({ CODEX_HOME: sharedHome }, repository, []);

    const ready = [
      Promise.withResolvers<void>(),
      Promise.withResolvers<void>(),
    ];
    const clients: TestClient[] = [];
    const runs: Promise<unknown>[] = [];
    const snapshots: string[] = [];
    const snapshotContents: string[] = [];
    const filesystems: Array<Record<string, unknown>> = [];
    const observedProviders: Array<Record<string, unknown>> = [];
    const checkedLaunches = [0, 0];
    const launches = [0, 0];
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
              runWorkbench: async (_options, args, input) =>
                args[0] === "list-scans"
                  ? { scans: [] }
                  : args[0] === "get-scan"
                    ? { scan: { progress: { status: "running" } } }
                    : mockWorkbench(args, input),
              prepareOutputDir: async () => scan,
              repositoryRevision: async () => "deadbeef",
              createCodex: (options) => ({
                startThread: () => ({
                  id: null,
                  async runStreamed() {
                    const environment = options.env!;
                    launches[index]!++;
                    snapshots[index] =
                      environment["CODEX_SECURITY_CONFIG_PATH"]!;
                    expect(environment["CODEX_HOME"]).toBe(sharedHome);
                    expect(
                      environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"],
                    ).toBeUndefined();
                    expect(dirname(snapshots[index]!)).not.toBe(sharedHome);
                    const config = options.config! as JsonObject;
                    const permissions = config["permissions"] as Record<
                      string,
                      Record<string, unknown>
                    >;
                    filesystems[index] = permissions["codex_security_scan"]![
                      "filesystem"
                    ] as Record<string, unknown>;
                    expect(filesystems[index]![sharedHome]).toEqual({
                      ".": "deny",
                    });
                    const preflight = await readFile(snapshots[index]!, "utf8");
                    snapshotContents[index] ??= preflight;
                    expect(preflight).not.toContain("synthetic-key-");
                    expect(preflight).not.toContain("synthetic-header-");
                    expect(config["web_search"]).toBe(webSearch);
                    expect(config["features"]).toMatchObject(featureOverrides);
                    expect(
                      (config["model_providers"] as JsonObject)["openrouter"],
                    ).toMatchObject(provider);
                    for (const [name, value] of Object.entries(
                      providerEnvironment,
                    )) {
                      expect(environment[name]).toBe(value);
                    }
                    const persistedPath = join(sharedHome, "config.toml");
                    const persisted = parseToml(
                      await readFile(persistedPath, "utf8"),
                    );
                    expect(
                      (persisted["model_providers"] as JsonObject)[
                        "openrouter"
                      ],
                    ).toMatchObject(provider);
                    if (process.platform !== "win32") {
                      expect((await stat(sharedHome)).mode & 0o777).toBe(0o700);
                      expect((await stat(persistedPath)).mode & 0o777).toBe(
                        0o600,
                      );
                      expect((await stat(snapshots[index]!)).mode & 0o777).toBe(
                        0o600,
                      );
                    }
                    if (observedProviders[index] === undefined) {
                      // Observe the native file layer while the current execution
                      // lock protects this scan's configuration. No model turn
                      // or provider definition is passed through process argv.
                      observedProviders[index] = await effectiveProvider(
                        environment,
                        repository,
                        [],
                      );
                      expect(observedProviders[index]).toMatchObject(provider);
                      expect(
                        observedProviders[index]!["http_headers"] ?? {},
                      ).toEqual(provider.http_headers ?? {});
                    }
                    checkedLaunches[index]!++;
                    ready[index]!.resolve();
                    throw new Error("synthetic provider configuration checked");
                  },
                }),
              }),
            },
          ),
        );
      }
      const scanOptions = {
        mode: "deep" as const,
        workers: 1,
        subagents: 0,
        maxDiscoveryRuns: 1,
        stopAfterConsecutiveErrors: 1,
      };
      // A's snapshot exists before B updates the shared credential home.
      runs.push(clients[0]!.run(repository, scanOptions));
      await Promise.race([ready[0]!.promise, runs[0]]);
      runs.push(
        clients[1]!
          .run(repository, scanOptions)
          .finally(() => ready[1]!.resolve()),
      );
      const outcomes = await Promise.allSettled(runs);
      for (const outcome of outcomes) {
        expect(outcome).toMatchObject({
          status: "rejected",
          reason: expect.objectContaining({
            message: "Deep Scan reached its consecutive error limit.",
          }),
        });
      }
      expect(snapshots[0]).not.toBe(snapshots[1]);
      expect(observedProviders).toHaveLength(2);
      expect(observedProviders[0]).not.toEqual(observedProviders[1]);
      expect(checkedLaunches).toEqual(launches);
      expect(checkedLaunches.every((count) => count > 0)).toBe(true);
      for (const [index, snapshot] of snapshots.entries()) {
        expect(await readFile(snapshot, "utf8")).toBe(snapshotContents[index]!);
      }
      expect(
        await readFile(join(sourceHome, "config.toml"), "utf8").catch(() => ""),
      ).toBe("");
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
  const original = stringifyToml({
    model_provider: "inherited.gateway",
    model_providers: { "inherited.gateway": provider },
  });
  await writeFile(join(home, "config.toml"), original);
  for (const providers of [
    undefined,
    {
      "inherited.gateway": {
        ...provider,
        base_url: "https://selected.example.test/v1",
      },
    },
  ]) {
    const profile =
      providers === undefined
        ? undefined
        : await createProviderProfile(home, { model_providers: providers });
    try {
      expect(
        await effectiveProvider({ CODEX_HOME: home }, root, [], profile?.name),
      ).toMatchObject(providers?.["inherited.gateway"] ?? provider);
      expect(await readFile(join(home, "config.toml"), "utf8")).toBe(original);
      if (profile && process.platform !== "win32")
        expect((await stat(profile.path)).mode & 0o777).toBe(0o600);
    } finally {
      await profile?.cleanup();
    }
    if (profile) expect(existsSync(profile.path)).toBe(false);
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
  [
    "OpenAI with custom definitions",
    {
      model_provider: "openai",
      model_providers: {
        synthetic: {
          name: "Synthetic",
          wire_api: "responses",
          base_url: "https://gateway.example.test/v1",
          env_key: "SYNTHETIC_OPENAI_API_KEY",
        },
      },
    },
  ],
  [
    "profile OpenAI with custom definitions",
    {
      profile: "selected",
      profiles: {
        selected: {
          model_provider: "openai",
          model_providers: {
            synthetic: {
              name: "Synthetic",
              wire_api: "responses",
              base_url: "https://gateway.example.test/v1",
              env_key: "SYNTHETIC_OPENAI_API_KEY",
            },
          },
        },
      },
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
const legacyScanCases: Array<
  [
    string,
    "standard" | "deep",
    JsonObject,
    {
      capability?: true | number;
      inherited?: string;
      managed?: string;
      isolatedConfig?: boolean;
      rejects?: boolean;
      reads?: boolean;
    },
  ]
> = [
  ...legacyProviders.map(
    ([name, overrides]): (typeof legacyScanCases)[number] => [
      `deep with incompatible ${name}`,
      "deep",
      overrides,
      { capability: 3, rejects: true },
    ],
  ),
  ["standard", "standard", {}, {}],
  ["deep", "deep", {}, {}],
  ["standard with explicit provider", "standard", legacyProviders[0]![1], {}],
  [
    "deep with a root endpoint and no private snapshot",
    "deep",
    { openai_base_url: "https://endpoint.example.test/v1" },
    { isolatedConfig: false, rejects: true },
  ],
  [
    "deep with an OpenAI endpoint and readable snapshot",
    "deep",
    {
      model_provider: "openai",
      openai_base_url: "https://endpoint.example.test/v1",
    },
    { capability: true, rejects: true },
  ],
  [
    "deep with a profile endpoint and selector snapshot 2",
    "deep",
    {
      profile: "selected",
      profiles: {
        selected: { openai_base_url: "https://endpoint.example.test/v1" },
      },
    },
    { capability: 2, rejects: true },
  ],
  [
    "deep with a profile endpoint override and selector snapshot 3",
    "deep",
    {
      openai_base_url: "https://unused.example.test/v1",
      profile: "selected",
      profiles: {
        selected: {
          model_provider: "openai",
          openai_base_url: "https://endpoint.example.test/v1",
        },
      },
    },
    { capability: 3, rejects: true },
  ],
  [
    "deep with an endpoint fallback and no private snapshot path",
    "deep",
    {
      openai_base_url: "https://endpoint.example.test/v1",
      profile: "selected",
      profiles: { selected: { model_provider: "openai" } },
    },
    { capability: 4, isolatedConfig: false, rejects: true },
  ],
  [
    "standard with an endpoint and no private snapshot",
    "standard",
    { openai_base_url: "https://endpoint.example.test/v1" },
    { isolatedConfig: false },
  ],
  [
    "deep with an unused profile endpoint",
    "deep",
    {
      profiles: {
        unused: { openai_base_url: "https://unused.example.test/v1" },
      },
    },
    { isolatedConfig: false },
  ],
  [
    "deep with a root endpoint and runtime snapshot 4",
    "deep",
    { openai_base_url: "https://endpoint.example.test/v1" },
    { capability: 4 },
  ],
  [
    "deep with a profile endpoint and runtime snapshot 4",
    "deep",
    {
      profile: "selected",
      profiles: {
        selected: {
          model_provider: "openai",
          openai_base_url: "https://endpoint.example.test/v1",
        },
      },
    },
    { capability: 4 },
  ],
  [
    "deep with explicit OpenAI",
    "deep",
    { model_provider: "openai" },
    { reads: true },
  ],
  [
    "deep with profile-selected OpenAI",
    "deep",
    {
      profile: "selected",
      profiles: { selected: { model_provider: "openai" } },
    },
    { reads: true },
  ],
  [
    "deep with a conflicting native provider",
    "deep",
    { model_provider: "openai" },
    {
      inherited: "synthetic.system",
      reads: true,
      rejects: true,
    },
  ],
  [
    "deep with the same managed provider",
    "deep",
    { model_provider: "openai" },
    {
      inherited: "synthetic.system",
      managed: "synthetic.required",
      reads: true,
    },
  ],
  ...([true, 2, 3] as const).map(
    (capability): (typeof legacyScanCases)[number] => [
      `deep with selector snapshot ${capability}`,
      "deep",
      { model_provider: "openai" },
      {
        capability,
        inherited: "synthetic.system",
      },
    ],
  ),
  [
    "deep with a resolved profile and readable snapshot",
    "deep",
    {
      profile: "selected.profile",
      profiles: { "selected.profile": { model_provider: "openai" } },
    },
    {
      capability: true,
      inherited: "synthetic.system",
    },
  ],
];
test.each(legacyScanCases)(
  "SDK-owned passes preserve provider selection for %s scans",
  async (_scenario, mode, overrides, native) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    const plugin = join(root, "custom-plugin");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    await cp(PLUGIN_ROOT, plugin, { recursive: true });
    const manifestPath = join(plugin, ".codex-plugin", "plugin.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (native.capability === undefined) delete manifest.codexSecurity;
    else manifest.codexSecurity = { workerProviderSnapshot: native.capability };
    await writeFile(manifestPath, JSON.stringify(manifest));
    if (native.isolatedConfig === false) {
      const mcpPath = join(plugin, ".mcp.json");
      const configuration = JSON.parse(await readFile(mcpPath, "utf8"));
      const server = configuration.mcpServers["codex-security"];
      server.env_vars = server.env_vars.filter(
        (name: string) => name !== "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      );
      await writeFile(mcpPath, JSON.stringify(configuration));
    }
    const observed: Array<Record<string, unknown>> = [];
    const client = new TestClient(
      { pluginPath: plugin, codexOverrides: overrides },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-openai-key",
          OPENROUTER_API_KEY: "synthetic-gateway-key",
        },
        resolvePluginPython: async () => "/managed/python",
        runWorkbench: async (_options, args, input) =>
          args[0] === "list-scans"
            ? { scans: [] }
            : args[0] === "get-scan"
              ? { scan: { progress: { status: "running" } } }
              : mockWorkbench(args, input),
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              const environment = options.env!;
              const config = resolveCodexProfile(
                parseToml(
                  await readFile(
                    environment["CODEX_SECURITY_CONFIG_PATH"]!,
                    "utf8",
                  ),
                ) as JsonObject,
              );
              const expected = resolveCodexProfile(overrides);
              expect(config["model_provider"]).toBe(expected["model_provider"]);
              expect(expected["openai_base_url"]).toBe(
                options.config?.["openai_base_url"],
              );
              expect(config).not.toHaveProperty("openai_base_url");
              expect(
                resolveCodexProfile(options.config! as JsonObject)[
                  "model_providers"
                ],
              ).toEqual(expected["model_providers"]);
              expect(
                environment["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"],
              ).toBeUndefined();
              expect(
                JSON.stringify({
                  config: options.config,
                  overrides: options.configOverrides,
                }),
              ).not.toContain("synthetic-openai-key");
              expect(
                JSON.stringify({
                  config: options.config,
                  overrides: options.configOverrides,
                }),
              ).not.toContain("synthetic-gateway-key");
              observed.push(config);
              throw new Error("synthetic SDK-owned pass observed");
            },
          }),
        }),
      },
    );
    try {
      await expect(
        client.run(repository, {
          mode,
          ...(mode === "deep"
            ? {
                workers: 1,
                subagents: 0,
                maxDiscoveryRuns: 1,
                stopAfterConsecutiveErrors: 1,
              }
            : {}),
        }),
      ).rejects.toThrow(
        mode === "deep"
          ? "Deep Scan reached its consecutive error limit."
          : "synthetic SDK-owned pass observed",
      );
      expect(observed.length).toBeGreaterThan(0);
    } finally {
      await client.close();
    }
  },
  30_000,
);

async function createPluginProbe(root: string, report: string) {
  const plugin = join(root, "plugin");
  await cp(PLUGIN_ROOT, plugin, { recursive: true });
  const probe = join(plugin, "environment-probe.mjs");
  await writeFile(
    probe,
    `import { writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.id === undefined) continue;
  let result = {};
  if (request.method === "initialize") {
    result = { protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} }, serverInfo: { name: "synthetic-environment", version: "1" } };
  } else if (request.method === "tools/list") {
    await writeFile(process.argv[2], JSON.stringify({
      inherited: Object.fromEntries([
        "SYNTHETIC_CUSTOM_API_KEY", "SYNTHETIC_CUSTOM_HEADER",
        "SYNTHETIC_REQUIRED_KEY", "SYNTHETIC_UNUSED_KEY",
      ].map((name) => [name, process.env[name] ?? null])),
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
  "Standard native plugin tools exclude custom %s provider variables",
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
    let checkedLaunches = 0;
    const launchFailures: string[] = [];
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
        runWorkbench: async (_options, args, input) =>
          args[0] === "list-scans"
            ? { scans: [] }
            : args[0] === "get-scan"
              ? { scan: { progress: { status: "running" } } }
              : mockWorkbench(args, input),
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              try {
                expect(options.apiKey).toBe(
                  external ? undefined : "synthetic-account-key",
                );
                expect(
                  (options.config!["model_providers"] as JsonObject)[
                    providerId
                  ],
                ).toMatchObject({
                  env_key: providerKey,
                  env_http_headers: {
                    "X-Synthetic-Token": headerKey,
                  },
                });
                expect(options.env![headerKey]).toBe(
                  providerEnvironment[headerKey],
                );
                if (providerKey !== "CODEX_API_KEY")
                  expect(options.env![providerKey]).toBe(
                    external
                      ? providerEnvironment[providerKey]!.trim()
                      : providerEnvironment[providerKey],
                  );
                // Reproduce the actual SDK constructor's native configuration.
                const status = await nativeRequest(
                  {
                    ...options.env!,
                    ...(options.apiKey === undefined
                      ? {}
                      : { CODEX_API_KEY: options.apiKey }),
                  },
                  repository,
                  profileConfigOverrides(options.config as JsonObject).flatMap(
                    (value) => ["--config", value],
                  ),
                  "mcpServerStatus/list",
                  { serverName: "codex-security", detail: "toolsAndAuthOnly" },
                );
                expect(status.data).toHaveLength(1);
                expect(status.data[0].name).toBe("codex-security");
                expect(status.data[0].toolsError).toBeNull();
                expect(status.data[0].tools).toEqual(
                  expect.objectContaining({
                    synthetic_environment: expect.anything(),
                  }),
                );
                expect(JSON.parse(await readFile(report, "utf8"))).toEqual({
                  inherited: {
                    SYNTHETIC_CUSTOM_API_KEY: null,
                    SYNTHETIC_CUSTOM_HEADER: null,
                    SYNTHETIC_REQUIRED_KEY: null,
                    SYNTHETIC_UNUSED_KEY: null,
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
              } catch (error) {
                launchFailures.push(
                  error instanceof Error ? error.message : String(error),
                );
                throw error;
              }
              checkedLaunches++;
              throw new Error("synthetic native plugin environment checked");
            },
          }),
        }),
      },
    );
    try {
      await expect(
        client.run(repository, { mode: "standard" }),
      ).rejects.toThrow("synthetic native plugin environment checked");
      expect(launchFailures).toEqual([]);
      expect(checkedLaunches).toBeGreaterThan(0);
    } finally {
      await client.close();
    }
  },
  30_000,
);
