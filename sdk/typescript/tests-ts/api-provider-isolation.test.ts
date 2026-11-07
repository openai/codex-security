import { runWorkbench } from "../src/runtime.js";
import {
  codexFactory,
  completedEvents,
  effectiveCodexConfiguration,
  preparedRuntime,
} from "./support/api-events.js";
import { nativeRequest } from "./support/native-request.js";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import {
  OPENROUTER_CODEX_PROVIDER,
  resolveCodexProfile,
  type JsonObject,
} from "../src/config.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { existsSync } from "node:fs";
import { cp, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createProviderProfile } from "../src/provider-profile.js";
import { copyCredentialTestPlugin, PLUGIN_ROOT } from "./plugin-root.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { TestClient, mockWorkbench } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const nativeTestTimeoutMs = Number(
  process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"] ?? 30_000,
);
const { temporaryDirectory, cleanup } = createApiTestFixtures();

afterEach(cleanup);

async function readProviderProfile(home: string, name: string) {
  return parseToml(await readFile(join(home, `${name}.config.toml`), "utf8"));
}

async function effectiveProvider(
  environment: Record<string, string>,
  cwd: string,
  overrides: string[],
  nativeProfile?: string,
) {
  if (nativeProfile !== undefined) {
    const config = await readProviderProfile(
      environment["CODEX_HOME"]!,
      nativeProfile,
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
                    const config = effectiveCodexConfiguration(options);
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
                      expect(environment[name]).toBe(
                        name === provider.env_key ? value.trim() : value,
                      );
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

const fileProviderKeyCases = [
  ["gateway", "custom only", "SYNTHETIC_GATEWAY_TOKEN"],
  ["gateway", "account-named primary", "OPENAI_API_KEY"],
  ["gateway", "declared external header", "SYNTHETIC_GATEWAY_TOKEN"],
  ["gateway", "declared Codex account header", "SYNTHETIC_GATEWAY_TOKEN"],
  ["gateway", "declared OpenAI account header", "SYNTHETIC_GATEWAY_TOKEN"],
  ["gateway", "missing custom primary", "SYNTHETIC_GATEWAY_TOKEN"],
  ["openrouter", "default", "OPENROUTER_API_KEY"],
  ["openrouter", "custom only", "SYNTHETIC_CUSTOM_API_KEY"],
  ["openrouter", "canonical header", "SYNTHETIC_CUSTOM_API_KEY"],
  ["openrouter", "missing custom primary", "SYNTHETIC_CUSTOM_API_KEY"],
  ["fireworks", "default", "FIREWORKS_API_KEY"],
  ["fireworks", "custom only", "SYNTHETIC_CUSTOM_API_KEY"],
  ["fireworks", "canonical header", "SYNTHETIC_CUSTOM_API_KEY"],
  ["fireworks", "missing custom primary", "SYNTHETIC_CUSTOM_API_KEY"],
  ["openrouter", "custom Codex key", "CODEX_API_KEY"],
  ["openrouter", "other external key", "FIREWORKS_API_KEY"],
] as const;

const gatewayHeaders = new Map<string, string>([
  ["declared external header", "FIREWORKS_API_KEY"],
  ["declared Codex account header", "CODEX_API_KEY"],
  ["declared OpenAI account header", "OPENAI_API_KEY"],
]);

test.each(["openrouter", "fireworks"] as const)(
  "native file profile accepts the %s custom environment key",
  async (providerId) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    await mkdir(home, { mode: 0o700 });
    await writeFile(
      join(home, "review.config.toml"),
      stringifyToml({
        model_provider: providerId,
        model: "synthetic-model",
        model_providers: {
          [providerId]: {
            name: "Synthetic provider",
            wire_api: "responses",
            base_url: "https://provider.example.test/v1",
            env_key: "SYNTHETIC_CUSTOM_API_KEY",
          },
        },
      }),
    );
    const selected = await effectiveProvider(
      { CODEX_HOME: home, SYNTHETIC_CUSTOM_API_KEY: "synthetic-custom-key" },
      root,
      [],
      "review",
    );
    expect(selected).toMatchObject({ env_key: "SYNTHETIC_CUSTOM_API_KEY" });
  },
  nativeTestTimeoutMs,
);

for (const mode of ["standard", "deep"] as const) {
  test.each(fileProviderKeyCases)(
    `file provider %s preserves %s authentication for ${mode} preflight and children`,
    async (providerId, _selection, providerKey) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const scan = join(root, "scan");
      const sourceHome = join(root, "source-home");
      await mkdir(repository);
      await writeFile(join(repository, "source.ts"), "export {};\n");
      await mkdir(scan, { mode: 0o700 });
      await mkdir(sourceHome, { mode: 0o700 });
      const canonicalKey = `${providerId.toUpperCase()}_API_KEY`;
      const gatewayHeader = gatewayHeaders.get(_selection);
      const headerKey =
        gatewayHeader ??
        (_selection === "canonical header" ? canonicalKey : undefined);
      const headerEnvironment =
        headerKey || _selection === "missing custom primary"
          ? { [headerKey ?? canonicalKey]: " synthetic-header-key " }
          : {};
      const inactiveKey = gatewayHeader
        ? "CHEAPER_INFERENCE_API_KEY"
        : "INACTIVE_GATEWAY_TOKEN";
      const inactiveEnvironment = gatewayHeader
        ? { [inactiveKey]: "synthetic-inactive-key" }
        : {};
      const inheritedEnvironment: Record<string, string> = {
        ...(_selection === "custom Codex key" ||
        _selection === "other external key" ||
        gatewayHeader
          ? Object.fromEntries(
              [
                "OPENAI_API_KEY",
                "CODEX_API_KEY",
                "OPENROUTER_API_KEY",
                "FIREWORKS_API_KEY",
              ]
                .filter((name) => name !== providerKey)
                .map((name) => [name, "synthetic-unrelated-key"]),
            )
          : {}),
        ...headerEnvironment,
        ...inactiveEnvironment,
        ...(_selection === "missing custom primary"
          ? {
              OPENAI_API_KEY: "synthetic-unrelated-account",
              INACTIVE_GATEWAY_TOKEN: "synthetic-unrelated-provider",
            }
          : { [providerKey]: "synthetic-file-key" }),
      };
      const provider = {
        name: "Synthetic file provider",
        wire_api: "responses",
        base_url: "https://provider.example.test/v1",
        env_key: providerKey,
        ...(gatewayHeader === "OPENAI_API_KEY"
          ? { requires_openai_auth: true }
          : {}),
        ...(headerKey
          ? { env_http_headers: { "X-Synthetic-Token": headerKey } }
          : {}),
      };
      const original = stringifyToml({
        model: "synthetic-model",
        model_provider: providerId,
        model_providers: {
          [providerId]: provider,
          inactive: { ...provider, env_key: inactiveKey },
        },
        features: { shell_tool: false, unified_exec: false },
      });
      await writeFile(join(sourceHome, "review.config.toml"), original);
      const controller = new AbortController();
      let launched = false;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT, codexOverrides: { profile: "review" } },
        {
          environment: {
            CODEX_HOME: sourceHome,
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
            ...inheritedEnvironment,
          },
          resolvePluginPython: async () =>
            Bun.which("python3") ?? Bun.which("python")!,
          prepareOutputDir: async (directory) => {
            const path = directory ?? scan;
            await mkdir(path, { recursive: true, mode: 0o700 });
            return path;
          },
          repositoryRevision: async () => "deadbeef",
          runWorkbench: async (options, args, input) => {
            if (args[0] === "register-cli-scan") {
              expect(options.environment).not.toHaveProperty(providerKey);
              if (gatewayHeader) {
                expect(options.environment).not.toHaveProperty(gatewayHeader);
                expect(options.environment).not.toHaveProperty(inactiveKey);
              }
            }
            return runWorkbench(options, args, input);
          },
          createCodex: (options) => {
            launched = true;
            return {
              startThread: () => ({
                id: null,
                async runStreamed() {
                  expect(options.apiKey).toBeUndefined();
                  const environment = options.env!;
                  expect(environment[providerKey]).toBe("synthetic-file-key");
                  for (const name of [
                    "OPENAI_API_KEY",
                    "CODEX_API_KEY",
                    "OPENROUTER_API_KEY",
                    "FIREWORKS_API_KEY",
                    "CHEAPER_INFERENCE_API_KEY",
                  ]) {
                    expect(environment[name]).toBe(
                      name === providerKey ||
                        name === canonicalKey ||
                        name === headerKey ||
                        name === inactiveKey
                        ? inheritedEnvironment[name]
                        : undefined,
                    );
                  }
                  const activeConfig = effectiveCodexConfiguration(options);
                  expect(activeConfig["model_providers"]).toMatchObject({
                    [providerId]: provider,
                  });
                  for (const text of [
                    await readFile(
                      environment["CODEX_SECURITY_CONFIG_PATH"]!,
                      "utf8",
                    ),
                    JSON.stringify({
                      config: options.config,
                      overrides: options.configOverrides,
                    }),
                  ]) {
                    expect(text).not.toContain("synthetic-file-key");
                    expect(text).not.toContain("synthetic-header-key");
                    expect(text).not.toContain("synthetic-inactive-key");
                  }
                  controller.abort(
                    new Error("synthetic file provider child checked"),
                  );
                  throw controller.signal.reason;
                },
              }),
            };
          },
        },
      );
      try {
        const preflight = await client.preflight(repository, { mode });
        expect(preflight.authentication).toEqual({
          method: "api_key",
          source: providerKey,
          verified: false,
        });
        expect(preflight.modelProvider).toBe(providerId);
        if (
          providerId === "gateway" &&
          (_selection === "custom only" ||
            _selection === "account-named primary")
        ) {
          const request = { mode, auth: "chatgpt" as const };
          const guidance = `ChatGPT authentication cannot use the gateway provider's required ${providerKey}`;
          await expect(client.preflight(repository, request)).rejects.toThrow(
            guidance,
          );
          await expect(client.run(repository, request)).rejects.toThrow(
            guidance,
          );
          expect(launched).toBe(false);
        }
        if (_selection === "missing custom primary") {
          await expect(
            client.preflight(repository, { mode, auth: "api-key" }),
          ).rejects.toThrow(providerKey);
          await expect(client.run(repository, { mode })).rejects.toThrow(
            providerKey,
          );
          expect(launched).toBe(false);
          return;
        }
        const failure = await client
          .run(repository, { mode, signal: controller.signal })
          .catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(Error);
        expect(controller.signal.reason?.message, String(failure)).toBe(
          "synthetic file provider child checked",
        );
        expect(launched).toBe(true);
        expect(
          await readFile(join(sourceHome, "review.config.toml"), "utf8"),
        ).toBe(original);
      } finally {
        await client.close();
      }
    },
    Number(process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"] ?? 30_000),
  );
}

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
    const providerEnvironment: Record<string, string> = {
      [providerKey]: external
        ? " synthetic-custom-key\n"
        : " synthetic-custom-key ",
      [headerKey]: " synthetic-custom-header ",
      SYNTHETIC_REQUIRED_KEY: "synthetic-required-key",
    };
    if (process.platform === "win32")
      providerEnvironment["SYNTHETIC_CUSTOM_HEADER"] =
        " synthetic-child-header ";
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
                ...(!external ? { "X-Synthetic-Primary": providerKey } : {}),
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
                expect(options.apiKey).toBeUndefined();
                expect(options.env!["OPENAI_API_KEY"]).toBeUndefined();
                const selectedKey = external
                  ? providerEnvironment[providerKey]!.trim()
                  : providerEnvironment[providerKey];
                expect(options.env![providerKey]).toBe(selectedKey);
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
                // Windows child processes use the first lexicographic case variant.
                expect(options.env![headerKey]).toBe(
                  providerEnvironment["SYNTHETIC_CUSTOM_HEADER"],
                );
                // Reproduce the actual SDK constructor's native configuration.
                const status = await nativeRequest(
                  options.env!,
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
      isolatedConfig?: boolean;
    },
  ]
> = [
  ...legacyProviders.map(
    ([name, overrides]): (typeof legacyScanCases)[number] => [
      `deep with incompatible ${name}`,
      "deep",
      overrides,
      { capability: 3 },
    ],
  ),
  ["standard", "standard", {}, {}],
  ["deep", "deep", {}, {}],
  ["standard with explicit provider", "standard", legacyProviders[0]![1], {}],
  [
    "deep with a root endpoint and no private snapshot",
    "deep",
    { openai_base_url: "https://endpoint.example.test/v1" },
    { isolatedConfig: false },
  ],
  [
    "deep with an OpenAI endpoint and readable snapshot",
    "deep",
    {
      model_provider: "openai",
      openai_base_url: "https://endpoint.example.test/v1",
    },
    { capability: true },
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
    { capability: 2 },
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
    { capability: 3 },
  ],
  [
    "deep with an endpoint fallback and no private snapshot path",
    "deep",
    {
      openai_base_url: "https://endpoint.example.test/v1",
      profile: "selected",
      profiles: { selected: { model_provider: "openai" } },
    },
    { capability: 4, isolatedConfig: false },
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
  ["deep with explicit OpenAI", "deep", { model_provider: "openai" }, {}],
  [
    "deep with profile-selected OpenAI",
    "deep",
    {
      profile: "selected",
      profiles: { selected: { model_provider: "openai" } },
    },
    {},
  ],
  ...([true, 2, 3] as const).map(
    (capability): (typeof legacyScanCases)[number] => [
      `deep with selector snapshot ${capability}`,
      "deep",
      { model_provider: "openai" },
      {
        capability,
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

test.each([
  ["root", "openai"],
  ["profile", "openai"],
  ["root", "openrouter"],
  ["profile", "openrouter"],
] as const)(
  "Deep workers, rerun and resume inherit the %s %s endpoint",
  async (selection, provider) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    await mkdir(repository);
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    await mkdir(scan, { mode: 0o700 });
    const endpoint = "https://endpoint.example.test/v1";
    const routing: JsonObject =
      provider === "openai"
        ? {
            openai_base_url: endpoint,
            chatgpt_base_url: "https://account.example.test",
          }
        : {
            model_provider: provider,
            model_providers: {
              [provider]: {
                ...OPENROUTER_CODEX_PROVIDER,
                base_url: endpoint,
                query_params: { version: "preview" },
              },
            },
          };
    const environment = {
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-openai-key",
      OPENROUTER_API_KEY: "synthetic-openrouter-key",
    };
    let recipe: JsonObject | undefined;
    const workerRoutes: JsonObject[] = [];
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides:
          selection === "root"
            ? routing
            : {
                openai_base_url: "https://unused.example.test/v1",
                profile: "selected",
                profiles: { selected: routing },
              },
      },
      {
        environment,
        runWorkbench: async (_options, args, input) => {
          if (args[0] === "list-scans") return { scans: [] };
          if (args[0] === "get-scan")
            return { scan: { progress: { status: "running" } } };
          if (
            args[0] === "register-cli-scan" &&
            !args.includes("--parent-scan-id")
          )
            recipe = JSON.parse(input!).recipe;
          return mockWorkbench(args, input);
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              workerRoutes.push(effectiveCodexConfiguration(options));
              throw new ScanTransportClosedError(
                "synthetic endpoint inherited",
              );
            },
          }),
        }),
      },
    );
    try {
      await expect(
        client.run(repository, {
          mode: "deep",
          outputDir: scan,
          workers: 1,
          maxDiscoveryRuns: 1,
        }),
      ).rejects.toThrow("synthetic endpoint inherited");
      expect(workerRoutes).toHaveLength(1);
      expect(workerRoutes[0]).toMatchObject(routing);
      expect(recipe).toMatchObject({
        mode: "deep",
        providerProfile: { home: "managed" },
      });
      expect(JSON.stringify(recipe)).not.toContain(endpoint);
      for (const command of ["rerun", "resume"]) {
        const { runCli, stderr } = createCliTest(main);
        let restored: JsonObject | undefined;
        const status = await runCli(
          ["scans", command, "saved", "--json"],
          dependencies({
            currentDirectory: repository,
            environment,
            onWorkbench: () => ({
              scanId: "saved",
              scanDir: scan,
              recipe: recipe!,
            }),
            onConfig: ({ codexOverrides }) => {
              restored = resolveCodexProfile(codexOverrides!);
            },
          }),
        );
        expect(status, stderr.text()).toBe(0);
        expect(restored).toMatchObject(routing);
      }
    } finally {
      await client.close();
    }
  },
  nativeTestTimeoutMs,
);

async function createPluginProbe(root: string, report: string) {
  const plugin = await copyCredentialTestPlugin(root);
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
