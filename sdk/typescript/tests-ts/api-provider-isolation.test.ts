import { afterEach, expect, spyOn, test } from "bun:test";
import { build } from "esbuild";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import * as childProcess from "node:child_process";
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

test.each(["root", "profile override", "profile only"] as const)(
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

    const workerRuntimeSettings = await loadWorkerSettings(root);
    let nativeProbe = Promise.resolve();

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
                features: selection === "root" ? featureOverrides : {},
                ...(selection === "profile only"
                  ? {}
                  : {
                      model_providers: {
                        openrouter:
                          selection === "root"
                            ? provider
                            : {
                                ...provider,
                                env_key: "SYNTHETIC_UNUSED_KEY",
                              },
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
                      features: featureOverrides,
                      web_search: webSearch,
                    });
                    expect(options.config!["web_search"]).toBe(webSearch);
                    expect(options.config!["features"]).toMatchObject(
                      featureOverrides,
                    );
                    expect(
                      (workerSnapshot["worker_runtime"] as JsonObject)[
                        "environment"
                      ],
                    ).toEqual(providerEnvironment);
                    if (process.platform !== "win32") {
                      expect(
                        (await stat(workerSnapshotPath)).mode & 0o777,
                      ).toBe(0o600);
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
                    // Native SQLite probes share a home; keep the scans concurrent.
                    const probe = nativeProbe.then(() =>
                      effectiveProvider(
                        environment,
                        repository,
                        profileConfigOverrides(settings.config),
                        settings.nativeProfile,
                      ),
                    );
                    nativeProbe = probe.then(
                      () => undefined,
                      () => undefined,
                    );
                    const actual = await probe;
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
  },
  30_000,
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
    "deep with a filtered profile and readable snapshot",
    "deep",
    {
      profile: "selected.profile",
      profiles: { "selected.profile": { model_provider: "openai" } },
    },
    {
      capability: true,
      inherited: "synthetic.system",
      reads: true,
      rejects: true,
    },
  ],
];
test.each(legacyScanCases)(
  "checks effective worker compatibility for %s scans",
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
    const callsPath = join(root, "config-reads.jsonl");
    const fakeNative = join(root, "native-config.mjs");
    await writeFile(
      fakeNative,
      `
      import { appendFileSync, existsSync } from "node:fs";
      import { join } from "node:path";
      import { createInterface } from "node:readline";
      const args = process.argv.slice(2);
      const selected = args.some((arg) => arg === 'model_provider="openai"') ? "openai" : ${JSON.stringify(native.inherited ?? "openai")};
      for await (const line of createInterface({ input: process.stdin })) {
        const request = JSON.parse(line);
        if (request.id === undefined) continue;
        if (request.method === "config/read") appendFileSync(${JSON.stringify(callsPath)}, JSON.stringify({
          args, cwd: process.cwd(), params: request.params,
          home: process.env.CODEX_HOME, key: process.env.CODEX_API_KEY,
          openai: process.env.OPENAI_API_KEY,
          lockHeld: existsSync(join(process.env.CODEX_HOME, ".codex-security-preflight", ".codex-security-scan.lock", "owner.json")),
        }) + "\\n");
        console.log(JSON.stringify({ id: request.id, result: request.method === "config/read"
          ? { config: { model_provider: ${JSON.stringify(native.managed)} ?? selected } } : {} }));
      }
    `,
    );
    const command = resolveCodexCommand({});
    const commandArgs = ["-c", "features.api_key_model_discovery=false"];
    const originalSpawn = childProcess.spawn;
    const spawnSpy = spyOn(childProcess, "spawn").mockImplementation(((
      ...input: Parameters<typeof originalSpawn>
    ) => {
      const [, args, options] = input;
      return args?.includes("app-server")
        ? originalSpawn(process.execPath, [fakeNative, ...args], options ?? {})
        : originalSpawn(...input);
    }) as typeof originalSpawn);
    let launched = false;
    const client = new TestClient(
      { pluginPath: plugin, codexOverrides: overrides },
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          OPENAI_API_KEY: "synthetic-openai-key",
          OPENROUTER_API_KEY: "synthetic-gateway-key",
        },
        resolveCodexCommand: () => ({ ...command, args: commandArgs }),
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => {
          launched = true;
          return {
            startThread: () => ({
              id: null,
              async runStreamed() {
                const config = parseToml(
                  await readFile(
                    options.env!["CODEX_SECURITY_CONFIG_PATH"]!,
                    "utf8",
                  ),
                );
                expect(
                  resolveCodexProfile(config as JsonObject)["model_provider"],
                ).toBe(resolveCodexProfile(overrides)["model_provider"]);
                if (native.capability === 2 || native.capability === 3) {
                  const worker = parseToml(
                    await readFile(
                      options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]!,
                      "utf8",
                    ),
                  );
                  expect(
                    (worker["worker_runtime"] as JsonObject)["model_provider"],
                  ).toBe("openai");
                }
                expect(
                  existsSync(
                    join(
                      options.env!["CODEX_HOME"]!,
                      ".codex-security-preflight",
                      ".codex-security-scan.lock",
                    ),
                  ),
                ).toBe(false);
                throw new Error("synthetic compatible scan started");
              },
            }),
          };
        },
      },
    );
    try {
      await expect(client.run(repository, { mode })).rejects.toThrow(
        native.rejects
          ? "Update the custom plugin or use the bundled plugin"
          : "synthetic compatible scan started",
      );
      expect(launched).toBe(!native.rejects);
      const calls = existsSync(callsPath)
        ? (await readFile(callsPath, "utf8"))
            .trim()
            .split("\n")
            .map((line) => JSON.parse(line))
        : [];
      expect(calls).toHaveLength(native.reads ? 2 : 0);
      for (const call of calls) {
        expect(call.cwd).toBe(scan);
        expect(call.params).toEqual({ cwd: scan, includeLayers: false });
        expect(call.home).toBe(join(root, "state", "codex-home"));
        expect(call.key).toBe("synthetic-openai-key");
        expect(call.openai).toBeUndefined();
        expect(call.lockHeld).toBe(true);
        expect(call.args.slice(0, commandArgs.length)).toEqual(commandArgs);
        expect(JSON.stringify(call.args)).not.toContain("synthetic-openai-key");
      }
      if (native.reads) {
        expect(calls[0].args).not.toContain('model_provider="openai"');
        expect(calls[1].args).toContain('model_provider="openai"');
      }
    } finally {
      await client.close();
      spawnSpy.mockRestore();
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

test.each(["SYNTHETIC_CUSTOM_API_KEY", "CODEX_API_KEY"])(
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
    const providerEnvironment = {
      [providerKey]: " synthetic-custom-key ",
      SYNTHETIC_CUSTOM_HEADER: " synthetic-custom-header ",
      SYNTHETIC_REQUIRED_KEY: "synthetic-required-key",
    };
    const client = new TestClient(
      {
        pluginPath: plugin,
        codexOverrides: {
          model_provider: "synthetic.gateway",
          model_providers: {
            "synthetic.gateway": {
              name: "Synthetic gateway",
              wire_api: "responses",
              base_url: "https://provider.example.test/v1",
              env_key: providerKey,
              env_http_headers: {
                "X-Synthetic-Token": "SYNTHETIC_CUSTOM_HEADER",
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
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              expect(options.apiKey).toBe("synthetic-account-key");
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
            },
          }),
        }),
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
  30_000,
);
