import { runWorkbench } from "../src/runtime.js";
import {
  preparedRuntime,
  codexFactory,
  completedEvents,
} from "./support/api-events.js";
import { afterEach, expect, test } from "bun:test";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { cp } from "node:fs/promises";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { executablePathForSpawn, resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const nativeTestTimeoutMs = Number(
  process.env["CODEX_SECURITY_TEST_TIMEOUT_MS"] ?? 30_000,
);
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
  // Keep the child deadline inside the CI runner's per-test budget.
  const probeTimeoutMs = nativeTestTimeoutMs / 2;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    // A descendant may retain stdout, so EOF cannot be the signal to stop reading.
    lines.close();
  }, probeTimeoutMs);
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
    const reason = timedOut
      ? `timed out after ${probeTimeoutMs}ms`
      : "closed before replying";
    throw new Error(`Native ${method} probe ${reason}: ${stderr}`);
  } finally {
    clearTimeout(timer);
    lines.close();
    // Bun on Windows can keep these pipes open after the app-server process exits.
    child.stdout.destroy();
    child.stderr.destroy();
    child.kill();
    await closed;
  }
}

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

test("native override tables retain inherited features and MCP servers", async () => {
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
      await mkdir(scan, { mode: 0o700 });
      await mkdir(sourceHome, { mode: 0o700 });
      await writeFile(join(repository, "source.ts"), "export {};\n");
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
          prepareOutputDir: async (directory) => {
            const path = directory ?? scan;
            await mkdir(path, { recursive: true, mode: 0o700 });
            return path;
          },
          repositoryRevision: async () => "deadbeef",
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
                  const activeProfile = options.nativeProfile ?? "review";
                  const activeConfig = parseToml(
                    await readFile(
                      join(
                        environment["CODEX_HOME"]!,
                        activeProfile + ".config.toml",
                      ),
                      "utf8",
                    ),
                  );
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
        await expect(
          client.run(repository, { mode, signal: controller.signal }),
        ).rejects.toThrow();
        expect(controller.signal.reason?.message).toBe(
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
