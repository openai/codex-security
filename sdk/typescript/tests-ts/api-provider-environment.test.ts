import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath, pathToFileURL } from "node:url";
import { executablePathForSpawn, resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function createPluginProbe(root: string, report: string) {
  const plugin = join(root, "plugin");
  await cp(PLUGIN_ROOT, plugin, { recursive: true });
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
  await writeFile(
    join(plugin, "worker-settings.mjs"),
    bundled.outputFiles[0]!.contents,
  );
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

async function nativePluginStatus(
  environment: Record<string, string>,
  cwd: string,
) {
  const child = spawn(
    executablePathForSpawn(resolveCodexCommand({}).command),
    ["app-server", "--stdio"],
    { cwd, env: environment, windowsHide: true },
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
        clientInfo: { name: "synthetic_provider_environment", version: "1" },
        capabilities: { experimentalApi: true },
      },
    });
    for await (const line of lines) {
      const response = JSON.parse(line);
      if (response.error) throw new Error(JSON.stringify(response.error));
      if (response.id === 1) {
        send({ method: "initialized", params: {} });
        // Enumerating MCP tools starts the actual native plugin child without
        // starting a thread or making a model request.
        send({
          id: 2,
          method: "mcpServerStatus/list",
          params: { serverName: "codex-security", detail: "toolsAndAuthOnly" },
        });
      }
      if (response.id === 2) return response.result;
    }
    throw new Error(`Native plugin probe did not finish: ${stderr}`);
  } finally {
    clearTimeout(timer);
    lines.close();
    child.kill();
    await closed;
  }
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
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              expect(options.apiKey).toBe(
                external ? undefined : "synthetic-account-key",
              );
              const status = await nativePluginStatus(
                {
                  ...options.env!,
                  ...(options.apiKey === undefined
                    ? {}
                    : { CODEX_API_KEY: options.apiKey }),
                },
                repository,
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
                  ...(external
                    ? { [providerKey]: "synthetic-custom-key" }
                    : {}),
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
