import { cp } from "node:fs/promises";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  preparedRuntime,
  codexFactory,
  completedEvents,
} from "./support/api-events.js";
import { afterEach, expect, test } from "bun:test";
import { stringify as stringifyToml } from "smol-toml";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { executablePathForSpawn, resolveCodexCommand } from "../src/runtime.js";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
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
