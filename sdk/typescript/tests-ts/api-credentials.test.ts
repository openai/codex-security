import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { initialCredentialsAvailable } from "../src/api.js";
import {
  acquireCodexSecurityCredentialHomeLock,
  resolveCodexCommand,
  setCodexSecurityCredentialLogout,
} from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { shellEnvironmentReference, TestClient } from "./support/api-client.js";
import {
  completedEvents,
  copyPluginVariant,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();
afterEach(cleanup);

describe("CodexSecurity orchestration", () => {
  test("reused managed clients restore their selected plugin before preparation and native startup", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const state = join(root, "state");
    await mkdir(repository);
    const selections = await Promise.all(
      ["selected-a", "selected-b"].map((name) => copyPluginVariant(root, name)),
    );
    const prepared: string[] = [];
    const launched: string[] = [];
    let outputs = 0;
    const clients = selections.map(
      (pluginPath) =>
        new TestClient(
          { pluginPath },
          {
            environment: {
              CODEX_SECURITY_STATE_DIR: state,
              OPENAI_API_KEY: "synthetic-plugin-selection-key",
            },
            resolvePluginPython: async () => {
              const config = parseToml(
                await readFile(
                  join(state, "codex-home", "config.toml"),
                  "utf8",
                ),
              );
              const marketplace = Object.values(
                config["marketplaces"] as Record<string, { source: string }>,
              )[0]!;
              const record = JSON.parse(
                await readFile(
                  join(marketplace.source, "installed-plugin.json"),
                  "utf8",
                ),
              );
              prepared.push(record.pluginRoot);
              return process.execPath;
            },
            prepareOutputDir: async () => {
              const directory = join(root, `scan-${++outputs}`);
              await mkdir(directory, { mode: 0o700 });
              return directory;
            },
            repositoryRevision: async () => "deadbeef",
            createCodex: (options) => ({
              startThread: () => ({
                id: null,
                async runStreamed() {
                  const servers = JSON.parse(
                    execFileSync(
                      resolveCodexCommand({}).command,
                      ["mcp", "list", "--json"],
                      {
                        env: options.env,
                        cwd: root,
                        encoding: "utf8",
                      },
                    ),
                  ) as { name: string; transport: { args: string[] } }[];
                  launched.push(
                    servers.find(({ name }) => name === "synthetic-plugin")!
                      .transport.args[0]!,
                  );
                  throw new Error("synthetic plugin selection observed");
                },
              }),
            }),
          },
        ),
    );
    try {
      for (const client of [clients[0]!, clients[1]!, clients[0]!])
        await expect(client.run(repository)).rejects.toThrow(
          "synthetic plugin selection observed",
        );
      expect(prepared).toEqual([
        selections[0]!,
        selections[1]!,
        selections[0]!,
      ]);
      expect(launched).toEqual(["selected-a", "selected-b", "selected-a"]);
    } finally {
      await Promise.all(clients.map((client) => client.close()));
    }
  });

  test.each(["direct", "profile"])(
    "runs native command authentication without importing credentials (%s)",
    async (selection) => {
      const profile = selection === "profile";
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const home = join(root, "model-home");
      const state = join(root, "state");
      const scanDir = join(root, "scan");
      await mkdir(repository);
      await mkdir(home);
      await mkdir(scanDir, { mode: 0o700 });
      const runtimeHome = join(state, "codex-home");
      if (profile) await mkdir(runtimeHome, { recursive: true, mode: 0o700 });
      await writeFile(join(home, "auth.json"), '{"auth_mode":"chatgpt"}\n');
      const auth = {
        command: "./synthetic-auth",
        args: ["token"],
        refresh_interval_ms: 1000,
        ...(profile ? { cwd: "helpers" } : {}),
      };
      const overrides = {
        ...(profile
          ? {
              profile: "review",
              profiles: { review: { model_provider: "synthetic.provider" } },
            }
          : { model_provider: "synthetic.provider" }),
        model_providers: {
          "synthetic.provider": {
            name: "Synthetic",
            base_url: "https://provider.example/v1",
            wire_api: "responses",
            auth,
          },
        },
      };
      let captured: CodexOptions | undefined;
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT, codexOverrides: overrides },
        {
          environment: {
            CODEX_HOME: relative(process.cwd(), home),
            CODEX_SECURITY_STATE_DIR: state,
            ...(profile
              ? {
                  OPENAI_API_KEY: "synthetic-ambient-key",
                  CODEX_API_KEY: "synthetic-other-key",
                }
              : {}),
          },
          resolvePluginPython: async () => "/managed/python",
          ...(profile
            ? {
                prepareRuntime: async () => ({
                  ...preparedRuntime(runtimeHome),
                  credentialsAvailable: false,
                }),
              }
            : {}),
          prepareOutputDir: async () => scanDir,
          repositoryRevision: async () => "deadbeef",
          createCodex: (options) => {
            captured = options;
            return {
              startThread: () => ({
                id: null,
                async runStreamed() {
                  throw new Error("synthetic command-auth scan started");
                },
              }),
            };
          },
        },
      );
      try {
        const preflight = await client.preflight(repository);
        expect(preflight.authentication).toEqual({
          method: "command",
          verified: false,
        });
        expect(JSON.stringify(preflight)).not.toContain("synthetic-auth");
        await expect(client.run(repository)).rejects.toThrow(
          "synthetic command-auth scan started",
        );
        expect(captured?.apiKey).toBeUndefined();
        expect(captured?.env).not.toHaveProperty("OPENAI_API_KEY");
        expect(captured?.env).not.toHaveProperty("CODEX_API_KEY");
        expect(captured?.env?.["CODEX_HOME"]).toBe(join(state, "codex-home"));
        const provider = {
          ...overrides.model_providers["synthetic.provider"],
          auth: { ...auth, cwd: profile ? join(home, "helpers") : home },
        };
        expect(captured!.config).toMatchObject({
          model_provider: "synthetic.provider",
          model_providers: { "synthetic.provider": provider },
        });
        expect(captured!.config).not.toHaveProperty("profile");
        expect(captured!.config).not.toHaveProperty("profiles");
        if (!profile) {
          const saved = parseToml(
            await readFile(join(runtimeHome, "config.toml"), "utf8"),
          );
          expect(saved["model_providers"]).toEqual({
            "synthetic.provider": provider,
          });
        }
        expect(existsSync(join(state, "codex-home", "auth.json"))).toBe(false);
      } finally {
        await client.close();
      }
    },
  );

  test("keeps a private preflight snapshot isolated from persistent credentials", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const ambientHome = join(root, "ambient-codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository, { mode: 0o700 });
    await mkdir(ambientHome, { mode: 0o700 });
    await mkdir(scanDir, { mode: 0o700 });
    await writeFile(join(ambientHome, "auth.json"), "{}\n");
    const interpreter =
      process.env["PYTHON"] ??
      Bun.which("python") ??
      Bun.which("py") ??
      Bun.which("python3");
    expect(interpreter).not.toBeNull();
    let capturedConfigPath: string | undefined;
    let capturedCodexHome: string | undefined;
    const unrelatedProjects = Object.fromEntries(
      Array.from({ length: 256 }, (_, index) => [
        join(root, `unrelated-project-${index}`),
        { trust_level: "untrusted" },
      ]),
    );
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: {
          approval_policy: "never",
          features: { goals: true },
          projects: {
            ...unrelatedProjects,
            [repository]: { trust_level: "trusted" },
          },
          mcp_servers: {
            private: {
              command: "echo",
              env: { PRIVATE_TOKEN: "RUNTIME_MCP_SECRET" },
            },
          },
          shell_environment_policy: {
            set: { PRIVATE_TOKEN: "RUNTIME_SHELL_SECRET" },
          },
          responses_api_metadata: {
            request_trace: "preserve-configured-metadata",
          },
        },
      },
      {
        environment: { CODEX_HOME: ambientHome },
        resolvePluginPython: async () => interpreter!,
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options: CodexOptions) => ({
          startThread: () => ({
            id: null,
            async runStreamed(input: string) {
              const configPath = options.env?.["CODEX_SECURITY_CONFIG_PATH"];
              const codexHome = options.env?.["CODEX_HOME"];
              expect(typeof configPath).toBe("string");
              expect(typeof codexHome).toBe("string");
              capturedConfigPath = configPath;
              capturedCodexHome = codexHome;
              expect(configPath!.startsWith(`${codexHome!}/`)).toBe(false);
              expect(
                parseToml(
                  await readFile(join(codexHome!, "config.toml"), "utf8"),
                ),
              ).toMatchObject({
                approval_policy: "never",
                permissions: {
                  codex_security_scan: {
                    filesystem: {
                      ":root": "read",
                      ":workspace_roots": "write",
                      [join(
                        ambientHome,
                        "state",
                        "plugins",
                        "codex-security",
                        "codex-home",
                      )]: "read",
                    },
                  },
                },
              });
              expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe("sdk");
              expect(options.config).toHaveProperty("projects");
              expect(options.config).toHaveProperty(
                "permissions.codex_security_scan",
              );
              expect(options.config).toMatchObject({
                default_permissions: "codex_security_scan",
                allow_login_shell: false,
                model_reasoning_summary: "detailed",
                show_raw_agent_reasoning: true,
                windows: { sandbox: "unelevated" },
                mcp_servers: {
                  private: {
                    command: "echo",
                    env: { PRIVATE_TOKEN: "RUNTIME_MCP_SECRET" },
                  },
                },
                shell_environment_policy: {
                  set: { PRIVATE_TOKEN: "RUNTIME_SHELL_SECRET" },
                },
                responses_api_metadata: {
                  request_trace: "preserve-configured-metadata",
                  codex_security_surface: "sdk",
                },
              });
              if (process.platform !== "win32") {
                expect((await stat(configPath!)).mode & 0o777).toBe(0o600);
              }
              const serialized = await readFile(configPath!, "utf8");
              expect(serialized).not.toContain("RUNTIME_MCP_SECRET");
              expect(serialized).not.toContain("RUNTIME_SHELL_SECRET");
              expect(serialized).not.toContain("mcp_servers");
              expect(serialized).not.toContain("shell_environment_policy");
              expect(parseToml(serialized)).toMatchObject({
                projects: {
                  [repository]: { trust_level: "trusted" },
                },
              });
              expect(input).toContain(
                `--config ${shellEnvironmentReference("CODEX_SECURITY_CONFIG_PATH")}`,
              );
              expect(input).toContain("--effective-config");
              const shellEnvironment = options.env as Record<string, string>;
              const helper = execFileSync(
                interpreter!,
                [
                  join(PLUGIN_ROOT, "scripts", "config_preflight.py"),
                  "--skill",
                  "security-scan",
                  "--config",
                  shellEnvironment["CODEX_SECURITY_CONFIG_PATH"]!,
                  "--cwd",
                  repository,
                  "--multi-agent-runtime-owner",
                  "native",
                  "--multi-agent-runtime-version",
                  "v2",
                  "--multi-agent-session-cap",
                  "12",
                  "--multi-agent-runtime-provenance",
                  "tool-surface",
                  "--runtime-check",
                  "delegation_available=true",
                  "--runtime-check",
                  "goal_tools_available=true",
                  "--effective-config",
                  "features.goals=true",
                ],
                {
                  env: {
                    PATH: process.env["PATH"],
                    CODEX_HOME: join(root, "denied"),
                  },
                  encoding: "utf8",
                },
              );
              const preflight = JSON.parse(helper) as Record<string, unknown>;
              expect(preflight["status"]).toBe("ready");
              expect(preflight["config_resolution"]).toBe("manual-layers");
              expect(preflight["config_paths"]).toEqual([configPath]);
              await copyCompletedScan(root);
              const manifestPath = join(scanDir, "scan-manifest.json");
              const manifest = JSON.parse(
                await readFile(manifestPath, "utf8"),
              ) as { scan: { producer: { version: string } } };
              const pluginManifest = JSON.parse(
                await readFile(
                  join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
                  "utf8",
                ),
              ) as { version: string };
              manifest.scan.producer.version = pluginManifest.version;
              await writeFile(manifestPath, JSON.stringify(manifest));
              return { events: completedEvents() };
            },
          }),
        }),
      },
    );

    try {
      await client.run(repository);
      expect(capturedConfigPath).toBeDefined();
      expect(capturedCodexHome).toBeDefined();
    } finally {
      await client.close();
    }
    expect(existsSync(capturedConfigPath!)).toBe(false);
    expect(capturedCodexHome).toBe(
      join(ambientHome, "state", "plugins", "codex-security", "codex-home"),
    );
    expect(existsSync(capturedCodexHome!)).toBe(true);
  });

  test("reuses keyring-compatible credentials across separate scan clients", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const ambientHome = join(root, "ambient-codex-home");
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    const runtimeHomes: string[] = [];
    await mkdir(repository);
    await mkdir(ambientHome);
    await writeFile(join(ambientHome, "auth.json"), "{}\n");

    for (const index of [0, 1]) {
      const scanDir = join(root, `scan-${index}`);
      await mkdir(scanDir, { mode: 0o700 });
      const client = new TestClient(
        { pluginPath: PLUGIN_ROOT },
        {
          environment: {
            CODEX_HOME: ambientHome,
            CODEX_SECURITY_STATE_DIR: stateDirectory,
          },
          resolvePluginPython: async () => "/managed/python",
          prepareOutputDir: async () => scanDir,
          repositoryRevision: async () => "deadbeef",
          createCodex: (options: CodexOptions) => {
            runtimeHomes.push(options.env?.["CODEX_HOME"] ?? "");
            throw new Error("persistent credential scan reached");
          },
        },
      );

      try {
        await expect(client.run(repository)).rejects.toThrow(
          "persistent credential scan reached",
        );
      } finally {
        await client.close();
      }
      expect(existsSync(credentialHome)).toBe(true);
    }

    expect(runtimeHomes).toEqual([credentialHome, credentialHome]);
  });

  test("runs parallel ChatGPT scans with isolated mutable configuration", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const ambientHome = join(root, "ambient-codex-home");
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(repository);
    await mkdir(ambientHome);
    await writeFile(join(ambientHome, "auth.json"), "{}\n");
    let scansStarted = 0;
    const deepScanConfigPaths = new Set<string>();
    let releaseScans!: () => void;
    const concurrentScans = new Promise<void>((resolve) => {
      releaseScans = resolve;
    });

    const clients = await Promise.all(
      [0, 1].map(async (index) => {
        const scanDir = join(root, `parallel-scan-${index}`);
        await mkdir(scanDir, { mode: 0o700 });
        return new TestClient(
          {
            pluginPath: PLUGIN_ROOT,
            codexOverrides: {
              model: index === 0 ? "gpt-5.6-sol" : "gpt-5.6-terra",
            },
          },
          {
            environment: {
              CODEX_HOME: ambientHome,
              CODEX_SECURITY_STATE_DIR: stateDirectory,
            },
            resolvePluginPython: async () => "/managed/python",
            prepareOutputDir: async () => scanDir,
            repositoryRevision: async () => "deadbeef",
            createCodex: (options: CodexOptions) => {
              expect(options.env?.["CODEX_HOME"]).toBe(credentialHome);
              const expectedModel =
                index === 0 ? "gpt-5.6-sol" : "gpt-5.6-terra";
              expect(options.config?.["model"]).toBe(expectedModel);
              const deepScanConfigPath =
                options.env?.["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"];
              expect(typeof deepScanConfigPath).toBe("string");
              deepScanConfigPaths.add(deepScanConfigPath!);
              return {
                startThread: () => ({
                  id: null,
                  async runStreamed() {
                    return {
                      events: (async function* () {
                        const credentialConfig = parseToml(
                          await readFile(
                            join(credentialHome, "config.toml"),
                            "utf8",
                          ),
                        );
                        expect(credentialConfig["model"]).toBe(expectedModel);
                        const before = parseToml(
                          await readFile(deepScanConfigPath!, "utf8"),
                        );
                        expect(before["deep_scan"]).toMatchObject({
                          workers: index + 2,
                        });
                        yield {
                          type: "thread.started",
                          thread_id: `synthetic-${index}`,
                        };
                        if (++scansStarted === 2) {
                          expect(
                            existsSync(
                              join(credentialHome, ".codex-security-scan.lock"),
                            ),
                          ).toBe(false);
                          releaseScans();
                        }
                        await concurrentScans;
                        const after = parseToml(
                          await readFile(deepScanConfigPath!, "utf8"),
                        );
                        expect(after["deep_scan"]).toMatchObject({
                          workers: index + 2,
                        });
                        throw new Error("parallel managed scan reached");
                      })(),
                    };
                  },
                }),
              };
            },
          },
        );
      }),
    );

    try {
      const results = await Promise.allSettled(
        clients.map((client, index) =>
          client
            .run(repository, { mode: "deep", workers: index + 2 })
            .finally(releaseScans),
        ),
      );
      for (const result of results) {
        expect(result).toMatchObject({
          status: "rejected",
          reason: expect.objectContaining({
            message: "parallel managed scan reached",
          }),
        });
      }
      expect(existsSync(credentialHome)).toBe(true);
      expect(scansStarted).toBe(2);
      expect(deepScanConfigPaths.size).toBe(2);
      const pluginConfiguration = JSON.parse(
        await readFile(join(PLUGIN_ROOT, ".mcp.json"), "utf8"),
      ) as { mcpServers: Record<string, { env_vars: string[] }> };
      expect(
        pluginConfiguration.mcpServers["codex-security"]?.env_vars.includes(
          "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
        ),
      ).toBe(true);
    } finally {
      releaseScans();
      await Promise.all(clients.map(async (client) => await client.close()));
    }
  });

  test("reuses the managed runtime when scan authentication changes", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const ambientHome = join(root, "ambient-codex-home");
    const stateDirectory = join(root, "state");
    const dedicatedHome = join(stateDirectory, "codex-home");
    const scanDir = join(root, "scan");
    const ambientAuthentication = '{"auth_mode":"chatgpt"}\n';
    await mkdir(repository);
    await mkdir(ambientHome);
    await mkdir(scanDir, { mode: 0o700 });
    await writeFile(join(ambientHome, "auth.json"), ambientAuthentication);
    const runs: Array<{ home: string; apiKey?: string }> = [];
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          CODEX_HOME: ambientHome,
          CODEX_SECURITY_STATE_DIR: stateDirectory,
          OPENAI_API_KEY: "synthetic-transient-key",
        },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scanDir,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options: CodexOptions) => {
          runs.push({
            home: options.env?.["CODEX_HOME"] ?? "",
            ...(options.apiKey === undefined ? {} : { apiKey: options.apiKey }),
          });
          throw new Error("authentication-selected scan reached");
        },
      },
    );

    try {
      await expect(client.run(repository, { auth: "api-key" })).rejects.toThrow(
        "authentication-selected scan reached",
      );
      expect(runs[0]?.home).toBe(dedicatedHome);
      expect(runs[0]?.apiKey).toBe("synthetic-transient-key");
      expect(existsSync(join(dedicatedHome, "auth.json"))).toBe(false);

      await expect(client.run(repository, { auth: "chatgpt" })).rejects.toThrow(
        "authentication-selected scan reached",
      );
      expect(runs[1]).toEqual({ home: dedicatedHome });
      expect(await readFile(join(dedicatedHome, "auth.json"), "utf8")).toBe(
        ambientAuthentication,
      );
      await expect(client.run(repository, { auth: "api-key" })).rejects.toThrow(
        "authentication-selected scan reached",
      );
      expect(runs[2]?.home).toBe(dedicatedHome);
      expect(runs[2]?.apiKey).toBe("synthetic-transient-key");
      expect(await readFile(join(dedicatedHome, "auth.json"), "utf8")).toBe(
        ambientAuthentication,
      );
    } finally {
      await client.close();
    }
    expect(existsSync(dedicatedHome)).toBe(true);
  });

  test("does not reimport ambient credentials after an explicit logout", async () => {
    const root = await temporaryDirectory();
    const ambientHome = join(root, "ambient-home");
    const credentialHome = join(root, "credential-home");
    await mkdir(ambientHome);
    await mkdir(credentialHome, { mode: 0o700 });
    await writeFile(join(ambientHome, "auth.json"), '{"token":"ambient"}\n');
    await setCodexSecurityCredentialLogout(credentialHome, true);
    let imported = false;

    await expect(
      initialCredentialsAvailable({}, ambientHome, credentialHome, async () => {
        imported = true;
        return true;
      }),
    ).resolves.toBe(false);
    expect(imported).toBe(false);

    await setCodexSecurityCredentialLogout(credentialHome, false);
    await expect(
      initialCredentialsAvailable(
        {},
        ambientHome,
        credentialHome,
        async () => true,
      ),
    ).resolves.toBe(true);
  });

  test("recognizes ambient credentials during account() on a fresh instance", async () => {
    const root = await temporaryDirectory();
    const ambientHome = join(root, "ambient-home");
    const stateDir = join(root, "state");
    const script = join(root, "codex.mjs");
    await mkdir(ambientHome);
    await mkdir(stateDir, { mode: 0o700 });
    await writeFile(
      join(ambientHome, "auth.json"),
      '{"auth_mode":"chatgpt"}\n',
    );
    await writeFile(
      script,
      `
import { existsSync } from "node:fs";
import { basename, join } from "node:path";

const args = [basename(process.argv[1]), ...process.argv.slice(2)];
if (args.join(" ") === "login status") {
  const codexHome = process.env.CODEX_HOME;
  if (codexHome && existsSync(join(codexHome, "auth.json"))) {
    console.log("Logged in using ChatGPT");
    process.exitCode = 0;
  } else {
    console.log("Not logged in");
    process.exitCode = 1;
  }
}
process.exit(process.exitCode ?? 0);
`,
    );
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          PATH: process.env["PATH"],
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
          CODEX_HOME: ambientHome,
          CODEX_SECURITY_STATE_DIR: stateDir,
        },
        resolveCodexCommand: () => ({
          command: execFileSync("node", ["-p", "process.execPath"], {
            encoding: "utf8",
          }).trim(),
        }),
      },
    );
    try {
      const status = await client.account();
      expect(status.authenticated).toBe(true);
      expect(status.details).toContain("Logged in using ChatGPT");
      expect(existsSync(join(stateDir, "codex-home", "auth.json"))).toBe(true);
    } finally {
      await client.close();
    }
  });
});

test.skipIf(process.platform === "win32")(
  "managed authentication waits for native startup and restores its selected settings",
  async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "home");
    await mkdir(repository);
    await mkdir(home, { mode: 0o700 });
    const capture = join(root, "status-configs.json");
    const executable = join(root, "synthetic-status");
    const node = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();
    await writeFile(
      executable,
      `#!${node}
const fs = require("node:fs");
const capture = ${JSON.stringify(capture)};
const seen = fs.existsSync(capture) ? JSON.parse(fs.readFileSync(capture, "utf8")) : [];
seen.push(fs.readFileSync(require("node:path").join(process.env.CODEX_HOME, "config.toml"), "utf8"));
fs.writeFileSync(capture, JSON.stringify(seen));
console.log(seen.length === 1 ? "Not logged in" : "Logged in using ChatGPT");
process.exit(seen.length === 1 ? 1 : 0);
`,
    );
    await chmod(executable, 0o700);
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: {
          CODEX_HOME: home,
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
        },
        resolveCodexCommand: () => ({ command: executable }),
        prepareRuntime: async () => ({
          ...preparedRuntime(home),
          plugin: {
            ...preparedRuntime(home).plugin,
            marketplaceName: "codex-security-sdk-synthetic-selection",
            marketplaceRoot: join(home, "selected-marketplace"),
          },
          credentialsAvailable: false,
          environment: { CODEX_HOME: home },
          configPath: join(root, "preflight.toml"),
        }),
        resolvePluginPython: async () => "/managed/python",
        createCodex: () => {
          throw new Error("synthetic authenticated execution reached");
        },
      },
    );
    try {
      const sharedConfig = join(home, "config.toml");
      const selectedByOtherScan = 'model = "synthetic-other-scan"\n';
      await writeFile(sharedConfig, selectedByOtherScan);
      const release = await acquireCodexSecurityCredentialHomeLock(home);
      let settled = false;
      const outcome = client
        .run(repository)
        .catch((error: unknown) => error)
        .finally(() => {
          settled = true;
        });
      try {
        // Another native process still owns the shared configuration.
        await new Promise((resolve) => setTimeout(resolve, 100));
        expect(settled).toBe(false);
        expect(await readFile(sharedConfig, "utf8")).toBe(selectedByOtherScan);
        expect(existsSync(capture)).toBe(false);
      } finally {
        await release();
      }
      expect(await outcome).toBeInstanceOf(Error);
      expect(((await outcome) as Error).message).toContain(
        "No credentials were found",
      );
      await writeFile(
        join(home, "config.toml"),
        'forced_login_method = "chatgpt"\nforced_chatgpt_workspace_id = "synthetic-other-workspace"\n',
      );
      await expect(client.run(repository)).rejects.toThrow(
        "synthetic authenticated execution reached",
      );
      const configs = JSON.parse(await readFile(capture, "utf8")).map(
        (text: string) => parseToml(text),
      );
      expect(configs).toHaveLength(2);
      for (const config of configs) {
        expect(config).toMatchObject({
          marketplaces: {
            "codex-security-sdk-synthetic-selection": {
              source_type: "local",
              source: join(home, "selected-marketplace"),
            },
          },
          plugins: {
            "codex-security@codex-security-sdk-synthetic-selection": {
              enabled: true,
            },
          },
        });
        expect(config).not.toHaveProperty("forced_login_method");
        expect(config).not.toHaveProperty("forced_chatgpt_workspace_id");
      }
    } finally {
      await client.close();
    }
  },
);
