import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import type { CodexOptions } from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { initialCredentialsAvailable } from "../src/api.js";
import { setCodexSecurityCredentialLogout } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  mockWorkbench,
  shellEnvironmentReference,
  TestClient,
} from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();
afterEach(cleanup);

describe("CodexSecurity orchestration", () => {
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
        expect(parseToml(captured!.configOverrides![0]!)).toEqual({
          model_providers: { "synthetic.provider": provider },
        });
        if (profile) {
          expect(captured?.config?.["profile"]).toBe("review");
          expect(captured?.config?.["profiles"]).toEqual({
            review: { model_provider: "synthetic.provider" },
          });
        } else {
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
              const codexConfig = await readFile(
                join(codexHome!, "config.toml"),
                "utf8",
              );
              expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe("sdk");
              expect(parseToml(codexConfig)).toMatchObject({
                model_reasoning_summary: "detailed",
                show_raw_agent_reasoning: true,
              });
              expect(options.config).not.toHaveProperty("projects");
              expect(options.config).not.toHaveProperty("permissions");
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

  test.each(["error", "empty", "cancel"])(
    "releases native startup ownership before the first event on %s",
    async (failure) => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const ambientHome = join(root, "ambient-codex-home");
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      const lock = join(credentialHome, ".codex-security-scan.lock");
      await mkdir(repository);
      await mkdir(ambientHome);
      await writeFile(join(ambientHome, "auth.json"), "{}\n");
      let startups = 0;
      for (const index of [0, 1]) {
        const controller = new AbortController();
        const startupError = new Error("synthetic startup failure");
        const client = new TestClient(
          { pluginPath: PLUGIN_ROOT },
          {
            environment: {
              CODEX_HOME: ambientHome,
              CODEX_SECURITY_STATE_DIR: stateDirectory,
            },
            resolvePluginPython: async () => "/managed/python",
            prepareOutputDir: async () => {
              const directory = join(root, `scan-${index}`);
              await mkdir(directory, { mode: 0o700 });
              return directory;
            },
            repositoryRevision: async () => "deadbeef",
            createCodex: () => ({
              startThread: () => ({
                id: null,
                async runStreamed() {
                  expect(existsSync(lock)).toBe(true);
                  startups += 1;
                  if (index === 0 && failure === "error") throw startupError;
                  return {
                    events: (async function* () {
                      await Promise.resolve();
                      if (index === 1)
                        throw new Error("next native startup reached");
                      if (failure === "empty") return;
                      controller.abort(startupError);
                      throw startupError;
                    })(),
                  };
                },
              }),
            }),
          },
        );
        try {
          const run = client.run(repository, { signal: controller.signal });
          if (index === 1)
            await expect(run).rejects.toThrow("next native startup reached");
          else if (failure === "error")
            await expect(run).rejects.toBe(startupError);
          else if (failure === "cancel") {
            const error = await run.catch((error: unknown) => error);
            expect(error).toMatchObject({ cause: startupError });
          } else await expect(run).rejects.toThrow();
          expect(existsSync(lock)).toBe(false);
        } finally {
          await client.close();
        }
      }
      expect(startups).toBe(2);
    },
  );

  test("runs parallel ChatGPT scans with isolated ordinary child settings", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const ambientHome = join(root, "ambient-codex-home");
    const stateDirectory = join(root, "state");
    const credentialHome = join(stateDirectory, "codex-home");
    await mkdir(repository);
    await mkdir(ambientHome);
    await writeFile(join(ambientHome, "auth.json"), "{}\n");
    const controllers = [new AbortController(), new AbortController()];
    const launches: Array<{
      index: number;
      home: string | undefined;
      directory: string | undefined;
      before: CodexOptions["config"];
      after: CodexOptions["config"];
      sharedConfig: unknown;
      credentialLockExists: boolean;
    }> = [];
    const recipes: Array<{ index: number; mode: string; deepScan?: unknown }> =
      [];
    let scansStarted = 0;
    let releaseScans!: () => void;
    const concurrentScans = new Promise<void>((resolve) => {
      releaseScans = resolve;
    });
    const clients = await Promise.all(
      [0, 1].map(async (index) => {
        const scanDir = join(root, `parallel-scan-${index}`);
        let registrations = 0;
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
            prepareOutputDir: async (requested) => {
              const directory = requested ?? scanDir;
              await mkdir(directory, { recursive: true, mode: 0o700 });
              return directory;
            },
            repositoryRevision: async () => "deadbeef",
            runWorkbench: async (_options, args, input) => {
              if (args[0] === "list-scans") return { scans: [] };
              if (args[0] === "get-scan")
                return { scan: { progress: { status: "running" } } };
              const result = mockWorkbench(args, input);
              if (args[0] === "get-scan-feedback")
                result["scanId"] = args[args.indexOf("--scan-id") + 1]!;
              if (args[0] === "register-cli-scan") {
                recipes.push({ index, ...JSON.parse(input!).recipe });
                result["scanId"] = `scan_parallel_${index}_${++registrations}`;
              }
              return result;
            },
            createCodex: (options: CodexOptions) => ({
              startThread: () => ({
                id: null,
                async runStreamed() {
                  const before = structuredClone(options.config);
                  const sharedConfig = parseToml(
                    await readFile(join(credentialHome, "config.toml"), "utf8"),
                  );
                  const credentialLockExists = existsSync(
                    join(credentialHome, ".codex-security-scan.lock"),
                  );
                  return {
                    events: (async function* () {
                      yield {
                        type: "thread.started",
                        thread_id: `parallel-${index}`,
                      };
                      if (++scansStarted === 2) releaseScans();
                      await concurrentScans;
                      launches.push({
                        index,
                        home: options.env?.["CODEX_HOME"],
                        directory: options.env?.["CODEX_SECURITY_SCAN_DIR"],
                        before,
                        after: structuredClone(options.config),
                        sharedConfig,
                        credentialLockExists,
                      });
                      const interrupted = new Error(
                        "parallel managed scan reached",
                      );
                      controllers[index]!.abort(interrupted);
                      throw interrupted;
                    })(),
                  };
                },
              }),
            }),
          },
        );
      }),
    );
    try {
      const results = await Promise.allSettled(
        clients.map((client, index) =>
          client
            .run(repository, {
              mode: "deep",
              workers: index + 2,
              subagents: index,
              maxDiscoveryRuns: 1,
              signal: controllers[index]!.signal,
            })
            .finally(releaseScans),
        ),
      );
      for (const result of results) expect(result.status).toBe("rejected");
      expect(scansStarted).toBe(2);
      expect(launches).toHaveLength(2);
      for (const launch of launches) {
        expect(launch.home).toBe(credentialHome);
        expect(launch.directory).toBe(
          join(
            root,
            `parallel-scan-${launch.index}`,
            "artifacts",
            "deep-scan",
            "passes",
            "pass-1",
          ),
        );
        expect(launch.before).toMatchObject({
          model: launch.index === 0 ? "gpt-5.6-sol" : "gpt-5.6-terra",
          features: {
            multi_agent_v2: {
              max_concurrent_threads_per_session: launch.index + 1,
            },
          },
        });
        expect(launch.after).toEqual(launch.before);
        expect(launch.sharedConfig).toMatchObject({
          model: launch.index === 0 ? "gpt-5.6-sol" : "gpt-5.6-terra",
          default_permissions: "codex_security_scan",
          features: {
            multi_agent_v2: {
              max_concurrent_threads_per_session: launch.index + 1,
            },
          },
        });
        expect(launch.credentialLockExists).toBe(true);
        expect(
          recipes.filter(({ index }) => index === launch.index),
        ).toMatchObject([
          {
            mode: "deep",
            deepScan: { workers: launch.index + 2, subagents: launch.index },
          },
          { mode: "standard" },
        ]);
      }
      expect(existsSync(credentialHome)).toBe(true);
      expect(
        existsSync(join(credentialHome, ".codex-security-scan.lock")),
      ).toBe(false);
    } finally {
      releaseScans();
      controllers.forEach((controller) => controller.abort());
      await Promise.all(clients.map((client) => client.close()));
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
