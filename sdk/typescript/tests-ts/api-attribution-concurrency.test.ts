import type { TurnOptions } from "@openai/codex-sdk";
import { InternalSecurity } from "./support/internal-security.js";
import { mkdir, readFile, realpath, symlink } from "node:fs/promises";

import { delimiter, join } from "node:path";

import type { CodexOptions, ThreadOptions } from "@openai/codex-sdk";

import { afterEach, describe, expect, test } from "bun:test";

import { parse as parseToml } from "smol-toml";

import { CodexSecurity } from "../src/index.js";
import { deepMerge, type JsonObject } from "../src/config.js";

import type { WorkbenchCommandOptions as RequiredWorkbenchCommandOptions } from "../src/runtime.js";

import { PLUGIN_ROOT } from "./plugin-root.js";

import { createApiTestFixtures } from "./support/api-events.js";

const fixtures = createApiTestFixtures();

const InternalCodexSecurity = CodexSecurity as unknown as new (
  config: Record<string, unknown>,
  dependencies: Record<string, unknown>,
  runtimeOptions?: { surface: "cli" | "sdk" },
) => CodexSecurity;

afterEach(async () => {
  await fixtures.cleanup();
});

describe("delegated scan attribution", () => {
  test.each(["standard", "deep"] as const)(
    "keeps overlapping CLI and SDK %s scans concurrent and correctly attributed",
    async (mode) => {
      const root = await fixtures.temporaryDirectory();
      const repository = join(root, "repository");
      const ambientHome = join(root, "ambient-home");
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      await mkdir(repository);
      await mkdir(ambientHome);
      let active = 0;
      let maximumActive = 0;
      let releaseConcurrentScans!: () => void;
      const concurrentScans = new Promise<void>((resolve) => {
        releaseConcurrentScans = resolve;
      });

      const controllers = [new AbortController(), new AbortController()];
      const clients = await Promise.all(
        (["cli", "sdk"] as const).map(async (surface, index) => {
          const scanDirectory = join(root, `${surface}-scan`);
          const gitDirectory = join(root, `${surface}-tools`);
          await mkdir(gitDirectory);
          const hostGit = Bun.which("git");
          expect(hostGit).not.toBeNull();
          const git = join(
            gitDirectory,
            process.platform === "win32" ? "git.exe" : "git",
          );
          await symlink(await realpath(hostGit!), git);
          const expectedGitDirectory = await realpath(gitDirectory);
          await mkdir(scanDirectory, { mode: 0o700 });
          let registrations = 0;
          return new InternalCodexSecurity(
            { pluginPath: PLUGIN_ROOT },
            {
              environment: {
                PATH: gitDirectory,
                GIT_SSH_COMMAND: `synthetic-${surface}-ssh`,
                CODEX_HOME: ambientHome,
                CODEX_SECURITY_STATE_DIR: stateDirectory,
                CODEX_SECURITY_SURFACE: "spoofed",
                OPENAI_API_KEY: `synthetic-${surface}-key`,
              },
              resolvePluginPython: async () => "/managed/python",
              probeCodexSandbox: async () => {},
              prepareOutputDir: async (requested: string | undefined) => {
                const directory = requested ?? scanDirectory;
                await mkdir(directory, { recursive: true, mode: 0o700 });
                return directory;
              },
              prepareScanArtifactRestorer: async () => ({
                prepareDirectory: async () => {},
                restore: async () => {},
                remove: async () => {},
              }),
              repositoryRevision: async () => "deadbeef",
              runWorkbench: async (
                options: WorkbenchCommandOptions,
                args: readonly string[],
              ) => {
                expect(options.environment["CODEX_HOME"]).toBe(credentialHome);
                if (args[0] === "list-scans") return { scans: [] };
                if (args[0] === "get-scan")
                  return { scan: { progress: { status: "running" } } };
                if (args[0] === "register-cli-scan") {
                  return {
                    scanId: `scan_${surface}_${++registrations}`,
                    targetId: `target_${surface}`,
                    targetRevision: "deadbeef",
                    scanDir: args[args.indexOf("--scan-dir") + 1],
                    contract: { target: { allowedKinds: ["git_revision"] } },
                  };
                }
                if (args[0] === "get-scan-feedback") {
                  return {
                    scanId: args[args.indexOf("--scan-id") + 1],
                    targetId: `target_${surface}`,
                    falsePositives: [],
                  };
                }
                return {};
              },
              createCodex: (options: CodexOptions) => ({
                startThread: (threadOptions: ThreadOptions) => ({
                  id: null,
                  async runStreamed() {
                    return {
                      events: (async function* () {
                        active += 1;
                        maximumActive = Math.max(maximumActive, active);
                        if (active === 2) releaseConcurrentScans();
                        try {
                          const initialEnvironment = { ...options.env };
                          const launchConfig = parseToml(
                            await readFile(
                              join(credentialHome, "config.toml"),
                              "utf8",
                            ),
                          ) as JsonObject;
                          const executionConfig = effectiveConfig(
                            options,
                            launchConfig,
                          );
                          expect(options.env?.["CODEX_HOME"]).toBe(
                            credentialHome,
                          );
                          expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                            surface,
                          );
                          expect(options.env?.["CODEX_SECURITY_GIT"]).toBe(git);
                          expect(
                            options.env?.["PATH"]?.split(delimiter),
                          ).toContain(expectedGitDirectory);
                          expect(
                            options.env?.["PATH"]?.split(delimiter),
                          ).not.toContain(
                            join(
                              root,
                              `${surface === "cli" ? "sdk" : "cli"}-tools`,
                            ),
                          );
                          expect(options.env?.["GIT_SSH_COMMAND"]).toBe(
                            `synthetic-${surface}-ssh`,
                          );
                          expect(options.env).not.toHaveProperty(
                            "OPENAI_API_KEY",
                          );
                          expect(executionConfig).toMatchObject({
                            responses_api_metadata: {
                              codex_security_surface: surface,
                            },
                          });
                          expect(threadOptions.threadSource).toBe(
                            "security_scan",
                          );
                          expect(options.env?.["CODEX_SECURITY_SCAN_DIR"]).toBe(
                            mode === "deep"
                              ? join(
                                  scanDirectory,
                                  "artifacts/deep-scan/passes/pass-1",
                                )
                              : scanDirectory,
                          );
                          yield {
                            type: "thread.started",
                            thread_id: `synthetic-${surface}`,
                          };
                          await concurrentScans;
                          expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                            surface,
                          );
                          expect(options.env).toEqual(initialEnvironment);
                          expect(
                            effectiveConfig(options, launchConfig),
                          ).toEqual(executionConfig);
                          const observed = new Error(
                            "delegated attribution observed",
                          );
                          controllers[index]!.abort(observed);
                          throw observed;
                        } finally {
                          active -= 1;
                        }
                      })(),
                    };
                  },
                }),
              }),
            },
            { surface },
          );
        }),
      );

      try {
        const results = await Promise.allSettled(
          clients.map((client, index) =>
            client
              .run(repository, {
                mode,
                ...(mode === "deep" ? { workers: 1, maxDiscoveryRuns: 1 } : {}),
                signal: controllers[index]!.signal,
              })
              .finally(releaseConcurrentScans),
          ),
        );
        for (const result of results) expect(result.status).toBe("rejected");
        for (const controller of controllers) {
          expect(controller.signal.reason?.message).toBe(
            "delegated attribution observed",
          );
        }
        expect(maximumActive).toBe(2);
      } finally {
        releaseConcurrentScans();
        await Promise.all(clients.map(async (client) => await client.close()));
      }
    },
  );

  test.each([
    ["standard", true, "root"],
    ["deep", true, "profile-override"],
    ["standard", false, "unset"],
    ["deep", false, "profile-only"],
    ["deep", true, "root"],
    ["deep", true, "profile-fallback"],
    ["deep", true, "unset"],
  ] as const)(
    "keeps overlapping CLI and SDK %s scans attributed with Cyber selection %p and %s endpoint",
    async (mode, selectProgram, endpointSource) => {
      const root = await fixtures.temporaryDirectory();
      const repository = join(root, "repository");
      const ambientHome = join(root, "ambient-home");
      const stateDirectory = join(root, "state");
      const credentialHome = join(stateDirectory, "codex-home");
      await mkdir(repository);
      await mkdir(ambientHome);
      let active = 0;
      let maximumActive = 0;
      const configPaths = new Set<string>();
      const programs = selectProgram
        ? (["daybreak_blue", "standard"] as const)
        : ([undefined, undefined] as const);
      const concurrentScans = Promise.withResolvers<void>();
      const controllers = [new AbortController(), new AbortController()];

      const clients = await Promise.all(
        (["cli", "sdk"] as const).map(async (surface, index) => {
          const program = surface === "cli" ? programs[0] : programs[1];
          const endpoint =
            endpointSource === "unset"
              ? undefined
              : `https://synthetic-user:synthetic-password@${surface}.example.test/v1?token=synthetic-${surface}-token`;
          const rootEndpoint =
            endpointSource === "profile-only"
              ? undefined
              : endpointSource === "profile-override"
                ? "https://overridden.example.test/v1"
                : endpoint;
          const profileEndpoint =
            endpointSource === "profile-only" ||
            endpointSource === "profile-override"
              ? endpoint
              : undefined;
          const features = selectProgram
            ? {
                api_key_cyber_access_programs: surface === "cli",
                ...(surface === "sdk"
                  ? { api_key_model_discovery: false }
                  : {}),
              }
            : {};
          const scanDirectory = join(root, `${surface}-scan`);
          const gitDirectory = join(root, `${surface}-tools`);
          await mkdir(gitDirectory);
          const hostGit = Bun.which("git");
          expect(hostGit).not.toBeNull();
          const git = join(
            gitDirectory,
            process.platform === "win32" ? "git.exe" : "git",
          );
          await symlink(await realpath(hostGit!), git);
          const expectedGitDirectory = await realpath(gitDirectory);
          await mkdir(scanDirectory, { mode: 0o700 });
          let registrations = 0;
          return new InternalSecurity(
            {
              pluginPath: PLUGIN_ROOT,
              codexOverrides: {
                analytics: { enabled: surface === "sdk" },
                responses_api_metadata: {
                  custom_attribution: surface,
                  codex_security_surface: "spoofed",
                  codex_security_command: "spoofed",
                  codex_security_package_version: "spoofed",
                },
                ...(rootEndpoint === undefined
                  ? {}
                  : { openai_base_url: rootEndpoint }),
                ...(endpointSource.startsWith("profile-")
                  ? {
                      profile: "selected",
                      profiles: {
                        selected:
                          profileEndpoint === undefined
                            ? {}
                            : { openai_base_url: profileEndpoint },
                        unselected: {
                          openai_base_url: "https://unused.example.test/v1",
                        },
                      },
                    }
                  : {}),
                ...(surface === "sdk" ? { features } : {}),
              },
            },
            {
              environment: {
                PATH: gitDirectory,
                GIT_SSH_COMMAND: `synthetic-${surface}-ssh`,
                CODEX_HOME: ambientHome,
                CODEX_SECURITY_STATE_DIR: stateDirectory,
                CODEX_SECURITY_SURFACE: "spoofed",
                OPENAI_API_KEY: `synthetic-${surface}-key`,
              },
              resolvePluginPython: async () => "/managed/python",
              probeCodexSandbox: async () => {},
              prepareOutputDir: async (requested: string | undefined) => {
                const directory = requested ?? scanDirectory;
                await mkdir(directory, { recursive: true, mode: 0o700 });
                return directory;
              },
              prepareScanArtifactRestorer: async () => ({
                prepareDirectory: async () => {},
                restore: async () => {},
                remove: async () => {},
              }),
              repositoryRevision: async () => "deadbeef",
              runWorkbench: async (
                _options: unknown,
                args: readonly string[],
              ) => {
                if (args[0] === "list-scans") return { scans: [] };
                if (args[0] === "get-scan")
                  return { scan: { progress: { status: "running" } } };
                if (args[0] === "register-cli-scan") {
                  return {
                    scanId: `scan_${surface}_${++registrations}`,
                    targetId: `target_${surface}`,
                    targetRevision: "deadbeef",
                    scanDir: args[args.indexOf("--scan-dir") + 1],
                    contract: { target: { allowedKinds: ["git_revision"] } },
                  };
                }
                if (args[0] === "get-scan-feedback") {
                  return {
                    scanId: args[args.indexOf("--scan-id") + 1],
                    targetId: `target_${surface}`,
                    falsePositives: [],
                  };
                }
                return {};
              },
              createCodex: (options: CodexOptions) => ({
                startThread: (threadOptions: ThreadOptions) => ({
                  id: null,
                  async runStreamed(
                    _input: unknown,
                    turnOptions?: TurnOptions,
                  ) {
                    return {
                      events: (async function* () {
                        active += 1;
                        maximumActive = Math.max(maximumActive, active);
                        if (active === 2) concurrentScans.resolve();
                        try {
                          const initialEnvironment = { ...options.env };
                          const launchConfig = parseToml(
                            await readFile(
                              join(credentialHome, "config.toml"),
                              "utf8",
                            ),
                          ) as JsonObject;
                          const executionConfig = effectiveConfig(
                            options,
                            launchConfig,
                          );
                          expect(options.env?.["CODEX_HOME"]).toBe(
                            credentialHome,
                          );
                          expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                            surface,
                          );
                          expect(options.env?.["CODEX_SECURITY_GIT"]).toBe(git);
                          expect(
                            options.env?.["PATH"]?.split(delimiter),
                          ).toContain(expectedGitDirectory);
                          expect(
                            options.env?.["PATH"]?.split(delimiter),
                          ).not.toContain(
                            join(
                              root,
                              `${surface === "cli" ? "sdk" : "cli"}-tools`,
                            ),
                          );
                          expect(options.env?.["GIT_SSH_COMMAND"]).toBe(
                            `synthetic-${surface}-ssh`,
                          );
                          expect(options.env).not.toHaveProperty(
                            "OPENAI_API_KEY",
                          );
                          expect(options.apiKey).toBe(
                            `synthetic-${surface}-key`,
                          );
                          expect(turnOptions?.cyberAccessProgram).toBe(program);
                          expect(executionConfig["openai_base_url"]).toBe(
                            endpoint,
                          );
                          expect(executionConfig).toMatchObject({
                            features,
                            analytics: { enabled: surface === "sdk" },
                            responses_api_metadata: {
                              custom_attribution: surface,
                              codex_security_surface: surface,
                              codex_security_command: "scan",
                              codex_security_package_version: VERSION,
                            },
                          });
                          expect(options.env?.["CODEX_SECURITY_SCAN_DIR"]).toBe(
                            mode === "deep"
                              ? join(
                                  scanDirectory,
                                  "artifacts/deep-scan/passes/pass-1",
                                )
                              : scanDirectory,
                          );
                          expect(threadOptions.threadSource).toBe(
                            "security_scan",
                          );
                          const configPath =
                            options.env?.["CODEX_SECURITY_CONFIG_PATH"];
                          expect(configPath).toBeString();
                          configPaths.add(configPath!);
                          const initialConfig = await readFile(
                            configPath!,
                            "utf8",
                          );
                          const runtimeConfig = parseToml(initialConfig);
                          expect(runtimeConfig).toMatchObject({ features });
                          expect(initialConfig).not.toContain(
                            "openai_base_url",
                          );
                          expect(initialConfig).not.toContain(
                            "synthetic-password",
                          );
                          if (program === undefined) {
                            expect(runtimeConfig).not.toHaveProperty(
                              "codex_security",
                            );
                            for (const config of [
                              executionConfig,
                              runtimeConfig,
                            ]) {
                              expect(config?.["features"]).not.toHaveProperty(
                                "api_key_cyber_access_programs",
                              );
                            }
                          } else {
                            expect(runtimeConfig).toMatchObject({
                              codex_security: { cyber_access_program: program },
                            });
                          }
                          yield {
                            type: "thread.started",
                            thread_id: `synthetic-${surface}`,
                          };
                          await concurrentScans.promise;
                          expect(await readFile(configPath!, "utf8")).toBe(
                            initialConfig,
                          );
                          expect(options.env).toEqual(initialEnvironment);
                          expect(
                            effectiveConfig(options, launchConfig),
                          ).toEqual(executionConfig);
                          const observed = new Error(
                            "delegated attribution observed",
                          );
                          controllers[index]!.abort(observed);
                          throw observed;
                        } finally {
                          active -= 1;
                        }
                      })(),
                    };
                  },
                }),
              }),
            },
            surface === "sdk" && !selectProgram ? undefined : { surface },
          );
        }),
      );

      try {
        const results = await Promise.allSettled(
          clients.map((client, index) =>
            client
              .run(repository, {
                mode,
                cyberAccessProgram: programs[index],
                signal: controllers[index]!.signal,
                ...(mode === "deep" ? { workers: 1, maxDiscoveryRuns: 1 } : {}),
              })
              .finally(concurrentScans.resolve),
          ),
        );
        for (const result of results) expect(result.status).toBe("rejected");
        for (const controller of controllers) {
          expect(controller.signal.reason?.message).toBe(
            "delegated attribution observed",
          );
        }
        expect(maximumActive).toBe(2);
        expect(configPaths.size).toBe(2);
      } finally {
        concurrentScans.resolve();
        await Promise.all(clients.map(async (client) => await client.close()));
      }
    },
  );
});

import { VERSION } from "../src/version.js";

function effectiveConfig(
  options: CodexOptions,
  base: JsonObject = {},
): JsonObject {
  expect(JSON.stringify(base)).not.toContain("synthetic-cli-key");
  expect(JSON.stringify(base)).not.toContain("synthetic-sdk-key");
  return (options.configOverrides ?? []).reduce(
    (config, override) => deepMerge(config, parseToml(override) as JsonObject),
    deepMerge(
      structuredClone(base),
      structuredClone(options.config ?? {}) as JsonObject,
    ),
  );
}

type WorkbenchCommandOptions = Omit<
  RequiredWorkbenchCommandOptions,
  "python"
> & { python?: string };
