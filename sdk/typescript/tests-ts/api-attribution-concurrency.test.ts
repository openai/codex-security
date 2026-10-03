import { mkdir, readFile, realpath, symlink } from "node:fs/promises";
import { delimiter, join } from "node:path";
import type {
  CodexOptions,
  ThreadOptions,
  TurnOptions,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import { CodexSecurity } from "../src/index.js";
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
      const configPaths = new Set<string>();
      const programs = ["daybreak_blue", "standard"] as const;
      const { promise: concurrentScans, resolve: releaseConcurrentScans } =
        Promise.withResolvers<void>();

      const clients = await Promise.all(
        (["cli", "sdk"] as const).map(async (surface) => {
          const program = surface === "cli" ? programs[0] : programs[1];
          const features = {
            api_key_cyber_access_programs: surface === "cli",
            ...(surface === "sdk" ? { api_key_model_discovery: false } : {}),
          };
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
          return new InternalCodexSecurity(
            {
              pluginPath: PLUGIN_ROOT,
              ...(surface === "sdk" ? { codexOverrides: { features } } : {}),
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
              prepareOutputDir: async () => scanDirectory,
              repositoryRevision: async () => "deadbeef",
              runWorkbench: async (
                _options: unknown,
                args: readonly string[],
              ) => {
                if (args[0] === "register-cli-scan") {
                  return {
                    scanId: `scan_${surface}`,
                    targetId: `target_${surface}`,
                    targetRevision: "deadbeef",
                    scanDir: scanDirectory,
                    contract: { target: { allowedKinds: ["git_revision"] } },
                  };
                }
                if (args[0] === "get-scan-feedback") {
                  return {
                    scanId: `scan_${surface}`,
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
                    active += 1;
                    maximumActive = Math.max(maximumActive, active);
                    if (active === 2) releaseConcurrentScans();
                    try {
                      const initialEnvironment = { ...options.env };
                      expect(options.env?.["CODEX_HOME"]).toBe(credentialHome);
                      expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                        surface,
                      );
                      expect(options.env?.["CODEX_SECURITY_GIT"]).toBe(git);
                      expect(options.env?.["PATH"]?.split(delimiter)).toContain(
                        expectedGitDirectory,
                      );
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
                      expect(options.env).not.toHaveProperty("OPENAI_API_KEY");
                      expect(options.apiKey).toBe(`synthetic-${surface}-key`);
                      expect(turnOptions?.cyberAccessProgram).toBe(program);
                      expect(options.config).toMatchObject({
                        features,
                        responses_api_metadata: {
                          codex_security_surface: surface,
                        },
                      });
                      expect(threadOptions.threadSource).toBe("security_scan");
                      const configPath =
                        options.env?.["CODEX_SECURITY_CONFIG_PATH"];
                      expect(configPath).toBeString();
                      configPaths.add(configPath!);
                      const initialConfig = await readFile(configPath!, "utf8");
                      expect(parseToml(initialConfig)).toMatchObject({
                        codex_security: { cyber_access_program: program },
                        features,
                      });
                      await concurrentScans;
                      const sharedConfig = parseToml(
                        await readFile(
                          join(credentialHome, "config.toml"),
                          "utf8",
                        ),
                      );
                      expect(sharedConfig).not.toHaveProperty(
                        "responses_api_metadata",
                      );
                      expect(sharedConfig).not.toHaveProperty("codex_security");
                      expect(sharedConfig["features"] ?? {}).not.toHaveProperty(
                        "api_key_cyber_access_programs",
                      );
                      expect(sharedConfig["features"] ?? {}).not.toHaveProperty(
                        "api_key_model_discovery",
                      );
                      expect(JSON.stringify(sharedConfig)).not.toContain(
                        "synthetic-cli-key",
                      );
                      expect(JSON.stringify(sharedConfig)).not.toContain(
                        "synthetic-sdk-key",
                      );
                      expect(await readFile(configPath!, "utf8")).toBe(
                        initialConfig,
                      );
                      expect(options.env).toEqual(initialEnvironment);
                      throw new Error("delegated attribution observed");
                    } finally {
                      active -= 1;
                    }
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
              .run(repository, { mode, cyberAccessProgram: programs[index] })
              .finally(releaseConcurrentScans),
          ),
        );
        for (const result of results) {
          expect(result).toMatchObject({
            status: "rejected",
            reason: expect.objectContaining({
              message: "delegated attribution observed",
            }),
          });
        }
        expect(maximumActive).toBe(2);
        expect(configPaths.size).toBe(2);
      } finally {
        releaseConcurrentScans();
        await Promise.all(clients.map(async (client) => await client.close()));
      }
    },
  );
});
