import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions, ThreadOptions } from "@openai/codex-sdk";
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
      let releaseConcurrentScans!: () => void;
      const concurrentScans = new Promise<void>((resolve) => {
        releaseConcurrentScans = resolve;
      });

      const controllers = [new AbortController(), new AbortController()];
      const clients = await Promise.all(
        (["cli", "sdk"] as const).map(async (surface, index) => {
          const scanDirectory = join(root, `${surface}-scan`);
          await mkdir(scanDirectory, { mode: 0o700 });
          let registrations = 0;
          return new InternalCodexSecurity(
            { pluginPath: PLUGIN_ROOT },
            {
              environment: {
                CODEX_HOME: ambientHome,
                CODEX_SECURITY_STATE_DIR: stateDirectory,
                CODEX_SECURITY_SURFACE: "spoofed",
                OPENAI_API_KEY: `synthetic-${surface}-key`,
              },
              resolvePluginPython: async () => "/managed/python",
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
                  async runStreamed() {
                    return {
                      events: (async function* () {
                        active += 1;
                        maximumActive = Math.max(maximumActive, active);
                        if (active === 2) releaseConcurrentScans();
                        try {
                          expect(options.env?.["CODEX_HOME"]).toBe(
                            credentialHome,
                          );
                          expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                            surface,
                          );
                          expect(options.config).toMatchObject({
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
                          const sharedConfig = parseToml(
                            await readFile(
                              join(credentialHome, "config.toml"),
                              "utf8",
                            ),
                          );
                          expect(sharedConfig).not.toHaveProperty(
                            "responses_api_metadata",
                          );
                          expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                            surface,
                          );
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
});
