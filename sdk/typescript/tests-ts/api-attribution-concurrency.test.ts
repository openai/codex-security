import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { CodexOptions } from "@openai/codex-sdk";
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

      const clients = await Promise.all(
        (["cli", "sdk"] as const).map(async (surface) => {
          const scanDirectory = join(root, `${surface}-scan`);
          await mkdir(scanDirectory, { mode: 0o700 });
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
                startThread: () => ({
                  id: null,
                  async runStreamed() {
                    active += 1;
                    maximumActive = Math.max(maximumActive, active);
                    if (active === 2) releaseConcurrentScans();
                    try {
                      expect(options.env?.["CODEX_HOME"]).toBe(credentialHome);
                      expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                        surface,
                      );
                      expect(options.config).toMatchObject({
                        responses_api_metadata: {
                          codex_security_surface: surface,
                        },
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
                      expect(options.env?.["CODEX_SECURITY_SURFACE"]).toBe(
                        surface,
                      );
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
          clients.map((client) =>
            client.run(repository, { mode }).finally(releaseConcurrentScans),
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
      } finally {
        releaseConcurrentScans();
        await Promise.all(clients.map(async (client) => await client.close()));
      }
    },
  );
});
