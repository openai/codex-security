import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import * as runtime from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([false, true])(
  "protects provider snapshots before writing credentials (ACL failure: %j)",
  async (failAcl) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    const original = runtime.requirePrivateCredentialHome;
    let protectedDirectory: string | undefined;
    let launched = false;
    const guard = spyOn(
      runtime,
      "requirePrivateCredentialHome",
    ).mockImplementation(async (metadata, path, options) => {
      if (!basename(path).startsWith("openai-codex-security-home-"))
        return original(metadata, path, options);
      await original(metadata, path, {
        platform: "win32",
        secureWindowsHome: async (directory) => {
          expect(await readdir(directory)).toEqual([]);
          protectedDirectory = directory;
          if (failAcl) throw new Error("synthetic ACL denial");
        },
      });
    });
    const client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: {
          model_provider: "synthetic.provider",
          model_providers: {
            "synthetic.provider": {
              name: "Synthetic provider",
              base_url: "https://provider.example.test/v1",
              wire_api: "responses",
              auth: {
                command: "synthetic-auth",
                env: { CLIENT_SECRET: "synthetic-client-secret" },
              },
            },
          },
        },
      },
      {
        environment: { CODEX_SECURITY_STATE_DIR: join(root, "state") },
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => scan,
        repositoryRevision: async () => "deadbeef",
        createCodex: (options) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              launched = true;
              const file = options.env!["CODEX_SECURITY_CONFIG_PATH"]!;
              expect(dirname(file)).toBe(protectedDirectory!);
              expect(await readFile(file, "utf8")).toContain(
                "synthetic-client-secret",
              );
              if (process.platform !== "win32") {
                expect((await stat(file)).mode & 0o777).toBe(0o600);
                expect((await stat(dirname(file))).mode & 0o777).toBe(0o700);
              }
              throw new Error("synthetic scan reached");
            },
          }),
        }),
      },
    );
    try {
      await expect(client.run(repository)).rejects.toThrow(
        failAcl ? "synthetic ACL denial" : "synthetic scan reached",
      );
      expect(protectedDirectory).toBeDefined();
      expect(launched).toBe(!failAcl);
    } finally {
      guard.mockRestore();
      await client.close();
    }
    expect(existsSync(protectedDirectory!)).toBe(false);
  },
);
