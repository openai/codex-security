import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import * as runtime from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { parse as parseToml } from "smol-toml";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each([false, true])(
  "protects provider snapshots across runtime reuse (ACL failure: %j)",
  async (failAcl) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const scan = join(root, "scan");
    await mkdir(repository);
    await mkdir(scan, { mode: 0o700 });
    const original = runtime.requirePrivateCredentialHome;
    let protectedDirectory: string | undefined;
    let workerFile: string | undefined;
    let launched = false;
    let operation: "deep" | "standard" | "validation" = "deep";
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
              const file = join(protectedDirectory!, "config-preflight.toml");
              expect(options.env!["CODEX_SECURITY_CONFIG_PATH"]).toBe(
                operation === "validation" ? undefined : file,
              );
              expect(dirname(file)).toBe(protectedDirectory!);
              expect(await readFile(file, "utf8")).not.toContain(
                "synthetic-client-secret",
              );
              workerFile ??=
                options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"];
              expect(options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"]).toBe(
                operation === "deep" ? workerFile : undefined,
              );
              expect(dirname(dirname(workerFile!))).toBe(
                options.env!["CODEX_HOME"]!,
              );
              expect(await readFile(workerFile!, "utf8")).not.toContain(
                "synthetic-client-secret",
              );
              const profileFile = join(
                options.env!["CODEX_HOME"]!,
                `${options.nativeProfile}.config.toml`,
              );
              expect(await readFile(profileFile, "utf8")).toContain(
                "synthetic-client-secret",
              );
              expect(JSON.stringify(options)).not.toContain(
                "synthetic-client-secret",
              );
              const filesystem = parseToml(
                options.configOverrides!.find((value) =>
                  value.startsWith(
                    "permissions.codex_security_scan.filesystem=",
                  ),
                )!,
              )["permissions"] as Record<string, Record<string, unknown>>;
              expect(
                (
                  filesystem["codex_security_scan"]!["filesystem"] as Record<
                    string,
                    unknown
                  >
                )[dirname(profileFile)],
              ).toEqual({ ".": "deny" });
              if (process.platform !== "win32") {
                expect((await stat(profileFile)).mode & 0o777).toBe(0o600);
                expect((await stat(file)).mode & 0o777).toBe(0o600);
                expect((await stat(dirname(file))).mode & 0o777).toBe(0o700);
                expect((await stat(workerFile!)).mode & 0o777).toBe(0o600);
                expect((await stat(dirname(workerFile!))).mode & 0o777).toBe(
                  0o700,
                );
              }
              throw new Error("synthetic scan reached");
            },
          }),
        }),
      },
    );
    try {
      await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
        failAcl ? "synthetic ACL denial" : "synthetic scan reached",
      );
      expect(protectedDirectory).toBeDefined();
      expect(launched).toBe(!failAcl);
      if (!failAcl) {
        operation = "standard";
        await expect(client.run(repository)).rejects.toThrow(
          "synthetic scan reached",
        );
        operation = "validation";
        await expect(
          client.validate({
            repositoryPath: repository,
            finding: "Synthetic finding",
            outputDir: join(root, "validation"),
          }),
        ).rejects.toThrow("synthetic scan reached");
      }
    } finally {
      guard.mockRestore();
      await client.close();
    }
    expect(existsSync(protectedDirectory!)).toBe(false);
    if (workerFile !== undefined) {
      expect(existsSync(dirname(workerFile))).toBe(false);
    }
  },
);
