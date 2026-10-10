import { mkdir, readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import * as runtime from "../src/runtime.js";
import type { CodexOptions } from "@openai/codex-sdk";
import { TestClient, mockWorkbench } from "./support/api-client.js";
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
    let bootstrapDirectory: string | undefined;
    let launched = false;
    let launchCount = 0;
    let checkedLaunchCount = 0;
    let operation: "deep" | "standard" | "validation" = "deep";
    const guard = spyOn(
      runtime,
      "requirePrivateCredentialHome",
    ).mockImplementation(async (metadata, path, options) => {
      if (path !== join(root, "state", "codex-home"))
        return original(metadata, path, options);
      await original(metadata, path, {
        platform: "win32",
        secureWindowsHome: async (directory) => {
          if (protectedDirectory === undefined) {
            expect(await readdir(directory)).toEqual([]);
            protectedDirectory = directory;
          }
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
        runWorkbench: async (_options, args, input) =>
          args[0] === "list-scans"
            ? { scans: [] }
            : args[0] === "get-scan"
              ? { scan: { progress: { status: "running" } } }
              : mockWorkbench(args, input),
        createCodex: (options: CodexOptions & { nativeProfile?: string }) => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              launched = true;
              launchCount++;
              expect(options.env!["CODEX_HOME"]).toBe(protectedDirectory!);
              const file = options.env!["CODEX_SECURITY_CONFIG_PATH"];
              if (operation === "validation") {
                expect(file).toBeUndefined();
              } else {
                expect(file).toBeDefined();
                bootstrapDirectory ??= dirname(file!);
                expect(dirname(file!)).toBe(bootstrapDirectory);
                expect(dirname(file!)).not.toBe(protectedDirectory);
                expect(await readFile(file!, "utf8")).not.toContain(
                  "synthetic-client-secret",
                );
              }
              // Deep Scan now composes ordinary scan sessions; their managed
              // home and configuration replace the retired worker snapshot.
              expect(
                options.env!["CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH"],
              ).toBeUndefined();
              const providers = options.config!["model_providers"] as Record<
                string,
                Record<string, unknown>
              >;
              const auth = providers["synthetic.provider"]!["auth"] as {
                env: Record<string, string>;
              };
              expect(auth.env["CLIENT_SECRET"]).toBe("synthetic-client-secret");
              // The injected factory is a trusted local caller. Native profile
              // transport and argv omission have separate real-process tests.
              const profileFile = join(protectedDirectory!, "config.toml");
              expect(await readFile(profileFile, "utf8")).toContain(
                "synthetic-client-secret",
              );
              const permissions = options.config!["permissions"] as Record<
                string,
                Record<string, unknown>
              >;
              const filesystem = permissions["codex_security_scan"]![
                "filesystem"
              ] as Record<string, unknown>;
              expect(filesystem[protectedDirectory!]).toEqual({ ".": "deny" });
              if (process.platform !== "win32") {
                expect((await stat(profileFile)).mode & 0o777).toBe(0o600);
                expect((await stat(protectedDirectory!)).mode & 0o777).toBe(
                  0o700,
                );
                if (file !== undefined) {
                  expect((await stat(file)).mode & 0o777).toBe(0o600);
                  expect((await stat(dirname(file))).mode & 0o777).toBe(0o700);
                }
              }
              checkedLaunchCount++;
              throw new Error("synthetic scan reached");
            },
          }),
        }),
      },
    );
    try {
      await expect(client.run(repository, { mode: "deep" })).rejects.toThrow(
        failAcl
          ? "synthetic ACL denial"
          : "Deep Scan reached its consecutive error limit.",
      );
      expect(protectedDirectory).toBeDefined();
      expect(launched).toBe(!failAcl);
      expect(checkedLaunchCount).toBe(launchCount);
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
        expect(checkedLaunchCount).toBe(launchCount);
      }
    } finally {
      guard.mockRestore();
      await client.close();
    }
    // Credential storage persists across clients; only bootstrap state is disposable.
    expect(existsSync(protectedDirectory!)).toBe(true);
    if (bootstrapDirectory !== undefined) {
      expect(existsSync(bootstrapDirectory)).toBe(false);
      expect(
        await readFile(join(protectedDirectory!, "config.toml"), "utf8"),
      ).not.toContain("synthetic-client-secret");
      if (process.platform !== "win32") {
        expect((await stat(protectedDirectory!)).mode & 0o777).toBe(0o700);
        expect(
          (await stat(join(protectedDirectory!, "config.toml"))).mode & 0o777,
        ).toBe(0o600);
      }
    }
  },
);
