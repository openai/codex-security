import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { probeCodexSandbox, resolveCodexCommand } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

test.each(
  [false, true].flatMap((profile) =>
    [
      "startup",
      "refresh",
      "scan-account",
      "account",
      "api-key",
      "logout",
      "browser",
      "device",
    ].map((operation) => ({ profile, operation })),
  ),
)(
  "native $operation receives managed provider metadata without credentials (profile: $profile)",
  async ({ profile, operation }) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const output = join(root, "scan");
    const ambientHome = join(root, "ambient-home");
    const capture = join(root, "startup.jsonl");
    const launcher = join(root, "managed-startup.mjs");
    await mkdir(repository);
    await mkdir(ambientHome, { mode: 0o700 });
    await mkdir(output, { mode: 0o700 });
    const native = resolveCodexCommand({});
    await writeFile(
      launcher,
      `
import { appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const original = process.argv.slice(2);
appendFileSync(${JSON.stringify(capture)}, JSON.stringify(original) + "\\n");
const args = [];
for (let index = 0; index < original.length; index++) {
  const value = original[index];
  if (value === "-c" || value === "--config") {
    const setting = original[++index];
    // Reproduce managed provider precedence without changing the host's policy.
    if (!setting.startsWith("model_provider=")) args.push(value, setting);
  } else args.push(value);
}
const sandbox = args.indexOf("sandbox");
// Exercise native configuration loading without requiring a kernel sandbox.
if (sandbox >= 0) args.splice(sandbox, args.length - sandbox, "plugin", "list", "--json");
const login = args.indexOf("login");
const interactive = login >= 0 && !args.includes("status") && !args.includes("--with-api-key");
// Use the real native config loader, then simulate only the network login step.
if (interactive) args.splice(login, args.length - login, "plugin", "list", "--json");
const child = spawnSync(${JSON.stringify(native.command)}, [
  "-c", 'model_provider="required.gateway"',
  "-c", 'cli_auth_credentials_store="file"', ...args,
], { stdio: "inherit", env: process.env });
if (child.error) throw child.error;
if (child.status === 0 && interactive) {
  console.log("https://login.example.test/device");
  console.log("ABCD-EFGH");
}
process.exit(child.status ?? 1);
`,
    );
    const provider = {
      name: "Synthetic managed provider",
      wire_api: "responses",
      base_url: "https://provider.example.test/v1",
      experimental_bearer_token: "synthetic-private-bearer",
      http_headers: { "X-Synthetic": "synthetic-private-header" },
      auth: {
        command: "synthetic-auth",
        env: { CLIENT_SECRET: "synthetic-private-command-secret" },
      },
    };
    await using client = new TestClient(
      {
        pluginPath: PLUGIN_ROOT,
        codexOverrides: profile
          ? {
              profile: "selected",
              profiles: {
                selected: { model_providers: { "required.gateway": provider } },
              },
            }
          : { model_providers: { "required.gateway": provider } },
      },
      {
        environment: {
          CODEX_HOME: ambientHome,
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
          ...(["startup", "refresh"].includes(operation)
            ? { OPENAI_API_KEY: "synthetic-startup-key" }
            : {}),
        },
        resolveCodexCommand: () => ({
          command: process.execPath,
          args: [launcher],
        }),
        probeCodexSandbox,
        resolvePluginPython: async () => "/managed/python",
        prepareOutputDir: async () => output,
        repositoryRevision: async () => "deadbeef",
        createCodex: () => {
          throw new Error("synthetic execution reached");
        },
      },
    );
    if (operation === "startup" || operation === "refresh") {
      await expect(client.run(repository)).rejects.toThrow(
        "synthetic execution reached",
      );
      if (operation === "refresh") {
        await expect(client.run(repository)).rejects.toThrow(
          "synthetic execution reached",
        );
      }
    } else if (operation === "scan-account") {
      await expect(client.run(repository)).rejects.toThrow(
        "No credentials were found",
      );
    } else if (operation === "account") {
      const status = await client.account();
      expect(status.authenticated).toBe(false);
      expect(status.details).toContain("Not logged in");
      expect(status.details).not.toContain("Model provider");
    } else if (operation === "api-key") {
      await client.loginApiKey("synthetic-login-key");
      expect((await client.account()).authenticated).toBe(true);
    } else if (operation === "logout") {
      await client.logout();
    } else {
      const handle = await (operation === "device"
        ? client.loginChatGPTDeviceCode()
        : client.loginChatGPT());
      expect((await handle.wait()).success).toBe(true);
      expect(handle.authUrl).toBe("https://login.example.test/device");
      if (operation === "device") expect(handle.userCode).toBe("ABCD-EFGH");
    }
    const launches: string[][] = (await readFile(capture, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const startup = launches.filter(
      (args) => args.includes("sandbox") || args.includes("plugin"),
    );
    if (["startup", "refresh", "scan-account"].includes(operation)) {
      if (process.platform !== "win32")
        expect(startup.some((args) => args.includes("sandbox"))).toBe(true);
      expect(
        startup.filter((args) => args.includes("marketplace")),
      ).toHaveLength(operation === "refresh" ? 2 : 1);
    }
    expect(launches.length).toBeGreaterThan(0);
    for (const args of launches) {
      const overrides = args.flatMap((arg, index) =>
        arg === "-c" || arg === "--config" ? [args[index + 1]!] : [],
      );
      expect(parseToml(overrides.join("\n"))).toMatchObject({
        model_providers: {
          "required.gateway": {
            name: provider.name,
            wire_api: provider.wire_api,
          },
        },
      });
      expect(args.join("\n")).not.toContain("synthetic-private-");
      expect(args.join("\n")).not.toContain("synthetic-auth");
    }
  },
);
