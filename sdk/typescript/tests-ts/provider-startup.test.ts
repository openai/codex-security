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

test.each([false, true])(
  "native startup receives managed provider metadata without credentials (profile: %j)",
  async (profile) => {
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
const child = spawnSync(${JSON.stringify(native.command)}, [
  "-c", 'model_provider="required.gateway"', ...args,
], { stdio: "inherit", env: process.env });
if (child.error) throw child.error;
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
          OPENAI_API_KEY: "synthetic-startup-key",
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
    await expect(client.run(repository)).rejects.toThrow(
      "synthetic execution reached",
    );
    const launches: string[][] = (await readFile(capture, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const startup = launches.filter(
      (args) => args.includes("sandbox") || args.includes("plugin"),
    );
    if (process.platform !== "win32")
      expect(startup.some((args) => args.includes("sandbox"))).toBe(true);
    expect(startup.some((args) => args.includes("marketplace"))).toBe(true);
    for (const args of startup) {
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
