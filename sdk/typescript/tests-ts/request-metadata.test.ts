import { writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { parse } from "smol-toml";
import { codexSecurityRequestContext } from "../src/request-metadata.js";
import { VERSION } from "../src/version.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-request-metadata-",
);
afterEach(cleanup);

test.each([
  [undefined, "openai"],
  ["openai", "openai"],
  ["amazon-bedrock", "amazon-bedrock"],
  ["cheaperinference", "cheaperinference"],
  ["openrouter", "openrouter"],
  ["fireworks", "fireworks"],
  ["ollama", "ollama"],
  ["lmstudio", "lmstudio"],
  ["synthetic.private-provider", "custom"],
] as const)("attributes provider %p as %s", (provider, expected) => {
  const context = codexSecurityRequestContext(
    provider === undefined ? {} : { model_provider: provider },
    { surface: "sdk", command: "scan" },
  );
  expect(context.metadata["codex_security_provider"]).toBe(expected);
});

test("selected profile metadata and provider win without changing telemetry settings", () => {
  const config = {
    model_provider: "openai",
    analytics: { enabled: true },
    otel: { exporter: "none" },
    responses_api_metadata: { "root.tag": "retained", "team.tag": "root" },
    profile: "selected.profile",
    profiles: {
      "selected.profile": {
        model_provider: "amazon-bedrock",
        analytics: { enabled: false },
        otel: {
          exporter: { "otlp-http": { endpoint: "http://localhost:4318" } },
        },
        responses_api_metadata: {
          "team.tag": "selected",
          codex_security_integration: "github_action",
          codex_security_surface: "spoofed",
          codex_security_command: "spoofed",
          codex_security_package_version: "spoofed",
          codex_security_plugin_version: "spoofed",
          codex_security_provider: "spoofed",
          codex_security_scan_mode: "spoofed",
        },
      },
      unused: { model_provider: "ollama" },
    },
  };
  const original = structuredClone(config);
  const context = codexSecurityRequestContext(config, {
    surface: "cli",
    command: "scan",
    pluginVersion: "1.2.3",
    mode: "deep",
  });
  expect(context.metadata).toEqual({
    "root.tag": "retained",
    "team.tag": "selected",
    codex_security_integration: "github_action",
    codex_security_surface: "cli",
    codex_security_command: "scan",
    codex_security_package_version: VERSION,
    codex_security_plugin_version: "1.2.3",
    codex_security_provider: "amazon-bedrock",
    codex_security_scan_mode: "deep",
  });
  expect(parse(context.configOverride)).toEqual({
    responses_api_metadata: context.metadata,
  });
  expect(config).toEqual(original);
});

test("leaves provider attribution to native configuration when unresolved", () => {
  const context = codexSecurityRequestContext(
    {},
    { surface: "cli", command: "patch", providerResolved: false },
  );
  expect(context.metadata).not.toHaveProperty("codex_security_provider");
  expect(context.metadata).not.toHaveProperty("codex_security_scan_mode");
  const inherited = codexSecurityRequestContext(
    { responses_api_metadata: { codex_security_provider: "amazon-bedrock" } },
    { surface: "cli", command: "patch", providerResolved: false },
  );
  expect(inherited.metadata["codex_security_provider"]).toBe("amazon-bedrock");
});

test("native table overrides preserve inherited literal metadata and opt-outs", async () => {
  const home = await temporaryDirectory();
  await writeFile(
    join(home, "config.toml"),
    '[analytics]\nenabled=false\n[responses_api_metadata]\n"home.tag"="preserved"\ncodex_security_integration="github_action"\n',
  );
  const context = codexSecurityRequestContext(
    { responses_api_metadata: { "caller.tag": "synthetic" } },
    { surface: "cli", command: "publish", providerResolved: false },
  );
  const { readDeepScanRuntimeConfig } = await import(
    pathToFileURL(join(PLUGIN_ROOT, "mcp", "permission-profile-preflight.mjs"))
      .href
  );
  const config = await readDeepScanRuntimeConfig({
    codexPath: resolveCodexCommand({}).command,
    // Native descendants can hold their working directory open on Windows.
    cwd: dirname(home),
    configOverrides: [context.configOverride],
    env: {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      CODEX_HOME: home,
    },
    signal: new AbortController().signal,
  });
  expect(config.responses_api_metadata).toEqual({
    "home.tag": "preserved",
    codex_security_integration: "github_action",
    ...context.metadata,
  });
  expect(config.analytics).toEqual({ enabled: false });
});
