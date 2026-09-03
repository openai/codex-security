import assert from "node:assert/strict";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { build } from "esbuild";

const applicationRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const guidanceBundle = await build({
  bundle: true,
  entryPoints: [path.join(applicationRoot, "src/model-guidance.ts")],
  format: "esm",
  platform: "node",
  write: false,
});
const { isNonAstraCyberModel, isBelowXhigh, scanModelGuidance } = await import(
  `data:text/javascript;base64,${Buffer.from(guidanceBundle.outputFiles[0].contents).toString("base64")}`
);

for (const model of [
  "gpt-5.5-cyber-preview",
  "gpt-5.6-cyber-sol-preview",
  "example-cyber",
  "CYBER-preview",
]) {
  assert.equal(isNonAstraCyberModel(model), true, model);
}
for (const model of [
  "astra-cyber-preview",
  "gpt-6-astra-cyber",
  "gpt-5.6-sol",
  "examplecyber",
  "cybernetics-model",
]) {
  assert.equal(isNonAstraCyberModel(model), false, model);
}
for (const effort of ["none", "minimal", "low", "medium", "high"]) {
  assert.equal(isBelowXhigh(effort), true, effort);
}
for (const effort of [
  "xhigh",
  "max",
  "ultra",
  "persistent",
  "",
  "unrecognized",
]) {
  assert.equal(isBelowXhigh(effort), false, effort);
}

const model = (name, extra = {}) => ({
  id: name,
  model: name,
  hidden: false,
  isDefault: false,
  supportedReasoningEfforts: ["high", "xhigh", "max"].map(
    (reasoningEffort) => ({ reasoningEffort }),
  ),
  ...extra,
});
const current = model("example-cyber", { upgrade: "scan-upgrade" });
const upgrade = model("scan-upgrade");
const catalog = [current, upgrade, model("scan-default", { isDefault: true })];
const advice = scanModelGuidance(
  { model: current.model, reasoningEffort: "high" },
  catalog,
);
assert.match(advice, /dynamic exploitation/);
assert.match(advice, /scan-upgrade/);
assert.doesNotMatch(
  advice,
  /scan-default/,
  "Prefer the declared non-cyber upgrade to an unrelated default.",
);
assert.match(advice, /use xhigh reasoning/);
assert.doesNotMatch(
  scanModelGuidance({ model: "astra-cyber", reasoningEffort: "xhigh" }),
  /dynamic exploitation/,
);
assert.doesNotMatch(
  scanModelGuidance({ model: current.model, reasoningEffort: "max" }, catalog),
  /use xhigh reasoning/,
);
assert.doesNotMatch(
  scanModelGuidance({ model: current.model, reasoningEffort: "unrecognized" }, [
    model(current.model, {
      supportedReasoningEfforts: ["max", "unrecognized", "xhigh"].map(
        (reasoningEffort) => ({ reasoningEffort }),
      ),
    }),
  ]),
  /use xhigh reasoning/,
  "Catalog position does not classify an unfamiliar effort as lower.",
);
assert.doesNotMatch(
  scanModelGuidance({ model: current.model, reasoningEffort: "high" }, [
    model(current.model, {
      supportedReasoningEfforts: [{ reasoningEffort: "high" }],
    }),
  ]),
  /use xhigh reasoning/,
  "Do not suggest an unsupported effort.",
);
assert.doesNotMatch(
  scanModelGuidance({}),
  /Would you like|would you like/,
  "Unknown settings do not establish an upgrade.",
);

const temporaryRoot = await mkdtemp(
  path.join(tmpdir(), "codex-security-model-guidance-"),
);
try {
  const runtimeBundle = path.join(temporaryRoot, "server.cjs");
  await build({
    bundle: true,
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": "__filename",
    },
    entryPoints: [path.join(applicationRoot, "main.ts")],
    external: ["fsevents"],
    format: "cjs",
    loader: { ".md": "text" },
    logLevel: "silent",
    outfile: runtimeBundle,
    platform: "node",
    target: "node20",
  });
  await assertGuidanceRuntime(runtimeBundle);
  const bundledPluginRoot =
    process.env.CODEX_SECURITY_TEST_PLUGIN_ROOT ??
    path.resolve(applicationRoot, "../../../sdk/typescript/_bundled_plugin");
  await assertGuidanceRuntime(path.join(bundledPluginRoot, "mcp/server.mjs"));
  assert.deepEqual(
    await readdir(temporaryRoot),
    ["server.cjs"],
    "Advisories must not create scan or configuration state.",
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function assertGuidanceRuntime(runtimeBundle) {
  const client = new Client({ name: "model-guidance-test", version: "1.0.0" });
  try {
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [runtimeBundle, "--stdio"],
        env: {
          ...process.env,
          CODEX_CLI_PATH: path.join(temporaryRoot, "missing-codex"),
          CODEX_SECURITY_STATE_DIR: path.join(temporaryRoot, "state"),
          CODEX_SECURITY_SCAN_ROOT: path.join(temporaryRoot, "scans"),
        },
      }),
    );
    const tool = (await client.listTools()).tools.find(
      ({ name }) => name === "get_codex_security_model_guidance",
    );
    assert.ok(tool);
    assert.equal(tool.annotations.readOnlyHint, true);
    assert.equal(tool.annotations.destructiveHint, false);
    assert.deepEqual(tool.inputSchema.properties, {});

    for (const settings of [
      { model: "gpt-5.5-cyber-preview", reasoningEffort: "high" },
      { model: "astra-cyber-preview", reasoningEffort: "xhigh" },
      { model: "gpt-5.6-sol", reasoningEffort: "ultra" },
      {},
    ]) {
      const result = await client.callTool({
        name: tool.name,
        arguments: {},
        _meta: {
          "codex/sandbox-state-meta": {
            sandboxCwd: pathToFileURL(temporaryRoot).href,
          },
          "x-codex-turn-metadata": {
            model: settings.model,
            reasoning_effort: settings.reasoningEffort,
          },
        },
      });
      assert.equal(result.isError, undefined);
      assert.deepEqual(result.content, [
        { type: "text", text: scanModelGuidance(settings) },
      ]);
      assert.equal(result.structuredContent, undefined);
    }
  } finally {
    await client.close();
  }
}
