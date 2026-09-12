import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  define: { "import.meta.url": JSON.stringify(new URL("../src/deep-scan/recovery-settings.ts", import.meta.url).href) },
  entryPoints: [new URL("../src/deep-scan/recovery-settings.ts", import.meta.url).pathname],
  format: "esm",
  platform: "node",
  write: false
});
const { captureDeepScanExecutionSettings: captureSettings, restoredDeepScanWorkerSettings: restoreSettings, loadOrCaptureDeepScanExecutionSettings: loadSettings } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);
const root = await mkdtemp(join(tmpdir(), "deep-settings-"));
try {
  const settings = {
    codexPath: "/fixture/runtime/codex",
    codexHome: "/fixture/account",
    model: "fixture-model",
    modelProvider: "fixture-provider",
    reasoningEffort: "high",
    reasoningSummary: "detailed",
    serviceTier: "fast"
  };
  const first = await loadSettings(join(root, "one"), async () => ({
    ...settings,
    apiKey: "synthetic-do-not-persist",
    env: { CODEX_API_KEY: "synthetic-do-not-persist" }
  }));
  assert.deepEqual(first, settings);
  const savedPath = join(root, "one", "artifacts", "deep_discovery", "execution-settings.json");
  const saved = await readFile(savedPath, "utf8");
  assert.equal(saved.includes("synthetic-do-not-persist"), false);
  const [recovered, concurrent] = await Promise.all([
    loadSettings(join(root, "one"), async () => assert.fail("recovery recaptured observer settings")),
    loadSettings(join(root, "two"), async () => ({ ...settings, model: "other-model" }))
  ]);
  assert.deepEqual(recovered, settings);
  assert.equal(concurrent.model, "other-model");
  assert.equal(await readFile(savedPath, "utf8"), saved);
  recovered.model = "caller-mutation";
  assert.deepEqual(await loadSettings(join(root, "one"), async () => assert.fail()), settings);
  const configPath = join(root, "runtime.toml");
  await writeFile(configPath, `model = "inherited-model"
model_provider = "custom"
profile = "scan"
[profiles.scan]
model_reasoning_summary = "concise"
service_tier = "flex"
[model_providers.custom]
name = "Fixture"
http_headers = { Authorization = "synthetic-secret" }
`);
  const captured = await captureSettings({ model: "original-model", reasoningEffort: "ultra" }, {
    filesystemDenies: ["/fixture/original-deny"], globScanMaxDepth: 3
  }, { CODEX_CLI_PATH: process.execPath, CODEX_HOME: root, CODEX_SECURITY_CONFIG_PATH: configPath });
  assert.equal(captured.model, "original-model");
  assert.equal(captured.modelProvider, "custom");
  assert.equal(captured.reasoningSummary, "concise");
  assert.equal(captured.serviceTier, "flex");
  assert.equal(captured.providerConfig, undefined);
  assert.equal(JSON.stringify(captured).includes("synthetic-secret"), false);
  let credential = "synthetic-first";
  const restored = restoreSettings(captured, { filesystemDenies: ["/fixture/current-deny"] }, () => ({
    CODEX_API_KEY: credential, CODEX_HOME: "/fixture/observer-home", CODEX_CLI_PATH: "/fixture/observer-codex"
  }));
  assert.equal(restored.codexOptions.env.CODEX_API_KEY, "synthetic-first");
  credential = "synthetic-refreshed";
  assert.equal(restored.codexOptions.env.CODEX_API_KEY, "synthetic-refreshed");
  assert.equal(restored.codexOptions.env.CODEX_HOME, root);
  assert.equal(restored.codexOptions.env.CODEX_CLI_PATH, captured.codexPath);
  assert.deepEqual(restored.parentSandbox.filesystemDenies, ["/fixture/original-deny", "/fixture/current-deny"]);
  assert.equal(restored.codexOptions.config.model_reasoning_effort, "ultra");
  await writeFile(join(root, "config.toml"), 'model = "native-home-model"\n');
  const native = await captureSettings({}, { filesystemDenies: [] }, { CODEX_CLI_PATH: process.execPath, CODEX_HOME: root });
  assert.equal(native.model, "native-home-model");
  const unsupported = JSON.stringify({ version: 99, settings });
  await writeFile(savedPath, unsupported);
  await assert.rejects(loadSettings(join(root, "one"), async () => assert.fail()), /unsupported/);
  assert.equal(await readFile(savedPath, "utf8"), unsupported);
} finally {
  await rm(root, { recursive: true, force: true });
}
