import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
  const sessionDirectory = join(root, "sessions");
  await mkdir(sessionDirectory);
  await writeFile(join(sessionDirectory, "parent.jsonl"), [
    { type: "session_meta", timestamp: "2026-01-01T00:00:00Z", payload: { id: "fixture-parent", model_provider: "openai" } },
    { type: "turn_context", timestamp: "2026-01-01T00:00:01Z", payload: { model: "parent-model", effort: "high", summary: "none" } },
    { type: "turn_context", timestamp: "2026-01-01T00:02:00Z", payload: { model: "later-model", effort: "low", summary: "detailed" } }
  ].map(JSON.stringify).join("\n") + "\n");
  await writeFile(join(sessionDirectory, "other.jsonl"), JSON.stringify({
    type: "session_meta", payload: { id: "fixture-other", model_provider: "other-provider" }
  }) + "\n");
  const parentSettings = await captureSettings({}, { filesystemDenies: [] }, {
    CODEX_CLI_PATH: process.execPath, CODEX_HOME: root
  }, { threadId: "fixture-parent", startedAt: "2026-01-01T00:01:00Z" });
  assert.equal(parentSettings.model, "native-home-model", "explicit config retains precedence");
  assert.equal(parentSettings.modelProvider, "openai");
  assert.equal(parentSettings.reasoningSummary, "none", "later owner turns are not original discovery settings");
  assert.equal(parentSettings.reasoningEffort, "high");
  await writeFile(join(root, "config.toml"), "");
  const parentEnvironment = { CODEX_CLI_PATH: process.execPath, CODEX_HOME: root };
  const [originalParent, otherParent, unavailableParent] = await Promise.all([
    captureSettings({}, { filesystemDenies: [] }, parentEnvironment,
      { threadId: "fixture-parent", startedAt: "2026-01-01T00:00:01Z" }),
    captureSettings({}, { filesystemDenies: [] }, parentEnvironment,
      { threadId: "fixture-other", startedAt: "2026-01-01T00:00:01Z" }),
    captureSettings({ model: "stored-model", reasoningEffort: "ultra" }, { filesystemDenies: [] }, parentEnvironment,
      { threadId: "fixture-unavailable", startedAt: "2026-01-01T00:00:01Z" })
  ]);
  assert.equal(originalParent.model, "parent-model");
  assert.equal(originalParent.reasoningSummary, "none", "the original turn is included at its timestamp");
  assert.equal(otherParent.modelProvider, "other-provider");
  assert.equal(otherParent.model, undefined, "concurrent scans do not borrow another parent's model");
  assert.equal(otherParent.reasoningSummary, undefined);
  assert.equal(unavailableParent.model, "stored-model");
  assert.equal(unavailableParent.reasoningEffort, "ultra");
  assert.equal(unavailableParent.modelProvider, undefined, "missing history does not establish a provider");
  assert.equal(unavailableParent.reasoningSummary, undefined);
  const unsupported = JSON.stringify({ version: 99, settings });
  await writeFile(savedPath, unsupported);
  await assert.rejects(loadSettings(join(root, "one"), async () => assert.fail()), /unsupported/);
  assert.equal(await readFile(savedPath, "utf8"), unsupported);
} finally {
  await rm(root, { recursive: true, force: true });
}
