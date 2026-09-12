import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  nodePaths: [fileURLToPath(new URL("../node_modules", import.meta.url))],
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
    { type: "turn_context", timestamp: "2026-01-01T00:00:01Z", payload: { turn_id: "original-turn", model: "parent-model", effort: "high", summary: "none" } },
    { type: "turn_context", timestamp: "2026-01-01T00:02:00Z", payload: { turn_id: "later-turn", model: "later-model", effort: "low", summary: "detailed" } }
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
  assert.equal(unavailableParent.serviceTier, undefined);
  assert.equal(unavailableParent.nativeServiceTierAbsent, undefined, "missing history does not prove native absence");
  const originalOwner = { threadId: "fixture-parent", turnId: "original-turn", startedAt: "2026-01-01T00:00:00Z" };
  const [rebound, unboundLegacy] = await Promise.all([
    captureSettings({ usageOwner: originalOwner }, { filesystemDenies: [] }, parentEnvironment,
      { threadId: "fixture-other", startedAt: "2026-01-01T00:03:00Z" }),
    captureSettings({ model: "stored-model", usageOwner: null }, { filesystemDenies: [] }, parentEnvironment,
      { threadId: "fixture-other", startedAt: "2026-01-01T00:03:00Z" })
  ]);
  assert.equal(rebound.modelProvider, "openai", "takeover uses the recorded owner, not the invoking conversation");
  assert.equal(rebound.model, "parent-model", "the bound turn takes precedence over later turns");
  assert.equal(rebound.reasoningSummary, "none");
  assert.equal(unboundLegacy.model, "stored-model");
  assert.equal(unboundLegacy.modelProvider, undefined, "unrecorded legacy ownership cannot recover caller selections");
  assert.equal(unboundLegacy.reasoningSummary, undefined);
  await writeFile(join(sessionDirectory, "legacy-auto.jsonl"), [
    { type: "session_meta", payload: { id: "fixture-legacy-auto", cli_version: "0.132.0", model_provider: "openai" } },
    { type: "turn_context", payload: { turn_id: "legacy-turn", model: "legacy-model", effort: "high", summary: "auto" } }
  ].map(JSON.stringify).join("\n") + "\n");
  const legacyAuto = await captureSettings({ usageOwner: { threadId: "fixture-legacy-auto", turnId: "legacy-turn" } },
    { filesystemDenies: [] }, parentEnvironment);
  assert.equal(legacyAuto.reasoningSummary, "auto", "older native turn-context selections remain readable");
  for (const version of ["0.133.0", "0.154.0"]) {
    const threadId = `fixture-fresh-${version}`;
    await writeFile(join(sessionDirectory, `${threadId}.jsonl`), [
      { type: "session_meta", timestamp: "2026-01-01T00:00:00Z", payload: { id: threadId, cli_version: version, model_provider: "openai" } },
      { type: "turn_context", timestamp: "2026-01-01T00:00:01Z", payload: { turn_id: "fresh-turn", model: "fresh-model", effort: "high", summary: "auto" } },
      { type: "event_msg", timestamp: "2026-01-01T00:02:00Z", payload: { type: "thread_settings_applied", thread_id: threadId,
        thread_settings: { model: "fresh-model", model_provider_id: "openai", reasoning_summary: "detailed" } } }
    ].map(JSON.stringify).join("\n") + "\n");
    const owner = { threadId, turnId: "fresh-turn", startedAt: "2026-01-01T00:01:00Z" };
    const fresh = await captureSettings({ usageOwner: owner }, { filesystemDenies: [] }, parentEnvironment);
    assert.equal(fresh.model, "fresh-model");
    assert.equal(fresh.reasoningSummary, undefined, "fresh native compatibility auto is not an original selection");
    assert.equal(restoreSettings(fresh, { filesystemDenies: [] }).codexOptions.config.model_reasoning_summary, undefined);
    const freshDir = join(root, threadId);
    await loadSettings(freshDir, async () => fresh);
    const freshPath = join(freshDir, "artifacts", "deep_discovery", "execution-settings.json");
    const freshBytes = await readFile(freshPath, "utf8");
    assert.deepEqual(await loadSettings(freshDir, async () => assert.fail(), { usageOwner: owner, createdAt: owner.startedAt }), fresh);
    assert.equal(await readFile(freshPath, "utf8"), freshBytes, "unknown summary is not replaced by a compatibility field or a later selection");
    await writeFile(join(root, "config.toml"), 'model_reasoning_summary = "auto"\n');
    const explicit = await captureSettings({ usageOwner: owner }, { filesystemDenies: [] }, parentEnvironment);
    assert.equal(explicit.reasoningSummary, "auto", "an explicit original config selection still takes precedence");
    await writeFile(join(root, "config.toml"), "");
  }
  await writeFile(join(sessionDirectory, "applied.jsonl"), [
    { type: "session_meta", timestamp: "2026-01-01T00:00:00Z", payload: { id: "fixture-applied", model_provider: "previous-provider" } },
    { type: "event_msg", timestamp: "2026-01-01T00:00:01Z", payload: { type: "thread_settings_applied", thread_id: "fixture-applied",
      thread_settings: { model: "applied-model", model_provider_id: "openai", service_tier: "default", reasoning_effort: "high", reasoning_summary: "concise" } } },
    { type: "turn_context", timestamp: "2026-01-01T00:00:02Z", payload: { turn_id: "applied-turn", model: "previous-model", effort: "low", summary: "none" } },
    { type: "event_msg", timestamp: "2026-01-01T00:00:03Z", payload: { type: "thread_settings_applied", thread_id: "fixture-copied-owner",
      thread_settings: { model: "copied-model", model_provider_id: "copied-provider", service_tier: "flex", reasoning_summary: "detailed" } } },
    { type: "event_msg", timestamp: "2026-01-01T00:02:00Z", payload: { type: "thread_settings_applied", thread_id: "fixture-applied",
      thread_settings: { model: "later-model", model_provider_id: "later-provider", service_tier: "fast", reasoning_summary: "detailed" } } }
  ].map(JSON.stringify).join("\n") + "\n");
  const appliedOwner = { threadId: "fixture-applied", turnId: "applied-turn", startedAt: "2026-01-01T00:00:00Z" };
  const applied = await captureSettings({ usageOwner: appliedOwner }, { filesystemDenies: [] }, parentEnvironment,
    { threadId: "fixture-other", startedAt: "2026-01-01T00:01:00Z" });
  assert.equal(applied.serviceTier, "default", "original explicit standard routing survives later and copied snapshots");
  assert.equal(applied.reasoningSummary, "concise", "native applied summary overrides the legacy compatibility field");
  assert.equal(applied.modelProvider, "openai", "complete native snapshot replaces the session metadata provider");
  assert.equal(applied.model, "applied-model", "complete native snapshot replaces compatibility turn settings");
  assert.equal(applied.reasoningEffort, "high");
  assert.equal(applied.nativeServiceTierAbsent, undefined, "explicit native standard remains an explicit selection");
  const tierDir = join(root, "missing-tier");
  const { serviceTier: omittedTier, ...withoutTier } = applied;
  assert.equal(omittedTier, "default");
  await loadSettings(tierDir, async () => withoutTier);
  const repairedTier = await loadSettings(tierDir, async () => assert.fail(), {
    usageOwner: appliedOwner, createdAt: "2026-01-01T00:01:00Z"
  });
  assert.equal(repairedTier.serviceTier, "default");
  await writeFile(join(sessionDirectory, "applied.jsonl"), (await readFile(join(sessionDirectory, "applied.jsonl"), "utf8"))
    + JSON.stringify({ type: "event_msg", timestamp: "2026-01-01T00:00:04Z", payload: {
      type: "thread_settings_applied", thread_id: "fixture-applied",
      thread_settings: { model: "applied-model", model_provider_id: "openai", reasoning_effort: "high", service_tier: "priority" }
    } }) + "\n");
  const nativeTier = await captureSettings({ usageOwner: appliedOwner }, { filesystemDenies: [] }, parentEnvironment,
    { threadId: "fixture-other", startedAt: "2026-01-01T00:01:00Z" });
  assert.equal(nativeTier.serviceTier, "priority", "an effective tier selected by native remains unchanged");
  assert.equal(nativeTier.nativeServiceTierAbsent, undefined);
  await writeFile(join(sessionDirectory, "applied.jsonl"), (await readFile(join(sessionDirectory, "applied.jsonl"), "utf8"))
    + JSON.stringify({ type: "event_msg", timestamp: "2026-01-01T00:00:05Z", payload: {
      type: "thread_settings_applied", thread_id: "fixture-applied",
      thread_settings: { model: "applied-model", model_provider_id: "openai", reasoning_effort: "high" }
    } }) + "\n");
  const nativeDefaults = await captureSettings({ usageOwner: appliedOwner }, { filesystemDenies: [] }, parentEnvironment,
    { threadId: "fixture-other", startedAt: "2026-01-01T00:01:00Z" });
  assert.equal(nativeDefaults.model, "applied-model", "absent optional selections do not erase the required model");
  assert.equal(nativeDefaults.modelProvider, "openai", "absent optional selections do not erase the required provider");
  assert.equal(nativeDefaults.reasoningEffort, "high");
  assert.equal(nativeDefaults.serviceTier, "default", "known native absence retains its omitted request tier");
  assert.equal(nativeDefaults.nativeServiceTierAbsent, true, "known native absence is recorded separately from explicit standard");
  assert.equal(nativeDefaults.reasoningSummary, undefined, "a compatibility summary is not a recorded native default");
  const incompleteDir = join(root, "incomplete");
  const incomplete = { codexPath: process.execPath, codexHome: root, serviceTier: "flex" };
  await loadSettings(incompleteDir, async () => incomplete);
  await writeFile(join(root, "config.toml"), 'model_provider = "observer-provider"\nmodel_reasoning_summary = "detailed"\n');
  const originalRun = { model: "stored-model", reasoningEffort: "ultra", usageOwner: originalOwner,
    createdAt: "2026-01-01T00:01:00Z" };
  const repaired = await loadSettings(incompleteDir, async () => assert.fail("existing settings must not recapture current config"), originalRun);
  assert.deepEqual(repaired, { ...incomplete, model: "stored-model", reasoningEffort: "ultra",
    modelProvider: "openai", reasoningSummary: "none" });
  const repairedPath = join(incompleteDir, "artifacts", "deep_discovery", "execution-settings.json");
  const repairedBytes = await readFile(repairedPath, "utf8");
  await rm(sessionDirectory, { recursive: true });
  assert.deepEqual(await loadSettings(incompleteDir, async () => assert.fail(), originalRun), repaired);
  assert.equal(await readFile(repairedPath, "utf8"), repairedBytes, "recovered selections survive unavailable history");
  const unknownDir = join(root, "unknown");
  await loadSettings(unknownDir, async () => incomplete);
  const unknown = await loadSettings(unknownDir, async () => assert.fail(), { ...originalRun, usageOwner: null });
  assert.equal(unknown.model, "stored-model");
  assert.equal(unknown.modelProvider, undefined, "missing original ownership is not current config");
  assert.equal(unknown.reasoningSummary, undefined);
  assert.equal(unknown.nativeServiceTierAbsent, undefined);
  const unsupported = JSON.stringify({ version: 99, settings });
  await writeFile(savedPath, unsupported);
  await assert.rejects(loadSettings(join(root, "one"), async () => assert.fail()), /unsupported/);
  assert.equal(await readFile(savedPath, "utf8"), unsupported);
} finally {
  await rm(root, { recursive: true, force: true });
}
