import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
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
const { captureDeepScanExecutionSettings: captureSettings, restoredDeepScanWorkerSettings: restoreSettings, loadDeepScanExecutionSettings: loadSettings } = await import(
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
  const globSandbox = (depth) => ({
    filesystemDenies: ["/fixture/**/*.secret"],
    ...(depth === undefined ? {} : { globScanMaxDepth: depth })
  });
  for (const [originalDepth, currentDepth, expectedDepth] of [
    [2, 5, 5], [5, 2, 5], [undefined, 2, undefined], [2, undefined, undefined]
  ]) {
    const restored = restoreSettings({ ...settings, parentSandbox: globSandbox(originalDepth) },
      globSandbox(currentDepth));
    assert.equal(restored.parentSandbox.globScanMaxDepth, expectedDepth,
      `deny expansion must preserve both policies: ${originalDepth}, ${currentDepth}`);
  }
  assert.equal(restoreSettings(settings, globSandbox(2)).parentSandbox.globScanMaxDepth, 2,
    "unavailable historical policy does not establish uncapped glob expansion");
  assert.equal(restoreSettings({ ...settings, parentSandbox: globSandbox(2) }, {
    filesystemDenies: ["/fixture/exact-denial"]
  }).parentSandbox.globScanMaxDepth, 2, "exact denials do not change glob expansion");
  const writeSnapshot = async (directory, value) => {
    const path = join(directory, "artifacts", "deep_discovery", "execution-settings.json");
    await mkdir(join(directory, "artifacts", "deep_discovery"), { recursive: true });
    await writeFile(path, JSON.stringify({ version: 1, settings: value }, null, 2) + "\n");
  };
  await assert.rejects(loadSettings(join(root, "missing")), /no recorded original execution settings/);
  await writeSnapshot(join(root, "one"), settings);
  await writeSnapshot(join(root, "two"), { ...settings, model: "other-model" });
  const savedPath = join(root, "one", "artifacts", "deep_discovery", "execution-settings.json");
  const saved = await readFile(savedPath, "utf8");
  const [recovered, concurrent] = await Promise.all([
    loadSettings(join(root, "one")), loadSettings(join(root, "two"))
  ]);
  assert.deepEqual(recovered, settings);
  assert.equal(concurrent.model, "other-model");
  assert.equal(await readFile(savedPath, "utf8"), saved);
  recovered.model = "caller-mutation";
  assert.deepEqual(await loadSettings(join(root, "one")), settings);
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
  for (const modelProvider of ["openrouter", "fireworks", "amazon-bedrock"]) {
    await writeFile(configPath, `model_provider = ${JSON.stringify(modelProvider)}
[model_providers.${modelProvider}.aws]
region = "us-west-2"
profile = "fixture-profile"
access_key_id = "synthetic-secret"
`);
    const selected = await captureSettings({}, { filesystemDenies: [] }, {
      CODEX_CLI_PATH: process.execPath, CODEX_HOME: root, CODEX_SECURITY_CONFIG_PATH: configPath
    });
    assert.equal(selected.modelProvider, modelProvider);
    const expectedProvider = modelProvider === "amazon-bedrock"
      ? { "amazon-bedrock": { aws: { region: "us-west-2", profile: "fixture-profile" } } } : undefined;
    assert.deepEqual(selected.providerConfig, expectedProvider,
      "saved selections exclude catalog definitions and retain Bedrock selectors");
    const providerDir = join(root, modelProvider);
    await writeSnapshot(providerDir, selected);
    const path = join(providerDir, "artifacts", "deep_discovery", "execution-settings.json");
    const bytes = await readFile(path, "utf8");
    assert.equal(bytes.includes("synthetic-secret"), false);
    const restoredProvider = restoreSettings(await loadSettings(providerDir), { filesystemDenies: [] })
      .codexOptions.config.model_providers;
    if (expectedProvider) assert.deepEqual(restoredProvider, expectedProvider);
    else assert.deepEqual(Object.keys(restoredProvider[modelProvider]).sort(),
      ["base_url", "env_key", "name", "wire_api"]);
    assert.equal(await readFile(path, "utf8"), bytes);
    // Older snapshots can contain catalog definitions. Reading them must not
    // rewrite their bytes or prevent the existing launch projection.
    if (!expectedProvider) {
      await writeSnapshot(providerDir, { ...selected, providerConfig: restoredProvider });
      const legacyBytes = await readFile(path, "utf8");
      const legacy = await loadSettings(providerDir);
      assert.equal(legacy.providerConfig, undefined);
      assert.deepEqual(restoreSettings(legacy, { filesystemDenies: [] }).codexOptions.config.model_providers,
        restoredProvider);
      assert.equal(await readFile(path, "utf8"), legacyBytes);
    }
  }
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
  for (const workflowVersion of ["deep-security-scan/v1", "deep-scan-mcp/v1"]) {
    const legacyDir = join(root, workflowVersion.replaceAll("/", "-"));
    const legacy = await loadSettings(legacyDir, {
      workflowVersion, model: "recorded-model", reasoningEffort: "ultra",
      createdAt: "2026-01-01T00:01:00Z", usageOwner: null
    }, async () => ({ config: { model_reasoning_summary: "concise", service_tier: "flex" },
      usageOwner: originalOwner }), parentEnvironment);
    assert.equal(legacy.model, "recorded-model");
    assert.equal(legacy.reasoningSummary, "concise", "recorded recipe retains precedence");
    assert.equal(legacy.modelProvider, "openai", "recorded original owner supplies native selections");
    assert.equal(legacy.serviceTier, "flex");
    assert.equal(legacy.codexPath, undefined, "legacy metadata did not record an executable");
    assert.equal(legacy.codexHome, undefined, "a history lookup home is not recorded execution provenance");
    const restoredLegacy = restoreSettings(legacy, { filesystemDenies: ["/fixture/current-deny"] },
      () => ({ CODEX_HOME: "/fixture/runtime-home", CODEX_CLI_PATH: "/fixture/runtime-codex",
        CODEX_API_KEY: "synthetic-live-key" }));
    assert.equal(restoredLegacy.codexOptions.env.CODEX_HOME, "/fixture/runtime-home");
    assert.equal(restoredLegacy.codexOptions.env.CODEX_CLI_PATH, "/fixture/runtime-codex");
    assert.equal(restoredLegacy.codexOptions.config.model_reasoning_summary, "concise");
    await assert.rejects(readFile(join(legacyDir, "artifacts/deep_discovery/execution-settings.json")),
      { code: "ENOENT" });
  }
  await assert.rejects(loadSettings(join(root, "missing-v2"), { workflowVersion: "deep-security-scan/v2" },
    async () => assert.fail("missing promised v2 settings must not become legacy recovery")), /no recorded original/);
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
    await writeSnapshot(freshDir, fresh);
    const freshPath = join(freshDir, "artifacts", "deep_discovery", "execution-settings.json");
    const freshBytes = await readFile(freshPath, "utf8");
    assert.deepEqual(await loadSettings(freshDir, { usageOwner: owner, createdAt: owner.startedAt }), fresh);
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
  await writeSnapshot(tierDir, withoutTier);
  const repairedTier = await loadSettings(tierDir, {
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
  await writeSnapshot(incompleteDir, incomplete);
  await writeFile(join(root, "config.toml"), 'model_provider = "observer-provider"\nmodel_reasoning_summary = "detailed"\n');
  const originalRun = { model: "stored-model", reasoningEffort: "ultra", usageOwner: originalOwner,
    createdAt: "2026-01-01T00:01:00Z" };
  const raceDir = join(root, "concurrent-recovery");
  await writeSnapshot(raceDir, incomplete);
  const racePath = join(raceDir, "artifacts", "deep_discovery", "execution-settings.json");
  const originalCreateReadStream = fs.createReadStream;
  const readingHistory = Promise.withResolvers();
  const releaseHistory = Promise.withResolvers();
  let held = false;
  let pendingRead;
  fs.createReadStream = (path, options) => {
    const source = originalCreateReadStream(path, options);
    if (path !== join(sessionDirectory, "parent.jsonl") || held) return source;
    held = true;
    const delayed = new PassThrough();
    source.once("error", (error) => delayed.destroy(error));
    delayed.once("close", () => source.destroy());
    void releaseHistory.promise.then(() => source.pipe(delayed));
    readingHistory.resolve();
    return delayed;
  };
  syncBuiltinESMExports();
  try {
    pendingRead = loadSettings(raceDir, originalRun);
    await Promise.race([readingHistory.promise, pendingRead.then(() =>
      assert.fail("historical recovery must reach the controlled history read"))]);
    const newer = { ...settings, modelProvider: "newer-provider", reasoningSummary: "concise" };
    await writeSnapshot(raceDir, newer);
    const newerBytes = await readFile(racePath, "utf8");
    releaseHistory.resolve();
    const delayedProjection = await pendingRead;
    assert.equal(delayedProjection.modelProvider, "openai");
    assert.equal(delayedProjection.reasoningSummary, "none");
    assert.equal(await readFile(racePath, "utf8"), newerBytes,
      "a delayed historical projection must not overwrite a newer snapshot");
    assert.deepEqual(await loadSettings(raceDir), newer);
  } finally {
    releaseHistory.resolve();
    await pendingRead?.catch(() => {});
    fs.createReadStream = originalCreateReadStream;
    syncBuiltinESMExports();
  }
  const incompletePath = join(incompleteDir, "artifacts", "deep_discovery", "execution-settings.json");
  const incompleteBytes = await readFile(incompletePath, "utf8");
  const repaired = await loadSettings(incompleteDir, originalRun);
  assert.deepEqual(repaired, { ...incomplete, model: "stored-model", reasoningEffort: "ultra",
    modelProvider: "openai", reasoningSummary: "none" });
  assert.equal(await readFile(incompletePath, "utf8"), incompleteBytes,
    "recovering historical fields is read-only");
  await rm(sessionDirectory, { recursive: true });
  const unavailable = await loadSettings(incompleteDir, originalRun);
  assert.equal(unavailable.model, "stored-model");
  assert.equal(unavailable.reasoningEffort, "ultra");
  assert.equal(unavailable.modelProvider, undefined, "unavailable history remains unknown");
  assert.equal(unavailable.reasoningSummary, undefined);
  assert.equal(await readFile(incompletePath, "utf8"), incompleteBytes);
  const unknownDir = join(root, "unknown");
  await writeSnapshot(unknownDir, incomplete);
  const unknown = await loadSettings(unknownDir, { ...originalRun, usageOwner: null });
  assert.equal(unknown.model, "stored-model");
  assert.equal(unknown.modelProvider, undefined, "missing original ownership is not current config");
  assert.equal(unknown.reasoningSummary, undefined);
  assert.equal(unknown.nativeServiceTierAbsent, undefined);
  const unsupported = JSON.stringify({ version: 99, settings });
  await writeFile(savedPath, unsupported);
  await assert.rejects(loadSettings(join(root, "one")), /unsupported/);
  assert.equal(await readFile(savedPath, "utf8"), unsupported);
} finally {
  await rm(root, { recursive: true, force: true });
}
