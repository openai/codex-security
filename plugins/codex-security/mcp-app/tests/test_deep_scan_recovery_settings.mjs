import assert from "node:assert/strict";
import {
  appendFile,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import * as zlib from "node:zlib";
import { importModule } from "./import-module.ts";

const entry = new URL("../src/deep-scan/recovery-settings.ts", import.meta.url);
const module = await importModule({
  nodePaths: [fileURLToPath(new URL("../node_modules", import.meta.url))],
  define: { "import.meta.url": JSON.stringify(entry.href) },
  entryPoints: [fileURLToPath(entry)],
});
const {
  captureDeepScanExecutionSettings: captureSettings,
  retainDeepScanExecutionSettings: retainSettings,
  restoredDeepScanWorkerSettings: restoreSettings,
  loadDeepScanExecutionSettings: loadRecordedSettings,
} = module;
function loadSnapshot(settings, run = {}) {
  return loadRecordedSettings({
    ...run,
    executionSettings: { version: 1, settings },
  });
}

function rollout(records) {
  return records.map((record) => JSON.stringify(record) + "\n").join("");
}

function settingsApplied(timestamp, thread_id, thread_settings) {
  return {
    type: "event_msg",
    timestamp,
    payload: { type: "thread_settings_applied", thread_id, thread_settings },
  };
}

const noDenials = { filesystemDenies: [] };
const root = await mkdtemp(join(tmpdir(), "deep-settings-"));
try {
  const parentEnvironment = {
    CODEX_CLI_PATH: process.execPath,
    CODEX_HOME: root,
  };
  const capture = (original, parent) =>
    captureSettings(original, noDenials, parentEnvironment, parent);
  const retainedConfigPath = join(root, "retained-settings.toml");
  const retainCurrent = () =>
    retainSettings(() =>
      captureSettings({}, noDenials, {
        ...parentEnvironment,
        CODEX_SECURITY_CONFIG_PATH: retainedConfigPath,
      }),
    );
  const owningCall = retainCurrent();
  await writeFile(retainedConfigPath, "broken = [");
  await assert.rejects(owningCall({}));
  await writeFile(
    retainedConfigPath,
    'service_tier="default"\nmodel_reasoning_summary="concise"\n',
  );
  const retainedCaptured = await owningCall({});
  await writeFile(
    retainedConfigPath,
    'service_tier="fast"\nmodel_reasoning_summary="detailed"\n',
  );
  assert.deepEqual(
    await owningCall({ coordinatorGeneration: 2 }),
    retainedCaptured,
  );
  const independent = await retainCurrent()({});
  assert.equal(independent.serviceTier, "fast");
  assert.equal(independent.reasoningSummary, "detailed");
  assert.equal(retainedCaptured.serviceTier, "default");
  assert.equal(retainedCaptured.reasoningSummary, "concise");

  const settings = {
    codexPath: "/fixture/runtime/codex",
    codexHome: "/fixture/account",
    model: "fixture-model",
    modelProvider: "fixture-provider",
    reasoningEffort: "high",
    reasoningSummary: "detailed",
    serviceTier: "fast",
  };
  const globSandbox = (depth) => ({
    filesystemDenies: ["/fixture/**/*.secret"],
    ...(depth === undefined ? {} : { globScanMaxDepth: depth }),
  });
  for (const [originalDepth, currentDepth, expectedDepth] of [
    [2, 5, 5],
    [5, 2, 5],
    [undefined, 2, undefined],
    [2, undefined, undefined],
  ]) {
    const restored = restoreSettings(
      { ...settings, parentSandbox: globSandbox(originalDepth) },
      globSandbox(currentDepth),
    );
    assert.equal(
      restored.parentSandbox.globScanMaxDepth,
      expectedDepth,
      `deny expansion must preserve both policies: ${originalDepth}, ${currentDepth}`,
    );
  }
  assert.equal(
    restoreSettings(settings, globSandbox(2)).parentSandbox.globScanMaxDepth,
    2,
    "unavailable historical policy does not establish uncapped glob expansion",
  );
  assert.equal(
    restoreSettings(
      { ...settings, parentSandbox: globSandbox(2) },
      {
        filesystemDenies: ["/fixture/exact-denial"],
      },
    ).parentSandbox.globScanMaxDepth,
    2,
    "exact denials do not change glob expansion",
  );
  const [recovered, concurrent] = await Promise.all([
    loadSnapshot(settings),
    loadSnapshot({ ...settings, model: "other-model" }),
  ]);
  assert.deepEqual(recovered, settings);
  assert.equal(concurrent.model, "other-model");
  recovered.model = "caller-mutation";
  assert.equal(settings.model, "fixture-model");
  const configPath = join(root, "runtime.toml");
  await writeFile(
    configPath,
    `model = "inherited-model"
model_provider = "custom"
profile = "scan"
[profiles.scan]
model_reasoning_summary = "concise"
service_tier = "flex"
[model_providers.custom]
name = "Fixture"
http_headers = { Authorization = "synthetic-secret" }
`,
  );
  const captured = await captureSettings(
    { model: "original-model", reasoningEffort: "ultra" },
    {
      filesystemDenies: ["/fixture/original-deny"],
      globScanMaxDepth: 3,
    },
    {
      ...parentEnvironment,
      CODEX_SECURITY_CONFIG_PATH: configPath,
    },
  );
  assert.equal(captured.model, "original-model");
  assert.equal(captured.modelProvider, "custom");
  assert.equal(captured.reasoningSummary, "concise");
  assert.equal(captured.serviceTier, "flex");
  assert.equal(captured.providerConfig, undefined);
  assert.equal(JSON.stringify(captured).includes("synthetic-secret"), false);
  for (const modelProvider of ["openrouter", "fireworks", "amazon-bedrock"]) {
    await writeFile(
      configPath,
      `model_provider = ${JSON.stringify(modelProvider)}
[model_providers.${modelProvider}.aws]
region = "us-west-2"
profile = "fixture-profile"
access_key_id = "synthetic-secret"
`,
    );
    const selected = await captureSettings({}, noDenials, {
      ...parentEnvironment,
      CODEX_SECURITY_CONFIG_PATH: configPath,
    });
    assert.equal(selected.modelProvider, modelProvider);
    const expectedProvider =
      modelProvider === "amazon-bedrock"
        ? {
            "amazon-bedrock": {
              aws: { region: "us-west-2", profile: "fixture-profile" },
            },
          }
        : undefined;
    assert.deepEqual(
      selected.providerConfig,
      expectedProvider,
      "saved selections exclude catalog definitions and retain Bedrock selectors",
    );
    assert.equal(JSON.stringify(selected).includes("synthetic-secret"), false);
    const restoredProvider = restoreSettings(
      await loadSnapshot(selected),
      noDenials,
    ).codexOptions.config.model_providers;
    if (expectedProvider) assert.deepEqual(restoredProvider, expectedProvider);
    else
      assert.deepEqual(Object.keys(restoredProvider[modelProvider]).sort(), [
        "base_url",
        "env_key",
        "name",
        "wire_api",
      ]);
    // Older snapshots can contain catalog definitions.
    if (!expectedProvider) {
      const original = { ...selected, providerConfig: restoredProvider };
      const saved = structuredClone(original);
      const legacy = await loadSnapshot(original);
      assert.equal(legacy.providerConfig, undefined);
      assert.deepEqual(
        restoreSettings(legacy, noDenials).codexOptions.config.model_providers,
        restoredProvider,
      );
      assert.deepEqual(original, saved);
    }
  }
  for (const provider of ["openrouter", "fireworks"]) {
    const providerHome = join(root, `legacy-${provider}`);
    await mkdir(join(providerHome, "sessions"), { recursive: true });
    const definition = {
      name: "Synthetic gateway",
      base_url: "https://gateway.invalid/v1",
      env_key: "SYNTHETIC_GATEWAY_KEY",
      wire_api: "responses",
    };
    const environment = {
      CODEX_HOME: providerHome,
      CODEX_CLI_PATH: process.execPath,
    };
    const recorded = await loadRecordedSettings(
      { workflowVersion: "deep-security-scan/v1" },
      async () => ({
        config: {
          model_provider: provider,
          model_providers: {
            [provider]: {
              ...definition,
              http_headers: { Authorization: "synthetic-only" },
            },
          },
        },
      }),
      environment,
    );
    const projected = restoreSettings(recorded, noDenials, () => environment);
    assert.equal(projected.codexOptions.config.model_provider, provider);
    assert.deepEqual(projected.codexOptions.config.model_providers, {
      [provider]: definition,
    });
    assert.equal(JSON.stringify(recorded).includes("synthetic-only"), false);
    const threadId = `legacy-${provider}-parent`;
    await writeFile(
      join(providerHome, "sessions", `${threadId}.jsonl`),
      JSON.stringify({
        type: "session_meta",
        timestamp: "2026-01-01T00:00:00Z",
        payload: { id: threadId, model_provider: provider },
      }) + "\n",
    );
    const native = await loadRecordedSettings(
      {
        workflowVersion: "deep-security-scan/v1",
        usageOwner: { threadId, startedAt: "2026-01-01T00:00:01Z" },
        createdAt: "2026-01-01T00:00:01Z",
      },
      async () => ({ config: {} }),
      environment,
    );
    const nativeRestored = restoreSettings(
      native,
      noDenials,
      () => environment,
    );
    assert.equal(nativeRestored.codexOptions.config.model_provider, provider);
    assert.equal(
      nativeRestored.codexOptions.config.model_providers,
      undefined,
      "legacy home-owned routing must not be replaced with a generated catalog table",
    );
    assert.equal(nativeRestored.codexOptions.env.CODEX_HOME, providerHome);
  }
  let credential = "synthetic-first";
  const restored = restoreSettings(
    captured,
    { filesystemDenies: ["/fixture/current-deny"] },
    () => ({
      CODEX_API_KEY: credential,
      CODEX_HOME: "/fixture/observer-home",
      CODEX_CLI_PATH: "/fixture/observer-codex",
    }),
  );
  assert.equal(restored.codexOptions.env.CODEX_API_KEY, "synthetic-first");
  credential = "synthetic-refreshed";
  assert.equal(restored.codexOptions.env.CODEX_API_KEY, "synthetic-refreshed");
  assert.equal(restored.codexOptions.env.CODEX_HOME, root);
  assert.equal(restored.codexOptions.env.CODEX_CLI_PATH, captured.codexPath);
  assert.deepEqual(restored.parentSandbox.filesystemDenies, [
    "/fixture/original-deny",
    "/fixture/current-deny",
  ]);
  assert.equal(restored.codexOptions.config.model_reasoning_effort, "ultra");
  await writeFile(join(root, "config.toml"), 'model = "native-home-model"\n');
  const native = await capture({});
  assert.equal(native.model, "native-home-model");
  const sessionDirectory = join(root, "sessions");
  await mkdir(sessionDirectory);
  await writeFile(
    join(sessionDirectory, "parent.jsonl"),
    rollout([
      {
        type: "session_meta",
        timestamp: "2026-01-01T00:00:00Z",
        payload: { id: "fixture-parent", model_provider: "openai" },
      },
      {
        type: "turn_context",
        timestamp: "2026-01-01T00:00:01Z",
        payload: {
          turn_id: "original-turn",
          model: "parent-model",
          effort: "high",
          summary: "none",
        },
      },
      {
        type: "turn_context",
        timestamp: "2026-01-01T00:02:00Z",
        payload: {
          turn_id: "later-turn",
          model: "later-model",
          effort: "low",
          summary: "detailed",
        },
      },
    ]),
  );
  await writeFile(
    join(sessionDirectory, "other.jsonl"),
    JSON.stringify({
      type: "session_meta",
      payload: { id: "fixture-other", model_provider: "other-provider" },
    }) + "\n",
  );
  const originalParentTurn = {
    threadId: "fixture-parent",
    startedAt: "2026-01-01T00:01:00Z",
  };
  const parentSettings = await capture({}, originalParentTurn);
  const requestedTier = await capture(
    { serviceTier: "fixture-future-tier" },
    originalParentTurn,
  );
  assert.equal(requestedTier.serviceTier, "fixture-future-tier");
  assert.equal(requestedTier.nativeServiceTierAbsent, undefined);
  assert.equal(
    parentSettings.model,
    "native-home-model",
    "explicit config retains precedence",
  );
  assert.equal(parentSettings.modelProvider, "openai");
  assert.equal(
    parentSettings.reasoningSummary,
    "none",
    "later owner turns are not original discovery settings",
  );
  assert.equal(parentSettings.reasoningEffort, "high");
  await writeFile(join(root, "config.toml"), "");
  const atFirstTurn = (threadId) => ({
    threadId,
    startedAt: "2026-01-01T00:00:01Z",
  });
  const [originalParent, otherParent, unavailableParent] = await Promise.all([
    capture({}, atFirstTurn("fixture-parent")),
    capture({}, atFirstTurn("fixture-other")),
    capture(
      { model: "stored-model", reasoningEffort: "ultra" },
      atFirstTurn("fixture-unavailable"),
    ),
  ]);
  assert.equal(originalParent.model, "parent-model");
  assert.equal(
    originalParent.reasoningSummary,
    "none",
    "the original turn is included at its timestamp",
  );
  assert.equal(otherParent.modelProvider, "other-provider");
  assert.equal(
    otherParent.model,
    undefined,
    "concurrent scans do not borrow another parent's model",
  );
  assert.equal(otherParent.reasoningSummary, undefined);
  assert.equal(unavailableParent.model, "stored-model");
  assert.equal(unavailableParent.reasoningEffort, "ultra");
  assert.equal(
    unavailableParent.modelProvider,
    undefined,
    "missing history does not establish a provider",
  );
  assert.equal(unavailableParent.reasoningSummary, undefined);
  assert.equal(unavailableParent.serviceTier, undefined);
  assert.equal(
    unavailableParent.nativeServiceTierAbsent,
    undefined,
    "missing history does not prove native absence",
  );
  const originalOwner = {
    threadId: "fixture-parent",
    turnId: "original-turn",
    startedAt: "2026-01-01T00:00:00Z",
  };
  for (const workflowVersion of ["deep-security-scan/v1", "deep-scan-mcp/v1"]) {
    const legacy = await loadRecordedSettings(
      {
        workflowVersion,
        model: "recorded-model",
        reasoningEffort: "ultra",
        createdAt: "2026-01-01T00:01:00Z",
        usageOwner: null,
      },
      async () => ({
        config: { model_reasoning_summary: "concise", service_tier: "flex" },
        usageOwner: originalOwner,
      }),
      parentEnvironment,
    );
    assert.equal(legacy.model, "recorded-model");
    assert.equal(
      legacy.reasoningSummary,
      "concise",
      "recorded recipe retains precedence",
    );
    assert.equal(
      legacy.modelProvider,
      "openai",
      "recorded original owner supplies native selections",
    );
    assert.equal(legacy.serviceTier, "flex");
    assert.equal(
      legacy.codexPath,
      undefined,
      "legacy metadata did not record an executable",
    );
    assert.equal(
      legacy.codexHome,
      undefined,
      "a history lookup home is not recorded execution provenance",
    );
    const restoredLegacy = restoreSettings(
      legacy,
      { filesystemDenies: ["/fixture/current-deny"] },
      () => ({
        CODEX_HOME: "/fixture/runtime-home",
        CODEX_CLI_PATH: "/fixture/runtime-codex",
        CODEX_API_KEY: "synthetic-live-key",
      }),
    );
    assert.equal(
      restoredLegacy.codexOptions.env.CODEX_HOME,
      "/fixture/runtime-home",
    );
    assert.equal(
      restoredLegacy.codexOptions.env.CODEX_CLI_PATH,
      "/fixture/runtime-codex",
    );
    assert.equal(
      restoredLegacy.codexOptions.config.model_reasoning_summary,
      "concise",
    );
  }
  await assert.rejects(
    loadRecordedSettings(
      { workflowVersion: "deep-security-scan/v2" },
      async () =>
        assert.fail(
          "missing promised v2 settings must not become legacy recovery",
        ),
    ),
    /no recorded original/,
  );
  const continuation = {
    threadId: "fixture-other",
    startedAt: "2026-01-01T00:03:00Z",
  };
  const [rebound, unboundLegacy] = await Promise.all([
    capture({ usageOwner: originalOwner }, continuation),
    capture({ model: "stored-model", usageOwner: null }, continuation),
  ]);
  assert.equal(
    rebound.modelProvider,
    "openai",
    "takeover uses the recorded owner, not the invoking conversation",
  );
  assert.equal(
    rebound.model,
    "parent-model",
    "the bound turn takes precedence over later turns",
  );
  assert.equal(rebound.reasoningSummary, "none");
  assert.equal(unboundLegacy.model, "stored-model");
  assert.equal(
    unboundLegacy.modelProvider,
    undefined,
    "unrecorded legacy ownership cannot recover caller selections",
  );
  assert.equal(unboundLegacy.reasoningSummary, undefined);
  const freshOwner = await capture(
    { usageOwner: null },
    { ...originalOwner, startedAt: "2026-01-01T00:01:00Z", created: true },
  );
  assert.equal(
    freshOwner.modelProvider,
    "openai",
    "a newly created run belongs to the known current parent",
  );
  assert.equal(freshOwner.model, "parent-model");
  assert.equal(freshOwner.reasoningSummary, "none");

  await writeFile(
    join(sessionDirectory, "legacy-auto.jsonl"),
    rollout([
      {
        type: "session_meta",
        payload: {
          id: "fixture-legacy-auto",
          cli_version: "0.132.0",
          model_provider: "openai",
        },
      },
      {
        type: "turn_context",
        payload: {
          turn_id: "legacy-turn",
          model: "legacy-model",
          effort: "high",
          summary: "auto",
        },
      },
    ]),
  );
  const legacyAuto = await capture({
    usageOwner: { threadId: "fixture-legacy-auto", turnId: "legacy-turn" },
  });
  assert.equal(
    legacyAuto.reasoningSummary,
    "auto",
    "older native turn-context selections remain readable",
  );
  for (const version of ["0.133.0", "0.154.0"]) {
    const threadId = `fixture-fresh-${version}`;
    await writeFile(
      join(sessionDirectory, `${threadId}.jsonl`),
      rollout([
        {
          type: "session_meta",
          timestamp: "2026-01-01T00:00:00Z",
          payload: {
            id: threadId,
            cli_version: version,
            model_provider: "openai",
          },
        },
        {
          type: "turn_context",
          timestamp: "2026-01-01T00:00:01Z",
          payload: {
            turn_id: "fresh-turn",
            model: "fresh-model",
            effort: "high",
            summary: "auto",
          },
        },
        settingsApplied("2026-01-01T00:02:00Z", threadId, {
          model: "fresh-model",
          model_provider_id: "openai",
          reasoning_summary: "detailed",
        }),
      ]),
    );
    const owner = {
      threadId,
      turnId: "fresh-turn",
      startedAt: "2026-01-01T00:01:00Z",
    };
    const fresh = await capture({ usageOwner: owner });
    assert.equal(fresh.model, "fresh-model");
    assert.equal(
      fresh.reasoningSummary,
      undefined,
      "fresh native compatibility auto is not an original selection",
    );
    assert.equal(
      restoreSettings(fresh, noDenials).codexOptions.config
        .model_reasoning_summary,
      undefined,
    );
    assert.deepEqual(
      await loadSnapshot(fresh, {
        usageOwner: owner,
        createdAt: owner.startedAt,
      }),
      fresh,
      "unknown summary is not replaced by a compatibility field or a later selection",
    );
    await writeFile(
      join(root, "config.toml"),
      'model_reasoning_summary = "auto"\n',
    );
    const explicit = await capture({ usageOwner: owner });
    assert.equal(
      explicit.reasoningSummary,
      "auto",
      "an explicit original config selection still takes precedence",
    );
    await writeFile(join(root, "config.toml"), "");
  }
  const appliedPath = join(sessionDirectory, "applied.jsonl");
  const modelSettings = {
    model: "applied-model",
    model_provider_id: "openai",
    reasoning_effort: "high",
  };
  await writeFile(
    appliedPath,
    rollout([
      {
        type: "session_meta",
        timestamp: "2026-01-01T00:00:00Z",
        payload: { id: "fixture-applied", model_provider: "previous-provider" },
      },
      settingsApplied("2026-01-01T00:00:01Z", "fixture-applied", {
        ...modelSettings,
        service_tier: "default",
        reasoning_summary: "concise",
      }),
      {
        type: "turn_context",
        timestamp: "2026-01-01T00:00:02Z",
        payload: {
          turn_id: "applied-turn",
          model: "previous-model",
          effort: "low",
          summary: "none",
        },
      },
      settingsApplied("2026-01-01T00:00:03Z", "fixture-copied-owner", {
        model: "copied-model",
        model_provider_id: "copied-provider",
        service_tier: "flex",
        reasoning_summary: "detailed",
      }),
      settingsApplied("2026-01-01T00:02:00Z", "fixture-applied", {
        model: "later-model",
        model_provider_id: "later-provider",
        service_tier: "fast",
        reasoning_summary: "detailed",
      }),
    ]),
  );
  const appliedOwner = {
    threadId: "fixture-applied",
    turnId: "applied-turn",
    startedAt: "2026-01-01T00:00:00Z",
  };
  const readApplied = () =>
    capture(
      { usageOwner: appliedOwner },
      { threadId: "fixture-other", startedAt: "2026-01-01T00:01:00Z" },
    );
  const applied = await readApplied();
  assert.equal(
    applied.serviceTier,
    "default",
    "original explicit standard routing survives later and copied snapshots",
  );
  assert.equal(
    applied.reasoningSummary,
    "concise",
    "native applied summary overrides the legacy compatibility field",
  );
  assert.equal(
    applied.modelProvider,
    "openai",
    "complete native snapshot replaces the session metadata provider",
  );
  assert.equal(
    applied.model,
    "applied-model",
    "complete native snapshot replaces compatibility turn settings",
  );
  assert.equal(applied.reasoningEffort, "high");
  assert.equal(
    applied.nativeServiceTierAbsent,
    undefined,
    "explicit native standard remains an explicit selection",
  );
  const withoutTier = { ...applied };
  delete withoutTier.serviceTier;
  const repairedTier = await loadSnapshot(withoutTier, {
    usageOwner: appliedOwner,
    createdAt: "2026-01-01T00:01:00Z",
  });
  assert.equal(repairedTier.serviceTier, "default");
  await appendFile(
    appliedPath,
    rollout([
      settingsApplied("2026-01-01T00:00:04Z", "fixture-applied", {
        ...modelSettings,
        service_tier: "priority",
      }),
    ]),
  );
  const nativeTier = await readApplied();
  assert.equal(
    nativeTier.serviceTier,
    "priority",
    "an effective tier selected by native remains unchanged",
  );
  assert.equal(nativeTier.nativeServiceTierAbsent, undefined);
  await appendFile(
    appliedPath,
    rollout([
      settingsApplied("2026-01-01T00:00:05Z", "fixture-applied", modelSettings),
    ]),
  );
  const nativeDefaults = await readApplied();
  assert.equal(
    nativeDefaults.model,
    "applied-model",
    "absent optional selections do not erase the required model",
  );
  assert.equal(
    nativeDefaults.modelProvider,
    "openai",
    "absent optional selections do not erase the required provider",
  );
  assert.equal(nativeDefaults.reasoningEffort, "high");
  assert.equal(
    nativeDefaults.serviceTier,
    "default",
    "known native absence retains its omitted request tier",
  );
  assert.equal(
    nativeDefaults.nativeServiceTierAbsent,
    true,
    "known native absence is recorded separately from explicit standard",
  );
  assert.equal(
    nativeDefaults.reasoningSummary,
    undefined,
    "a compatibility summary is not a recorded native default",
  );
  for (const compressed of [
    false,
    ...(typeof zlib.zstdCompressSync === "function" ? [true] : []),
  ]) {
    const threadId = `fixture-replayed-${compressed}`;
    const archive = join(root, "archived_sessions");
    await mkdir(archive, { recursive: true });
    const records = rollout([
      {
        type: "session_meta",
        timestamp: "2026-01-01T00:00:00Z",
        payload: {
          id: threadId,
          timestamp: "2026-01-01T00:00:00Z",
          model_provider: "original-provider",
        },
      },
      {
        type: "session_meta",
        timestamp: "2025-12-31T23:00:00Z",
        payload: {
          id: "copied-parent",
          timestamp: "2025-12-31T23:00:00Z",
          model_provider: "copied-provider",
        },
      },
      {
        type: "turn_context",
        timestamp: "2025-12-31T23:00:01Z",
        payload: { model: "copied-model", effort: "low" },
      },
      {
        type: "event_msg",
        timestamp: "2026-01-01T00:00:01Z",
        payload: {
          type: "task_started",
          started_at: Date.parse("2026-01-01T00:00:01Z") / 1000,
        },
      },
      {
        type: "turn_context",
        timestamp: "2026-01-01T00:00:02Z",
        payload: {
          turn_id: "original-turn",
          model: "original-model",
          effort: "ultra",
          summary: "concise",
        },
      },
      {
        type: "turn_context",
        timestamp: "2026-01-01T00:02:00Z",
        payload: {
          turn_id: "later-turn",
          model: "later-model",
          effort: "low",
        },
      },
    ]);
    await writeFile(
      join(archive, `${threadId}.jsonl${compressed ? ".zst" : ""}`),
      compressed ? zlib.zstdCompressSync(records) : records,
    );
    const replayed = await capture({
      usageOwner: {
        threadId,
        turnId: "original-turn",
        startedAt: "2026-01-01T00:01:00Z",
      },
    });
    assert.equal(replayed.model, "original-model");
    assert.equal(replayed.modelProvider, "original-provider");
    assert.equal(replayed.reasoningEffort, "ultra");
    assert.equal(replayed.reasoningSummary, "concise");
  }
  {
    const home = join(root, "framed-owner");
    const archive = join(home, "archived_sessions");
    const threadId = "fixture-archived-owner";
    const owner = { threadId, startedAt: "2026-01-01T00:01:00Z" };
    const environment = { CODEX_HOME: home, CODEX_CLI_PATH: process.execPath };
    await mkdir(archive, { recursive: true });
    const file = join(archive, `${threadId}.jsonl.zst`);
    // One session_meta and one turn_context, independently compressed so the
    // supported Node versions without built-in Zstandard run the same case.
    const frames = [
      "KLUv/SBCEQIAeyJ0eXBlIjoic2Vzc2lvbl9tZXRhIiwicGF5bG9hZCI6eyJpZCI6ImZpeHR1cmUtYXJjaGl2ZWQtb3duZXIifX0K",
      "KLUv/SBNRQIAcsQPFpDHDVxkLMSuFRi/F0l2d144ivO8GQTAez8DOsc3Y2P2JNA10Cksj0+rTNzhNTm1XCfvY1txERQr+vhdre8CAQBEw4QC",
    ].map((frame) => Buffer.from(frame, "base64"));
    await writeFile(file, Buffer.concat(frames));
    const readOwner = () =>
      captureSettings({ usageOwner: owner }, noDenials, environment);
    const captured = await readOwner();
    assert.equal(captured.model, "archived-model");
    assert.equal(captured.reasoningEffort, "high");
    await writeFile(
      file,
      Buffer.concat([frames[0], frames[1].subarray(0, -1)]),
    );
    await assert.rejects(readOwner, /unexpected EOF/);
    await assert.rejects(
      loadRecordedSettings(
        {
          workflowVersion: "deep-security-scan/v1",
          usageOwner: owner,
          createdAt: owner.startedAt,
        },
        async () => ({ config: {} }),
        environment,
      ),
      /unexpected EOF/,
    );
  }
  if (typeof zlib.zstdCompressSync === "function") {
    const parentId = "0198ff20-1b40-7000-8000-000000000001";
    const foreignId = "0198ff20-1b40-7000-8000-000000000002";
    const owner = {
      threadId: parentId,
      turnId: "original-history-turn",
      startedAt: "2026-09-01T00:00:01Z",
    };
    const nativeSelections = {
      model: "original-history-model",
      modelProvider: "openai",
      reasoningEffort: "ultra",
      reasoningSummary: "concise",
    };
    for (const layout of ["ordinary", "reverted"]) {
      const home = join(root, `corrupt-foreign-history-${layout}`);
      const sessions = join(home, "sessions");
      const archive = join(home, "archived_sessions");
      await mkdir(sessions, { recursive: true });
      await mkdir(archive);
      await writeFile(
        join(sessions, `rollout-2026-09-01T00-00-00-${parentId}.jsonl`),
        rollout([
          {
            type: "session_meta",
            timestamp: "2026-09-01T00:00:00Z",
            payload: {
              id: parentId,
              timestamp: "2026-09-01T00:00:00Z",
              model_provider: nativeSelections.modelProvider,
            },
          },
          {
            type: "turn_context",
            timestamp: owner.startedAt,
            payload: {
              turn_id: owner.turnId,
              model: nativeSelections.model,
              effort: nativeSelections.reasoningEffort,
              summary: nativeSelections.reasoningSummary,
            },
          },
        ]),
      );
      const compressed = zlib.zstdCompressSync(
        JSON.stringify({ type: "session_meta", payload: { id: foreignId } }) +
          "\n",
      );
      compressed[0] ^= 0xff;
      const suffix =
        layout === "reverted" ? "_0198ff20-1b40-7000-8000-000000000003" : "";
      await writeFile(
        join(
          archive,
          `rollout-2026-09-01T00-00-00-${foreignId}${suffix}.jsonl.zst`,
        ),
        compressed,
      );
      const environment = {
        CODEX_HOME: home,
        CODEX_CLI_PATH: process.execPath,
      };
      if (process.platform !== "win32" && process.getuid() !== 0) {
        const unreadable = join(
          archive,
          `rollout-2026-09-01T00-00-00-${foreignId}${suffix}.jsonl`,
        );
        await writeFile(unreadable, "");
        await chmod(unreadable, 0);
        await assert.rejects(readFile(unreadable), { code: "EACCES" });
      }
      const run = { usageOwner: owner, createdAt: owner.startedAt };
      const recovered = await Promise.all([
        captureSettings({ usageOwner: null }, noDenials, environment, {
          ...owner,
          created: true,
        }),
        loadRecordedSettings(
          { ...run, workflowVersion: "deep-security-scan/v1" },
          async () => ({ config: {} }),
          environment,
        ),
        loadSnapshot({ codexPath: process.execPath, codexHome: home }, run),
      ]);
      for (const selection of recovered) {
        for (const [key, value] of Object.entries(nativeSelections))
          assert.equal(selection[key], value, layout);
        const worker = restoreSettings(selection, noDenials, () => environment);
        assert.equal(worker.model, nativeSelections.model);
        assert.equal(worker.reasoningEffort, nativeSelections.reasoningEffort);
        assert.equal(
          worker.codexOptions.config.model_provider,
          nativeSelections.modelProvider,
        );
      }
    }
  }
  const incomplete = Object.freeze({
    codexPath: process.execPath,
    codexHome: root,
    serviceTier: "flex",
  });
  await writeFile(
    join(root, "config.toml"),
    'model_provider = "observer-provider"\nmodel_reasoning_summary = "detailed"\n',
  );
  const originalRun = {
    model: "stored-model",
    reasoningEffort: "ultra",
    usageOwner: originalOwner,
    createdAt: "2026-01-01T00:01:00Z",
  };
  const [repaired, newer] = await Promise.all([
    loadSnapshot(incomplete, originalRun),
    loadSnapshot(settings),
  ]);
  assert.deepEqual(newer, settings);
  assert.deepEqual(repaired, {
    ...incomplete,
    model: "stored-model",
    reasoningEffort: "ultra",
    modelProvider: "openai",
    reasoningSummary: "none",
  });
  await rm(sessionDirectory, { recursive: true });
  const unavailable = await loadSnapshot(incomplete, originalRun);
  assert.equal(unavailable.model, "stored-model");
  assert.equal(unavailable.reasoningEffort, "ultra");
  assert.equal(
    unavailable.modelProvider,
    undefined,
    "unavailable history remains unknown",
  );
  assert.equal(unavailable.reasoningSummary, undefined);
  const unknown = await loadSnapshot(incomplete, {
    ...originalRun,
    usageOwner: null,
  });
  assert.equal(unknown.model, "stored-model");
  assert.equal(
    unknown.modelProvider,
    undefined,
    "missing original ownership is not current config",
  );
  assert.equal(unknown.reasoningSummary, undefined);
  assert.equal(unknown.nativeServiceTierAbsent, undefined);
  await assert.rejects(
    loadRecordedSettings({ executionSettings: { version: 99, settings } }),
    /unsupported/,
  );

  // Model-writable artifacts cannot supply or override trusted launch settings.
  const directory = join(root, "artifacts", "deep_discovery");
  await mkdir(directory, { recursive: true });
  const artifact = join(directory, "execution-settings.json");
  for (const version of [undefined, 1, 99]) {
    const bytes = JSON.stringify({ version, settings: incomplete });
    if (version !== undefined) await writeFile(artifact, bytes);
    const run = { scanDir: root, workflowVersion: "deep-security-scan/v2" };
    assert.deepEqual(await loadSnapshot(settings, run), settings);
    await assert.rejects(loadRecordedSettings(run), /no recorded original/);
    let reads = 0;
    const legacy = await loadRecordedSettings(
      { ...run, workflowVersion: "deep-security-scan/v1" },
      async () => {
        reads++;
        return {
          config: { model: "original", model_reasoning_effort: "high" },
        };
      },
    );
    assert.equal(reads, 1);
    assert.equal(legacy.model, "original");
    assert.equal(legacy.reasoningEffort, "high");
    assert.equal(legacy.codexPath, undefined);
    assert.equal(legacy.codexHome, undefined);
    if (version === undefined)
      await assert.rejects(readFile(artifact), { code: "ENOENT" });
    else assert.equal(await readFile(artifact, "utf8"), bytes);
  }
} finally {
  await rm(root, { recursive: true, force: true });
}
