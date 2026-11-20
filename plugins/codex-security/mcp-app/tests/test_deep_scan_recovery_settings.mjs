import assert from "node:assert/strict";
import fs from "node:fs";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  rename,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";

const root = await mkdtemp(join(tmpdir(), "deep-settings-"));
const module = await importSource(
  fileURLToPath(
    new URL("../src/deep-scan/recovery-settings.ts", import.meta.url),
  ),
);
const {
  beginDeepScanWithCapturedSettings: beginWithCapturedSettings,
  captureDeepScanExecutionSettings: captureSettings,
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
try {
  const parentEnvironment = {
    CODEX_CLI_PATH: process.execPath,
    CODEX_HOME: root,
  };
  const capture = (original, parent) =>
    captureSettings(original, noDenials, parentEnvironment, parent);
  const ownerHome = join(root, "owner-home");
  const ownerId = "00000000-0000-4000-8000-000000000001";
  const otherId = "00000000-0000-4000-8000-000000000002";
  const ownerHistory = join(ownerHome, "sessions");
  const archives = join(ownerHome, "archived_sessions");
  await mkdir(ownerHistory, { recursive: true });
  await mkdir(archives);
  await writeFile(
    join(ownerHistory, "owner.jsonl"),
    JSON.stringify({
      type: "session_meta",
      payload: { id: ownerId, model_provider: "owner-provider" },
    }) + "\n",
  );
  const archivePath = (id) =>
    join(archives, `rollout-2026-01-01T00-00-00-${id}.jsonl.zst`);
  const captureOwner = () =>
    captureSettings(
      {},
      { filesystemDenies: [] },
      { CODEX_HOME: ownerHome, CODEX_CLI_PATH: process.execPath },
      { threadId: ownerId },
    );
  await writeFile(
    archivePath(otherId),
    Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x60]),
  );
  assert.equal((await captureOwner()).modelProvider, "owner-provider");
  await rename(archivePath(otherId), archivePath(ownerId));
  await assert.rejects(captureOwner, /unexpected EOF/i);
  await rename(archivePath(ownerId), join(archives, "unknown.jsonl.zst"));
  await assert.rejects(captureOwner, /unexpected EOF/i);
  await rm(join(archives, "unknown.jsonl.zst"));
  const meta = {
    type: "session_meta",
    payload: { id: ownerId, timestamp: "2026-01-01T00:00:00Z" },
  };
  const context = (model) => ({ type: "turn_context", payload: { model } });
  const marker = (text) => ({ type: "response_item", payload: { text } });
  const writeHistory = (path, events) =>
    writeFile(
      path,
      events.map((event) => JSON.stringify(event)).join("\n") + "\n",
    );
  const liveEvents = [meta, marker("original"), context("live-model")];
  await writeHistory(join(ownerHistory, "owner.jsonl"), liveEvents);
  const sibling = join(archives, "owner.jsonl");
  await writeHistory(sibling, [
    meta,
    marker("divergent"),
    context("live-model"),
    context("archive-model"),
  ]);
  assert.equal(
    (await captureOwner()).model,
    "live-model",
    "a divergent archive must not displace live history",
  );
  const extended = [
    ...liveEvents,
    context("archive-model"),
    { type: "session_meta", payload: { id: otherId } },
    context("replayed-model"),
  ];
  await writeHistory(sibling, extended);
  assert.equal(
    (await captureOwner()).model,
    "archive-model",
    "a strict extension contributes owned events only",
  );
  await writeHistory(sibling, [
    ...extended,
    {
      type: "event_msg",
      payload: {
        type: "task_started",
        started_at: Date.parse(meta.payload.timestamp) / 1000,
      },
    },
    context("resumed-model"),
  ]);
  assert.equal((await captureOwner()).model, "resumed-model");
  const settings = {
    codexPath: "/fixture/runtime/codex",
    codexHome: "/fixture/account",
    model: "fixture-model",
    modelProvider: "fixture-provider",
    reasoningEffort: "high",
    reasoningSummary: "detailed",
    serviceTier: "fast",
  };
  for (const source of ["missing", "invalid"]) {
    const config = join(root, `${source}.toml`);
    if (source === "invalid") await writeFile(config, "model = [");
    let captureFailure;
    const capture = async () => {
      try {
        return await captureSettings(
          {},
          { filesystemDenies: [] },
          { CODEX_HOME: root, CODEX_SECURITY_CONFIG_PATH: config },
        );
      } catch (error) {
        captureFailure = error;
        throw error;
      }
    };
    const startFailure = new Error(
      "New runs require original execution settings.",
    );
    await assert.rejects(
      beginWithCapturedSettings(capture, async (captured) => {
        assert.equal(captured, null);
        throw startFailure;
      }),
      (error) => {
        assert.ok(error instanceof AggregateError);
        assert.deepEqual(error.errors, [startFailure, captureFailure]);
        assert.ok(error.message.includes(startFailure.message));
        assert.ok(error.message.includes(captureFailure.message));
        return true;
      },
    );
    const existing = { scanId: "existing-scan", status: "running" };
    assert.equal(
      await beginWithCapturedSettings(capture, async (captured) => {
        assert.equal(captured, null);
        return existing;
      }),
      existing,
    );
  }
  const unrelatedFailure = new Error("Synthetic workbench failure.");
  const blockedRuntimeHome = join(root, "blocked-runtime-home");
  await mkdir(blockedRuntimeHome);
  await writeFile(
    join(blockedRuntimeHome, "codex-security-worker-settings"),
    "not a directory",
  );
  const readableConfig = join(root, "readable-config.toml");
  await writeFile(readableConfig, 'model = "fixture-model"\n');
  const isolatedRuntime = join(root, "isolated-runtime.toml");
  await writeFile(
    isolatedRuntime,
    '[worker_runtime]\nweb_search = "disabled"\n',
  );
  await assert.rejects(
    captureSettings(
      {},
      { filesystemDenies: [blockedRuntimeHome] },
      {
        CODEX_HOME: blockedRuntimeHome,
        CODEX_CLI_PATH: process.execPath,
        CODEX_SECURITY_CONFIG_PATH: readableConfig,
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: isolatedRuntime,
      },
    ),
    /ENOTDIR|EEXIST/,
    "failure to retain the original private runtime config must fail capture",
  );
  const braceHome = join(root, "home-{first,second}");
  await mkdir(braceHome);
  const braceEnvironment = {
    CODEX_HOME: braceHome,
    CODEX_CLI_PATH: process.execPath,
    CODEX_SECURITY_CONFIG_PATH: readableConfig,
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: isolatedRuntime,
  };
  const braceGlob = await captureSettings(
    {},
    { filesystemDenies: [braceHome] },
    braceEnvironment,
  );
  assert.equal(braceGlob.runtimeConfigPath, undefined);
  assert.ok(braceGlob.runtimeConfigSource);
  assert.equal(
    fs.existsSync(join(braceHome, "codex-security-worker-settings")),
    false,
    "a brace glob does not protect a directory whose name contains literal braces",
  );
  const braceLiteral = await captureSettings(
    {},
    { filesystemDenies: [], literalFilesystemDenies: [braceHome] },
    braceEnvironment,
  );
  assert.ok(braceLiteral.runtimeConfigPath);
  if (process.platform !== "win32") {
    const physicalHome = join(root, "physical-home");
    const physicalChild = join(physicalHome, "child");
    await mkdir(physicalChild, { recursive: true });
    await symlink(physicalChild, join(root, "home-alias"));
    const traversalHome = `${root}/home-alias/..`;
    const traversal = await captureSettings(
      {},
      { filesystemDenies: [physicalHome] },
      {
        CODEX_HOME: traversalHome,
        CODEX_CLI_PATH: process.execPath,
        CODEX_SECURITY_CONFIG_PATH: readableConfig,
        CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: isolatedRuntime,
      },
    );
    assert.equal(traversal.codexHome, traversalHome);
    assert.equal(
      traversal.runtimeConfigPath.startsWith(
        `${physicalHome}/codex-security-worker-settings/`,
      ),
      true,
      "snapshot placement must preserve filesystem traversal through a home symlink",
    );
  }
  await assert.rejects(
    beginWithCapturedSettings(
      async () => settings,
      async (captured) => {
        assert.equal(captured, settings);
        throw unrelatedFailure;
      },
    ),
    (error) => error === unrelatedFailure,
  );
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
  const captureEnvironment = {
    CODEX_CLI_PATH: process.execPath,
    CODEX_HOME: root,
    CODEX_SECURITY_CONFIG_PATH: configPath,
  };
  const captured = await captureSettings(
    { model: "original-model", reasoningEffort: "ultra" },
    {
      filesystemDenies: ["/fixture/original-deny"],
      literalFilesystemDenies: ["/fixture/account [original]"],
      globScanMaxDepth: 3,
    },
    captureEnvironment,
  );
  const explicitTier = await captureSettings(
    { serviceTier: "future-tier" },
    { filesystemDenies: [] },
    captureEnvironment,
  );
  assert.equal(explicitTier.serviceTier, "future-tier");
  assert.equal(
    restoreSettings(explicitTier, { filesystemDenies: [] }).codexOptions.config
      .service_tier,
    "future-tier",
  );
  assert.deepEqual(captured.parentSandbox.literalFilesystemDenies, [
    "/fixture/account [original]",
  ]);
  const resumedSandbox = restoreSettings(captured, {
    filesystemDenies: ["/fixture/current-deny"],
    literalFilesystemDenies: [
      "/fixture/account [original]",
      "/fixture/account [current]",
    ],
  }).parentSandbox;
  assert.deepEqual(resumedSandbox.literalFilesystemDenies, [
    "/fixture/account [original]",
    "/fixture/account [current]",
  ]);
  assert.deepEqual(resumedSandbox.filesystemDenies, [
    "/fixture/original-deny",
    "/fixture/current-deny",
  ]);
  assert.equal(
    restoreSettings(settings, { filesystemDenies: [] }).parentSandbox
      .literalFilesystemDenies,
    undefined,
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
    const selected = await captureSettings({}, noDenials, captureEnvironment);
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
    assert.deepEqual(restoredProvider, expectedProvider);
    await writeFile(
      join(root, "config.toml"),
      `model_provider = ${JSON.stringify(modelProvider)}
[model_providers.${modelProvider}]
base_url = "https://native.example.invalid/v1"
env_key = "SYNTHETIC_NATIVE_KEY"
[model_providers.${modelProvider}.aws]
region = "us-west-2"
profile = "fixture-profile"
`,
    );
    const native = await capture({});
    const nativeConfig = restoreSettings(native, { filesystemDenies: [] })
      .codexOptions.config;
    assert.equal(nativeConfig.model_provider, modelProvider);
    assert.deepEqual(nativeConfig.model_providers, expectedProvider);
    // Older snapshots can contain catalog definitions. Reading them keeps
    // their bytes intact and still inherits the original native definition.
    if (!expectedProvider) {
      const legacyProvider = {
        [modelProvider]: {
          name: "Fixture",
          base_url: "https://catalog.example.invalid/v1",
          env_key: "SYNTHETIC_CATALOG_KEY",
          wire_api: "responses",
        },
      };
      const legacy = await loadSnapshot({
        ...selected,
        providerConfig: legacyProvider,
      });
      assert.equal(legacy.providerConfig, undefined);
      assert.deepEqual(
        restoreSettings(legacy, { filesystemDenies: [] }).codexOptions.config
          .model_providers,
        restoredProvider,
      );
    }
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
  const archive = join(root, "archived_sessions");
  await mkdir(archive);
  // A native Zstandard session_meta frame from the selected parent.
  await writeFile(
    join(archive, "parent.jsonl.zst"),
    Buffer.from(
      "KLUv/QRYTQIAsoQPFKDFDZxcS+7Ss3DSb/3DzeWhhjgxQGudqGqbSUlcc/F0so8DTKWD0Pdx1LNxvC3r+OKX0pCzilCijyevdBYCADcJQMyhzAYyQIw=",
      "base64",
    ),
  );
  const archived = await capture({}, { threadId: "archived-parent" });
  assert.equal(archived.modelProvider, "archived-provider");
  const badHistoryHome = join(root, "unreadable-history");
  await mkdir(badHistoryHome);
  await writeFile(
    join(badHistoryHome, "sessions"),
    "synthetic invalid directory",
  );
  await assert.rejects(
    captureSettings(
      {},
      { filesystemDenies: [] },
      {
        CODEX_HOME: badHistoryHome,
        CODEX_CLI_PATH: process.execPath,
      },
      { threadId: "original-parent" },
    ),
    { code: "ENOTDIR" },
  );
  const originalParentTurn = {
    threadId: "fixture-parent",
    startedAt: "2026-01-01T00:01:00Z",
  };
  const parentSettings = await capture({}, originalParentTurn);
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
