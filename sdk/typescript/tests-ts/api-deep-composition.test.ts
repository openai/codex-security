import { execFileSync } from "node:child_process";
import { effectiveCodexConfiguration } from "./support/api-events.js";
import { main } from "../src/cli.js";
import { capture, dependencies as cliDependencies } from "./cli-fixtures.js";
import { createHash, randomUUID } from "node:crypto";

import { restoreScanKnowledge } from "../src/scan-inputs.js";
import { restoreProviderProfile } from "../src/provider-profile.js";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { afterEach, expect, spyOn, test } from "bun:test";

import { stringify as stringifyToml } from "smol-toml";
import { CodexSecurity } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { git } from "./git-fixture.js";

import { ScanTransportClosedError } from "../src/scan-execution.js";
import { ScanInterruptedError } from "../src/errors.js";
import {
  DeepScanPublicationError,
  DeepScanRecoveryError,
  ScanCostTrackingError,
} from "../src/deep-scan.js";
import { loadDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";

import { DeepScanProgressTracker } from "../src/deep-progress.js";

import { tokenUsageEvent } from "./support/usage-rollout.js";

import {
  createDeepApiFixtures,
  pluginRoot,
  usage,
} from "./support/deep-api.js";

const { fixture, cleanup } = createDeepApiFixtures();
afterEach(cleanup);

const promptFiles = [
  {
    setting: "model_instructions_file",
    digestKey: "modelInstructionsFileSha256",
    label: "model instructions",
  },
  {
    setting: "experimental_compact_prompt_file",
    digestKey: "compactPromptFileSha256",
    label: "compact prompt",
  },
] as const;

test.each(["active", "completed"] as const)(
  "cancellation retains file-authored discovery checkpoints (%s worker)",
  async (phase) => {
    const h = await fixture(phase);
    await using client = h.makeClient();
    await expect(
      client.run(h.repository, { ...h.options, workers: 1, maxCostUsd: 1 }),
    ).rejects.toBeInstanceOf(ScanInterruptedError);
    expect(h.launches).toHaveLength(1);
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "canceled",
    });
    const findings = JSON.parse(
      await readFile(join(h.outputDir, "findings.json"), "utf8"),
    );
    const coverage = JSON.parse(
      await readFile(join(h.outputDir, "coverage.json"), "utf8"),
    );
    expect(findings.findings).toHaveLength(1);
    expect(coverage).not.toHaveProperty("completeness");
    expect(coverage.deferred).toContainEqual(
      expect.objectContaining({
        reason: "Independent source validation is pending.",
        sourceCandidateId: "pending-candidate",
        candidate: {
          title: "Pending source review",
          evidence: "Synthetic saved evidence",
        },
      }),
    );
    expect(h.commands).not.toContain("complete-scan");
    expect(h.commands).not.toContain("write-scan-draft");
    const child = [...h.records].find(
      ([, record]) => record.mode === "standard",
    )!;
    const receipt = await runWorkbench(
      { ...child[1].options, signal: undefined },
      ["get-scan", "--scan-id", child[0]],
    );
    expect((receipt["scan"] as JsonObject)["cost"]).toMatchObject(
      estimateScanCost("gpt-6-astra", usage)!,
    );
  },
);

test("ordinary children and reducer share one immutable preparation and knowledge directory", async () => {
  const h = await fixture();
  await using client = h.makeClient();
  const result = await client.run(h.repository, h.options);
  expect(h.preparations()).toBe(1);
  expect(h.launches).toHaveLength(3);
  expect(new Set(h.launches.map((launch) => launch.knowledge)).size).toBe(1);
  const workerConfig = {
    features: {
      multi_agent_v2: {
        enabled: true,
        max_concurrent_threads_per_session: 4,
      },
    },
  };
  for (const launch of h.launches) {
    expect(launch.options.env!["SYNTHETIC_SETTING"]).toBe("captured");
    expect(launch.preflightConfig).toMatchObject(workerConfig);
    expect(
      h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.recipe[
        "config"
      ],
    ).toMatchObject(workerConfig);
    expect(effectiveCodexConfiguration(launch.options)).toMatchObject({
      ...workerConfig,
      model: "gpt-6-astra",
      model_reasoning_effort: "high",
      mcp_servers: {
        "codex-security": { command: "node", enabled: false },
        "synthetic.server": { command: "synthetic-command" },
      },
      permissions: {
        codex_security_scan: {
          filesystem: {
            [join(h.root, "private")]: "deny",
            [launch.knowledge!]: "read",
          },
          network: { enabled: false },
        },
      },
    });
  }
  expect(result.findings.findings).toHaveLength(2);
  expect(h.parentPhases).toEqual([
    expect.objectContaining({
      phase: "discovery",
      independentReviews: expect.objectContaining({ consolidating: false }),
    }),
    expect.objectContaining({
      phase: "discovery",
      independentReviews: expect.objectContaining({ consolidating: false }),
    }),
    expect.objectContaining({
      phase: "discovery",
      status: "running",
      independentReviews: {
        active: 0,
        completed: 2,
        maximum: 2,
        consolidating: false,
      },
    }),
  ]);
  expect(result.cost).not.toBeNull();
  expect(await readFile(join(h.home, "config.toml"), "utf8")).toBe(
    'model = "gpt-6-astra"\n',
  );
  expect(h.commands.filter((command) => command === "list-scans")).toHaveLength(
    1,
  );
});

test("Deep progress keeps inter-batch merges in discovery until the stop decision", async () => {
  const h = await fixture();
  await using client = h.makeClient();
  const result = await client.run(h.repository, {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 3,
  });
  expect(
    h.launches.map(
      (launch) =>
        h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode,
    ),
  ).toEqual(["standard", "standard", "deep", "standard", "deep"]);
  expect(h.parentPhases).toEqual(
    [
      { active: 1, completed: 0 },
      { active: 1, completed: 1 },
      { active: 0, completed: 2 },
      { active: 1, completed: 2 },
      { active: 0, completed: 3 },
    ].map((reviews) =>
      expect.objectContaining({
        phase: "discovery",
        status: "running",
        independentReviews: {
          ...reviews,
          maximum: 3,
          consolidating: false,
        },
      }),
    ),
  );
  const parent = h.records.get(result.manifest.scan.id)!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    result.manifest.scan.id,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    phase: "reporting",
    status: "complete",
    independentReviews: {
      active: 0,
      completed: 3,
      maximum: 3,
      consolidating: false,
    },
  });
  expect(await loadDeepScanCheckpoint(h.outputDir)).toMatchObject({
    terminalReason: "capped",
  });
});

test("a deterministic child receipt verifies the final cost without a reducer", async () => {
  const h = await fixture();
  const warnings: string[] = [];
  await using client = h.makeClient();
  const result = await client.run(h.repository, {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 1,
    maxCostUsd: 1,
    onWarning: (message) => warnings.push(message),
  });
  expect(h.launches).toHaveLength(1);
  expect(result.threadId).toBeNull();
  expect(result.findings.findings).toHaveLength(1);
  expect(result.cost).toEqual(estimateScanCost("gpt-6-astra", usage));
  expect(warnings).toEqual([]);
});

test("shared matching reads evidence through the prepared parent session", async () => {
  const h = await fixture();
  h.mergeDuplicates();
  await using client = h.makeClient();
  const result = await client.run(h.repository, h.options);
  expect(result.findings.findings).toHaveLength(1);
  expect(
    result.findings.findings[0]!.provenance["sourceFindings"],
  ).toHaveLength(2);
  const parentTurns = h.launches.filter(
    (launch) =>
      h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
      "deep",
  );
  expect(parentTurns).toHaveLength(2);
  expect(h.preparations()).toBe(1);
  expect(h.threadScans.size).toBe(3);
  for (const turn of parentTurns) {
    expect(effectiveCodexConfiguration(turn.options)).toMatchObject({
      model: "gpt-6-astra",
      model_reasoning_effort: "high",
      permissions: {
        codex_security_scan: {
          filesystem: { [join(h.root, "private")]: "deny" },
          network: { enabled: false },
        },
      },
    });
    expect(turn.runOptions?.signal).toBeInstanceOf(AbortSignal);
    expect(turn.runOptions?.outputSchema).toMatchObject({
      properties: { matches: { type: "array" }, request: expect.any(Object) },
    });
  }
  expect(
    h.completedPrompts.some((prompt) => prompt.includes('"content":')),
  ).toBe(true);
  expect(result.cost).not.toBeNull();
});

test("owner reports use discovery hints without another turn and publish only on the Deep parent", async () => {
  const h = await fixture();
  git(h.repository, "init", "-q");
  git(h.repository, "add", ".");
  git(h.repository, "commit", "-qm", "Synthetic owner fixture");
  h.mergeDuplicates();
  await using client = h.makeClient();
  const result = await client.run(h.repository, {
    ...h.options,
    ownerSuggestions: true,
  });
  expect(result.ownerSuggestionsError).toBeUndefined();
  expect(result.ownerSuggestionsPath).toBe(
    join(h.outputDir, "owner-suggestions.json"),
  );
  expect(h.preparations()).toBe(1);
  const ownerTurns = h.launches.filter(
    ({ threadOptions }) =>
      threadOptions.threadSource ===
      CODEX_SECURITY_THREAD_SOURCES.suggestOwners,
  );
  expect(ownerTurns).toHaveLength(0);
  expect(h.records.get(result.manifest.scan.id)?.mode).toBe("deep");
  const discoveryPrompts = h.completedPrompts.filter((prompt) =>
    prompt.startsWith("Use [$codex-security]"),
  );
  expect(discoveryPrompts).toHaveLength(2);
  for (const prompt of discoveryPrompts)
    expect(prompt).toContain("extensions.ownerSuggestion");
  expect(
    JSON.parse(await readFile(result.ownerSuggestionsPath!, "utf8")),
  ).toMatchObject({
    results: [
      {
        findingId: result.findings.findings[0]!.findingId,
        status: "abstained",
        reason: "The scan did not record a supported owner suggestion.",
      },
    ],
  });
  for (const record of h.records.values()) {
    if (record.mode !== "standard") continue;
    await expect(
      readFile(
        join(
          record.registration["scanDir"] as string,
          "owner-suggestions.json",
        ),
      ),
    ).rejects.toMatchObject({ code: "ENOENT" });
  }
});

test.each([
  { global: "flex", selected: undefined, expected: "flex" },
  { global: "flex", selected: "priority", expected: "priority" },
])(
  "custom provider recipes preserve fresh and resumed discovery and reducer settings (tier: $expected)",
  async ({ global, selected, expected }) => {
    const h = await fixture();
    const provider = {
      name: "Synthetic custom provider",
      base_url: "https://provider.example.test/v1",
      wire_api: "responses",
      env_http_headers: { "X-Synthetic": "SYNTHETIC_SETTING" },
      request_max_retries: 7,
      auth: {
        command: "synthetic-auth",
        args: ["session", "synthetic-private-command-argument"],
        env: { CLIENT_SECRET: "synthetic-private-command-environment" },
        refresh_interval_ms: 1000,
      },
    };
    const replaySettings = {
      analytics: { enabled: false },
      developer_instructions: "synthetic-private-developer-instructions",
      shell_environment_policy: {
        inherit: "all",
        set: { SYNTHETIC_SETTING: "synthetic-private-shell-value" },
      },
      model_instructions_file: join(h.root, "instructions.md"),
      experimental_compact_prompt_file: join(h.root, "compact.md"),
      model_catalog_json: join(h.root, "catalog.json"),
      sqlite_home: join(h.root, "sqlite"),
    };
    await writeFile(
      replaySettings.model_instructions_file,
      "Synthetic replay instructions.",
    );
    await writeFile(
      replaySettings.experimental_compact_prompt_file,
      "Synthetic compact prompt.",
    );
    await writeFile(
      replaySettings.model_catalog_json,
      JSON.stringify({ models: [] }),
    );
    await mkdir(replaySettings.sqlite_home);
    h.stopBeforeSealing();
    await using first = h.makeClient({
      ...replaySettings,
      model_instructions_file: "../instructions.md",
      experimental_compact_prompt_file: "../compact.md",
      model_catalog_json: "../catalog.json",
      sqlite_home: "../sqlite",
      profile: "selected",
      service_tier: global,
      model_context_window: 128_000,
      model_auto_compact_token_limit: 96_000,
      profiles: {
        selected: {
          model_provider: "synthetic",
          ...(selected === undefined
            ? {}
            : {
                service_tier: selected,
                model_auto_compact_token_limit: 112_000,
              }),
        },
      },
      model_providers: {
        synthetic: {
          ...provider,
          experimental_bearer_token: "synthetic-private-bearer",
          http_headers: { Authorization: "Bearer synthetic-private-header" },
        },
      },
    });
    const options = {
      ...h.options,
      workers: 1,
      knowledgeBasePaths: undefined,
    };
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan-recipe",
      "--scan-id",
      parentId,
    ]);
    const config = (saved["recipe"] as JsonObject)["config"] as JsonObject;
    const replayProvider = {
      ...provider,
      auth: { ...provider.auth, cwd: h.home },
    };
    expect(config).not.toHaveProperty("model_providers");
    const providerProfile = (saved["recipe"] as JsonObject)["providerProfile"];
    const restored = await restoreProviderProfile(config, providerProfile, {
      CODEX_HOME: h.home,
    });
    expect(restored["model_providers"]).toEqual({
      synthetic: {
        ...replayProvider,
        experimental_bearer_token: "synthetic-private-bearer",
        http_headers: { Authorization: "Bearer synthetic-private-header" },
      },
    });
    expect(restored).toMatchObject(replaySettings);
    expect(config["service_tier"]).toBe(expected);
    const contextLimits = {
      model_context_window: 128_000,
      model_auto_compact_token_limit: selected === undefined ? 96_000 : 112_000,
    };
    expect(config).toMatchObject(contextLimits);
    await writeFile(
      join(h.home, "config.toml"),
      "model_context_window = 999000\nmodel_auto_compact_token_limit = 888000\n",
    );
    expect(JSON.stringify(saved)).not.toContain("synthetic-private-");
    await using resumed = h.makeClient(restored);
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    expect(result.findings.findings).toHaveLength(2);
    expect(h.launches[0]!.options.env!["CODEX_SECURITY_SCAN_ID"]).toBe(
      h.launches[1]!.options.env!["CODEX_SECURITY_SCAN_ID"],
    );
    expect(
      h.launches.some(
        (launch) =>
          h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!
            .mode === "deep",
      ),
    ).toBe(true);
    const { auth: _privateAuth, ...transportProvider } = replayProvider;
    for (const launch of h.launches) {
      expect(
        (launch.options.config!["model_providers"] as JsonObject)["synthetic"],
      ).not.toHaveProperty("auth");
      expect(effectiveCodexConfiguration(launch.options)).toMatchObject({
        model_provider: "synthetic",
        model_providers: { synthetic: transportProvider },
        service_tier: expected,
        ...replaySettings,
        ...contextLimits,
      });
      expect(launch.preflightConfig).not.toHaveProperty("model_providers");
    }
  },
);

test("native ChatGPT resume preserves a saved absent safety identifier", async () => {
  const h = await fixture(undefined, true);
  delete h.environment["OPENAI_API_KEY"];
  delete h.environment["CODEX_API_KEY"];
  delete h.environment["CODEX_SAFETY_IDENTIFIER"];
  await writeFile(
    join(h.home, "auth.json"),
    JSON.stringify({
      auth_mode: "chatgpt",
      tokens: { access_token: "synthetic-stored-access-token" },
    }),
  );
  h.stopAfterSealing("standard");
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, workers: 1, auth: "chatgpt" }),
  ).rejects.toBeInstanceOf(ScanTransportClosedError);
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const commandOptions = { ...parent.options, signal: undefined };
  const saved = await runWorkbench(commandOptions, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  const receipt = await runWorkbench(commandOptions, [
    "get-scan-recipe",
    "--scan-id",
    parentId,
  ]);
  const recipe = receipt["recipe"] as JsonObject;
  expect(recipe).not.toHaveProperty("safetyIdentifier");
  h.environment["CODEX_SAFETY_IDENTIFIER"] = "later-ambient-identifier";
  const nativeEnvironment = {
    CODEX_HOME: h.home,
    CODEX_CLI_PATH: process.execPath,
    CODEX_API_KEY: undefined,
    OPENAI_API_KEY: undefined,
    CODEX_SAFETY_IDENTIFIER: h.environment["CODEX_SAFETY_IDENTIFIER"],
    CODEX_SECURITY_CONFIG_PATH: undefined,
    CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH: undefined,
  };
  const original = Object.keys(nativeEnvironment).map(
    (key) => [key, process.env[key]] as const,
  );
  const { prepareNativeScan } = await import(
    new URL(
      "../../../plugins/codex-security/mcp-app/src/native-scan.ts",
      import.meta.url,
    ).href
  );
  const prepared = await (async () => {
    try {
      for (const [key, value] of Object.entries(nativeEnvironment)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      return await prepareNativeScan({
        scan: saved["scan"],
        recipe,
        threadId: "native-owner",
        pluginRoot,
        pythonPath: Bun.which("python3")!,
        stateDirectory: join(h.root, "state"),
        parentSandbox: { filesystemDenies: [] },
      });
    } finally {
      for (const [key, value] of original) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
  })();
  try {
    const previousLaunches = h.launches.length;
    const authentications: unknown[] = [];
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, {
      ...prepared.options,
      onAuthentication(authentication) {
        authentications.push(authentication);
      },
    });
    expect(authentications).not.toHaveLength(0);
    for (const authentication of authentications)
      expect(authentication).toMatchObject({
        method: "stored_credentials",
        credentialType: "chatgpt",
      });
    expect(result.findings.findings).toHaveLength(2);
    expect(prepared.options.safetyIdentifier).toBeUndefined();
    const resumedLaunches = h.launches.slice(previousLaunches);
    expect(
      new Set(
        resumedLaunches.map(
          (launch) =>
            h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode,
        ),
      ),
    ).toEqual(new Set(["standard", "deep"]));
    for (const launch of resumedLaunches)
      expect(launch.options.env).not.toHaveProperty("CODEX_SAFETY_IDENTIFIER");
  } finally {
    await prepared.client.close();
  }
});

test("a reused client's sealed read uses its installed plugin after the source is removed", async () => {
  const h = await fixture();
  const source = join(h.root, "plugin-source");
  await cp(pluginRoot, source, {
    recursive: true,
    filter: (path) => path !== join(pluginRoot, "mcp-app", "node_modules"),
  });
  await using client = h.makeClient({}, source);
  const options = { ...h.options, knowledgeBasePaths: undefined };
  h.stopAfterSealing();
  await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const findings = JSON.parse(
    await readFile(join(h.outputDir, "findings.json"), "utf8"),
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  await rm(source, { recursive: true });
  h.forbidCodex();
  const restored = await client.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(restored.findings).toEqual(findings);
  expect(h.launches).toHaveLength(3);
});

test.each([
  "sdk",
  "native",
  "native-missing-profile",
  "native-missing-home",
  "native-follow-up",
  "native-wrong-claim",
  "native-unsealed",
] as const)(
  "saved %s resume keeps publication independent from model credentials",
  async (surface) => {
    const privateReplay = surface !== "sdk" && surface !== "native";
    const unsealed = surface === "native-unsealed";
    const followUp = surface === "native-follow-up";
    const wrongClaim = surface === "native-wrong-claim";
    const h = await fixture(undefined, surface !== "sdk");
    if (unsealed) h.stopBeforeSealing("deep");
    else h.stopAfterSealing();
    await using first = h.makeClient(
      privateReplay
        ? {
            model_provider: "synthetic",
            model_providers: {
              synthetic: {
                name: "Synthetic",
                wire_api: "responses",
                requires_openai_auth: true,
                http_headers: {
                  Authorization: "synthetic-private-native-token",
                },
              },
            },
          }
        : {},
    );
    await expect(
      first.run(h.repository, {
        ...h.options,
        knowledgeBasePaths: undefined,
        ...(followUp
          ? { postScanPrompt: "Synthetic requested follow-up" }
          : {}),
      }),
    ).rejects.toBeInstanceOf(ScanTransportClosedError);
    const parentId = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )![0];
    const findings = unsealed
      ? undefined
      : JSON.parse(await readFile(join(h.outputDir, "findings.json"), "utf8"));
    const artifactNames = [
      "artifacts/deep-scan/checkpoint.json",
      ...(unsealed
        ? []
        : [
            "scan-manifest.json",
            "findings.json",
            "coverage.json",
            "report.md",
          ]),
    ];
    const artifacts = await Promise.all(
      artifactNames.map((name) => readFile(join(h.outputDir, name))),
    );
    const priorFinding = {
      findingId: "prior-open-issue",
      title: "Earlier issue",
      status: "open",
      confirmedInLatestScan: false,
    };
    h.setRepositoryFindings([priorFinding]);
    h.forbidCodex();
    if (surface === "sdk") {
      await using resumed = h.makeClient();
      const restored = await resumed.run(h.repository, {
        ...h.options,
        signal: undefined,
        knowledgeBasePaths: undefined,
        resumeScanId: parentId,
      });
      expect(restored.findings).toEqual(findings);
      expect(restored.repositoryFindings).toMatchObject([priorFinding]);
    } else {
      const keys = [
        "CODEX_HOME",
        "CODEX_CLI_PATH",
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "CODEX_SECURITY_CONFIG_PATH",
        "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
      ];
      const original = keys.map((key) => [key, process.env[key]] as const);
      try {
        for (const key of keys) delete process.env[key];
        Object.assign(process.env, {
          CODEX_HOME: h.home,
          CODEX_CLI_PATH: process.execPath,
          OPENAI_API_KEY: "synthetic-unusable-key",
        });
        const parent = h.records.get(parentId)!;
        const saved = await runWorkbench(
          { ...parent.options, signal: undefined },
          ["get-scan", "--scan-id", parentId],
        );
        if (privateReplay) {
          const joined = await runWorkbench(
            { ...parent.options, signal: undefined },
            [
              "begin-deep-scan",
              "--scan-id",
              parentId,
              "--thread-id",
              "native-owner",
              "--claim-token",
              h.options.registeredScan!.handoffClaimToken!,
            ],
          );
          expect(joined["recipe"]).toEqual(parent.recipe);
          const receipt = await runWorkbench(
            { ...parent.options, signal: undefined },
            [
              "get-cli-scan-resume",
              "--scan-id",
              parentId,
              "--claim-token",
              h.options.registeredScan!.handoffClaimToken!,
            ],
          );
          expect(typeof receipt["sealedProducerVersion"]).toBe(
            unsealed ? "undefined" : "string",
          );
          const profile = parent.recipe["providerProfile"] as JsonObject;
          expect(typeof profile["name"]).toBe("string");
          expect(profile["home"]).toBe("ambient");
          const path = join(h.home, `${profile["name"]}.config.toml`);
          expect(await readFile(path, "utf8")).toContain(
            "synthetic-private-native-token",
          );
          if (surface === "native-missing-home")
            await rm(h.home, { recursive: true });
          else await rm(path);
        }
        const { prepareNativeScan } = await import(
          new URL(
            "../../../plugins/codex-security/mcp-app/src/native-scan.ts",
            import.meta.url,
          ).href
        );
        const preparation = prepareNativeScan({
          scan: wrongClaim
            ? {
                ...(saved["scan"] as JsonObject),
                handoffClaimToken: randomUUID(),
              }
            : saved["scan"],
          recipe: parent.recipe,
          threadId: "native-owner",
          pluginRoot,
          pythonPath: Bun.which("python3")!,
          stateDirectory: join(h.root, "state"),
          parentSandbox: { filesystemDenies: [] },
        });
        if (followUp || unsealed) {
          await expect(preparation).rejects.toThrow("ENOENT");
          expect(
            (
              await runWorkbench({ ...parent.options, signal: undefined }, [
                "get-scan",
                "--scan-id",
                parentId,
              ])
            )["scan"],
          ).toMatchObject({ progress: { status: "running" } });
          expect(
            await Promise.all(
              artifactNames.map((name) => readFile(join(h.outputDir, name))),
            ),
          ).toEqual(artifacts);
          expect(h.launches).toHaveLength(3);
          return;
        }
        const prepared = await preparation;
        const resumed = prepared.client;
        try {
          const pending = resumed.run(h.repository, {
            ...prepared.options,
            onWarning() {},
          });
          if (wrongClaim) {
            await expect(pending).rejects.toThrow("another continuation");
            expect(
              (
                await runWorkbench({ ...parent.options, signal: undefined }, [
                  "get-scan",
                  "--scan-id",
                  parentId,
                ])
              )["scan"],
            ).toMatchObject({ progress: { status: "running" } });
            expect(
              await Promise.all(
                artifactNames.map((name) => readFile(join(h.outputDir, name))),
              ),
            ).toEqual(artifacts);
            expect(h.launches).toHaveLength(3);
            return;
          }
          const restored = await pending;
          expect(restored.findings).toEqual(findings);
          const completed = await runWorkbench(
            { ...parent.options, signal: undefined },
            ["get-scan", "--scan-id", parentId],
          );
          expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
            status: "complete",
          });
        } finally {
          await resumed.close();
        }
      } finally {
        for (const [key, value] of original) {
          if (value === undefined) delete process.env[key];
          else process.env[key] = value;
        }
      }
    }
    expect(h.launches).toHaveLength(3);
    expect(
      await Promise.all(
        artifactNames.map((name) => readFile(join(h.outputDir, name))),
      ),
    ).toEqual(artifacts);
  },
);

test("zero-work Deep Scan preserves a zero receipt across interrupted sealing", async () => {
  const h = await fixture();
  const options = {
    ...h.options,
    maxTimeHours: 1e-12,
    maxCostUsd: 1,
    knowledgeBasePaths: undefined,
  };
  h.stopAfterSealing();
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  const zeroCost = estimateScanCost("gpt-6-astra", {
    input_tokens: 0,
    output_tokens: 0,
  });
  expect(checkpoint.passes).toEqual([]);
  expect(checkpoint.mergeStarted).toBeUndefined();
  expect(checkpoint.finalCost).toEqual(zeroCost);
  expect(h.launches).toHaveLength(0);
  h.forbidCodex();
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(result.cost).toEqual(zeroCost);
  expect(result.findings.findings).toEqual([]);
  expect(result.coverage).not.toHaveProperty("completeness");
  const deferredReason =
    "The configured discovery time limit elapsed before any source review completed.";
  expect(result.coverage.deferred).toEqual([
    expect.objectContaining({
      reason: deferredReason,
    }),
  ]);
  expect(await readFile(join(h.outputDir, "report.md"), "utf8")).toContain(
    deferredReason,
  );
  expect(h.launches).toHaveLength(0);
});

async function interruptedSealedChild() {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  const options = {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 3,
    knowledgeBasePaths: undefined,
    maxCostUsd: passCost.estimatedUsd * 1.5,
  };
  h.stopAfterSealing("standard");
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const [childId, childRecord] = [...h.records].find(
    ([, record]) => record.mode === "standard",
  )!;
  const saved = await runWorkbench(
    { ...childRecord.options, signal: undefined },
    ["get-scan", "--scan-id", childId],
  );
  const child = saved["scan"] as JsonObject;
  expect(child["progress"]).toMatchObject({ status: "running" });
  expect(h.launches).toHaveLength(1);
  const childDirectory = childRecord.registration["scanDir"] as string;
  const manifest = JSON.parse(
    await readFile(join(childDirectory, "scan-manifest.json"), "utf8"),
  );
  expect(manifest.scan.status).toBe("completed");
  expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
  return {
    h,
    child,
    childId,
    childRecord,
    passCost,
    resumeOptions: { ...options, signal: undefined, resumeScanId: parentId },
  };
}

test.each(["live", "archived"])(
  "a sealed child resumes from %s session accounting and counts against the Deep Scan budget",
  async (storage) => {
    const { h, childId, childRecord, passCost, resumeOptions } =
      await interruptedSealedChild();
    if (storage === "archived")
      await rename(join(h.home, "sessions"), join(h.home, "archived_sessions"));
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, resumeOptions);
    const saved = await runWorkbench(
      { ...childRecord.options, signal: undefined },
      ["get-scan", "--scan-id", childId],
    );
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
    expect(saved["scan"]).toMatchObject({ cost: passCost });
    expect(h.launches).toHaveLength(2);
    expect(h.commands).toContain("complete-budget-exhausted-scan");
    expect(result.findings.findings).toHaveLength(2);
    expect(result.cost?.estimatedUsd).toBeCloseTo(
      passCost.estimatedUsd * 2,
      12,
    );
  },
);

test.each([
  ["sdk", false],
  ["native", false],
  ["native", true],
] as const)(
  "%s resume retains archived reducer subagent usage (budget: %p)",
  async (resume, budget) => {
    const h = await fixture(undefined, resume === "native");
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      ...(budget
        ? {
            maxCostUsd:
              estimateScanCost("gpt-6-astra", usage)!.estimatedUsd * 10,
          }
        : {}),
    };
    h.failPublication(true);
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      DeepScanPublicationError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const reducerThreadId = [...h.threadScans].find(
      ([, scanId]) => scanId === parentId,
    )![0];
    const archivedUsage = { input_tokens: 1000, output_tokens: 100 };
    await mkdir(join(h.home, "archived_sessions"));
    await writeFile(
      join(h.home, "archived_sessions", "reducer-subagent.jsonl"),
      [
        {
          type: "session_meta",
          payload: {
            id: "archived-reducer-subagent",
            cwd: join(h.outputDir, "artifacts", "deep-scan", "merge"),
            parent_thread_id: reducerThreadId,
            timestamp: new Date().toISOString(),
          },
        },
        tokenUsageEvent(archivedUsage),
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );
    h.failPublication(false);
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, {
      ...options,
      ...(resume === "native"
        ? { registeredScan: options.registeredScan! }
        : { resumeScanId: parentId }),
    });
    expect(result.cost).toMatchObject({
      inputTokens: usage.input_tokens * 3 + archivedUsage.input_tokens,
      outputTokens: usage.output_tokens * 3 + archivedUsage.output_tokens,
    });
    expect(result.cost?.estimatedUsd).toBeCloseTo(
      estimateScanCost("gpt-6-astra", {
        input_tokens: usage.input_tokens * 3 + archivedUsage.input_tokens,
        cached_input_tokens: 0,
        output_tokens: usage.output_tokens * 3 + archivedUsage.output_tokens,
      })!.estimatedUsd,
      12,
    );
    expect(h.launches).toHaveLength(3);
    if (budget) {
      expect(result.cost!.estimatedUsd).toBeGreaterThan(options.maxCostUsd!);
      expect(result.coverage).not.toHaveProperty("completeness");
      expect(h.commands).toContain("complete-budget-exhausted-scan");
    }
    const completed = await runWorkbench(
      { ...parent.options, signal: undefined },
      ["get-scan", "--scan-id", parentId],
    );
    expect(completed["scan"]).toMatchObject({
      cost: result.cost,
      progress: { status: "complete" },
    });
  },
);

test("a sealed child without persisted usage rejects cost-limited Deep Scan resume", async () => {
  const { h, child, resumeOptions } = await interruptedSealedChild();
  const sessionPath = join(
    h.home,
    "sessions",
    `rollout-${child["continuationThreadId"]}.jsonl`,
  );
  const metadata = (await readFile(sessionPath, "utf8"))
    .split("\n")
    .filter((line) => line && JSON.parse(line).type === "session_meta");
  await writeFile(sessionPath, metadata.join("\n") + "\n");
  await using resumed = h.makeClient();
  await expect(resumed.run(h.repository, resumeOptions)).rejects.toBeInstanceOf(
    ScanCostTrackingError,
  );
  expect(h.launches).toHaveLength(1);
});

test("sealed recovery rejects a partial receipt when final accounting is unavailable", async () => {
  const h = await fixture();
  h.stopAfterSealing();
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(ScanTransportClosedError);
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const checkpointPath = join(
    h.outputDir,
    "artifacts/deep-scan/checkpoint.json",
  );
  const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
  expect(checkpoint.finalCost).not.toBeNull();
  delete checkpoint.finalCost;
  await writeFile(checkpointPath, JSON.stringify(checkpoint));
  h.forbidCodex();
  await using resumed = h.makeClient();
  await expect(
    resumed.run(h.repository, {
      ...h.options,
      signal: undefined,
      knowledgeBasePaths: undefined,
      resumeScanId: parentId,
      requireCost: true,
    }),
  ).rejects.toThrow("no verified cost receipt");
  expect(h.launches).toHaveLength(3);
});

test("accepted publication failure remains resumable without repeating child work", async () => {
  const h = await fixture();
  h.failPublication(true);
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(DeepScanPublicationError);
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  h.failPublication(false);
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...h.options,
    knowledgeBasePaths: undefined,
    resumeScanId: parentId,
  });
  expect(result.findings.findings).toHaveLength(2);
  expect(h.launches).toHaveLength(3);
});

test.each([
  { resumed: false, command: "prepare-scan-completion" },
  { resumed: true, command: "prepare-scan-completion" },
  { resumed: false, command: "complete-scan" },
  { resumed: true, command: "complete-scan" },
] as const)(
  "final Deep publication can retry accepted work (%p)",
  async ({ resumed, command }) => {
    const h = await fixture();
    const options = { ...h.options, knowledgeBasePaths: undefined };
    let resumeScanId: string | undefined;
    if (resumed) {
      h.stopBeforeSealing("deep");
      await using first = h.makeClient();
      await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      resumeScanId = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )![0];
    }

    h.failFinalPublication(command);
    await using interrupted = h.makeClient();
    const failure = await interrupted
      .run(h.repository, { ...options, signal: undefined, resumeScanId })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toContain(
      "Synthetic transient final publication failure",
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "running",
    });
    expect(failure).toBeInstanceOf(DeepScanPublicationError);
    expect(h.commands).not.toContain("fail-scan");
    const accepted = await loadDeepScanCheckpoint(h.outputDir);
    expect(accepted!.mergedScanIds).toHaveLength(2);
    expect(accepted!.aggregate!.findings).toHaveLength(2);
    expect(accepted!.finalCost).toBeDefined();
    expect(accepted!.finalCost).not.toBeNull();
    expect(h.launches).toHaveLength(3);
    const manifest = JSON.parse(
      await readFile(join(h.outputDir, "scan-manifest.json"), "utf8"),
    );
    if (command === "complete-scan") {
      expect(manifest.scan.sealedAt).toBeString();
      h.forbidCodex();
    } else {
      expect(manifest.scan.sealedAt).toBeUndefined();
    }

    await using retry = h.makeClient();
    const result = await retry.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    expect(result.findings.findings).toHaveLength(2);
    expect(result.cost).toEqual(accepted!.finalCost!);
    expect(h.launches).toHaveLength(3);
    const completed = await runWorkbench(
      { ...parent.options, signal: undefined },
      ["get-scan", "--scan-id", parentId],
    );
    expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
  },
);

test("lost final completion response preserves the completed Deep result", async () => {
  const h = await fixture();
  const artifacts = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const readArtifacts = () =>
    Promise.all(artifacts.map((name) => readFile(join(h.outputDir, name))));
  let sealedArtifacts: Awaited<ReturnType<typeof readArtifacts>> | undefined;
  h.afterCompletion(async () => {
    sealedArtifacts = await readArtifacts();
    throw new Error("Synthetic lost final completion response");
  });
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toBeInstanceOf(DeepScanPublicationError);
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "complete",
  });
  expect(sealedArtifacts).toBeDefined();
  expect(
    JSON.parse(sealedArtifacts![0]!.toString()).scan.sealedAt,
  ).toBeString();
  expect(await readArtifacts()).toEqual(sealedArtifacts!);
  expect(h.commands).not.toContain("fail-scan");

  expect(h.launches).toHaveLength(3);
});

test("a resumed child projection failure keeps accepted work resumable", async () => {
  const h = await fixture();
  const options = { ...h.options, knowledgeBasePaths: undefined };
  h.failPublication(true);
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    DeepScanPublicationError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const accepted = await loadDeepScanCheckpoint(h.outputDir);
  expect(accepted!.mergedScanIds).toHaveLength(2);
  expect(h.launches).toHaveLength(3);

  h.failPublication(false);
  h.failChildProjection(true);
  await using interrupted = h.makeClient();
  await expect(
    interrupted.run(h.repository, { ...options, resumeScanId: parentId }),
  ).rejects.toBeInstanceOf(DeepScanRecoveryError);
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "running",
  });
  expect(h.commands).not.toContain("fail-scan");
  expect((await loadDeepScanCheckpoint(h.outputDir))!.mergedScanIds).toEqual(
    accepted!.mergedScanIds,
  );

  h.failChildProjection(false);
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    resumeScanId: parentId,
  });
  expect(result.findings.findings).toHaveLength(2);
  expect(h.launches).toHaveLength(3);
  const completed = await runWorkbench(
    { ...parent.options, signal: undefined },
    ["get-scan", "--scan-id", parentId],
  );
  expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "complete",
  });
});

test("publication recovery keeps verified cost when one child is empty", async () => {
  const h = await fixture();
  h.makeFirstChildEmpty();
  h.failPublication(true);
  const options = {
    ...h.options,
    knowledgeBasePaths: undefined,
    maxCostUsd: 1,
    requireCost: true,
  };
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    DeepScanPublicationError,
  );
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const accepted = await loadDeepScanCheckpoint(h.outputDir);
  expect(accepted!.mergedScanIds).toHaveLength(2);
  expect(accepted!.aggregate!.findings).toHaveLength(1);
  expect(accepted!.mergeStarted).not.toBe(true);
  expect(h.launches).toHaveLength(2);
  expect(
    h.launches.every(
      (launch) =>
        h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
        "standard",
    ),
  ).toBe(true);

  h.failPublication(false);
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    resumeScanId: parentId,
  });
  expect(h.launches).toHaveLength(2);
  expect(result.threadId).toBeNull();
  expect(result.findings.findings).toHaveLength(1);
  expect(result.findings.findings[0]!.provenance["sourceFindings"]).toEqual(
    Object.entries(accepted!.aggregate!.sourceFindings).map(
      ([id, finding]) => ({
        id,
        finding,
      }),
    ),
  );
  expect(result.cost?.estimatedUsd).toBeCloseTo(
    estimateScanCost("gpt-6-astra", usage)!.estimatedUsd * 2,
    12,
  );
  const completed = await loadDeepScanCheckpoint(h.outputDir);
  expect(completed!.finalCost).toEqual(result.cost);
});

test.each([
  ["draft", false],
  ["receipt", false],
  ["receipt", true],
  ["budget", true],
] as const)(
  "foreground interruption during %s publication cancels retained output (budget: %p)",
  async (stage, budget) => {
    const h = await fixture();
    await h.interruptPublication(stage);
    await using client = h.makeClient();
    const failure = await client
      .run(h.repository, {
        ...h.options,
        knowledgeBasePaths: undefined,
        ...(budget
          ? {
              workers: 1,
              maxDiscoveryRuns: 3,
              maxCostUsd:
                estimateScanCost("gpt-6-astra", usage)!.estimatedUsd * 1.5,
            }
          : {}),
      })
      .then(
        () => null,
        (error: unknown) => error,
      );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "canceled",
    });
    expect(failure).toBeInstanceOf(ScanInterruptedError);
    expect(failure).not.toBeInstanceOf(DeepScanPublicationError);
    expect((failure as Error).cause).toBe(h.cancellation);
    expect(String(h.publicationFailure())).toContain("KeyboardInterrupt");
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.mergedScanIds.length).toBeGreaterThan(0);
    expect(h.launches).toHaveLength(budget ? 2 : 3);
    if (stage === "draft") expect(checkpoint.terminalReason).toBe("canceled");
  },
);

test.each([false, true])(
  "follow-up writes fresh output while sealed reports stay read-only (resumed: %p)",
  async (resumed) => {
    const h = await fixture();
    let resumeScanId: string | undefined;
    if (resumed) {
      h.stopAfterSealing();
      await using first = h.makeClient();
      await expect(first.run(h.repository, h.options)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      await writeFile(h.knowledgePath, "Original immutable context");
      resumeScanId = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )![0];
    }
    await using client = h.makeClient();
    const result = await client.run(h.repository, {
      ...h.options,
      ...(resumed
        ? {
            resumeScanId,
            signal: undefined,
            knowledgeBaseSnapshot: await restoreScanKnowledge(
              h.outputDir,
              h.repository,
              h.records.get(resumeScanId!)!.recipe["scanInputs"],
            ),
          }
        : {}),
      postScanPrompt: "Write follow-up notes",
    });
    expect(result.turnResult.finalResponse).toBe(
      await readFile(result.reportPath, "utf8"),
    );
    const followUp = h.launches.at(-1)!;
    const output = followUp.threadOptions.workingDirectory!;
    expect(dirname(output)).toBe(join(h.outputDir, "artifacts/follow-up"));
    expect(effectiveCodexConfiguration(followUp.options)).toMatchObject({
      permissions: {
        codex_security_scan: {
          filesystem: {
            [h.outputDir]: { ".": "read" },
            [output]: { ".": "write" },
            [join(h.root, "private")]: "deny",
          },
        },
      },
    });
    const parentId = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )![0];
    const record = h.records.get(parentId)!;
    const saved = await runWorkbench(record.options, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
  },
);

test("budget exhaustion seals accepted findings without a reducer session", async () => {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  await using client = h.makeClient();
  const result = await client.run(h.repository, {
    ...h.options,
    workers: 1,
    maxDiscoveryRuns: 3,
    maxCostUsd: passCost.estimatedUsd * 1.5,
  });
  expect(h.launches).toHaveLength(2);
  expect(
    h.launches.every(
      (launch) =>
        h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode ===
        "standard",
    ),
  ).toBe(true);
  expect(h.commands).toContain("complete-budget-exhausted-scan");
  expect(result.threadId).toBeNull();
  expect(result.findings.findings).toHaveLength(2);
  expect(result.coverage).not.toHaveProperty("completeness");
  expect(result.cost).not.toBeNull();
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  expect(checkpoint.finalCost).toEqual(result.cost);
});

test("failure follow-up survives the parent's own failed-status transition", async () => {
  const h = await fixture();
  let tracker: DeepScanProgressTracker | undefined;
  const start = spyOn(
    DeepScanProgressTracker.prototype,
    "start",
  ).mockImplementation(function (this: DeepScanProgressTracker) {
    tracker = this;
  });
  const failure = new Error("Synthetic reducer failure");
  h.failReducer(failure, async () => {
    await tracker!.refresh();
  });
  try {
    await using client = h.makeClient();
    await expect(
      client.run(h.repository, {
        ...h.options,
        postScanPrompt: "Write follow-up notes",
      }),
    ).rejects.toBe(failure);
    expect(
      h.completedPrompts.some((prompt) =>
        prompt.endsWith("Write follow-up notes"),
      ),
    ).toBe(true);
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "failed",
    });
  } finally {
    start.mockRestore();
  }
});

test.each(["direct", "resumed"])(
  "first parallel batch budget recovery (%s) preserves completed discovery without a reducer",
  async (recovery) => {
    const h = await fixture();
    h.completeFirstChildBeforeSibling();
    const passCost = estimateScanCost("gpt-6-astra", usage)!;
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 2,
      maxDiscoveryRuns: 4,
      maxCostUsd: passCost.estimatedUsd * 1.5,
    };
    await using client = h.makeClient();
    let result;
    if (recovery === "resumed") {
      h.stopBeforeBudgetCompletion();
      await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
        ScanTransportClosedError,
      );
      const [parentId, parent] = [...h.records].find(
        ([, record]) => record.mode === "deep",
      )!;
      const interrupted = await runWorkbench(
        { ...parent.options, signal: undefined },
        ["get-scan", "--scan-id", parentId],
      );
      expect((interrupted["scan"] as JsonObject)["progress"]).toMatchObject({
        status: "running",
      });
      await expect(
        readFile(join(h.outputDir, "scan-manifest.json")),
      ).rejects.toMatchObject({ code: "ENOENT" });
      const receipt = JSON.parse(
        await readFile(
          join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
          "utf8",
        ),
      );
      expect(receipt.finalCost.estimatedUsd).toBeCloseTo(
        passCost.estimatedUsd * 2,
        12,
      );
      expect(h.launches).toHaveLength(2);
      await using resumed = h.makeClient();
      result = await resumed.run(h.repository, {
        ...options,
        signal: undefined,
        resumeScanId: parentId,
      });
    } else {
      result = await client.run(h.repository, options);
    }
    expect(h.launches).toHaveLength(2);
    expect(
      h.launches.every(
        (launch) =>
          h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!
            .mode === "standard",
      ),
    ).toBe(true);
    expect(result.threadId).toBeNull();
    expect(result.coverage).not.toHaveProperty("completeness");
    expect(result.findings.findings).toContainEqual(
      expect.objectContaining({ title: "First completed discovery" }),
    );
    expect(result.cost?.estimatedUsd).toBeCloseTo(
      passCost.estimatedUsd * 2,
      12,
    );
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.finalCost).toEqual(result.cost);
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "complete",
    });
  },
);

test("resumed reducer budget recovery includes completed child receipts before enforcing the saved limit", async () => {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  const options = {
    ...h.options,
    knowledgeBasePaths: undefined,
    maxCostUsd: passCost.estimatedUsd * 3.5,
  };
  h.stopBeforeSealing("deep");
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  const parentScan = saved["scan"] as JsonObject;
  expect(parentScan["progress"]).toMatchObject({ status: "running" });
  expect(h.launches).toHaveLength(3);
  for (const [childId, child] of h.records) {
    if (child.mode !== "standard") continue;
    const complete = await runWorkbench(
      { ...child.options, signal: undefined },
      ["get-scan", "--scan-id", childId],
    );
    expect(complete["scan"]).toMatchObject({
      cost: passCost,
      progress: { status: "complete" },
    });
    // A prior execution can have a different price for the same token counts.
    await runWorkbench({ ...child.options, signal: undefined }, [
      "complete-scan",
      "--scan-id",
      childId,
      "--cost-json",
      JSON.stringify({ ...passCost, estimatedUsd: passCost.estimatedUsd / 2 }),
    ]);
  }
  await appendFile(
    join(
      h.home,
      "sessions",
      `rollout-${parentScan["continuationThreadId"]}.jsonl`,
    ),
    JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: {
            input_tokens: usage.input_tokens * 4,
            cached_input_tokens: usage.cached_input_tokens * 4,
            output_tokens: usage.output_tokens * 4,
          },
        },
      },
    }) + "\n",
  );
  await using resumed = h.makeClient();
  const result = await resumed.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(h.launches).toHaveLength(3);
  expect(result.findings.findings).toHaveLength(2);
  expect(result.coverage).not.toHaveProperty("completeness");
  const expectedCost = {
    ...estimateScanCost("gpt-6-astra", {
      input_tokens: usage.input_tokens * 6,
      cached_input_tokens: usage.cached_input_tokens * 6,
      output_tokens: usage.output_tokens * 6,
    })!,
    estimatedUsd: result.cost!.estimatedUsd,
  };
  expect(result.cost?.estimatedUsd).toBeCloseTo(passCost.estimatedUsd * 5, 12);
  expect(result.cost).toEqual(expectedCost);
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  expect(checkpoint.finalCost).toEqual(expectedCost);
  const complete = await runWorkbench(
    { ...parent.options, signal: undefined },
    ["get-scan", "--scan-id", parentId],
  );
  expect(complete["scan"]).toMatchObject({
    cost: expectedCost,
    progress: { status: "complete" },
  });
});

test("budget exhaustion resumes from its final receipt after sealing before database completion", async () => {
  const h = await fixture();
  const passCost = estimateScanCost("gpt-6-astra", usage)!;
  await h.stopBudgetAfterSealing();
  await using first = h.makeClient();
  await expect(
    first.run(h.repository, {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 1,
      maxDiscoveryRuns: 3,
      maxCostUsd: passCost.estimatedUsd * 1.5,
    }),
  ).rejects.toBeInstanceOf(DeepScanPublicationError);
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
    "get-scan",
    "--scan-id",
    parentId,
  ]);
  expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "running",
  });
  const manifestPath = join(h.outputDir, "scan-manifest.json");
  const sealedManifest = await readFile(manifestPath, "utf8");
  const manifest = JSON.parse(sealedManifest);
  expect(manifest.scan.status).toBe("completed");
  expect(manifest.scan.sealedAt).toBe(manifest.scan.completedAt);
  const checkpoint = JSON.parse(
    await readFile(
      join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
      "utf8",
    ),
  );
  const expectedCost = estimateScanCost("gpt-6-astra", {
    input_tokens: usage.input_tokens * 2,
    cached_input_tokens: usage.cached_input_tokens * 2,
    output_tokens: usage.output_tokens * 2,
  });
  expect(checkpoint.finalCost).toEqual(expectedCost);
  expect(h.launches).toHaveLength(2);
  expect(parent.recipe["maxCostUsd"]).toBe(passCost.estimatedUsd * 1.5);

  h.restoreWorkbench();
  h.forbidCodex();
  await using resumed = h.makeClient();
  const restored = await resumed.run(h.repository, {
    ...h.options,
    signal: undefined,
    knowledgeBasePaths: undefined,
    resumeScanId: parentId,
    maxCostUsd: parent.recipe["maxCostUsd"] as number,
  });
  expect(restored.cost).toEqual(expectedCost);
  expect(restored.findings.findings).toHaveLength(2);
  expect(restored.coverage).not.toHaveProperty("completeness");
  expect(await readFile(manifestPath, "utf8")).toBe(sealedManifest);
  expect(h.launches).toHaveLength(2);
  const completed = await runWorkbench(
    { ...parent.options, signal: undefined },
    ["get-scan", "--scan-id", parentId],
  );
  expect((completed["scan"] as JsonObject)["progress"]).toMatchObject({
    status: "complete",
  });
});

function unavailableFinalCost(
  h: Awaited<ReturnType<typeof fixture>>,
  mode: string,
) {
  const scans = new WeakMap<ScanCostTracker, string>();
  const start = ScanCostTracker.prototype.start;
  const stop = ScanCostTracker.prototype.stop;
  const startSpy = spyOn(ScanCostTracker.prototype, "start").mockImplementation(
    function (this: ScanCostTracker, threadId: string) {
      scans.set(this, h.threadScans.get(threadId)!);
      return start.call(this, threadId);
    },
  );
  const stopSpy = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
    async function (this: ScanCostTracker, fallbackUsage?: unknown) {
      const snapshot = await stop.call(this, fallbackUsage);
      return h.records.get(scans.get(this)!)?.mode === mode &&
        h.launches.length > 1
        ? { usage: null, cost: null }
        : snapshot;
    },
  );
  return {
    [Symbol.dispose]() {
      stopSpy.mockRestore();
      startSpy.mockRestore();
    },
  };
}

test.each(["standard", "deep"])(
  "budget exhaustion does not finalize an unavailable %s cost receipt",
  async (mode) => {
    const h = await fixture();
    using _failure = unavailableFinalCost(h, mode);
    const passCost = estimateScanCost("gpt-6-astra", usage)!;
    await using client = h.makeClient();
    await expect(
      client.run(h.repository, {
        ...h.options,
        workers: mode === "standard" ? 1 : 2,
        maxDiscoveryRuns: 3,
        maxCostUsd: passCost.estimatedUsd * (mode === "standard" ? 1.5 : 2.5),
      }),
    ).rejects.toBeInstanceOf(ScanCostTrackingError);
    expect(h.launches).toHaveLength(mode === "standard" ? 2 : 3);
    expect(h.commands).not.toContain("complete-budget-exhausted-scan");
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.finalCost).toBeUndefined();
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const saved = await runWorkbench({ ...parent.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      parentId,
    ]);
    expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "failed",
    });
  },
);

test.each(["budget", "execution"])(
  "a resumed child with unavailable final usage cannot reuse its earlier cost receipt after %s failure",
  async (failure) => {
    const h = await fixture();
    const passCost = estimateScanCost("gpt-6-astra", usage)!;
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 1,
      maxDiscoveryRuns: 3,
      maxCostUsd: passCost.estimatedUsd * (failure === "budget" ? 1.5 : 10),
    };
    h.stopBeforeSealing();
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, record]) => record.mode === "deep",
    )!;
    const [childId, child] = [...h.records].find(
      ([, record]) => record.mode === "standard",
    )!;
    const previous = await runWorkbench(
      { ...child.options, signal: undefined },
      ["get-scan", "--scan-id", childId],
    );
    expect(previous["scan"]).toMatchObject({
      cost: passCost,
      progress: { status: "running" },
    });
    const childManifest = JSON.parse(
      await readFile(
        join(child.registration["scanDir"] as string, "scan-manifest.json"),
        "utf8",
      ),
    );
    expect(childManifest.scan.sealedAt).toBeUndefined();

    if (failure === "execution") h.failResumedChild();
    using _failure = unavailableFinalCost(h, "standard");
    await using resumed = h.makeClient();
    let reportedCost = 0;
    await expect(
      resumed.run(h.repository, {
        ...options,
        signal: undefined,
        resumeScanId: parentId,
        onCost(cost) {
          reportedCost = Math.max(reportedCost, cost.estimatedUsd);
        },
      }),
    ).rejects.toBeInstanceOf(ScanCostTrackingError);
    expect(reportedCost).toBeCloseTo(passCost.estimatedUsd * 2, 12);
    expect(h.launches).toHaveLength(2);
    expect(h.records.size).toBe(2);
    expect(h.commands).not.toContain("complete-budget-exhausted-scan");
    const checkpoint = JSON.parse(
      await readFile(
        join(h.outputDir, "artifacts/deep-scan/checkpoint.json"),
        "utf8",
      ),
    );
    expect(checkpoint.finalCost).toBeUndefined();
    expect(checkpoint.costUnavailable).toBe(true);
    const failed = await runWorkbench({ ...child.options, signal: undefined }, [
      "get-scan",
      "--scan-id",
      childId,
    ]);
    expect(failed["scan"]).toMatchObject({
      cost: estimateScanCost("gpt-6-astra", {
        input_tokens: usage.input_tokens * 2,
        cached_input_tokens: usage.cached_input_tokens * 2,
        output_tokens: usage.output_tokens * 2,
      }),
      progress: { status: "failed" },
    });
    const parentSaved = await runWorkbench(
      { ...parent.options, signal: undefined },
      ["get-scan", "--scan-id", parentId],
    );
    expect((parentSaved["scan"] as JsonObject)["progress"]).toMatchObject({
      status: "failed",
    });
  },
);

test("budgeted resume retries pending child retirement before rejecting unavailable cost", async () => {
  const h = await fixture();
  const options = {
    ...h.options,
    knowledgeBasePaths: undefined,
    workers: 1,
    maxCostUsd: 1,
  };
  h.stopAfterChildRegistration();
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )!;
  const [childId, child] = [...h.records].find(
    ([, record]) => record.mode === "standard",
  )!;
  const readScan = async (id: string, record: typeof parent) =>
    (
      await runWorkbench({ ...record.options, signal: undefined }, [
        "get-scan",
        "--scan-id",
        id,
      ])
    )["scan"] as JsonObject;
  expect(await readScan(childId, child)).toMatchObject({
    progress: { status: "running" },
    continuationThreadId: null,
  });
  expect(h.launches).toHaveLength(0);
  h.failChildRetirement(true);
  await using interrupted = h.makeClient();
  const resumeOptions = {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  };
  await expect(
    interrupted.run(h.repository, resumeOptions),
  ).rejects.toBeInstanceOf(DeepScanRecoveryError);
  const checkpointPath = join(
    h.outputDir,
    "artifacts/deep-scan/checkpoint.json",
  );
  expect(JSON.parse(await readFile(checkpointPath, "utf8"))).toMatchObject({
    costUnavailable: true,
    pendingStop: { reason: "failed" },
  });
  for (const [id, record] of [
    [parentId, parent],
    [childId, child],
  ] as const)
    expect(await readScan(id, record)).toMatchObject({
      progress: { status: "running" },
    });

  h.failChildRetirement(false);
  await using resumed = h.makeClient();
  await expect(resumed.run(h.repository, resumeOptions)).rejects.toBeInstanceOf(
    ScanInterruptedError,
  );
  for (const [id, record] of [
    [parentId, parent],
    [childId, child],
  ] as const)
    expect(await readScan(id, record)).toMatchObject({
      progress: { status: "failed" },
    });
  const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8"));
  expect(checkpoint).toMatchObject({
    costUnavailable: true,
    terminalReason: "failed",
  });
  expect(checkpoint.pendingStop).toBeUndefined();
  expect(checkpoint.finalCost).toBeUndefined();
  expect(h.launches).toHaveLength(0);
  expect(h.records.size).toBe(2);
  expect(h.commands).not.toContain("complete-budget-exhausted-scan");
});

test.each(
  (["standard", "deep"] as const).flatMap((role) =>
    ["missing", "valid", "truncated"].map((manifest) => ({ role, manifest })),
  ),
)(
  "composed resume repairs unfinished canonical manifests: %j",
  async ({ role, manifest }) => {
    const h = await fixture();
    const options = { ...h.options, knowledgeBasePaths: undefined, workers: 1 };
    h.stopBeforeSealing(role);
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId] = [...h.records].find(([, row]) => row.mode === "deep")!;
    const [scanId, record] = [...h.records].find(
      ([, row]) => row.mode === role,
    )!;
    const directory = record.registration["scanDir"] as string;
    const savedThreads = [...h.threadScans].filter(([, id]) => id === scanId);
    expect(savedThreads).toHaveLength(1);
    const checkpoints = join(directory, "checkpoints");
    const retained = await Promise.all(
      (await readdir(checkpoints))
        .filter((name) => name.endsWith(".json"))
        .map(async (name) => ({
          name,
          bytes: await readFile(join(checkpoints, name)),
        })),
    );
    expect(retained.length).toBeGreaterThan(0);
    const manifestPath = join(directory, "scan-manifest.json");
    expect(
      JSON.parse(await readFile(manifestPath, "utf8")).scan.sealedAt,
    ).toBeUndefined();
    if (manifest === "missing") await rm(manifestPath);
    else if (manifest === "truncated")
      await writeFile(manifestPath, '{"scan":');
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    expect(result.manifest.scan.id).toBe(parentId);
    expect(result.findings.findings).toHaveLength(2);
    expect(h.records.size).toBe(3);
    expect([...h.threadScans].filter(([, id]) => id === scanId)).toEqual(
      savedThreads,
    );
    if (role === "standard")
      expect(
        h.launches.filter(
          (launch) => launch.options.env!["CODEX_SECURITY_SCAN_ID"] === scanId,
        ),
      ).toHaveLength(2);
    for (const { name, bytes } of retained)
      expect(await readFile(join(checkpoints, name))).toEqual(bytes);
  },
);

test.each(["relative", "absolute", "profile"] as const)(
  "Deep instruction files retain their parent origin across fresh and resumed workers (%s)",
  async (origin) => {
    const h = await fixture();
    const instructionPath = join(h.root, "instructions.md");
    await writeFile(instructionPath, "Synthetic instructions for this scan.\n");
    const selected =
      origin === "absolute" ? instructionPath : "../instructions.md";
    const configuration: JsonObject =
      origin === "profile"
        ? {
            profile: "selected",
            profiles: { selected: { model_instructions_file: selected } },
          }
        : { model_instructions_file: selected };
    const options = { ...h.options, knowledgeBasePaths: undefined };
    h.stopBeforeSealing();
    await using first = h.makeClient(configuration);
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, row]) => row.mode === "deep",
    )!;
    const expectedDigest = createHash("sha256")
      .update("Synthetic instructions for this scan.\n")
      .digest("hex");
    expect(parent.recipe["scanInputs"]).toMatchObject({
      modelInstructionsFileSha256: expectedDigest,
    });
    await using resumed = h.makeClient(configuration);
    await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    expect(h.launches.length).toBeGreaterThanOrEqual(3);
    for (const launch of h.launches) {
      const instructions = launch.options.config![
        "model_instructions_file"
      ] as string;
      expect(
        await readFile(
          resolve(launch.threadOptions.workingDirectory!, instructions),
          "utf8",
        ),
      ).toBe("Synthetic instructions for this scan.\n");
      expect(instructions).toBe(instructionPath);
    }
    expect(
      h.records.get(h.launches[0]!.options.env!["CODEX_SECURITY_SCAN_ID"]!)!
        .mode,
    ).toBe("standard");
    expect(
      h.launches.some(
        (launch) =>
          h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!
            .mode === "deep",
      ),
    ).toBe(true);
  },
);

test.each([
  ...(["sdk", "native"] as const).flatMap((continuation) =>
    (["changed", "missing", "empty"] as const).map((contents) => ({
      ...promptFiles[0],
      continuation,
      contents,
    })),
  ),
  ...(["changed", "missing", "empty"] as const).map((contents) => ({
    ...promptFiles[1],
    continuation: "sdk" as const,
    contents,
  })),
])(
  "Deep instruction file changes block resumed execution until original bytes are restored: %j",
  async ({ continuation, contents, setting, digestKey, label }) => {
    const h = await fixture(undefined, continuation === "native");
    const instructionPath = join(h.root, "instructions.md");
    const original =
      contents === "empty" ? "" : "Original synthetic instructions.\n";
    await writeFile(instructionPath, original);
    const observations: string[] = [];
    h.observeLaunch(async (launch) => {
      observations.push(
        execFileSync(
          "node",
          [
            "-e",
            'process.stdout.write(require("node:fs").readFileSync(process.argv[1], "utf8"))',
            launch.options.config![setting] as string,
          ],
          { cwd: launch.threadOptions.workingDirectory, encoding: "utf8" },
        ),
      );
    });
    const origin =
      continuation === "native"
        ? "absolute"
        : contents === "changed"
          ? "relative"
          : contents === "missing"
            ? "profile"
            : "home";
    if (origin === "home") {
      h.environment["HOME"] = h.root;
      h.environment["USERPROFILE"] = h.root;
    }
    const selected =
      origin === "absolute"
        ? instructionPath
        : origin === "home"
          ? "~/instructions.md"
          : "../instructions.md";
    const configuration: JsonObject =
      origin === "profile"
        ? {
            profile: "selected",
            profiles: { selected: { [setting]: selected } },
          }
        : { [setting]: selected };
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      maxCostUsd: 1,
      workers: 1,
    };
    h.stopAfterSealing("standard");
    await using first = h.makeClient(configuration);
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, row]) => row.mode === "deep",
    )!;
    const readRecipe = async () =>
      (
        await runWorkbench({ ...parent.options, signal: undefined }, [
          "get-scan-recipe",
          "--scan-id",
          parentId,
        ])
      )["recipe"] as JsonObject;
    const saved = await readRecipe();
    const digest = createHash("sha256").update(original).digest("hex");
    expect(saved["scanInputs"]).toMatchObject({
      [digestKey]: digest,
    });
    if (contents === "changed") {
      const edit = () =>
        writeFile(instructionPath, "Changed synthetic instructions.\n");
      if (continuation === "native") h.afterChildRegistration(edit);
      else await edit();
    } else await rm(instructionPath);
    const beforeResume = h.launches.length;
    await using resumed = h.makeClient(configuration);
    const resumeOptions = {
      ...options,
      signal: undefined,
      ...(continuation === "sdk" ? { resumeScanId: parentId } : {}),
    };
    const beforeCommands = h.commands.length;
    const failure = await resumed
      .run(h.repository, resumeOptions)
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(DeepScanRecoveryError);
    expect((failure as Error).message).toContain(
      contents === "changed" ? `${label} file has changed` : "ENOENT",
    );
    if (contents !== "changed")
      expect((failure as Error).cause).toMatchObject({ code: "ENOENT" });
    expect(h.launches).toHaveLength(beforeResume);
    expect(h.commands.slice(beforeCommands)).not.toContain("fail-scan");
    expect(h.commands.slice(beforeCommands)).not.toContain("cancel-scan");
    expect((await readRecipe())["scanInputs"]).toEqual(saved["scanInputs"]);
    const blocked = await loadDeepScanCheckpoint(h.outputDir);
    expect(blocked?.terminalReason).not.toBe("failed");
    expect(blocked?.terminalReason).not.toBe("canceled");
    expect(
      blocked?.passes.filter((pass) => pass.executionNotStarted === true),
    ).toHaveLength(1);
    const blockedPassIds = blocked?.passes.map((pass) => pass.scanId);
    await expect(
      resumed.run(h.repository, resumeOptions),
    ).rejects.toBeInstanceOf(DeepScanRecoveryError);
    expect(h.launches).toHaveLength(beforeResume);
    await writeFile(instructionPath, original);
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      ...(continuation === "sdk" ? { resumeScanId: parentId } : {}),
    });
    expect(result.manifest.scan.id).toBe(parentId);
    const completed = await loadDeepScanCheckpoint(h.outputDir);
    expect(completed?.passes.map((pass) => pass.scanId)).toEqual(
      blockedPassIds,
    );
    expect(
      completed?.passes.some((pass) => pass.executionNotStarted === true),
    ).toBe(false);
    expect((await readRecipe())["scanInputs"]).toEqual(saved["scanInputs"]);
    expect(h.launches.length).toBeGreaterThan(beforeResume);
    expect(observations.every((text) => text === original)).toBe(true);
    for (const launch of h.launches)
      expect(launch.options.config![setting]).toBe(instructionPath);
  },
  120_000,
);

test.each(["standard", "deep", "primary"] as const)(
  "Deep worker observations retain shared numbering across fresh and resumed %s launches",
  async (mode) => {
    const h = await fixture(undefined, false, mode !== "primary");
    const observed: Array<{ kind: "observed"; worker: number }> = [];
    const sessions: Array<{ threadId: string; worker?: number }> = [];
    const options = {
      ...h.options,
      subagents: mode === "primary" ? 0 : h.options.subagents,
      knowledgeBasePaths: undefined,
      onWorkerEvent: (event: { kind: "observed"; worker: number }) =>
        observed.push(event),
      onSessionEvent: (event: { threadId: string; worker?: number }) =>
        sessions.push(event),
    };
    h.stopBeforeSealing();
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const firstEvents = {
      observed: observed.splice(0),
      sessions: sessions.splice(0),
    };
    const [parentId] = [...h.records].find(([, row]) => row.mode === "deep")!;
    await using resumed = h.makeClient();
    await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    const selectedIds = new Set(
      mode === "primary"
        ? [...h.threadScans]
            .filter(([, scanId]) => h.records.get(scanId)!.mode === "standard")
            .map(([threadId]) => threadId)
        : h.observedSubagents
            .filter((row) => row.mode === mode)
            .map((row) => row.id),
    );
    const covered = new Set<string>();
    for (const events of [firstEvents, { observed, sessions }]) {
      const selected = events.sessions.filter((row) =>
        selectedIds.has(row.threadId),
      );
      const threadIds = new Set(selected.map((row) => row.threadId));
      for (const threadId of threadIds) {
        covered.add(threadId);
        const numbers = new Set(
          selected
            .filter((row) => row.threadId === threadId)
            .map((row) => row.worker),
        );
        expect(numbers.size).toBe(1);
        expect(numbers.has(undefined)).toBe(false);
      }
      const expected = new Set(selected.map((row) => row.worker));
      expect(expected.size).toBe(threadIds.size);
      const delivered = new Set(events.observed.map((row) => row.worker));
      for (const number of expected) expect(delivered.has(number!)).toBe(true);
    }
    expect(covered).toEqual(selectedIds);
    expect(covered.size).toBeGreaterThan(0);
  },
);

test.each([false, true])(
  "Deep resume observes completed child workers before merging (observer throws: %p)",
  async (observerThrows) => {
    const h = await fixture(undefined, false, true);
    const options = { ...h.options, knowledgeBasePaths: undefined };
    h.failChildProjection(true);
    await using first = h.makeClient();
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      DeepScanRecoveryError,
    );
    expect(h.launches).toHaveLength(2);
    const children = [...h.records].filter(
      ([, row]) => row.mode === "standard",
    );
    expect(children).toHaveLength(2);
    for (const [scanId, record] of children) {
      const saved = await runWorkbench(
        { ...record.options, signal: undefined },
        ["get-scan", "--scan-id", scanId],
      );
      expect((saved["scan"] as JsonObject)["progress"]).toMatchObject({
        status: "complete",
      });
    }
    expect(
      h.observedSubagents.filter((row) => row.mode === "standard"),
    ).toHaveLength(2);
    const [parentId] = [...h.records].find(([, row]) => row.mode === "deep")!;
    const observed: Array<{ kind: "observed"; worker: number }> = [];
    const observerErrors: string[] = [];
    h.failChildProjection(false);
    await using resumed = h.makeClient();
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
      onWorkerEvent(event) {
        observed.push(event);
        if (observerThrows)
          throw new Error("Synthetic optional observer failure");
      },
      onObserverError(observer) {
        observerErrors.push(observer);
      },
    });
    expect(result.manifest.scan.status).toBe("completed");
    expect(result.findings.findings).toHaveLength(2);
    expect(h.launches).toHaveLength(3);
    expect(
      h.launches
        .slice(2)
        .map((launch) => launch.options.env!["CODEX_SECURITY_SCAN_ID"]),
    ).toEqual([parentId]);
    // Two completed child roots and their nested workers precede the new reducer worker.
    // The reducer root itself is the parent tracker, not another observed worker.
    expect(observed).toEqual(
      [1, 2, 3, 4, 5].map((worker) => ({ kind: "observed", worker })),
    );
    expect(
      h.observedSubagents.filter((row) => row.mode === "deep"),
    ).toHaveLength(1);
    expect(observerErrors).toEqual(
      observerThrows ? Array(5).fill("onWorkerEvent") : [],
    );
  },
);

test("queued native callers preserve the first saved knowledge snapshot", async () => {
  const h = await fixture(undefined, true);
  await using first = h.makeClient();
  await using queued = h.makeClient();
  const queuedOptions = { ...h.options, signal: undefined };
  h.stopAfterSealing("standard");
  await expect(first.run(h.repository, h.options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const path = join(h.outputDir, ".scan-knowledge.json");
  const original = await readFile(path, "utf8");
  await writeFile(h.knowledgePath, "Original immutable context");
  const result = await queued.run(h.repository, queuedOptions);
  expect(result.manifest.scan.status).toBe("completed");
  expect(await readFile(path, "utf8")).toBe(original);
  expect(result.manifest.scan.id).toBe(h.options.registeredScan!.scanId);
  expect(h.launches.length).toBeGreaterThan(1);
});

test("accepted patches restore ambient providers from a produced native-preservation recipe", async () => {
  const h = await fixture();
  const provider = {
    name: "Synthetic",
    wire_api: "responses",
    base_url: "https://provider.example.test/v1",
    auth: { command: ["synthetic-credential-command"] },
    http_headers: { Authorization: "synthetic-native-patch-token" },
  };
  const configuration = {
    model: "gpt-6-astra",
    model_reasoning_effort: "high",
    service_tier: "priority",
    analytics: { enabled: false },
    model_provider: "synthetic",
    model_providers: { synthetic: provider },
  };
  await writeFile(join(h.home, "config.toml"), stringifyToml(configuration));
  h.stopAfterSealing();
  await using first = h.makeClient(configuration);
  await expect(
    first.run(h.repository, {
      ...h.options,
      knowledgeBasePaths: undefined,
      preserveProviderEnvironment: true,
    }),
  ).rejects.toBeInstanceOf(ScanTransportClosedError);
  const parentId = [...h.records].find(
    ([, record]) => record.mode === "deep",
  )![0];
  const parent = h.records.get(parentId)!;
  expect(parent.recipe["preserveProviderEnvironment"]).toBe(true);
  expect(parent.recipe["providerProfile"]).toEqual({
    name: expect.any(String),
    home: "ambient",
  });
  const replay = await restoreProviderProfile(
    {},
    parent.recipe["providerProfile"],
    { CODEX_HOME: h.home },
  );
  expect(replay).toEqual({ analytics: { enabled: false } });
  expect(parent.recipe["config"]).not.toHaveProperty("model_providers");
  const environment: NodeJS.ProcessEnv = {
    ...parent.options.environment,
    CODEX_HOME: h.home,
    TERM: "xterm",
  };
  delete environment["CI"];
  const command = (args: readonly string[], input?: string) =>
    runWorkbench(
      { ...parent.options, environment, signal: undefined },
      args,
      input,
    );
  const receipt = await command(["get-cli-scan-resume", "--scan-id", parentId]);
  expect(typeof receipt["sealedProducerVersion"]).toBe("string");
  const names = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
    "artifacts/deep-scan/checkpoint.json",
  ];
  const before = await Promise.all(
    names.map((name) => readFile(join(h.outputDir, name))),
  );
  const stdout = capture(),
    stderr = capture(true);
  const patchConfigurations: unknown[] = [];
  let runtimeStarts = 0;
  let prompted = false;
  await main(
    ["scans", "resume", parentId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...cliDependencies({
        environment,
        currentDirectory: h.root,
        onCodex(_args, output) {
          patchConfigurations.push(output?.codexOverrides);
          return 1;
        },
      }),
      runWorkbench: command,
      confirmPatchReview: async () => {
        prompted = true;
        expect(
          (await command(["get-scan", "--scan-id", parentId]))["scan"],
        ).toMatchObject({ progress: { status: "complete" } });
        return true;
      },
      patchEditor: async (_repository, findings) => ({
        severity: "low",
        occurrenceIds: [findings[0]!.occurrenceId],
      }),
      createSecurity(config) {
        return new CodexSecurity(
          {
            ...config,
            pluginPath: pluginRoot,
            pythonPath: Bun.which("python3")!,
          },
          {
            environment,
            resolvePluginPython: async () => Bun.which("python3")!,
            prepareRuntime: async () => {
              runtimeStarts++;
              throw new Error("Publication must not prepare a runtime");
            },
            createCodex: () => {
              runtimeStarts++;
              throw new Error("Publication must not create a model client");
            },
            runWorkbench,
          },
          { surface: "sdk" },
        );
      },
    },
  );
  expect(prompted, stderr.text()).toBe(true);
  expect(runtimeStarts).toBe(0);
  expect(patchConfigurations).toHaveLength(1);
  expect(patchConfigurations[0]).toMatchObject(configuration);
  expect(
    (await command(["get-scan", "--scan-id", parentId]))["scan"],
  ).toMatchObject({ progress: { status: "complete" } });
  expect(
    await Promise.all(names.map((name) => readFile(join(h.outputDir, name)))),
  ).toEqual(before);
  expect(h.launches).toHaveLength(3);
});

test.each([undefined, "Write follow-up notes"])(
  "composed Deep Scan preserves completed usage and report through follow-up %p",
  async (postScanPrompt) => {
    const h = await fixture();
    let starts = 0;
    await using client = h.makeClient();
    const result = await client.run(h.repository, {
      ...h.options,
      postScanPrompt,
      onScanStarted: () => {
        starts += 1;
      },
    });
    const report = await readFile(result.reportPath, "utf8");
    const expectedUsage = {
      ...usage,
      input_tokens: usage.input_tokens * 3,
      output_tokens: usage.output_tokens * 3,
    };
    expect(starts).toBe(1);
    expect(result.reportPath).toBe(join(h.outputDir, "report.md"));
    expect(result.turnResult.finalResponse).toBe(report);
    expect(result.toJSON()["turn"]).toMatchObject({ finalResponse: report });
    expect(result.turnResult.usage).toMatchObject(expectedUsage);
    expect(result.cost).toEqual(estimateScanCost("gpt-6-astra", expectedUsage));
    const checkpoint = await loadDeepScanCheckpoint(h.outputDir);
    expect(checkpoint?.finalCost).toEqual(result.cost);
    expect(h.launches).toHaveLength(postScanPrompt === undefined ? 3 : 4);
    if (postScanPrompt !== undefined) {
      expect(h.completedPrompts.at(-1)).toContain(postScanPrompt);
      expect(h.launches.at(-1)!.runOptions?.signal).toBeInstanceOf(AbortSignal);
    }
  },
);

test.each([
  { continuation: "sdk", changed: false, sealed: false },
  { continuation: "sdk", changed: true, sealed: true },
] as const)(
  "Deep unchanged instructions and sealed recovery preserve child execution behavior: %j",
  async ({ continuation, changed, sealed }) => {
    const h = await fixture();
    const instructionPath = join(h.root, "instructions.md");
    const original = "Original synthetic execution instructions.\n";
    const edited = "Edited synthetic execution instructions.\n";
    await writeFile(instructionPath, original);
    const observations: Array<{ mode: string; text: string; scanId: string }> =
      [];
    h.observeLaunch(async (launch) => {
      const file = launch.options.config!["model_instructions_file"] as string;
      const text = execFileSync(
        "node",
        [
          "-e",
          'process.stdout.write(require("node:fs").readFileSync(process.argv[1], "utf8"))',
          file,
        ],
        {
          cwd: launch.threadOptions.workingDirectory,
          encoding: "utf8",
        },
      );
      const scanId = launch.options.env!["CODEX_SECURITY_SCAN_ID"]!;
      observations.push({ mode: h.records.get(scanId)!.mode, text, scanId });
    });
    const configuration = { model_instructions_file: instructionPath };
    const options = { ...h.options, knowledgeBasePaths: undefined };
    if (sealed) h.stopAfterSealing();
    else h.stopBeforeSealing();
    await using first = h.makeClient(configuration);
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, row]) => row.mode === "deep",
    )!;
    const recipe = async () =>
      (
        await runWorkbench({ ...parent.options, signal: undefined }, [
          "get-scan-recipe",
          "--scan-id",
          parentId,
        ])
      )["recipe"] as JsonObject;
    const saved = await recipe();
    expect(saved["scanInputs"]).toMatchObject({
      modelInstructionsFileSha256: createHash("sha256")
        .update(original)
        .digest("hex"),
    });
    expect(observations.length).toBeGreaterThan(0);
    expect(observations.every((row) => row.text === original)).toBe(true);
    if (sealed) await rm(instructionPath);
    else if (changed) await writeFile(instructionPath, edited);
    const before = observations.length;
    if (sealed) h.forbidCodex();
    await using resumed = h.makeClient(configuration);
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      ...(continuation === "sdk" ? { resumeScanId: parentId } : {}),
    });
    expect(result.manifest.scan.id).toBe(parentId);
    expect((await recipe())["scanInputs"]).toEqual(saved["scanInputs"]);
    const resumedObservations = observations.slice(before);
    if (sealed) expect(resumedObservations).toEqual([]);
    else {
      expect(new Set(resumedObservations.map((row) => row.mode))).toEqual(
        new Set(["standard", "deep"]),
      );
      expect(
        resumedObservations.every(
          (row) => row.text === (changed ? edited : original),
        ),
      ).toBe(true);
    }
    console.log(
      "instruction-resume-proof",
      JSON.stringify({
        continuation,
        changed,
        sealed,
        sameScanId: true,
        initial: observations
          .slice(0, before)
          .map(({ mode, text }) => ({ mode, text })),
        resumed: resumedObservations.map(({ mode, text }) => ({ mode, text })),
        savedDigestUnchanged: true,
      }),
    );
  },
);

test("public scans resume rejects changed instructions and resumes the same scan after restoration", async () => {
  const h = await fixture();
  const instructionPath = join(h.root, "instructions.md");
  const original = "Original synthetic CLI instructions.\n";
  const edited = "Edited synthetic CLI instructions.\n";
  await writeFile(instructionPath, original);
  const observed: Array<{ mode: string; text: string }> = [];
  h.observeLaunch(async (launch) => {
    observed.push({
      mode: h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode,
      text: execFileSync(
        "node",
        [
          "-e",
          'process.stdout.write(require("node:fs").readFileSync(process.argv[1], "utf8"))',
          launch.options.config!["model_instructions_file"] as string,
        ],
        { cwd: launch.threadOptions.workingDirectory, encoding: "utf8" },
      ),
    });
  });
  h.stopAfterSealing("standard");
  await using first = h.makeClient({
    model_instructions_file: instructionPath,
  });
  await expect(
    first.run(h.repository, {
      ...h.options,
      workers: 1,
      knowledgeBasePaths: undefined,
    }),
  ).rejects.toBeInstanceOf(ScanTransportClosedError);
  const [parentId, parent] = [...h.records].find(
    ([, row]) => row.mode === "deep",
  )!;
  const command = (args: readonly string[], input?: string) =>
    runWorkbench({ ...parent.options, signal: undefined }, args, input);
  const saved = (await command(["get-scan-recipe", "--scan-id", parentId]))[
    "recipe"
  ] as JsonObject;
  expect(saved["scanInputs"]).toMatchObject({
    modelInstructionsFileSha256: createHash("sha256")
      .update(original)
      .digest("hex"),
  });
  const before = observed.length;
  expect(observed.every((row) => row.text === original)).toBe(true);
  await writeFile(instructionPath, edited);
  const stdout = capture(),
    stderr = capture(true);
  const resume = () =>
    main(
      ["scans", "resume", parentId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...cliDependencies({
          environment: h.environment,
          currentDirectory: h.root,
        }),
        runWorkbench: command,
        createSecurity(config) {
          return h.makeClient(config.codexOverrides);
        },
      },
    );
  expect(await resume()).not.toBe(0);
  expect(stderr.text()).toContain("model instructions file has changed");
  expect(observed).toHaveLength(before);
  await writeFile(instructionPath, original);
  expect(await resume(), stderr.text()).toBe(0);
  expect(
    (await command(["get-scan", "--scan-id", parentId]))["scan"],
  ).toMatchObject({ progress: { status: "complete" } });
  expect(
    (
      (await command(["get-scan-recipe", "--scan-id", parentId]))[
        "recipe"
      ] as JsonObject
    )["scanInputs"],
  ).toEqual(saved["scanInputs"]);
  const resumed = observed.slice(before);
  expect(new Set(resumed.map((row) => row.mode))).toEqual(
    new Set(["standard", "deep"]),
  );
  expect(resumed.every((row) => row.text === original)).toBe(true);
  console.log(
    "instruction-cli-resume-proof",
    JSON.stringify({
      sameScanId: true,
      initial: observed.slice(0, before),
      resumed,
      savedDigestUnchanged: true,
    }),
  );
}, 120_000);

test.each(promptFiles)(
  "unsealed accepted aggregate resumes without reopening instruction files (%j)",
  async ({ setting, digestKey }) => {
    const h = await fixture(undefined, true);
    const instructionPath = join(h.root, "instructions.md");
    await writeFile(
      instructionPath,
      "Synthetic aggregate recovery instructions.\n",
    );
    const config = { [setting]: instructionPath };
    const options = { ...h.options, knowledgeBasePaths: undefined };
    h.stopBeforeSealing("deep");
    await using first = h.makeClient(config);
    await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, row]) => row.mode === "deep",
    )!;
    const manifest = JSON.parse(
      await readFile(join(h.outputDir, "scan-manifest.json"), "utf8"),
    );
    expect(manifest.scan.sealedAt).toBeUndefined();
    const before = h.launches.length;
    await rm(instructionPath);
    h.observeLaunch(async () => {
      throw new Error("Artifact recovery must not execute a model turn");
    });
    await using resumed = h.makeClient(config);
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
    });
    expect(result.manifest.scan.id).toBe(parentId);
    expect(h.launches.length).toBe(before);
    console.log(
      "instruction-unsealed-recovery-proof",
      JSON.stringify({
        sameScanId: true,
        wasSealed: false,
        instructionFileDeleted: true,
        newExecutionLaunches: 0,
        savedDigest: (parent.recipe["scanInputs"] as JsonObject)[digestKey],
      }),
    );
  },
);

test.each(promptFiles)(
  "first reducer resume rejects changed instructions without consuming the checkpoint or required cost (%j)",
  async ({ setting, digestKey, label }) => {
    const h = await fixture();
    const instructionPath = join(h.root, "instructions.md");
    const original = "Original reducer instructions.\n";
    await writeFile(instructionPath, original);
    const configuration = { [setting]: instructionPath };
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      maxCostUsd: 1,
    };
    h.failChildProjection(true);
    await using client = h.makeClient(configuration);
    await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
      DeepScanRecoveryError,
    );
    const [parentId, parent] = [...h.records].find(
      ([, row]) => row.mode === "deep",
    )!;
    const savedInputs = parent.recipe["scanInputs"] as JsonObject;
    expect(savedInputs[digestKey]).toBe(
      createHash("sha256").update(original).digest("hex"),
    );
    const before = await loadDeepScanCheckpoint(h.outputDir);
    expect(before?.mergeStarted).toBeUndefined();
    expect([...h.threadScans.values()]).not.toContain(parentId);
    const accepted = before!.passes;
    const launches = h.launches.length;
    let editedAfterPreparation = false;
    h.observeCheckpoint(async (checkpoint) => {
      if (checkpoint["mergeStarted"] === true && !editedAfterPreparation) {
        editedAfterPreparation = true;
        await writeFile(instructionPath, "Changed reducer instructions.\n");
      }
    });
    h.failChildProjection(false);
    await using resumed = h.makeClient(configuration);
    const resume = () =>
      resumed.run(h.repository, {
        ...options,
        signal: undefined,
        resumeScanId: parentId,
      });
    const failure = await resume().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(DeepScanRecoveryError);
    expect((failure as Error).message).toContain(`${label} file has changed`);
    expect(h.launches).toHaveLength(launches);
    const blocked = await loadDeepScanCheckpoint(h.outputDir);
    expect(editedAfterPreparation).toBe(true);
    expect(blocked?.mergeStarted).toBeUndefined();
    expect(blocked?.passes).toEqual(accepted);
    expect(blocked?.terminalReason).not.toBe("failed");
    expect([...h.threadScans.values()]).not.toContain(parentId);
    await writeFile(instructionPath, original);
    const result = await resume();
    expect(result.manifest.scan.id).toBe(parentId);
    expect(result.cost?.estimatedUsd).toBeGreaterThan(0);
    expect(
      (
        await runWorkbench({ ...parent.options, signal: undefined }, [
          "get-scan-recipe",
          "--scan-id",
          parentId,
        ])
      )["recipe"],
    ).toMatchObject({ scanInputs: savedInputs });
    expect(
      (
        await runWorkbench({ ...parent.options, signal: undefined }, [
          "get-scan",
          "--scan-id",
          parentId,
        ])
      )["scan"],
    ).toMatchObject({ progress: { status: "complete" } });
  },
);

test("missing fresh compact prompt releases its provisional saved profile before registration", async () => {
  const h = await fixture();
  await writeFile(
    join(h.home, "unrelated.config.toml"),
    "# Synthetic existing profile.\n",
  );
  const profiles = () =>
    readdir(h.home).then((names) =>
      names.filter((name) => name.endsWith(".config.toml")).sort(),
    );
  const before = await profiles();
  await using client = h.makeClient({
    experimental_compact_prompt_file: join(h.root, "missing-compact.md"),
  });
  await expect(
    client.run(h.repository, { ...h.options, knowledgeBasePaths: undefined }),
  ).rejects.toMatchObject({ code: "ENOENT" });
  expect(h.launches).toHaveLength(0);
  expect(h.records.size).toBe(0);
  expect(h.commands).not.toContain("register-cli-scan");
  expect(h.commands).toContain("list-scans");
  expect(await profiles()).toEqual(before);
});

test("Deep compact prompt absence rejects a newly selected file until the setting is removed", async () => {
  const h = await fixture();
  const compactPath = join(h.root, "compact.md");
  await writeFile(compactPath, "New synthetic compact prompt.\n");
  const options = { ...h.options, knowledgeBasePaths: undefined, workers: 1 };
  h.stopAfterSealing("standard");
  await using first = h.makeClient();
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, row]) => row.mode === "deep",
  )!;
  const readRecipe = async () =>
    (
      await runWorkbench({ ...parent.options, signal: undefined }, [
        "get-scan-recipe",
        "--scan-id",
        parentId,
      ])
    )["recipe"] as JsonObject;
  const saved = await readRecipe();
  expect(saved["scanInputs"]).toMatchObject({
    compactPromptFileSha256: null,
  });
  const launches = h.launches.length;
  const resumeOptions = {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  };
  await using resumed = h.makeClient({
    experimental_compact_prompt_file: compactPath,
  });
  const failure = await resumed
    .run(h.repository, resumeOptions)
    .catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(DeepScanRecoveryError);
  expect((failure as Error).message).toContain(
    "started without a compact prompt file",
  );
  expect(h.launches).toHaveLength(launches);
  expect((await readRecipe())["scanInputs"]).toEqual(saved["scanInputs"]);
  const blocked = await loadDeepScanCheckpoint(h.outputDir);
  expect(blocked?.terminalReason).not.toBe("failed");
  await using restored = h.makeClient();
  const result = await restored.run(h.repository, resumeOptions);
  expect(result.manifest.scan.id).toBe(parentId);
  expect((await readRecipe())["scanInputs"]).toEqual(saved["scanInputs"]);
  expect(
    (await loadDeepScanCheckpoint(h.outputDir))?.passes.map(
      (pass) => pass.scanId,
    ),
  ).toEqual(blocked?.passes.map((pass) => pass.scanId));
  const resumedLaunches = h.launches.slice(launches);
  expect(
    new Set(
      resumedLaunches.map(
        (launch) =>
          h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode,
      ),
    ),
  ).toEqual(new Set(["standard", "deep"]));
  for (const launch of resumedLaunches)
    expect(launch.options.config).not.toHaveProperty(
      "experimental_compact_prompt_file",
    );
});

test("legacy compact metadata skips only compact validation and preserves the model instruction guard", async () => {
  const h = await fixture();
  const instructionPath = join(h.root, "instructions.md");
  const compactPath = join(h.root, "compact.md");
  const originalInstructions = "Original synthetic model instructions.\n";
  const editedCompact = "Changed synthetic legacy compact prompt.\n";
  await writeFile(instructionPath, originalInstructions);
  await writeFile(compactPath, "Original synthetic compact prompt.\n");
  const configuration = {
    model_instructions_file: instructionPath,
    experimental_compact_prompt_file: compactPath,
  };
  const options = { ...h.options, knowledgeBasePaths: undefined, workers: 1 };
  h.stopAfterSealing("standard");
  await using first = h.makeClient(configuration);
  await expect(first.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, row]) => row.mode === "deep",
  )!;
  const readRecipe = async () =>
    (
      await runWorkbench({ ...parent.options, signal: undefined }, [
        "get-scan-recipe",
        "--scan-id",
        parentId,
      ])
    )["recipe"] as JsonObject;
  const recipe = structuredClone(await readRecipe());
  expect(recipe["scanInputs"]).toMatchObject({
    compactPromptFileSha256: createHash("sha256")
      .update("Original synthetic compact prompt.\n")
      .digest("hex"),
    modelInstructionsFileSha256: createHash("sha256")
      .update(originalInstructions)
      .digest("hex"),
  });
  delete (recipe["scanInputs"] as JsonObject)["compactPromptFileSha256"];
  const python = await resolvePluginPython({
    environment: h.environment,
    protectedRoot: h.repository,
  });
  execFileSync(
    python,
    [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE scans SET recipe_json=? WHERE id=?',(sys.argv[2],sys.argv[3])); c.commit()",
      join(h.environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
      JSON.stringify(recipe),
      parentId,
    ],
    { env: h.environment },
  );
  await writeFile(instructionPath, "Changed synthetic model instructions.\n");
  await writeFile(compactPath, editedCompact);
  const launches = h.launches.length;
  await using resumed = h.makeClient(configuration);
  const resume = () =>
    resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
  const failure = await resume().catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(DeepScanRecoveryError);
  expect((failure as Error).message).toContain(
    "model instructions file has changed",
  );
  expect(h.launches).toHaveLength(launches);
  expect((await readRecipe())["scanInputs"]).toEqual(recipe["scanInputs"]);
  await writeFile(instructionPath, originalInstructions);
  const observed: Array<{
    mode: string;
    compact: string;
    instructions: string;
  }> = [];
  h.observeLaunch(async (launch) => {
    observed.push({
      mode: h.records.get(launch.options.env!["CODEX_SECURITY_SCAN_ID"]!)!.mode,
      compact: await readFile(
        launch.options.config!["experimental_compact_prompt_file"] as string,
        "utf8",
      ),
      instructions: await readFile(
        launch.options.config!["model_instructions_file"] as string,
        "utf8",
      ),
    });
  });
  const result = await resume();
  expect(result.manifest.scan.id).toBe(parentId);
  expect(new Set(observed.map((row) => row.mode))).toEqual(
    new Set(["standard", "deep"]),
  );
  expect(
    observed.every(
      (row) =>
        row.compact === editedCompact &&
        row.instructions === originalInstructions,
    ),
  ).toBe(true);
  expect((await readRecipe())["scanInputs"]).toEqual(recipe["scanInputs"]);
});

test("legacy Deep recipes without instruction digests retain resume behavior", async () => {
  const h = await fixture();
  const instructionPath = join(h.root, "instructions.md");
  await writeFile(instructionPath, "Original legacy instructions.\n");
  const configuration = { model_instructions_file: instructionPath };
  const options = { ...h.options, knowledgeBasePaths: undefined, workers: 1 };
  h.stopAfterSealing("standard");
  await using client = h.makeClient(configuration);
  await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
    ScanTransportClosedError,
  );
  const [parentId, parent] = [...h.records].find(
    ([, row]) => row.mode === "deep",
  )!;
  const recipe = structuredClone(parent.recipe);
  delete (recipe["scanInputs"] as JsonObject)["modelInstructionsFileSha256"];
  execFileSync(Bun.which("python3")!, [
    "-c",
    "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE scans SET recipe_json=? WHERE id=?',(sys.argv[2],sys.argv[3])); c.commit()",
    join(h.environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
    JSON.stringify(recipe),
    parentId,
  ]);
  await writeFile(instructionPath, "Changed legacy instructions.\n");
  const texts: string[] = [];
  h.observeLaunch(async (launch) => {
    texts.push(
      await readFile(
        launch.options.config!["model_instructions_file"] as string,
        "utf8",
      ),
    );
  });
  await using resumed = h.makeClient(configuration);
  const result = await resumed.run(h.repository, {
    ...options,
    signal: undefined,
    resumeScanId: parentId,
  });
  expect(result.manifest.scan.id).toBe(parentId);
  expect(texts.length).toBeGreaterThan(0);
  expect(texts.every((text) => text === "Changed legacy instructions.\n")).toBe(
    true,
  );
});

test.each(promptFiles)(
  "successful resumed Deep post-scan turns do not inherit canonical instruction validation (%j)",
  async ({ setting }) => {
    const h = await fixture();
    const instructionPath = join(h.root, "instructions.md");
    await writeFile(instructionPath, "Original post-scan instructions.\n");
    const configuration = { [setting]: instructionPath };
    const options = {
      ...h.options,
      knowledgeBasePaths: undefined,
      workers: 1,
      postScanPrompt: "Synthetic follow-up after canonical completion.",
    };
    h.stopAfterSealing("standard");
    await using client = h.makeClient(configuration);
    await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId] = [...h.records].find(([, row]) => row.mode === "deep")!;
    h.afterCompletion(() =>
      writeFile(instructionPath, "Changed follow-up instructions.\n"),
    );
    const texts: string[] = [];
    h.observeLaunch(async (launch) => {
      texts.push(
        await readFile(launch.options.config![setting] as string, "utf8"),
      );
    });
    await using resumed = h.makeClient(configuration);
    const result = await resumed.run(h.repository, {
      ...options,
      signal: undefined,
      resumeScanId: parentId,
    });
    expect(result.manifest.scan.id).toBe(parentId);
    expect(texts.at(-1)).toBe("Changed follow-up instructions.\n");
    expect(
      texts
        .slice(0, -1)
        .every((text) => text === "Original post-scan instructions.\n"),
    ).toBe(true);
    expect(h.completedPrompts.at(-1)).toContain(options.postScanPrompt);
  },
);

test.each(promptFiles)(
  "cancellation during a successful instruction digest read retains cancellation classification (%j)",
  async ({ setting }) => {
    const h = await fixture();
    const instructionPath = join(h.root, "instructions.md");
    await writeFile(instructionPath, "Original cancellation instructions.\n");
    const configuration = { [setting]: instructionPath };
    const options = { ...h.options, knowledgeBasePaths: undefined, workers: 1 };
    h.stopAfterSealing("standard");
    await using client = h.makeClient(configuration);
    await expect(client.run(h.repository, options)).rejects.toBeInstanceOf(
      ScanTransportClosedError,
    );
    const [parentId] = [...h.records].find(([, row]) => row.mode === "deep")!;
    const files = await import("node:fs/promises");
    const read = files.readFile;
    const controller = new AbortController();
    const cause = new Error(
      "Synthetic cancellation during successful digest read",
    );
    let checked = false;
    const reading = spyOn(files, "readFile").mockImplementation((async (
      ...args: Parameters<typeof read>
    ) => {
      const result = await read(...args);
      if (args[0] === instructionPath) {
        checked = true;
        controller.abort(cause);
        return Buffer.from(
          "Changed bytes returned as cancellation becomes visible.",
        );
      }
      return result;
    }) as typeof read);
    const launches = h.launches.length;
    try {
      await using resumed = h.makeClient(configuration);
      const error = await resumed
        .run(h.repository, {
          ...options,
          signal: controller.signal,
          resumeScanId: parentId,
        })
        .catch((error: unknown) => error);
      expect(checked).toBe(true);
      expect(error).toBeInstanceOf(ScanInterruptedError);
      expect(error).not.toBeInstanceOf(DeepScanRecoveryError);
      expect((error as Error).cause).toBe(cause);
      expect(h.launches).toHaveLength(launches);
    } finally {
      reading.mockRestore();
    }
  },
);
