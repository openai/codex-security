import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";
import { DeepScanProgressTracker } from "../src/deep-progress.js";
import { loadDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import {
  DeepScanPublicationError,
  DeepScanRecoveryError,
  ScanCostTrackingError,
} from "../src/deep-scan.js";
import { ScanInterruptedError } from "../src/errors.js";
import { restoreProviderProfile } from "../src/provider-profile.js";
import { runWorkbench } from "../src/runtime.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { restoreScanKnowledge } from "../src/scan-inputs.js";
import { CODEX_SECURITY_THREAD_SOURCES } from "../src/thread-source.js";
import { git } from "./git-fixture.js";
import { effectiveCodexConfiguration } from "./support/api-events.js";
import {
  createDeepApiFixtures,
  pluginRoot,
  usage,
} from "./support/deep-api.js";
import { acceptedReviewCheckpoint } from "./support/review-state.js";
import { tokenUsageEvent } from "./support/usage-rollout.js";

const { fixture, cleanup } = createDeepApiFixtures();
afterEach(cleanup);

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
    const { reviewState: coverage } = await acceptedReviewCheckpoint(
      h.outputDir,
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

test("an empty target checkpoints failure without starting a child scan", async () => {
  const h = await fixture();
  await mkdir(join(h.repository, "empty"));
  await using client = h.makeClient();
  await expect(
    client.run(h.repository, { ...h.options, target: ["empty"] }),
  ).rejects.toThrow(
    "Deep Scan target is empty; no security audit was performed.",
  );
  expect(h.launches).toHaveLength(0);
  expect(h.commands).toContain("check-deep-scan-target");
  const checkpoint = await loadDeepScanCheckpoint(h.outputDir);
  expect(checkpoint!.passes).toEqual([]);
  expect(checkpoint!.terminalReason).toBe("failed");
});

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
        "codex-security": { command: "synthetic-workbench", enabled: false },
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
  expect(parentTurns).toHaveLength(4);
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
  }
  expect(
    parentTurns.map((turn) => turn.runOptions?.outputSchema),
  ).toMatchObject([
    { properties: { matches: {}, request: {} } },
    { properties: { matches: {}, request: {} } },
    { properties: { reviews: {} } },
    { properties: { sources: {} } },
  ]);
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
      features: {
        code_mode: {
          enabled: true,
          direct_only_tool_namespaces: ["viewer"],
          excluded_tool_namespaces: ["mcp__codex_security"],
        },
      },
      mcp_servers: {
        "codex.security": {
          command: "synthetic-private-inspector",
          enabled_tools: ["inspect"],
          omit_tools_from: ["direct"],
        },
      },
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
    expect((saved["recipe"] as JsonObject)["scanInputs"]).toMatchObject({
      modelCatalogFileSha256: createHash("sha256")
        .update(await readFile(replaySettings.model_catalog_json))
        .digest("hex"),
    });
    const replayProvider = {
      ...provider,
      auth: { ...provider.auth, cwd: h.home },
    };
    expect(config).not.toHaveProperty("model_providers");
    expect(config).not.toHaveProperty("mcp_servers");
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
      ...(unsealed ? [] : ["scan-manifest.json", "findings.json", "report.md"]),
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
  expect(result.review).not.toHaveProperty("completeness");
  const deferredReason =
    "The configured discovery time limit elapsed before any source review completed.";
  const savedAggregate = (await loadDeepScanCheckpoint(result.scanDir))!
    .aggregate!;
  expect(savedAggregate.coverage.deferred).toEqual([
    expect.objectContaining({
      reason: deferredReason,
    }),
  ]);
  const { reviewState } = await acceptedReviewCheckpoint(h.outputDir);
  expect(reviewState.deferred).toContainEqual(
    expect.objectContaining({ reason: deferredReason }),
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
      expect(result.review).not.toHaveProperty("completeness");
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
  const artifacts = ["scan-manifest.json", "findings.json", "report.md"];
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
      mcp_servers: {
        "codex-security": { command: "synthetic-workbench", enabled: true },
        "synthetic.server": { command: "synthetic-command" },
      },
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
  const lifecycle: string[] = [];
  const result = await client.run(h.repository, {
    ...h.options,
    onLifecycle: (scan) => {
      if (scan.mode === "deep") lifecycle.push(scan.status);
    },
    workers: 1,
    maxDiscoveryRuns: 3,
    maxCostUsd: passCost.estimatedUsd * 1.5,
  });
  expect(lifecycle).toEqual(["running", "completed"]);
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
  expect(result.review).not.toHaveProperty("completeness");
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
    expect(result.review).not.toHaveProperty("completeness");
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
  expect(result.review).not.toHaveProperty("completeness");
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
  expect(restored.review).not.toHaveProperty("completeness");
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
        ? {
            usage: null,
            cost: null,
            measurement: {
              ...snapshot.measurement,
              usage: null,
              cost: null,
              coverage: "unavailable" as const,
            },
          }
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
    const lifecycle: string[] = [];
    await expect(
      client.run(h.repository, {
        ...h.options,
        onLifecycle: (scan) => {
          if (scan.mode === "deep") lifecycle.push(scan.status);
        },
        workers: mode === "standard" ? 1 : 2,
        maxDiscoveryRuns: 3,
        maxCostUsd: passCost.estimatedUsd * (mode === "standard" ? 1.5 : 2.5),
      }),
    ).rejects.toBeInstanceOf(ScanCostTrackingError);
    expect(lifecycle).toEqual(["running", "failed"]);
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
