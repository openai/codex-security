import { execFileSync } from "node:child_process";
import { createCliTest } from "./support/cli-run.js";
import { workbenchCommand } from "./support/workbench-command.js";
import { gitText } from "./support/shell.js";
import { readSealedScanTurn } from "../src/scan-publication.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { createProviderProfile } from "../src/provider-profile.js";
import { nativeScanConfiguration } from "../src/execution-preparation.js";
import { randomUUID } from "node:crypto";
import { stripVTControlCharacters } from "node:util";
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
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { scanPreflightCodexConfig, type ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost, type ScanCost } from "../src/cost.js";
import { formatTokenUsage } from "../src/cost-model.js";
import {
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
} from "../src/deep-scan.js";
import {
  prepareSemanticScanDraft,
  type SemanticScan,
} from "../src/scan-semantics.js";
import {
  publishScan,
  writeSemanticScanDraft,
} from "../src/scan-publication.js";
import { prepareScanArtifactRestorer, runWorkbench } from "../src/runtime.js";
import {
  prepareKnowledgeBase,
  readKnowledgeBaseSnapshot,
} from "../src/knowledge-base.js";
import { workflowDigest } from "../src/finding-workflow.js";
import { saveScanKnowledge, scanInputIdentity } from "../src/scan-inputs.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { semanticCoverage, semanticFinding } from "./helpers/semantic-scan.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  preparedRuntime as fixtureRuntime,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { fail } from "./support/errors.js";
import { tokenUsageEvent } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

function preparedRuntime(codexHome: string) {
  const runtime = fixtureRuntime(codexHome);
  runtime.plugin.pluginRoot = PLUGIN_ROOT;
  runtime.plugin.installedRoot = PLUGIN_ROOT;
  runtime.plugin.marketplaceRoot = PLUGIN_ROOT;
  return runtime;
}

async function interruptedScan(
  mode: "deep" | "standard" = "deep",
  bulk = false,
  settings: Pick<
    ScanOptions,
    | "knowledgeBasePaths"
    | "cyberAccessProgram"
    | "maxCostUsd"
    | "safetyIdentifier"
    | "postScanPrompt"
    | "auth"
    | "inheritedPermissions"
    | "preserveProviderEnvironment"
  > & {
    config?: JsonObject;
    model?: string;
    modelProvider?: string;
    privateProvider?: JsonObject;
    scopedPaths?: string[];
  } = {},
  resolvedDeep = false,
  startedMerge = true,
  ordinaryPass: {
    cost?: ScanCost;
    findings?: SemanticScan["findings"];
    coverage?: SemanticScan["coverage"];
  } | null = {},
  knowledgeState: "saved" | "legacy" = "saved",
) {
  const {
    model = "gpt-5.6-sol",
    modelProvider,
    scopedPaths,
    privateProvider,
    ...scanSettings
  } = settings;
  const root = await temporaryDirectory();
  const repository = bulk
    ? join(root, "checkouts", "repo")
    : join(root, "repository");
  const scanDir = bulk
    ? join(root, "artifacts", "repo", "attempt-1")
    : join(root, "scan");
  const codexHome = join(root, "state", "codex-home");
  await mkdir(repository, { recursive: true, mode: 0o700 });
  await mkdir(scanDir, { recursive: true, mode: 0o700 });
  await mkdir(join(codexHome, "sessions"), { recursive: true, mode: 0o700 });
  await writeFile(join(repository, "source.py"), "# synthetic source\n");
  const input = join(root, "repositories.csv");
  if (bulk) {
    const git = (...args: string[]) =>
      gitText(["-C", repository, ...args]).trim();
    git("init", "-q");
    git("add", ".");
    git(
      "-c",
      "user.name=Recovery Test",
      "-c",
      "user.email=recovery@example.test",
      "commit",
      "-qm",
      "initial",
    );
    const source = join(root, "source");
    git("clone", "--quiet", "--no-hardlinks", repository, source);
    const task = {
      id: "repo",
      repository: source,
      revision: git("rev-parse", "HEAD"),
      mode,
    };
    await writeFile(
      input,
      `id,repository,revision,mode\nrepo,${source},${task.revision},${mode}\n`,
    );
    await writeFile(
      join(root, "manifest.json"),
      JSON.stringify(
        {
          version: 2,
          tasks: [task],
          ...(settings.knowledgeBasePaths?.length
            ? {
                knowledgeBaseDigests: {
                  [mode]: workflowDigest(
                    (
                      await readKnowledgeBaseSnapshot(
                        settings.knowledgeBasePaths,
                      )
                    ).documents,
                  ),
                },
              }
            : {}),
        },
        null,
        2,
      ) + "\n",
    );
    await writeFile(
      join(root, "results.jsonl"),
      JSON.stringify({
        ...task,
        status: "failed",
        attempt: 1,
        outputDir: scanDir,
        error: "Occupied attempt",
      }) + "\n",
    );
  }
  const python = Bun.which("python3") ?? Bun.which("python");
  if (python === null) throw new Error("Python is required for this test.");
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: codexHome,
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    ...(modelProvider === "amazon-bedrock"
      ? { AWS_PROFILE: "synthetic-bedrock" }
      : {}),
    ...(settings.safetyIdentifier === undefined
      ? {}
      : { OPENAI_API_KEY: "synthetic-resume-key" }),
  };
  const command = workbenchCommand(python, () => environment);
  const knowledge = settings.knowledgeBasePaths?.length
    ? await prepareKnowledgeBase(settings.knowledgeBasePaths, undefined, root)
    : undefined;
  await knowledge?.cleanup();
  const knowledgeSnapshot =
    !bulk && knowledgeState === "saved" ? knowledge?.snapshot : undefined;
  const providerProfile =
    privateProvider === undefined
      ? undefined
      : await createProviderProfile(codexHome, {
          model_providers: { [modelProvider!]: privateProvider },
        });
  const recipe = {
    ...(providerProfile === undefined
      ? {}
      : {
          providerProfile: {
            name: providerProfile.name,
            home: "managed" as const,
          },
        }),
    ...(knowledge ? { knowledgeBaseSha256: knowledge.sha256 } : {}),
    repository,
    target: {
      kind: scopedPaths ? "paths" : "repository",
      paths: scopedPaths ?? [],
    },
    mode,
    config: {
      model,
      ...(modelProvider === undefined ? {} : { model_provider: modelProvider }),
      approval_policy: "never",
      ...(settings.preserveProviderEnvironment
        ? {
            model_provider: "custom",
            model_providers: { custom: { env_key: "OPENAI_API_KEY" } },
          }
        : {}),
    },
    pluginVersion: "0.1.0",
    requiresScanPrompt: true,
    ...scanSettings,
    ...(knowledgeSnapshot === undefined
      ? {}
      : {
          scanInputs: scanInputIdentity(
            "Keep the original scan instructions.",
            knowledgeSnapshot,
          ),
        }),
    ...(mode === "deep"
      ? {
          deepScan: {
            workers: 2,
            maxDiscoveryRuns: 5,
            ...(resolvedDeep
              ? {
                  subagents: 0,
                  stopAfterNoNew: 6,
                  stopAfterConsecutiveErrors: 2,
                  maxTimeHours: 1.5,
                }
              : {}),
          },
          ...(resolvedDeep ? { deepScanResolved: true } : {}),
        }
      : {}),
  };
  const registration = await command(
    [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--registration-json-stdin",
    ],
    JSON.stringify({
      recipe,
      userContext: "Keep the original scan instructions.",
    }),
  );
  const scanId = registration["scanId"] as string;
  if (knowledgeSnapshot !== undefined)
    await saveScanKnowledge(scanDir, knowledgeSnapshot);
  const threadId = randomUUID();
  if (startedMerge)
    await command([
      "set-scan-thread",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId,
    ]);
  const sessionPath = join(codexHome, "sessions", `rollout-${threadId}.jsonl`);
  await writeFile(
    sessionPath,
    JSON.stringify({
      type: "session_meta",
      payload: {
        id: threadId,
        cwd:
          mode === "deep"
            ? join(scanDir, "artifacts/deep-scan/merge")
            : scanDir,
      },
    }) + "\n",
  );
  let childId: string | undefined;
  let childDir: string | undefined;
  if (mode === "deep" && ordinaryPass !== null) {
    childDir = join(scanDir, "artifacts/deep-scan/passes/pass-1");
    await mkdir(childDir, { recursive: true, mode: 0o700 });
    const child = await command(
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        childDir,
        "--parent-scan-id",
        scanId,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        recipe: {
          repository,
          target: recipe.target,
          mode: "standard",
          config: recipe.config,
        },
        parentScanRole: "deep_pass",
      }),
    );
    childId = child["scanId"] as string;
    const aggregate: SemanticScan = {
      scanId,
      findings: ordinaryPass.findings ?? [],
      coverage: ordinaryPass.coverage ?? {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [{ id: "time-cap", reason: "Synthetic time cap" }],
      },
    };
    await writeDraft(command, child, "standard", {
      ...aggregate,
      scanId: childId,
    });
    await command(["prepare-scan-completion", "--scan-id", childId]);
    await command([
      "complete-scan",
      "--scan-id",
      childId,
      ...(ordinaryPass.cost
        ? ["--cost-json", JSON.stringify(ordinaryPass.cost)]
        : []),
    ]);
    const state: DeepScanCheckpoint = {
      version: 3,
      startedAt: "2000-01-01T00:00:00Z",
      passes: [
        { directory: "artifacts/deep-scan/passes/pass-1", scanId: childId },
      ],
      mergedScanIds: startedMerge ? [childId] : [],
      aggregate: startedMerge ? { ...aggregate, sourceFindings: {} } : null,
      noNewStreak: startedMerge ? 1 : 0,
      consecutiveErrors: 0,
    };
    await command(
      [
        "save-scan-artifact",
        "--scan-id",
        scanId,
        "--artifact-path",
        DEEP_SCAN_CHECKPOINT,
      ],
      JSON.stringify({ ...state, aggregate: undefined, aggregatePath: null }),
    );
  }
  const checkpoint = join(scanDir, "checkpoint.json");
  await writeFile(checkpoint, '{"completed":"setup"}\n');
  return {
    root,
    repository,
    scanDir,
    codexHome,
    python,
    environment,
    command,
    recipe,
    scanId,
    threadId,
    registration,
    sessionPath,
    checkpoint,
    input,
    childId,
    childDir,
  };
}

async function writeDraft(
  command: (args: readonly string[], input?: string) => Promise<JsonObject>,
  registration: JsonObject,
  mode: "deep" | "standard",
  draft: SemanticScan,
) {
  await writeSemanticScanDraft(
    {
      contract: {
        targetContract: registration["contract"] as JsonObject,
        mode,
        targetRevision: registration["targetRevision"] as string,
      },
      workbench: command,
    },
    draft,
  );
}

test.each([
  "interrupted-export",
  "interrupted-missing-findings",
  "interrupted-complete-export",
  "first-export",
  "partial-first-export",
  "invalid-manifest",
  "file-authored-result",
  "file-authored-new-timestamp",
  "file-authored-omitted-timestamp",
  "file-authored-complete-checkpoint",
  "file-authored-unchanged-manifest",
] as const)(
  "SDK completion preserves the latest committed or authored draft (%s)",
  async (scenario) => {
    const f = await interruptedScan("standard");
    const authored = scenario.startsWith("file-authored-");
    const previouslyComplete = [
      "file-authored-complete-checkpoint",
      "file-authored-unchanged-manifest",
      "interrupted-complete-export",
    ].includes(scenario);
    const provisional: SemanticScan = {
      scanId: f.scanId,
      complete: previouslyComplete,
      findings: [],
      coverage: {
        completeness: previouslyComplete ? "complete" : "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: previouslyComplete
          ? []
          : [{ id: "unfinished", reason: "Synthetic unfinished work" }],
      },
    };
    await writeDraft(f.command, f.registration, "standard", provisional);
    const oldManifest = await readFile(join(f.scanDir, "scan-manifest.json"));
    const oldCoverage = await readFile(join(f.scanDir, "coverage.json"));
    if (!authored) {
      await writeDraft(f.command, f.registration, "standard", {
        ...provisional,
        complete: true,
        findings:
          scenario === "interrupted-complete-export"
            ? [
                semanticFinding({
                  title: "Synthetic final authored finding",
                  locations: [{ path: "source.py", startLine: 1 }],
                }),
              ]
            : [],
        coverage: {
          ...provisional.coverage,
          completeness: "complete",
          deferred: [],
        },
      });
      // Reproduce failure after findings export but before coverage and manifest.
      await writeFile(join(f.scanDir, "coverage.json"), oldCoverage);
      await writeFile(join(f.scanDir, "scan-manifest.json"), oldManifest);
      if (scenario === "interrupted-missing-findings") {
        await rm(join(f.scanDir, "findings.json"));
      } else if (
        scenario === "first-export" ||
        scenario === "partial-first-export"
      ) {
        for (const name of [
          "scan-manifest.json",
          "coverage.json",
          ...(scenario === "first-export" ? ["findings.json"] : []),
        ])
          await rm(join(f.scanDir, name));
      } else if (scenario === "invalid-manifest") {
        await writeFile(join(f.scanDir, "scan-manifest.json"), "{invalid");
      }
    } else {
      const manifest = JSON.parse(oldManifest.toString());
      if (scenario !== "file-authored-unchanged-manifest")
        delete manifest.scan.complete;
      if (
        [
          "file-authored-new-timestamp",
          "file-authored-complete-checkpoint",
        ].includes(scenario)
      )
        manifest.scan.completedAt = "2030-01-01T00:00:00Z";
      if (scenario === "file-authored-omitted-timestamp")
        delete manifest.scan.completedAt;
      const final = prepareSemanticScanDraft(
        {
          targetContract: f.registration["contract"] as JsonObject,
          mode: "standard",
          targetRevision: f.registration["targetRevision"] as string,
        },
        {
          ...provisional,
          complete: true,
          findings: [
            semanticFinding({
              title: "Synthetic final authored finding",
              locations: [{ path: "source.py", startLine: 1 }],
            }),
          ],
        },
      );
      await writeFile(
        join(f.scanDir, "findings.json"),
        JSON.stringify(final.findings),
      );
      const coverage = JSON.parse(oldCoverage.toString());
      coverage.completeness = "complete";
      coverage.deferred = [];
      await writeFile(
        join(f.scanDir, "coverage.json"),
        JSON.stringify(coverage),
      );
      if (scenario !== "file-authored-unchanged-manifest")
        await writeFile(
          join(f.scanDir, "scan-manifest.json"),
          JSON.stringify(manifest),
        );
    }
    const draft = JSON.parse(
      await readFile(join(f.scanDir, "artifacts/scan-draft.json"), "utf8"),
    );
    const publication = publishScan(
      {
        writer: await prepareScanArtifactRestorer(
          {
            python: f.python,
            pluginRoot: PLUGIN_ROOT,
            environment: f.environment,
          },
          f.scanDir,
        ),
        scanId: f.scanId,
        scanDir: f.scanDir,
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          repository: f.repository,
          repositoryRevision: null,
          target: { kind: "repository", paths: [] },
          mode: "standard",
          pluginVersion: draft.manifest.scan.producer.version,
        },
        signal: new AbortController().signal,
        workbench: f.command,
      },
      { threadId: f.threadId, turnResult: { status: "completed" } },
      null,
      false,
    );
    if (scenario === "invalid-manifest") {
      await expect(publication).rejects.toThrow();
      return;
    }
    const published = await publication;
    expect(published.result.coverage.completeness).toBe("complete");
    expect(published.result.coverage.deferred).toEqual([]);
    expect(
      published.result.findings.findings.map((finding) => finding.title),
    ).toEqual(
      authored || scenario === "interrupted-complete-export"
        ? ["Synthetic final authored finding"]
        : [],
    );
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
    });
  },
);

test("resume preserves its identity, launch recipe, accepted child and checkpoint", async () => {
  const f = await interruptedScan();
  const before = await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT));
  const child = await f.command(["get-scan", "--scan-id", f.childId!]);
  const artifacts = await readFile(join(f.childDir!, "findings.json"));
  const resumed = await f.command([
    "get-cli-scan-resume",
    "--scan-id",
    f.scanId,
  ]);
  expect(resumed).toMatchObject({
    ...f.registration,
    recipe: f.recipe,
    threadId: f.threadId,
  });
  expect(await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT))).toEqual(before);
  expect(await f.command(["get-scan", "--scan-id", f.childId!])).toEqual(child);
  expect(await readFile(join(f.childDir!, "findings.json"))).toEqual(artifacts);
});

test("CLI and native replay restore custom provider credentials from the denied home", async () => {
  const provider = {
    name: "Synthetic replay provider",
    wire_api: "responses",
    auth: {
      command: "synthetic-auth",
      args: ["synthetic-private-argument"],
      env: { CLIENT_SECRET: "synthetic-private-environment" },
    },
  };
  const f = await interruptedScan("deep", false, {
    modelProvider: "synthetic",
    privateProvider: provider,
  });
  const saved = await f.command(["get-scan-recipe", "--scan-id", f.scanId]);
  expect(JSON.stringify(saved)).not.toContain("synthetic-private-");
  expect(f.recipe.config).not.toHaveProperty("model_providers");
  const native = await nativeScanConfiguration(
    f.environment,
    { recipe: f.recipe },
    1,
  );
  expect(native["model_providers"]).toEqual({ synthetic: provider });
  const deps = dependencies({
    environment: f.environment,
    currentDirectory: f.root,
  });
  const { stderr, runCli } = createCliTest(main);
  let launched = false;
  const code = await runCli(["scans", "resume", f.scanId, "--json"], {
    ...deps,
    runWorkbench: f.command,
    createSecurity: (config) => {
      expect(config.codexOverrides?.["model_providers"]).toEqual({
        synthetic: provider,
      });
      return {
        ...deps.createSecurity(config),
        run: async () => {
          launched = true;
          throw new Error("synthetic replay boundary reached");
        },
      };
    },
  });
  expect(launched, stderr.text()).toBe(true);
  expect(code).toBe(2);
  expect(stderr.text()).toContain("synthetic replay boundary reached");
});

test.each(["failed", "canceled", "changed", "replaced", "wrong-owner"])(
  "resume refuses %s scans without altering their saved state",
  async (scenario) => {
    const f = await interruptedScan();
    if (scenario === "failed")
      await f.command([
        "fail-scan",
        "--scan-id",
        f.scanId,
        "--message",
        "Synthetic failure",
      ]);
    if (scenario === "canceled")
      await f.command(["cancel-scan", "--scan-id", f.scanId]);
    if (scenario === "changed")
      await writeFile(join(f.repository, "source.py"), "# changed\n");
    if (scenario === "replaced") {
      await rename(f.repository, join(f.root, "original-repository"));
      await mkdir(f.repository);
      await writeFile(join(f.repository, "source.py"), "# synthetic source\n");
    }
    const ownerArgs =
      scenario === "wrong-owner" ? ["--claim-token", randomUUID()] : [];
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    expect(
      await f.command([
        "get-cli-scan-resume",
        "--scan-id",
        f.scanId,
        "--allow-unavailable",
        ...ownerArgs,
      ]),
    ).toMatchObject({ unavailable: expect.any(String) });
    await expect(
      f.command(["get-cli-scan-resume", "--scan-id", f.scanId, ...ownerArgs]),
    ).rejects.toThrow(
      scenario === "changed"
        ? "revision or contents changed"
        : scenario === "replaced"
          ? "checkout is missing or was replaced"
          : scenario === "wrong-owner"
            ? "original owning CLI session"
            : "running scan; completed, failed, and canceled",
    );
    expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
      before,
    );
    expect(await readFile(f.checkpoint, "utf8")).toBe(
      '{"completed":"setup"}\n',
    );
  },
);

function resumeClient(
  f: Awaited<ReturnType<typeof interruptedScan>>,
  createCodex: NonNullable<
    ConstructorParameters<typeof TestClient>[1]["createCodex"]
  >,
  workbench: typeof runWorkbench = runWorkbench,
) {
  return (config: ConstructorParameters<typeof TestClient>[0]) =>
    new TestClient(config, {
      environment: f.environment,
      prepareRuntime: async () => {
        const runtime = preparedRuntime(f.codexHome);
        runtime.configPath = join(f.root, "resumed-runtime.toml");
        runtime.environment = Object.fromEntries(
          Object.entries(f.environment).filter(
            (entry): entry is [string, string] => entry[1] !== undefined,
          ),
        );
        runtime.plugin.version = JSON.parse(
          await readFile(
            join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
            "utf8",
          ),
        ).version;
        return runtime;
      },
      resolvePluginPython: async () => f.python,
      prepareScanArtifactRestorer,
      runWorkbench: workbench,
      createCodex,
    });
}

test.each(["chatgpt", "api-key"] as const)(
  "CLI saves %s authentication and launch settings before execution",
  async (auth) => {
    const safetyIdentifier =
      auth === "chatgpt" ? undefined : "synthetic-original-user";
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "state", "codex-home");
    await mkdir(repository);
    await mkdir(codexHome, { recursive: true, mode: 0o700 });
    await writeFile(join(repository, "source.py"), "# synthetic source\n");
    const promptFile = join(root, "post-scan.md");
    const postScanPrompt = "Keep these original post-scan instructions.\n";
    await writeFile(promptFile, postScanPrompt);
    const python = Bun.which("python3") ?? Bun.which("python");
    if (python === null) throw new Error("Python is required for this test.");
    const environment = {
      PATH: process.env["PATH"],
      SystemRoot: process.env["SystemRoot"],
      TEMP: process.env["TEMP"],
      TMP: process.env["TMP"],
      CODEX_HOME: codexHome,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
      OPENAI_API_KEY: "synthetic-launch-key",
    };
    const command = workbenchCommand(python, () => environment);
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      [
        "scan",
        repository,
        "--mode",
        "deep",
        "--output-dir",
        join(root, "scan"),
        "--auth",
        auth,
        ...(safetyIdentifier === undefined
          ? []
          : ["--safety-identifier", safetyIdentifier]),
        "--post-scan-prompt-file",
        promptFile,
        "--json",
      ],
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: () => fail("Synthetic stop after registration"),
          }),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Synthetic stop after registration");
    await writeFile(
      promptFile,
      "Changed instructions that must not replace the saved text.",
    );
    await rm(promptFile);
    const scans = (await command(["list-scans", "--repository", repository]))[
      "scans"
    ] as Array<{ scanId: string }>;
    expect(scans).toHaveLength(1);
    const saved = await command([
      "get-scan-recipe",
      "--scan-id",
      scans[0]!.scanId,
    ]);
    expect(saved["recipe"]).toMatchObject({
      auth,
      ...(safetyIdentifier === undefined ? {} : { safetyIdentifier }),
      postScanPrompt,
    });
    expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
    expect(JSON.stringify(saved)).not.toContain(promptFile);
  },
);

test.each([
  ["chatgpt", false, false],
  ["api-key", false, false],
  [undefined, false, false],
  ["chatgpt", true, false],
  ["api-key", true, false],
  [undefined, true, false],
  [undefined, false, true],
  [undefined, true, true],
] as const)(
  "resume restores saved launch settings with %s auth (bulk: %p, native provider: %p)",
  async (auth, bulk, preserveProviderEnvironment) => {
    const profile =
      auth === "chatgpt"
        ? "review.v2"
        : auth === "api-key"
          ? "review mode"
          : "分析";
    const selected = {
      model: `synthetic-${auth ?? "auto"}-model`,
      model_reasoning_effort: "high",
      features: { goals: false },
    };
    const settings = {
      config: scanPreflightCodexConfig({
        model: "synthetic-root-model",
        model_reasoning_effort: "low",
        profile,
        profiles: { [profile]: selected },
      }),
      auth,
      ...(preserveProviderEnvironment
        ? { preserveProviderEnvironment: true }
        : {}),
      safetyIdentifier:
        auth === "chatgpt" ? undefined : "synthetic-original-user",
      postScanPrompt: "Run these exact saved post-scan instructions.\n",
      inheritedPermissions: {
        filesystem: {
          [join(tmpdir(), "synthetic-private")]: "deny",
          glob_scan_max_depth: 4,
        },
        network: { enabled: false },
      },
    };
    const f = await interruptedScan("deep", bulk, settings, true);
    f.environment.OPENAI_API_KEY = "synthetic-resume-key";
    const ambientHome = join(f.root, "ambient-codex-home");
    f.environment.CODEX_HOME = ambientHome;
    const ambientDeepConfig = join(
      ambientHome,
      "codex-security",
      "config.toml",
    );
    await mkdir(join(ambientHome, "codex-security"), { recursive: true });
    await writeFile(ambientDeepConfig, "invalid ambient TOML [");
    const prompts: string[] = [];
    const { stderr, runCli } = createCliTest(main);

    const code = await runCli(
      bulk
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, (options) => {
          expect(options.config).toMatchObject(selected);
          expect(options.config).toMatchObject({
            permissions: { codex_security_scan: settings.inheritedPermissions },
          });
          expect(options.env?.["CODEX_SAFETY_IDENTIFIER"]).toBe(
            settings.safetyIdentifier,
          );
          expect(options.apiKey).toBe(
            preserveProviderEnvironment || auth === "chatgpt"
              ? undefined
              : "synthetic-resume-key",
          );
          expect(options.env?.["OPENAI_API_KEY"]).toBe(
            preserveProviderEnvironment ? "synthetic-resume-key" : undefined,
          );
          expect(options.env?.["CODEX_API_KEY"]).toBeUndefined();
          expect(options.config?.["features"]).not.toHaveProperty(
            "api_key_cyber_access_programs",
          );
          return {
            startThread() {
              return {
                id: f.threadId,
                async runStreamed(prompt) {
                  prompts.push(prompt as string);
                  return { events: completedEvents(f.threadId) };
                },
              };
            },
            resumeThread(threadId) {
              expect(threadId).toBe(f.threadId);
              return {
                id: threadId,
                async runStreamed() {
                  throw new Error("Completed inputs need no model turn.");
                },
              };
            },
          };
        }),
      },
    );
    expect(code, stderr.text()).toBe(2);
    expect(prompts, stderr.text()).toHaveLength(1);
    expect(prompts[0]).toContain(JSON.stringify(f.repository));
    expect(prompts[0]).toContain(JSON.stringify(f.scanDir));
    expect(prompts[0]?.endsWith(settings.postScanPrompt)).toBe(true);
    expect(
      (await f.command(["get-scan-recipe", "--scan-id", f.scanId]))["recipe"],
    ).toMatchObject({
      ...JSON.parse(JSON.stringify(settings)),
      deepScan: {
        subagents: 0,
        stopAfterConsecutiveErrors: 2,
        maxTimeHours: 1.5,
      },
    });
    expect(f.environment.OPENAI_API_KEY).toBe("synthetic-resume-key");
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
    });
  },
);

test.each([false, true])(
  "resumed CLI starts with terminal Deep progress (interactive=%p)",
  async (interactive) => {
    const f = await interruptedScan();
    await f.command([
      "update-progress",
      "--scan-id",
      f.scanId,
      "--phase",
      "validation",
    ]);
    const { stderr, runCli } = createCliTest(main, { stderr: interactive });
    const progress = Promise.withResolvers<void>();
    const updates: Array<boolean | undefined> = [];
    const createSecurity = resumeClient(
      f,
      () => ({
        startThread: () => ({
          id: null,
          runStreamed: async () =>
            fail("Completed review needs no new discovery"),
        }),
        resumeThread: (threadId) => ({
          id: threadId,
          runStreamed: async () =>
            fail("Completed review needs no new discovery"),
        }),
      }),
      async (options, args, input) => {
        if (args[0] === "list-scans") {
          await progress.promise;
          const text = stripVTControlCharacters(stderr.text()).replace(
            /\s+/gu,
            " ",
          );
          expect(text).toContain("consolidating results");
          expect(text).toContain("Reviews: 1 completed, 0 active, cap 5");
          throw new Error("Terminal progress captured");
        }
        return runWorkbench(options, args, input);
      },
    );
    const code = await runCli(["scans", "resume", f.scanId, "--json"], {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: (config) => {
        const security = createSecurity(config);
        const run = security.run.bind(security);
        security.run = (repository, options = {}) =>
          run(repository, {
            ...options,
            onDeepProgress(update) {
              options.onDeepProgress?.(update);
              updates.push(update.consolidating);
              progress.resolve();
            },
          });
        return security;
      },
    });
    expect(code).toBe(2);
    expect(updates[0]).toBe(true);
    expect(stderr.text()).toContain("Terminal progress captured");
  },
);

test("bulk Deep resume stages campaign knowledge after its source is removed", async () => {
  const documentRoot = await temporaryDirectory();
  const document = join(documentRoot, "architecture.md");
  await writeFile(document, "Original architecture.");
  const f = await interruptedScan("deep", true, {
    knowledgeBasePaths: [document],
  });
  const stdout = capture();
  const stderr = capture();
  let staged: Promise<Record<string, string>> | undefined;
  const code = await main(
    [
      "bulk-scan",
      f.input,
      "--output-dir",
      f.root,
      "--recover",
      "--knowledge-base",
      document,
      "--json",
    ],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      createSecurity: resumeClient(f, (codex) => ({
        startThread(options) {
          return this.resumeThread!(f.threadId, options);
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          const directory = codex.env!["CODEX_SECURITY_KNOWLEDGE_BASE"]!;
          staged = readdir(directory).then(async (names) =>
            Object.fromEntries(
              await Promise.all(
                names.map(async (name) => [
                  name,
                  await readFile(join(directory, name), "utf8"),
                ]),
              ),
            ),
          );
          return {
            id: threadId,
            async runStreamed() {
              throw new Error("Completed inputs need no model turn.");
            },
          };
        },
      })),
      runWorkbench: async (args, input) => {
        if (args[0] === "get-cli-scan-resume") await rm(document);
        return f.command(args, input);
      },
    },
  );
  expect(staged, stderr.text()).toBeDefined();
  expect(await staged).toEqual({
    "0-architecture.md.txt": "Original architecture.",
  });
  expect(code, stderr.text()).toBe(2);
  expect(JSON.parse(stdout.text())).toMatchObject({ incomplete: 1, failed: 0 });
  expect(
    (await f.command(["get-scan-recipe", "--scan-id", f.scanId]))["recipe"],
  ).toMatchObject({ knowledgeBasePaths: [document] });
});

test.each(["unchanged", "edited", "deleted"] as const)(
  "single Deep resume uses saved knowledge when original files are %s",
  async (sourceState) => {
    const documentRoot = await temporaryDirectory();
    const document = join(documentRoot, "architecture.md");
    await writeFile(document, "Original architecture.\n");
    const f = await interruptedScan("deep", false, {
      knowledgeBasePaths: [document],
    });
    const before = await readFile(f.checkpoint, "utf8");
    const savedBytes = await readFile(
      join(f.scanDir, ".scan-knowledge.json"),
      "utf8",
    );
    if (sourceState === "edited")
      await writeFile(document, "Changed architecture.\n");
    if (sourceState === "deleted") await rm(document);
    const stdout = capture();
    const stderr = capture();
    let resumed = false;
    let staged = "";
    let stagedText: Promise<string> | undefined;
    const code = await main(
      ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, (codex) => ({
          startThread(options) {
            return this.resumeThread!(f.threadId, options);
          },
          resumeThread() {
            staged = codex.env!["CODEX_SECURITY_KNOWLEDGE_BASE"]!;
            stagedText = readFile(
              join(staged, "0-architecture.md.txt"),
              "utf8",
            );
            resumed = true;
            return {
              id: f.threadId,
              async runStreamed() {
                throw new Error("synthetic interrupted transport");
              },
            };
          },
        })),
      },
    );
    expect(resumed, stderr.text()).toBe(true);
    expect(await stagedText).toBe("Original architecture.\n");
    expect(code).toBe(2);
    expect(
      await readFile(join(f.scanDir, ".scan-knowledge.json"), "utf8"),
    ).toContain("Original architecture.");
    expect(await readdir(staged).catch(() => null)).toBeNull();
    expect(await readFile(f.checkpoint, "utf8")).toBe(before);
    expect(
      await readFile(join(f.scanDir, ".scan-knowledge.json"), "utf8"),
    ).toBe(savedBytes);
    expect(
      (await f.command(["get-scan-recipe", "--scan-id", f.scanId]))["recipe"],
    ).toEqual(f.recipe);
  },
);

test.each(["legacy", "missing", "modified"] as const)(
  "single Deep resume preserves saved work when knowledge snapshot is %s",
  async (snapshotState) => {
    const documentRoot = await temporaryDirectory();
    const document = join(documentRoot, "architecture.md");
    await writeFile(document, "Original architecture.");
    const f = await interruptedScan(
      "deep",
      false,
      { knowledgeBasePaths: [document] },
      false,
      true,
      {},
      snapshotState === "legacy" ? "legacy" : "saved",
    );
    const snapshot = join(f.scanDir, ".scan-knowledge.json");
    if (snapshotState === "missing") await rm(snapshot);
    if (snapshotState === "modified") {
      const value = JSON.parse(await readFile(snapshot, "utf8"));
      value.documents["0-architecture.md.txt"] = "Changed architecture.";
      await writeFile(snapshot, JSON.stringify(value));
    }
    const before = await readFile(f.checkpoint, "utf8");
    const stderr = capture();
    const code = await main(
      ["scans", "resume", f.scanId, "--json"],
      capture().stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, () => {
          throw new Error(
            "Cannot run with missing or changed original context",
          );
        }),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toMatch(/new scan/i);
    expect(await readFile(f.checkpoint, "utf8")).toBe(before);
    expect(
      (await f.command(["get-cli-scan-resume", "--scan-id", f.scanId]))[
        "recipe"
      ],
    ).toEqual(f.recipe);
  },
);

test("missing session logs do not create another session or fail the original scan", async () => {
  const f = await interruptedScan();
  await rm(f.sessionPath);
  const { stderr, runCli } = createCliTest(main);

  const code = await runCli(["scans", "resume", f.scanId], {
    ...dependencies({ environment: f.environment, currentDirectory: f.root }),
    runWorkbench: f.command,
    createSecurity: resumeClient(f, () =>
      fail("Must not invoke Codex without the original session"),
    ),
  });
  expect(code).not.toBe(0);
  expect(stderr.text()).toContain("original Codex session");
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "running" } });
});

async function sealSavedScan(
  f: Awaited<ReturnType<typeof interruptedScan>>,
  cost: ScanCost,
) {
  await writeDraft(f.command, f.registration, "deep", {
    scanId: f.scanId,
    findings: [],
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  });
  const checkpoint = JSON.parse(
    await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
  );
  await f.command(
    [
      "save-scan-artifact",
      "--scan-id",
      f.scanId,
      "--artifact-path",
      DEEP_SCAN_CHECKPOINT,
    ],
    JSON.stringify({
      ...checkpoint,
      finalCost: cost,
      terminalReason: "capped",
    }),
  );
  await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
}

test.each([
  "managed",
  "native",
  "changed-target",
  "deleted-scope",
  "deleted-scope-native",
  "deleted-scope-mismatch",
  "deleted-scope-escape",
  "wrong-claim",
  "wrong-target",
  "wrong-output",
  "changed-artifact",
] as const)(
  "sealed publication reads without authentication or execution (%s)",
  async (scenario) => {
    const childCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 375,
      output_tokens: 3,
    })!;
    const expectedCost = {
      ...estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1375,
        output_tokens: 13,
      })!,
      // The saved price can differ from today's estimate of the same tokens.
      estimatedUsd: 0.125,
    };
    const f = await interruptedScan(
      "deep",
      false,
      scenario.startsWith("deleted-scope")
        ? { scopedPaths: ["source.py"] }
        : {},
      true,
      true,
      { cost: childCost },
    );
    await sealSavedScan(f, expectedCost);
    const native =
      scenario === "deleted-scope-native" ||
      (scenario !== "managed" &&
        scenario !== "changed-target" &&
        !scenario.startsWith("deleted-scope"));
    const owner = "synthetic-native-owner";
    const claim = randomUUID();
    if (native) {
      const nativeHome = join(f.root, "native-home");
      await rename(f.codexHome, nativeHome);
      f.environment.CODEX_HOME = nativeHome;
      execFileSync(f.python, [
        "-c",
        `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("UPDATE scans SET deep_scan_owner_thread_id = ?, handoff_claim_token = ? WHERE id = ?", sys.argv[2:])
`,
        join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
        owner,
        claim,
        f.scanId,
      ]);
    }
    let repository = f.repository;
    let outputDir = f.scanDir;
    if (scenario === "wrong-target") {
      repository = join(f.root, "other-repository");
      await mkdir(repository);
      await writeFile(
        join(repository, "source.py"),
        "# another synthetic source\n",
      );
    }
    if (scenario === "wrong-output") {
      outputDir = join(f.root, "other-output");
      await mkdir(outputDir, { mode: 0o700 });
      await cp(f.scanDir, outputDir, { recursive: true });
    }
    if (scenario === "changed-artifact")
      await appendFile(join(f.scanDir, "findings.json"), "\n");
    if (scenario === "changed-target")
      await writeFile(
        join(f.repository, "source.py"),
        "# changed after sealing\n",
      );
    if (scenario.startsWith("deleted-scope"))
      await rm(join(f.repository, "source.py"));
    const artifactNames = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
      DEEP_SCAN_CHECKPOINT,
    ];
    const artifacts = await Promise.all(
      artifactNames.map((name) => readFile(join(f.scanDir, name))),
    );
    const commands: string[] = [];
    let authentications = 0;
    const client = new TestClient(
      { pluginPath: PLUGIN_ROOT },
      {
        environment: f.environment,
        ...(native
          ? {
              ambientExecution: {
                command: { command: "synthetic-unused-codex" },
                configuration: {},
                environment: f.environment,
                pluginRoot: PLUGIN_ROOT,
              },
            }
          : {}),
        prepareRuntime: async () => {
          throw new Error(
            "Saved publication must not prepare a Codex runtime.",
          );
        },
        createCodex: () => {
          throw new Error("Saved publication must not create a model client.");
        },
        resolvePluginPython: async () => f.python,
        runWorkbench: async (options, args, input) => {
          commands.push(args[0]!);
          return runWorkbench(options, args, input);
        },
      },
    );
    try {
      const pending = client.run(repository, {
        mode: "deep",
        ...(scenario.startsWith("deleted-scope")
          ? {
              target: [
                scenario === "deleted-scope-mismatch"
                  ? "missing.py"
                  : scenario === "deleted-scope-escape"
                    ? "../missing.py"
                    : "source.py",
              ],
            }
          : {}),
        outputDir,
        maxCostUsd: 1,
        ...(native
          ? {
              registeredScan: {
                scanId: f.scanId,
                scanDir: outputDir,
                threadId: owner,
                handoffClaimToken:
                  scenario === "wrong-claim" ? randomUUID() : claim,
              },
            }
          : { resumeScanId: f.scanId }),
        onAuthentication() {
          authentications++;
        },
      });
      if (
        scenario === "managed" ||
        scenario === "native" ||
        scenario === "changed-target" ||
        scenario === "deleted-scope" ||
        scenario === "deleted-scope-native"
      ) {
        const result = await pending;
        expect(result.cost).toEqual(expectedCost);
        expect(result.threadId).toBe(f.threadId);
        expect(result.repositoryFindings).toEqual([]);
        expect(commands).toContain("list-global-findings");
        expect(
          commands.filter((command) => command === "complete-scan"),
        ).toHaveLength(1);
      } else {
        await expect(pending).rejects.toThrow(
          scenario === "deleted-scope-mismatch"
            ? "mismatched scan resume context"
            : scenario === "deleted-scope-escape"
              ? "outside the repository"
              : scenario === "wrong-claim"
                ? "another continuation"
                : scenario === "changed-artifact"
                  ? "Cannot resume sealed scan"
                  : "match its target, directory and mode",
        );
        expect(commands).not.toContain("complete-scan");
      }
      expect(authentications).toBe(0);
      expect(commands).not.toContain("get-scan-feedback");
      expect(
        await Promise.all(
          artifactNames.map((name) => readFile(join(f.scanDir, name))),
        ),
      ).toEqual(artifacts);
    } finally {
      await client.close();
    }
  },
);

test("a sealed native scan binds an absent recipe before returning its verified receipt", async () => {
  const f = await interruptedScan("deep", false, {}, true);
  const cost = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 100,
    output_tokens: 10,
  })!;
  await sealSavedScan(f, cost);
  execFileSync(f.python, [
    "-c",
    `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute("UPDATE scans SET recipe_json = NULL, deep_scan_owner_thread_id = ? WHERE id = ?", sys.argv[2:])
`,
    join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    f.threadId,
    f.scanId,
  ]);
  await using client = resumeClient(f, () => {
    throw new Error("A sealed native scan must not create a model client");
  })({ pluginPath: PLUGIN_ROOT, codexOverrides: f.recipe.config });
  const result = await client.run(f.repository, {
    mode: "deep",
    outputDir: f.scanDir,
    registeredScan: {
      scanId: f.scanId,
      scanDir: f.scanDir,
      threadId: f.threadId,
    },
    ...f.recipe.deepScan,
    requireCost: true,
  });
  expect(result.cost).toEqual(cost);
  expect(result.threadId).toBe(f.threadId);
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["recipe"],
  ).toMatchObject({ repository: f.repository, mode: "deep" });
});

test.each([
  ["dedicated", true],
  ["archived", true],
  ["archived-copy", true],
  ["archived-prefix", true],
  ["live-prefix", true],
  ["unpriced", false],
  ["unpriced", true],
  ["other-directory", false],
  ["other-directory", true],
  ["predates-scan", false],
  ["predates-scan", true],
  ["undated", false],
  ["undated", true],
  ["completed", true],
  ["completed-unpriced", false],
] as const)(
  "sealed Standard recovery attributes only scan-owned sessions (%s, required: %p)",
  async (origin, requireCost) => {
    const f = await interruptedScan(
      "standard",
      false,
      origin === "unpriced" || origin === "completed-unpriced"
        ? { model: "unpriced-synthetic-model" }
        : {},
    );
    const usage = { input_tokens: 1_000_000, output_tokens: 100 };
    const startedAt = (
      await f.command(["get-cli-scan-resume", "--scan-id", f.scanId])
    )["startedAt"] as string;
    await writeFile(
      f.sessionPath,
      [
        {
          type: "session_meta",
          payload: {
            id: f.threadId,
            cwd: origin === "other-directory" ? f.repository : f.scanDir,
            ...(origin === "undated"
              ? {}
              : {
                  timestamp: new Date(
                    Date.parse(startedAt) +
                      (origin === "predates-scan" ? -60_000 : 1),
                  ).toISOString(),
                }),
          },
        },
        tokenUsageEvent(usage),
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );
    const archived = join(f.codexHome, "archived_sessions");
    if (origin.startsWith("archived") || origin === "live-prefix") {
      await mkdir(archived, { recursive: true });
      const contents = await readFile(f.sessionPath, "utf8");
      const metadata = contents.split("\n")[0] + "\n";
      await writeFile(
        join(archived, "saved-session.jsonl"),
        origin === "archived-prefix" ? metadata : contents,
      );
      if (origin === "archived") await rm(f.sessionPath);
      if (origin === "live-prefix") await writeFile(f.sessionPath, metadata);
    }
    await writeDraft(f.command, f.registration, "standard", {
      scanId: f.scanId,
      findings: [],
      coverage: {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      },
    });
    await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    const names = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
    ];
    const artifacts = await Promise.all(
      names.map((name) => readFile(join(f.scanDir, name))),
    );
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    const storedCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 100,
      output_tokens: 10,
    })!;
    const storedUsage = {
      coverage: "complete",
      source: "codex_rollout",
      inputTokens: 100,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 10,
      reasoningOutputTokens: 3,
      totalTokens: 110,
      threadCount: 1,
    };
    await using client = resumeClient(
      f,
      () => {
        throw new Error("Sealed recovery must not invoke Codex");
      },
      async (options, args, input) => {
        const result = await runWorkbench(options, args, input);
        if (
          (origin === "completed" || origin === "completed-unpriced") &&
          args[0] === "get-cli-scan-resume"
        ) {
          // Completion can commit after resume reads its registration.
          await f.command([
            "complete-scan",
            "--scan-id",
            f.scanId,
            "--cost-json",
            JSON.stringify({
              usage: storedUsage,
              ...(origin === "completed" ? { cost: storedCost } : {}),
            }),
          ]);
          await rm(f.sessionPath);
        }
        return result;
      },
    )({ codexOverrides: f.recipe.config });
    const pending = client.run(f.repository, {
      mode: "standard",
      deepScanPass: true,
      outputDir: f.scanDir,
      resumeScanId: f.scanId,
      requireCost,
    });
    const ownsSession = [
      "dedicated",
      "archived",
      "archived-copy",
      "archived-prefix",
      "live-prefix",
    ].includes(origin);
    if (requireCost && !ownsSession && origin !== "completed") {
      await expect(pending).rejects.toThrow("no verified cost receipt");
      expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
        before,
      );
    } else {
      const result = await pending;
      const expectedCost = ownsSession
        ? estimateScanCost("gpt-5.6-sol", usage)
        : origin === "completed"
          ? storedCost
          : null;
      expect(result.cost).toEqual(expectedCost);
      if (origin === "completed" || origin === "completed-unpriced")
        expect(result.turnResult.usage).toEqual({
          input_tokens: 100,
          cached_input_tokens: 0,
          cache_write_input_tokens: 0,
          cache_write_input_tokens_reported: false,
          output_tokens: 10,
          reasoning_output_tokens: 3,
          total_tokens: 110,
        });
      if (origin === "unpriced") {
        expect(result.turnResult.usage).toMatchObject({
          ...usage,
          total_tokens: 1_000_100,
        });
        expect(result.toJSON()).toMatchObject({
          cost: null,
          turn: {
            model: "unpriced-synthetic-model",
            usage: result.turnResult.usage,
          },
        });
      }
      const saved = (await f.command(["get-scan", "--scan-id", f.scanId]))[
        "scan"
      ] as JsonObject;
      expect(saved["progress"]).toMatchObject({ status: "complete" });
      expect<unknown>(saved["cost"] ?? null).toEqual(expectedCost);
    }
    expect(
      await Promise.all(names.map((name) => readFile(join(f.scanDir, name)))),
    ).toEqual(artifacts);
  },
);

test.each(["failed", "missing-checkout", "missing-session", "standard"])(
  "bulk recovery retries an unavailable %s scan without overwriting its attempt",
  async (scenario) => {
    const f = await interruptedScan(
      scenario === "standard" ? "standard" : "deep",
      true,
    );
    if (scenario === "failed")
      await f.command([
        "fail-scan",
        "--scan-id",
        f.scanId,
        "--message",
        "Synthetic failure",
      ]);
    if (scenario === "missing-checkout")
      await rm(f.repository, { recursive: true });
    if (scenario === "missing-session") await rm(f.sessionPath);
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies({
      environment: f.environment,
      currentDirectory: f.root,
    });
    let attempts = 0;
    expect(
      await runCli(
        ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
        {
          ...deps,
          runWorkbench: f.command,
          createSecurity: (config) => ({
            ...deps.createSecurity(config),
            run: async (repository, options = {}) => {
              attempts++;
              expect(options.resumeScanId).toBeUndefined();
              expect(options.mode).toBe(f.recipe.mode);
              expect(options.outputDir).toBe(
                join(f.root, "artifacts", "repo", "attempt-2"),
              );
              expect(repository).toBe(
                join(f.root, "recovery-checkouts", "repo", "attempt-2"),
              );
              expect(
                (
                  await readFile(join(repository, "source.py"), "utf8")
                ).replaceAll("\r\n", "\n"),
              ).toBe("# synthetic source\n");
              return {
                coverage: { completeness: "complete" },
                cost: null,
              } as import("../src/result.js").ScanResult;
            },
          }),
        },
      ),
      stderr.text(),
    ).toBe(0);
    expect(attempts).toBe(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      completed: 1,
      failed: 0,
    });
    expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(
      before,
    );
    expect(await readFile(f.checkpoint, "utf8")).toBe(
      '{"completed":"setup"}\n',
    );
  },
);

test("the public resume command remains limited to Deep scans", async () => {
  const f = await interruptedScan("standard");
  const before = await f.command(["get-scan", "--scan-id", f.scanId]);
  let runs = 0;
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    capture().stream,
    capture().stream,
    {
      ...dependencies({
        environment: f.environment,
        currentDirectory: f.root,
        onRun() {
          runs++;
        },
      }),
      runWorkbench: f.command,
    },
  );
  expect(code).toBe(2);
  expect(runs).toBe(0);
  expect(await f.command(["get-scan", "--scan-id", f.scanId])).toEqual(before);
});

test("resume requires an explicit scan ID", async () => {
  const { stderr, runCli } = createCliTest(main);

  const code = await runCli(["scans", "resume"], {
    ...dependencies(),
    runWorkbench: async () => fail("Must select a scan explicitly"),
  });
  expect(code).toBe(2);
  expect(stderr.text()).toContain("scanId");
});

test("bulk recovery completes a sealed historical attempt without another scan", async () => {
  const f = await interruptedScan("deep", true, {}, false, true, null);
  await writeDraft(f.command, f.registration, "deep", {
    scanId: f.scanId,
    findings: [
      semanticFinding({
        identity: { anchor: "retained-historical" },
        locations: [{ path: "source.py", startLine: 1 }],
      }),
    ],
    coverage: semanticCoverage({ completeness: "partial" }),
  });
  await f.command(
    [
      "save-scan-artifact",
      "--scan-id",
      f.scanId,
      "--artifact-path",
      DEEP_SCAN_CHECKPOINT,
    ],
    JSON.stringify({
      version: 3,
      startedAt: "2026-01-01T00:00:00Z",
      passes: [],
      mergedScanIds: [],
      noNewStreak: 0,
      terminalReason: "capped",
      aggregatePath: null,
    }),
  );
  await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
  await rm(join(f.scanDir, DEEP_SCAN_CHECKPOINT));
  await writeFile(
    f.sessionPath,
    JSON.stringify({
      type: "session_meta",
      payload: { id: f.threadId, cwd: f.scanDir },
    }) + "\n",
  );
  execFileSync(f.python, [
    "-c",
    `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as connection:
    connection.execute(
        "INSERT INTO deep_scan_runs (scan_id, schema_version, workflow_version, "
        "status, phase, workers, subagents, stop_after_no_new, max_discovery_runs, "
        "manifest_path, terminal_reason, created_at, updated_at, completed_at) "
        "VALUES (?, 1, 'recovery-test', 'succeeded', 'terminal', 1, 0, 1, 1, "
        "?, 'saturated', ?, ?, ?)",
        (sys.argv[2], sys.argv[3], *(["2026-01-01T00:00:00Z"] * 3)),
    )
`,
    join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    f.scanId,
    join(f.scanDir, "scan-manifest.json"),
  ]);
  expect(
    await f.command(["get-cli-scan-resume", "--scan-id", f.scanId]),
  ).toMatchObject({
    sealedProducerVersion: expect.any(String),
    threadId: f.threadId,
  });
  const names = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const before = await Promise.all(
    names.map((name) => readFile(join(f.scanDir, name))),
  );
  const createClient = resumeClient(f, () => {
    throw new Error("Sealed recovery must not create a model client.");
  });
  const requests: (string | undefined)[] = [];
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity(config) {
        const client = createClient({ ...config, pluginPath: PLUGIN_ROOT });
        return {
          preflight: (options) => client.preflight(options),
          close: () => client.close(),
          async run(repository, options = {}) {
            requests.push(options.resumeScanId);
            expect(options.outputDir).toBe(f.scanDir);
            return client.run(repository, options);
          },
        };
      },
    },
  );
  expect(requests, stderr.text()).toEqual([f.scanId]);
  expect(code, stderr.text()).toBe(2);
  const result = JSON.parse(stdout.text());
  const savedResults = await readFile(result.resultsPath, "utf8");
  expect(result, savedResults).toMatchObject({ incomplete: 1, failed: 0 });
  const receipts = savedResults
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(receipts).toHaveLength(2);
  expect(receipts[1]).toMatchObject({
    attempt: 1,
    outputDir: f.scanDir,
    status: "completed_with_incomplete_coverage",
  });
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "complete" }, findingCount: 1 });
  expect(
    (await f.command(["list-scans", "--repository", f.repository]))["scans"],
  ).toHaveLength(1);
  expect(
    await Promise.all(names.map((name) => readFile(join(f.scanDir, name)))),
  ).toEqual(before);
});

test("resumed Bedrock scans retain provider context for the account advisory", async () => {
  const f = await interruptedScan(
    "deep",
    false,
    { modelProvider: "amazon-bedrock" },
    false,
    true,
    null,
  );
  const stdout = capture();
  const stderr = capture();
  let parentResumed = false;
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: resumeClient(f, (options) => {
        expect(options.env).toMatchObject({ AWS_PROFILE: "synthetic-bedrock" });
        expect(options.apiKey).toBeUndefined();
        const thread = (id: string) => ({
          id,
          async runStreamed(prompt: string) {
            expect(prompt).toContain("Amazon Bedrock with AWS authentication");
            expect(prompt).toContain(
              "Skip the ChatGPT account Daybreak access advisory",
            );
            throw new ScanTransportClosedError(
              "Resumed Bedrock prompt captured",
            );
          },
        });
        return {
          startThread: () => thread("synthetic-bedrock-child"),
          resumeThread(threadId) {
            expect(threadId).toBe(f.threadId);
            parentResumed = true;
            return thread(threadId);
          },
        };
      }),
    },
  );
  expect(code).not.toBe(0);
  expect(parentResumed).toBe(true);
  expect(stderr.text()).toContain("Resumed Bedrock prompt captured");
  expect(stderr.text()).toContain(`scans show ${f.scanId}`);
  expect(stderr.text()).toContain(`scans logs ${f.scanId}`);
});

test("resuming Deep Scan includes archived spending before starting another turn", async () => {
  const f = await interruptedScan(
    "deep",
    false,
    { maxCostUsd: 0.000001 },
    false,
    true,
    {
      cost: estimateScanCost("gpt-5.6-sol", {
        input_tokens: 0,
        output_tokens: 0,
      })!,
    },
  );
  await appendFile(
    f.sessionPath,
    JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 10000, output_tokens: 2000 },
        },
      },
    }) + "\n",
  );
  const archived = join(f.codexHome, "archived_sessions");
  await mkdir(archived);
  await rename(f.sessionPath, join(archived, "root.jsonl"));
  const stdout = capture();
  const stderr = capture();
  let turns = 0;
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({
        environment: f.environment,
        currentDirectory: f.root,
      }),
      runWorkbench: f.command,
      createSecurity: resumeClient(f, () => ({
        startThread() {
          throw new Error("Resume must preserve the owning thread.");
        },
        resumeThread(threadId) {
          expect(threadId).toBe(f.threadId);
          return {
            id: threadId,
            async runStreamed() {
              turns++;
              throw new Error(
                "Synthetic turn started despite archived spending.",
              );
            },
          };
        },
      })),
    },
  );
  expect(code).not.toBe(0);
  expect(turns).toBe(0);
  expect(stderr.text()).toContain("exceeded the $0.000001 limit");
});

test.each([
  {
    mode: "deep",
    location: "scan",
    beforeScan: false,
    receipt: true,
    tokens: 10,
  },
  {
    mode: "standard",
    location: "repository",
    beforeScan: false,
    receipt: true,
    tokens: 1_000_000,
  },
  {
    mode: "standard",
    location: "scan",
    beforeScan: true,
    receipt: true,
    tokens: 1_000_000,
  },
  {
    mode: "standard",
    location: "repository",
    beforeScan: false,
    receipt: false,
    tokens: 1_000_000,
  },
  {
    mode: "standard",
    location: "scan",
    beforeScan: true,
    receipt: false,
    tokens: 1_000_000,
  },
  {
    mode: "standard",
    location: "scan",
    beforeScan: false,
    receipt: false,
    tokens: 100,
  },
  {
    mode: "deep",
    location: "scan",
    beforeScan: false,
    receipt: false,
    tokens: 100,
  },
] as const)(
  "sealed recovery uses scan-owned accounting: %p",
  async ({ mode, location, beforeScan, receipt, tokens }) => {
    const f = await interruptedScan(mode);
    const cost = {
      model: f.recipe.config.model as string,
      inputTokens: 100,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 10,
      estimatedUsd: 0.125,
    };
    const saved = await f.command(["get-scan", "--scan-id", f.scanId]);
    const scan = saved["scan"] as import("../src/config.js").JsonObject;
    await writeFile(
      f.sessionPath,
      [
        {
          type: "session_meta",
          payload: {
            id: f.threadId,
            cwd: location === "scan" ? f.scanDir : f.repository,
            timestamp: beforeScan
              ? "2026-10-01T00:00:00Z"
              : "2026-10-01T02:00:00Z",
          },
        },
        {
          type: "event_msg",
          payload: {
            type: "token_count",
            info: {
              total_token_usage: { input_tokens: tokens, output_tokens: 1 },
            },
          },
        },
      ]
        .map((event) => JSON.stringify(event))
        .join("\n") + "\n",
    );
    const context = {
      scanId: f.scanId,
      scanDir: f.scanDir,
      codexHome: f.codexHome,
      model: f.recipe.config.model as string,
      startedAt: "2026-10-01T01:00:00Z",
      checkpoint: null,
      expectation: {
        repository: f.repository,
        repositoryRevision: null,
        target: { kind: "repository" as const, paths: [] },
        mode,
        pluginVersion: "0.1.0",
      },
      signal: new AbortController().signal,
      workbench: async (args: readonly string[]) =>
        args[0] === "get-scan"
          ? {
              ...saved,
              scan: {
                ...scan,
                ...(receipt
                  ? {
                      progress: { status: "complete" },
                      usage: {
                        coverage: "complete",
                        inputTokens: cost.inputTokens,
                        cachedInputTokens: cost.cachedInputTokens,
                        cacheWriteInputTokens: cost.cacheWriteInputTokens,
                        outputTokens: cost.outputTokens,
                      },
                    }
                  : {}),
                cost: receipt ? cost : null,
              },
            }
          : f.command(args),
      onTrackingError: (error: unknown) => {
        throw error;
      },
      onCost: () => {},
    };
    const recovered = await readSealedScanTurn(context);
    if (receipt) {
      expect(recovered.cost).toEqual(cost);
      expect(recovered.turnResult.usage).toMatchObject({
        input_tokens: cost.inputTokens,
      });
      expect(formatTokenUsage(recovered.turnResult.usage)).toContain(
        "110 total",
      );
    } else if (mode === "standard" && location === "scan" && !beforeScan) {
      expect(recovered.cost?.inputTokens).toBe(tokens);
      expect(recovered.turnResult.usage).toMatchObject({
        input_tokens: tokens,
      });
    } else {
      expect(recovered.cost).toBeNull();
      expect(recovered.turnResult.usage).toBeNull();
      await expect(
        readSealedScanTurn({ ...context, maxCostUsd: 1 }),
      ).rejects.toThrow("no verified cost receipt");
    }
  },
);

test.each([
  { coverage: "complete", priced: true },
  { coverage: "complete", priced: false },
  { coverage: "partial", priced: true },
])(
  "sealed token summary normalizes saved receipts (%p)",
  async ({ coverage, priced }) => {
    const cost = priced
      ? estimateScanCost("gpt-6-astra", {
          input_tokens: 100,
          cached_input_tokens: 20,
          cache_write_input_tokens: 10,
          output_tokens: 30,
        })!
      : null;
    const recovered = await readSealedScanTurn({
      scanId: "synthetic-scan",
      scanDir: "/synthetic/scan",
      codexHome: "/synthetic/home",
      model: "gpt-6-astra",
      startedAt: "2026-10-01T01:00:00Z",
      checkpoint: null,
      expectation: {
        repository: "/synthetic/repository",
        repositoryRevision: null,
        target: { kind: "repository", paths: [] },
        mode: "deep",
        pluginVersion: "0.1.0",
      },
      signal: new AbortController().signal,
      workbench: async () => ({
        scan: {
          progress: { status: "complete" },
          cost: JSON.parse(JSON.stringify(cost)),
          usage: {
            coverage,
            inputTokens: coverage === "complete" ? 100 : 1,
            cachedInputTokens: coverage === "complete" ? 20 : 0,
            cacheWriteInputTokens: coverage === "complete" ? 10 : 0,
            outputTokens: coverage === "complete" ? 30 : 1,
          },
        },
      }),
      onTrackingError: (error) => {
        throw error;
      },
      onCost() {},
    });
    expect(recovered.turnResult.usage).toMatchObject({
      input_tokens: 100,
      cached_input_tokens: 20,
      cache_write_input_tokens: 10,
      output_tokens: 30,
    });
    expect(formatTokenUsage(recovered.turnResult.usage)).toBe(
      priced
        ? "70 uncached input, 20 cache reads, 10 cache writes, 30 output, 130 total"
        : "unavailable uncached input, 20 cache reads, unavailable cache writes, 30 output, 130 total",
    );
  },
);

test.each([
  {
    bulk: false,
    missingHome: false,
    keepProfile: true,
    interactive: true,
    publicationOnly: true,
  },
  { bulk: false, missingHome: false, keepProfile: true, publicationOnly: true },
  { bulk: false, missingHome: true, publicationOnly: true },
  { bulk: true, missingHome: false, publicationOnly: true },
  {
    bulk: true,
    missingHome: true,
    savedPrompt: "",
    fallbackPrompt: "Synthetic bulk follow-up",
    publicationOnly: true,
  },
  {
    bulk: true,
    missingHome: true,
    savedPrompt: " \n",
    fallbackPrompt: "Synthetic bulk follow-up",
    publicationOnly: true,
  },
  {
    bulk: false,
    missingHome: true,
    savedPrompt: "Synthetic saved follow-up",
    publicationOnly: false,
  },
  {
    bulk: true,
    missingHome: true,
    fallbackPrompt: "Synthetic bulk follow-up",
    publicationOnly: false,
  },
  {
    bulk: true,
    missingHome: true,
    savedPrompt: "Synthetic saved follow-up",
    fallbackPrompt: "",
    publicationOnly: false,
  },
  { bulk: false, missingHome: true, rerun: true, publicationOnly: false },
  { bulk: false, missingHome: true, unsealed: true, publicationOnly: false },
] as {
  bulk: boolean;
  missingHome: boolean;
  keepProfile?: boolean;
  interactive?: boolean;
  savedPrompt?: string;
  fallbackPrompt?: string;
  rerun?: boolean;
  unsealed?: boolean;
  publicationOnly: boolean;
}[])(
  "sealed CLI recovery only requires private replay configuration for execution %j",
  async ({
    bulk,
    missingHome,
    keepProfile,
    interactive,
    savedPrompt,
    fallbackPrompt,
    rerun,
    unsealed,
    publicationOnly,
  }) => {
    const childCost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 375,
      output_tokens: 3,
    })!;
    const cost = {
      ...estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1375,
        output_tokens: 13,
      })!,
      estimatedUsd: 0.125,
    };
    const f = await interruptedScan("deep", bulk, {}, true, true, {
      cost: childCost,
    });
    const home = join(f.root, "private-replay-home");
    await mkdir(home, { mode: 0o700 });
    const profile = await createProviderProfile(home, {
      model_providers: {
        synthetic: {
          name: "Synthetic",
          wire_api: "responses",
          http_headers: { Authorization: "synthetic-private-replay-token" },
          auth: {
            command: "synthetic-unused-auth",
            args: ["synthetic-private-argument"],
          },
        },
      },
    });
    const recipe = {
      ...f.recipe,
      auth: interactive ? "auto" : "api-key",
      config: {
        ...(f.recipe.config as JsonObject),
        model_provider: "synthetic",
      },
      providerProfile: { name: profile.name, home: "ambient" },
      ...(savedPrompt === undefined ? {} : { postScanPrompt: savedPrompt }),
    };
    execFileSync(f.python, [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE scans SET recipe_json=? WHERE id=?',(sys.argv[2],sys.argv[3])); c.commit()",
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      JSON.stringify(recipe),
      f.scanId,
    ]);
    if (!unsealed) await sealSavedScan(f, cost);
    const saved = await f.command([
      "get-cli-scan-resume",
      "--scan-id",
      f.scanId,
    ]);
    expect(typeof saved["sealedProducerVersion"]).toBe(
      unsealed ? "undefined" : "string",
    );
    const names = [
      ...(unsealed
        ? []
        : [
            "scan-manifest.json",
            "findings.json",
            "coverage.json",
            "report.md",
          ]),
      DEEP_SCAN_CHECKPOINT,
    ];
    const before = await Promise.all(
      names.map((name) => readFile(join(f.scanDir, name))),
    );
    f.environment.CODEX_HOME = home;
    if (missingHome) await rm(home, { recursive: true });
    else if (!keepProfile) await rm(profile.path);
    const promptFile = join(f.root, "post-scan.md");
    if (fallbackPrompt !== undefined)
      await writeFile(promptFile, fallbackPrompt);
    if (bulk && fallbackPrompt?.trim()) {
      const manifestPath = join(f.root, "manifest.json");
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      manifest.postScanPrompt = fallbackPrompt;
      await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
    }
    const instructionFile = join(f.root, "original-instructions.md");
    if (rerun)
      await writeFile(instructionFile, "Keep the original scan instructions.");
    const stdout = capture(),
      stderr = capture();
    if (interactive) {
      Object.assign(stderr.stream, { isTTY: true });
      f.environment.OPENAI_API_KEY = "synthetic-unused-key";
    }
    let authenticationChecks = 0;
    const requests: (string | undefined)[] = [];
    let runtimeStarts = 0;
    const code = await main(
      bulk
        ? [
            "bulk-scan",
            f.input,
            "--output-dir",
            f.root,
            "--recover",
            "--json",
            ...(fallbackPrompt === undefined
              ? []
              : ["--post-scan-prompt-file", promptFile]),
          ]
        : [
            "scans",
            rerun ? "rerun" : "resume",
            f.scanId,
            "--json",
            ...(rerun ? ["--scan-prompt-file", instructionFile] : []),
          ],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        hasStoredChatGPTSignIn: async () => {
          authenticationChecks++;
          throw new Error("Publication must not inspect stored authentication");
        },
        scanAuthenticationPrompt: {
          isInteractive: () => true,
          select: async () => {
            authenticationChecks++;
            throw new Error("Publication must not request authentication");
          },
        },
        createSecurity(config) {
          const client = new TestClient(
            { ...config, pluginPath: PLUGIN_ROOT, pythonPath: f.python },
            {
              environment: f.environment,
              resolvePluginPython: async () => f.python,
              prepareRuntime: async () => {
                runtimeStarts++;
                throw new Error("Publication must not prepare a model runtime");
              },
              createCodex: () => {
                runtimeStarts++;
                throw new Error("Publication must not create a model client");
              },
              runWorkbench,
            },
          );
          return {
            preflight: (...args: Parameters<TestClient["preflight"]>) =>
              client.preflight(...args),
            close: () => client.close(),
            run: async (repository: string, options: ScanOptions = {}) => {
              requests.push(options.resumeScanId);
              return client.run(repository, options);
            },
          };
        },
      },
    );
    expect(code, stderr.text()).toBe(2);
    expect(runtimeStarts).toBe(0);
    expect(authenticationChecks).toBe(0);
    expect(requests).toEqual(publicationOnly ? [f.scanId] : []);
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: publicationOnly ? "complete" : "running" },
    });
    if (!publicationOnly)
      expect(stdout.text() + stderr.text()).toContain("ENOENT");
    if (publicationOnly && bulk) {
      const result = JSON.parse(stdout.text());
      expect(result).toMatchObject({ incomplete: 1, failed: 0 });
      const receipts = (await readFile(result.resultsPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(receipts).toHaveLength(2);
      expect(receipts[1]).toMatchObject({ attempt: 1, outputDir: f.scanDir });
    }
    expect(
      await Promise.all(names.map((name) => readFile(join(f.scanDir, name)))),
    ).toEqual(before);
  },
);

test.each([
  "accept",
  "choose-auth",
  "cancel-auth",
  "decline",
  "cancel",
  "empty",
  "missing",
] as const)(
  "sealed resume restores private execution settings only for selected patches (%s)",
  async (selection) => {
    const chooseAuthentication =
      selection === "choose-auth" || selection === "cancel-auth";
    const patchStarts = selection === "accept" || selection === "choose-auth";
    const findings = [
      semanticFinding({ locations: [{ path: "source.py", startLine: 1 }] }),
    ];
    const cost = estimateScanCost("gpt-5.6-sol", {
      input_tokens: 375,
      output_tokens: 3,
    })!;
    const f = await interruptedScan("deep", false, {}, false, true, {
      findings,
      coverage: semanticCoverage(),
      cost,
    });
    await writeDraft(f.command, f.registration, "deep", {
      scanId: f.scanId,
      findings,
      coverage: semanticCoverage(),
    });
    const checkpoint = JSON.parse(
      await readFile(join(f.scanDir, DEEP_SCAN_CHECKPOINT), "utf8"),
    );
    await f.command(
      [
        "save-scan-artifact",
        "--scan-id",
        f.scanId,
        "--artifact-path",
        DEEP_SCAN_CHECKPOINT,
      ],
      JSON.stringify({
        ...checkpoint,
        terminalReason: "capped",
        finalCost: cost,
      }),
    );
    const home = join(f.root, "private-replay-home");
    await mkdir(home, { mode: 0o700 });
    const provider = {
      name: "Synthetic",
      wire_api: "responses",
      base_url: "https://provider.example.test/v1",
      ...(chooseAuthentication
        ? { requires_openai_auth: true }
        : { auth: { command: ["synthetic-credential-command"] } }),
      http_headers: { Authorization: "synthetic-private-patch-token" },
    };
    const profile = await createProviderProfile(home, {
      model_providers: { synthetic: provider },
    });
    const recipe = {
      ...f.recipe,
      auth: selection === "accept" ? "api-key" : "auto",
      config: {
        ...f.recipe.config,
        model_provider: "synthetic",
        model_reasoning_effort: "high",
        service_tier: "priority",
        analytics: { enabled: false },
      },
      providerProfile: { name: profile.name, home: "ambient" },
    };
    execFileSync(f.python, [
      "-c",
      "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE scans SET recipe_json=? WHERE id=?',(sys.argv[2],sys.argv[3])); c.commit()",
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      JSON.stringify(recipe),
      f.scanId,
    ]);
    await f.command(["prepare-scan-completion", "--scan-id", f.scanId]);
    f.environment.CODEX_HOME = home;
    Object.assign(f.environment, {
      OPENAI_API_KEY: "synthetic-optional-patch-key",
    });
    if (!patchStarts && !chooseAuthentication) await rm(profile.path);
    const files = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
      DEEP_SCAN_CHECKPOINT,
    ];
    const before = await Promise.all(
      files.map((name) => readFile(join(f.scanDir, name))),
    );
    const stdout = capture(),
      stderr = capture(true);
    const patchConfigurations: unknown[] = [];
    const patchAuthentication: unknown[] = [];
    let authenticationChecks = 0;
    let authenticationChoices = 0;
    let prompted = false;
    let runtimeStarts = 0;
    const code = await main(
      ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
          onCodex(_args, output) {
            patchConfigurations.push(output?.codexOverrides);
            patchAuthentication.push(output?.auth);
            return 1;
          },
        }),
        runWorkbench: f.command,
        hasStoredChatGPTSignIn: async () => {
          authenticationChecks++;
          expect(prompted).toBe(true);
          expect(
            (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
          ).toMatchObject({ progress: { status: "complete" } });
          return true;
        },
        scanAuthenticationPrompt: {
          isInteractive: () => true,
          async select(_question, choices) {
            authenticationChoices++;
            expect(prompted).toBe(true);
            if (selection === "cancel-auth")
              throw Object.assign(
                new Error("Synthetic authentication choice canceled"),
                { name: "ExitPromptError" },
              );
            return choices.find(({ value }) => value === "chatgpt")!.value;
          },
        },
        confirmPatchReview: async () => {
          prompted = true;
          expect(
            (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
          ).toMatchObject({ progress: { status: "complete" } });
          return selection !== "decline";
        },
        patchEditor: async (_repository, findings) =>
          selection === "cancel"
            ? null
            : {
                severity: "high",
                occurrenceIds:
                  selection === "empty"
                    ? []
                    : findings.map((finding) => finding.occurrenceId),
              },
        createSecurity(config) {
          const client = new TestClient(
            { ...config, pluginPath: PLUGIN_ROOT, pythonPath: f.python },
            {
              environment: f.environment,
              resolvePluginPython: async () => f.python,
              prepareRuntime: async () => {
                runtimeStarts++;
                throw new Error("Publication must not prepare a model runtime");
              },
              createCodex: () => {
                runtimeStarts++;
                throw new Error("Publication must not create a model client");
              },
              runWorkbench,
            },
          );
          return client;
        },
      },
    );
    expect(prompted, stderr.text()).toBe(true);
    expect(runtimeStarts).toBe(0);
    expect(authenticationChecks).toBe(chooseAuthentication ? 1 : 0);
    expect(authenticationChoices).toBe(chooseAuthentication ? 1 : 0);
    expect(patchConfigurations).toHaveLength(patchStarts ? 1 : 0);
    expect(patchAuthentication).toEqual(
      patchStarts ? [selection === "choose-auth" ? "chatgpt" : "api-key"] : [],
    );
    if (patchStarts) {
      expect(patchConfigurations[0]).toMatchObject({
        model: (recipe.config as JsonObject)["model"],
        model_reasoning_effort: "high",
        service_tier: "priority",
        analytics: { enabled: false },
        model_provider: "synthetic",
        model_providers: { synthetic: provider },
      });
    } else if (selection === "cancel-auth") {
      expect(code).toBe(2);
      expect(stderr.text()).toContain(
        "Synthetic authentication choice canceled",
      );
    } else if (selection === "missing") {
      expect(code).toBe(2);
      expect(stderr.text()).toContain("ENOENT");
    } else expect(code, stderr.text()).toBe(0);
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({ progress: { status: "complete" } });
    expect(
      await Promise.all(files.map((name) => readFile(join(f.scanDir, name)))),
    ).toEqual(before);
  },
);
