import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  appendFile,
  cp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { ScanOptions } from "../src/api.js";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost, type ScanCost } from "../src/cost.js";
import {
  DEEP_SCAN_CHECKPOINT,
  type DeepScanCheckpoint,
} from "../src/deep-scan.js";
import type { SemanticScan } from "../src/scan-semantics.js";
import {
  publishScan,
  writeSemanticScanDraft,
} from "../src/scan-publication.js";
import { prepareScanArtifactRestorer, runWorkbench } from "../src/runtime.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { semanticCoverage, semanticFinding } from "./helpers/semantic-scan.js";
import { TestClient } from "./support/api-client.js";
import { tokenUsageEvent } from "./support/usage-rollout.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime as fixtureRuntime,
} from "./support/api-events.js";

const PLUGIN_ROOT = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);

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
    | "maxCostUsd"
    | "safetyIdentifier"
    | "postScanPrompt"
    | "auth"
    | "inheritedPermissions"
    | "preserveProviderEnvironment"
  > & { model?: string; scopedPaths?: string[] } = {},
  resolvedDeep = false,
  startedMerge = true,
  ordinaryPass: {
    cost?: ScanCost;
    findings?: SemanticScan["findings"];
    coverage?: SemanticScan["coverage"];
  } | null = {},
) {
  const { model = "gpt-5.6-sol", scopedPaths, ...scanSettings } = settings;
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
  await mkdir(join(codexHome, "sessions"), { recursive: true });
  await writeFile(join(repository, "source.py"), "# synthetic source\n");
  const input = join(root, "repositories.csv");
  if (bulk) {
    const git = (...args: string[]) =>
      execFileSync("git", ["-C", repository, ...args], {
        encoding: "utf8",
      }).trim();
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
      JSON.stringify({ version: 1, tasks: [task] }, null, 2) + "\n",
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
    ...(settings.safetyIdentifier === undefined
      ? {}
      : { OPENAI_API_KEY: "synthetic-resume-key" }),
  };
  const command = (args: readonly string[], input?: string) =>
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
  const recipe = {
    repository,
    target: {
      kind: scopedPaths ? "paths" : "repository",
      paths: scopedPaths ?? [],
    },
    mode,
    config: {
      model,
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
  "first-export",
  "partial-first-export",
  "invalid-manifest",
  "file-authored-result",
] as const)(
  "SDK completion preserves the latest committed or authored draft (%s)",
  async (scenario) => {
    const f = await interruptedScan("standard");
    const provisional: SemanticScan = {
      scanId: f.scanId,
      complete: false,
      findings: [],
      coverage: {
        completeness: "partial",
        surfaces: [],
        explicitExclusions: [],
        deferred: [{ id: "unfinished", reason: "Synthetic unfinished work" }],
      },
    };
    await writeDraft(f.command, f.registration, "standard", provisional);
    const oldManifest = await readFile(join(f.scanDir, "scan-manifest.json"));
    const oldCoverage = await readFile(join(f.scanDir, "coverage.json"));
    if (scenario !== "file-authored-result") {
      await writeDraft(f.command, f.registration, "standard", {
        ...provisional,
        complete: true,
        coverage: {
          ...provisional.coverage,
          completeness: "complete",
          deferred: [],
        },
      });
      // Reproduce failure after findings export but before coverage and manifest.
      await writeFile(join(f.scanDir, "coverage.json"), oldCoverage);
      await writeFile(join(f.scanDir, "scan-manifest.json"), oldManifest);
      if (scenario === "first-export" || scenario === "partial-first-export") {
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
      manifest.scan.complete = true;
      const coverage = JSON.parse(oldCoverage.toString());
      coverage.completeness = "complete";
      coverage.deferred = [];
      await writeFile(
        join(f.scanDir, "coverage.json"),
        JSON.stringify(coverage),
      );
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
    await mkdir(codexHome, { recursive: true });
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
    const command = (args: readonly string[], input?: string) =>
      runWorkbench(
        { python, pluginRoot: PLUGIN_ROOT, environment },
        args,
        input,
      );
    const stdout = capture();
    const stderr = capture();
    const code = await main(
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
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({ environment, currentDirectory: root }),
        runWorkbench: command,
        createSecurity: (config) =>
          new TestClient(config, {
            environment,
            prepareRuntime: async () => preparedRuntime(codexHome),
            resolvePluginPython: async () => python,
            runWorkbench,
            createCodex: () => {
              throw new Error("Synthetic stop after registration");
            },
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
    const settings = {
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
    const stdout = capture();
    const stderr = capture();
    const code = await main(
      bulk
        ? ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"]
        : ["scans", "resume", f.scanId, "--json"],
      stdout.stream,
      stderr.stream,
      {
        ...dependencies({
          environment: f.environment,
          currentDirectory: f.root,
        }),
        runWorkbench: f.command,
        createSecurity: resumeClient(f, (options) => {
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

test("missing session logs do not create another session or fail the original scan", async () => {
  const f = await interruptedScan();
  await rm(f.sessionPath);
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["scans", "resume", f.scanId],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: resumeClient(f, () => {
        throw new Error("Must not invoke Codex without the original session");
      }),
    },
  );
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
                preserveProviderEnvironment: false,
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
        expect(result.turnResult.usage).toEqual(storedUsage);
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
    const stdout = capture();
    const stderr = capture();
    const deps = dependencies({
      environment: f.environment,
      currentDirectory: f.root,
    });
    let attempts = 0;
    expect(
      await main(
        ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
        stdout.stream,
        stderr.stream,
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
  const stdout = capture();
  const stderr = capture();
  const code = await main(["scans", "resume"], stdout.stream, stderr.stream, {
    ...dependencies(),
    runWorkbench: async () => {
      throw new Error("Must select a scan explicitly");
    },
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
