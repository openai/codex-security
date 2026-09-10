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
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import type { ScanOptions } from "../src/api.js";
import { runWorkbench } from "../src/runtime.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { TestClient } from "./support/api-client.js";
import {
  completedEvents,
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

async function interruptedScan(
  mode: "deep" | "standard" = "deep",
  bulk = false,
  settings: Pick<
    ScanOptions,
    "auth" | "safetyIdentifier" | "postScanPrompt"
  > = {},
) {
  const root = await temporaryDirectory();
  const repository = bulk
    ? join(root, "checkouts", "repo")
    : join(root, "repository");
  const scanDir = bulk
    ? join(root, "artifacts", "repo", "attempt-1")
    : join(root, "scan");
  const codexHome = join(root, "state", "codex-home");
  await mkdir(repository, { recursive: true });
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
    await cp(repository, source, { recursive: true });
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
    ...(settings.safetyIdentifier === undefined && settings.auth === undefined
      ? {}
      : { OPENAI_API_KEY: "synthetic-resume-key" }),
  };
  const command = (args: readonly string[], input?: string) =>
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
  const recipe = {
    repository,
    target: { kind: "repository", paths: [] },
    mode,
    config: { model: "gpt-5.6-sol", approval_policy: "never" },
    pluginVersion: "0.1.0",
    ...settings,
    ...(mode === "deep"
      ? { deepScan: { workers: 2, maxDiscoveryRuns: 5 } }
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
      payload: { id: threadId, cwd: scanDir },
    }) + "\n",
  );
  if (mode === "deep") {
    await command([
      "begin-deep-scan",
      "--scan-id",
      scanId,
      "--thread-id",
      threadId,
      "--available-parallelism",
      "4",
      "--workflow-version",
      "deep-scan-mcp/v1",
    ]);
    const workerId = randomUUID();
    const prompt = join(scanDir, "setup-prompt.md");
    await writeFile(prompt, "Saved setup prompt.\n");
    for (const status of ["running", "succeeded"]) {
      await command([
        "upsert-deep-scan-worker",
        "--scan-id",
        scanId,
        "--worker-id",
        workerId,
        "--kind",
        "setup",
        "--status",
        status,
        "--prompt-path",
        prompt,
        "--artifact-dir",
        scanDir,
      ]);
    }
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
  };
}

test("resume resolves an interrupted scan without changing its ID, recipe, or completed workers", async () => {
  const f = await interruptedScan();
  const before = await f.command([
    "get-deep-scan",
    "--scan-id",
    f.scanId,
    "--thread-id",
    f.threadId,
  ]);
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
  expect(
    await f.command([
      "get-deep-scan",
      "--scan-id",
      f.scanId,
      "--thread-id",
      f.threadId,
    ]),
  ).toEqual(before);
  expect(await readFile(f.checkpoint, "utf8")).toBe('{"completed":"setup"}\n');
});

test.each([
  "failed",
  "canceled",
  "standard",
  "changed",
  "replaced",
  "wrong-owner",
])(
  "resume refuses %s scans without altering their saved state",
  async (scenario) => {
    const f = await interruptedScan(
      scenario === "standard" ? "standard" : "deep",
    );
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
    if (scenario === "wrong-owner")
      await f.command([
        "set-scan-thread",
        "--scan-id",
        f.scanId,
        "--thread-id",
        randomUUID(),
      ]);
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    expect(
      await f.command([
        "get-cli-scan-resume",
        "--scan-id",
        f.scanId,
        "--allow-unavailable",
      ]),
    ).toMatchObject({ unavailable: expect.any(String) });
    await expect(
      f.command(["get-cli-scan-resume", "--scan-id", f.scanId]),
    ).rejects.toThrow(
      scenario === "changed"
        ? "revision or contents changed"
        : scenario === "replaced"
          ? "checkout is missing or was replaced"
          : scenario === "wrong-owner"
            ? "original owning CLI session"
            : scenario === "standard"
              ? "Deep Scan with a saved CLI launch recipe"
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

test("CLI resumes the owning Codex thread and preserves running state on a transport failure", async () => {
  const f = await interruptedScan();
  const before = await f.command([
    "get-deep-scan",
    "--scan-id",
    f.scanId,
    "--thread-id",
    f.threadId,
  ]);
  let resumedThread: string | undefined;
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["scans", "resume", f.scanId, "--json"],
    stdout.stream,
    stderr.stream,
    {
      ...dependencies({ environment: f.environment, currentDirectory: f.root }),
      runWorkbench: f.command,
      createSecurity: (config) =>
        new TestClient(config, {
          environment: f.environment,
          prepareRuntime: async () => preparedRuntime(f.codexHome),
          resolvePluginPython: async () => f.python,
          runWorkbench,
          createCodex: (options) => ({
            startThread() {
              throw new Error("Resume must not create a new thread.");
            },
            resumeThread(threadId, threadOptions) {
              resumedThread = threadId;
              expect(threadOptions.workingDirectory).toBe(f.scanDir);
              expect(options.env).toMatchObject({
                CODEX_SECURITY_SCAN_ID: f.scanId,
                CODEX_SECURITY_SCAN_DIR: f.scanDir,
              });
              return {
                id: threadId,
                async runStreamed(prompt) {
                  expect(prompt).toContain(f.scanId);
                  expect(prompt).toContain(
                    "Keep the original scan instructions.",
                  );
                  const joined = await f.command([
                    "begin-deep-scan",
                    "--scan-id",
                    f.scanId,
                    "--thread-id",
                    threadId,
                    "--available-parallelism",
                    "4",
                  ]);
                  expect(joined["deepScan"]).toMatchObject({
                    scanId: f.scanId,
                  });
                  throw new Error("Synthetic transport disconnected");
                },
              };
            },
          }),
        }),
    },
  );
  expect(stderr.text()).toContain("Synthetic transport disconnected");
  expect(code).not.toBe(0);
  expect(resumedThread).toBe(f.threadId);
  expect(
    await f.command([
      "get-deep-scan",
      "--scan-id",
      f.scanId,
      "--thread-id",
      f.threadId,
    ]),
  ).toEqual(before);
  expect(
    (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
  ).toMatchObject({ progress: { status: "running" } });
  expect(await readFile(f.checkpoint, "utf8")).toBe('{"completed":"setup"}\n');
});

function resumeClient(
  f: Awaited<ReturnType<typeof interruptedScan>>,
  createCodex: NonNullable<
    ConstructorParameters<typeof TestClient>[1]["createCodex"]
  >,
) {
  return (config: ConstructorParameters<typeof TestClient>[0]) =>
    new TestClient(config, {
      environment: f.environment,
      prepareRuntime: async () => {
        const runtime = preparedRuntime(f.codexHome);
        runtime.plugin.version = JSON.parse(
          await readFile(
            join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"),
            "utf8",
          ),
        ).version;
        return runtime;
      },
      resolvePluginPython: async () => f.python,
      runWorkbench,
      createCodex,
    });
}

async function finishDiscovery(f: Awaited<ReturnType<typeof interruptedScan>>) {
  // Advance the persisted clock to exercise a coordinator reaching its time cap.
  const expired = Bun.spawnSync(
    [
      f.python,
      "-I",
      "-B",
      "-c",
      "import sqlite3, sys; c = sqlite3.connect(sys.argv[1]); c.execute(\"UPDATE deep_scan_runs SET created_at = '2000-01-01T00:00:00+00:00' WHERE scan_id = ?\", (sys.argv[2],)); c.commit()",
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      f.scanId,
    ],
    { stdout: "pipe", stderr: "pipe" },
  );
  expect(expired.exitCode, new TextDecoder().decode(expired.stderr)).toBe(0);
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), f.scanDir, {
    recursive: true,
  });
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    const path = join(f.scanDir, name);
    const doc = JSON.parse(await readFile(path, "utf8"));
    if (name === "scan-manifest.json") {
      doc.scan.id = f.scanId;
      const contract = f.registration["contract"] as {
        target: { allowedKinds: string[] };
      };
      doc.scan.target = { kind: contract.target.allowedKinds[0] };
      delete doc.scan.sealedAt;
      delete doc.scan.artifacts;
    } else {
      doc.scanId = f.scanId;
      if (name === "findings.json") doc.findings = [];
      else {
        doc.mode = "deep_repository";
        doc.completeness = "partial";
        doc.surfaces = [];
        doc.deferred = [{ id: "time_cap", reason: "Synthetic time cap" }];
      }
    }
    await writeFile(path, JSON.stringify(doc) + "\n");
  }
  await f.command([
    "finish-deep-scan",
    "--scan-id",
    f.scanId,
    "--terminal-reason",
    "capped",
    "--manifest-path",
    join(f.scanDir, "scan-manifest.json"),
  ]);
}

test.each([
  [false, false],
  [true, false],
  [false, true],
  [true, true],
])(
  "resumed CLI seals the original scan (coordinator finished: %s, bulk: %s)",
  async (alreadyFinished, bulk) => {
    const f = await interruptedScan("deep", bulk);
    if (alreadyFinished) await finishDiscovery(f);
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
        createSecurity: resumeClient(f, () => ({
          startThread() {
            throw new Error("Unexpected new session");
          },
          resumeThread(threadId) {
            expect(threadId).toBe(f.threadId);
            return {
              id: threadId,
              async runStreamed() {
                if (!alreadyFinished) await finishDiscovery(f);
                return { events: completedEvents(threadId) };
              },
            };
          },
        })),
      },
    );
    // Preserve the CLI's nonzero exit for a valid, sealed partial result.
    expect(code, stderr.text()).toBe(2);
    const result = JSON.parse(stdout.text());
    if (bulk) {
      expect(result, stderr.text()).toMatchObject({ incomplete: 1, failed: 0 });
      const receipts = (await readFile(result.resultsPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(receipts).toHaveLength(2);
      expect(receipts[1]).toMatchObject({
        attempt: 1,
        outputDir: f.scanDir,
        status: "completed_with_incomplete_coverage",
        cost: { inputTokens: 10000, outputTokens: 2000 },
      });
      // Reconcile a crash after sealing but before the bulk receipt was appended.
      await writeFile(result.resultsPath, JSON.stringify(receipts[0]) + "\n");
      const reconciledOutput = capture();
      expect(
        await main(
          ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
          reconciledOutput.stream,
          stderr.stream,
          {
            ...dependencies({
              onRun() {
                throw new Error("A sealed scan needs no Codex invocation");
              },
            }),
            runWorkbench: f.command,
          },
        ),
      ).toBe(2);
      expect(JSON.parse(reconciledOutput.text())).toMatchObject({
        incomplete: 1,
        failed: 0,
      });
      const reconciled = (await readFile(result.resultsPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(reconciled[1]).toMatchObject({
        attempt: 1,
        cost: { inputTokens: 10000, outputTokens: 2000 },
      });
      // A subsequent bulk recovery must skip the reconciled completion.
      const nextOutput = capture();
      expect(
        await main(
          ["bulk-scan", f.input, "--output-dir", f.root, "--recover", "--json"],
          nextOutput.stream,
          stderr.stream,
          { ...dependencies(), runWorkbench: f.command },
        ),
      ).toBe(2);
      expect(JSON.parse(nextOutput.text())).toMatchObject({
        skipped: 1,
        incomplete: 1,
        failed: 0,
      });
    } else {
      expect(result.coverage.completeness).toBe("partial");
      expect(result.manifest.scan.id).toBe(f.scanId);
      expect(result.manifest.scan.sealedAt).toBeString();
      expect(result.cost.inputTokens).toBe(10000);
      expect(result.cost.outputTokens).toBe(2000);
    }
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
    });
    expect(
      (await f.command(["list-scans", "--repository", f.repository]))["scans"],
    ).toHaveLength(1);
    expect(await readFile(f.checkpoint, "utf8")).toBe(
      '{"completed":"setup"}\n',
    );
    await expect(
      f.command(["get-cli-scan-resume", "--scan-id", f.scanId]),
    ).rejects.toThrow("running scan");
  },
);

test.each([
  "single",
  "bulk",
  "unsupported-schema",
  "wrong-producer",
  "changed-findings",
])(
  "resume preserves sealed artifacts across a plugin upgrade (%s)",
  async (scenario) => {
    const f = await interruptedScan("deep", scenario === "bulk");
    await finishDiscovery(f);
    const oldPlugin = join(f.root, "old-plugin");
    for (const path of ["scripts", "schemas", ".codex-plugin"]) {
      await cp(join(PLUGIN_ROOT, path), join(oldPlugin, path), {
        recursive: true,
      });
    }
    const pluginManifest = join(oldPlugin, ".codex-plugin", "plugin.json");
    const plugin = JSON.parse(await readFile(pluginManifest, "utf8"));
    plugin.version = f.recipe.pluginVersion;
    await writeFile(pluginManifest, JSON.stringify(plugin));
    await runWorkbench(
      { python: f.python, pluginRoot: oldPlugin, environment: f.environment },
      ["prepare-scan-completion", "--scan-id", f.scanId],
    );
    const manifestPath = join(f.scanDir, "scan-manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    expect(manifest.scan.producer.version).toBe(f.recipe.pluginVersion);
    if (scenario === "unsupported-schema") manifest.schemaVersion = "999.0";
    if (scenario === "wrong-producer")
      manifest.scan.producer.name = "different-producer";
    if (scenario === "unsupported-schema" || scenario === "wrong-producer") {
      await writeFile(manifestPath, JSON.stringify(manifest));
    }
    if (scenario === "changed-findings") {
      await appendFile(join(f.scanDir, "findings.json"), "\n");
    }
    const artifactNames = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
      "report.md",
    ];
    const artifacts = await Promise.all(
      artifactNames.map((name) => readFile(join(f.scanDir, name))),
    );
    const before = await f.command(["get-scan", "--scan-id", f.scanId]);
    const rejected = !["single", "bulk"].includes(scenario);
    let turns = 0;
    const stdout = capture();
    const stderr = capture();
    const code = await main(
      scenario === "bulk"
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
        createSecurity: resumeClient(f, () => ({
          startThread() {
            throw new Error("Unexpected new session");
          },
          resumeThread(threadId) {
            expect(threadId).toBe(f.threadId);
            return {
              id: threadId,
              async runStreamed() {
                turns++;
                return { events: completedEvents(threadId) };
              },
            };
          },
        })),
      },
    );
    expect(code, stderr.text()).toBe(2);
    expect(
      await Promise.all(
        artifactNames.map((name) => readFile(join(f.scanDir, name))),
      ),
    ).toEqual(artifacts);
    const after = await f.command(["get-scan", "--scan-id", f.scanId]);
    if (rejected) {
      expect(stderr.text()).toContain("Cannot resume sealed scan");
      expect(turns).toBe(0);
      expect(after).toEqual(before);
    } else {
      expect(after["scan"], stderr.text()).toMatchObject({
        progress: { status: "complete" },
        continuationThreadId: f.threadId,
      });
      if (scenario === "bulk") {
        expect(JSON.parse(stdout.text())).toMatchObject({
          incomplete: 1,
          failed: 0,
        });
        const receipts = (await readFile(join(f.root, "results.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(receipts).toHaveLength(2);
        expect(receipts[1]).toMatchObject({
          attempt: 1,
          outputDir: f.scanDir,
          status: "completed_with_incomplete_coverage",
        });
      }
    }
  },
);

test("CLI saves launch settings before execution without depending on the prompt file", async () => {
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
    runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args, input);
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
      "api-key",
      "--safety-identifier",
      "synthetic-original-user",
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
    auth: "api-key",
    safetyIdentifier: "synthetic-original-user",
    postScanPrompt,
  });
  expect(JSON.stringify(saved)).not.toContain("synthetic-launch-key");
  expect(JSON.stringify(saved)).not.toContain(promptFile);
});

test.each([false, true])(
  "resume restores saved launch settings (bulk: %s)",
  async (bulk) => {
    const settings = {
      safetyIdentifier: "synthetic-original-user",
      postScanPrompt: "Run these exact saved post-scan instructions.\n",
    };
    const f = await interruptedScan("deep", bulk, settings);
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
          expect(options.env?.["CODEX_SAFETY_IDENTIFIER"]).toBe(
            settings.safetyIdentifier,
          );
          return {
            startThread() {
              throw new Error("Resume must use the original session.");
            },
            resumeThread(threadId) {
              expect(threadId).toBe(f.threadId);
              return {
                id: threadId,
                async runStreamed(prompt) {
                  prompts.push(prompt as string);
                  if (prompts.length === 1) await finishDiscovery(f);
                  return { events: completedEvents(threadId) };
                },
              };
            },
          };
        }),
      },
    );
    expect(code, stderr.text()).toBe(2);
    expect(prompts, stderr.text()).toHaveLength(2);
    expect(prompts[1]).toBe(settings.postScanPrompt);
    expect(
      (await f.command(["get-scan", "--scan-id", f.scanId]))["scan"],
    ).toMatchObject({
      progress: { status: "complete" },
      continuationThreadId: f.threadId,
    });
  },
);

test.each([
  ["chatgpt", false],
  ["api-key", false],
  ["chatgpt", true],
  ["api-key", true],
] as const)(
  "resume preserves %s authentication with an ambient key (bulk: %p)",
  async (auth, bulk) => {
    const f = await interruptedScan("deep", bulk, { auth });
    const stdout = capture();
    const stderr = capture();
    let resumedThread: string | undefined;
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
          expect(options.apiKey).toBe(
            auth === "api-key" ? "synthetic-resume-key" : undefined,
          );
          expect(options.env?.["OPENAI_API_KEY"]).toBeUndefined();
          expect(options.env?.["CODEX_API_KEY"]).toBeUndefined();
          return {
            startThread() {
              throw new Error("Resume must use the original session.");
            },
            resumeThread(threadId) {
              resumedThread = threadId;
              return {
                id: threadId,
                async runStreamed() {
                  throw new Error("Synthetic resume transport stopped");
                },
              };
            },
          };
        }),
      },
    );
    expect(code).toBe(2);
    expect(stderr.text()).toContain("Synthetic resume transport stopped");
    expect(resumedThread).toBe(f.threadId);
    expect(f.environment.OPENAI_API_KEY).toBe("synthetic-resume-key");
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
