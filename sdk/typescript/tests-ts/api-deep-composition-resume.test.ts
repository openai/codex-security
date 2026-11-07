import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { stringify as stringifyToml } from "smol-toml";
import { CodexSecurity } from "../src/api.js";
import { main } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost } from "../src/cost.js";
import { loadDeepScanCheckpoint } from "../src/deep-scan-checkpoint.js";
import { DeepScanRecoveryError } from "../src/deep-scan.js";
import { ScanInterruptedError } from "../src/errors.js";
import { restoreProviderProfile } from "../src/provider-profile.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { ScanTransportClosedError } from "../src/scan-execution.js";
import { capture, dependencies as cliDependencies } from "./cli-fixtures.js";
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
  expect(replay).toEqual({
    analytics: configuration.analytics,
    mcp_servers: {
      "codex-security": { command: "synthetic-workbench", enabled: true },
      "synthetic.server": { command: "synthetic-command" },
    },
  });
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
    ["scans", "resume", parentId],
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
