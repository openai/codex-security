import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  access,
  appendFile,
  mkdir,
  readdir,
  rename,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import {
  OperationTelemetry,
  readOperationTelemetry,
  summarizeOperationTelemetry,
  type OperationTelemetryEvent,
} from "../src/operation-telemetry.js";
import { TestClient } from "./support/api-client.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { workflowFixture } from "./support/workflow-fixture.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures("telemetry-");
afterEach(cleanup);

test("journals early failures without copying target paths or diagnostic text", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "missing-synthetic-repository");
  const observed: OperationTelemetryEvent[] = [];
  const client = new TestClient(
    {},
    {
      environment: { CODEX_SECURITY_STATE_DIR: root },
      createOperationTelemetry: (options) => new OperationTelemetry(options),
    },
  );
  try {
    await expect(
      client.run(repository, {
        onTelemetry: (event) => observed.push(event),
      }),
    ).rejects.toThrow();
  } finally {
    await client.close();
  }
  const saved = await readOperationTelemetry(root);
  expect(saved.parseFailures).toBe(0);
  expect(saved.events.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(saved.events[1]).toMatchObject({
    outcome: "failed",
    command: "scan",
    surface: "sdk",
    failureCategory: "input",
  });
  expect(saved.events[1]!.durationMs).toBeGreaterThanOrEqual(0);
  expect(observed.map((event) => event.eventId)).toEqual(
    saved.events.map((event) => event.eventId),
  );
  expect(JSON.stringify(saved.events)).not.toContain(repository);
  expect(JSON.stringify(saved.events)).not.toContain(
    "missing-synthetic-repository",
  );
});

test.each(["scan", "validate", "policy"] as const)(
  "explicit %s output stays empty through runtime preparation",
  async (command) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const state = join(root, "state");
    const outputDir = join(state, "telemetry");
    await mkdir(repository);
    await mkdir(outputDir, { recursive: true, mode: 0o700 });
    const observed: OperationTelemetryEvent[] = [];
    const failure = new Error("Synthetic runtime boundary reached");
    let runtimeCalls = 0;
    const client = new TestClient(
      {},
      {
        environment: {
          CODEX_SECURITY_STATE_DIR: state,
          CODEX_HOME: join(root, "codex"),
        },
        createOperationTelemetry: (options) => new OperationTelemetry(options),
        prepareRuntime: async () => {
          runtimeCalls++;
          throw failure;
        },
      },
    );
    const options = {
      outputDir,
      onTelemetry: (event: Readonly<OperationTelemetryEvent>) =>
        observed.push(event),
    };
    try {
      const operation =
        command === "scan"
          ? client.run(repository, { ...options, mode: "standard" })
          : command === "validate"
            ? client.validate({
                ...options,
                repositoryPath: repository,
                finding: "Synthetic candidate finding",
              })
            : client.generatePolicy(repository, options);
      await expect(operation).rejects.toBe(failure);
    } finally {
      await client.close();
    }
    expect(runtimeCalls).toBe(1);
    expect(await readdir(outputDir)).toEqual([]);
    expect(observed.map((event) => event.type)).toEqual([
      "attempt_started",
      "attempt_finished",
    ]);
    expect(observed[1]).toMatchObject({
      operationId: observed[0]!.operationId,
      attemptId: observed[0]!.attemptId,
      outcome: "failed",
      collection: { persisted: 0 },
    });
  },
);

test("rejected explicit scan output keeps its completed artifacts unchanged", async () => {
  await using fixture = await workflowFixture();
  const state = fixture.environment.CODEX_SECURITY_STATE_DIR;
  await mkdir(state, { mode: 0o700 });
  const outputDir = join(state, "telemetry");
  await rename(fixture.scanDir, outputDir);
  const entries = await readdir(outputDir, { recursive: true });
  const client = new TestClient(
    {},
    {
      environment: fixture.environment,
      createOperationTelemetry: (options) => new OperationTelemetry(options),
    },
  );
  try {
    await expect(
      client.run(fixture.repository, { mode: "standard", outputDir }),
    ).rejects.toThrow("Scan output directory is not empty");
  } finally {
    await client.close();
  }
  expect((await readdir(outputDir, { recursive: true })).sort()).toEqual(
    entries.sort(),
  );
});

test("rejected workflow state paths leave sealed artifacts unchanged", async () => {
  await using fixture = await workflowFixture();
  const state = join(fixture.scanDir, "state");
  const entries = await readdir(fixture.scanDir, { recursive: true });
  const observed: OperationTelemetryEvent[] = [];
  const client = new TestClient(
    {},
    {
      environment: {
        ...fixture.environment,
        CODEX_SECURITY_STATE_DIR: state,
      },
      createOperationTelemetry: (options) => new OperationTelemetry(options),
    },
  );
  try {
    await expect(
      client.run(fixture.repository, {
        mode: "standard",
        workflowId: "synthetic-workflow",
        outputDir: fixture.scanDir,
        onTelemetry: (event) => observed.push(event),
      }),
    ).rejects.toThrow(
      "Workflow state must be outside the sealed scan artifacts.",
    );
  } finally {
    await client.close();
  }
  expect((await readdir(fixture.scanDir, { recursive: true })).sort()).toEqual(
    entries.sort(),
  );
  await expect(access(state)).rejects.toThrow();
  expect(observed.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(observed[1]).toMatchObject({
    outcome: "failed",
    collection: { persisted: 0, writeFailures: 0 },
  });
});

test.each(["explicit", "saved"] as const)(
  "%s workflow artifacts cannot become the journal directory",
  async (source) => {
    await using fixture = await workflowFixture();
    const state = fixture.environment.CODEX_SECURITY_STATE_DIR;
    await mkdir(state, { mode: 0o700 });
    const scanDir = join(state, "telemetry");
    await rename(fixture.scanDir, scanDir);
    const entries = await readdir(scanDir, { recursive: true });
    const observed: OperationTelemetryEvent[] = [];
    const warnings: string[] = [];
    const client = new TestClient(
      {},
      {
        environment: {
          ...fixture.environment,
          CODEX_SECURITY_STATE_DIR: state,
        },
        createOperationTelemetry: (options) => new OperationTelemetry(options),
        runWorkbench: async () => ({
          workflow: {
            id: "synthetic-workflow",
            scanId: fixture.document.scanId,
            scanDir,
            stages: {
              scan: {
                status: "completed",
                result: {
                  threadId: "synthetic-thread",
                  turnResult: { status: "completed" },
                },
              },
              publish: { status: "pending" },
              dedupe: { status: "pending" },
            },
          },
        }),
      },
    );
    try {
      const result = await client.run(fixture.repository, {
        mode: "standard",
        workflowId: "synthetic-workflow",
        ...(source === "explicit" ? { outputDir: scanDir } : {}),
        onTelemetry: (event) => observed.push(event),
        onWarning: (message) => warnings.push(message),
      });
      expect(result.manifest.scan.id).toBe(fixture.document.scanId);
    } finally {
      await client.close();
    }
    expect((await readdir(scanDir, { recursive: true })).sort()).toEqual(
      entries.sort(),
    );
    expect(observed.map((event) => event.type)).toEqual([
      "attempt_started",
      "attempt_finished",
    ]);
    expect(observed[1]).toMatchObject({
      outcome: "completed",
      reusedResult: true,
      collection: { persisted: 0, writeFailures: 1 },
    });
    expect(warnings).toHaveLength(1);
  },
);

test.each(["immediate", "deferred"] as const)(
  "resume keeps one operation identity and deduplicates receipts, %s",
  async (persistence) => {
    const deferPersistence = persistence === "deferred";
    const directory = await temporaryDirectory();
    const first = new OperationTelemetry({
      directory,
      protectedOutput: join(directory, "scan-artifacts"),
      command: "scan",
      surface: "sdk",
    });
    await first.start();
    await first.bindScan("synthetic-scan");
    await first.finish("failed");
    await first.finish("completed");
    const observed: OperationTelemetryEvent[] = [];
    const resumed = new OperationTelemetry({
      directory,
      deferPersistence,
      onEvent: (event) => observed.push(structuredClone(event)),
      protectedOutput: join(directory, "scan-artifacts"),
      command: "scan",
      surface: "sdk",
      resumeScanId: "synthetic-scan",
    });
    await resumed.start();
    if (deferPersistence) {
      expect(observed).toHaveLength(0);
      await resumed.activatePersistence([]);
    }
    expect(resumed.operationId).toBe(first.operationId);
    expect(resumed.attemptId).not.toBe(first.attemptId);
    await resumed.finish("completed");
    expect(observed.map((event) => event.operationId)).toEqual([
      first.operationId,
      first.operationId,
    ]);
    expect(new Set(observed.map((event) => event.usageScopeId))).toEqual(
      new Set([first.attemptId]),
    );
    const interrupted = new OperationTelemetry({
      directory,
      command: "scan",
      surface: "sdk",
    });
    await interrupted.start();
    const { events } = await readOperationTelemetry(directory);
    expect(events).toHaveLength(5);
    expect(
      events
        .filter((event) => event.attemptId === resumed.attemptId)
        .map((event) => event.operationId),
    ).toEqual([first.operationId, first.operationId]);
    const summary = summarizeOperationTelemetry(
      [...events].reverse().concat(events),
    );
    expect(summary).toMatchObject({
      attempts: 3,
      outcomes: { completed: 1, failed: 1, canceled: 0, unresolved: 1 },
      usageCoverage: { complete: 0, partial: 0, unavailable: 3 },
      duplicates: 5,
      pricedAttempts: 0,
    });
  },
);

test("reports corrupt trailing records and keeps usable receipts", async () => {
  const directory = await temporaryDirectory();
  const journal = new OperationTelemetry({
    directory,
    command: "patch",
    surface: "cli",
  });
  await journal.start();
  await appendFile(
    join(directory, "telemetry", `${journal.attemptId}.jsonl`),
    '{"partial":',
  );
  const result = await readOperationTelemetry(directory);
  expect(result.events).toHaveLength(1);
  expect(result.parseFailures).toBe(1);
  expect(summarizeOperationTelemetry(result.events).outcomes.unresolved).toBe(
    1,
  );
});

test("counts reused results once while preserving completed call outcomes", async () => {
  const directory = await temporaryDirectory();
  const execution = new OperationTelemetry({
    directory,
    command: "scan",
    surface: "sdk",
  });
  await execution.start();
  await execution.finish("completed", { findingCount: 2 });
  const retrieval = new OperationTelemetry({
    directory,
    command: "scan",
    surface: "sdk",
    context: { operationId: execution.operationId },
  });
  await retrieval.start();
  retrieval.reusedResult = true;
  await retrieval.finish("completed", { findingCount: 2 });
  const { events } = await readOperationTelemetry(directory);
  expect(
    events.find(
      (event) =>
        event.attemptId === execution.attemptId &&
        event.type === "attempt_finished",
    )?.reusedResult,
  ).toBe(false);
  const reused = events.find((event) => event.reusedResult === true);
  expect(reused).toMatchObject({
    type: "attempt_finished",
    outcome: "completed",
    findingCount: 2,
  });
  expect(reused?.measurement).toBeUndefined();
  expect(
    summarizeOperationTelemetry([...events].reverse().concat(events)),
  ).toMatchObject({
    operations: 1,
    successfulOperations: 1,
    attempts: 2,
    reusedAttempts: 1,
    usageCoverage: { complete: 0, partial: 0, unavailable: 1 },
    outcomes: { completed: 2, failed: 0, canceled: 0, unresolved: 0 },
    duplicates: 4,
  });
});

test.each([
  ["operation ID", { operationId: undefined }],
  ["usage scope ID", { usageScopeId: undefined }],
  ["outcome", { outcome: "unknown" }],
  ["terminal outcome", { outcome: undefined }],
  ["measurement coverage", { measurement: { coverage: "unknown" } }],
] as const)(
  "reports incomplete journal %s without changing valid summaries",
  async (_field, invalid) => {
    const directory = await temporaryDirectory();
    const journal = new OperationTelemetry({
      directory,
      command: "scan",
      surface: "sdk",
    });
    await journal.start();
    await journal.finish("completed");
    const original = await readOperationTelemetry(directory);
    const terminal = original.events.find(
      (event) => event.type === "attempt_finished",
    )!;
    await appendFile(
      join(directory, "telemetry", `${journal.attemptId}.jsonl`),
      `${JSON.stringify({ ...terminal, eventId: "invalid-event", attemptId: "invalid-attempt", ...invalid })}\n`,
    );
    const result = await readOperationTelemetry(directory);
    expect(result.parseFailures).toBe(1);
    expect(result.events).toEqual(original.events);
    expect(summarizeOperationTelemetry(result.events)).toEqual(
      summarizeOperationTelemetry(original.events),
    );
  },
);

test("deferred resume failures emit matching in-memory start and terminal events", async () => {
  const directory = join(await temporaryDirectory(), "not-created");
  const observed: OperationTelemetryEvent[] = [];
  const journal = new OperationTelemetry({
    directory,
    command: "scan",
    surface: "sdk",
    deferPersistence: true,
    resumeScanId: "synthetic-scan",
    onEvent: (event) => observed.push(structuredClone(event)),
  });
  await journal.start();
  await journal.finish("failed", { failureCategory: "input" });
  expect(observed.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(observed[1]).toMatchObject({
    operationId: observed[0]!.operationId,
    usageScopeId: observed[0]!.usageScopeId,
    attemptId: observed[0]!.attemptId,
    collection: { persisted: 0, writeFailures: 0 },
  });
  await expect(access(directory)).rejects.toThrow();
});

test("journal and observer failures cannot stop an operation", async () => {
  const directory = await temporaryDirectory();
  await writeFile(join(directory, "telemetry"), "occupied");
  const observed: OperationTelemetryEvent[] = [];
  const errors: unknown[] = [];
  const journal = new OperationTelemetry({
    directory,
    command: "validate",
    surface: "sdk",
    onEvent(event) {
      observed.push(event);
      throw new Error("observer failed");
    },
    onError(error) {
      errors.push(error);
    },
  });
  await journal.start();
  await journal.finish("canceled");
  await Promise.resolve();
  expect(errors.length).toBeGreaterThan(0);
  expect(observed.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(observed[1]!.collection.writeFailures).toBeGreaterThan(0);
});

test("journal refuses to write inside the protected repository", async () => {
  const repository = await temporaryDirectory();
  const state = join(repository, "state");
  const errors: unknown[] = [];
  const journal = new OperationTelemetry({
    directory: state,
    protectedRepository: repository,
    command: "scan",
    surface: "sdk",
    onError: (error) => errors.push(error),
  });
  await journal.start();
  await journal.finish("failed");
  expect(errors).toHaveLength(1);
  await expect(access(state)).rejects.toThrow();
});

test("journal protects the enclosing checkout before a missing target is validated", async () => {
  const repository = await temporaryDirectory();
  await mkdir(join(repository, ".git"), { mode: 0o700 });
  const state = join(repository, "state");
  const errors: unknown[] = [];
  const observed: OperationTelemetryEvent[] = [];
  const journal = new OperationTelemetry({
    directory: state,
    protectedRepository: join(repository, "missing-target"),
    command: "scan",
    surface: "sdk",
    onError: (error) => errors.push(error),
    onEvent: (event) => observed.push(event),
  });
  await journal.start();
  await journal.finish("failed");
  expect(errors).toHaveLength(1);
  await expect(access(state)).rejects.toThrow();
  expect(observed.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(observed[1]!.collection).toEqual({
    persisted: 0,
    writeFailures: 1,
  });
});

test.each([
  "separate",
  "linked",
  "nested",
  "objects",
  "nested-objects",
] as const)(
  "policy journals leave external %s Git metadata untouched",
  async (kind) => {
    const root = await temporaryDirectory();
    let repository = join(root, "repository");
    await mkdir(repository, { mode: 0o700 });
    let metadata = join(root, "metadata");
    if (kind === "linked") {
      execFileSync("git", ["init", "--quiet", repository]);
      execFileSync("git", [
        "-C",
        repository,
        "-c",
        "user.name=Synthetic",
        "-c",
        "user.email=synthetic@example.invalid",
        "commit",
        "--allow-empty",
        "--quiet",
        "-m",
        "initial",
      ]);
      const linked = join(root, "linked");
      execFileSync("git", [
        "-C",
        repository,
        "worktree",
        "add",
        "--quiet",
        "--detach",
        linked,
      ]);
      metadata = join(repository, ".git", "worktrees", "linked");
      repository = linked;
    } else {
      const checkout = kind.startsWith("nested")
        ? join(repository, "component")
        : repository;
      execFileSync("git", [
        "init",
        "--quiet",
        "--separate-git-dir",
        metadata,
        checkout,
      ]);
      execFileSync("git", [
        "-C",
        checkout,
        "config",
        "core.worktree",
        checkout,
      ]);
      if (kind.endsWith("objects")) {
        const objects = join(root, "external-objects");
        await mkdir(join(objects, "info"), { recursive: true, mode: 0o700 });
        await writeFile(
          join(metadata, "objects", "info", "alternates"),
          `${objects}\n`,
        );
        metadata = objects;
      }
    }
    const state = join(metadata, "state");
    const observed: OperationTelemetryEvent[] = [];
    const client = new TestClient(
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: state },
        createOperationTelemetry: (options) => new OperationTelemetry(options),
      },
    );
    try {
      await expect(
        client.generatePolicy(repository, {
          onTelemetry: (event) => observed.push(event),
        }),
      ).rejects.toThrow("outside the protected scan root");
    } finally {
      await client.close();
    }
    await expect(access(state)).rejects.toThrow();
    expect(observed.map((event) => event.type)).toEqual([
      "attempt_started",
      "attempt_finished",
    ]);
    expect(observed[1]!.outcome).toBe("failed");
  },
);

test("deferred journals persist the original start once after path validation", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository, { mode: 0o700 });
  const state = join(root, "state");
  const observed: OperationTelemetryEvent[] = [];
  const journal = new OperationTelemetry({
    directory: state,
    protectedRepository: repository,
    command: "policy",
    surface: "sdk",
    deferPersistence: true,
    onEvent: (event) => observed.push(event),
  });
  await journal.start();
  expect(observed).toHaveLength(1);
  await expect(access(state)).rejects.toThrow();
  await journal.activatePersistence([repository]);
  await journal.activatePersistence([repository]);
  await journal.finish("completed");
  const saved = await readOperationTelemetry(state);
  expect(saved.events).toHaveLength(2);
  expect(observed).toHaveLength(2);
  expect(saved.events[0]).toMatchObject({
    eventId: observed[0]!.eventId,
    occurredAt: observed[0]!.occurredAt,
    observedAt: observed[0]!.observedAt,
    collection: { persisted: 1, writeFailures: 0 },
  });
  expect(saved.events[1]!.collection.persisted).toBe(2);
});

test("deferred journal activation failures leave the operation observable", async () => {
  const directory = await temporaryDirectory();
  await writeFile(join(directory, "telemetry"), "occupied");
  const observed: OperationTelemetryEvent[] = [];
  const journal = new OperationTelemetry({
    directory,
    command: "policy",
    surface: "sdk",
    deferPersistence: true,
    onEvent: (event) => observed.push(event),
    onError: () => {
      throw new Error("Synthetic warning observer failure");
    },
  });
  await journal.start();
  await journal.activatePersistence([]);
  await journal.finish("completed");
  expect(observed.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(observed[1]!.collection).toEqual({
    persisted: 0,
    writeFailures: 1,
  });
});

test("cumulative resume costs are counted once while independent retries are added", async () => {
  const directory = await temporaryDirectory();
  await mkdir(join(directory, "telemetry"));
  const first = new OperationTelemetry({
    directory,
    command: "scan",
    surface: "sdk",
  });
  const measurement = (tokens: number) => ({
    usage: {
      input_tokens: tokens,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 0,
      reasoning_output_tokens: 0,
      total_tokens: tokens,
    },
    cost: {
      model: "gpt-5.6-sol",
      inputTokens: tokens,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 0,
      estimatedUsd: tokens,
    },
    coverage: "complete" as const,
    observedAt: new Date().toISOString(),
    threadCount: 1,
    missingThreadCount: 0,
  });
  await first.start();
  await first.bindScan("synthetic-scan");
  first.measurement = measurement(10);
  await first.finish("failed");
  const resumed = new OperationTelemetry({
    directory,
    command: "scan",
    surface: "sdk",
    resumeScanId: "synthetic-scan",
  });
  await resumed.start();
  resumed.measurement = measurement(15);
  await resumed.finish("completed");
  const retry = new OperationTelemetry({
    directory,
    command: "scan",
    surface: "sdk",
    context: { operationId: first.operationId },
  });
  await retry.start();
  retry.measurement = measurement(3);
  await retry.finish("completed");
  expect(
    summarizeOperationTelemetry(
      (await readOperationTelemetry(directory)).events,
    ),
  ).toMatchObject({
    attempts: 3,
    operations: 1,
    successfulOperations: 1,
    pricedAttempts: 3,
    observedCostUsd: 18,
  });
});
