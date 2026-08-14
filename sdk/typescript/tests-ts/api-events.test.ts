import { mkdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  Codex,
  type McpToolCallItem,
  type ThreadEvent,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, test } from "bun:test";
import { runScanEvents } from "../src/api.js";
import {
  CodexSecurityError,
  IncompleteScanError,
  ScanInterruptedError,
  type ScanAuthentication,
  type ScanActivity,
  type ScanProgress,
  type ScanReconnectDetails,
  type ScanTrustedAccessStatus,
  type ScanWorkerStatus,
} from "../src/index.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import {
  completedEvents,
  createApiTestFixtures,
  runEvents,
  type ScanObserverName,
} from "./support/api-events.js";

const { cleanup, copyCompletedScan, temporaryDirectory } =
  createApiTestFixtures();

afterEach(cleanup);

function tacToolCall(
  status: "granted" | "not_granted" | "unknown",
  overrides: Partial<McpToolCallItem> = {},
): McpToolCallItem {
  return {
    id: "tac-status-1",
    type: "mcp_tool_call",
    server: "codex_apps",
    tool: "get_tac_status",
    arguments: {},
    result: {
      content: [],
      structured_content: {
        schemaVersion: 1,
        status,
        grants: status === "granted" ? [{ level: "tac1", source: "user" }] : [],
        checkedAt: "2026-07-29T00:00:00.000Z",
        stale: false,
      },
    },
    status: "completed",
    ...overrides,
  };
}

async function* tacEvents(
  items: readonly McpToolCallItem[],
): AsyncGenerator<ThreadEvent> {
  yield { type: "thread.started", thread_id: "thread-1" };
  yield { type: "turn.started" };
  for (const item of items) {
    yield { type: "item.completed", item };
  }
  yield {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text: "scan complete" },
  };
  yield {
    type: "turn.completed",
    usage: {
      input_tokens: 10,
      cached_input_tokens: 2,
      cache_write_input_tokens: 0,
      output_tokens: 3,
      reasoning_output_tokens: 1,
    },
  };
}

function runTacEvents(
  scanDir: string,
  items: readonly McpToolCallItem[],
  onWarning: (warning: string) => void,
  onObserverError?: (observer: ScanObserverName, error: unknown) => void,
  onTrustedAccessStatus?: (status: ScanTrustedAccessStatus) => void,
  authentication?: ScanAuthentication,
): ReturnType<typeof runEvents> {
  return runEvents(scanDir, tacEvents(items), {
    authentication,
    onObserverError,
    onTrustedAccessStatus,
    onWarning,
  });
}

describe("one-shot scan events", () => {
  test("validates completed scan artifacts", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const result = await runEvents(scanDir, completedEvents());

    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult).toMatchObject({
      status: "completed",
      model: "gpt-5.6-sol",
      finalResponse: "scan complete",
    });
    expect(result.cost).toEqual({
      model: "gpt-5.6-sol",
      inputTokens: 10,
      cachedInputTokens: 2,
      cacheWriteInputTokens: 0,
      outputTokens: 3,
      estimatedUsd: 0.000131,
    });
  });

  test.each([null, undefined])(
    "preserves completed scans when the real Codex SDK receives %p token usage",
    async (usage) => {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const thread = new Codex({
        codexPathOverride: process.execPath,
      }).startThread();
      const executable = thread as unknown as {
        _exec: { run(): AsyncGenerator<string> };
      };
      executable._exec.run = async function* () {
        yield JSON.stringify({ type: "thread.started", thread_id: "thread-1" });
        yield JSON.stringify({
          type: "item.completed",
          item: {
            id: "message-1",
            type: "agent_message",
            text: "scan complete",
          },
        });
        yield JSON.stringify({ type: "turn.completed", usage });
      };

      const { events } = await thread.runStreamed("Scan the repository.");
      const result = await runEvents(scanDir, events);

      expect(result.threadId).toBe("thread-1");
      expect(result.turnResult).toMatchObject({
        status: "completed",
        finalResponse: "scan complete",
      });
      expect(result.cost).toBeNull();
    },
  );

  test("does not suppress unrelated SDK stream failures", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      throw new TypeError("Cannot read properties of null (reading 'message')");
    }

    await expect(runEvents(scanDir, failedEvents())).rejects.toThrow(
      "reading 'message'",
    );
  });

  test("reports granted trusted cyber access once without a warning", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const warnings: string[] = [];
    const statuses: ScanTrustedAccessStatus[] = [];
    const item = tacToolCall("granted");

    const result = await runTacEvents(
      scanDir,
      [item, item],
      (warning) => warnings.push(warning),
      undefined,
      (status) => statuses.push(status),
    );

    expect(result.turnResult.status).toBe("completed");
    expect(warnings).toEqual([]);
    expect(statuses).toEqual(["granted"]);
  });

  test("warns once and continues when trusted cyber access is not granted", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const warnings: string[] = [];
    const item = tacToolCall("not_granted");

    const result = await runTacEvents(scanDir, [item, item], (warning) =>
      warnings.push(warning),
    );

    expect(result.turnResult.status).toBe("completed");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toBe(
      "Some cybersecurity requests or findings may be refused because your account does not have Trusted Access for Cyber. Apply at https://chatgpt.com/cyber.",
    );
  });

  test("warns once and continues when trusted cyber access is unknown", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const warnings: string[] = [];

    const result = await runTacEvents(
      scanDir,
      [tacToolCall("unknown")],
      (warning) => warnings.push(warning),
    );

    expect(result.turnResult.status).toBe("completed");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toBe(
      "Some cybersecurity requests or findings may be refused because your Trusted Access for Cyber status could not be verified. Check your access or apply at https://chatgpt.com/cyber.",
    );
  });

  test("directs API-key scans to the organizational trusted cyber application", async () => {
    for (const [authentication, status, expected] of [
      [
        {
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        },
        "not_granted",
        "Some cybersecurity requests or findings may be refused because your API organization does not have Trusted Access for Cyber. Apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
      ],
      [
        {
          method: "api_key",
          source: "CODEX_API_KEY",
          verified: false,
        },
        "unknown",
        "Some cybersecurity requests or findings may be refused because Trusted Access for Cyber for your API organization could not be verified. Check your organization's access or apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
      ],
      [
        {
          method: "stored_credentials",
          credentialType: "api_key",
          verified: false,
        },
        "not_granted",
        "Some cybersecurity requests or findings may be refused because your API organization does not have Trusted Access for Cyber. Apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
      ],
      [
        {
          method: "stored_credentials",
          credentialType: "api_key",
          verified: false,
        },
        "unknown",
        "Some cybersecurity requests or findings may be refused because Trusted Access for Cyber for your API organization could not be verified. Check your organization's access or apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
      ],
    ] as const) {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const warnings: string[] = [];

      const result = await runTacEvents(
        scanDir,
        [tacToolCall(status)],
        (warning) => warnings.push(warning),
        undefined,
        undefined,
        authentication,
      );

      expect(result.turnResult.status).toBe("completed");
      expect(warnings).toEqual([expected]);
      expect(warnings[0]).not.toContain("chatgpt.com/cyber");
    }
  });

  test("does not mistake external-provider keys for OpenAI API organizations", async () => {
    for (const source of ["OPENROUTER_API_KEY", "FIREWORKS_API_KEY"] as const) {
      for (const status of ["not_granted", "unknown"] as const) {
        const scanDir = await copyCompletedScan(await temporaryDirectory());
        const warnings: string[] = [];

        const result = await runTacEvents(
          scanDir,
          [tacToolCall(status)],
          (warning) => warnings.push(warning),
          undefined,
          undefined,
          { method: "api_key", source, verified: false },
        );

        expect(result.turnResult.status).toBe("completed");
        expect(warnings).toHaveLength(1);
        expect(warnings[0]).toContain("https://chatgpt.com/cyber");
        expect(warnings[0]).not.toContain("API organization");
        expect(warnings[0]).not.toContain(
          "enterprise-trusted-access-for-cyber",
        );
      }
    }
  });

  test("treats failed trusted cyber access checks as an advisory without exposing provider errors", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const warnings: string[] = [];

    const result = await runTacEvents(
      scanDir,
      [
        tacToolCall("unknown", {
          status: "failed",
          result: undefined,
          error: { message: "SYNTHETIC_PRIVATE_PROVIDER_ERROR" },
        }),
      ],
      (warning) => warnings.push(warning),
    );

    expect(result.turnResult.status).toBe("completed");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("https://chatgpt.com/cyber");
    expect(warnings[0]).not.toContain("SYNTHETIC_PRIVATE_PROVIDER_ERROR");
  });

  test("treats malformed or stale trusted cyber access results as unverified", async () => {
    for (const structuredContent of [
      null,
      { schemaVersion: 1, status: "granted", grants: [] },
      {
        schemaVersion: 1,
        status: "granted",
        grants: [{ level: "tac1", source: "user" }],
        stale: false,
      },
      {
        schemaVersion: 1,
        status: "granted",
        grants: [],
        checkedAt: "2026-07-29T00:00:00.000Z",
        stale: false,
      },
      {
        schemaVersion: 1,
        status: "not_granted",
        grants: [{ level: "tac1", source: "user" }],
        checkedAt: "2026-07-29T00:00:00.000Z",
        stale: false,
      },
      {
        schemaVersion: 1,
        status: "granted",
        grants: [{ level: "tac3", source: "user" }],
        checkedAt: "2026-07-29T00:00:00.000Z",
        stale: false,
      },
      {
        schemaVersion: 1,
        status: "granted",
        grants: [],
        stale: true,
      },
      {
        schemaVersion: 2,
        status: "granted",
        grants: [],
        stale: false,
      },
    ]) {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const warnings: string[] = [];

      const result = await runTacEvents(
        scanDir,
        [
          tacToolCall("granted", {
            result: { content: [], structured_content: structuredContent },
          }),
        ],
        (warning) => warnings.push(warning),
      );

      expect(result.turnResult.status).toBe("completed");
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("could not be verified");
    }
  });

  test("does not trust similarly named tools from other MCP servers", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const warnings: string[] = [];

    const result = await runTacEvents(
      scanDir,
      [
        tacToolCall("not_granted", { server: "untrusted_server" }),
        tacToolCall("not_granted", { tool: "unrelated_tool" }),
        tacToolCall("granted"),
      ],
      (warning) => warnings.push(warning),
    );

    expect(result.turnResult.status).toBe("completed");
    expect(warnings).toEqual([]);
  });

  test("isolates trusted cyber access warning observer failures", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const observerErrors: Array<[ScanObserverName, string]> = [];

    const result = await runTacEvents(
      scanDir,
      [tacToolCall("not_granted")],
      () => {
        throw new Error("TAC warning observer failed");
      },
      (observer, error) => {
        observerErrors.push([observer, (error as Error).message]);
      },
    );

    expect(result.turnResult.status).toBe("completed");
    expect(observerErrors).toEqual([
      ["onWarning", "TAC warning observer failed"],
    ]);
  });

  test("isolates trusted cyber access status observer failures", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const observerErrors: Array<[ScanObserverName, string]> = [];

    const result = await runTacEvents(
      scanDir,
      [tacToolCall("granted")],
      () => {},
      (observer, error) => {
        observerErrors.push([observer, (error as Error).message]);
      },
      () => {
        throw new Error("TAC status observer failed");
      },
    );

    expect(result.turnResult.status).toBe("completed");
    expect(observerErrors).toEqual([
      ["onTrustedAccessStatus", "TAC status observer failed"],
    ]);
  });

  test("accepts target identity validated by the workbench", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const events = completedEvents();

    const result = await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events };
        },
      },
      events,
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "different-revision",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      workbenchValidated: true,
    });

    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult.status).toBe("completed");
  });

  test("lets the workbench seal artifacts before validating completed scans", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "scan");
    const events = completedEvents();
    let finalized = false;

    const result = await runScanEvents({
      thread: {
        id: null,
        async runStreamed() {
          return { events };
        },
      },
      events,
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: PLUGIN_ROOT,
      expectation: {
        repository: "/repository",
        repositoryRevision: "deadbeef",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      onFinalize: async (usage) => {
        expect(usage).toMatchObject({
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
        });
        expect(existsSync(join(scanDir, "scan-manifest.json"))).toBe(false);
        await copyCompletedScan(root);
        finalized = true;
      },
    });

    expect(finalized).toBe(true);
    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult.status).toBe("completed");
  });

  test("reports a scan as started only after the thread starts", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const milestones: string[] = [];

    async function* events(): AsyncGenerator<ThreadEvent> {
      milestones.push("stream opened");
      yield { type: "turn.started" };
      milestones.push("thread starting");
      yield* completedEvents();
    }

    await runEvents(scanDir, events(), {
      onScanStarted: () => milestones.push("scan started"),
    });

    expect(milestones).toEqual([
      "stream opened",
      "thread starting",
      "scan started",
    ]);
  });

  test("does not report a scan as started when its stream fails first", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    let scanStarted = false;

    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "error", message: "stream failed to start" };
    }

    await expect(
      runEvents(scanDir, failedEvents(), {
        onScanStarted: () => {
          scanStarted = true;
        },
      }),
    ).rejects.toThrow("stream failed to start");
    expect(scanStarted).toBe(false);
  });

  test("reports a scan as started only once if thread events are replayed", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    let starts = 0;
    const observerErrors: Array<[ScanObserverName, string]> = [];

    async function* replayedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield* completedEvents();
    }

    await runEvents(scanDir, replayedEvents(), {
      onScanStarted: () => {
        starts += 1;
        throw new Error("start observer exploded");
      },
      onObserverError: (observer, error) => {
        observerErrors.push([observer, (error as Error).message]);
      },
    });

    expect(starts).toBe(1);
    expect(observerErrors).toEqual([
      ["onScanStarted", "start observer exploded"],
    ]);
  });

  test("retains partial output and reports interruption", async () => {
    const root = await temporaryDirectory();
    const scanDir = join(root, "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    const abortController = new AbortController();
    const reconnects: Array<[number, number]> = [];
    let notifyReconnect!: () => void;
    const reconnectSeen = new Promise<void>((resolve) => {
      notifyReconnect = resolve;
    });
    async function* interruptedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-2" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      await new Promise<void>((resolve) => {
        abortController.signal.addEventListener("abort", () => resolve(), {
          once: true,
        });
      });
      throw new DOMException("aborted", "AbortError");
    }
    const result = runEvents(scanDir, interruptedEvents(), {
      abortController,
      onReconnect: (attempt, maxAttempts) => {
        reconnects.push([attempt, maxAttempts]);
        notifyReconnect();
      },
    });

    await reconnectSeen;
    abortController.abort();
    await expect(result).rejects.toMatchObject({
      name: ScanInterruptedError.name,
      scanDir,
    });
    expect(reconnects).toEqual([[2, 5]]);
    await expect(stat(scanDir)).resolves.toBeDefined();
  });

  test("isolates synchronous and asynchronous progress-observer failures", async () => {
    for (const asynchronous of [false, true]) {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const observerErrors: Array<[ScanObserverName, string]> = [];
      async function* reconnectingEvents(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "error", message: "Reconnecting... 2/5" };
        yield {
          type: "turn.completed",
          usage: {
            input_tokens: 1,
            cached_input_tokens: 0,
            cache_write_input_tokens: 0,
            output_tokens: 1,
            reasoning_output_tokens: 0,
          },
        };
      }

      await expect(
        runEvents(scanDir, reconnectingEvents(), {
          onReconnect: () => {
            const error = new Error("observer exploded");
            if (asynchronous) return Promise.reject(error);
            throw error;
          },
          onObserverError: (observer, error) => {
            observerErrors.push([observer, (error as Error).message]);
            if (asynchronous) return Promise.reject(new Error("report failed"));
          },
        }),
      ).resolves.toBeDefined();
      expect(observerErrors).toEqual([["onReconnect", "observer exploded"]]);
    }
  });

  test("keeps the Codex stream alive through reconnect notifications", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: Array<[number, number]> = [];
    let release!: () => void;
    const paused = new Promise<void>((resolve) => {
      release = resolve;
    });
    let notifyReconnect!: () => void;
    const reconnectSeen = new Promise<void>((resolve) => {
      notifyReconnect = resolve;
    });
    let closed = false;
    async function* reconnectingEvents(): AsyncGenerator<ThreadEvent> {
      try {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "turn.started" };
        yield {
          type: "error",
          message:
            "Reconnecting... 2/5 (Rate limit reached for org-private. Please try again in 1.2s.)",
        };
        notifyReconnect();
        await paused;
        yield { type: "error", message: "Reconnecting… 3/5" };
        yield {
          type: "item.completed",
          item: {
            id: "message-1",
            type: "agent_message",
            text: "scan complete",
          },
        };
        yield {
          type: "turn.completed",
          usage: {
            input_tokens: 10,
            cached_input_tokens: 2,
            cache_write_input_tokens: 0,
            output_tokens: 3,
            reasoning_output_tokens: 1,
          },
        };
      } finally {
        closed = true;
      }
    }
    const result = runEvents(scanDir, reconnectingEvents(), {
      onReconnect: (attempt, maxAttempts) =>
        reconnects.push([attempt, maxAttempts]),
    });

    await reconnectSeen;
    expect(closed).toBe(false);
    expect(reconnects).toEqual([[2, 5]]);
    release();

    await expect(result).resolves.toBeDefined();
    expect(closed).toBe(true);
    expect(reconnects).toEqual([
      [2, 5],
      [3, 5],
    ]);
  });

  test("preserves terminal failures after reconnect notifications", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      yield {
        type: "turn.failed",
        error: { message: "retry budget exhausted" },
      };
    }

    await expect(runEvents(scanDir, failedEvents())).rejects.toMatchObject({
      name: CodexSecurityError.name,
      message: "retry budget exhausted",
    });
  });

  test("fails the scan for every turn.failed error payload shape", async () => {
    const usage = {
      input_tokens: 10,
      cached_input_tokens: 2,
      cache_write_input_tokens: 0,
      output_tokens: 3,
      reasoning_output_tokens: 1,
    };
    const payloads: Array<[string, unknown]> = [
      ["object message", { message: "model refused the turn" }],
      ["null", null],
      ["undefined", undefined],
      ["string", "model refused the turn"],
      ["non-string message", { message: { text: "model refused the turn" } }],
      ["array", ["model refused the turn"]],
      ["blank message", { message: "   " }],
    ];
    for (const [label, error] of payloads) {
      // A complete, valid artifact bundle so the failed turn is the only variable.
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      async function* failedEvents(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "turn.completed", usage };
        yield { type: "turn.failed", error } as unknown as ThreadEvent;
      }
      await expect(
        runEvents(scanDir, failedEvents()),
        `turn.failed carrying ${label} must fail the scan`,
      ).rejects.toMatchObject({ name: CodexSecurityError.name });
    }
  });

  test("reuses only a nested turn.failed message and falls back otherwise", async () => {
    const usage = {
      input_tokens: 10,
      cached_input_tokens: 2,
      cache_write_input_tokens: 0,
      output_tokens: 3,
      reasoning_output_tokens: 1,
    };
    async function* failedWith(error: unknown): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.completed", usage };
      yield { type: "turn.failed", error } as unknown as ThreadEvent;
    }

    await expect(
      runEvents(
        await copyCompletedScan(await temporaryDirectory()),
        failedWith({ message: "retry budget exhausted" }),
      ),
    ).rejects.toMatchObject({
      name: CodexSecurityError.name,
      message: "retry budget exhausted",
    });

    await expect(
      runEvents(
        await copyCompletedScan(await temporaryDirectory()),
        failedWith("token sk-proj-EXAMPLE1234567890 rejected"),
      ),
    ).rejects.toMatchObject({
      name: CodexSecurityError.name,
      message:
        "The Codex Security scan turn failed without a readable error message.",
    });

    await expect(
      runEvents(
        await copyCompletedScan(await temporaryDirectory()),
        failedWith({ code: 500 }),
      ),
    ).rejects.toMatchObject({
      name: CodexSecurityError.name,
      message:
        "The Codex Security scan turn failed without a readable error message.",
    });
  });

  test("extracts bounded rate-limit context from reconnect notifications", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: Array<{
      attempt: number;
      maxAttempts: number;
      details?: ScanReconnectDetails;
    }> = [];

    async function* events(): AsyncGenerator<ThreadEvent> {
      yield {
        type: "error",
        message:
          "Reconnecting... 2/5 (Rate limit reached for org-private. Please try again in 1.2s.)",
      };
      yield {
        type: "error",
        message:
          "Reconnecting... 3/5 (Rate limit reached. Please try again in 999999s.)",
      };
      yield { type: "error", message: "Reconnecting... 4/5" };
      yield* completedEvents();
    }

    await runEvents(scanDir, events(), {
      onReconnect: (attempt, maxAttempts, details) => {
        reconnects.push({
          attempt,
          maxAttempts,
          ...(details ? { details } : {}),
        });
      },
    });

    expect(reconnects).toEqual([
      {
        attempt: 2,
        maxAttempts: 5,
        details: { reason: "rate_limit", retryAfterSeconds: 1.2 },
      },
      { attempt: 3, maxAttempts: 5, details: { reason: "rate_limit" } },
      { attempt: 4, maxAttempts: 5 },
    ]);
    expect(JSON.stringify(reconnects)).not.toContain("org-private");
  });

  test("classifies retryable reconnect causes without exposing provider details", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const reconnects: ScanReconnectDetails[] = [];

    async function* events(): AsyncGenerator<ThreadEvent> {
      yield {
        type: "error",
        message: "Reconnecting... 1/5 (ECONNRESET org-private)",
      };
      yield {
        type: "error",
        message: "Reconnecting... 2/5 (429 rate limit reached org-private)",
      };
      yield* completedEvents();
    }

    await runEvents(scanDir, events(), {
      onReconnect: (_a, _m, detail) => {
        if (detail !== undefined) reconnects.push(detail);
      },
    });

    expect(reconnects).toEqual([
      { reason: "network" },
      { reason: "rate_limit" },
    ]);
    expect(JSON.stringify(reconnects)).not.toContain("org-private");
  });

  test("fails immediately on definitive authentication and authorization errors", async () => {
    for (const message of [
      "Reconnecting... 1/5 (401 invalid API key org-private)",
      "Reconnecting... 1/5 (403 model access denied org-private)",
    ]) {
      const scanDir = join(await temporaryDirectory(), "partial-scan");
      await mkdir(scanDir, { mode: 0o700 });
      const reconnects: Array<[number, number]> = [];
      let advancedPastFailure = false;

      async function* events(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "error", message };
        advancedPastFailure = true;
        yield { type: "error", message: "Reconnecting... 2/5" };
      }

      await expect(
        runEvents(scanDir, events(), {
          onReconnect: (attempt, maxAttempts) => {
            reconnects.push([attempt, maxAttempts]);
          },
        }),
      ).rejects.toMatchObject({ name: CodexSecurityError.name, message });
      expect(reconnects).toEqual([]);
      expect(advancedPastFailure).toBe(false);
    }
  });

  test("uses the last reconnect error when Codex ends without a terminal event", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* incompleteEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield { type: "error", message: "Reconnecting... 2/5" };
    }

    await expect(runEvents(scanDir, incompleteEvents())).rejects.toMatchObject({
      name: IncompleteScanError.name,
      message: "Reconnecting... 2/5",
    });
  });

  test("keeps non-reconnect stream errors terminal", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    for (const message of ["stream disconnected", "Reconnecting... 6/5"]) {
      async function* failedEvents(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "turn.started" };
        yield { type: "error", message: "Reconnecting... 2/5" };
        yield { type: "error", message };
      }

      await expect(runEvents(scanDir, failedEvents())).rejects.toMatchObject({
        name: CodexSecurityError.name,
        message,
      });
    }
  });

  test("preserves subprocess failures after reconnect notifications", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      throw new Error("Codex Exec exited with code 1");
    }

    await expect(runEvents(scanDir, failedEvents())).rejects.toThrow(
      "Codex Exec exited with code 1",
    );
  });

  test("forwards bounded worker-capacity updates while the scan runs", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const statuses: ScanWorkerStatus[] = [];
    async function* workerEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield {
        type: "item.completed",
        item: {
          id: "command-1",
          type: "command_execution",
          command:
            "python3 /plugin/scripts/config_preflight.py --profile security_scan",
          aggregated_output: JSON.stringify({
            profile: "security_scan",
            status: "ready",
            results: [
              { capability: "delegated_workers", status: "pass" },
              {
                capability: "usable_worker_slots_6",
                status: "pass",
                actual: 8,
              },
            ],
          }),
          exit_code: 0,
          status: "completed",
        },
      };
      yield {
        type: "item.completed",
        item: {
          id: "message-1",
          type: "agent_message",
          text: 'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":6,"started":3}',
        },
      };
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
          reasoning_output_tokens: 1,
        },
      };
    }

    await expect(
      runEvents(scanDir, workerEvents(), {
        onWorkerStatus: (status) => statuses.push(status),
      }),
    ).resolves.toBeDefined();
    expect(statuses).toEqual([
      { kind: "preflight", delegation: "available", configuredSlots: 8 },
      { kind: "dispatch", phase: "ranking", planned: 6, started: 3 },
    ]);
  });

  test("forwards real file activity as commands start and complete", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const activities: ScanActivity[] = [];

    async function* activityEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      for (const [type, status] of [
        ["item.started", "in_progress"],
        ["item.completed", "completed"],
      ] as const) {
        yield {
          type,
          item: {
            id: "file-review-1",
            type: "command_execution",
            command: 'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
            aggregated_output: "",
            status,
          },
        };
      }
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
          reasoning_output_tokens: 1,
        },
      };
    }

    await expect(
      runEvents(scanDir, activityEvents(), {
        onActivity: (activity) => activities.push(activity),
      }),
    ).resolves.toBeDefined();
    expect(activities).toEqual([
      {
        id: "file-review-1",
        kind: "command",
        status: "running",
        description: 'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
        paths: ["routes/login.ts"],
      },
      {
        id: "file-review-1",
        kind: "command",
        status: "completed",
        description: 'nl -ba "$CODEX_SECURITY_REPOSITORY/routes/login.ts"',
        paths: ["routes/login.ts"],
      },
    ]);
  });

  test("forwards separate main-agent reasoning summaries", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const activities: ScanActivity[] = [];

    async function* reasoningEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield {
        type: "item.completed",
        item: {
          id: "reasoning-1",
          type: "reasoning",
          text:
            "**Implementing safe fallback file generation**\n\n" +
            "**Planning batch file size verification and progress output**",
        },
      };
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
          reasoning_output_tokens: 1,
        },
      };
    }

    await runEvents(scanDir, reasoningEvents(), {
      onActivity: (activity) => activities.push(activity),
    });

    expect(activities).toEqual([
      expect.objectContaining({
        id: "reasoning-1",
        kind: "reasoning",
        description: "Implementing safe fallback file generation",
      }),
      expect.objectContaining({
        id: "reasoning-1:1",
        kind: "reasoning",
        description:
          "Planning batch file size verification and progress output",
      }),
    ]);
  });

  test("forwards real phase and reviewed-file progress while the scan runs", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const updates: ScanProgress[] = [];

    async function* progressEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      for (const text of [
        'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":0,"filesTotal":8}',
        'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
        'CODEX_SECURITY_SCAN_PROGRESS {"phase":"validation","filesCompleted":8,"filesTotal":8}',
      ]) {
        yield {
          type: "item.completed",
          item: {
            id: `progress-${updates.length}`,
            type: "agent_message",
            text,
          },
        };
      }
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
          reasoning_output_tokens: 1,
        },
      };
    }

    await expect(
      runEvents(scanDir, progressEvents(), {
        onProgress: (progress) => updates.push(progress),
      }),
    ).resolves.toBeDefined();
    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 0, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "validation", filesCompleted: 8, filesTotal: 8 },
    ]);
  });

  test("forwards every file count printed by a completed review command", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const updates: ScanProgress[] = [];

    async function* progressEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "turn.started" };
      yield {
        type: "item.completed",
        item: {
          id: "file-review-1",
          type: "command_execution",
          command: "review the two files in the inventory",
          aggregated_output: [
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":3,"filesTotal":8}',
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":0,"filesTotal":2}',
            "--- commands.py ---",
            "--- server.py ---",
            'CODEX_SECURITY_SCAN_PROGRESS {"phase":"discovery","filesCompleted":2,"filesTotal":2}',
          ].join("\n"),
          exit_code: 0,
          status: "completed",
        },
      };
      yield {
        type: "turn.completed",
        usage: {
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
          reasoning_output_tokens: 1,
        },
      };
    }

    await expect(
      runEvents(scanDir, progressEvents(), {
        expectedFilesTotal: 2,
        onProgress: (progress) => updates.push(progress),
      }),
    ).resolves.toBeDefined();
    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 0, filesTotal: 2 },
      { phase: "discovery", filesCompleted: 2, filesTotal: 2 },
    ]);
  });
});
