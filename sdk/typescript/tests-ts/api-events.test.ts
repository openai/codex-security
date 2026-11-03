import { copyCompletedScan, PLUGIN_ROOT } from "./plugin-root.js";
import { once } from "node:events";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  Codex,
  type McpToolCallItem,
  type ThreadEvent,
} from "@openai/codex-sdk";
import { afterEach, describe, expect, test, mock } from "bun:test";
import {
  CodexSecurityError,
  ContractValidationError,
  IncompleteScanError,
  ScanInterruptedError,
  type ScanActivity,
  type ScanProgress,
  type ScanTrustedAccessStatus,
  type ScanWorkerStatus,
} from "../src/index.js";
import {
  collectObserverErrors,
  completedEvents,
  completedTurn,
  runEvents,
  type ScanObserverName,
} from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { runScanEvents } from "../src/api.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();

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
  for (const item of items) {
    yield { type: "item.completed", item };
  }
  yield {
    type: "item.completed",
    item: { id: "message-1", type: "agent_message", text: "scan complete" },
  };
}

async function runTacEvents(
  scanDir: string,
  items: readonly McpToolCallItem[],
  options: Parameters<typeof runEvents>[2] = {},
) {
  const warnings: string[] = [];
  const statuses: ScanTrustedAccessStatus[] = [];
  const result = await runEvents(
    scanDir,
    completedEvents("thread-1", tacEvents(items)),
    {
      onWarning: (warning) => warnings.push(warning),
      onTrustedAccessStatus: (status) => statuses.push(status),
      ...options,
    },
  );
  expect(result.turnResult.status).toBe("completed");
  return { warnings, statuses };
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
    expect(result.cost).toMatchObject({
      model: "gpt-5.6-sol",
      inputTokens: 10,
      cachedInputTokens: 2,
      cacheWriteInputTokens: 0,
      outputTokens: 3,
      estimatedUsd: 0.0000928,
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

  test.each([
    ["granted", []],
    [
      "not_granted",
      [
        "Some cybersecurity requests or findings may be refused because your account does not have Trusted Access for Cyber. Apply at https://chatgpt.com/cyber.",
      ],
    ],
    [
      "unknown",
      [
        "Some cybersecurity requests or findings may be refused because your Trusted Access for Cyber status could not be verified. Check your access or apply at https://chatgpt.com/cyber.",
      ],
    ],
  ] as const)(
    "reports %s trusted cyber access once",
    async (status, warnings) => {
      const scanDir = await copyCompletedScan(await temporaryDirectory());
      const item = tacToolCall(status);
      expect(await runTacEvents(scanDir, [item, item])).toEqual({
        warnings: [...warnings],
        statuses: [status],
      });
    },
  );

  test("directs API-key scans to the organizational trusted cyber application", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const expected = {
      not_granted:
        "Some cybersecurity requests or findings may be refused because your API organization does not have Trusted Access for Cyber. Apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
      unknown:
        "Some cybersecurity requests or findings may be refused because Trusted Access for Cyber for your API organization could not be verified. Check your organization's access or apply at https://openai.com/form/enterprise-trusted-access-for-cyber/.",
    };
    const stored = {
      method: "stored_credentials",
      credentialType: "api_key",
      verified: false,
    } as const;
    for (const [authentication, status] of [
      [
        { method: "api_key", source: "OPENAI_API_KEY", verified: false },
        "not_granted",
      ],
      [
        { method: "api_key", source: "CODEX_API_KEY", verified: false },
        "unknown",
      ],
      [stored, "not_granted"],
      [stored, "unknown"],
    ] as const) {
      const { warnings } = await runTacEvents(scanDir, [tacToolCall(status)], {
        authentication,
      });
      expect(warnings).toEqual([expected[status]]);
    }
  });

  test("does not apply ChatGPT account advisories to Bedrock scans", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    for (const authentication of [
      { method: "aws_credentials", source: "AWS_PROFILE", verified: false },
      { method: "command", verified: false },
    ] as const) {
      for (const status of ["granted", "not_granted", "unknown"] as const) {
        expect(
          await runTacEvents(scanDir, [tacToolCall(status)], {
            authentication,
            modelProvider: "amazon-bedrock",
          }),
        ).toEqual({ warnings: [], statuses: [] });
      }
    }
  });

  test("preserves Bedrock failures after an inapplicable account advisory", async () => {
    const scanDir = join(await temporaryDirectory(), "partial-scan");
    await mkdir(scanDir, { mode: 0o700 });
    const message =
      "HTTP 403 ExpiredTokenException: The security token included in the request is expired";
    const warnings: string[] = [];
    async function* events(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield { type: "item.completed", item: tacToolCall("not_granted") };
      yield { type: "turn.failed", error: { message } };
    }

    await expect(
      runEvents(scanDir, events(), {
        authentication: {
          method: "aws_credentials",
          source: "AWS_PROFILE",
          verified: false,
        },
        modelProvider: "amazon-bedrock",
        onWarning: (warning) => warnings.push(warning),
      }),
    ).rejects.toMatchObject({ name: CodexSecurityError.name, message });
    expect(warnings).toEqual([]);
  });

  test("does not mistake external-provider keys for OpenAI API organizations", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    for (const source of [
      "OPENROUTER_API_KEY",
      "FIREWORKS_API_KEY",
      "CHEAPER_INFERENCE_API_KEY",
    ] as const) {
      for (const status of ["not_granted", "unknown"] as const) {
        const { warnings } = await runTacEvents(
          scanDir,
          [tacToolCall(status)],
          {
            authentication: { method: "api_key", source, verified: false },
          },
        );
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
    const { warnings } = await runTacEvents(scanDir, [
      tacToolCall("unknown", {
        status: "failed",
        result: undefined,
        error: { message: "SYNTHETIC_PRIVATE_PROVIDER_ERROR" },
      }),
    ]);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("https://chatgpt.com/cyber");
    expect(warnings[0]).not.toContain("SYNTHETIC_PRIVATE_PROVIDER_ERROR");
  });

  test("treats malformed or stale trusted cyber access results as unverified", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
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
      const { warnings } = await runTacEvents(scanDir, [
        tacToolCall("granted", {
          result: { content: [], structured_content: structuredContent },
        }),
      ]);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toContain("could not be verified");
    }
  });

  test("does not trust similarly named tools from other MCP servers", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const { warnings, statuses } = await runTacEvents(scanDir, [
      tacToolCall("not_granted", { server: "untrusted_server" }),
      tacToolCall("not_granted", { tool: "unrelated_tool" }),
      tacToolCall("granted"),
    ]);
    expect(warnings).toEqual([]);
    expect(statuses).toEqual(["granted"]);
  });

  test("captures warning observers before payload evaluation and isolates failures", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const observerErrors: Array<[ScanObserverName, string]> = [];
    const replacement = mock();
    let warningPending = false;
    let onWarning: () => void = function (this: void) {
      expect(this).toBeUndefined();
      throw new Error("TAC warning observer failed");
    };
    let onObserverError = function (
      this: void,
      observer: ScanObserverName,
      error: unknown,
    ) {
      expect(this).toBeUndefined();
      observerErrors.push([observer, (error as Error).message]);
    };
    const result = await runScanEvents({
      thread: { id: null },
      events: completedEvents(
        "thread-1",
        tacEvents([tacToolCall("not_granted")]),
      ),
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
      get onTrustedAccessStatus() {
        warningPending = true;
        return undefined;
      },
      get authentication() {
        if (warningPending) {
          onWarning = replacement;
          onObserverError = replacement;
        }
        return undefined;
      },
      get onWarning() {
        return onWarning;
      },
      get onObserverError() {
        return onObserverError;
      },
    });
    expect(result.turnResult.status).toBe("completed");
    expect(observerErrors).toEqual([
      ["onWarning", "TAC warning observer failed"],
    ]);
    expect(replacement).not.toHaveBeenCalled();
  });

  test("isolates trusted cyber access status observer failures", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const observerErrors: Array<[ScanObserverName, string]> = [];

    await runTacEvents(scanDir, [tacToolCall("granted")], {
      onObserverError: collectObserverErrors(observerErrors),
      onTrustedAccessStatus: throwing("TAC status observer failed"),
    });
    expect(observerErrors).toEqual([
      ["onTrustedAccessStatus", "TAC status observer failed"],
    ]);
  });

  test("accepts target identity validated by the workbench", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const events = completedEvents();

    const result = await runEvents(
      scanDir,
      events,
      { model: undefined, workbenchValidated: true },
      "different-revision",
    );

    expect(result.threadId).toBe("thread-1");
    expect(result.turnResult.status).toBe("completed");
  });

  test("lets the workbench seal artifacts before validating completed scans", async () => {
    const root = await temporaryDirectory();
    const scanDir = await copyCompletedScan(root);
    await rm(join(scanDir, "report.md"));
    const events = completedEvents();
    let finalized = false;

    const result = await runEvents(scanDir, events, {
      model: undefined,
      onFinalize: async (usage) => {
        expect(usage).toMatchObject({
          input_tokens: 10,
          cached_input_tokens: 2,
          cache_write_input_tokens: 0,
          output_tokens: 3,
        });
        expect(existsSync(join(scanDir, "scan-manifest.json"))).toBe(true);
        expect(existsSync(join(scanDir, "report.md"))).toBe(false);
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
    const onScanStarted = mock();

    async function* failedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "error", message: "stream failed to start" };
    }

    await expect(
      runEvents(scanDir, failedEvents(), {
        onScanStarted,
      }),
    ).rejects.toThrow("stream failed to start");
    expect(onScanStarted).not.toHaveBeenCalled();
  });

  test("reports a scan as started only once if thread events are replayed", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const onScanStarted = mock(throwing("start observer exploded"));
    const observerErrors: Array<[ScanObserverName, string]> = [];

    async function* replayedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-1" };
      yield* completedEvents();
    }

    await runEvents(scanDir, replayedEvents(), {
      onScanStarted,
      onObserverError: collectObserverErrors(observerErrors),
    });

    expect(onScanStarted).toHaveBeenCalledTimes(1);
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
    const reconnectSeen = Promise.withResolvers<void>();
    async function* interruptedEvents(): AsyncGenerator<ThreadEvent> {
      yield { type: "thread.started", thread_id: "thread-2" };
      yield { type: "error", message: "Reconnecting... 2/5" };
      await once(abortController.signal, "abort");
      throw new DOMException("aborted", "AbortError");
    }
    const result = runEvents(scanDir, interruptedEvents(), {
      abortController,
      onReconnect: (attempt, maxAttempts) => {
        reconnects.push([attempt, maxAttempts]);
        reconnectSeen.resolve();
      },
    });

    await reconnectSeen.promise;
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
    const paused = Promise.withResolvers<void>();
    const reconnectSeen = Promise.withResolvers<void>();
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
        reconnectSeen.resolve();
        await paused.promise;
        yield { type: "error", message: "Reconnecting… 3/5" };
        yield {
          type: "item.completed",
          item: {
            id: "message-1",
            type: "agent_message",
            text: "scan complete",
          },
        };
        yield completedTurn();
      } finally {
        closed = true;
      }
    }
    const result = runEvents(scanDir, reconnectingEvents(), {
      onReconnect: (attempt, maxAttempts) =>
        reconnects.push([attempt, maxAttempts]),
    });

    await reconnectSeen.promise;
    expect(closed).toBe(false);
    expect(reconnects).toEqual([[2, 5]]);
    paused.resolve();

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

  test("fails the scan for every turn.failed payload, reporting only readable nested messages", async () => {
    const fallback =
      "The Codex Security scan turn failed without a readable error message.";
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const payloads: Array<[string, unknown, string]> = [
      [
        "object message",
        { message: "model refused the turn" },
        "model refused the turn",
      ],
      ["null", null, fallback],
      ["undefined", undefined, fallback],
      ["raw string", "token sk-proj-EXAMPLE1234567890 rejected", fallback],
      [
        "non-string message",
        { message: { text: "model refused the turn" } },
        fallback,
      ],
      ["array", ["model refused the turn"], fallback],
      ["blank message", { message: "   " }, fallback],
      ["missing message", { code: 500 }, fallback],
    ];
    for (const [label, error, message] of payloads) {
      async function* failedEvents(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield completedTurn();
        yield { type: "turn.failed", error } as unknown as ThreadEvent;
      }
      await expect(
        runEvents(scanDir, failedEvents()),
        `turn.failed carrying ${label}`,
      ).rejects.toMatchObject({ name: CodexSecurityError.name, message });
    }
  });

  test("classifies reconnect causes and bounds the reported retry delay", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const onReconnect = mock();
    async function* events(): AsyncGenerator<ThreadEvent> {
      for (const message of [
        "Reconnecting... 1/5 (ECONNRESET org-private)",
        "Reconnecting... 2/5 (Rate limit reached for org-private. Please try again in 1.2s.)",
        "Reconnecting... 3/5 (Rate limit reached. Please try again in 999999s.)",
        "Reconnecting... 4/5",
        "Reconnecting... 5/5 (429 rate limit reached org-private)",
      ])
        yield { type: "error", message };
      yield* completedEvents();
    }
    await runEvents(scanDir, events(), { onReconnect });
    expect(onReconnect.mock.calls).toEqual([
      [1, 5, { reason: "network" }],
      [2, 5, { reason: "rate_limit", retryAfterSeconds: 1.2 }],
      [3, 5, { reason: "rate_limit" }],
      [4, 5, undefined],
      [5, 5, { reason: "rate_limit" }],
    ]);
  });

  test("fails immediately on definitive authentication and authorization errors", async () => {
    for (const message of [
      "Reconnecting... 1/5 (401 invalid API key org-private)",
      "Reconnecting... 1/5 (403 model access denied org-private)",
    ]) {
      const scanDir = join(await temporaryDirectory(), "partial-scan");
      await mkdir(scanDir, { mode: 0o700 });
      const reconnects = mock((_attempt: number, _maxAttempts: number) => {});
      let advancedPastFailure = false;

      async function* events(): AsyncGenerator<ThreadEvent> {
        yield { type: "thread.started", thread_id: "thread-1" };
        yield { type: "error", message };
        advancedPastFailure = true;
        yield { type: "error", message: "Reconnecting... 2/5" };
      }

      await expect(
        runEvents(scanDir, events(), {
          onReconnect: reconnects,
        }),
      ).rejects.toMatchObject({ name: CodexSecurityError.name, message });
      expect(reconnects).not.toHaveBeenCalled();
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

  test("forwards worker dispatch updates while the scan runs", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const statuses: ScanWorkerStatus[] = [];
    async function* workerEvents(): AsyncGenerator<ThreadEvent> {
      yield {
        type: "item.completed",
        item: {
          id: "message-1",
          type: "agent_message",
          text: 'CODEX_SECURITY_WORKER_STATUS {"phase":"ranking","planned":6,"started":3}',
        },
      };
    }

    await expect(
      runEvents(scanDir, completedEvents("thread-1", workerEvents()), {
        onWorkerStatus: (status) => statuses.push(status),
      }),
    ).resolves.toBeDefined();
    expect(statuses).toEqual([
      { kind: "dispatch", phase: "ranking", planned: 6, started: 3 },
    ]);
  });

  test("forwards real file activity as commands start and complete", async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const activities: ScanActivity[] = [];

    async function* activityEvents(): AsyncGenerator<ThreadEvent> {
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
    }

    await expect(
      runEvents(scanDir, completedEvents("thread-1", activityEvents()), {
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
    }

    await runEvents(scanDir, completedEvents("thread-1", reasoningEvents()), {
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
    }

    await expect(
      runEvents(scanDir, completedEvents("thread-1", progressEvents()), {
        onProgress: (progress) => updates.push(progress),
      }),
    ).resolves.toBeDefined();
    expect(updates).toEqual([
      { phase: "discovery", filesCompleted: 0, filesTotal: 8 },
      { phase: "discovery", filesCompleted: 3, filesTotal: 8 },
      { phase: "validation", filesCompleted: 8, filesTotal: 8 },
    ]);
  });
});

test.each(["scan-manifest.json", "findings.json", "report.md"])(
  "missing required artifact %s remains an incomplete scan",
  async (name) => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    await rm(join(scanDir, name));
    await expect(runEvents(scanDir, completedEvents())).rejects.toMatchObject({
      name: IncompleteScanError.name,
      message: `Codex Security scan completed without required artifacts: ${name}`,
    });
  },
);

test("an aborted completed turn cannot prepare workbench artifacts", async () => {
  const abortController = new AbortController();
  let finalizations = 0;
  async function* events() {
    yield { type: "thread.started", thread_id: "synthetic-thread" } as const;
    yield { type: "turn.started" } as const;
    abortController.abort("synthetic cancellation");
    yield completedTurn();
  }
  await expect(
    runEvents("/synthetic-scan", events(), {
      abortController,
      workbenchValidated: true,
      onFinalize: async () => {
        finalizations++;
      },
    }),
  ).rejects.toMatchObject({ name: ScanInterruptedError.name });
  expect(finalizations).toBe(0);
});

test("workbench reconciliation precedes admission of canonical artifacts", async () => {
  const scanDir = await copyCompletedScan(await temporaryDirectory());
  const file = join(scanDir, "scan-manifest.json");
  const original = await readFile(file, "utf8");
  const interrupted = JSON.parse(original);
  interrupted.scan.complete = false;
  await writeFile(file, JSON.stringify(interrupted));
  let reconciliations = 0;
  const result = await runEvents(scanDir, completedEvents(), {
    workbenchValidated: true,
    onFinalize: async () => {
      reconciliations++;
      await writeFile(file, original);
    },
  });
  expect(reconciliations).toBe(1);
  expect(result.turnResult.status).toBe("completed");
});

test.skipIf(process.platform === "win32")(
  "preserves unsafe scan-root diagnostics instead of reporting missing files",
  async () => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const parent = dirname(scanDir);
    await chmod(parent, 0o777);
    try {
      await expect(runEvents(scanDir, completedEvents())).rejects.toMatchObject(
        {
          name: ContractValidationError.name,
          message: expect.stringContaining("sticky bit"),
          cause: expect.any(Error),
        },
      );
    } finally {
      await chmod(parent, 0o700);
    }
  },
);
