import { PassThrough, Writable } from "node:stream";
import { setImmediate } from "node:timers/promises";
import { describe, expect, test } from "bun:test";
import type { CallToolResult, Tool } from "@modelcontextprotocol/server";
import { main } from "../src/cli.js";
import { ConfigurationError } from "../src/errors.js";
import type { ScanOptions } from "../src/api.js";
import {
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
  FakeSignals,
} from "./cli-fixtures.js";
import { BUNDLED_PLUGIN_VERSION, VERSION } from "../src/version.js";

async function connect(
  deps = dependencies(),
  finishWrite: (callback: (error?: Error | null) => void) => void = (
    callback,
  ) => callback(),
) {
  const input = new PassThrough();
  const stderr = capture(true);
  const responses = new Map<string | number, unknown>();
  const waiting = new Map<string | number, (result: unknown) => void>();
  let partial = "";
  const output = new Writable({
    write(chunk, _encoding, callback) {
      partial += chunk.toString();
      let newline: number;
      while ((newline = partial.indexOf("\n")) !== -1) {
        // Every stdout line must be protocol JSON, even while scans report progress.
        const response = JSON.parse(partial.slice(0, newline));
        partial = partial.slice(newline + 1);
        if (
          typeof response.id === "number" ||
          typeof response.id === "string"
        ) {
          responses.set(response.id, response.result ?? response.error);
          waiting.get(response.id)?.(response.result ?? response.error);
          waiting.delete(response.id);
        }
      }
      finishWrite(callback);
    },
  });
  const serving = main(["--mcp"], output, stderr.stream, {
    ...deps,
    mcpInput: input,
  });
  let id = 0;
  const send = (message: object) => input.write(JSON.stringify(message) + "\n");
  const request = <T>(
    method: string,
    params: object = {},
    requestId: string | number = ++id,
  ) => {
    const result = new Promise<T>((resolve) => {
      waiting.set(requestId, (value) => resolve(value as T));
    });
    send({ jsonrpc: "2.0", id: requestId, method, params });
    return { id: requestId, result };
  };
  await request("initialize", {
    protocolVersion: "2025-11-25",
    capabilities: {},
    clientInfo: { name: "codex-security-test", version: "1.0.0" },
  }).result;
  send({ jsonrpc: "2.0", method: "notifications/initialized" });
  return {
    input,
    output,
    stderr,
    serving,
    responses,
    request,
    call: (name: string, args: object = {}, requestId?: string | number) =>
      request<CallToolResult>(
        "tools/call",
        { name, arguments: args },
        requestId,
      ),
    cancel: (requestId: string | number) =>
      send({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId, reason: "test cancellation" },
      }),
    close: async () => {
      input.end();
      expect(await serving).toBe(0);
      expect(partial).toBe("");
    },
  };
}

describe("CLI MCP scans", () => {
  test("advertises scan-only inputs and read-only metadata", async () => {
    const session = await connect();
    try {
      const { tools } = await session.request<{ tools: Tool[] }>("tools/list")
        .result;
      expect(tools.map((tool) => tool.name).sort()).toEqual(["info", "scan"]);
      const scan = tools.find((tool) => tool.name === "scan")!;
      expect(scan.inputSchema.properties).toMatchObject({
        repository: { type: "string" },
        path: { type: "array", default: [] },
        auth: { default: "auto" },
        mode: { default: "standard" },
        dryRun: { type: "boolean", default: false },
        mock: { type: "boolean", default: false },
        workflowId: { type: "string" },
      });
      for (const name of ["patch", "patchSeverity", "createPr"]) {
        expect(scan.inputSchema.properties).not.toHaveProperty(name);
      }
      expect(scan.annotations).toMatchObject({
        readOnlyHint: false,
        openWorldHint: true,
      });
      expect(
        tools.find((tool) => tool.name === "info")?.annotations,
      ).toMatchObject({
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      });
      const info = await session.call("info").result;
      expect(info.structuredContent).toMatchObject({
        sdkVersion: VERSION,
        bundledPluginVersion: BUNDLED_PLUGIN_VERSION,
        scanMcp: true,
      });
      expect(JSON.parse((info.content[0] as { text: string }).text)).toEqual(
        info.structuredContent,
      );
    } finally {
      await session.close();
    }
  });

  test("runs scans with shared options, noninteractive auth and protocol-safe progress", async () => {
    const calls: unknown[] = [];
    let closed = 0;
    const deps = dependencies({
      onTurn: (repository, options) => calls.push({ repository, options }),
      onClose: () => {
        closed++;
      },
      costUpdates: [
        {
          model: "gpt-5.6-sol",
          estimatedUsd: 1,
          inputTokens: 1,
          cachedInputTokens: 0,
          cacheWriteInputTokens: 0,
          outputTokens: 1,
        },
      ],
    });
    deps.scanAuthenticationPrompt = {
      isInteractive: () => true,
      select: async () => {
        throw new Error("MCP must not prompt");
      },
    };
    deps.hasStoredChatGPTSignIn = async () => true;
    const session = await connect(deps);
    try {
      const result = await session.call("scan", {
        repository: "/synthetic/repo",
        auth: "chatgpt",
        path: ["src"],
        mode: "deep",
        workers: 2,
        maxCost: 5,
        outputDir: "/synthetic/results",
        model: "gpt-5.6-terra",
        effort: "high",
      }).result;
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        exitCode: 0,
        data: { scanDir: "/tmp/scan" },
      });
      expect(calls).toEqual([
        expect.objectContaining({
          repository: "/synthetic/repo",
          options: expect.objectContaining({
            auth: "chatgpt",
            mode: "deep",
            workers: 2,
            maxCostUsd: 5,
            onBudgetApproaching: undefined,
            outputDir: "/synthetic/results",
          }),
        }),
      ]);
      expect(closed).toBe(1);
      expect(session.stderr.text()).toContain("Scan complete");
      expect(session.stderr.text()).not.toContain("\u001b[");
    } finally {
      await session.close();
    }
  });

  test("passes mock scans and workflow reuse through to the SDK", async () => {
    const calls: unknown[] = [];
    const session = await connect(
      dependencies({ onTurn: (_repository, options) => calls.push(options) }),
    );
    try {
      const result = await session.call("scan", {
        repository: "/synthetic/repo",
        mock: true,
        workflowId: "synthetic-workflow",
      }).result;
      expect(result.isError).not.toBe(true);
      expect(calls).toEqual([
        expect.objectContaining({
          mock: true,
          workflowId: "synthetic-workflow",
        }),
      ]);
    } finally {
      await session.close();
    }
  });

  test("uses preflight for dry runs without starting a model", async () => {
    const deps = dependencies({
      onRun: () => {
        throw new Error("must not scan");
      },
    });
    const session = await connect(deps);
    try {
      const result = await session.call("scan", {
        repository: "/synthetic/repo",
        dryRun: true,
      }).result;
      expect(result.structuredContent).toMatchObject({
        exitCode: 0,
        data: { dryRun: true, repository: "/synthetic/repo" },
      });
    } finally {
      await session.close();
    }
  });

  test("rejects invalid option combinations and unsupported mutations before scanning", async () => {
    let started = 0;
    const session = await connect(
      dependencies({
        onRun: () => {
          started++;
        },
      }),
    );
    try {
      for (const input of [
        { path: ["src"], diff: "main" },
        { workingTree: true, diff: "main" },
        { head: "main" },
        { base: "main" },
        { archiveExisting: true },
        { workers: 2 },
        { maxCost: -1 },
        { mock: true, dryRun: true },
        { patch: true },
        { patchSeverity: "high" },
        { createPr: true },
      ]) {
        expect((await session.call("scan", input).result).isError).toBe(true);
      }
      expect(started).toBe(0);
      expect(await session.call("patch").result).toMatchObject({
        code: -32602,
      });
    } finally {
      await session.close();
    }
  });

  test("preserves findings and per-call failure status without stopping the server", async () => {
    for (const [result, input, exitCode] of [
      [fakeResult(["high"]), { failOnSeverity: "high" }, 1],
      [fakeResult([], "partial"), {}, 2],
    ] as const) {
      const session = await connect(dependencies({ result }));
      try {
        const response = await session.call("scan", input).result;
        expect(response.isError).toBe(true);
        expect(response.structuredContent).toMatchObject({
          exitCode,
          data: JSON.parse(JSON.stringify(result.toJSON())),
        });
        expect((await session.call("info").result).isError).not.toBe(true);
      } finally {
        await session.close();
      }
    }
    const deps = dependencies();
    deps.createSecurity = () => ({
      run: async () => {
        throw new ConfigurationError("synthetic configuration error");
      },
      preflight: async () => fakePreflight(),
      close: async () => {},
    });
    const session = await connect(deps);
    try {
      expect(
        (await session.call("scan").result).structuredContent,
      ).toMatchObject({
        exitCode: 2,
        error: expect.stringContaining("synthetic configuration error"),
      });
    } finally {
      await session.close();
    }
  });

  test.each([0, "", "0", 42])(
    "cancels only scan request %j and waits for its cleanup",
    async (requestId) => {
      const started = Promise.withResolvers<void>();
      const healthyStarted = Promise.withResolvers<AbortSignal>();
      const finishHealthy = Promise.withResolvers<void>();
      const stopped = Promise.withResolvers<void>();
      const deps = dependencies();
      deps.createSecurity = () => {
        let canceledScan = false;
        return {
          run: async (repository, options) => {
            canceledScan = repository === "/synthetic/cancel";
            if (!canceledScan) {
              healthyStarted.resolve(options!.signal!);
              await finishHealthy.promise;
              return fakeResult();
            }
            started.resolve();
            await new Promise<void>((resolve) =>
              options!.signal!.addEventListener("abort", () => resolve(), {
                once: true,
              }),
            );
            throw new DOMException("Canceled", "AbortError");
          },
          preflight: async () => fakePreflight(),
          close: async () => {
            if (canceledScan) stopped.resolve();
          },
        };
      };
      const session = await connect(deps);
      try {
        const canceled = session.call(
          "scan",
          {
            repository: "/synthetic/cancel",
          },
          requestId,
        );
        const healthy = session.call(
          "scan",
          {
            repository: "/synthetic/complete",
          },
          requestId === "0" ? 0 : "0",
        );
        await started.promise;
        const healthySignal = await healthyStarted.promise;
        session.cancel(canceled.id);
        await stopped.promise;
        expect(healthySignal.aborted).toBe(false);
        finishHealthy.resolve();
        const completed = await healthy.result;
        expect(completed.structuredContent).toMatchObject({ exitCode: 0 });
        expect(session.responses.has(canceled.id)).toBe(false);
        expect((await session.call("info").result).isError).not.toBe(true);
      } finally {
        finishHealthy.resolve();
        await session.close();
      }
    },
  );

  test.each([0, "", "0"])(
    "honors immediate cancellation of request %j before starting a scan",
    async (requestId) => {
      let started = 0;
      const session = await connect(
        dependencies({
          onRun: () => {
            started++;
          },
        }),
      );
      try {
        session.call("scan", {}, requestId);
        session.cancel(requestId);
        await session.call("info").result;
        await setImmediate();
        expect(started).toBe(0);
        expect(session.responses.has(requestId)).toBe(false);
      } finally {
        await session.close();
      }
    },
  );

  test.each([0, ""])(
    "ignores unknown and late cancellations of request %j",
    async (requestId) => {
      const session = await connect();
      try {
        session.cancel(requestId);
        expect(
          (await session.call("scan", {}, requestId).result).structuredContent,
        ).toMatchObject({ exitCode: 0 });
        session.cancel(requestId);
        expect(
          (await session.call("scan", {}, requestId).result).structuredContent,
        ).toMatchObject({ exitCode: 0 });
      } finally {
        await session.close();
      }
    },
  );

  test("handles a buffered stdout failure after EOF while scan cleanup is pending", async () => {
    let bufferOutput = false;
    const pendingWrite =
      Promise.withResolvers<(error?: Error | null) => void>();
    const started = Promise.withResolvers<void>();
    const cleanupStarted = Promise.withResolvers<void>();
    const finishCleanup = Promise.withResolvers<void>();
    const deps = dependencies();
    deps.createSecurity = () => ({
      run: async (_repository, options) => {
        started.resolve();
        await new Promise<void>((resolve) =>
          options!.signal!.addEventListener("abort", () => resolve(), {
            once: true,
          }),
        );
        throw new DOMException("Canceled", "AbortError");
      },
      preflight: async () => fakePreflight(),
      close: async () => {
        cleanupStarted.resolve();
        await finishCleanup.promise;
      },
    });
    const session = await connect(deps, (callback) => {
      if (bufferOutput) pendingWrite.resolve(callback);
      else callback();
    });
    try {
      session.call("scan");
      await started.promise;
      bufferOutput = true;
      session.call("info");
      const finishWrite = await pendingWrite.promise;
      session.input.end();
      await cleanupStarted.promise;
      finishWrite(new Error("synthetic broken pipe"));
      await setImmediate();
    } finally {
      finishCleanup.resolve();
      expect(await session.serving).toBe(0);
    }
    expect(session.output.listenerCount("error")).toBe(0);
  });

  test.each(["info", "scan"])(
    "handles a buffered %s response failure after main returns",
    async (name) => {
      let bufferOutput = false;
      let scansClosed = 0;
      const pendingWrite =
        Promise.withResolvers<(error?: Error | null) => void>();
      const session = await connect(
        dependencies({
          onClose: () => {
            scansClosed++;
          },
        }),
        (callback) => {
          if (bufferOutput) pendingWrite.resolve(callback);
          else callback();
        },
      );
      bufferOutput = true;
      const response = session.call(name);
      const finishWrite = await pendingWrite.promise;
      expect((await response.result).isError).not.toBe(true);
      session.input.end();
      expect(await session.serving).toBe(0);
      expect(scansClosed).toBe(name === "scan" ? 1 : 0);
      expect(session.output.writableLength).toBeGreaterThan(0);
      finishWrite(new Error("synthetic broken pipe after shutdown"));
      await setImmediate();
      expect(session.output.closed).toBe(true);
      expect(session.output.listenerCount("error")).toBe(0);
    },
  );

  test("disconnects abort preparation and active scans, preserve artifacts, and await cleanup", async () => {
    for (const phase of [
      "preparation",
      "scan",
      "preflight",
      "output-close",
      "output-error",
    ] as const) {
      const started = Promise.withResolvers<void>();
      const canceled = Promise.withResolvers<void>();
      const finishCleanup = Promise.withResolvers<void>();
      const deps = dependencies();
      const waitForCancellation = async (options: ScanOptions | undefined) => {
        if (phase === "scan") options!.onOutputDirReady?.("/synthetic/partial");
        started.resolve();
        await new Promise<void>((resolve) =>
          options!.signal!.addEventListener("abort", () => resolve(), {
            once: true,
          }),
        );
        canceled.resolve();
        throw new DOMException("Canceled", "AbortError");
      };
      deps.createSecurity = () => ({
        run: async (_repository, options) => waitForCancellation(options),
        preflight: async (_repository, options) => waitForCancellation(options),
        close: async () => {
          await finishCleanup.promise;
        },
      });
      const session = await connect(deps);
      session.call("scan", { dryRun: phase === "preflight" });
      await started.promise;
      let finished = false;
      void session.serving.then(() => {
        finished = true;
      });
      if (phase === "output-close") session.output.destroy();
      else if (phase === "output-error")
        session.output.destroy(new Error("synthetic broken pipe"));
      else if (phase === "scan") session.input.destroy();
      else session.input.end();
      await canceled.promise;
      expect(finished).toBe(false);
      finishCleanup.resolve();
      expect(await session.serving).toBe(0);
      if (phase === "scan")
        expect(session.stderr.text()).toContain(
          "Partial output was kept at /synthetic/partial",
        );
    }
  });

  test("server signals cancel scans and remove signal handlers", async () => {
    for (const [signal, exitCode] of [
      ["SIGINT", 130],
      ["SIGTERM", 143],
    ] as const) {
      const signals = new FakeSignals();
      const started = Promise.withResolvers<void>();
      const deps = dependencies({ signals });
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
          started.resolve();
          await new Promise<void>((resolve) =>
            options!.signal!.addEventListener("abort", () => resolve(), {
              once: true,
            }),
          );
          return fakeResult();
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });
      const session = await connect(deps);
      session.call("scan");
      await started.promise;
      signals.emit(signal);
      expect(await session.serving).toBe(exitCode);
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    }
  });
});
