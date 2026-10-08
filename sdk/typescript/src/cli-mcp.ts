import type {
  StandardSchemaWithJSON,
  Transport,
} from "@modelcontextprotocol/server";
import type { Readable, Writable } from "node:stream";
import { z } from "incur";
import { listenForAbort } from "./cli-signals.js";
import { VERSION } from "./version.js";

export const scanMcpInstructions =
  "Use info for SDK metadata and scan to run security scans. Scans use local credentials, can make billable model calls, and write artifacts. Only scan repositories the user has authorized. Patching and other commands remain CLI-only.";
export const scanMcpAnnotations = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
};

interface ScanOutcome {
  exitCode: number;
  data?: Record<string, unknown>;
  error?: string;
}

export async function serveScanMcp<
  ScanInput extends Record<string, unknown>,
  InfoInput extends Record<string, unknown>,
>({
  input,
  output,
  dependencies,
  scanInputSchema,
  infoInputSchema,
  infoOutputSchema,
  runScan,
  readInfo,
}: {
  input: Readable;
  output: Writable;
  dependencies: Parameters<typeof listenForAbort>[0] & {
    forceExit(signal: "SIGINT" | "SIGTERM"): void;
  };
  scanInputSchema: StandardSchemaWithJSON<unknown, ScanInput>;
  infoInputSchema: StandardSchemaWithJSON<unknown, InfoInput>;
  infoOutputSchema: StandardSchemaWithJSON;
  runScan(input: ScanInput, signal: AbortSignal): Promise<ScanOutcome>;
  readInfo(input: InfoInput): Promise<Record<string, unknown>>;
}): Promise<number> {
  const [{ McpServer }, { StdioServerTransport }] = await Promise.all([
    import("@modelcontextprotocol/server"),
    import("@modelcontextprotocol/server/stdio"),
  ]);
  const server = new McpServer(
    { name: "codex-security", version: VERSION },
    { instructions: scanMcpInstructions },
  );
  const pending = new Set<Promise<ScanOutcome>>();
  // The pinned SDK ignores request IDs 0 and "" when handling cancellation.
  // Track them before async input validation so immediate cancellation works.
  const scanCancellation = new Map<string | number, AbortController>();
  server.registerTool(
    "info",
    {
      description: "Show read-only SDK and bundled-plugin metadata.",
      inputSchema: infoInputSchema,
      outputSchema: infoOutputSchema,
      annotations: {
        readOnlyHint: true,
        idempotentHint: true,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    async (input) => {
      const data = await readInfo(input);
      return {
        content: [{ type: "text", text: JSON.stringify(data) }],
        structuredContent: data,
      };
    },
  );
  server.registerTool(
    "scan",
    {
      description:
        "Run a Codex Security scan and return its exit code and results. Uses local credentials, can incur model costs, and writes scan artifacts. Does not patch findings.",
      inputSchema: scanInputSchema,
      outputSchema: z.object({
        exitCode: z.number(),
        data: z.record(z.string(), z.unknown()).optional(),
        error: z.string().optional(),
      }),
      annotations: scanMcpAnnotations,
    },
    async (input, context) => {
      const cancellation = scanCancellation.get(context.mcpReq.id);
      const signal = cancellation
        ? AbortSignal.any([context.mcpReq.signal, cancellation.signal])
        : context.mcpReq.signal;
      const operation = runScan(input, signal);
      pending.add(operation);
      try {
        const outcome = await operation;
        return {
          content: [{ type: "text", text: JSON.stringify(outcome) }],
          structuredContent: { ...outcome },
          ...(outcome.exitCode === 0 ? {} : { isError: true }),
        };
      } finally {
        pending.delete(operation);
      }
    },
  );
  const stdio = new StdioServerTransport(input, output);
  const transport: Transport = {
    async start() {
      stdio.onmessage = (message) => {
        if (
          "id" in message &&
          (message.id === 0 || message.id === "") &&
          "method" in message &&
          message.method === "tools/call" &&
          message.params?.["name"] === "scan"
        ) {
          scanCancellation.set(message.id, new AbortController());
        } else if (
          "method" in message &&
          message.method === "notifications/cancelled"
        ) {
          const requestId = message.params?.["requestId"];
          if (requestId === 0 || requestId === "") {
            scanCancellation.get(requestId)?.abort();
          }
        }
        transport.onmessage?.(message);
      };
      stdio.onclose = () => transport.onclose?.();
      stdio.onerror = (error) => transport.onerror?.(error);
      await stdio.start();
    },
    async send(message) {
      if (
        "id" in message &&
        !("method" in message) &&
        message.id !== undefined &&
        message.id !== null
      ) {
        const cancellation = scanCancellation.get(message.id);
        scanCancellation.delete(message.id);
        if (cancellation?.signal.aborted) return;
      }
      await stdio.send(message);
    },
    close: () => stdio.close(),
  };

  const { promise: closed, resolve: resolveClosed } =
    Promise.withResolvers<void>();
  server.server.onclose = resolveClosed;
  let closing: Promise<void> | undefined;
  const stop = (): void => {
    closing ??= server.close();
    void closing.then(resolveClosed, resolveClosed);
  };
  const shutdown = new AbortController();
  shutdown.signal.addEventListener("abort", stop, { once: true });
  const removeSignals = listenForAbort(
    dependencies,
    shutdown,
    dependencies.forceExit,
  );
  // The SDK stdio transport does not close itself on EOF.
  input.once("end", stop);
  input.once("close", stop);
  input.once("error", stop);
  output.once("close", () => {
    output.off("error", stop);
    stop();
  });
  // Buffered writes can fail after EOF or after main returns.
  output.on("error", stop);
  try {
    await server.connect(transport);
    await closed;
    await Promise.allSettled(pending);
    await closing;
  } finally {
    input.off("end", stop);
    input.off("close", stop);
    input.off("error", stop);
    removeSignals();
    await server.close();
  }
  return shutdown.signal.reason === "SIGINT"
    ? 130
    : shutdown.signal.reason === "SIGTERM"
      ? 143
      : 0;
}
