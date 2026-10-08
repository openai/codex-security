import type {
  StandardSchemaWithJSON,
  Transport,
} from "@modelcontextprotocol/server";
import { Writable, type Readable } from "node:stream";
import type {
  CliMcpCommand,
  CliMcpInput,
  CliMcpResult,
} from "./cli-mcp-commands.js";
import { z } from "incur";
import { listenForAbort } from "./cli-signals.js";
import { VERSION } from "./version.js";

export const cliMcpInstructions =
  "Use info for SDK metadata and scan to run security scans. Other command tools accept args and options matching the CLI. Commands use local credentials and can make billable model calls, modify files or scan history, and publish external issues or pull requests. Only perform operations the user has authorized. Supply explicit inputs for commands that otherwise use a terminal picker. Authentication setup and CLI integration installers remain local operator actions.";
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

export async function serveCliMcp<
  ScanInput extends Record<string, unknown>,
  InfoInput extends Record<string, unknown>,
>({
  input,
  output,
  dependencies,
  commands,
  runCommand,
  errorOutput,
  scanInputSchema,
  infoInputSchema,
  infoOutputSchema,
  runScan,
  readInfo,
}: {
  input: Readable;
  output: Writable;
  errorOutput: { write(chunk: string): unknown };
  commands: CliMcpCommand[];
  runCommand(
    command: CliMcpCommand,
    input: CliMcpInput,
    signal: AbortSignal,
    forceSignal: AbortSignal,
  ): Promise<CliMcpResult>;
  dependencies: Parameters<typeof listenForAbort>[0] & {
    forceExit(signal: "SIGINT" | "SIGTERM"): void;
  };
  scanInputSchema: StandardSchemaWithJSON<unknown, ScanInput>;
  infoInputSchema: StandardSchemaWithJSON<unknown, InfoInput>;
  infoOutputSchema: StandardSchemaWithJSON;
  runScan(input: ScanInput, signal: AbortSignal): Promise<ScanOutcome>;
  readInfo(input: InfoInput): Promise<Record<string, unknown>>;
}): Promise<number> {
  const [{ McpServer, fromJsonSchema }, { StdioServerTransport }] =
    await Promise.all([
      import("@modelcontextprotocol/server"),
      import("@modelcontextprotocol/server/stdio"),
    ]);
  const server = new McpServer(
    { name: "codex-security", version: VERSION },
    { instructions: cliMcpInstructions },
  );
  const pending = new Set<Promise<unknown>>();
  const forceShutdown = new AbortController();
  // The pinned SDK ignores request IDs 0 and "" when handling cancellation.
  // Track them before async input validation so immediate cancellation works.
  const requestCancellation = new Map<string | number, AbortController>();
  const requestSignal = (id: string | number, signal: AbortSignal) => {
    const cancellation = requestCancellation.get(id);
    return cancellation
      ? AbortSignal.any([signal, cancellation.signal])
      : signal;
  };
  const trackedResult = async (operation: Promise<CliMcpResult>) => {
    pending.add(operation);
    try {
      const outcome = await operation;
      return {
        content: [{ type: "text" as const, text: JSON.stringify(outcome) }],
        structuredContent: { ...outcome },
        ...(outcome.exitCode === 0 ? {} : { isError: true }),
      };
    } finally {
      pending.delete(operation);
    }
  };
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
    (input, context) =>
      trackedResult(
        runScan(input, requestSignal(context.mcpReq.id, context.mcpReq.signal)),
      ),
  );
  const commandOutput = z.object({
    exitCode: z.number(),
    data: z.unknown().optional(),
    output: z.string().optional(),
    error: z.string().optional(),
    diagnostics: z.string().optional(),
  });
  for (const command of commands) {
    server.registerTool(
      command.name,
      {
        description: command.description,
        inputSchema: fromJsonSchema<CliMcpInput>(command.inputSchema),
        outputSchema: commandOutput,
        annotations: command.annotations,
      },
      (input, context) =>
        trackedResult(
          runCommand(
            command,
            input,
            requestSignal(context.mcpReq.id, context.mcpReq.signal),
            forceShutdown.signal,
          ),
        ),
    );
  }

  const stdio = new StdioServerTransport(input, output);
  const transport: Transport = {
    async start() {
      stdio.onmessage = (message) => {
        if (
          "id" in message &&
          (message.id === 0 || message.id === "") &&
          "method" in message &&
          message.method === "tools/call"
        ) {
          requestCancellation.set(message.id, new AbortController());
        } else if (
          "method" in message &&
          message.method === "notifications/cancelled"
        ) {
          const requestId = message.params?.["requestId"];
          if (requestId === 0 || requestId === "") {
            requestCancellation.get(requestId)?.abort();
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
        const cancellation = requestCancellation.get(message.id);
        requestCancellation.delete(message.id);
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
  const removeSignals = listenForAbort(dependencies, shutdown, (signal) => {
    forceShutdown.abort(signal);
    dependencies.forceExit(signal);
  });
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
  if (errorOutput instanceof Writable) {
    // Diagnostic writes can finish after a command or the server returns.
    const ignoreDiagnosticError = (): void => {};
    errorOutput.on("error", ignoreDiagnosticError);
    errorOutput.once("close", () =>
      errorOutput.off("error", ignoreDiagnosticError),
    );
  }
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
