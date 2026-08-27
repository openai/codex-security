// @modelcontextprotocol/sdk@1.29.0 publishes declaration maps without declaration files.
// Keep this narrow shim until the upstream package restores its server declarations.
declare module "@modelcontextprotocol/sdk/server/mcp.js" {
  export type RegisteredTool = unknown;
  export type ToolCallback<T = unknown> = (
    args: T extends Record<string, import("zod/v4").ZodType>
      ? { [K in keyof T]: import("zod/v4").output<T[K]> }
      : unknown,
    extra: unknown
  ) => unknown;
  export class McpServer {
    constructor(serverInfo: unknown, options?: unknown);
    readonly server: {
      onclose?: () => void;
      getClientCapabilities(): import("@modelcontextprotocol/sdk/types.js").ClientCapabilities | undefined;
      elicitInput(
        params: {
          mode: "form";
          message: string;
          requestedSchema: {
            type: "object";
            properties: Record<string, unknown>;
            required?: string[];
          };
        },
        options?: { signal?: AbortSignal; timeout?: number }
      ): Promise<{
        action: "accept" | "decline" | "cancel";
        content?: Record<string, unknown>;
      }>;
    };
    close(): Promise<void>;
    connect(transport: unknown): Promise<void>;
    sendLoggingMessage(
      params: {
        data: unknown;
        level: "debug" | "info" | "notice" | "warning" | "error" | "critical" | "alert" | "emergency";
        logger?: string;
      },
      sessionId?: string
    ): Promise<void>;
    registerTool<
      T extends Record<string, import("zod/v4").ZodType> | import("zod/v4").ZodType
    >(
      name: string,
      config: {
        annotations?: Record<string, unknown>;
        description?: string;
        inputSchema: T;
        title?: string;
        _meta?: Record<string, unknown>;
      },
      callback: ToolCallback<T>
    ): RegisteredTool;
  }
}

declare module "@modelcontextprotocol/sdk/server/stdio.js" {
  export class StdioServerTransport {
    constructor(...args: unknown[]);
  }
}
