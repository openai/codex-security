import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import {
  ErrorCode,
  type JSONRPCMessage,
} from "@modelcontextprotocol/sdk/types.js";

// The native client's rmcp transport drops lines above 16 MiB, including the LF,
// without completing the request. Return a correlated error before that happens.
const NATIVE_STDIO_LINE_LIMIT_BYTES = 16 * 1024 * 1024;

export class CodexSecurityStdioTransport extends StdioServerTransport {
  override async send(message: JSONRPCMessage): Promise<void> {
    if (
      !("result" in message || "error" in message) ||
      message.id === undefined
    ) {
      return super.send(message);
    }

    const bytes = Buffer.byteLength(serializeMessage(message), "utf8");
    if (bytes <= NATIVE_STDIO_LINE_LIMIT_BYTES) return super.send(message);

    return super.send({
      jsonrpc: "2.0",
      id: message.id,
      error: {
        code: ErrorCode.InternalError,
        message:
          `MCP response size ${bytes} bytes exceeds the native stdio line limit of ${NATIVE_STDIO_LINE_LIMIT_BYTES} bytes. ` +
          "For paged reads, reduce the requested page byte budget and retry the same page. " +
          "The operation may already have completed; check its result before repeating a write.",
      },
    });
  }
}
