import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { serializeMessage } from "@modelcontextprotocol/sdk/shared/stdio.js";
import {
  ErrorCode,
  type JSONRPCMessage,
  type RequestId,
} from "@modelcontextprotocol/sdk/types.js";

// The native client's rmcp transport drops lines above 16 MiB, including the LF,
// without completing the request. Return a correlated error before that happens.
const NATIVE_STDIO_LINE_LIMIT_BYTES = 16 * 1024 * 1024;

export class CodexSecurityStdioTransport extends StdioServerTransport {
  private readonly resultReceipts = new Map<
    RequestId,
    () => Promise<unknown>
  >();

  afterResultSent(
    id: RequestId,
    signal: AbortSignal,
    receipt: () => Promise<unknown>,
  ) {
    if (signal.aborted) return;
    const attachedReceipt = async () => {
      if (!signal.aborted) await receipt();
    };
    this.resultReceipts.set(id, attachedReceipt);
    signal.addEventListener(
      "abort",
      () => {
        if (this.resultReceipts.get(id) === attachedReceipt)
          this.resultReceipts.delete(id);
      },
      { once: true },
    );
  }

  override async send(message: JSONRPCMessage): Promise<void> {
    if (
      !("result" in message || "error" in message) ||
      message.id === undefined
    ) {
      return super.send(message);
    }

    const receipt = this.resultReceipts.get(message.id);
    this.resultReceipts.delete(message.id);
    const bytes = Buffer.byteLength(serializeMessage(message), "utf8");
    if (bytes <= NATIVE_STDIO_LINE_LIMIT_BYTES) {
      await super.send(message);
      if ("result" in message) await receipt?.();
      return;
    }

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
