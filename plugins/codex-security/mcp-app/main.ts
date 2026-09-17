import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCodexSecurityServer } from "./server.js";

async function main(): Promise<void> {
  const server = createCodexSecurityServer();
  await server.connect(new StdioServerTransport());
  let closing = false;
  const close = async (exitCode?: number): Promise<void> => {
    if (closing) return;
    closing = true;
    if (exitCode !== undefined) process.exitCode = exitCode;
    await server.close().catch((error: unknown) => {
      console.error(
        "Codex Security MCP server failed to close:",
        error
      );
    });
  };
  process.stdin.once("end", () => void close());
  process.once("SIGINT", () => void close(130));
  process.once("SIGTERM", () => void close(143));
}

main().catch((error) => {
  console.error(
    "Codex Security MCP server failed to start:",
    error
  );
  process.exitCode = 1;
});
