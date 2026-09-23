import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createCodexSecurityArtifactWriterServer } from "./artifact-writer-main.js";
import { createCodexSecurityDependencyAgentWriterServer } from "./dependency-agent-writer-main.js";
import { createCodexSecurityServer } from "./server.js";

async function main(): Promise<void> {
  const artifactWriter = process.argv.includes("--artifact-writer");
  const dependencyAgentWriter = process.argv.includes(
    "--dependency-agent-writer",
  );
  const server = dependencyAgentWriter
    ? await createCodexSecurityDependencyAgentWriterServer()
    : artifactWriter
      ? await createCodexSecurityArtifactWriterServer()
      : createCodexSecurityServer();
  await server.connect(new StdioServerTransport());
  let closing = false;
  const close = async (exitCode?: number): Promise<void> => {
    if (closing) return;
    closing = true;
    if (exitCode !== undefined) process.exitCode = exitCode;
    await server.close().catch((error: unknown) => {
      console.error(
        dependencyAgentWriter
          ? "Codex Security dependency agent writer failed to close:"
          : artifactWriter
            ? "Codex Security artifact writer failed to close:"
            : "Codex Security MCP server failed to close:",
        error,
      );
    });
  };
  process.stdin.once("end", () => void close());
  process.once("SIGINT", () => void close(130));
  process.once("SIGTERM", () => void close(143));
}

main().catch((error) => {
  console.error(
    process.argv.includes("--dependency-agent-writer")
      ? "Codex Security dependency agent writer failed to start:"
      : process.argv.includes("--artifact-writer")
        ? "Codex Security artifact writer failed to start:"
        : "Codex Security MCP server failed to start:",
    error,
  );
  process.exitCode = 1;
});
