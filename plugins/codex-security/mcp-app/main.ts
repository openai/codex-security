import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolve } from "node:path";
import { createCodexSecurityArtifactWriterServer } from "./artifact-writer-main.js";
import { createCodexSecurityServer } from "./server.js";
import { collectFeedbackCommand } from "./src/helpers/collect-feedback.js";

async function main(): Promise<void> {
  const helperIndex = process.argv.indexOf("--helper");
  if (helperIndex !== -1 && process.argv[helperIndex + 1] === "collect-feedback") {
    process.exitCode = await collectFeedbackCommand(resolve(__dirname, ".."));
    return;
  }
  const artifactWriter = process.argv.includes("--artifact-writer");
  const server = artifactWriter
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
        artifactWriter
          ? "Codex Security artifact writer failed to close:"
          : "Codex Security MCP server failed to close:",
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
    process.argv.includes("--helper")
      ? "Codex Security feedback collector failed to start:"
      : process.argv.includes("--artifact-writer")
        ? "Codex Security artifact writer failed to start:"
        : "Codex Security MCP server failed to start:",
    error
  );
  process.exitCode = 1;
});
