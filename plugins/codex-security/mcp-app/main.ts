import { CodexSecurityStdioTransport } from "./src/stdio-transport.js";

const dependencyTrace = process.argv[2] === "--dependency-trace";

async function createServer() {
  if (dependencyTrace) {
    if (process.argv.length !== 4) {
      throw new Error(
        "--dependency-trace requires an absolute checkout directory.",
      );
    }
    const { createDependencyTraceServer } =
      await import("./src/dependency-trace/server.js");
    return createDependencyTraceServer(process.argv[3]);
  }
  if (process.argv.includes("--artifact-writer")) {
    const { createCodexSecurityArtifactWriterServer } =
      await import("./artifact-writer-main.js");
    return createCodexSecurityArtifactWriterServer();
  }
  const { createCodexSecurityServer } = await import("./server.js");
  return createCodexSecurityServer();
}

async function main(): Promise<void> {
  if (!dependencyTrace && process.argv.includes("--deep-scan-engine")) {
    const { runCliDeepScan } = await import("./deep-scan-main.js");
    await runCliDeepScan();
    return;
  }
  const artifactWriter = process.argv.includes("--artifact-writer");
  const server = await createServer();
  await server.connect(
    new CodexSecurityStdioTransport(
      process.stdin,
      process.stdout,
      // Only scan checkpoints need more than the SDK's default 10 MiB buffer.
      dependencyTrace ? undefined : { maxBufferSize: Infinity },
    ),
  );
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
    process.argv.includes("--deep-scan-engine")
      ? "Codex Security Deep Scan failed:"
      : process.argv.includes("--artifact-writer")
        ? "Codex Security artifact writer failed to start:"
        : "Codex Security MCP server failed to start:",
    error,
  );
  process.exitCode = 1;
});
