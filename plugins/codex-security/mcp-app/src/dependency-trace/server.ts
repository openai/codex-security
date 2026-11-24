import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { version } from "../../package.json";
import {
  readingAnnotations,
  writingAnnotations,
} from "../server/tool-annotations.js";
import {
  createDependencyGraphSession,
  dependencyGraphTools,
} from "./session.js";

export async function createDependencyTraceServer(checkout: string) {
  const session = await createDependencyGraphSession(checkout, false);
  const server = new McpServer({ name: "codex-security-dependency", version });
  for (const [name, { description, schema }] of Object.entries(
    dependencyGraphTools,
  )) {
    server.registerTool(
      name,
      {
        description,
        inputSchema: schema,
        annotations:
          name === "query_codex_security_graph"
            ? readingAnnotations
            : writingAnnotations,
      },
      async (
        args: unknown,
        { signal }: { signal: AbortSignal },
      ): Promise<CallToolResult> => {
        const body = await session.call(name, args, signal);
        return {
          structuredContent: body,
          content: [{ type: "text", text: JSON.stringify(body) }],
        };
      },
    );
  }
  server.server.onclose = () => {
    void session.close().catch(console.error);
  };
  return server;
}
