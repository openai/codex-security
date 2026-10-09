import { readJson } from "../json.ts";
import type { TextContent } from "@modelcontextprotocol/sdk/types.js";
import type { ZodRawShapeCompat } from "@modelcontextprotocol/sdk/server/zod-compat.js";
import { appendFile } from "node:fs/promises";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { getCodexSecurityDeepReducerInputs } from "../../../src/artifact-deep-reducer.js";
import { registerCompactWorkerArtifactTools } from "../../../src/server/compact-artifact-tools.js";

async function main() {
  const { context, tracePath } = await readJson(process.argv[2]);
  const server = new McpServer({
    name: "deep-reducer-paging-eval",
    version: "1",
  });
  type RegisterTool = typeof server.registerTool<
    ZodRawShapeCompat,
    ZodRawShapeCompat
  >;
  let injected = false;
  let sequence = 0;

  // Exercise the production tool registration and handlers. Only the first read
  // returns the old duplicated result, forcing a real code-mode transport error.
  registerCompactWorkerArtifactTools(
    {
      registerTool(...[name, definition, handler]: Parameters<RegisterTool>) {
        return server.registerTool(name, definition, async (input, extra) => {
          const id = ++sequence;
          const read = name === "get_codex_security_deep_reducer_inputs";
          await trace({
            event: "request",
            id,
            tool: name,
            ...(read
              ? { input }
              : {
                  findingCount: (input.findings as unknown[] | undefined)
                    ?.length,
                }),
          });
          try {
            let result;
            const inject = read && !injected;
            if (inject) {
              injected = true;
              const full = await getCodexSecurityDeepReducerInputs(context);
              result = {
                content: [
                  { type: "text" as const, text: JSON.stringify(full) },
                ],
                structuredContent: full as unknown as Record<string, unknown>,
              };
            } else {
              result = await handler(input, extra);
            }
            await trace({
              event: "response",
              id,
              injected: inject,
              bytes: Buffer.byteLength(JSON.stringify(result)),
              ...(read && !inject
                ? {
                    nextCursor: JSON.parse(
                      (result.content[0] as TextContent).text,
                    ).nextCursor,
                  }
                : {}),
            });
            return result;
          } catch (error) {
            await trace({
              event: "error",
              id,
              message: (error as Error).message,
            });
            throw error;
          }
        });
      },
    } as unknown as McpServer,
    context,
  );

  await server.connect(new StdioServerTransport());

  async function trace(event: Record<string, unknown>) {
    await appendFile(tracePath, JSON.stringify(event) + "\n");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
