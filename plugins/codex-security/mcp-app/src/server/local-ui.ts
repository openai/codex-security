import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";

const resourceUri = "ui://codex-security/local.html";

export function registerLocalUi(server: McpServer, runtimeDirectory: string) {
  // Distributions may supply a UI document alongside the runtime.
  // Without it, hosts retain their existing native workbench.
  const document = join(runtimeDirectory, "local.html");
  if (!existsSync(document)) return;

  server.registerResource(
    "codex-security-local",
    resourceUri,
    {
      mimeType: "text/html;profile=mcp-app",
      description: "Local security scans and findings",
    },
    async () => ({
      contents: [
        {
          uri: resourceUri,
          mimeType: "text/html;profile=mcp-app",
          text: await readFile(document, "utf8"),
          _meta: { ui: { csp: { connectDomains: [], resourceDomains: [] } } },
        },
      ],
    }),
  );
  // The host owns rollout and navigation. Older clients do not discover a new global entrypoint.
  server.registerTool(
    "open_codex_security_local",
    {
      title: "Codex Security · Local",
      description:
        "App-only. Open local security scans and findings on this computer.",
      inputSchema: z.object({}).strict(),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
      _meta: { ui: { resourceUri, visibility: ["app"] } },
    },
    async () => ({
      content: [{ type: "text", text: "Local security scans and findings." }],
      structuredContent: { mode: "local" },
    }),
  );
}
