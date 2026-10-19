import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import type { JsonObject } from "../types.js";
import { readingAnnotations, writingAnnotations } from "./tool-annotations.js";

const identifier = z.string().min(1);
const destinationSchema = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("linear"),
      teamId: identifier,
      projectId: identifier.optional(),
    })
    .strict(),
  z
    .object({
      type: z.literal("jira"),
      cloudId: identifier,
      projectId: identifier,
    })
    .strict(),
  z
    .object({
      type: z.enum(["github-issue", "github-advisory"]),
      hostname: identifier,
      repository: identifier,
    })
    .strict(),
]);
const sourceSchema = z
  .object({
    scanDirectory: identifier,
    destination: destinationSchema,
    findingIds: z.array(identifier).optional(),
  })
  .strict();
const receiptSchema = z
  .object({
    findingId: identifier,
    occurrenceId: identifier,
    issueIdentifier: identifier,
    url: identifier.optional(),
    operation: z.enum(["create", "update", "reuse"]),
    readback: z
      .object({
        status: z.enum(["verified", "failed"]),
        error: z.string().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export function registerFindingIssueTools(
  server: McpServer,
  runWorkbench: (
    args: string[],
    input?: string | Buffer,
  ) => Promise<JsonObject>,
): void {
  const meta = { ui: { visibility: ["model"] } };
  const execute = async (action: "inspect" | "record", input: object) => {
    const result = await runWorkbench(
      ["finding-issues"],
      JSON.stringify({ action, ...input }),
    );
    return {
      content: [{ type: "text" as const, text: JSON.stringify(result) }],
      structuredContent: result,
    };
  };
  server.registerTool(
    "get_codex_security_finding_issues",
    {
      title: "Get Codex Security Finding Issues",
      description:
        "Validate a sealed scan and read its findings' saved issue associations for the exact destination, including earlier scan occurrences. Saved receipts are duplicate candidates; verify them through the provider before reusing an issue. Does not contact providers or require local scan history.",
      inputSchema: sourceSchema,
      annotations: readingAnnotations,
      _meta: meta,
    },
    (input) => execute("inspect", input),
  );
  server.registerTool(
    "record_codex_security_finding_issues",
    {
      title: "Record Codex Security Finding Issues",
      description:
        "Validate a sealed scan and save accepted provider creates or updates, or verified issue reuse, in the shared local issue history. Record the returned identity immediately; repeat the same receipt with readback status after an optional provider read. A failed read or local save does not undo an accepted write or authorize another create. Does not contact providers or modify the scan bundle.",
      inputSchema: sourceSchema.extend({ receipts: z.array(receiptSchema) }),
      annotations: writingAnnotations,
      _meta: meta,
    },
    (input) => execute("record", input),
  );
}
