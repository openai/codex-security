import { writingAnnotations } from "./tool-annotations.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import * as z from "zod/v4";
import type { JsonObject } from "../types.js";

export interface HandoffWorkspaceState extends JsonObject {
  id: string;
  results?: JsonObject;
  setup: {
    submitted: boolean;
  };
}

interface ScanHandoffToolDependencies {
  appMeta: Record<string, unknown>;
  runWorkbench: (args: string[]) => Promise<JsonObject>;
  workspaceResult: (workspace: HandoffWorkspaceState) => CallToolResult;
}

export const recoveryHandoffClaimTokenSchema = z
  .string()
  .regex(
    /^recovery_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  );
export const handoffClaimTokenSchema = z.union([
  z.string().uuid(),
  recoveryHandoffClaimTokenSchema,
]);
const handoffClaimSchema = z.object({
  claimToken: handoffClaimTokenSchema,
  scanId: z.string().uuid(),
});
const handoffTakeoverSchema = handoffClaimSchema.extend({
  takeOverStale: z.boolean().optional(),
});
const scanContinuationThreadSchema = handoffClaimSchema.extend({
  threadId: z.string().trim().min(1).max(512),
});

export function registerScanHandoffTools(
  server: McpServer,
  { appMeta, runWorkbench, workspaceResult }: ScanHandoffToolDependencies,
) {
  for (const { name, title, description, inputSchema, command } of [
    {
      name: "mark_codex_security_scan_handoff_delivered",
      title: "Record Delivered Codex Security Handoff",
      description:
        "App-only. Record that the launched scan instructions were delivered to Codex.",
      inputSchema: handoffClaimSchema,
      command: "mark-handoff-delivered",
    },
    {
      name: "claim_codex_security_scan_handoff_delivery",
      title: "Claim Codex Security Handoff Delivery",
      description:
        "App-only. Durably claim scan handoff delivery before sending continuation instructions to Codex.",
      inputSchema: handoffTakeoverSchema,
      command: "claim-handoff-delivery",
    },
    {
      name: "release_codex_security_scan_handoff_delivery",
      title: "Release Codex Security Handoff Delivery",
      description:
        "App-only. Release a failed scan handoff delivery claim so the app can retry it.",
      inputSchema: handoffClaimSchema,
      command: "release-handoff-delivery",
    },
    {
      name: "attach_codex_security_scan_continuation_thread",
      title: "Attach Codex Security Scan Thread",
      description:
        "App-only. Persist the normal local Codex thread created for a claimed scan handoff.",
      inputSchema: scanContinuationThreadSchema,
      command: "attach-scan-continuation-thread",
    },
  ] as const) {
    server.registerTool(
      name,
      {
        title,
        description,
        inputSchema,
        annotations: writingAnnotations,
        _meta: appMeta,
      },
      async (input: z.infer<typeof inputSchema>) => {
        const arguments_ = [
          command,
          "--scan-id",
          input.scanId,
          "--claim-token",
          input.claimToken,
        ];
        if ("takeOverStale" in input && input.takeOverStale)
          arguments_.push("--take-over-stale");
        if ("threadId" in input) arguments_.push("--thread-id", input.threadId);
        return workspaceResult(
          (await runWorkbench(arguments_)) as HandoffWorkspaceState,
        );
      },
    );
  }
}
