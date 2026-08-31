import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as z from "zod/v4";
import type { ScanResults } from "../types.js";

type JsonObject = Record<string, unknown>;

export interface HandoffWorkspaceState extends JsonObject {
  id: string;
  results?: ScanResults & JsonObject;
  setup: {
    submitted: boolean;
  };
}

interface ScanHandoffToolDependencies {
  appMeta: Record<string, unknown>;
  runWorkbench: (args: string[]) => Promise<JsonObject>;
  workspaceResult: (workspace: HandoffWorkspaceState) => unknown;
}

export const recoveryHandoffClaimTokenSchema = z.string().regex(
  /^recovery_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
);
export const handoffClaimTokenSchema = z.union([z.string().uuid(), recoveryHandoffClaimTokenSchema]);
const handoffClaimSchema = { claimToken: handoffClaimTokenSchema, scanId: z.string().uuid() };
const handoffTakeoverSchema = { ...handoffClaimSchema, takeOverStale: z.boolean().optional() };
const scanContinuationThreadSchema = {
  ...handoffClaimSchema,
  threadId: z.string().trim().min(1).max(512)
};

export function registerScanHandoffTools(
  server: McpServer,
  { appMeta, runWorkbench, workspaceResult }: ScanHandoffToolDependencies
) {
  server.registerTool("mark_codex_security_scan_handoff_delivered", {
    title: "Record Delivered Codex Security Handoff",
    description: "App-only. Record that the launched scan instructions were delivered to Codex.",
    inputSchema: handoffClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, claimToken }) => {
    const workspace = await runWorkbench([
      "mark-handoff-delivered",
      "--scan-id",
      scanId,
      "--claim-token",
      claimToken
    ]) as HandoffWorkspaceState;
    return workspaceResult(workspace);
  });

  server.registerTool("claim_codex_security_scan_handoff_delivery", {
    title: "Claim Codex Security Handoff Delivery",
    description: "App-only. Durably claim scan handoff delivery before sending continuation instructions to Codex.",
    inputSchema: handoffTakeoverSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, claimToken, takeOverStale }) => {
    const workspace = await runWorkbench([
      "claim-handoff-delivery",
      "--scan-id",
      scanId,
      "--claim-token",
      claimToken,
      ...(takeOverStale ? ["--take-over-stale"] : [])
    ]) as HandoffWorkspaceState;
    return workspaceResult(workspace);
  });

  server.registerTool("release_codex_security_scan_handoff_delivery", {
    title: "Release Codex Security Handoff Delivery",
    description: "App-only. Release a failed scan handoff delivery claim so the app can retry it.",
    inputSchema: handoffClaimSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, claimToken }) => {
    const workspace = await runWorkbench([
      "release-handoff-delivery",
      "--scan-id",
      scanId,
      "--claim-token",
      claimToken
    ]) as HandoffWorkspaceState;
    return workspaceResult(workspace);
  });

  server.registerTool("attach_codex_security_scan_continuation_thread", {
    title: "Attach Codex Security Scan Thread",
    description: "App-only. Persist the normal local Codex thread created for a claimed scan handoff.",
    inputSchema: scanContinuationThreadSchema,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    _meta: appMeta
  }, async ({ scanId, claimToken, threadId }) => {
    const workspace = await runWorkbench([
      "attach-scan-continuation-thread",
      "--scan-id",
      scanId,
      "--claim-token",
      claimToken,
      "--thread-id",
      threadId
    ]) as HandoffWorkspaceState;
    return workspaceResult(workspace);
  });
}
