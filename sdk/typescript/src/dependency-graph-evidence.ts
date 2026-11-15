import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import {
  inventoryResultPayload,
  type DependencyInventoryReceiptMetadata,
  type DependencyInventoryRpc,
} from "./dependency-inventory.js";
import { errorMessage } from "./errors.js";
import { canonicalJson, isRecord } from "./record.js";

const format = "codex-security-graph-evidence/v1";
const referenceSchema = z.object({
  format: z.literal(format),
  uri: z.string().min(1),
  sha256: z.string().regex(/^[a-f0-9]{64}$/u),
});
export const graphEvidenceResourceSchema = z.object({
  format: z.literal(format),
  frame_order: z.literal("root_first"),
  observations: z.array(
    z.object({
      id: z.string().min(1),
      kind: z.literal("sampled_stack"),
      scope: z.record(z.string(), z.json()),
      frames: z.array(
        z.object({
          kind: z.string().min(1),
          name: z.string(),
          scope: z.string().optional(),
        }),
      ),
    }),
  ),
});

export type GraphEvidenceObservations = z.infer<
  typeof graphEvidenceResourceSchema
>["observations"];
export type RecordGraphInventory = (
  server: string,
  result: unknown,
  metadata: DependencyInventoryReceiptMetadata,
) => string | undefined;

function references(result: unknown): unknown[] {
  const values = [inventoryResultPayload(result, null)];
  if (isRecord(result) && Array.isArray(result["content"]))
    for (let index = 0; index < result["content"].length; index++)
      values.push(inventoryResultPayload(result, index));
  return values.flatMap((value) =>
    isRecord(value) && value["graph_evidence"] !== undefined
      ? [value["graph_evidence"]]
      : [],
  );
}

/** Machine-to-machine ingestion. Neither the resource nor its frames enter a tool reply. */
export function createGraphEvidenceIngestion(options: {
  record: RecordGraphInventory;
  ingest: (
    observations: GraphEvidenceObservations,
    receiptId: string,
  ) => JsonObject;
  signal?: AbortSignal;
}) {
  const entries = new Map<string, JsonObject>();
  const pending = new Set<Promise<void>>();
  return {
    observe(
      server: string,
      result: unknown,
      parentReceiptId: string,
      rpc: DependencyInventoryRpc,
    ) {
      for (const reference of references(result)) {
        const key = canonicalJson([server, parentReceiptId, reference]);
        const existing = entries.get(key);
        if (existing && existing["status"] !== "failed") continue;
        const entry: JsonObject = {
          server,
          sourceReceiptId: parentReceiptId,
          status: "pending",
        };
        entries.set(key, entry);
        const task = (async () => {
          let resourceResult: unknown;
          let uri: string | undefined;
          try {
            const descriptor = referenceSchema.parse(reference);
            uri = descriptor.uri;
            Object.assign(entry, descriptor);
            if (!rpc.read)
              throw new Error(
                "This runtime does not support MCP resource reads.",
              );
            options.signal?.throwIfAborted();
            resourceResult = await rpc.read(server, uri);
            options.signal?.throwIfAborted();
            const contents = isRecord(resourceResult)
              ? resourceResult["contents"]
              : undefined;
            // The descriptor identifies one complete UTF-8 JSON resource.
            if (
              !Array.isArray(contents) ||
              contents.length !== 1 ||
              !isRecord(contents[0]) ||
              contents[0]["uri"] !== uri ||
              typeof contents[0]["text"] !== "string"
            )
              throw new Error(
                "Graph evidence resource did not return its complete JSON text.",
              );
            const text = contents[0]["text"];
            const sha256 = createHash("sha256")
              .update(text, "utf8")
              .digest("hex");
            if (sha256 !== descriptor.sha256)
              throw new Error(
                "Graph evidence resource hash does not match its collection receipt.",
              );
            const evidence = graphEvidenceResourceSchema.parse(
              JSON.parse(text),
            );
            const receiptId = options.record(server, resourceResult, {
              tool: "mcpServer/resource/read",
              arguments: { uri },
              parentReceiptId,
            });
            if (!receiptId)
              throw new Error(
                "Graph evidence resource could not be retained as an original receipt.",
              );
            entry["receiptId"] = receiptId;
            entry["ingestion"] = options.ingest(
              evidence.observations,
              receiptId,
            );
            entry["metadataSelection"] = {
              receiptId,
              textBlock: 0,
              record: ["metadata"],
            };
            entry["status"] = "loaded";
          } catch (error) {
            entry["status"] = "failed";
            entry["reason"] = errorMessage(error);
            const receiptId = options.record(
              server,
              resourceResult ?? { error: errorMessage(error) },
              {
                tool: "mcpServer/resource/read",
                arguments: uri === undefined ? {} : { uri },
                parentReceiptId,
                outcome: "failed",
              },
            );
            if (receiptId) entry["receiptId"] = receiptId;
          }
        })();
        pending.add(task);
        void task.finally(() => pending.delete(task));
      }
    },
    async flush() {
      while (pending.size) await Promise.all(pending);
    },
    summary(): JsonObject | undefined {
      if (!entries.size) return undefined;
      const summary: JsonObject = {
        pending: 0,
        loaded: 0,
        failed: 0,
        resources: [],
      };
      const resources: JsonObject[] = [];
      summary["resources"] = resources;
      for (const entry of entries.values()) {
        const status = String(entry["status"]);
        summary[status] = Number(summary[status] ?? 0) + 1;
        resources.push(entry);
        // The graph itself allows 32 KiB; keep ingestion receipts small alongside it.
        if (Buffer.byteLength(JSON.stringify(summary), "utf8") > 8 * 1024) {
          resources.pop();
          summary["truncated"] = true;
        }
      }
      return summary;
    },
  };
}
