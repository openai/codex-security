import { createHash } from "node:crypto";
import { z } from "zod";
import type { JsonObject, JsonValue } from "./config.js";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson, cloneWithoutGetters, isRecord } from "./record.js";

export interface DependencyInventoryRpc {
  list(): Promise<unknown>;
  call(server: string, tool: string, args: JsonObject): Promise<unknown>;
  read?(server: string, uri: string): Promise<unknown>;
}

export interface DependencyInventoryReceiptMetadata {
  tool?: string;
  arguments?: unknown;
  itemId?: string;
  outcome?: "failed" | "empty" | "unavailable";
  startedAt?: string;
  finishedAt?: string;
  /** Tool receipt that supplied this immutable evidence resource. */
  parentReceiptId?: string;
}
export const inventoryReceiptSelectionSchema = z.strictObject({
  receiptId: z.string().trim().min(1),
  textBlock: z.number().int().nonnegative().nullable(),
  record: z.array(z.union([z.string(), z.number().int().nonnegative()])),
});
export type DependencyInventoryReceiptSelection = z.infer<
  typeof inventoryReceiptSelectionSchema
>;
export const inventoryReceiptQuerySchema = z.union([
  inventoryReceiptSelectionSchema,
  z.strictObject({
    receiptId: inventoryReceiptSelectionSchema.shape.receiptId,
    original: z.literal(true).optional(),
  }),
]);
export type DependencyInventoryReceiptQuery = z.infer<
  typeof inventoryReceiptQuerySchema
>;
export interface BoundDependencyInventoryReceipt {
  key: string;
  receiptId: string;
  server: string;
  originalPayloadSha256: string;
  origin: Pick<
    DependencyInventoryReceiptMetadata,
    "tool" | "arguments" | "parentReceiptId"
  >;
  selection?: Omit<DependencyInventoryReceiptSelection, "receiptId">;
  result: unknown;
  outcome?: DependencyInventoryReceiptMetadata["outcome"];
  historical?: boolean;
}
interface Receipt {
  id: string;
  server: string;
  result: unknown;
  payloadSha256: string;
  payloadCharacters: number;
  originKey: string;
  origin: Pick<
    DependencyInventoryReceiptMetadata,
    "tool" | "arguments" | "parentReceiptId"
  >;
  itemId?: string;
  outcome?: DependencyInventoryReceiptMetadata["outcome"];
}

function digest(value: unknown): string {
  return createHash("sha256")
    .update(canonicalJson(value) ?? "null")
    .digest("hex");
}
export function inventoryJsonField(
  value: unknown,
  path: readonly (string | number)[],
): unknown {
  for (const key of path) {
    if (typeof key === "number" && Array.isArray(value)) value = value[key];
    else if (
      typeof key === "string" &&
      isRecord(value) &&
      Object.hasOwn(value, key)
    )
      value = value[key];
    else return undefined;
  }
  return value;
}
export function inventoryResultPayload(
  result: unknown,
  textBlock: number | null,
): unknown {
  if (!isRecord(result)) return undefined;
  if (textBlock === null)
    return (
      result["structured_content"] ?? result["structuredContent"] ?? undefined
    );
  const resource =
    !Array.isArray(result["content"]) && Array.isArray(result["contents"]);
  const blocks = resource ? result["contents"] : result["content"];
  if (!Array.isArray(blocks)) return undefined;
  const block: unknown = blocks[textBlock];
  if (
    !isRecord(block) ||
    (!resource && block["type"] !== "text") ||
    typeof block["text"] !== "string"
  )
    return undefined;
  try {
    return JSON.parse(block["text"]);
  } catch {
    return undefined;
  }
}

function describeResult(result: unknown): JsonObject {
  if (Array.isArray(result)) return { length: result.length };
  if (!isRecord(result))
    return { type: result === null ? "null" : typeof result };
  const structured = inventoryResultPayload(result, null);
  const content = result["content"] ?? result["contents"];
  return {
    fields: Object.keys(result),
    ...(Array.isArray(structured)
      ? { structuredLength: structured.length }
      : isRecord(structured)
        ? { structuredFields: Object.keys(structured) }
        : {}),
    ...(Array.isArray(content) ? { contentBlockCount: content.length } : {}),
  };
}

function checkResourceProof(bound: readonly BoundDependencyInventoryReceipt[]) {
  const resourceProof = bound.filter(
    (value) => value.origin.parentReceiptId !== undefined,
  );
  if (
    resourceProof.length &&
    Buffer.byteLength(canonicalJson(resourceProof), "utf8") > 32 * 1024
  )
    throw new CodexSecurityError(
      "The selected resource evidence exceeds the review context budget. Use the graph's exact frame and witness-scope receiptSelections for the deciding path; the complete collection remains retained outside model context.",
    );
}

/** Scan-owned original receipts. A projection is an exact value, never a summary. */
export function createDependencyInventory() {
  const receipts = new Map<string, Receipt>();
  const byMaterial = new Map<string, string>();
  const latestByOrigin = new Map<string, string>();
  let generation = 0;

  function superseded(id: string): string | undefined {
    const original = receipts.get(id);
    if (!original) return `Inventory receipt ${id} is unavailable.`;
    const latest = latestByOrigin.get(original.originKey);
    if (latest !== id)
      return `Inventory receipt ${id} was superseded by ${latest ?? "unavailable evidence"} from the same server/tool/arguments.`;
    return original.origin.parentReceiptId === undefined
      ? undefined
      : superseded(original.origin.parentReceiptId);
  }

  function staleReason(bound: readonly BoundDependencyInventoryReceipt[]) {
    for (const item of bound) {
      if (item.historical) continue;
      const reason = superseded(item.receiptId);
      if (reason)
        return `${reason} Reassess against the current original result and queue its receipt ID or exact record selection. The older proof cannot establish the refreshed state.`;
    }
    return undefined;
  }
  function receipt(id: string): Receipt {
    const value = receipts.get(id);
    if (!value)
      throw new CodexSecurityError(
        `Unknown inventory receipt ID: ${id}. Check review status for available original receipts.`,
      );
    const reason = superseded(id);
    if (reason)
      throw new CodexSecurityError(
        `${reason} Reassess using the current receipt and update the queued receipt IDs or record selections.`,
      );
    return value;
  }
  function bindOne(
    value: Receipt,
    selection?: DependencyInventoryReceiptSelection,
  ): BoundDependencyInventoryReceipt {
    if (value.origin.parentReceiptId !== undefined && selection === undefined)
      throw new CodexSecurityError(
        `Select exact receiptSelections from the graph for resource receipt ${value.id}. Its bulk collection stays outside model context; a whole-resource receiptId is not a review projection.`,
      );
    const pointer = selection && {
      textBlock: selection.textBlock,
      record: selection.record,
    };
    const result = pointer
      ? inventoryJsonField(
          inventoryResultPayload(value.result, pointer.textBlock),
          pointer.record,
        )
      : value.result;
    if (result === undefined)
      throw new CodexSecurityError(
        `Inventory selection in ${value.id} does not exist or is not JSON. Use textBlock=null for structured content, or the zero-based JSON text-block index, and an exact record key/index path.`,
      );
    return {
      key: digest({
        server: value.server,
        origin: value.origin,
        payloadSha256: value.payloadSha256,
        selection: pointer,
        outcome: value.outcome,
      }),
      receiptId: value.id,
      server: value.server,
      originalPayloadSha256: value.payloadSha256,
      origin: value.origin,
      ...(pointer ? { selection: pointer } : {}),
      result,
      ...(value.outcome ? { outcome: value.outcome } : {}),
    };
  }
  const describe = (value: Receipt) => ({
    id: value.id,
    server: value.server,
    ...value.origin,
    ...(value.itemId ? { itemId: value.itemId } : {}),
    ...(value.outcome ? { outcome: value.outcome } : {}),
    originalPayloadSha256: value.payloadSha256,
    payloadCharacters: value.payloadCharacters,
    current: superseded(value.id) === undefined,
  });
  return {
    isReceiptCurrent(id: string) {
      return superseded(id) === undefined;
    },
    generation: () => generation,
    clearUnavailable(server: string) {
      const originKey = digest({
        server,
        tool: undefined,
        arguments: undefined,
      });
      const current = latestByOrigin.get(originKey);
      if (current && receipts.get(current)?.outcome === "unavailable") {
        latestByOrigin.delete(originKey);
        generation++;
      }
    },
    record(
      server: string,
      result: unknown,
      metadata: DependencyInventoryReceiptMetadata = {},
    ): string | undefined {
      // Preserve historical proof even if a caller later changes its result object.
      const captured = cloneWithoutGetters(result);
      if (captured === undefined) return undefined;
      const origin = {
        tool: metadata.tool,
        arguments: cloneWithoutGetters(metadata.arguments),
        ...(metadata.parentReceiptId === undefined
          ? {}
          : { parentReceiptId: metadata.parentReceiptId }),
      };
      const payload = canonicalJson(captured);
      const payloadSha256 = createHash("sha256").update(payload).digest("hex");
      const originKey = digest({ server, ...origin });
      const material = digest({
        originKey,
        payloadSha256,
        outcome: metadata.outcome,
      });
      let id = byMaterial.get(material);
      if (!id) {
        id = `inventory-${receipts.size + 1}`;
        receipts.set(id, {
          id,
          server,
          result: captured,
          payloadSha256,
          payloadCharacters: payload.length,
          originKey,
          origin,
          ...(metadata.itemId ? { itemId: metadata.itemId } : {}),
          ...(metadata.outcome ? { outcome: metadata.outcome } : {}),
        });
        byMaterial.set(material, id);
      }
      if (latestByOrigin.get(originKey) !== id) {
        latestByOrigin.set(originKey, id);
        generation++;
      }
      return id;
    },
    servers: () => [
      ...new Set([...receipts.values()].map((value) => value.server)),
    ],
    snapshot: () => [...receipts.values()].map(describe),
    read(query: DependencyInventoryReceiptQuery): JsonObject {
      const value = receipt(query.receiptId);
      const metadata = describe(value) as JsonObject;
      if (!("record" in query) && !query.original)
        return { ...metadata, resultShape: describeResult(value.result) };
      const selection = "record" in query ? query : undefined;
      const bound = bindOne(value, selection);
      checkResourceProof([bound]);
      return {
        ...metadata,
        ...(selection && { selection }),
        result: bound.result as JsonValue,
      };
    },
    bind(
      servers: readonly string[],
      receiptIds?: readonly string[],
      selections?: readonly DependencyInventoryReceiptSelection[],
    ): BoundDependencyInventoryReceipt[] {
      const named = new Set(servers);
      const explicit = receiptIds !== undefined || selections !== undefined;
      const bound = [
        ...(receiptIds ?? []).map((id) => bindOne(receipt(id))),
        ...(selections ?? []).map((selection) =>
          bindOne(receipt(selection.receiptId), selection),
        ),
      ];
      if (!explicit) {
        for (const server of named) {
          const available = [...receipts.values()].filter(
            (value) =>
              value.server === server && superseded(value.id) === undefined,
          );
          if (available.length !== 1)
            throw new CodexSecurityError(
              `Select explicit receiptIds or receiptSelections for ${server} on the queued review item. ${available.length} current originals are available in review status; server name or free-text record descriptions do not identify the deciding receipt.`,
            );
          bound.push(bindOne(available[0]!));
        }
      }
      for (const value of bound)
        if (!named.has(value.server))
          throw new CodexSecurityError(
            `Selected receipt ${value.receiptId} belongs to ${value.server}, which is not named in this item's observations. Bind the original record to the appropriate observation.`,
          );
      for (const server of named)
        if (!bound.some((value) => value.server === server))
          throw new CodexSecurityError(
            `No selected original receipt supports the observations from ${server}. Choose its receiptIds or exact receiptSelections in this queued item.`,
          );
      const selected = [
        ...new Map(bound.map((value) => [value.key, value])).values(),
      ].sort((a, b) => a.key.localeCompare(b.key));
      checkResourceProof(selected);
      return selected;
    },
    staleReason,
  };
}
