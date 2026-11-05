import { createHash } from "node:crypto";
import { CodexSecurityError } from "./errors.js";
import { canonicalJson, cloneWithoutGetters, isRecord } from "./record.js";

export interface DependencyInventoryReceiptMetadata {
  tool?: string;
  arguments?: unknown;
  itemId?: string;
}
export interface DependencyInventoryReceiptSelection {
  receiptId: string;
  textBlock: number | null;
  record: (string | number)[];
}
export interface BoundDependencyInventoryReceipt {
  key: string;
  receiptId: string;
  server: string;
  originalPayloadSha256: string;
  origin: Pick<DependencyInventoryReceiptMetadata, "tool" | "arguments">;
  selection?: Omit<DependencyInventoryReceiptSelection, "receiptId">;
  result: unknown;
  historical?: boolean;
}
interface Receipt {
  id: string;
  server: string;
  result: unknown;
  payloadSha256: string;
  payloadCharacters: number;
  originKey: string;
  origin: Pick<DependencyInventoryReceiptMetadata, "tool" | "arguments">;
  itemId?: string;
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
  if (!Array.isArray(result["content"])) return undefined;
  const block: unknown = result["content"][textBlock];
  if (
    !isRecord(block) ||
    block["type"] !== "text" ||
    typeof block["text"] !== "string"
  )
    return undefined;
  try {
    return JSON.parse(block["text"]);
  } catch {
    return undefined;
  }
}

/** Scan-owned original receipts. A projection is an exact value, never a summary. */
export function createDependencyInventory() {
  const receipts = new Map<string, Receipt>();
  const byMaterial = new Map<string, string>();
  const latestByOrigin = new Map<string, string>();

  function staleReason(bound: readonly BoundDependencyInventoryReceipt[]) {
    for (const item of bound) {
      if (item.historical) continue;
      const original = receipts.get(item.receiptId);
      const latest = original && latestByOrigin.get(original.originKey);
      if (!original || latest !== item.receiptId)
        return `Inventory receipt ${item.receiptId} was superseded by ${latest ?? "unavailable evidence"} from the same server/tool/arguments. Reassess against the current original result and queue its receipt ID or exact record selection. The older proof cannot establish the refreshed state.`;
    }
    return undefined;
  }
  function receipt(id: string): Receipt {
    const value = receipts.get(id);
    if (!value)
      throw new CodexSecurityError(
        `Unknown inventory receipt ID: ${id}. Check review status for available original receipts.`,
      );
    const latest = latestByOrigin.get(value.originKey);
    if (latest !== id)
      throw new CodexSecurityError(
        `Inventory receipt ${id} was superseded by ${latest} from the same server/tool/arguments. Reassess using the current receipt and update the queued receipt IDs or record selections.`,
      );
    return value;
  }
  function bindOne(
    value: Receipt,
    selection?: DependencyInventoryReceiptSelection,
  ): BoundDependencyInventoryReceipt {
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
      }),
      receiptId: value.id,
      server: value.server,
      originalPayloadSha256: value.payloadSha256,
      origin: value.origin,
      ...(pointer ? { selection: pointer } : {}),
      result,
    };
  }
  return {
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
      };
      const payload = canonicalJson(captured);
      const payloadSha256 = createHash("sha256").update(payload).digest("hex");
      const originKey = digest({ server, ...origin });
      const material = digest({ originKey, payloadSha256 });
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
        });
        byMaterial.set(material, id);
      }
      latestByOrigin.set(originKey, id);
      return id;
    },
    servers: () => [
      ...new Set([...receipts.values()].map((value) => value.server)),
    ],
    snapshot: () =>
      [...receipts.values()].map((value) => ({
        id: value.id,
        server: value.server,
        ...value.origin,
        ...(value.itemId ? { itemId: value.itemId } : {}),
        originalPayloadSha256: value.payloadSha256,
        payloadCharacters: value.payloadCharacters,
        current: latestByOrigin.get(value.originKey) === value.id,
      })),
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
              value.server === server &&
              latestByOrigin.get(value.originKey) === value.id,
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
      return [
        ...new Map(bound.map((value) => [value.key, value])).values(),
      ].sort((a, b) => a.key.localeCompare(b.key));
    },
    staleReason,
  };
}
