import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { z } from "zod";
import type { JsonValue } from "./config.js";
import {
  dependencyRecordHash,
  type DependencyAttemptStore,
} from "./dependency-attempt-store.js";
import { dependencyEvidencePayload } from "./dependency-graph-evidence.js";
import {
  inventoryJsonField,
  stackJsonValue,
  type BoundDependencyInventoryReceipt,
  type DependencyInventoryReceiptSelection,
} from "./dependency-stack-evidence.js";
import { CodexSecurityError } from "./errors.js";
import { readRegularInputFileBytes } from "./prompt-files.js";
import { isRecord } from "./record.js";

const text = z.string().trim().min(1);
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const runtimeImportServer = "runtime-import";
const captureServers = new Set([
  "stack-packet",
  "stack-observation",
  runtimeImportServer,
]);

export const runtimeEvidenceInputSchema = z
  .strictObject({
    kind: z.literal("runtime"),
    server: text.refine(
      (name) => !captureServers.has(name),
      "A runtime receipt cannot use a host capture server name.",
    ),
    tool: text,
    arguments: stackJsonValue.optional(),
    scope: stackJsonValue.optional(),
    result: stackJsonValue.optional(),
    resource: z.strictObject({ path: text, sha256: digest }).optional(),
  })
  .refine(
    (input) => (input.result !== undefined) !== (input.resource !== undefined),
    "Provide exactly one runtime result or resource.",
  );

export type RuntimeEvidenceInput = z.input<typeof runtimeEvidenceInputSchema>;

interface RuntimeReceiptRecord {
  server: string;
  tool: string;
  arguments?: JsonValue;
  scope?: JsonValue;
  result: JsonValue;
  resourceSha256?: string;
}

export interface PreparedRuntimeEvidence {
  receiptId: string;
  sha256: string;
  record: RuntimeReceiptRecord;
}

/** Capture the supplied original before opening the short state transaction. */
export async function prepareRuntimeEvidence(
  raw: unknown,
  repository: string,
  signal?: AbortSignal,
): Promise<PreparedRuntimeEvidence> {
  const input = runtimeEvidenceInputSchema.parse(raw);
  signal?.throwIfAborted();
  let result = input.result;
  if (input.resource) {
    const bytes = await readRegularInputFileBytes(
      resolve(input.resource.path),
      repository,
    );
    signal?.throwIfAborted();
    if (
      createHash("sha256").update(bytes).digest("hex") !== input.resource.sha256
    )
      throw new CodexSecurityError(
        "Runtime resource SHA-256 does not match its original bytes.",
      );
    try {
      result = JSON.parse(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } catch (error) {
      throw new CodexSecurityError(
        `Runtime resource is not UTF-8 JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    result = stackJsonValue.parse(result);
  }
  const record: RuntimeReceiptRecord = {
    server: input.server,
    tool: input.tool,
    ...(input.arguments !== undefined && { arguments: input.arguments }),
    ...(input.scope !== undefined && { scope: input.scope }),
    result: result as JsonValue,
    ...(input.resource && { resourceSha256: input.resource.sha256 }),
  };
  const sha256 = dependencyRecordHash(record);
  return { receiptId: "runtime-" + sha256, sha256, record };
}

export function saveRuntimeEvidence(
  store: DependencyAttemptStore,
  prepared: PreparedRuntimeEvidence,
): { receiptId: string; sha256: string } {
  const { receiptId, sha256, record } = prepared;
  if (
    sha256 !== dependencyRecordHash(record) ||
    receiptId !== "runtime-" + sha256
  )
    throw new CodexSecurityError(
      "Runtime receipt identity does not match its original record.",
    );
  const existing = store.get<RuntimeReceiptRecord>(
    "runtime-receipt",
    receiptId,
  );
  if (existing && dependencyRecordHash(existing) !== sha256)
    throw new CodexSecurityError(
      "A runtime receipt cannot replace its original record.",
    );
  if (!existing) store.set("runtime-receipt", receiptId, record);
  return { receiptId, sha256 };
}

/** Reopen and verify the host-saved original before binding any projection. */
export function selectRuntimeReceipt(
  store: DependencyAttemptStore,
  receiptId: string,
  selection?: DependencyInventoryReceiptSelection,
): BoundDependencyInventoryReceipt {
  const record = store.get<RuntimeReceiptRecord>("runtime-receipt", receiptId);
  if (!record)
    throw new CodexSecurityError("Unknown runtime receipt: " + receiptId);
  const sha256 = dependencyRecordHash(record);
  if (receiptId !== "runtime-" + sha256 || captureServers.has(record.server))
    throw new CodexSecurityError(
      "Runtime receipt no longer matches its original record.",
    );
  if (selection && selection.receiptId !== receiptId)
    throw new CodexSecurityError(
      "Runtime receipt selection identifies a different receipt.",
    );
  let result: unknown = record.result;
  if (selection) {
    if (selection.textBlock !== null) {
      if (!isRecord(record.result))
        throw new CodexSecurityError(
          "A runtime text block requires an original MCP response.",
        );
      result = dependencyEvidencePayload(
        { result: record.result },
        selection.textBlock,
      );
    } else if (isRecord(result)) {
      result =
        result["structuredContent"] ?? result["structured_content"] ?? result;
    }
    result = inventoryJsonField(result, selection.record);
    if (result === undefined)
      throw new CodexSecurityError(
        "The selected runtime receipt record does not exist.",
      );
  }
  const origin = {
    tool: "record-evidence",
    arguments: {
      kind: "runtime",
      provenance: "caller_imported",
      verification: "unverified",
      declaredServer: record.server,
      declaredTool: record.tool,
      receiptId,
      sha256,
      ...(record.arguments !== undefined && { arguments: record.arguments }),
      ...(record.scope !== undefined && { scope: record.scope }),
      ...(record.resourceSha256 && { resourceSha256: record.resourceSha256 }),
    },
  };
  const originalPayloadSha256 =
    record.resourceSha256 ?? dependencyRecordHash(record.result);
  const projection = selection && {
    textBlock: selection.textBlock,
    record: selection.record,
  };
  return {
    receiptId,
    key: dependencyRecordHash({
      server: runtimeImportServer,
      origin,
      originalPayloadSha256,
      selection: projection ?? null,
    }),
    server: runtimeImportServer,
    originalPayloadSha256,
    origin,
    ...(projection && { selection: projection }),
    result,
  };
}

/** The import receipt protects immutable bytes, not the claimed provider identity. */
export function isRuntimeReceipt(
  receipt: BoundDependencyInventoryReceipt,
): boolean {
  const args = receipt.origin.arguments;
  return (
    receipt.server === runtimeImportServer &&
    receipt.origin.tool === "record-evidence" &&
    args["kind"] === "runtime" &&
    args["provenance"] === "caller_imported" &&
    args["verification"] === "unverified" &&
    typeof args["declaredServer"] === "string" &&
    !captureServers.has(args["declaredServer"]) &&
    typeof args["declaredTool"] === "string" &&
    args["receiptId"] === receipt.receiptId &&
    typeof args["sha256"] === "string" &&
    /^[a-f0-9]{64}$/u.test(args["sha256"]) &&
    receipt.receiptId === "runtime-" + args["sha256"] &&
    /^[a-f0-9]{64}$/u.test(receipt.originalPayloadSha256)
  );
}
