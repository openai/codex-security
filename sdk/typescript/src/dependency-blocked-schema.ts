import { dependencyTargetSchema } from "./dependency-source-identity.js";
import { z } from "zod";
import { dependencyReceiptSelectionSchema } from "./dependency-receipt-selection.js";

const label = z.string().trim().min(1);
const check = z.strictObject({
  requiredRecord: label,
  selection: dependencyReceiptSelectionSchema,
  missing: z.boolean(),
});
const coverage = z.discriminatedUnion("basis", [
  z.strictObject({
    basis: z.literal("observed_scope"),
    scope: label,
    checked: z.number().int().min(2),
    missing: z.number().int().min(2),
    checks: z.array(check).min(2),
    representativeness: label,
  }),
  z.strictObject({
    basis: z.literal("provider_declared"),
    scope: label,
    declaration: label,
    selection: dependencyReceiptSelectionSchema,
    representativeness: label,
  }),
  z.strictObject({
    basis: z.literal("server_startup"),
    server: label,
    receiptId: label,
    requiredCheck: label,
  }),
]);
export const dependencyAbortInputSchema = z.strictObject({
  reason: label,
  category: z.literal("widespread_required_data_unavailable"),
  tool: z.strictObject({ server: label, name: label }).optional(),
  affectedScope: label,
  coverage,
  scopeImpact: label,
  unblockCondition: label,
  evidenceReferences: z.array(label).default([]),
});
const retainedEvidence = z.strictObject({
  assessmentRevisions: z.array(
    z.strictObject({
      id: label,
      revision: z.number().int().positive(),
      status: label,
    }),
  ),
  inventoryReceiptIds: z.array(label),
});
export const dependencyScopedBlockedSchema = dependencyAbortInputSchema.extend({
  status: z.literal("blocked"),
  code: z.literal("INVESTIGATION_BLOCKED"),
  cve: label.optional(),
  target: dependencyTargetSchema.optional(),
  nativeThreadId: label,
  retainedEvidence,
});
export type DependencyBlockDetails = Omit<
  z.infer<typeof dependencyScopedBlockedSchema>,
  "status" | "code" | "cve"
>;
