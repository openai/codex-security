import { z } from "zod";

export const dependencyReceiptSelectionSchema = z.strictObject({
  receiptId: z.string().min(1),
  textBlock: z.number().int().nonnegative().nullable(),
  record: z.array(z.union([z.string(), z.number().int().nonnegative()])),
});
export type DependencyReceiptSelection = z.infer<
  typeof dependencyReceiptSelectionSchema
>;
