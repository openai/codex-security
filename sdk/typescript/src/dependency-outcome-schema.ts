import { z } from "zod";

const text = z.string().regex(/\S/u);
export const dependencyOutcomesSchema = z.array(text).min(1);
export const dependencyReviewerSchema = z.enum([
  "enabled",
  "disabled",
  "outcome",
]);
export type DependencyReviewer = z.infer<typeof dependencyReviewerSchema>;
export const dependencyReportReviewerSchema = dependencyReviewerSchema.exclude([
  "enabled",
]);

const criterion = z.strictObject({
  index: z.number().int().nonnegative(),
  status: z.enum(["satisfied", "needs_revision"]),
  reason: text,
  reportPaths: z.array(
    z.array(z.union([text, z.number().int().nonnegative()])).min(1),
  ),
  receiptIds: z.array(text),
});
export const dependencyOutcomeGradeSchema = z.strictObject({
  reportHash: text,
  criteria: z.array(criterion).min(1),
});
export const dependencyOutcomeReviewSchema =
  dependencyOutcomeGradeSchema.extend({
    status: z.enum(["satisfied", "needs_revision"]),
    attempt: z.number().int().positive(),
    criteria: z.array(criterion.extend({ outcome: text })).min(1),
  });
export type DependencyOutcomeReview = z.infer<
  typeof dependencyOutcomeReviewSchema
>;
